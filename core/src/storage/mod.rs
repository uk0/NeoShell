use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use parking_lot::RwLock;
use zeroize::Zeroizing;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::crypto::{CryptoEngine, VaultHeader};

/// The one `ConnectionStore` this process opened, for the code that cannot be
/// handed one.
///
/// `ProxyStore` and `TunnelStore` are built ad hoc — including deep inside a
/// background SSH thread that only ever sees a `ConnectParams` — and they need
/// the vault to resolve the credentials that used to sit in `proxies.json` and
/// `tunnels.json` in the clear. Threading a handle through every one of those
/// call sites would touch far more code than the secrets themselves.
///
/// Only the handle is global; whether it can decrypt anything is still the
/// store's own `is_unlocked()` state, so registering this at startup does not
/// weaken the lock screen.
static GLOBAL_VAULT: OnceLock<Arc<ConnectionStore>> = OnceLock::new();

/// Register the process-wide vault. Call once, right after the store is built.
/// Later calls are ignored, so this is safe to call defensively.
///
/// Called from `NeoShell::default`, before any `ProxyStore` / `TunnelStore`
/// exists.
pub fn set_global_vault(store: Arc<ConnectionStore>) {
    let _ = GLOBAL_VAULT.set(store);
}

/// The registered vault, if `set_global_vault` has run. `None` during early
/// startup and in tests, which is why every caller treats it as optional.
pub fn global_vault() -> Option<Arc<ConnectionStore>> {
    GLOBAL_VAULT.get().cloned()
}

/// Tighten an existing file to 0600 if it is more permissive.
///
/// Files written by builds before 0.7.0 went through `std::fs::write` and so
/// inherited the umask — 0644 in practice. Only ever narrows.
#[cfg(unix)]
pub fn tighten_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o177 != 0 {
            let narrowed = std::fs::Permissions::from_mode(mode & 0o7600);
            if let Err(e) = std::fs::set_permissions(path, narrowed) {
                log::warn!("failed to tighten permissions on {}: {}", path.display(), e);
            }
        }
    }
}

#[cfg(not(unix))]
pub fn tighten_permissions(_path: &Path) {}

/// Create `path` (and any missing parents) owner-only on unix.
///
/// Every NeoShell config directory holds either secrets or a map of what the
/// user connects to, so none of them should be group- or world-traversable.
pub fn create_dir_private(path: &Path) -> std::io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Write `bytes` to `path` atomically, owner-only.
///
/// The bytes land in a sibling temp file in the *same* directory (so the final
/// `rename` can never cross a filesystem), are fsync'd, and only then replace
/// `path` in one atomic step. A crash, a full disk or a kill mid-write leaves
/// the previous `path` completely intact instead of a truncated file.
///
/// On unix the temp file is created with mode 0600, so the contents are never
/// even briefly world-readable — setting the mode after the write would leave
/// exactly that race.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    create_dir_private(parent)?;

    let tmp = tmp_sibling(path, parent)?;

    // Drop any leftover from a killed run: the 0600 mode below only applies to
    // a freshly created file.
    let _ = std::fs::remove_file(&tmp);

    let result = (|| -> std::io::Result<()> {
        let mut f = create_private_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }

    // Make the rename itself durable. Best effort: not every platform lets you
    // fsync a directory, and failing here does not invalidate the data.
    sync_dir(parent);
    Ok(())
}

/// `write_private`, but the bytes it replaces are overwritten first.
///
/// `write_private` renames a fresh file over `path`; the previous contents are
/// merely unlinked, so a cleartext password stays in the freed blocks until
/// something else claims them. That is fine for an ordinary rewrite and wrong
/// for the one write that strips a secret out of a file, which is what the
/// proxy/tunnel migration does.
///
/// Order is chosen so the data is never only in RAM: the replacement is
/// staged and fsync'd beside `path` first, `path` is then zeroed in place and
/// fsync'd, and only then does the staged file take its place. A crash in the
/// microseconds between the zeroing and the rename leaves `path` zeroed with
/// the complete replacement sitting next to it as `<name>.tmp<pid>` — the
/// secrets themselves are already in the vault by that point, so what is at
/// risk is the recoverable non-secret half.
pub fn write_private_scrubbing(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    create_dir_private(parent)?;

    let tmp = tmp_sibling(path, parent)?;
    let _ = std::fs::remove_file(&tmp);

    let staged = (|| -> std::io::Result<()> {
        let mut f = create_private_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // The replacement is durable now, so destroying the old bytes is safe.
    scrub_file(path);

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(parent);
    Ok(())
}

/// `<name>.tmp<pid>` next to `path`, so the final rename never crosses a
/// filesystem and two processes cannot collide on the same staging file.
fn tmp_sibling(path: &Path, parent: &Path) -> std::io::Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".tmp{}", std::process::id()));
    Ok(parent.join(tmp_name))
}

/// Overwrite an existing file's bytes with zeros, in place. Best effort: a
/// missing file, a read-only file or a short write is not worth failing the
/// caller over, and on a copy-on-write filesystem this is a courtesy anyway.
fn scrub_file(path: &Path) {
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return,
    };
    if len == 0 {
        return;
    }
    let mut f = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let zeros = [0u8; 8192];
    let mut left = len;
    while left > 0 {
        let n = std::cmp::min(left, zeros.len() as u64) as usize;
        if f.write_all(&zeros[..n]).is_err() {
            return;
        }
        left -= n as u64;
    }
    let _ = f.sync_all();
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConnectionConfig {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub color: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
}

/// Safe version without secrets - sent to frontend for listing
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConnectionInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: String,
    pub group: String,
    pub color: String,
    #[serde(default)]
    pub proxy_id: Option<String>,
}

impl From<&ConnectionConfig> for ConnectionInfo {
    fn from(c: &ConnectionConfig) -> Self {
        ConnectionInfo {
            id: c.id.clone(),
            name: c.name.clone(),
            host: c.host.clone(),
            port: c.port,
            username: c.username.clone(),
            auth_type: c.auth_type.clone(),
            group: c.group.clone(),
            color: c.color.clone(),
            proxy_id: c.proxy_id.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct VaultFile {
    pub header: VaultHeader,
    pub connections: HashMap<String, EncryptedBlob>,
    /// Credentials that belong to something other than a connection — today
    /// proxies (`proxy:<id>`) and tunnels (`tunnel:<id>`). Same DEK, same
    /// AES-256-GCM envelope as `connections`.
    ///
    /// `default` so a vault written before this field existed keeps loading.
    #[serde(default)]
    pub secrets: HashMap<String, EncryptedBlob>,
}

/// The three credential fields a proxy or tunnel used to carry inline.
///
/// `private_key` is the *path* to a key file rather than the key itself, but it
/// moves with the other two: knowing which key opens which bastion is half the
/// answer, and splitting the group would leave a config that is only partly
/// readable while the vault is locked.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxySecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

impl ProxySecret {
    /// Nothing worth storing — the entry authenticates some other way, or the
    /// user cleared the fields.
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.private_key.is_none() && self.passphrase.is_none()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedBlob {
    pub nonce: String,
    pub data: String,
}

/// AES-256-GCM's nonce length, in bytes.
const GCM_NONCE_LEN: usize = 12;

impl EncryptedBlob {
    /// Whether `nonce` decodes to exactly one AES-GCM nonce.
    ///
    /// `CryptoEngine::decrypt` hands the decoded bytes to `Nonce::from_slice`,
    /// which panics on any other length instead of returning an error. `open`
    /// checks first, because a sealed blob is read back from a file that can
    /// hold anything.
    fn has_well_formed_nonce(&self) -> bool {
        BASE64
            .decode(&self.nonce)
            .is_ok_and(|n| n.len() == GCM_NONCE_LEN)
    }
}

pub struct ConnectionStore {
    crypto: RwLock<CryptoEngine>,
    vault_path: PathBuf,
}

impl ConnectionStore {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("neoshell");

        // Ensure the directory exists, owner-only
        if let Err(e) = create_dir_private(&data_dir) {
            eprintln!("Warning: failed to create data dir {:?}: {}", data_dir, e);
        }

        let store = Self::with_vault_path(data_dir.join("vault.json"));
        // A vault written by an older build is 0644 on disk; narrow it now
        // rather than waiting for the next save to rewrite it.
        tighten_permissions(&store.vault_path);
        tighten_permissions(&store.backup_path());
        store
    }

    /// Build a store around an explicit vault path. `new()` is the normal entry
    /// point; this exists so tests can point at a scratch directory.
    pub(crate) fn with_vault_path(vault_path: PathBuf) -> Self {
        ConnectionStore {
            crypto: RwLock::new(CryptoEngine::new()),
            vault_path,
        }
    }

    /// The single retained previous generation, `vault.json.1`.
    fn backup_path(&self) -> PathBuf {
        let mut name = self
            .vault_path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| std::ffi::OsString::from("vault.json"));
        name.push(".1");
        self.vault_path.with_file_name(name)
    }

    /// Check if the vault file exists on disk
    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Initialize vault with a new master password
    pub fn set_master_password(&self, password: &str) -> Result<(), String> {
        if self.vault_exists() {
            return Err("Master password is already set. Vault exists.".to_string());
        }

        let mut crypto = self.crypto.write();
        let header = crypto.init_vault(password)?;

        let vault = VaultFile {
            header,
            connections: HashMap::new(),
            secrets: HashMap::new(),
        };

        self.save_vault(&vault)
    }

    /// Verify a master password against the stored vault
    pub fn verify_master_password(&self, password: &str) -> Result<bool, String> {
        if !self.vault_exists() {
            return Err("No vault found. Set a master password first.".to_string());
        }

        let vault = self.load_vault()?;
        let mut crypto = self.crypto.write();
        crypto.unlock(password, &vault.header)
    }

    /// Unlock the vault with the master password (keeps DEK in memory)
    pub fn unlock(&self, password: &str) -> Result<bool, String> {
        if !self.vault_exists() {
            return Err("No vault found. Set a master password first.".to_string());
        }

        let vault = self.load_vault()?;
        let mut crypto = self.crypto.write();
        crypto.unlock(password, &vault.header)
    }

    pub fn is_unlocked(&self) -> bool {
        self.crypto.read().is_unlocked()
    }

    /// Re-lock the vault, wiping the in-memory DEK.
    ///
    /// Nothing on disk changes; every later read has to go through `unlock`
    /// again. This is what the manual "Lock now" action and the idle timeout
    /// call, so the key does not sit in memory for the life of a process that
    /// deliberately outlives its window.
    pub fn lock(&self) {
        self.crypto.write().lock();
    }

    /// Save a new connection. Generates a UUID if id is empty. Returns the id.
    pub fn save_connection(&self, mut config: ConnectionConfig) -> Result<String, String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        if config.id.is_empty() {
            config.id = uuid::Uuid::new_v4().to_string();
        }

        let id = config.id.clone();

        // Serialize the full config to JSON. This buffer holds the password /
        // passphrase in the clear, so it is wiped when it goes out of scope.
        let json = Zeroizing::new(
            serde_json::to_vec(&config)
                .map_err(|e| format!("Failed to serialize connection: {}", e))?,
        );

        // Encrypt with DEK
        let crypto = self.crypto.read();
        let (nonce, data) = crypto.encrypt(json.as_slice())?;

        let blob = EncryptedBlob { nonce, data };

        let mut vault = self.load_vault()?;
        vault.connections.insert(id.clone(), blob);
        drop(crypto);
        self.save_vault(&vault)?;

        Ok(id)
    }

    /// Get all connections as safe ConnectionInfo (no secrets)
    pub fn get_connections(&self) -> Result<Vec<ConnectionInfo>, String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let vault = self.load_vault()?;
        let crypto = self.crypto.read();
        let mut connections = Vec::new();

        for (_id, blob) in &vault.connections {
            let plaintext = crypto.decrypt(&blob.nonce, &blob.data)?;
            let config: ConnectionConfig = serde_json::from_slice(plaintext.as_slice())
                .map_err(|e| format!("Failed to deserialize connection: {}", e))?;
            connections.push(ConnectionInfo::from(&config));
        }

        Ok(connections)
    }

    /// Get a single connection with full secrets (for SSH connect)
    pub fn get_connection(&self, id: &str) -> Result<ConnectionConfig, String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let vault = self.load_vault()?;
        let blob = vault.connections.get(id)
            .ok_or_else(|| format!("Connection '{}' not found", id))?;

        let crypto = self.crypto.read();
        let plaintext = crypto.decrypt(&blob.nonce, &blob.data)?;
        let config: ConnectionConfig = serde_json::from_slice(plaintext.as_slice())
            .map_err(|e| format!("Failed to deserialize connection: {}", e))?;

        Ok(config)
    }

    /// Delete a connection by id
    pub fn delete_connection(&self, id: &str) -> Result<(), String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let mut vault = self.load_vault()?;
        if vault.connections.remove(id).is_none() {
            return Err(format!("Connection '{}' not found", id));
        }
        self.save_vault(&vault)
    }

    /// Update an existing connection
    pub fn update_connection(&self, config: ConnectionConfig) -> Result<(), String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let mut vault = self.load_vault()?;
        if !vault.connections.contains_key(&config.id) {
            return Err(format!("Connection '{}' not found", config.id));
        }

        let json = Zeroizing::new(
            serde_json::to_vec(&config)
                .map_err(|e| format!("Failed to serialize connection: {}", e))?,
        );

        let crypto = self.crypto.read();
        let (nonce, data) = crypto.encrypt(json.as_slice())?;
        drop(crypto);

        vault.connections.insert(config.id.clone(), EncryptedBlob { nonce, data });
        self.save_vault(&vault)
    }

    /// Store a proxy/tunnel credential under `key` (`proxy:<id>` or
    /// `tunnel:<id>`). Replaces whatever was there.
    pub fn put_secret(&self, key: &str, value: &ProxySecret) -> Result<(), String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        // Holds the password in the clear, so it is wiped on the way out.
        let json = Zeroizing::new(
            serde_json::to_vec(value).map_err(|e| format!("Failed to serialize secret: {}", e))?,
        );

        let crypto = self.crypto.read();
        let (nonce, data) = crypto.encrypt(json.as_slice())?;
        drop(crypto);

        let mut vault = self.load_vault()?;
        vault.secrets.insert(key.to_string(), EncryptedBlob { nonce, data });
        self.save_vault(&vault)
    }

    /// Read a stored credential. `Ok(None)` means no secret is filed under
    /// `key` — an entry that authenticates without one — which is a different
    /// answer from `Err`, i.e. the vault could not be read at all.
    pub fn get_secret(&self, key: &str) -> Result<Option<ProxySecret>, String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let vault = self.load_vault()?;
        let blob = match vault.secrets.get(key) {
            Some(b) => b,
            None => return Ok(None),
        };

        let crypto = self.crypto.read();
        let plaintext = crypto.decrypt(&blob.nonce, &blob.data)?;
        serde_json::from_slice(plaintext.as_slice())
            .map(Some)
            .map_err(|e| format!("Failed to deserialize secret: {}", e))
    }

    /// Drop a stored credential. Removing one that is not there succeeds: the
    /// callers use this to clear a field the user emptied, and to tidy up
    /// after a delete, neither of which knows whether a secret existed.
    pub fn delete_secret(&self, key: &str) -> Result<(), String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let mut vault = self.load_vault()?;
        if vault.secrets.remove(key).is_none() {
            return Ok(());
        }
        self.save_vault(&vault)
    }

    /// Encrypt `plaintext` under the vault DEK, for data kept outside
    /// vault.json that should be no easier to read than the vault itself —
    /// the persisted command history, whose command lines can carry hosts,
    /// paths and the odd password passed as an argument.
    ///
    /// Same key and AES-256-GCM envelope as a connection, with a fresh random
    /// nonce per call, so sealing the same bytes twice never yields the same
    /// blob. Nothing is written to disk; where the blob goes is up to the
    /// caller.
    pub fn seal(&self, plaintext: &[u8]) -> Result<EncryptedBlob, String> {
        // Check and encrypt under one guard, so an idle re-lock cannot land
        // in between.
        let crypto = self.crypto.read();
        if !crypto.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        let (nonce, data) = crypto.encrypt(plaintext)?;
        Ok(EncryptedBlob { nonce, data })
    }

    /// Decrypt a blob made by `seal`. The plaintext is wiped when dropped.
    ///
    /// A blob this vault did not produce, or one changed since — a flipped
    /// bit, a torn write, a nonce from another blob, a blob from another
    /// vault — comes back as `Err`, never as partial plaintext.
    pub fn open(&self, blob: &EncryptedBlob) -> Result<Zeroizing<Vec<u8>>, String> {
        let crypto = self.crypto.read();
        if !crypto.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }
        if !blob.has_well_formed_nonce() {
            return Err(format!(
                "Malformed sealed blob: nonce is not {} bytes",
                GCM_NONCE_LEN
            ));
        }
        crypto.decrypt(&blob.nonce, &blob.data)
    }

    fn load_vault(&self) -> Result<VaultFile, String> {
        let primary_err = match std::fs::read_to_string(&self.vault_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(vault) => return Ok(vault),
                Err(e) => format!("Failed to parse vault file: {}", e),
            },
            Err(e) => format!("Failed to read vault file: {}", e),
        };

        // vault.json is missing or unreadable — fall back to the one retained
        // generation rather than reporting every connection as lost.
        let backup = self.backup_path();
        if let Ok(content) = std::fs::read_to_string(&backup) {
            if let Ok(vault) = serde_json::from_str::<VaultFile>(&content) {
                log::error!(
                    "{} — recovered from previous generation {}",
                    primary_err,
                    backup.display()
                );
                return Ok(vault);
            }
        }

        Err(primary_err)
    }

    fn save_vault(&self, vault: &VaultFile) -> Result<(), String> {
        let json = serde_json::to_string_pretty(vault)
            .map_err(|e| format!("Failed to serialize vault: {}", e))?;

        // Retain exactly one previous generation. Copy rather than rename, so
        // vault.json is never momentarily absent: vault_exists() is what picks
        // the Locked screen over Setup, and a missing file there looks like a
        // brand new install. Only retain a generation that parses — if
        // load_vault just recovered from the backup, copying the corrupt
        // primary over it would throw away the one recoverable copy.
        if let Ok(previous) = std::fs::read(&self.vault_path) {
            if serde_json::from_slice::<VaultFile>(&previous).is_ok() {
                if let Err(e) = write_private(&self.backup_path(), &previous) {
                    log::warn!("failed to retain previous vault generation: {}", e);
                }
            }
        }

        write_private(&self.vault_path, json.as_bytes())
            .map_err(|e| format!("Failed to write vault file: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PW: &str = "correct horse battery staple";

    /// A fresh scratch directory per test, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "neoshell-store-test-{}-{}-{}",
                std::process::id(),
                tag,
                N.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn vault(&self) -> PathBuf {
            self.0.join("vault.json")
        }

        fn store(&self) -> ConnectionStore {
            ConnectionStore::with_vault_path(self.vault())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample(name: &str) -> ConnectionConfig {
        ConnectionConfig {
            id: String::new(),
            name: name.to_string(),
            host: "10.0.0.1".to_string(),
            port: 22,
            username: "root".to_string(),
            auth_type: "password".to_string(),
            password: Some("hunter2".to_string()),
            private_key: None,
            passphrase: None,
            group: String::new(),
            color: String::new(),
            proxy_id: None,
        }
    }

    #[test]
    fn set_password_then_unlock_and_round_trip_a_connection() {
        let s = Scratch::new("roundtrip");
        let store = s.store();
        assert!(!store.vault_exists());
        store.set_master_password(PW).unwrap();
        assert!(store.vault_exists());

        let id = store.save_connection(sample("prod")).unwrap();

        // A separate store proves it survived the disk round trip.
        let reopened = s.store();
        assert!(!reopened.is_unlocked());
        assert!(reopened.unlock(PW).unwrap());

        let list = reopened.get_connections().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "prod");

        let full = reopened.get_connection(&id).unwrap();
        assert_eq!(full.password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn wrong_master_password_is_rejected_and_leaves_the_store_locked() {
        let s = Scratch::new("wrongpw");
        let store = s.store();
        store.set_master_password(PW).unwrap();

        let reopened = s.store();
        assert!(reopened.unlock("wrong").is_err());
        assert!(!reopened.is_unlocked());
        assert!(reopened.get_connections().is_err());
    }

    #[test]
    fn secrets_are_not_stored_in_the_clear() {
        let s = Scratch::new("ciphertext");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        store.save_connection(sample("prod")).unwrap();

        let raw = std::fs::read_to_string(s.vault()).unwrap();
        assert!(!raw.contains("hunter2"));
        assert!(!raw.contains("10.0.0.1"));
    }

    #[test]
    fn locked_store_refuses_every_mutation() {
        let s = Scratch::new("locked");
        let store = s.store();
        store.set_master_password(PW).unwrap();

        let locked = s.store();
        assert!(locked.save_connection(sample("x")).is_err());
        assert!(locked.delete_connection("x").is_err());
        assert!(locked.get_connection("x").is_err());
    }

    #[test]
    fn save_keeps_one_previous_generation() {
        let s = Scratch::new("generation");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        // The very first write has nothing to retain.
        assert!(!store.backup_path().exists());

        store.save_connection(sample("a")).unwrap();
        assert!(store.backup_path().exists());
    }

    /// The atomic-write payoff: a vault.json truncated by a crash mid-write is
    /// recoverable from the retained generation instead of losing the vault.
    #[test]
    fn truncated_vault_recovers_from_the_retained_generation() {
        let s = Scratch::new("partial");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        store.save_connection(sample("a")).unwrap();
        store.save_connection(sample("b")).unwrap();

        // Simulate a partial write: the O_TRUNC window std::fs::write used to
        // leave open, i.e. a half-serialized file.
        let full = std::fs::read_to_string(s.vault()).unwrap();
        std::fs::write(s.vault(), &full[..full.len() / 2]).unwrap();

        let reopened = s.store();
        assert!(reopened.unlock(PW).unwrap(), "master password must survive a torn write");
        let names: Vec<String> = reopened
            .get_connections()
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert!(names.contains(&"a".to_string()), "got {:?}", names);
    }

    #[test]
    fn the_retained_generation_is_itself_a_complete_vault() {
        let s = Scratch::new("missing");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        store.save_connection(sample("a")).unwrap();

        // Restoring vault.json.1 by hand must produce a working vault.
        std::fs::remove_file(s.vault()).unwrap();
        std::fs::copy(store.backup_path(), s.vault()).unwrap();

        let reopened = s.store();
        assert!(reopened.unlock(PW).unwrap());
    }

    #[test]
    fn a_corrupt_vault_with_no_backup_reports_an_error_rather_than_panicking() {
        let s = Scratch::new("corrupt");
        std::fs::write(s.vault(), "{not json").unwrap();
        let store = s.store();
        assert!(store.unlock(PW).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn vault_and_backup_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("perms");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        store.save_connection(sample("a")).unwrap();

        for p in [s.vault(), store.backup_path()] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{:?} is mode {:o}", p, mode);
        }
    }

    #[cfg(unix)]
    #[test]
    fn tighten_permissions_narrows_a_legacy_world_readable_vault() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("tighten");
        // Exactly what a pre-0.7.0 std::fs::write left behind.
        std::fs::write(s.vault(), "{}").unwrap();
        std::fs::set_permissions(s.vault(), std::fs::Permissions::from_mode(0o644)).unwrap();

        tighten_permissions(&s.vault());
        assert_eq!(
            std::fs::metadata(s.vault()).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Already-narrow files are left alone, and a missing path is a no-op.
        tighten_permissions(&s.vault());
        assert_eq!(
            std::fs::metadata(s.vault()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        tighten_permissions(&s.0.join("nope.json"));
    }

    #[cfg(unix)]
    #[test]
    fn write_private_creates_owner_only_files_and_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("writeprivate");
        let nested = s.0.join("a").join("b");
        let target = nested.join("secret.json");

        write_private(&target, b"payload").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"payload");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // Overwriting keeps the mode and leaves no temp file behind.
        write_private(&target, b"second").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second");
        let leftovers: Vec<_> = std::fs::read_dir(&nested)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {:?}", leftovers);
    }

    #[test]
    fn delete_and_update_round_trip() {
        let s = Scratch::new("crud");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        let id = store.save_connection(sample("a")).unwrap();

        let mut cfg = store.get_connection(&id).unwrap();
        cfg.name = "renamed".to_string();
        cfg.password = Some("new-secret".to_string());
        store.update_connection(cfg).unwrap();
        assert_eq!(store.get_connection(&id).unwrap().name, "renamed");
        assert_eq!(
            store.get_connection(&id).unwrap().password.as_deref(),
            Some("new-secret")
        );

        store.delete_connection(&id).unwrap();
        assert!(store.get_connection(&id).is_err());
        assert!(store.delete_connection(&id).is_err());
    }

    // -- proxy/tunnel secrets ------------------------------------------------

    fn secret() -> ProxySecret {
        ProxySecret {
            password: Some("bastion-pw".to_string()),
            private_key: Some("/home/u/.ssh/id_ed25519".to_string()),
            passphrase: Some("key-phrase".to_string()),
        }
    }

    #[test]
    fn secrets_round_trip_and_are_encrypted_on_disk() {
        let s = Scratch::new("secret-roundtrip");
        let store = s.store();
        store.set_master_password(PW).unwrap();

        assert_eq!(store.get_secret("proxy:a").unwrap(), None);
        store.put_secret("proxy:a", &secret()).unwrap();

        let raw = std::fs::read_to_string(s.vault()).unwrap();
        assert!(!raw.contains("bastion-pw"));
        assert!(!raw.contains("key-phrase"));

        let reopened = s.store();
        assert!(reopened.unlock(PW).unwrap());
        assert_eq!(reopened.get_secret("proxy:a").unwrap(), Some(secret()));

        // Replacing is a plain overwrite, and connections are untouched by it.
        let narrowed = ProxySecret { password: Some("new".into()), ..Default::default() };
        reopened.put_secret("proxy:a", &narrowed).unwrap();
        assert_eq!(reopened.get_secret("proxy:a").unwrap(), Some(narrowed));
    }

    #[test]
    fn delete_secret_is_idempotent_and_leaves_others_alone() {
        let s = Scratch::new("secret-delete");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        store.put_secret("proxy:a", &secret()).unwrap();
        store.put_secret("tunnel:b", &secret()).unwrap();

        store.delete_secret("proxy:a").unwrap();
        assert_eq!(store.get_secret("proxy:a").unwrap(), None);
        // Deleting what is not there is success, not an error.
        store.delete_secret("proxy:a").unwrap();
        store.delete_secret("proxy:never-existed").unwrap();
        assert_eq!(store.get_secret("tunnel:b").unwrap(), Some(secret()));
    }

    #[test]
    fn a_locked_vault_refuses_every_secret_operation() {
        let s = Scratch::new("secret-locked");
        let store = s.store();
        store.set_master_password(PW).unwrap();

        let locked = s.store();
        assert!(locked.get_secret("proxy:a").is_err());
        assert!(locked.put_secret("proxy:a", &secret()).is_err());
        assert!(locked.delete_secret("proxy:a").is_err());
    }

    /// A vault.json written before `secrets` existed has no such key. It must
    /// still deserialize, or the upgrade locks the user out of everything.
    #[test]
    fn a_vault_without_the_secrets_field_still_loads() {
        let s = Scratch::new("secret-compat");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        let id = store.save_connection(sample("prod")).unwrap();

        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(s.vault()).unwrap()).unwrap();
        raw.as_object_mut().unwrap().remove("secrets").unwrap();
        std::fs::write(s.vault(), serde_json::to_string_pretty(&raw).unwrap()).unwrap();

        let reopened = s.store();
        assert!(reopened.unlock(PW).unwrap());
        assert_eq!(reopened.get_connection(&id).unwrap().name, "prod");
        assert_eq!(reopened.get_secret("proxy:a").unwrap(), None);
        // And writing one into it works from there on.
        reopened.put_secret("proxy:a", &secret()).unwrap();
        assert_eq!(reopened.get_secret("proxy:a").unwrap(), Some(secret()));
    }

    /// The other half of the downgrade note in README.md: a pre-0.7.0 build
    /// writes vault.json back without `secrets`, because its `VaultFile` has
    /// no such field. This build must carry the map through every rewrite —
    /// the bare load/save round trip, and each connection mutation that loads,
    /// modifies and saves the whole file.
    #[test]
    fn the_secrets_map_survives_every_vault_rewrite() {
        let s = Scratch::new("secret-survives");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        store.put_secret("proxy:a", &secret()).unwrap();
        store.put_secret("tunnel:b", &secret()).unwrap();

        let vault = store.load_vault().unwrap();
        assert_eq!(vault.secrets.len(), 2);
        store.save_vault(&vault).unwrap();

        let id = store.save_connection(sample("a")).unwrap();
        let mut cfg = store.get_connection(&id).unwrap();
        cfg.name = "renamed".to_string();
        store.update_connection(cfg).unwrap();
        store.delete_connection(&id).unwrap();

        // On disk, in the live file and in the retained generation alike.
        for path in [s.vault(), store.backup_path()] {
            let raw: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let map = raw["secrets"]
                .as_object()
                .unwrap_or_else(|| panic!("{} has no secrets map", path.display()));
            assert!(
                map.contains_key("proxy:a") && map.contains_key("tunnel:b"),
                "{} lost a secret: {:?}",
                path.display(),
                map.keys().collect::<Vec<_>>()
            );
        }

        // And a fresh process still decrypts them.
        let reopened = s.store();
        assert!(reopened.unlock(PW).unwrap());
        assert_eq!(reopened.get_secret("proxy:a").unwrap(), Some(secret()));
        assert_eq!(reopened.get_secret("tunnel:b").unwrap(), Some(secret()));
    }

    #[test]
    fn scrub_file_zeroes_the_bytes_in_place() {
        let s = Scratch::new("scrub");
        let f = s.0.join("cleartext.json");
        std::fs::write(&f, b"password=hunter2").unwrap();

        scrub_file(&f);
        assert_eq!(std::fs::read(&f).unwrap(), vec![0u8; 16]);

        // Missing and empty files are no-ops rather than failures.
        scrub_file(&s.0.join("nope"));
        let empty = s.0.join("empty");
        std::fs::write(&empty, b"").unwrap();
        scrub_file(&empty);
    }

    #[test]
    fn write_private_scrubbing_replaces_the_file_contents() {
        let s = Scratch::new("scrubwrite");
        let f = s.0.join("nested").join("proxies.json");
        write_private_scrubbing(&f, b"[{\"password\":\"hunter2\"}]").unwrap();
        write_private_scrubbing(&f, b"{\"schema\":1}").unwrap();

        assert_eq!(std::fs::read(&f).unwrap(), b"{\"schema\":1}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let leftovers: Vec<_> = std::fs::read_dir(f.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {:?}", leftovers);
    }

    // -- sealed blobs --------------------------------------------------------

    #[test]
    fn a_sealed_blob_round_trips_under_the_vault_dek() {
        let s = Scratch::new("seal-roundtrip");
        let store = s.store();
        store.set_master_password(PW).unwrap();

        let history = br#"[{"cmd":"mysql -u root -phunter2"}]"#;
        let blob = store.seal(history).unwrap();
        assert_eq!(store.open(&blob).unwrap().as_slice(), &history[..]);
        assert!(!serde_json::to_string(&blob).unwrap().contains("hunter2"));

        // A fresh nonce every time: the same bytes never seal to the same blob.
        let again = store.seal(history).unwrap();
        assert_ne!(blob.nonce, again.nonce);
        assert_ne!(blob.data, again.data);

        // The vault's own DEK, not a per-process key: a second store over the
        // same vault.json opens it once unlocked.
        let reopened = s.store();
        assert!(reopened.unlock(PW).unwrap());
        assert_eq!(reopened.open(&blob).unwrap().as_slice(), &history[..]);

        // An empty payload is still a payload.
        assert!(store.open(&store.seal(b"").unwrap()).unwrap().is_empty());
    }

    #[test]
    fn a_locked_vault_refuses_to_seal_or_open() {
        let s = Scratch::new("seal-locked");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        let blob = store.seal(b"ls -la").unwrap();

        let locked = s.store();
        let err = locked
            .seal(b"ls -la")
            .err()
            .expect("seal must refuse while locked");
        assert!(
            err.to_lowercase().contains("vault is locked"),
            "unexpected error: {}",
            err
        );
        let err = locked.open(&blob).unwrap_err();
        assert!(
            err.to_lowercase().contains("vault is locked"),
            "unexpected error: {}",
            err
        );

        // The idle re-lock: a store that was open refuses the same way...
        store.lock();
        assert!(store.seal(b"x").is_err());
        assert!(store
            .open(&blob)
            .unwrap_err()
            .to_lowercase()
            .contains("vault is locked"));
        // ...and loses nothing by it.
        assert!(store.unlock(PW).unwrap());
        assert_eq!(store.open(&blob).unwrap().as_slice(), b"ls -la");
    }

    #[test]
    fn a_tampered_sealed_blob_is_rejected() {
        let s = Scratch::new("seal-tamper");
        let store = s.store();
        store.set_master_password(PW).unwrap();
        let blob = store.seal(b"ssh root@10.0.0.1").unwrap();
        let other = store.seal(b"ssh root@10.0.0.2").unwrap();

        let flip = |b64: &str| {
            let mut raw = BASE64.decode(b64).unwrap();
            raw[0] ^= 0x01;
            BASE64.encode(raw)
        };
        let forged = |nonce: String, data: String| EncryptedBlob { nonce, data };

        // One flipped bit in the ciphertext, or in the nonce.
        assert!(store
            .open(&forged(blob.nonce.clone(), flip(&blob.data)))
            .is_err());
        assert!(store
            .open(&forged(flip(&blob.nonce), blob.data.clone()))
            .is_err());
        // A torn write.
        let mut short = BASE64.decode(&blob.data).unwrap();
        short.truncate(short.len() - 1);
        assert!(store
            .open(&forged(blob.nonce.clone(), BASE64.encode(short)))
            .is_err());
        // A nonce lifted from another blob.
        assert!(store
            .open(&forged(other.nonce.clone(), blob.data.clone()))
            .is_err());
        // Not base64, or a nonce of the wrong length: an error, not a panic
        // inside aes-gcm.
        assert!(store
            .open(&forged("not base64!".into(), blob.data.clone()))
            .is_err());
        for len in [0, 8, 16] {
            let nonce = BASE64.encode(vec![0u8; len]);
            assert!(
                store.open(&forged(nonce, blob.data.clone())).is_err(),
                "{}-byte nonce",
                len
            );
        }

        // Right shape, wrong key: a blob sealed by another vault.
        let elsewhere = Scratch::new("seal-tamper-foreign");
        let foreign = elsewhere.store();
        foreign.set_master_password(PW).unwrap();
        assert!(store
            .open(&foreign.seal(b"ssh root@10.0.0.1").unwrap())
            .is_err());

        // The untouched blob still opens, so every rejection above was earned.
        assert_eq!(store.open(&blob).unwrap().as_slice(), b"ssh root@10.0.0.1");
    }
}
