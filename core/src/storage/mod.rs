use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use parking_lot::RwLock;
use zeroize::Zeroizing;

use crate::crypto::{CryptoEngine, VaultHeader};

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

    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".tmp{}", std::process::id()));
    let tmp = parent.join(tmp_name);

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
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedBlob {
    pub nonce: String,
    pub data: String,
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
    fn with_vault_path(vault_path: PathBuf) -> Self {
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
}
