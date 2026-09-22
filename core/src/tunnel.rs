//! SSH tunnel manager — persistent local port forwarding through an SSH
//! jump host to an internal target. Each tunnel runs in its own background
//! thread with its own SSH session; lifecycle is independent of the terminal
//! tabs (a tunnel can be active without any open SSH shell tab).
//!
//! Config inspired by https://github.com/uk0/sshrw — a single SSH session
//! carries one or more forwards. Three kinds exist, matching the SSH client's
//! `-L`, `-R` and `-D`:
//!
//! * local   — a `TcpListener` here, `direct-tcpip` out of the jump host;
//! * remote  — `channel_forward_listen` on the jump host, a local `TcpStream` per channel;
//! * dynamic — a `TcpListener` here speaking SOCKS5, target chosen per connection.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::storage::{ConnectionStore, ProxySecret};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TunnelConfig {
    pub id: String,
    pub name: String,
    /// SSH jump host
    pub ssh_host: String,
    pub ssh_port: u16,
    pub username: String,
    pub auth_type: String, // "password" | "key"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    /// One or more port forwards through this SSH session.
    pub forwards: Vec<ForwardRule>,
    /// If true, the tunnel auto-starts when the app opens.
    #[serde(default)]
    pub auto_start: bool,
}

/// Which direction a rule forwards in — the SSH client's `-L`, `-R` and `-D`.
///
/// `Local` is the default so that a `tunnels.json` written by a build that
/// only knew local forwards keeps parsing: those entries have no `kind` field
/// and `#[serde(default)]` on `ForwardRule::kind` fills it in.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    /// `-L` — we listen locally, the jump host opens the connection.
    #[default]
    Local,
    /// `-R` — the jump host listens, we open the connection locally.
    Remote,
    /// `-D` — we listen locally speaking SOCKS5; the client picks the target.
    Dynamic,
}

/// One port forward. What the three numbers mean depends on `kind`:
///
/// * `Local`   — bind `127.0.0.1:local_port`, jump host dials `remote_host:remote_port`.
/// * `Remote`  — jump host binds `remote_host:remote_port`, we dial `127.0.0.1:local_port`.
///   An empty `remote_host` means the jump host's loopback, as with `ssh -R`.
/// * `Dynamic` — bind `127.0.0.1:local_port` as a SOCKS5 proxy; `remote_*` unused.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ForwardRule {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    #[serde(default)]
    pub kind: ForwardKind,
}

impl ForwardRule {
    /// Parse one rule. Accepted forms, case-insensitive on the prefix:
    ///
    /// * `LOCAL:REMOTE_HOST:REMOTE_PORT`         — local forward (`-L`)
    /// * `REMOTE_HOST:REMOTE_PORT->LOCAL_PORT`   — local forward, sshrw arrow syntax
    /// * `R:LOCAL_PORT:REMOTE_HOST:REMOTE_PORT`  — remote forward (`-R`)
    /// * `D:LOCAL_PORT`                          — dynamic SOCKS5 forward (`-D`)
    ///
    /// `R:` keeps the field order of the compact form on purpose: the first
    /// number is always the local port, the last two are always the remote
    /// endpoint, and only the direction of travel changes.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        // `get(..2)` rather than indexing: a one-byte or non-ASCII input must
        // fall through to the local parser, not panic on a char boundary.
        let (kind, body) = match s.get(..2) {
            Some(p) if p.eq_ignore_ascii_case("r:") => (ForwardKind::Remote, s[2..].trim()),
            Some(p) if p.eq_ignore_ascii_case("d:") => (ForwardKind::Dynamic, s[2..].trim()),
            _ => (ForwardKind::Local, s),
        };

        if kind == ForwardKind::Dynamic {
            let port = body.parse::<u16>().map_err(|e| crate::i18n::tf(
                "tunnel.err.bad_socks_port", &[("port", body), ("err", &e.to_string())]))?;
            if port == 0 {
                return Err(crate::i18n::t("tunnel.err.socks_port_zero").to_string());
            }
            return Ok(ForwardRule {
                local_port: port,
                remote_host: String::new(),
                remote_port: 0,
                kind,
            });
        }

        if let Some((remote, local)) = body.split_once("->") {
            let (rh, rp) = remote.trim().rsplit_once(':')
                .ok_or_else(|| crate::i18n::tf("tunnel.err.bad_remote", &[("remote", remote.trim())]))?;
            let rp = rp.trim();
            let rp = rp.parse::<u16>().map_err(|e| crate::i18n::tf(
                "tunnel.err.bad_remote_port", &[("port", rp), ("err", &e.to_string())]))?;
            let lp = local.trim().split_once(':')
                .map(|(_h, p)| p.trim()).unwrap_or(local.trim());
            let lp = lp.parse::<u16>().map_err(|e| crate::i18n::tf(
                "tunnel.err.bad_local_port", &[("port", lp), ("err", &e.to_string())]))?;
            Ok(ForwardRule { local_port: lp, remote_host: rh.trim().to_string(), remote_port: rp, kind })
        } else {
            let parts: Vec<&str> = body.split(':').collect();
            if parts.len() != 3 {
                return Err(crate::i18n::tf("tunnel.err.bad_rule", &[("rule", s)]));
            }
            let host = parts[1].trim();
            // A remote forward may leave the bind host empty: loopback on the
            // jump host, as with `ssh -R` (see `remote_bind_host`). A local
            // forward has nothing to dial without one.
            if host.is_empty() && kind == ForwardKind::Local {
                return Err(crate::i18n::tf("tunnel.err.missing_host", &[("rule", s)]));
            }
            let (lp, rp) = (parts[0].trim(), parts[2].trim());
            Ok(ForwardRule {
                local_port: lp.parse::<u16>().map_err(|e| crate::i18n::tf(
                    "tunnel.err.bad_local_port", &[("port", lp), ("err", &e.to_string())]))?,
                remote_host: host.to_string(),
                remote_port: rp.parse::<u16>().map_err(|e| crate::i18n::tf(
                    "tunnel.err.bad_remote_port", &[("port", rp), ("err", &e.to_string())]))?,
                kind,
            })
        }
    }

    /// Render back into the syntax `parse` accepts.
    ///
    /// The rule list is edited as text, so a rule that cannot be printed in a
    /// form `parse` understands would silently downgrade to `Local` on the
    /// next save. Use this instead of hand-formatting the three fields.
    pub fn spec(&self) -> String {
        match self.kind {
            ForwardKind::Local => format!("{}:{}:{}", self.local_port, self.remote_host, self.remote_port),
            ForwardKind::Remote => format!("R:{}:{}:{}", self.local_port, self.remote_host, self.remote_port),
            ForwardKind::Dynamic => format!("D:{}", self.local_port),
        }
    }
}

impl std::fmt::Display for ForwardRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.spec())
    }
}

// ---------------------------------------------------------------------------
// Config store
//
// tunnels.json keeps only what the UI needs to list a tunnel while the vault is
// locked — id, name, jump host, port, username, auth type, forwards, auto_start.
// `password`, `private_key` and `passphrase` live in the vault under
// `tunnel:<id>`, encrypted with the same DEK as a connection. A tunnel opens a
// port straight into an internal network, so its credential deserves the vault
// rather than 0600 alone.
//
// Entries written before 0.7.0 still carry the secret inline; `migrate_secrets`
// moves them across exactly once, and `schema` records that it happened.
// ---------------------------------------------------------------------------

/// On-disk schema for tunnels.json.
///
/// * 0 — bare JSON array, `password` / `private_key` / `passphrase` inline.
/// * 1 — `{ "schema": 1, "tunnels": [...] }`, secrets in the vault.
pub const TUNNEL_SCHEMA: u32 = 1;

/// Vault key holding this tunnel's credentials.
pub fn tunnel_secret_key(id: &str) -> String {
    format!("tunnel:{}", id)
}

/// The schema-1 document. Both fields default, so `{}` and a file written by a
/// future build that adds a field still parse.
#[derive(Serialize, Deserialize, Default)]
struct TunnelFile {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    tunnels: Vec<TunnelConfig>,
}

pub struct TunnelStore {
    path: PathBuf,
    /// An explicitly supplied vault. `None` means "ask the process-wide
    /// registry at the point of use" — `new()` runs inside the app's `Default`,
    /// which is before the vault has been registered.
    vault: Option<Arc<ConnectionStore>>,
}

impl TunnelStore {
    /// The normal entry point. Resolves the process-wide vault lazily.
    pub fn new() -> Self {
        Self::with_vault(None)
    }

    /// `new`, with the vault handle supplied explicitly.
    pub fn with_vault(vault: Option<Arc<ConnectionStore>>) -> Self {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("neoshell");
        if let Err(e) = crate::storage::create_dir_private(&dir) {
            log::error!("failed to create data dir {}: {}", dir.display(), e);
        }
        let store = Self::at(dir.join("tunnels.json"), vault);
        // A file written by a pre-0.7.0 build is 0644 on disk; narrow it now
        // rather than waiting for the next save to rewrite it.
        crate::storage::tighten_permissions(&store.path);
        store
    }

    /// Explicit path — `new()` is the real entry point; this is for tests.
    fn at(path: PathBuf, vault: Option<Arc<ConnectionStore>>) -> Self {
        Self { path, vault }
    }

    /// The vault to use: the explicit handle, else whatever is registered.
    /// `None` once it is locked — a locked vault is no more usable than none.
    fn vault_handle(&self) -> Option<Arc<ConnectionStore>> {
        self.vault
            .clone()
            .or_else(crate::storage::global_vault)
            .filter(|v| v.is_unlocked())
    }

    /// The vault, or the reason it cannot be used. Never falls back to writing
    /// a credential into tunnels.json in the clear.
    fn vault(&self) -> Result<Arc<ConnectionStore>, String> {
        self.vault_handle()
            .ok_or_else(|| crate::i18n::t("vault.locked_secret").to_string())
    }

    fn read_file(&self) -> TunnelFile {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(d) => d,
            // No file yet: nothing to migrate, so start at the current schema.
            Err(_) => return TunnelFile { schema: TUNNEL_SCHEMA, tunnels: Vec::new() },
        };
        if let Ok(file) = serde_json::from_str::<TunnelFile>(&data) {
            return file;
        }
        // Pre-0.7.0 shape: a bare array with the secrets inline.
        match serde_json::from_str::<Vec<TunnelConfig>>(&data) {
            Ok(tunnels) => TunnelFile { schema: 0, tunnels },
            Err(e) => {
                // Report the current schema so nothing rewrites — and thereby
                // destroys — a file we simply failed to understand.
                log::error!("cannot parse {}: {}", self.path.display(), e);
                TunnelFile { schema: TUNNEL_SCHEMA, tunnels: Vec::new() }
            }
        }
    }

    /// Fill in `cfg`'s secrets from the vault. `Err` means they exist but are
    /// out of reach, which is not the same as a tunnel that has none.
    fn resolve_secret(&self, schema: u32, cfg: &mut TunnelConfig) -> Result<(), String> {
        if schema < TUNNEL_SCHEMA {
            return Ok(()); // not migrated yet — the secret is still inline
        }
        if let Some(s) = self.vault()?.get_secret(&tunnel_secret_key(&cfg.id))? {
            cfg.password = s.password;
            cfg.private_key = s.private_key;
            cfg.passphrase = s.passphrase;
        }
        Ok(())
    }

    /// Move `cfg`'s secrets into the vault, leaving `cfg` secret-free and ready
    /// to serialize. Clearing every field deletes the stored secret, so a
    /// password the user emptied in the form does not come back.
    fn store_secret(&self, cfg: &mut TunnelConfig) -> Result<(), String> {
        let secret = ProxySecret {
            password: cfg.password.take(),
            private_key: cfg.private_key.take(),
            passphrase: cfg.passphrase.take(),
        };
        let key = tunnel_secret_key(&cfg.id);
        let vault = self.vault()?;
        if secret.is_empty() {
            vault.delete_secret(&key)
        } else {
            vault.put_secret(&key, &secret)
        }
    }

    /// Every tunnel, with its credentials filled in when the vault allows.
    ///
    /// A tunnel whose secret cannot be read is still listed — the manager panel
    /// has to show it — just without the credential, and starting it then fails
    /// rather than authenticating with nothing.
    pub fn load(&self) -> Vec<TunnelConfig> {
        let mut file = self.read_file();
        for t in file.tunnels.iter_mut() {
            if let Err(e) = self.resolve_secret(file.schema, t) {
                log::debug!("tunnel '{}': credentials unavailable: {}", t.id, e);
            }
        }
        file.tunnels
    }

    fn write(&self, file: &TunnelFile, scrubbing: bool) -> Result<(), String> {
        let json = serde_json::to_string_pretty(file)
            .map_err(|e| format!("cannot serialise tunnels: {}", e))?;
        let write = if scrubbing {
            crate::storage::write_private_scrubbing
        } else {
            crate::storage::write_private
        };
        write(&self.path, json.as_bytes())
            .map_err(|e| format!("cannot write {}: {}", self.path.display(), e))
    }

    /// Move every inline secret into the vault, exactly once.
    ///
    /// Returns whether the file on disk changed. Idempotent: `schema` records
    /// that it ran. A locked vault defers to the next unlock rather than
    /// dropping anything, and the plaintext is only cleared after the vault is
    /// confirmed to hold the secret — a failure anywhere leaves tunnels.json
    /// untouched and the migration is simply retried.
    pub fn migrate_secrets(&self) -> Result<bool, String> {
        let mut file = self.read_file();
        if file.schema >= TUNNEL_SCHEMA {
            return Ok(false);
        }

        let pending = file.tunnels.iter().filter(|t| has_inline_secret(t)).count();
        if pending > 0 {
            let vault = match self.vault_handle() {
                Some(v) => v,
                None => {
                    log::info!(
                        "tunnel store: {} entries still hold an inline credential; \
                         deferring migration until the vault is unlocked",
                        pending
                    );
                    return Ok(false);
                }
            };
            for t in file.tunnels.iter_mut() {
                let secret = ProxySecret {
                    password: t.password.take(),
                    private_key: t.private_key.take(),
                    passphrase: t.passphrase.take(),
                };
                if secret.is_empty() {
                    continue;
                }
                let key = tunnel_secret_key(&t.id);
                vault.put_secret(&key, &secret)?;
                // Read it back before the cleartext is destroyed below.
                if vault.get_secret(&key)?.as_ref() != Some(&secret) {
                    return Err(crate::i18n::tf(
                        "tunnel.err.vault_not_retained",
                        &[("id", &t.id), ("path", &self.path.display().to_string())],
                    ));
                }
            }
        }

        file.schema = TUNNEL_SCHEMA;
        // The bytes being replaced are the ones holding the cleartext.
        self.write(&file, true)?;
        log::info!("tunnel store: migrated {} credentials into the vault", pending);
        Ok(true)
    }

    /// Migrate if needed, then hand back the file — or refuse, because writing
    /// on top of a deferred migration would either strand the secrets that
    /// never moved or mark them migrated when they were not.
    fn file_for_write(&self) -> Result<TunnelFile, String> {
        self.migrate_secrets()?;
        let file = self.read_file();
        if file.schema < TUNNEL_SCHEMA {
            return Err(crate::i18n::t("vault.locked_secret").to_string());
        }
        Ok(file)
    }

    /// Insert or replace one tunnel, its credentials going to the vault.
    pub fn try_upsert(&self, mut cfg: TunnelConfig) -> Result<(), String> {
        let mut file = self.file_for_write()?;
        self.store_secret(&mut cfg)?;
        if let Some(existing) = file.tunnels.iter_mut().find(|t| t.id == cfg.id) {
            *existing = cfg;
        } else {
            file.tunnels.push(cfg);
        }
        self.write(&file, false)
    }

    /// Remove one tunnel and its vault secret.
    pub fn try_delete(&self, id: &str) -> Result<(), String> {
        let mut file = self.file_for_write()?;
        file.tunnels.retain(|t| t.id != id);
        match self.vault_handle() {
            Some(v) => v.delete_secret(&tunnel_secret_key(id))?,
            // Harmless — an unreferenced blob — but worth knowing about.
            None => log::warn!("tunnel '{}' deleted; its vault secret was left behind", id),
        }
        self.write(&file, false)
    }

    /// One tunnel, for actually starting it.
    ///
    /// Unlike `load` this fails when the credentials are out of reach, so a
    /// locked vault surfaces as "unlock first" instead of a handshake that
    /// offers an empty password to the jump host.
    pub fn get_for_connect(&self, id: &str) -> Result<TunnelConfig, String> {
        let file = self.read_file();
        let mut cfg = file
            .tunnels
            .into_iter()
            .find(|t| t.id == id)
            .ok_or_else(|| crate::i18n::tf("tunnel.err.not_found", &[("id", id)]))?;
        self.resolve_secret(file.schema, &mut cfg)?;
        Ok(cfg)
    }
}

/// Does this entry still carry a credential in the JSON file?
fn has_inline_secret(t: &TunnelConfig) -> bool {
    t.password.is_some() || t.private_key.is_some() || t.passphrase.is_some()
}

// ---------------------------------------------------------------------------
// Runtime state + manager
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum TunnelState {
    Stopped,
    Starting,
    Running { connections: u32, started: Instant },
    Failed(String),
}

impl TunnelState {
    pub fn is_running(&self) -> bool {
        matches!(self, TunnelState::Running { .. } | TunnelState::Starting)
    }
}

struct TunnelHandle {
    stop_flag: Arc<AtomicBool>,
    state: Arc<Mutex<TunnelState>>,
}

pub struct TunnelManager {
    tunnels: Mutex<HashMap<String, TunnelHandle>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self { tunnels: Mutex::new(HashMap::new()) }
    }

    /// Returns current state for every known tunnel id.
    pub fn states(&self) -> HashMap<String, TunnelState> {
        self.tunnels.lock().iter().map(|(k, h)| (k.clone(), h.state.lock().clone())).collect()
    }

    pub fn state_of(&self, id: &str) -> TunnelState {
        self.tunnels.lock().get(id).map(|h| h.state.lock().clone()).unwrap_or(TunnelState::Stopped)
    }

    pub fn is_running(&self, id: &str) -> bool {
        self.state_of(id).is_running()
    }

    pub fn start(&self, cfg: TunnelConfig) -> Result<(), String> {
        {
            let guard = self.tunnels.lock();
            if let Some(h) = guard.get(&cfg.id) {
                if h.state.lock().is_running() {
                    return Err("tunnel already running".into());
                }
            }
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(TunnelState::Starting));

        let stop_for_thread = stop_flag.clone();
        let state_for_thread = state.clone();
        let cfg_for_thread = cfg.clone();

        std::thread::spawn(move || {
            match run_tunnel_loop(cfg_for_thread, stop_for_thread, state_for_thread.clone()) {
                Ok(()) => {
                    let mut s = state_for_thread.lock();
                    if !matches!(*s, TunnelState::Failed(_)) {
                        *s = TunnelState::Stopped;
                    }
                }
                Err(e) => {
                    log::error!("tunnel loop exited: {}", e);
                    *state_for_thread.lock() = TunnelState::Failed(e);
                }
            }
        });

        self.tunnels.lock().insert(cfg.id.clone(), TunnelHandle { stop_flag, state });
        Ok(())
    }

    pub fn stop(&self, id: &str) {
        if let Some(h) = self.tunnels.lock().remove(id) {
            h.stop_flag.store(true, Ordering::Relaxed);
            *h.state.lock() = TunnelState::Stopped;
        }
    }

    pub fn stop_all(&self) {
        let handles: Vec<_> = self.tunnels.lock().drain().collect();
        for (_, h) in handles {
            h.stop_flag.store(true, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Tunnel lifecycle — one SSH session, multiple listening ports
// ---------------------------------------------------------------------------

fn run_tunnel_loop(
    cfg: TunnelConfig,
    stop_flag: Arc<AtomicBool>,
    state: Arc<Mutex<TunnelState>>,
) -> Result<(), String> {
    // 1. Open SSH session to jump host.
    let session = open_ssh_session(&cfg)?;
    // Non-blocking for the rest of the tunnel's life. A remote forward is
    // polled through `Listener::accept`, which in blocking mode parks inside
    // libssh2 holding the session lock and starves every other forward on the
    // same session; and the first pump thread used to flip the session to
    // non-blocking behind the accept loop's back anyway, which is why only the
    // first local connection ever got a channel. Every channel-open path here
    // therefore tolerates EAGAIN — see `SharedSession::request`.
    session.set_blocking(false);
    let session = Arc::new(TunnelSession::new(session));

    // 2. Bind every listener up-front so port-in-use errors surface early.
    let mut local: Vec<(TcpListener, ForwardRule)> = Vec::new();
    let mut remote: Vec<(ssh2::Listener, ForwardRule)> = Vec::new();
    for rule in &cfg.forwards {
        match rule.kind {
            ForwardKind::Local | ForwardKind::Dynamic => {
                let addr = format!("127.0.0.1:{}", rule.local_port);
                let lst = TcpListener::bind(&addr).map_err(|e| crate::i18n::tf(
                    "tunnel.err.bind", &[("addr", &addr), ("err", &e.to_string())]))?;
                lst.set_nonblocking(true).ok();
                if rule.kind == ForwardKind::Dynamic {
                    log::info!("tunnel '{}' SOCKS5 listening {}", cfg.name, addr);
                } else {
                    log::info!("tunnel '{}' listening {} -> {}:{}",
                        cfg.name, addr, rule.remote_host, rule.remote_port);
                }
                local.push((lst, rule.clone()));
            }
            ForwardKind::Remote => {
                let bind = remote_bind_host(&rule.remote_host);
                let (lst, bound) = forward_listen(&session, rule.remote_port, bind)?;
                log::info!("tunnel '{}' remote listening {}:{} -> 127.0.0.1:{}",
                    cfg.name, bind, bound, rule.local_port);
                remote.push((lst, rule.clone()));
            }
        }
    }

    *state.lock() = TunnelState::Running { connections: 0, started: Instant::now() };

    // 3. Poll-accept on every listener; each accepted connection gets its own
    //    channel and its own pump thread.
    let conn_count = Arc::new(parking_lot::Mutex::new(0u32));
    while !stop_flag.load(Ordering::Relaxed) {
        let mut had_work = false;

        // Local (-L) and dynamic (-D): a local socket, an outbound channel.
        for (lst, rule) in &local {
            match lst.accept() {
                Ok((client, peer)) => {
                    had_work = true;
                    if rule.kind == ForwardKind::Dynamic {
                        log::info!("tunnel '{}' SOCKS5 accepted {}", cfg.name, peer);
                    } else {
                        log::info!("tunnel '{}' accepted {} → {}:{}", cfg.name, peer, rule.remote_host, rule.remote_port);
                    }
                    client.set_nonblocking(false).ok();

                    let sess_clone = session.clone();
                    let rule_clone = rule.clone();
                    let state_clone = state.clone();
                    let conn_counter = conn_count.clone();
                    let name = cfg.name.clone();

                    {
                        let mut c = conn_counter.lock();
                        *c += 1;
                        bump_state(&state_clone, *c);
                    }

                    std::thread::spawn(move || {
                        let result = if rule_clone.kind == ForwardKind::Dynamic {
                            serve_socks5(client, &sess_clone)
                        } else {
                            let (host, port) = (&rule_clone.remote_host, rule_clone.remote_port);
                            match open_direct_tcpip(&sess_clone, host, port) {
                                Ok(channel) => pump_bidir(client, channel, sess_clone.clone()),
                                Err(e) => Err(format!("direct-tcpip {}:{}: {}", host, port, e)),
                            }
                        };
                        if let Err(e) = result {
                            log::warn!("tunnel '{}' pump error: {}", name, e);
                        }
                        let mut c = conn_counter.lock();
                        *c = c.saturating_sub(1);
                        bump_state(&state_clone, *c);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("accept error: {}", e)),
            }
        }

        // Remote (-R): the jump host is the listener. libssh2 queues inbound
        // connections until we accept them, and answers EAGAIN meanwhile.
        for (lst, rule) in remote.iter_mut() {
            let accepted = {
                let _s = session.lock();
                lst.accept()
            };
            match accepted {
                Ok(channel) => {
                    had_work = true;
                    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, rule.local_port));
                    log::info!("tunnel '{}' remote connection on {}:{} → {}",
                        cfg.name, rule.remote_host, rule.remote_port, target);

                    let sess_clone = session.clone();
                    let state_clone = state.clone();
                    let conn_counter = conn_count.clone();
                    let name = cfg.name.clone();

                    {
                        let mut c = conn_counter.lock();
                        *c += 1;
                        bump_state(&state_clone, *c);
                    }

                    std::thread::spawn(move || {
                        // Dropping `channel` on the error path closes it, so a
                        // refused local connect is reported to the remote peer.
                        let result = match TcpStream::connect_timeout(&target, Duration::from_secs(10)) {
                            Ok(local) => pump_bidir(local, channel, sess_clone.clone()),
                            Err(e) => Err(format!("connect {}: {}", target, e)),
                        };
                        if let Err(e) = result {
                            log::warn!("tunnel '{}' remote pump error: {}", name, e);
                        }
                        let mut c = conn_counter.lock();
                        *c = c.saturating_sub(1);
                        bump_state(&state_clone, *c);
                    });
                }
                Err(ref e) if is_eagain(e) => {}
                Err(e) => return Err(crate::i18n::tf(
                    "tunnel.err.remote_accept",
                    &[("port", &rule.remote_port.to_string()), ("err", &e.to_string())],
                )),
            }
        }

        if !had_work {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    log::info!("tunnel '{}' stopping", cfg.name);
    Ok(())
}

/// libssh2's "try again" under a non-blocking session (`LIBSSH2_ERROR_EAGAIN`).
fn is_eagain(e: &ssh2::Error) -> bool {
    e.code() == ssh2::ErrorCode::Session(-37)
}

/// How long a connection waits for its turn to open a channel before it is
/// refused. Only the wait for a turn is bounded — see `SharedSession::request`.
///
/// The trade-off behind this and `OPEN_STALL`, before anyone tunes either:
/// opens are serialized per session (see `SharedSession`), because libssh2
/// keeps a pending open in the session and two in flight get each other's
/// channels. The price is head-of-line blocking. An open to a blackholed
/// target holds the turn until libssh2 gives up on the reply — its packet read
/// timeout, about 60 s — and every new connection on the tunnel queues behind
/// it, whatever its own target. That open cannot be cut short without handing
/// its channel to the next caller, so what the two limits decide is only how
/// the queue behind it fails:
///
/// * `OPEN_TURN_WAIT` caps the wait for a turn. It leaves room for a long
///   queue that is still moving — a browser opening dozens of connections
///   over a slow link.
/// * `OPEN_STALL`: once the open holding the turn has been in flight that
///   long, its target is not answering and nobody waits behind it any more.
///   Whoever is queued gives up at that moment, and whoever arrives before it
///   is resolved gives up at once.
///
/// A connection turned away never reaches libssh2. A SOCKS5 client is told so
/// straight away with REP 0x01, general server failure — its target was never
/// tried, so "host unreachable" would be false — and a local forward's client
/// sees its socket close. Lower limits refuse healthy queues; higher ones only
/// make the same failure slower, until a client's own timeout fires first and
/// it is told nothing at all. Removing the trade-off takes opens that do not
/// share a session's open state (a session per open), not other numbers here.
const OPEN_TURN_WAIT: Duration = Duration::from_secs(20);
/// How long the open holding the turn may be in flight before the queue
/// behind it stops waiting — see `OPEN_TURN_WAIT`. A target that answers is
/// open after one round trip to the jump host plus the jump host's own
/// connect: well under a second. Ten seconds still covers a resolver timeout
/// on the jump host (5 s by default) or two lost SYNs (resent after 1 s and
/// 3 s); past that, the target is not answering.
const OPEN_STALL: Duration = Duration::from_secs(10);
/// Pause between polls of a request that answered EAGAIN.
const OPEN_RETRY: Duration = Duration::from_millis(5);

/// Why `SharedSession::request` produced nothing.
#[derive(Debug)]
enum OpenError {
    /// The turn never came — see `OPEN_TURN_WAIT`. libssh2 was not called,
    /// so the target was never tried.
    NoTurn,
    /// libssh2's own answer, its reply timeout included.
    Ssh(ssh2::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::NoTurn => {
                f.write_str("timed out waiting for another channel open on this session")
            }
            OpenError::Ssh(e) => write!(f, "{}", e),
        }
    }
}

/// The jump-host session every forward on one tunnel shares.
///
/// libssh2 is not thread-safe, so every call into it goes through `session`'s
/// lock, held for that one call and no longer.
///
/// `open_lock` exists because libssh2 keeps the state of a pending channel
/// open in the *session*, not in the call (`direct_state`, `open_state`;
/// `fwdLstn_state` for a remote listen). While one is pending, the next
/// `channel_direct_tcpip` on the session resumes it and ignores its own host
/// and port. Two pump threads each retrying their own open on EAGAIN therefore
/// trade channels, and a connection meant for one target is wired to another.
///
/// Generic over the session only so the tests can drive it with a fake.
struct SharedSession<S> {
    session: Mutex<S>,
    open_lock: Mutex<()>,
    /// When the request holding `open_lock` took it; `None` while none does.
    turn_since: Mutex<Option<Instant>>,
    turn_wait: Duration,
    stall_after: Duration,
}

type TunnelSession = SharedSession<ssh2::Session>;

/// The turn to open a channel, held for one whole request. `turn_since` is
/// cleared before the slot is released, so the next holder's start is never
/// read as this one's.
struct Turn<'a> {
    since: &'a Mutex<Option<Instant>>,
    _slot: parking_lot::MutexGuard<'a, ()>,
}

impl<'a> Turn<'a> {
    fn start(slot: parking_lot::MutexGuard<'a, ()>, since: &'a Mutex<Option<Instant>>) -> Self {
        *since.lock() = Some(Instant::now());
        Self { since, _slot: slot }
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        // Runs before the fields drop, so before `_slot` unlocks.
        *self.since.lock() = None;
    }
}

impl<S> SharedSession<S> {
    fn new(session: S) -> Self {
        Self {
            session: Mutex::new(session),
            open_lock: Mutex::new(()),
            turn_since: Mutex::new(None),
            turn_wait: OPEN_TURN_WAIT,
            stall_after: OPEN_STALL,
        }
    }

    /// The session, for one libssh2 call.
    fn lock(&self) -> parking_lot::MutexGuard<'_, S> {
        self.session.lock()
    }

    /// Run one channel open or remote listen to completion on the
    /// non-blocking session, with no other in flight.
    ///
    /// The turn (`open_lock`) is taken before the first attempt and released
    /// after the last, EAGAIN retries included, so only one request is ever in
    /// flight per session. The session lock is taken per attempt and never held
    /// across the sleep: pumps on channels that are already open keep moving
    /// meanwhile.
    ///
    /// A request, once started, is seen through to libssh2's answer. Giving up
    /// on EAGAIN would leave it in flight, and the next caller would be handed
    /// its channel — the same cross-wiring. libssh2 bounds that wait itself: it
    /// gives up on the reply after its packet read timeout (60 s) and resets
    /// the request. What is bounded here is the wait for a turn.
    fn request<T>(
        &self,
        mut attempt: impl FnMut(&mut S) -> Result<T, ssh2::Error>,
    ) -> Result<T, OpenError> {
        let _turn = self.take_turn().ok_or(OpenError::NoTurn)?;
        loop {
            let result = {
                let mut s = self.session.lock();
                attempt(&mut s)
            };
            match result {
                Err(ref e) if is_eagain(e) => std::thread::sleep(OPEN_RETRY),
                done => return done.map_err(OpenError::Ssh),
            }
        }
    }

    /// Wait for the turn, or `None` once waiting no longer pays: `turn_wait`
    /// has passed, or the open holding the turn has been in flight for
    /// `stall_after`. The second limit is measured on the holder, not on this
    /// caller, so a queue that keeps moving is waited out in full.
    fn take_turn(&self) -> Option<Turn<'_>> {
        let deadline = Instant::now() + self.turn_wait;
        loop {
            if let Some(slot) = self.open_lock.try_lock() {
                return Some(Turn::start(slot, &self.turn_since));
            }
            let now = Instant::now();
            // A holder that has not stamped its start yet has only just begun.
            let since = *self.turn_since.lock();
            let in_flight = since.map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
            let wait = self
                .stall_after
                .saturating_sub(in_flight)
                .min(deadline.saturating_duration_since(now));
            if wait.is_zero() {
                return None;
            }
            // Woken early by a release; otherwise look again at whoever holds
            // the turn by then.
            if let Some(slot) = self.open_lock.try_lock_for(wait) {
                return Some(Turn::start(slot, &self.turn_since));
            }
        }
    }
}

/// Open a direct-tcpip channel to `host:port` through the jump host.
fn open_direct_tcpip(session: &TunnelSession, host: &str, port: u16) -> Result<ssh2::Channel, OpenError> {
    session.request(|s| s.channel_direct_tcpip(host, port, None))
}

/// Ask the jump host to listen on `bind:port`. Returns the listener and the
/// port the server actually bound (which differs from `port` when `port` is 0
/// and the server picks one).
fn forward_listen(
    session: &TunnelSession,
    port: u16,
    bind: &str,
) -> Result<(ssh2::Listener, u16), String> {
    session
        .request(|s| s.channel_forward_listen(port, Some(bind), None))
        .map_err(|e| crate::i18n::tf(
            "tunnel.err.remote_listen",
            &[("bind", bind), ("port", &port.to_string()), ("err", &e.to_string())],
        ))
}

/// Bind address to request for a remote forward. Always an explicit address:
/// for `None`, libssh2 sends `"0.0.0.0"` — every interface.
///
/// No address means loopback, exactly as with `ssh -R`: the forward exists for
/// this machine, not for the jump host's network. The wildcards are spelled out
/// as what they mean, and `::` stays IPv6. Anything but loopback also needs
/// `GatewayPorts` on the server before it is honoured.
fn remote_bind_host(host: &str) -> &str {
    match host.trim() {
        "" => "localhost",
        "*" | "0.0.0.0" => "0.0.0.0",
        h => h,
    }
}

fn bump_state(state: &Arc<Mutex<TunnelState>>, count: u32) {
    let mut s = state.lock();
    if let TunnelState::Running { started, .. } = *s {
        *s = TunnelState::Running { connections: count, started };
    }
}

fn open_ssh_session(cfg: &TunnelConfig) -> Result<ssh2::Session, String> {
    let addr = format!("{}:{}", cfg.ssh_host, cfg.ssh_port);
    let tcp = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .map_err(|e| format!("DNS {}: {}", addr, e))?
            .next()
            .ok_or_else(|| format!("no address for {}", addr))?,
        Duration::from_secs(10),
    )
    .map_err(|e| format!("TCP {}: {}", addr, e))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(15))).ok();

    let mut session = ssh2::Session::new().map_err(|e| format!("Session::new: {}", e))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(15_000);
    // Offer the algorithm this host is already trusted under first, or a host
    // pinned as ssh-rsa answers with ed25519 and the check below reports a
    // mismatch on a perfectly legitimate server.
    crate::ssh::prepare_host_key_prefs_for(&session, &cfg.ssh_host, cfg.ssh_port);
    session.handshake().map_err(|e| format!("SSH handshake: {}", e))?;
    // Before any credential is offered. This never prompts, so it is safe on
    // the auto-start path, which runs with no UI attached.
    crate::ssh::verify_host_key(&session, &cfg.ssh_host, cfg.ssh_port)
        .map_err(|e| crate::ssh::translate_ssh_error(&e))?;

    match cfg.auth_type.as_str() {
        "key" => {
            let key_path = cfg.private_key.as_deref()
                .ok_or_else(|| "tunnel: private_key required".to_string())?;
            session.userauth_pubkey_file(
                &cfg.username, None,
                &PathBuf::from(key_path),
                cfg.passphrase.as_deref(),
            ).map_err(|e| format!("key auth: {}", e))?;
        }
        _ => {
            // No fallback to "": the password now lives in the vault, and
            // opening a forward into an internal network with an empty
            // credential because the vault is locked is exactly the silent
            // failure this must not have.
            let pass = cfg.password.as_deref()
                .ok_or_else(|| crate::i18n::t("vault.no_credential").to_string())?;
            session.userauth_password(&cfg.username, pass)
                .map_err(|e| format!("password auth: {}", e))?;
        }
    }
    if !session.authenticated() {
        return Err("auth failed".into());
    }
    session.set_keepalive(true, 30);
    Ok(session)
}

/// Bidirectional byte pump between a local TCP socket and an SSH channel.
/// Shares the session mutex so concurrent tunnels through the same session
/// don't step on libssh2's thread-unsafe session state.
fn pump_bidir(
    mut local: TcpStream,
    mut channel: ssh2::Channel,
    session: Arc<TunnelSession>,
) -> Result<(), String> {
    use std::io::ErrorKind;

    local.set_nonblocking(true).ok();
    local.set_read_timeout(None).ok();
    local.set_write_timeout(None).ok();
    {
        let s = session.lock();
        s.set_blocking(false);
    }

    // Each direction keeps the unwritten tail of its buffer across iterations:
    // a partial write followed by a fresh read would silently drop the
    // remainder, which is what a full SSH window used to cause here. Only
    // refill a buffer once it has fully drained.
    let mut up = [0u8; 32 * 1024];
    let (mut up_pos, mut up_len) = (0usize, 0usize);
    let mut dn = [0u8; 32 * 1024];
    let (mut dn_pos, mut dn_len) = (0usize, 0usize);
    let mut local_eof = false;
    let mut channel_eof = false;

    loop {
        let mut did_work = false;

        // local -> channel
        if up_pos == up_len && !local_eof {
            match local.read(&mut up) {
                Ok(0) => {
                    local_eof = true;
                    let _s = session.lock();
                    let _ = channel.send_eof();
                }
                Ok(n) => { up_pos = 0; up_len = n; did_work = true; }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("local read: {}", e)),
            }
        }
        if up_pos < up_len {
            let written = {
                let _s = session.lock();
                channel.write(&up[up_pos..up_len])
            };
            match written {
                Ok(k) => { up_pos += k; did_work = true; }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("ch write: {}", e)),
            }
        }

        // channel -> local
        if dn_pos == dn_len && !channel_eof {
            let read_result = {
                let _s = session.lock();
                channel.read(&mut dn)
            };
            match read_result {
                Ok(0) => {
                    let _s = session.lock();
                    if channel.eof() {
                        channel_eof = true;
                        let _ = local.shutdown(std::net::Shutdown::Write);
                    }
                }
                Ok(n) => { dn_pos = 0; dn_len = n; did_work = true; }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("ch read: {}", e)),
            }
        }
        if dn_pos < dn_len {
            match local.write(&dn[dn_pos..dn_len]) {
                Ok(k) => { dn_pos += k; did_work = true; }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("local write: {}", e)),
            }
        }

        // Only leave once both sides are done *and* both buffers are flushed.
        if local_eof && channel_eof && up_pos == up_len && dn_pos == dn_len {
            break;
        }
        if !did_work {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    let _s = session.lock();
    let _ = channel.close();
    Ok(())
}

// ---------------------------------------------------------------------------
// SOCKS5 server (RFC 1928) — the local end of a dynamic (`-D`) forward
//
// Everything parsed below arrives from whatever local process reached the
// listening port, so the rules are: read fixed-size frames with `read_exact`
// (a short read is an error, never a silently zero-filled buffer), cap every
// length-prefixed field at what the protocol itself allows, index only into
// slices already proven long enough, and answer a malformed or unsupported
// request with the right REP byte instead of dropping the socket — a client
// that gets no answer retries, a client that gets 0x07 gives up.
//
// Scope is deliberately the same as `ssh -D`: no authentication (method
// 0x00), CONNECT only, IPv4 / IPv6 / DOMAINNAME.
// ---------------------------------------------------------------------------

const SOCKS5_VER: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

// REP codes, RFC 1928 §6.
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// A validated SOCKS5 CONNECT target.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksTarget {
    host: String,
    port: u16,
}

/// Write a SOCKS5 reply. BND.ADDR/BND.PORT are reported as `0.0.0.0:0`: no
/// socket is bound on the client's behalf, and RFC 1928 §6 permits it.
fn socks5_reply<W: Write>(w: &mut W, rep: u8) -> std::io::Result<()> {
    w.write_all(&[SOCKS5_VER, rep, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
}

/// Run the server half of a SOCKS5 handshake and return the CONNECT target.
///
/// On a protocol error the matching reply is written before returning, so the
/// caller only has to close the socket. No reply is sent when the peer is not
/// speaking SOCKS5 at all — there is no reply format that could be trusted.
fn socks5_handshake<S: Read + Write>(s: &mut S) -> Result<SocksTarget, String> {
    // --- greeting: VER | NMETHODS | METHODS[NMETHODS] ---
    let mut head = [0u8; 2];
    s.read_exact(&mut head).map_err(|e| format!("socks5 greeting: {}", e))?;
    if head[0] != SOCKS5_VER {
        return Err(format!("socks5: unsupported version {:#04x}", head[0]));
    }
    let nmethods = head[1] as usize; // <= 255 by construction
    if nmethods == 0 {
        let _ = s.write_all(&[SOCKS5_VER, SOCKS5_NO_ACCEPTABLE]);
        return Err("socks5: client offered no auth methods".to_string());
    }
    let mut methods = [0u8; 255];
    s.read_exact(&mut methods[..nmethods])
        .map_err(|e| format!("socks5 method list: {}", e))?;
    if !methods[..nmethods].contains(&SOCKS5_NO_AUTH) {
        let _ = s.write_all(&[SOCKS5_VER, SOCKS5_NO_ACCEPTABLE]);
        return Err("socks5: client requires authentication".to_string());
    }
    s.write_all(&[SOCKS5_VER, SOCKS5_NO_AUTH])
        .map_err(|e| format!("socks5 method reply: {}", e))?;

    // --- request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT ---
    let mut req = [0u8; 4];
    s.read_exact(&mut req).map_err(|e| format!("socks5 request: {}", e))?;
    if req[0] != SOCKS5_VER {
        let _ = socks5_reply(s, REP_GENERAL_FAILURE);
        return Err(format!("socks5: unsupported request version {:#04x}", req[0]));
    }
    if req[1] != SOCKS5_CMD_CONNECT {
        let _ = socks5_reply(s, REP_CMD_NOT_SUPPORTED);
        return Err(format!("socks5: unsupported command {:#04x}", req[1]));
    }

    let host = match req[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).map_err(|e| format!("socks5 IPv4 address: {}", e))?;
            Ipv4Addr::from(a).to_string()
        }
        SOCKS5_ATYP_IPV6 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).map_err(|e| format!("socks5 IPv6 address: {}", e))?;
            Ipv6Addr::from(a).to_string()
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).map_err(|e| format!("socks5 domain length: {}", e))?;
            let len = len[0] as usize; // <= 255 by construction
            if len == 0 {
                let _ = socks5_reply(s, REP_ADDR_NOT_SUPPORTED);
                return Err("socks5: empty domain name".to_string());
            }
            let mut name = vec![0u8; len];
            s.read_exact(&mut name).map_err(|e| format!("socks5 domain name: {}", e))?;
            match String::from_utf8(name) {
                Ok(h) if !h.chars().any(|c| c.is_control()) => h,
                _ => {
                    let _ = socks5_reply(s, REP_ADDR_NOT_SUPPORTED);
                    return Err("socks5: malformed domain name".to_string());
                }
            }
        }
        other => {
            let _ = socks5_reply(s, REP_ADDR_NOT_SUPPORTED);
            return Err(format!("socks5: unsupported address type {:#04x}", other));
        }
    };

    let mut port = [0u8; 2];
    s.read_exact(&mut port).map_err(|e| format!("socks5 port: {}", e))?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        let _ = socks5_reply(s, REP_GENERAL_FAILURE);
        return Err("socks5: port 0 is not a valid target".to_string());
    }

    Ok(SocksTarget { host, port })
}

/// The REP a SOCKS5 client is sent when its channel did not open.
fn socks5_failure_rep(e: &OpenError) -> u8 {
    match e {
        // Never tried: this server could not take the request, which says
        // nothing about the target. See `OPEN_TURN_WAIT`.
        OpenError::NoTurn => REP_GENERAL_FAILURE,
        // The jump host could not reach the target, or never answered.
        OpenError::Ssh(_) => REP_HOST_UNREACHABLE,
    }
}

/// Handshake, then `open` a channel to the requested target, answering the
/// client either way: REP_SUCCESS and the channel, for the caller to pump, or
/// the matching failure REP and an `Err`, after which the caller only has to
/// close the socket.
fn socks5_connect<C: Read + Write, T>(
    client: &mut C,
    open: impl FnOnce(&SocksTarget) -> Result<T, OpenError>,
) -> Result<T, String> {
    let target = socks5_handshake(client)?;
    match open(&target) {
        Ok(channel) => {
            socks5_reply(client, REP_SUCCESS)
                .map_err(|e| format!("socks5 success reply: {}", e))?;
            Ok(channel)
        }
        Err(e) => {
            let _ = socks5_reply(client, socks5_failure_rep(&e));
            Err(format!("direct-tcpip {}:{}: {}", target.host, target.port, e))
        }
    }
}

/// Serve one connection on a dynamic forward: SOCKS5 handshake, then the same
/// direct-tcpip pump a local forward uses.
fn serve_socks5(mut client: TcpStream, session: &Arc<TunnelSession>) -> Result<(), String> {
    // The handshake is a handful of tiny frames. A peer that opens the socket
    // and then says nothing must not hold a thread forever.
    client.set_read_timeout(Some(Duration::from_secs(10))).ok();
    client.set_write_timeout(Some(Duration::from_secs(10))).ok();

    match socks5_connect(&mut client, |t| open_direct_tcpip(session, &t.host, t.port)) {
        Ok(channel) => pump_bidir(client, channel, session.clone()),
        Err(e) => {
            let _ = client.shutdown(std::net::Shutdown::Both);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    // -- ForwardRule::parse --------------------------------------------------

    #[test]
    fn forward_rule_parses_arrow_form() {
        let r = ForwardRule::parse("192.168.1.10:3306->localhost:13306").unwrap();
        assert_eq!(r.local_port, 13306);
        assert_eq!(r.remote_host, "192.168.1.10");
        assert_eq!(r.remote_port, 3306);
        assert_eq!(r.kind, ForwardKind::Local);
    }

    #[test]
    fn forward_rule_parses_compact_form() {
        let r = ForwardRule::parse("9000:10.0.0.5:80").unwrap();
        assert_eq!(r.local_port, 9000);
        assert_eq!(r.remote_host, "10.0.0.5");
        assert_eq!(r.remote_port, 80);
        assert_eq!(r.kind, ForwardKind::Local);
    }

    #[test]
    fn forward_rule_rejects_garbage() {
        assert!(ForwardRule::parse("not-a-rule").is_err());
    }

    #[test]
    fn forward_rule_parses_remote_form() {
        let r = ForwardRule::parse("R:3000:0.0.0.0:8080").unwrap();
        assert_eq!(r.kind, ForwardKind::Remote);
        assert_eq!(r.local_port, 3000);
        assert_eq!(r.remote_host, "0.0.0.0");
        assert_eq!(r.remote_port, 8080);
        assert_eq!(remote_bind_host(&r.remote_host), "0.0.0.0");
        let r = ForwardRule::parse("R:3000:*:8080").unwrap();
        assert_eq!(remote_bind_host(&r.remote_host), "0.0.0.0");
        // Prefix is case-insensitive, and an empty bind host is legal here: it
        // is the jump host's loopback, as `ssh -R 2222:localhost:22` would bind.
        let r = ForwardRule::parse("r:22::2222").unwrap();
        assert_eq!(r.kind, ForwardKind::Remote);
        assert_eq!(r.remote_host, "");
        assert_eq!(r.remote_port, 2222);
        assert_eq!(remote_bind_host(&r.remote_host), "localhost");
    }

    #[test]
    fn forward_rule_parses_dynamic_form() {
        let r = ForwardRule::parse("D:1080").unwrap();
        assert_eq!(r.kind, ForwardKind::Dynamic);
        assert_eq!(r.local_port, 1080);
        assert_eq!(r.remote_host, "");
        assert_eq!(r.remote_port, 0);
        assert_eq!(ForwardRule::parse("d: 1080 ").unwrap(), r);
    }

    #[test]
    fn forward_rule_rejects_bad_prefixed_forms() {
        for bad in [
            "D:",              // no port
            "D:0",             // port 0 cannot be listened on usefully
            "D:70000",         // out of u16 range
            "D:1080:extra",    // dynamic takes a port and nothing else
            "R:",              // nothing after the prefix
            "R:8080:host",     // remote still needs all three fields
            "R:abc:host:80",   // local port is not a number
            "R:80:host:abc",   // remote port is not a number
            "8080::80",        // a local forward with no host to dial
            "",                // empty line
            ":::",             // four empty fields
        ] {
            assert!(ForwardRule::parse(bad).is_err(), "expected '{}' to be rejected", bad);
        }
    }

    /// Every rejection reaches the "Forward parse error" dialog, so each one is
    /// a translated message, with the offending text filled in.
    #[test]
    fn forward_rule_errors_are_translated_messages() {
        let check = |rule: &str, key: &str, params: &[(&str, &str)]| {
            let err = ForwardRule::parse(rule).unwrap_err();
            assert!(is_message(&err, key, params), "{:?} gave {:?}, not {}", rule, err, key);
        };
        // What `str::parse::<u16>` says about a field, as the messages quote it.
        let why = |field: &str| field.parse::<u16>().unwrap_err().to_string();
        let (x, empty) = (why("x"), why(""));

        check("D:0", "tunnel.err.socks_port_zero", &[]);
        check("D:x", "tunnel.err.bad_socks_port", &[("port", "x"), ("err", &x)]);
        check("D:", "tunnel.err.bad_socks_port", &[("port", ""), ("err", &empty)]);
        check("db->5432", "tunnel.err.bad_remote", &[("remote", "db")]);
        check("db:x->5432", "tunnel.err.bad_remote_port", &[("port", "x"), ("err", &x)]);
        check("db:5432->localhost:x", "tunnel.err.bad_local_port", &[("port", "x"), ("err", &x)]);
        check("not-a-rule", "tunnel.err.bad_rule", &[("rule", "not-a-rule")]);
        check("R:8080:host", "tunnel.err.bad_rule", &[("rule", "R:8080:host")]);
        check("8080::80", "tunnel.err.missing_host", &[("rule", "8080::80")]);
        check("x:host:80", "tunnel.err.bad_local_port", &[("port", "x"), ("err", &x)]);
        check("R:80:host:x", "tunnel.err.bad_remote_port", &[("port", "x"), ("err", &x)]);
    }

    #[test]
    fn forward_rule_spec_round_trips() {
        for spec in ["9000:10.0.0.5:80", "R:3000:0.0.0.0:8080", "D:1080"] {
            let r = ForwardRule::parse(spec).unwrap();
            assert_eq!(r.spec(), spec);
            assert_eq!(ForwardRule::parse(&r.spec()).unwrap(), r);
        }
    }

    #[test]
    fn legacy_forward_json_parses_as_local() {
        let r: ForwardRule = serde_json::from_str(
            r#"{"local_port":8080,"remote_host":"10.0.0.5","remote_port":80}"#,
        ).unwrap();
        assert_eq!(r.kind, ForwardKind::Local);
        assert_eq!(r.spec(), "8080:10.0.0.5:80");
    }

    #[test]
    fn remote_bind_host_defaults_to_loopback_like_ssh_r() {
        // No address: loopback. This used to be `None`, which libssh2 sends
        // as "0.0.0.0" — a listener on every interface of the jump host.
        assert_eq!(remote_bind_host(""), "localhost");
        assert_eq!(remote_bind_host("  "), "localhost");
        // Wildcards are sent as what they mean, and IPv6 any stays IPv6.
        assert_eq!(remote_bind_host("*"), "0.0.0.0");
        assert_eq!(remote_bind_host("0.0.0.0"), "0.0.0.0");
        assert_eq!(remote_bind_host("::"), "::");
        // Anything else passes through.
        assert_eq!(remote_bind_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(remote_bind_host(" 10.0.0.7 "), "10.0.0.7");
        assert_eq!(remote_bind_host("localhost"), "localhost");
    }

    // -- One channel open in flight per session ------------------------------

    /// Just enough of libssh2's channel-open state machine to show the hazard:
    /// the open in flight lives in the session, and a call made while one is
    /// pending carries on with *that* one, whatever it asked for — which is
    /// what `channel_direct_tcpip` does while `direct_state` is not idle.
    #[derive(Default)]
    struct FakeLibssh2 {
        /// The target being opened, and how many more polls answer EAGAIN.
        in_flight: Option<(String, u32)>,
        /// `(asked for, handed instead)` for each call that resumed another's open.
        resumed_foreign: Vec<(String, String)>,
        calls: u32,
    }

    impl FakeLibssh2 {
        /// Start opening `target`, answering EAGAIN `eagains` times before the
        /// channel is ready — unless an open is already in flight, in which
        /// case this polls that one instead. The "channel" is its target.
        fn open(&mut self, target: &str, eagains: u32) -> Result<String, ssh2::Error> {
            self.calls += 1;
            let (opening, left) = self.in_flight.get_or_insert_with(|| (target.to_string(), eagains));
            if opening.as_str() != target {
                self.resumed_foreign.push((target.to_string(), opening.clone()));
            }
            if *left > 0 {
                *left -= 1;
                return Err(ssh2::Error::new(ssh2::ErrorCode::Session(-37), "would block"));
            }
            Ok(self.in_flight.take().map(|(t, _)| t).unwrap_or_default())
        }
    }

    fn fake_session(turn_wait: Duration) -> SharedSession<FakeLibssh2> {
        SharedSession { turn_wait, ..SharedSession::new(FakeLibssh2::default()) }
    }

    /// Open `target` on another thread, returning once its first poll is done
    /// — with `eagains > 0`, while that open is still in flight.
    fn open_in_background(
        shared: &Arc<SharedSession<FakeLibssh2>>,
        target: &'static str,
        eagains: u32,
    ) -> std::thread::JoinHandle<Result<String, OpenError>> {
        let shared = shared.clone();
        let (polled_tx, polled_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut first_poll = Some(polled_tx);
            shared.request(|fake| {
                let polled = fake.open(target, eagains);
                if let Some(tx) = first_poll.take() {
                    let _ = tx.send(());
                }
                polled
            })
        });
        polled_rx.recv().unwrap();
        handle
    }

    #[test]
    fn concurrent_opens_each_get_the_channel_for_their_own_target() {
        let shared = Arc::new(fake_session(OPEN_TURN_WAIT));
        // A's open stays in flight for 30 polls (~150 ms); B arrives inside it.
        let a = open_in_background(&shared, "db.internal:5432", 30);
        let b = {
            let shared = shared.clone();
            std::thread::spawn(move || shared.request(|fake| fake.open("web.internal:443", 3)))
        };

        assert_eq!(a.join().unwrap().unwrap(), "db.internal:5432");
        assert_eq!(b.join().unwrap().unwrap(), "web.internal:443");
        let fake = shared.lock();
        assert!(
            fake.resumed_foreign.is_empty(),
            "an open was resumed by a caller asking for another target: {:?}",
            fake.resumed_foreign
        );
        assert!(fake.in_flight.is_none());
    }

    #[test]
    fn an_open_in_flight_is_seen_through_not_left_for_the_next_caller() {
        // In flight for 20 polls (~100 ms), far past the 10 ms this session
        // allows for a turn. Giving up on the request itself would leave it
        // inside libssh2, and the next open would be handed its channel.
        let shared = fake_session(Duration::from_millis(10));
        let first = shared.request(|fake| fake.open("slow.internal:22", 20));
        let second = shared.request(|fake| fake.open("next.internal:22", 0));
        assert_eq!(first.ok().as_deref(), Some("slow.internal:22"));
        assert_eq!(second.ok().as_deref(), Some("next.internal:22"));
        assert!(shared.lock().resumed_foreign.is_empty());
    }

    #[test]
    fn a_caller_that_cannot_get_a_turn_gives_up_without_touching_the_session() {
        let shared = fake_session(Duration::from_millis(50));
        // Another open is in flight and not finishing.
        let other = shared.open_lock.lock();
        let err = shared.request(|fake| fake.open("web.internal:443", 0)).unwrap_err();
        drop(other);
        assert!(
            matches!(err, OpenError::NoTurn),
            "a refused turn must say so, not pass for an answer from libssh2: {}",
            err
        );
        assert_eq!(shared.lock().calls, 0, "libssh2 was called while another open was in flight");
    }

    #[test]
    fn pumps_keep_the_session_while_an_open_waits_for_its_reply() {
        let shared = Arc::new(fake_session(OPEN_TURN_WAIT));
        // In flight for 40 polls (~200 ms).
        let opener = open_in_background(&shared, "db.internal:5432", 40);
        // A pump's turn at the session, while that open is still waiting.
        let pump = shared.session.try_lock_for(Duration::from_millis(100));
        let open_still_waiting = pump.as_ref().map(|s| s.in_flight.is_some());
        drop(pump);
        assert_eq!(open_still_waiting, Some(true), "the session stayed locked while an open waited");
        assert_eq!(opener.join().unwrap().unwrap(), "db.internal:5432");
    }

    /// The open ahead has been in flight past the stall limit: its target is
    /// not answering, and queueing behind it until libssh2 gives up would
    /// only make every caller's failure slower.
    #[test]
    fn nobody_queues_behind_an_open_that_has_stalled() {
        let shared = Arc::new(SharedSession {
            stall_after: Duration::from_millis(50),
            ..fake_session(OPEN_TURN_WAIT)
        });
        // In flight for 200 polls, a second at least: a target not answering.
        let stuck = open_in_background(&shared, "blackhole.internal:443", 200);

        // Queued before the stall shows: turned away the moment it does — not
        // after its 20 s budget, and not served once the stuck open is done.
        let started = Instant::now();
        let queued = shared.request(|fake| fake.open("web.internal:443", 0));
        let waited = started.elapsed();
        assert!(matches!(queued, Err(OpenError::NoTurn)), "{:?}", queued);
        assert!(waited < Duration::from_millis(500), "waited {:?} behind a stalled open", waited);
        // Arriving after it shows: turned away too.
        let late = shared.request(|fake| fake.open("api.internal:443", 0));
        assert!(matches!(late, Err(OpenError::NoTurn)), "{:?}", late);

        // The stuck open is still seen through, and the turn is free after it.
        assert_eq!(stuck.join().unwrap().unwrap(), "blackhole.internal:443");
        let next = shared.request(|fake| fake.open("web.internal:443", 0));
        assert_eq!(next.unwrap(), "web.internal:443");
        assert!(shared.lock().resumed_foreign.is_empty());
    }

    /// The stall limit is measured on the open holding the turn, not on the
    /// caller: behind a queue that keeps moving, a caller waits well past it.
    #[test]
    fn a_queue_that_keeps_moving_is_waited_out_past_the_stall_limit() {
        let stall = Duration::from_millis(400);
        let shared = Arc::new(SharedSession { stall_after: stall, ..fake_session(OPEN_TURN_WAIT) });
        let started = Instant::now();
        // Ten opens of 10 polls, 50 ms at least each: every one far inside
        // the limit, all of them together past it.
        let first = open_in_background(&shared, "t0.internal:443", 10);
        let queued: Vec<_> = (1..10)
            .map(|i| {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    let target = format!("t{}.internal:443", i);
                    shared.request(|fake| fake.open(&target, 10)).map(|got| (target, got))
                })
            })
            .collect();

        assert_eq!(first.join().unwrap().unwrap(), "t0.internal:443");
        for q in queued {
            let (asked, got) = q.join().unwrap().expect("a moving queue was turned away");
            assert_eq!(got, asked);
        }
        assert!(started.elapsed() > stall, "the queue drained inside the limit, proving nothing");
        assert!(shared.lock().resumed_foreign.is_empty());
    }

    // -- SOCKS5 server -------------------------------------------------------

    /// A socket stand-in: `input` is what the client sent, `output` collects
    /// everything written back.
    struct Duplex {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Duplex {
        fn new(input: Vec<u8>) -> Self {
            Self { input: std::io::Cursor::new(input), output: Vec::new() }
        }
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A greeting that offers only "no authentication".
    const NO_AUTH_GREETING: [u8; 3] = [0x05, 0x01, 0x00];

    /// The REP byte of the 10-byte reply that follows the 2-byte method
    /// selection, or `None` when no reply was written.
    fn rep_byte(out: &[u8]) -> Option<u8> {
        if out.len() == 12 { Some(out[3]) } else { None }
    }

    #[test]
    fn socks5_accepts_ipv4_connect() {
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5]);
        req.extend_from_slice(&443u16.to_be_bytes());
        let mut d = Duplex::new(req);
        let t = socks5_handshake(&mut d).unwrap();
        assert_eq!(t, SocksTarget { host: "10.0.0.5".into(), port: 443 });
        // Only the method selection — the success reply is the caller's job,
        // it must not go out before the channel actually opens.
        assert_eq!(d.output.as_slice(), &[0x05, 0x00]);
    }

    #[test]
    fn socks5_accepts_domain_connect() {
        let host = b"db.internal.example";
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
        req.extend_from_slice(host);
        req.extend_from_slice(&5432u16.to_be_bytes());
        let mut d = Duplex::new(req);
        let t = socks5_handshake(&mut d).unwrap();
        assert_eq!(t, SocksTarget { host: "db.internal.example".into(), port: 5432 });
    }

    #[test]
    fn socks5_accepts_ipv6_connect() {
        // Client offers no-auth plus username/password; we pick no-auth.
        let mut req = vec![0x05, 0x02, 0x02, 0x00];
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x04]);
        req.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        req.extend_from_slice(&22u16.to_be_bytes());
        let mut d = Duplex::new(req);
        let t = socks5_handshake(&mut d).unwrap();
        assert_eq!(t, SocksTarget { host: "::1".into(), port: 22 });
    }

    #[test]
    fn socks5_rejects_non_socks_peer() {
        // Someone pointed a browser at the SOCKS port: "GET / HTTP/1.1".
        let mut d = Duplex::new(b"GET / HTTP/1.1\r\n\r\n".to_vec());
        assert!(socks5_handshake(&mut d).is_err());
        assert!(d.output.is_empty(), "no reply is valid for a non-SOCKS peer");
    }

    #[test]
    fn socks5_rejects_truncated_greeting() {
        for truncated in [vec![], vec![0x05u8], vec![0x05, 0x02, 0x00]] {
            let mut d = Duplex::new(truncated.clone());
            assert!(socks5_handshake(&mut d).is_err(), "accepted {:?}", truncated);
        }
    }

    #[test]
    fn socks5_rejects_oversized_method_list_claim() {
        // Claims 200 methods, sends two.
        let mut d = Duplex::new(vec![0x05, 200, 0x00, 0x02]);
        assert!(socks5_handshake(&mut d).is_err());
    }

    #[test]
    fn socks5_rejects_client_without_no_auth() {
        let mut d = Duplex::new(vec![0x05, 0x01, 0x02]);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(d.output.as_slice(), &[0x05, SOCKS5_NO_ACCEPTABLE]);
    }

    #[test]
    fn socks5_rejects_zero_method_count() {
        let mut d = Duplex::new(vec![0x05, 0x00]);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(d.output.as_slice(), &[0x05, SOCKS5_NO_ACCEPTABLE]);
    }

    #[test]
    fn socks5_rejects_truncated_request() {
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 10, 0]); // half an IPv4, no port
        let mut d = Duplex::new(req);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(d.output.as_slice(), &[0x05, 0x00]);
    }

    #[test]
    fn socks5_rejects_oversized_domain_claim() {
        // Length byte says 255, five bytes follow.
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, 255]);
        req.extend_from_slice(b"short");
        let mut d = Duplex::new(req);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(d.output.as_slice(), &[0x05, 0x00]);
    }

    #[test]
    fn socks5_accepts_maximum_length_domain() {
        let host = vec![b'a'; 255];
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, 255]);
        req.extend_from_slice(&host);
        req.extend_from_slice(&80u16.to_be_bytes());
        let mut d = Duplex::new(req);
        let t = socks5_handshake(&mut d).unwrap();
        assert_eq!(t.host.len(), 255);
        assert_eq!(t.port, 80);
    }

    #[test]
    fn socks5_rejects_empty_domain() {
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50]);
        let mut d = Duplex::new(req);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(rep_byte(&d.output), Some(REP_ADDR_NOT_SUPPORTED));
    }

    #[test]
    fn socks5_rejects_control_characters_in_domain() {
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, 0x04]);
        req.extend_from_slice(b"a\0b\n");
        req.extend_from_slice(&80u16.to_be_bytes());
        let mut d = Duplex::new(req);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(rep_byte(&d.output), Some(REP_ADDR_NOT_SUPPORTED));
    }

    #[test]
    fn socks5_rejects_bind_and_udp_commands() {
        for cmd in [0x02u8, 0x03, 0xFF] {
            let mut req = NO_AUTH_GREETING.to_vec();
            req.extend_from_slice(&[0x05, cmd, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50]);
            let mut d = Duplex::new(req);
            assert!(socks5_handshake(&mut d).is_err());
            assert_eq!(rep_byte(&d.output), Some(REP_CMD_NOT_SUPPORTED), "cmd {:#04x}", cmd);
        }
    }

    #[test]
    fn socks5_rejects_unknown_address_type() {
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4, 0x00, 0x50]);
        let mut d = Duplex::new(req);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(rep_byte(&d.output), Some(REP_ADDR_NOT_SUPPORTED));
    }

    #[test]
    fn socks5_rejects_wrong_request_version() {
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50]);
        let mut d = Duplex::new(req);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(rep_byte(&d.output), Some(REP_GENERAL_FAILURE));
    }

    #[test]
    fn socks5_rejects_zero_port() {
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x00]);
        let mut d = Duplex::new(req);
        assert!(socks5_handshake(&mut d).is_err());
        assert_eq!(rep_byte(&d.output), Some(REP_GENERAL_FAILURE));
    }

    #[test]
    fn socks5_reply_is_a_well_formed_frame() {
        let mut out = Vec::new();
        socks5_reply(&mut out, REP_SUCCESS).unwrap();
        assert_eq!(out.as_slice(), &[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    /// The no-auth greeting, then a CONNECT to `host:port` by name.
    fn socks5_connect_request(host: &str, port: u16) -> Vec<u8> {
        let mut req = NO_AUTH_GREETING.to_vec();
        req.extend_from_slice(&[0x05, 0x01, 0x00, SOCKS5_ATYP_DOMAIN, host.len() as u8]);
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        req
    }

    #[test]
    fn socks5_connect_answers_with_what_the_open_did() {
        let mut opened = Duplex::new(socks5_connect_request("db.internal", 5432));
        let got = socks5_connect(&mut opened, |t| Ok(t.clone())).unwrap();
        assert_eq!(got, SocksTarget { host: "db.internal".into(), port: 5432 });
        assert_eq!(rep_byte(&opened.output), Some(REP_SUCCESS));

        // The jump host tried and failed: that answer is about the target.
        let mut refused = Duplex::new(socks5_connect_request("db.internal", 5432));
        let failed: Result<(), String> = socks5_connect(&mut refused, |_| {
            Err(OpenError::Ssh(ssh2::Error::new(
                ssh2::ErrorCode::Session(-21), // LIBSSH2_ERROR_CHANNEL_FAILURE
                "Channel open failure (connect failed)",
            )))
        });
        assert!(failed.is_err());
        assert_eq!(rep_byte(&refused.output), Some(REP_HOST_UNREACHABLE));

        // No turn to open in: that answer is about this server.
        let mut busy = Duplex::new(socks5_connect_request("db.internal", 5432));
        let failed: Result<(), String> = socks5_connect(&mut busy, |_| Err(OpenError::NoTurn));
        assert!(failed.is_err());
        assert_eq!(rep_byte(&busy.output), Some(REP_GENERAL_FAILURE));
    }

    #[test]
    fn a_socks5_request_stuck_behind_a_stalled_open_is_answered_promptly_and_truthfully() {
        let shared = Arc::new(SharedSession {
            stall_after: Duration::from_millis(50),
            ..fake_session(OPEN_TURN_WAIT)
        });
        // Another client's CONNECT, to a blackholed target, holds the turn.
        let stuck = open_in_background(&shared, "blackhole.internal:443", 200);

        let mut client = Duplex::new(socks5_connect_request("web.internal", 443));
        let started = Instant::now();
        let result = socks5_connect(&mut client, |t| {
            let target = format!("{}:{}", t.host, t.port);
            shared.request(|fake| fake.open(&target, 0))
        });
        let waited = started.elapsed();

        assert!(result.is_err(), "{:?}", result);
        // 0x01, general server failure. web.internal was never tried, so 0x04
        // "host unreachable" would tell the client something false about it.
        assert_eq!(rep_byte(&client.output), Some(REP_GENERAL_FAILURE));
        assert!(waited < Duration::from_millis(500), "the client waited {:?} for its answer", waited);
        assert_eq!(stuck.join().unwrap().unwrap(), "blackhole.internal:443");
        assert!(shared.lock().resumed_foreign.is_empty());
    }

    // -- TunnelStore secrets -------------------------------------------------

    const PW: &str = "correct horse battery staple";

    /// A scratch directory holding a vault plus a tunnels.json, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::AtomicUsize;
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "neoshell-tunnel-test-{}-{}-{}",
                std::process::id(),
                tag,
                N.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn tunnels(&self) -> PathBuf {
            self.0.join("tunnels.json")
        }

        /// An unlocked vault over this directory.
        fn vault(&self) -> Arc<ConnectionStore> {
            let v = Arc::new(ConnectionStore::with_vault_path(self.0.join("vault.json")));
            if v.vault_exists() {
                v.unlock(PW).unwrap();
            } else {
                v.set_master_password(PW).unwrap();
            }
            v
        }

        /// A vault that exists but is still locked.
        fn locked_vault(&self) -> Arc<ConnectionStore> {
            let _ = self.vault();
            Arc::new(ConnectionStore::with_vault_path(self.0.join("vault.json")))
        }

        /// `None` means no vault at all here: nothing in the test binary
        /// calls `set_global_vault`, so the lazy fallback finds nothing.
        fn store(&self, vault: Option<Arc<ConnectionStore>>) -> TunnelStore {
            TunnelStore::at(self.tunnels(), vault)
        }

        fn raw(&self) -> String {
            std::fs::read_to_string(self.tunnels()).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Exactly what a pre-0.7.0 build left on disk: a bare array, secrets
    /// inline, and no `kind` on the forward rule either.
    fn write_legacy(s: &Scratch) {
        std::fs::write(
            s.tunnels(),
            r#"[
              {"id":"t1","name":"db","ssh_host":"10.0.0.9","ssh_port":22,
               "username":"jump","auth_type":"password","password":"hunter2",
               "forwards":[{"local_port":13306,"remote_host":"db.internal","remote_port":3306}],
               "auto_start":true}
            ]"#,
        )
        .unwrap();
    }

    fn sample(id: &str) -> TunnelConfig {
        TunnelConfig {
            id: id.to_string(),
            name: "db".to_string(),
            ssh_host: "10.0.0.9".to_string(),
            ssh_port: 22,
            username: "jump".to_string(),
            auth_type: "key".to_string(),
            password: None,
            private_key: Some("/home/u/.ssh/id_ed25519".to_string()),
            passphrase: Some("key-phrase".to_string()),
            forwards: vec![ForwardRule::parse("13306:db.internal:3306").unwrap()],
            auto_start: true,
        }
    }

    #[test]
    fn an_unmigrated_tunnel_file_still_loads_with_its_secret() {
        let s = Scratch::new("legacy-load");
        write_legacy(&s);

        // Even with no vault at all: the secret is still inline.
        let list = s.store(None).load();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].password.as_deref(), Some("hunter2"));
        assert_eq!(list[0].forwards[0].local_port, 13306);
        assert!(list[0].auto_start);
    }

    #[test]
    fn migration_moves_the_secret_and_clears_the_plaintext() {
        let s = Scratch::new("migrate");
        write_legacy(&s);
        let vault = s.vault();
        let store = s.store(Some(vault.clone()));

        assert!(store.migrate_secrets().unwrap());

        let raw = s.raw();
        assert!(!raw.contains("hunter2"), "plaintext survived: {}", raw);
        assert!(raw.contains("\"schema\": 1"), "schema not recorded: {}", raw);
        // The non-secret half stays behind so the UI can list it while locked.
        assert!(raw.contains("db.internal"));
        assert!(raw.contains("10.0.0.9"));

        assert_eq!(
            vault.get_secret("tunnel:t1").unwrap(),
            Some(ProxySecret { password: Some("hunter2".into()), ..Default::default() })
        );

        let back = store.get_for_connect("t1").unwrap();
        assert_eq!(back.password.as_deref(), Some("hunter2"));
        assert_eq!(back.forwards, vec![ForwardRule::parse("13306:db.internal:3306").unwrap()]);
        assert!(back.auto_start);
    }

    #[test]
    fn migration_is_idempotent() {
        let s = Scratch::new("migrate-twice");
        write_legacy(&s);
        let store = s.store(Some(s.vault()));

        assert!(store.migrate_secrets().unwrap());
        let after_first = s.raw();
        assert!(!store.migrate_secrets().unwrap(), "second run must be a no-op");
        assert_eq!(s.raw(), after_first);
        assert_eq!(store.get_for_connect("t1").unwrap().password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn a_locked_vault_defers_migration_instead_of_destroying_the_secret() {
        let s = Scratch::new("migrate-locked");
        write_legacy(&s);
        let before = s.raw();

        for store in [s.store(None), s.store(Some(s.locked_vault()))] {
            assert!(!store.migrate_secrets().unwrap());
            assert_eq!(s.raw(), before, "a locked vault must not touch the file");
            assert_eq!(store.get_for_connect("t1").unwrap().password.as_deref(), Some("hunter2"));
            assert!(store.try_delete("t1").is_err());
        }

        // Unlocking later completes it.
        let store = s.store(Some(s.vault()));
        assert!(store.migrate_secrets().unwrap());
        assert!(!s.raw().contains("hunter2"));
    }

    #[test]
    fn upsert_writes_the_credential_to_the_vault_and_not_to_the_file() {
        let s = Scratch::new("upsert");
        let vault = s.vault();
        let store = s.store(Some(vault.clone()));

        store.try_upsert(sample("t1")).unwrap();
        let raw = s.raw();
        assert!(!raw.contains("key-phrase"), "cleartext in tunnels.json: {}", raw);
        assert!(!raw.contains("id_ed25519"), "key path in tunnels.json: {}", raw);
        assert_eq!(store.get_for_connect("t1").unwrap().passphrase.as_deref(), Some("key-phrase"));
        assert_eq!(
            store.get_for_connect("t1").unwrap().private_key.as_deref(),
            Some("/home/u/.ssh/id_ed25519")
        );

        // Upsert of an existing id replaces rather than duplicating, and
        // clearing the fields drops the stored secret.
        let mut cleared = sample("t1");
        cleared.private_key = None;
        cleared.passphrase = None;
        store.try_upsert(cleared).unwrap();
        assert_eq!(store.load().len(), 1);
        assert_eq!(vault.get_secret("tunnel:t1").unwrap(), None);

        store.try_delete("t1").unwrap();
        assert!(store.get_for_connect("t1").is_err());
    }

    #[test]
    fn a_locked_vault_refuses_to_start_rather_than_offering_no_credential() {
        let s = Scratch::new("connect-locked");
        s.store(Some(s.vault())).try_upsert(sample("t1")).unwrap();

        let locked = s.store(Some(s.locked_vault()));
        // Listing still works — the manager panel needs it.
        let list = locked.load();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].ssh_host, "10.0.0.9");
        assert_eq!(list[0].passphrase, None);
        // Starting does not.
        assert!(locked.get_for_connect("t1").is_err());
        assert!(locked.try_upsert(sample("t2")).is_err());
    }

    #[test]
    fn a_garbled_file_is_reported_and_never_silently_replaced() {
        let s = Scratch::new("garbled");
        std::fs::write(s.tunnels(), "{not json").unwrap();
        let store = s.store(Some(s.vault()));
        assert!(store.load().is_empty());
        assert!(!store.migrate_secrets().unwrap());
        assert_eq!(s.raw(), "{not json");
    }

    #[test]
    fn starting_a_tunnel_that_is_gone_says_so_in_the_ui_language() {
        let s = Scratch::new("gone");
        let err = s.store(None).get_for_connect("nope").unwrap_err();
        assert!(is_message(&err, "tunnel.err.not_found", &[("id", "nope")]), "{}", err);
    }

    // -- Translated errors ----------------------------------------------------

    /// Every translation of `key`, with `params` filled in, read from the
    /// tables' source rather than through the process-wide locale — another
    /// test in this binary flips that locale while it runs.
    fn is_message(err: &str, key: &str, params: &[(&str, &str)]) -> bool {
        const SRC: &str = include_str!("i18n.rs");
        let needle = format!("m.insert(\"{}\", \"", key);
        let all: Vec<String> = SRC
            .match_indices(&needle)
            .map(|(at, _)| {
                let rest = &SRC[at + needle.len()..];
                let mut text = rest[..rest.find("\");").expect("end of entry")].to_string();
                for (name, value) in params {
                    text = text.replace(&format!("{{{}}}", name), value);
                }
                text
            })
            .collect();
        assert_eq!(all.len(), 2, "{} should be in both tables", key);
        all.iter().any(|t| t == err)
    }

    /// Every error that reaches the user — the forward-rule dialog, "Start
    /// tunnel", the save and delete dialogs, a tunnel's ERR line — comes from
    /// the translation tables, and every key this file uses is in both.
    #[test]
    fn user_facing_tunnel_errors_are_translated_in_both_tables() {
        const SRC: &str = include_str!("tunnel.rs");
        const I18N: &str = include_str!("i18n.rs");
        // This file's code, without the tests.
        let code = &SRC[..SRC.find("#[cfg(test)]\nmod tests").expect("test module")];

        let mut used = Vec::new();
        for call in ["i18n::t(", "i18n::tf("] {
            for (at, _) in code.match_indices(call) {
                if let Some(lit) = code[at + call.len()..].trim_start().strip_prefix('"') {
                    used.push(&lit[..lit.find('"').expect("end of key")]);
                }
            }
        }
        for key in [
            "tunnel.err.bad_socks_port",
            "tunnel.err.socks_port_zero",
            "tunnel.err.bad_remote",
            "tunnel.err.bad_remote_port",
            "tunnel.err.bad_local_port",
            "tunnel.err.bad_rule",
            "tunnel.err.missing_host",
            "tunnel.err.not_found",
            "tunnel.err.vault_not_retained",
            "tunnel.err.bind",
            "tunnel.err.remote_listen",
            "tunnel.err.remote_accept",
        ] {
            assert!(used.contains(&key), "{} is not routed through i18n", key);
        }
        // The literals a review found shown raw in English under the Chinese UI.
        for literal in [
            "\"SOCKS5 listen port must not be 0\"",
            "\"bad SOCKS5 listen port",
            "\"missing remote host in",
            "\"invalid remote:",
            "\"bad remote port",
            "\"bad local port",
            "\"expected 'LOCAL:REMOTE_HOST",
            "\"Tunnel '{}' not found\"",
            "\"vault did not retain",
            "\"bind {}: {}\"",
            "\"remote listen on",
            "\"remote accept on port",
        ] {
            assert!(!code.contains(literal), "{} is still an English literal", literal);
        }

        let table = |name: &str| -> &'static str {
            let start = I18N.find(&format!("static {}:", name)).expect("translation table");
            let rest = &I18N[start..];
            &rest[..rest.find("\n});").expect("end of table")]
        };
        let (en, zh) = (table("EN"), table("ZH"));
        for key in used {
            let entry = format!("m.insert(\"{}\",", key);
            assert!(en.contains(&entry), "{} is missing from the EN table", key);
            assert!(zh.contains(&entry), "{} is missing from the ZH table", key);
        }
    }
}
