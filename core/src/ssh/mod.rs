use std::collections::HashMap;
use std::io::{Read as IoRead, Seek, Write as IoWrite};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use ssh2::{MethodType, Session};

/// Configure SSH session with broad algorithm support for maximum server compatibility.
/// Must be called BEFORE session.handshake().
/// Rigorously configure session algorithms for maximum server compatibility.
///
/// Strategy:
/// 1. Query libssh2 for all compiled-in algorithms (via supported_algs)
/// 2. Filter out pseudo-algorithms that aren't real negotiable methods
///    (ext-info-c/s, kex-strict-c-v00@openssh.com — these are extension
///     markers handled internally by libssh2, not transport algorithms)
/// 3. Keep libssh2's default order (modern → legacy)
/// 4. Offer the entire filtered list to the server; server picks the first
///    algorithm from our list that it also supports
///
/// The SSH protocol negotiation itself handles "automatic switching": the
/// client sends ALL offered algorithms in one KEXINIT message, and the
/// server responds with its choice. No per-attempt fallback loop is needed.
fn configure_session_algorithms(session: &Session) {
    // Pseudo-algorithms that must not appear in method_pref.
    // These are SSH extension negotiation markers, not actual crypto methods.
    let is_pseudo = |alg: &str| -> bool {
        alg.starts_with("ext-info-")
            || alg.starts_with("kex-strict-")
    };

    for method in &[
        MethodType::Kex,
        MethodType::HostKey,
        MethodType::CryptCs,
        MethodType::CryptSc,
        MethodType::MacCs,
        MethodType::MacSc,
        MethodType::CompCs,
        MethodType::CompSc,
    ] {
        let supported = match session.supported_algs(*method) {
            Ok(algs) => algs,
            Err(_) => continue,
        };

        // Keep only real crypto algorithms, preserve libssh2's default order
        let real: Vec<&str> = supported.iter()
            .copied()
            .filter(|a| !is_pseudo(a))
            .collect();

        if real.is_empty() {
            continue;
        }

        let list = real.join(",");
        if let Err(e) = session.method_pref(*method, &list) {
            log::warn!("method_pref({:?}) failed with list={}: {}",
                *method as i32, list, e);
            // Don't abort — libssh2 defaults will be used for this method
        }
    }
}

/// Translate ssh2 / libssh2 / TCP error strings into user-friendly explanations.
/// Returns the original message plus an i18n'd hint line when a known pattern is matched.
pub fn translate_ssh_error(raw: &str) -> String {
    let low = raw.to_ascii_lowercase();
    let hint_key: Option<&'static str> = if low.contains("authentication failed")
        || low.contains("auth failed")
        || low.contains("password auth failed")
        || low.contains("all authentication methods")
    {
        Some("ssh.err.auth")
    } else if low.contains("connection refused") {
        Some("ssh.err.refused")
    } else if low.contains("timed out") || low.contains("timeout") {
        Some("ssh.err.timeout")
    } else if low.contains("no route to host") {
        Some("ssh.err.no_route")
    } else if low.contains("host key") && (low.contains("mismatch") || low.contains("changed") || low.contains("verification")) {
        Some("ssh.err.host_key")
    } else if low.contains("dns") || low.contains("name or service not known") || low.contains("no address") || low.contains("failed to lookup") {
        Some("ssh.err.dns")
    } else if low.contains("unable to exchange encryption keys")
        || low.contains("kex")
        || low.contains("key exchange")
    {
        Some("ssh.err.kex")
    } else if low.contains("permission denied") {
        Some("ssh.err.denied")
    } else if low.contains("private key file not found") || low.contains("no such file") {
        Some("ssh.err.key_missing")
    } else if low.contains("invalid") && low.contains("key") {
        Some("ssh.err.key_format")
    } else if low.contains("broken pipe") || low.contains("connection reset") {
        Some("ssh.err.reset")
    } else {
        None
    };
    match hint_key {
        Some(k) => {
            let hint = crate::i18n::t(k);
            if hint.is_empty() || hint == k {
                raw.to_string()
            } else {
                format!("{} — {}", raw, hint)
            }
        }
        None => raw.to_string(),
    }
}

/// Result of a lightweight SSH connection test (TCP + handshake + auth, no shell).
#[derive(Debug, Clone)]
pub struct ConnectionTestResult {
    pub ok: bool,
    pub latency_ms: u64,
    pub stage: String,          // "tcp" | "handshake" | "auth" | "done"
    pub error: Option<String>,  // friendly error when ok=false
}

/// Commands sent from the UI to an SSH session.
pub enum SshCommand {
    Write(Vec<u8>),
    Resize(u32, u32),
    Disconnect,
}

/// Events emitted by an SSH session back to the UI.
pub enum SshEvent {
    Data { session_id: String, data: Vec<u8> },
    Closed { session_id: String },
    Error { session_id: String, error: String },
    Reconnecting { session_id: String, attempt: u32 },
    Reconnected { session_id: String },
}

/// Credentials and connection parameters stored for automatic reconnection.
#[derive(Clone)]
pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    pub proxy_id: Option<String>,
}

/// Attempt an SSH handshake. When `configure_algos` is true, applies our
/// filtered algorithm list via method_pref; when false, uses libssh2 defaults
/// (which includes kex-strict and ext-info markers that some modern OpenSSH
/// servers require). The fallback covers edge cases where method_pref would
/// otherwise break kex-strict negotiation.
fn try_handshake(
    params: &ConnectParams,
    timeout_ms: u32,
    configure_algos: bool,
) -> Result<Session, String> {
    let tcp = establish_tcp(params)?;
    tcp.set_nonblocking(false)
        .map_err(|e| format!("Failed to set blocking mode: {}", e))?;

    let mut session = Session::new()
        .map_err(|e| format!("Failed to create SSH session: {}", e))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(timeout_ms);
    if configure_algos {
        configure_session_algorithms(&session);
    }
    session
        .handshake()
        .map_err(|e| e.to_string())?;
    Ok(session)
}

/// Establish TCP connection, optionally through a proxy.
fn establish_tcp(params: &ConnectParams) -> Result<TcpStream, String> {
    use crate::proxy::{self, ProxyStore};

    if let Some(ref proxy_id) = params.proxy_id {
        let store = ProxyStore::new();
        if let Some(proxy_cfg) = store.get(proxy_id) {
            return proxy::connect_via_proxy(
                &proxy_cfg,
                &params.host,
                params.port,
                Duration::from_secs(15),
            );
        }
        // proxy_id set but proxy not found — fall through to direct
        log::warn!("Proxy '{}' not found, connecting directly", proxy_id);
    }
    proxy::connect_direct(&params.host, params.port, Duration::from_secs(10))
}

/// How the interactive shell is wrapped for session persistence.
#[derive(Clone, Debug)]
pub enum SessionMode {
    /// Persistent session using remote FIFO pipes + setsid shell.
    /// Shell survives SSH disconnect; reconnect reattaches via pipes.
    Persistent(String),  // session name (used for FIFO paths)
    /// Raw shell — reconnect gets a new shell, display preserved locally only.
    RawShell,
}

/// Per-interface network statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetInterface {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Per-mount-point disk usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskInfo {
    pub filesystem: String,
    pub mount_point: String,
    pub total: String,
    pub used: String,
    pub avail: String,
    pub percent: f64,
    pub total_gb: f64,
    pub used_gb: f64,
}

/// Server resource statistics collected via SSH exec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerStats {
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub cpu_cores: usize,
    pub mem_total_mb: u64,
    pub mem_used_mb: u64,
    pub mem_percent: f64,
    pub disk_total_gb: f64,
    pub disk_used_gb: f64,
    pub disk_percent: f64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub net_rx_rate: String,
    pub net_tx_rate: String,
    pub uptime: String,
    pub interfaces: Vec<NetInterface>,
    pub disks: Vec<DiskInfo>,
}

/// A single process entry from `ps aux`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub user: String,
    pub cpu: f64,
    pub mem: f64,
    pub command: String,
}

/// A file/directory entry from `ls -la`.
#[derive(Debug, Clone, Default)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: String,
    pub permissions: String,
    pub modified: String,
    pub owner: String,
}

/// Shared progress state for SFTP file transfers.
#[derive(Debug)]
pub struct TransferProgress {
    pub transferred: AtomicU64,
    pub total: AtomicU64,
    pub finished: AtomicBool,
    pub error: parking_lot::Mutex<Option<String>>,
    pub filename: parking_lot::Mutex<String>,
    pub start_time: parking_lot::Mutex<Option<std::time::Instant>>,
}

impl TransferProgress {
    pub fn new() -> Self {
        Self {
            transferred: AtomicU64::new(0),
            total: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            error: parking_lot::Mutex::new(None),
            filename: parking_lot::Mutex::new(String::new()),
            start_time: parking_lot::Mutex::new(None),
        }
    }

    pub fn percent(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let transferred = self.transferred.load(Ordering::Relaxed);
        (transferred as f64 / total as f64 * 100.0).min(100.0)
    }

    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Relaxed)
    }
}

/// A handle to a single active SSH session.
pub struct SshSession {
    pub session_id: String,
    pub connection_id: String,
    /// Channel for sending commands (write, resize, disconnect) into the
    /// session's background thread.
    pub writer: tokio::sync::mpsc::Sender<SshCommand>,
    /// SEPARATE SSH session dedicated to exec commands (monitoring, file listing).
    /// None for minimal SSH servers (MINA SSHD, embedded devices) where a
    /// second parallel connection would either be rejected or disrupt the main
    /// shell. Consumers must check this before calling exec_command etc.
    pub exec_session: Option<Arc<Mutex<Session>>>,
    /// Connection parameters stored for automatic reconnection.
    pub params: ConnectParams,
    /// Session persistence mode.
    pub mode: SessionMode,
    /// True when the server banner doesn't identify as OpenSSH — disables
    /// setenv, keepalive, exec-based shell start, and monitoring exec calls.
    pub minimal_mode: bool,
}

/// Manages multiple concurrent SSH sessions.
pub struct SshManager {
    sessions: RwLock<HashMap<String, SshSession>>,
    event_tx: mpsc::Sender<SshEvent>,
}

impl SshManager {
    pub fn new() -> (Self, mpsc::Receiver<SshEvent>) {
        let (event_tx, event_rx) = mpsc::channel();
        (
            SshManager {
                sessions: RwLock::new(HashMap::new()),
                event_tx,
            },
            event_rx,
        )
    }

    /// Quickly verify a connection is reachable and authenticates.
    /// No shell channel is opened — returns as soon as the session is authenticated.
    /// Intended for a "Test" button in the connection form.
    #[allow(clippy::too_many_arguments)]
    pub fn test_connection(
        host: &str,
        port: u16,
        username: &str,
        auth_type: &str,
        password: Option<&str>,
        private_key: Option<&str>,
        passphrase: Option<&str>,
        proxy_id: Option<&str>,
    ) -> ConnectionTestResult {
        use std::time::Instant;
        let start = Instant::now();

        let params = ConnectParams {
            host: host.to_string(),
            port,
            username: username.to_string(),
            auth_type: auth_type.to_string(),
            password: password.map(|s| s.to_string()),
            private_key: private_key.map(|s| s.to_string()),
            passphrase: passphrase.map(|s| s.to_string()),
            proxy_id: proxy_id.map(|s| s.to_string()),
        };

        // --- TCP ---
        let tcp = match establish_tcp(&params) {
            Ok(t) => t,
            Err(e) => {
                return ConnectionTestResult {
                    ok: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    stage: "tcp".into(),
                    error: Some(translate_ssh_error(&e)),
                };
            }
        };

        // --- Handshake ---
        let mut session = match Session::new() {
            Ok(s) => s,
            Err(e) => {
                return ConnectionTestResult {
                    ok: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    stage: "handshake".into(),
                    error: Some(format!("Session::new failed: {}", e)),
                };
            }
        };
        session.set_tcp_stream(tcp);
        session.set_timeout(10_000);
        configure_session_algorithms(&session);
        if let Err(e) = session.handshake() {
            return ConnectionTestResult {
                ok: false,
                latency_ms: start.elapsed().as_millis() as u64,
                stage: "handshake".into(),
                error: Some(translate_ssh_error(&e.to_string())),
            };
        }

        // --- Authenticate ---
        let auth_err = match auth_type {
            "password" => {
                let pw = match password {
                    Some(p) => p,
                    None => {
                        return ConnectionTestResult {
                            ok: false,
                            latency_ms: start.elapsed().as_millis() as u64,
                            stage: "auth".into(),
                            error: Some("密码未填写".into()),
                        };
                    }
                };
                session.userauth_password(username, pw).err().map(|e| e.to_string())
            }
            "key" => {
                let key_path_str = match private_key {
                    Some(p) => p,
                    None => {
                        return ConnectionTestResult {
                            ok: false,
                            latency_ms: start.elapsed().as_millis() as u64,
                            stage: "auth".into(),
                            error: Some("私钥路径未填写".into()),
                        };
                    }
                };
                let key_path = std::path::Path::new(key_path_str);
                if !key_path.exists() {
                    return ConnectionTestResult {
                        ok: false,
                        latency_ms: start.elapsed().as_millis() as u64,
                        stage: "auth".into(),
                        error: Some(format!("私钥文件不存在: {}", key_path_str)),
                    };
                }
                session
                    .userauth_pubkey_file(username, None, key_path, passphrase)
                    .err()
                    .map(|e| e.to_string())
            }
            other => Some(format!("Unknown auth type: {}", other)),
        };
        if let Some(e) = auth_err {
            return ConnectionTestResult {
                ok: false,
                latency_ms: start.elapsed().as_millis() as u64,
                stage: "auth".into(),
                error: Some(translate_ssh_error(&e)),
            };
        }
        if !session.authenticated() {
            return ConnectionTestResult {
                ok: false,
                latency_ms: start.elapsed().as_millis() as u64,
                stage: "auth".into(),
                error: Some(translate_ssh_error("Authentication failed")),
            };
        }

        ConnectionTestResult {
            ok: true,
            latency_ms: start.elapsed().as_millis() as u64,
            stage: "done".into(),
            error: None,
        }
    }

    /// Connect using a ConnectionConfig (convenience wrapper).
    pub fn connect_config(
        &self,
        config: &crate::storage::ConnectionConfig,
    ) -> Result<String, String> {
        self.connect(
            config.id.clone(),
            &config.host,
            config.port,
            &config.username,
            &config.auth_type,
            config.password.as_deref(),
            config.private_key.as_deref(),
            config.passphrase.as_deref(),
            config.proxy_id.as_deref(),
        )
    }

    /// Alias for write() used by the UI layer.
    pub fn send_data(&self, session_id: &str, data: &[u8]) -> Result<(), String> {
        self.write(session_id, data)
    }

    /// Establish a new SSH connection and return the session id.
    ///
    /// The connection runs on a background thread; data arriving from the
    /// remote host is forwarded as `SshEvent::Data` through the event channel.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        &self,
        connection_id: String,
        host: &str,
        port: u16,
        username: &str,
        auth_type: &str,
        password: Option<&str>,
        private_key: Option<&str>,
        passphrase: Option<&str>,
        proxy_id: Option<&str>,
    ) -> Result<String, String> {
        let session_id = uuid::Uuid::new_v4().to_string();

        let tmp_params = ConnectParams {
            host: host.to_string(),
            port,
            username: username.to_string(),
            auth_type: auth_type.to_string(),
            password: password.map(|s| s.to_string()),
            private_key: private_key.map(|s| s.to_string()),
            passphrase: passphrase.map(|s| s.to_string()),
            proxy_id: proxy_id.map(|s| s.to_string()),
        };

        // --- Establish SSH handshake ---------------------------------------
        // --- Pre-handshake banner peek — read up to 128 bytes from a disposable TCP
        // connection so we know what SSH implementation is on the other end, even
        // if KEX fails later. Does not interfere with the real handshake socket.
        if let Ok(mut peek_tcp) = establish_tcp(&tmp_params) {
            peek_tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut buf = [0u8; 128];
            if let Ok(n) = std::io::Read::read(&mut peek_tcp, &mut buf) {
                let line = String::from_utf8_lossy(&buf[..n]);
                let banner_line = line.lines().next().unwrap_or("").trim();
                log::info!("SSH peek {}:{} — server announces: {}", host, port, banner_line);
            }
            drop(peek_tcp);
        }

        // Attempt handshake — two-phase retry to handle both old and modern servers.
        // Phase 1: filtered algorithm list (our preferred path)
        // Phase 2: fall back to libssh2 defaults (uncustomized) to handle kex-strict servers
        let session = match try_handshake(&tmp_params, 15000, true) {
            Ok(s) => s,
            Err(e1) => {
                log::warn!("First handshake attempt failed ({}), retrying with libssh2 defaults", e1);
                match try_handshake(&tmp_params, 15000, false) {
                    Ok(s) => {
                        log::info!("Fallback handshake (default algorithms) succeeded");
                        s
                    }
                    Err(e2) => {
                        // Both attempts failed — log full client-side diagnostics
                        if let Ok(sess) = Session::new() {
                            let kex = sess.supported_algs(MethodType::Kex).unwrap_or_default();
                            let hk = sess.supported_algs(MethodType::HostKey).unwrap_or_default();
                            let cipher = sess.supported_algs(MethodType::CryptCs).unwrap_or_default();
                            let mac = sess.supported_algs(MethodType::MacCs).unwrap_or_default();
                            log::error!(
                                "Both SSH handshake attempts failed.\n  Primary: {}\n  Fallback: {}\n  Client KEX: {}\n  Client HostKey: {}\n  Client Cipher: {}\n  Client MAC: {}",
                                e1, e2, kex.join(","), hk.join(","), cipher.join(","), mac.join(",")
                            );
                        }
                        return Err(translate_ssh_error(&format!("SSH handshake failed: {}", e2)));
                    }
                }
            }
        };

        let server_banner = session.banner().unwrap_or("<unknown>").to_string();
        log::info!("SSH handshake OK to {}:{} (banner: {}), authenticating as {} ({})",
            host, port, server_banner, username, auth_type);

        // --- Authenticate --------------------------------------------------
        match auth_type {
            "password" => {
                let pw = password.ok_or("Password required for password auth")?;
                session
                    .userauth_password(username, pw)
                    .map_err(|e| translate_ssh_error(&format!("Password auth failed: {}", e)))?;
            }
            "key" => {
                let key_path_str =
                    private_key.ok_or("Private key path required for key auth")?;
                let key_path = std::path::Path::new(key_path_str);
                log::info!("SSH key auth: user={}, key={}, exists={}", username, key_path_str, key_path.exists());

                if !key_path.exists() {
                    return Err(format!("Private key file not found: {}", key_path_str));
                }

                // Try pubkey_file first, then try loading key from memory
                match session.userauth_pubkey_file(username, None, key_path, passphrase) {
                    Ok(()) => {
                        log::info!("SSH key auth succeeded via pubkey_file");
                    }
                    Err(e) => {
                        log::warn!("pubkey_file failed ({}), trying in-memory key auth", e);
                        // Read key content and try userauth_pubkey_frommemory
                        // Fallback: write key to temp file and retry
                        let tmp_key = std::env::temp_dir().join(format!("neoshell_key_{}", uuid::Uuid::new_v4()));
                        std::fs::copy(key_path, &tmp_key)
                            .map_err(|e2| format!("Failed to copy key: {}", e2))?;
                        let result = session.userauth_pubkey_file(username, None, &tmp_key, passphrase);
                        let _ = std::fs::remove_file(&tmp_key);
                        result.map_err(|e2| format!("Key auth failed: {}, retry: {}", e, e2))?;
                        log::info!("SSH key auth succeeded via in-memory pubkey");
                    }
                }
            }
            other => {
                return Err(format!("Unknown auth type: {}", other));
            }
        }

        if !session.authenticated() {
            return Err("Authentication failed".to_string());
        }

        // --- Classify server — minimal SSH servers (MINA SSHD, embedded devices)
        // can't handle the full feature set. Banner detection gates everything.
        let banner_lower = session.banner().unwrap_or("").to_ascii_lowercase();
        let minimal_mode = !banner_lower.contains("openssh");
        if minimal_mode {
            log::info!("Minimal SSH mode (banner {:?}) — disabling keepalive, setenv, exec_session, monitoring", banner_lower);
        }

        // --- Enable SSH keepalive only for OpenSSH; minimal servers may interpret
        // the keepalive probe as a protocol violation and disconnect.
        if !minimal_mode {
            session.set_keepalive(true, 15);
        }

        // --- Build ConnectParams for reconnection -------------------------
        let params = tmp_params;

        // --- Open a SECOND independent SSH connection for exec commands ----
        // Skipped in minimal mode: many embedded devices limit to 1 concurrent
        // SSH session; a second connection causes both to disconnect.
        let exec_session: Option<Arc<Mutex<Session>>> = if minimal_mode {
            None
        } else {
            let tcp2 = establish_tcp(&params)?;

            let mut sess2 = Session::new()
                .map_err(|e| format!("Failed to create exec session: {}", e))?;
            sess2.set_tcp_stream(tcp2);
            configure_session_algorithms(&sess2);
            sess2.handshake()
                .map_err(|e| format!("Exec SSH handshake failed: {}", e))?;

            match auth_type {
                "password" => {
                    let pw = password.ok_or("Password required")?;
                    sess2.userauth_password(username, pw)
                        .map_err(|e| format!("Exec auth failed: {}", e))?;
                }
                "key" => {
                    let key_str = private_key.ok_or("Private key required")?;
                    let key_path = std::path::Path::new(key_str);
                    if sess2.userauth_pubkey_file(username, None, key_path, passphrase).is_err() {
                        let key_data = std::fs::read_to_string(key_path)
                            .map_err(|e| format!("Failed to read key: {}", e))?;
                        let tmp_key = std::env::temp_dir().join(format!("neoshell_ekey_{}", uuid::Uuid::new_v4()));
                        std::fs::write(&tmp_key, &key_data).map_err(|e| format!("Write tmp key: {}", e))?;
                        let result = sess2.userauth_pubkey_file(username, None, &tmp_key, passphrase);
                        let _ = std::fs::remove_file(&tmp_key);
                        result.map_err(|e| format!("Exec key auth failed: {}", e))?;
                    }
                }
                _ => return Err(format!("Unknown auth type: {}", auth_type)),
            }

            sess2.set_keepalive(true, 15);

            Some(Arc::new(Mutex::new(sess2)))
        };

        // --- Detect session persistence capability --------------------------
        // Minimal mode: always RawShell, no probing at all.
        let session_name = format!("neo-{}", &session_id[..8]);
        let mode = if minimal_mode {
            SessionMode::RawShell
        } else if let Some(ref es) = exec_session {
            let sess2 = es.lock();
            detect_and_setup_session(&sess2, &session_name)
        } else {
            SessionMode::RawShell
        };
        log::info!("Session mode: {:?}", mode);

        // --- Open channel, request PTY, start shell -------------------------
        let mut channel = session
            .channel_session()
            .map_err(|e| format!("Failed to open channel: {}", e))?;

        channel
            .request_pty("xterm-256color", None, Some((120, 40, 0, 0)))
            .map_err(|e| format!("PTY request failed: {}", e))?;

        // Set UTF-8 locale. Skip entirely for minimal servers — some of them
        // (MINA SSHD 0.9.5, certain embedded firmware) treat unknown setenv as
        // protocol violation and disconnect.
        if !minimal_mode {
            let _ = channel.setenv("LANG", "en_US.UTF-8");
            let _ = channel.setenv("LC_ALL", "en_US.UTF-8");
            let _ = channel.setenv("TERM", "xterm-256color");
        }

        match &mode {
            SessionMode::Persistent(name) => {
                // Create or attach to persistent tmux session with hidden UI
                let cmd = format!(
                    "export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 TERM=xterm-256color; \
                     tmux has-session -t {n} 2>/dev/null && tmux attach-session -t {n} || \
                     (tmux new-session -d -s {n} -x 80 -y 24 2>/dev/null && \
                      tmux set-option -t {n} status off 2>/dev/null && \
                      tmux set-option -t {n} escape-time 10 2>/dev/null && \
                      tmux attach-session -t {n}) || exec $SHELL -l",
                    n = name
                );
                channel
                    .exec(&cmd)
                    .map_err(|e| format!("Session setup failed: {}", e))?;
            }
            SessionMode::RawShell => {
                // Minimal servers: use a plain SSH "shell" request — the widest-
                // compatibility path. Embedded devices often don't support "exec".
                if minimal_mode {
                    channel
                        .shell()
                        .map_err(|e| format!("Shell request failed: {}", e))?;
                } else {
                    channel
                        .exec("LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 TERM=xterm-256color exec $SHELL -l")
                        .unwrap_or_else(|_| {
                            let _ = channel.shell();
                        });
                }
            }
        }

        // Make the session non-blocking for reading
        session.set_blocking(false);

        // Wrap the channel in Arc<Mutex> so both the reader and writer threads
        // (and the write() method) can share it.
        let channel = Arc::new(Mutex::new(channel));

        // Create a tokio mpsc channel for commands coming from the UI.
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<SshCommand>(256);

        // Clone handles for the background threads.
        let sid_reader = session_id.clone();
        let event_tx = self.event_tx.clone();
        let channel_reader = Arc::clone(&channel);

        // Wrap session in Arc so we can share it between reader & writer.
        let session = Arc::new(Mutex::new(session));
        let session_writer = Arc::clone(&session);
        let session_reader = Arc::clone(&session);

        // Clone reconnection context for the reader thread.
        let reader_params = params.clone();
        let reader_mode = mode.clone();
        let reader_minimal = minimal_mode;
        let reader_exec = exec_session.clone();

        // --- Reader thread: reads from SSH channel, emits SshEvent ---------
        // On EOF or error (not WouldBlock), attempts auto-reconnect with
        // exponential backoff before giving up and sending Closed.
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            'outer: loop {
                let result = {
                    let mut ch = channel_reader.lock();
                    ch.read(&mut buf)
                };
                match result {
                    Ok(n) if n > 0 => {
                        let data = buf[..n].to_vec();
                        if event_tx
                            .send(SshEvent::Data {
                                session_id: sid_reader.clone(),
                                data,
                            })
                            .is_err()
                        {
                            break; // receiver dropped
                        }
                        continue 'outer;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Non-blocking read: nothing available yet.
                        std::thread::sleep(Duration::from_millis(10));
                        continue 'outer;
                    }
                    Ok(_zero) => {
                        // EOF — remote closed the channel
                    }
                    Err(ref e) => {
                        let _ = event_tx.send(SshEvent::Error {
                            session_id: sid_reader.clone(),
                            error: format!("Read error: {}", e),
                        });
                    }
                }

                // --- Reconnection logic (reached on EOF or real error) ----
                let max_retries: u32 = 10;
                let mut retry: u32 = 0;
                let mut backoff_ms: u64 = 1000;

                loop {
                    retry += 1;
                    if retry > max_retries {
                        let _ = event_tx.send(SshEvent::Closed {
                            session_id: sid_reader.clone(),
                        });
                        break 'outer;
                    }

                    let _ = event_tx.send(SshEvent::Reconnecting {
                        session_id: sid_reader.clone(),
                        attempt: retry,
                    });

                    std::thread::sleep(Duration::from_millis(backoff_ms));
                    backoff_ms = (backoff_ms * 2).min(30_000);

                    match reconnect_ssh(&reader_params, &reader_mode, reader_minimal) {
                        Ok((new_session, new_channel, new_exec)) => {
                            // Replace channel first (writer shares this Arc)
                            {
                                let mut ch = channel_reader.lock();
                                *ch = new_channel;
                            }
                            // Replace interactive session
                            {
                                let mut sess = session_reader.lock();
                                *sess = new_session;
                            }
                            // Replace exec session for monitoring/SFTP (only if we have one)
                            if let (Some(slot), Some(fresh)) = (reader_exec.as_ref(), new_exec) {
                                let mut es = slot.lock();
                                *es = fresh;
                            }

                            let _ = event_tx.send(SshEvent::Reconnected {
                                session_id: sid_reader.clone(),
                            });

                            // Resume reading from the new channel
                            continue 'outer;
                        }
                        Err(_) => {
                            continue; // next retry
                        }
                    }
                }
            }
        });

        // --- Writer thread: receives SshCommand, writes to channel ---------
        let sid_writer = session_id.clone();
        let channel_writer = Arc::clone(&channel);
        let event_tx_w = self.event_tx.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime for SSH writer");

            rt.block_on(async move {
                while let Some(cmd) = cmd_rx.recv().await {
                    match cmd {
                        SshCommand::Write(data) => {
                            let mut ch = channel_writer.lock();
                            // Must set blocking for writes
                            {
                                let sess = session_writer.lock();
                                sess.set_blocking(true);
                            }
                            if let Err(e) = ch.write_all(&data) {
                                let _ = event_tx_w.send(SshEvent::Error {
                                    session_id: sid_writer.clone(),
                                    error: format!("Write error: {}", e),
                                });
                            }
                            if let Err(e) = ch.flush() {
                                let _ = event_tx_w.send(SshEvent::Error {
                                    session_id: sid_writer.clone(),
                                    error: format!("Flush error: {}", e),
                                });
                            }
                            // Back to non-blocking for the reader
                            {
                                let sess = session_writer.lock();
                                sess.set_blocking(false);
                            }
                        }
                        SshCommand::Resize(cols, rows) => {
                            let mut ch = channel_writer.lock();
                            {
                                let sess = session_writer.lock();
                                sess.set_blocking(true);
                            }
                            if let Err(e) = ch.request_pty_size(cols, rows, None, None) {
                                let _ = event_tx_w.send(SshEvent::Error {
                                    session_id: sid_writer.clone(),
                                    error: format!("Resize error: {}", e),
                                });
                            }
                            {
                                let sess = session_writer.lock();
                                sess.set_blocking(false);
                            }
                        }
                        SshCommand::Disconnect => {
                            let mut ch = channel_writer.lock();
                            {
                                let sess = session_writer.lock();
                                sess.set_blocking(true);
                            }
                            let _ = ch.send_eof();
                            let _ = ch.close();
                            break;
                        }
                    }
                }
            });
        });

        // --- Register the session ------------------------------------------
        let ssh_session = SshSession {
            session_id: session_id.clone(),
            connection_id,
            writer: cmd_tx,
            exec_session,
            params,
            mode,
            minimal_mode,
        };

        self.sessions.write().insert(session_id.clone(), ssh_session);

        Ok(session_id)
    }

    /// Send raw bytes to the remote shell.
    pub fn write(&self, session_id: &str, data: &[u8]) -> Result<(), String> {
        let writer = {
            let sessions = self.sessions.read();
            sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?
                .writer.clone()
        };
        // sessions read lock dropped
        writer
            .try_send(SshCommand::Write(data.to_vec()))
            .map_err(|e| format!("Failed to send write command: {}", e))
    }

    /// Request a PTY resize on the remote end.
    pub fn resize(&self, session_id: &str, cols: u32, rows: u32) -> Result<(), String> {
        let writer = {
            let sessions = self.sessions.read();
            sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?
                .writer.clone()
        };
        // sessions read lock dropped
        writer
            .try_send(SshCommand::Resize(cols, rows))
            .map_err(|e| format!("Failed to send resize command: {}", e))
    }

    /// Disconnect a session.
    pub fn disconnect(&self, session_id: &str) -> Result<(), String> {
        let writer = {
            let sessions = self.sessions.read();
            sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?
                .writer.clone()
        };
        // sessions read lock dropped before sending command and taking write lock
        let _ = writer.try_send(SshCommand::Disconnect);
        self.sessions.write().remove(session_id);
        Ok(())
    }

    /// Get a list of active session ids.
    pub fn active_sessions(&self) -> Vec<String> {
        self.sessions.read().keys().cloned().collect()
    }

    /// Execute a single command via the dedicated exec session and return stdout.
    /// Auto-reconnects the exec session on failure and retries once.
    pub fn exec_command(&self, session_id: &str, command: &str) -> Result<String, String> {
        match self.exec_command_inner(session_id, command) {
            Ok(output) => Ok(output),
            Err(_first_err) => {
                // Exec session may be dead — try to rebuild it
                self.rebuild_exec_session(session_id)?;
                // Retry once with the new session
                self.exec_command_inner(session_id, command)
            }
        }
    }

    fn exec_command_inner(&self, session_id: &str, command: &str) -> Result<String, String> {
        let exec_session = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            match &s.exec_session {
                Some(es) => es.clone(),
                None => return Err("exec not supported on this server (minimal SSH mode)".into()),
            }
        };

        let sess = exec_session.lock();
        sess.set_blocking(true);

        let mut channel = sess
            .channel_session()
            .map_err(|e| format!("Failed to open exec channel: {}", e))?;
        // Force UTF-8 locale for all exec commands
        let utf8_cmd = format!("export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 2>/dev/null; {}", command);
        channel
            .exec(&utf8_cmd)
            .map_err(|e| format!("Failed to exec command: {}", e))?;

        let mut output = String::new();
        channel
            .read_to_string(&mut output)
            .map_err(|e| format!("Failed to read command output: {}", e))?;
        let _ = channel.wait_close();

        Ok(output)
    }

    /// Get the exec session Arc (with auto-reconnect on failure).
    /// Returns Err for minimal-mode sessions that have no exec_session.
    fn get_exec_session(&self, session_id: &str) -> Result<Arc<Mutex<Session>>, String> {
        let exec_session = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            match &s.exec_session {
                Some(es) => es.clone(),
                None => return Err("exec not supported on this server (minimal SSH mode)".into()),
            }
        };

        // Quick health check: try to set blocking (fails if TCP is dead)
        {
            let sess = exec_session.lock();
            sess.set_blocking(true);
            if sess.channel_session().is_err() {
                drop(sess);
                // Rebuild and return fresh session
                self.rebuild_exec_session(session_id)?;
                let sessions = self.sessions.read();
                let s = sessions.get(session_id).ok_or("Session not found")?;
                return match &s.exec_session {
                    Some(es) => Ok(es.clone()),
                    None => Err("exec not supported".into()),
                };
            }
        }

        Ok(exec_session)
    }

    /// Rebuild the exec session by creating a fresh SSH connection.
    /// No-op for minimal-mode sessions.
    fn rebuild_exec_session(&self, session_id: &str) -> Result<(), String> {
        let (params, has_slot) = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            (s.params.clone(), s.exec_session.is_some())
        };

        if !has_slot {
            return Err("minimal SSH mode: no exec_session to rebuild".into());
        }

        let new_exec = create_exec_connection(&params)?;

        // Replace the exec session in-place
        let sessions = self.sessions.read();
        if let Some(ssh_session) = sessions.get(session_id) {
            if let Some(slot) = &ssh_session.exec_session {
                let mut old = slot.lock();
                *old = new_exec;
            }
        }
        Ok(())
    }

    /// Fetch server stats by running monitoring commands.
    pub fn fetch_server_stats(&self, session_id: &str) -> Result<ServerStats, String> {
        // Single compound command for efficiency
        let cmd = "cat /proc/loadavg; echo '---SEPARATOR---'; \
                   free -m; echo '---SEPARATOR---'; \
                   df -hP -x tmpfs -x devtmpfs -x overlay 2>/dev/null || df -h / 2>/dev/null; echo '---SEPARATOR---'; \
                   cat /proc/net/dev 2>/dev/null; echo '---SEPARATOR---'; \
                   nproc 2>/dev/null || echo 1; echo '---SEPARATOR---'; \
                   uptime -p 2>/dev/null || uptime";
        let output = self.exec_command(session_id, cmd)?;

        let sections: Vec<&str> = output.split("---SEPARATOR---").collect();
        let mut stats = ServerStats::default();

        // Parse /proc/loadavg
        if let Some(loadavg) = sections.first() {
            let parts: Vec<&str> = loadavg.trim().split_whitespace().collect();
            if parts.len() >= 3 {
                stats.load_1m = parts[0].parse().unwrap_or(0.0);
                stats.load_5m = parts[1].parse().unwrap_or(0.0);
                stats.load_15m = parts[2].parse().unwrap_or(0.0);
            }
        }

        // Parse free -m
        if let Some(free_output) = sections.get(1) {
            for line in free_output.lines() {
                if line.starts_with("Mem:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        stats.mem_total_mb = parts[1].parse().unwrap_or(0);
                        stats.mem_used_mb = parts[2].parse().unwrap_or(0);
                        if stats.mem_total_mb > 0 {
                            stats.mem_percent =
                                (stats.mem_used_mb as f64 / stats.mem_total_mb as f64) * 100.0;
                        }
                    }
                }
            }
        }

        // Parse df -hP (all real filesystems)
        if let Some(df_output) = sections.get(2) {
            for line in df_output.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let mount = parts[5];
                    // Skip pseudo/system mounts
                    if mount.starts_with("/snap") || mount.starts_with("/boot/efi") {
                        continue;
                    }
                    let total_gb = parse_size_to_gb(parts[1]);
                    let used_gb = parse_size_to_gb(parts[2]);
                    let pct: f64 = parts[4].trim_end_matches('%').parse().unwrap_or(0.0);

                    stats.disks.push(DiskInfo {
                        filesystem: parts[0].to_string(),
                        mount_point: mount.to_string(),
                        total: parts[1].to_string(),
                        used: parts[2].to_string(),
                        avail: parts[3].to_string(),
                        percent: pct,
                        total_gb,
                        used_gb,
                    });

                    // Keep root "/" as the summary stats
                    if mount == "/" {
                        stats.disk_total_gb = total_gb;
                        stats.disk_used_gb = used_gb;
                        stats.disk_percent = pct;
                    }
                }
            }
        }

        // Parse /proc/net/dev (per-interface)
        if let Some(net_output) = sections.get(3) {
            for line in net_output.lines() {
                let line = line.trim();
                if !line.contains(':') || line.starts_with("Inter") || line.starts_with("face") {
                    continue;
                }
                let parts_split: Vec<&str> = line.splitn(2, ':').collect();
                if parts_split.len() < 2 {
                    continue;
                }
                let iface_name = parts_split[0].trim().to_string();
                let values: Vec<&str> = parts_split[1].split_whitespace().collect();
                if values.len() >= 9 {
                    let rx = values[0].parse::<u64>().unwrap_or(0);
                    let tx = values[8].parse::<u64>().unwrap_or(0);
                    if iface_name != "lo" {
                        stats.net_rx_bytes += rx;
                        stats.net_tx_bytes += tx;
                    }
                    stats.interfaces.push(NetInterface {
                        name: iface_name,
                        rx_bytes: rx,
                        tx_bytes: tx,
                    });
                }
            }
        }

        // Parse nproc
        if let Some(nproc) = sections.get(4) {
            stats.cpu_cores = nproc.trim().parse().unwrap_or(1);
        }

        // Parse uptime
        if let Some(uptime) = sections.get(5) {
            stats.uptime = uptime.trim().to_string();
        }

        Ok(stats)
    }

    /// Fetch top processes sorted by CPU usage.
    pub fn fetch_top_processes(
        &self,
        session_id: &str,
        count: usize,
    ) -> Result<Vec<ProcessInfo>, String> {
        let cmd = format!(
            "ps aux --sort=-%cpu 2>/dev/null | head -n {} || ps aux | head -n {}",
            count + 1,
            count + 1,
        );
        let output = self.exec_command(session_id, &cmd)?;

        let mut processes = Vec::new();
        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 11 {
                processes.push(ProcessInfo {
                    pid: parts[1].parse().unwrap_or(0),
                    user: parts[0].to_string(),
                    cpu: parts[2].parse().unwrap_or(0.0),
                    mem: parts[3].parse().unwrap_or(0.0),
                    command: parts[10..].join(" "),
                });
            }
        }

        Ok(processes)
    }

    /// List files in a directory.
    pub fn list_files(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<(String, Vec<FileEntry>), String> {
        // Get canonical path + listing
        let cmd = format!("cd {} && pwd && ls -la", shell_escape(path));
        let output = self.exec_command(session_id, &cmd)?;

        let mut lines = output.lines();
        let current_dir = lines.next().unwrap_or(path).trim().to_string();

        let mut entries = Vec::new();
        for line in lines {
            let line = line.trim();
            if line.starts_with("total ") || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                let name = parts[8..].join(" ");
                // Keep .. for navigation but skip .
                if name == "." {
                    continue;
                }
                entries.push(FileEntry {
                    permissions: parts[0].to_string(),
                    is_dir: parts[0].starts_with('d'),
                    owner: parts[2].to_string(),
                    size: parts[4].to_string(),
                    modified: format!("{} {} {}", parts[5], parts[6], parts[7]),
                    name,
                });
            }
        }

        Ok((current_dir, entries))
    }

    /// Download a remote file to a local path using SFTP.
    pub fn download_file(&self, session_id: &str, remote_path: &str, local_path: &str) -> Result<(), String> {
        let exec_session = self.get_exec_session(session_id)?;
        let sess = exec_session.lock();
        sess.set_blocking(true);

        let sftp = sess.sftp()
            .map_err(|e| format!("SFTP init failed: {}", e))?;

        let mut remote_file = sftp.open(std::path::Path::new(remote_path))
            .map_err(|e| format!("Failed to open remote file '{}': {}", remote_path, e))?;

        let mut contents = Vec::new();
        remote_file.read_to_end(&mut contents)
            .map_err(|e| format!("Failed to read remote file: {}", e))?;

        std::fs::write(local_path, &contents)
            .map_err(|e| format!("Failed to write local file '{}': {}", local_path, e))?;

        Ok(())
    }

    /// Upload a local file to a remote path using SFTP.
    pub fn upload_file(&self, session_id: &str, local_path: &str, remote_path: &str) -> Result<(), String> {
        let exec_session = self.get_exec_session(session_id)?;
        let sess = exec_session.lock();
        sess.set_blocking(true);

        let contents = std::fs::read(local_path)
            .map_err(|e| format!("Failed to read local file '{}': {}", local_path, e))?;

        let sftp = sess.sftp()
            .map_err(|e| format!("SFTP init failed: {}", e))?;

        let mut remote_file = sftp.create(std::path::Path::new(remote_path))
            .map_err(|e| format!("Failed to create remote file '{}': {}", remote_path, e))?;

        remote_file.write_all(&contents)
            .map_err(|e| format!("Failed to write remote file: {}", e))?;

        Ok(())
    }

    /// Upload a local file with progress reporting and resume support.
    pub fn upload_file_with_progress(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        progress: Arc<TransferProgress>,
    ) -> Result<(), String> {
        let exec_session = self.get_exec_session(session_id)?;

        let local_size = std::fs::metadata(local_path)
            .map(|m| m.len())
            .map_err(|e| format!("Local file error: {}", e))?;

        let filename = std::path::Path::new(local_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        *progress.filename.lock() = filename;
        progress.total.store(local_size, Ordering::Relaxed);
        progress.finished.store(false, Ordering::Relaxed);

        let sess = exec_session.lock();
        sess.set_blocking(true);
        let sftp = sess.sftp().map_err(|e| format!("SFTP init failed: {}", e))?;

        // Check remote file size for resume
        let remote_size = sftp
            .stat(std::path::Path::new(remote_path))
            .map(|s| s.size.unwrap_or(0))
            .unwrap_or(0);

        let start_offset = if remote_size > 0 && remote_size < local_size {
            remote_size // Resume from where we left off
        } else {
            0 // Start fresh
        };

        progress.transferred.store(start_offset, Ordering::Relaxed);

        // Open remote file (create or append for resume)
        let mut remote_file = if start_offset > 0 {
            let mut f = sftp
                .open_mode(
                    std::path::Path::new(remote_path),
                    ssh2::OpenFlags::WRITE | ssh2::OpenFlags::APPEND,
                    0o644,
                    ssh2::OpenType::File,
                )
                .map_err(|e| format!("Open for append failed: {}", e))?;
            f.seek(std::io::SeekFrom::Start(start_offset)).ok();
            f
        } else {
            sftp.create(std::path::Path::new(remote_path))
                .map_err(|e| format!("Failed to create remote file: {}", e))?
        };

        // Open local file and seek past already-uploaded bytes
        let mut local_file =
            std::fs::File::open(local_path).map_err(|e| format!("Open local: {}", e))?;
        if start_offset > 0 {
            local_file
                .seek(std::io::SeekFrom::Start(start_offset))
                .map_err(|e| format!("Seek local: {}", e))?;
        }

        // Record transfer start time for speed calculation
        *progress.start_time.lock() = Some(std::time::Instant::now());

        let mut buf = [0u8; 32768];
        let mut uploaded = start_offset;
        loop {
            if progress.finished.load(Ordering::Relaxed) {
                return Err("Transfer cancelled".to_string());
            }
            let n = local_file.read(&mut buf).map_err(|e| format!("Read: {}", e))?;
            if n == 0 {
                break;
            }
            remote_file
                .write_all(&buf[..n])
                .map_err(|e| format!("Write: {}", e))?;
            uploaded += n as u64;
            progress.transferred.store(uploaded, Ordering::Relaxed);
        }

        progress.finished.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Download a remote file with progress reporting and resume support.
    pub fn download_file_with_progress(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        progress: Arc<TransferProgress>,
    ) -> Result<(), String> {
        let exec_session = self.get_exec_session(session_id)?;

        // Check if local file exists (partial download for resume)
        let existing_size = std::fs::metadata(local_path)
            .map(|m| m.len())
            .unwrap_or(0);

        let sess = exec_session.lock();
        sess.set_blocking(true);
        let sftp = sess.sftp().map_err(|e| format!("SFTP init failed: {}", e))?;

        // Get remote file size
        let file_stat = sftp
            .stat(std::path::Path::new(remote_path))
            .map_err(|e| format!("Failed to stat remote file: {}", e))?;
        let total_size = file_stat.size.unwrap_or(0);

        // Setup progress
        let filename = std::path::Path::new(remote_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        *progress.filename.lock() = filename;
        progress.total.store(total_size, Ordering::Relaxed);
        progress
            .transferred
            .store(existing_size, Ordering::Relaxed);
        progress.finished.store(false, Ordering::Relaxed);

        let mut remote_file = sftp
            .open(std::path::Path::new(remote_path))
            .map_err(|e| format!("Failed to open remote file: {}", e))?;

        // Seek past already-downloaded bytes for resume
        if existing_size > 0 && existing_size < total_size {
            remote_file
                .seek(std::io::SeekFrom::Start(existing_size))
                .map_err(|e| format!("Seek failed: {}", e))?;
        }

        // Open local file in append mode (resume) or create fresh
        let mut local_file = if existing_size > 0 && existing_size < total_size {
            std::fs::OpenOptions::new()
                .append(true)
                .open(local_path)
                .map_err(|e| format!("Open local for append failed: {}", e))?
        } else {
            std::fs::File::create(local_path)
                .map_err(|e| format!("Create local file failed: {}", e))?
        };

        // Record transfer start time for speed calculation
        *progress.start_time.lock() = Some(std::time::Instant::now());

        let mut buf = [0u8; 32768];
        let mut downloaded = existing_size;
        loop {
            if progress.finished.load(Ordering::Relaxed) {
                return Err("Transfer cancelled".to_string());
            }
            let n = remote_file
                .read(&mut buf)
                .map_err(|e| format!("Read: {}", e))?;
            if n == 0 {
                break;
            }
            local_file
                .write_all(&buf[..n])
                .map_err(|e| format!("Write: {}", e))?;
            downloaded += n as u64;
            progress.transferred.store(downloaded, Ordering::Relaxed);
        }

        progress.finished.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Read a remote file's content as a string (for editing).
    pub fn read_file_content(&self, session_id: &str, remote_path: &str) -> Result<String, String> {
        let exec_session = self.get_exec_session(session_id)?;
        let sess = exec_session.lock();
        sess.set_blocking(true);

        let sftp = sess.sftp()
            .map_err(|e| format!("SFTP init failed: {}", e))?;

        let mut remote_file = sftp.open(std::path::Path::new(remote_path))
            .map_err(|e| format!("Failed to open remote file: {}", e))?;

        let mut contents = String::new();
        remote_file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        Ok(contents)
    }

    /// Write content to a remote file (for saving edits).
    pub fn write_file_content(&self, session_id: &str, remote_path: &str, content: &str) -> Result<(), String> {
        let exec_session = self.get_exec_session(session_id)?;
        let sess = exec_session.lock();
        sess.set_blocking(true);

        let sftp = sess.sftp()
            .map_err(|e| format!("SFTP init failed: {}", e))?;

        let mut remote_file = sftp.create(std::path::Path::new(remote_path))
            .map_err(|e| format!("Failed to create remote file: {}", e))?;

        remote_file.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write file: {}", e))?;

        Ok(())
    }
}

/// Re-establish an SSH connection for auto-reconnect.
///
/// Returns the interactive session (already set to non-blocking), the channel
/// (with PTY + tmux or shell), and a fresh exec session for monitoring.
/// Create a standalone SSH session for exec/SFTP operations.
fn create_exec_connection(params: &ConnectParams) -> Result<Session, String> {
    let tcp = establish_tcp(params)?;

    tcp.set_nonblocking(false).ok();

    let mut session = Session::new()
        .map_err(|e| format!("Exec session create failed: {}", e))?;
    session.set_tcp_stream(tcp);
    configure_session_algorithms(&session);
    session.handshake()
        .map_err(|e| format!("Exec handshake failed: {}", e))?;
    session.set_keepalive(true, 15);

    match params.auth_type.as_str() {
        "password" => {
            let pw = params.password.as_deref().ok_or("No password")?;
            session.userauth_password(&params.username, pw)
                .map_err(|e| format!("Exec auth failed: {}", e))?;
        }
        "key" => {
            let key = params.private_key.as_deref().ok_or("No key")?;
            let key_path = std::path::Path::new(key);
            if let Err(e) = session.userauth_pubkey_file(
                &params.username, None, key_path, params.passphrase.as_deref(),
            ) {
                let tmp = std::env::temp_dir().join(format!("neo_k_{}", uuid::Uuid::new_v4()));
                std::fs::copy(key_path, &tmp).map_err(|e2| format!("Copy key: {}", e2))?;
                let r = session.userauth_pubkey_file(&params.username, None, &tmp, params.passphrase.as_deref());
                let _ = std::fs::remove_file(&tmp);
                r.map_err(|e2| format!("Key auth failed: {}, retry: {}", e, e2))?;
            }
        }
        _ => return Err("Unknown auth type".into()),
    }

    if !session.authenticated() {
        return Err("Exec auth failed".into());
    }

    Ok(session)
}

/// Detect available session persistence tools on the remote server and decide
/// which `SessionMode` to use.
///
/// Priority: tmux (hidden UI) > raw shell fallback.
/// The detection runs a quick exec channel to probe `command -v tmux`.
fn detect_and_setup_session(session: &Session, name: &str) -> SessionMode {
    session.set_blocking(true);

    let result = (|| -> Result<String, String> {
        let mut ch = session.channel_session().map_err(|e| format!("{}", e))?;
        ch.exec("command -v tmux >/dev/null 2>&1 && echo HAS_TMUX || echo NONE")
            .map_err(|e| format!("{}", e))?;
        let mut out = String::new();
        ch.read_to_string(&mut out).ok();
        let _ = ch.wait_close();
        Ok(out)
    })();

    match result {
        Ok(ref out) if out.contains("HAS_TMUX") => SessionMode::Persistent(name.to_string()),
        _ => SessionMode::RawShell,
    }
}

fn reconnect_ssh(
    params: &ConnectParams,
    mode: &SessionMode,
    minimal_mode: bool,
) -> Result<(Session, ssh2::Channel, Option<Session>), String> {
    let tcp = establish_tcp(params)?;

    tcp.set_nonblocking(false).ok();

    let mut session =
        Session::new().map_err(|e| format!("Session create failed: {}", e))?;
    session.set_tcp_stream(tcp);
    configure_session_algorithms(&session);
    session
        .handshake()
        .map_err(|e| format!("Handshake failed: {}", e))?;
    if !minimal_mode {
        session.set_keepalive(true, 15);
    }

    // Authenticate
    match params.auth_type.as_str() {
        "password" => {
            let pw = params.password.as_deref().ok_or("No password stored")?;
            session
                .userauth_password(&params.username, pw)
                .map_err(|e| format!("Auth failed: {}", e))?;
        }
        "key" => {
            let key = params.private_key.as_deref().ok_or("No key path stored")?;
            let path = std::path::Path::new(key);
            if let Err(e) = session.userauth_pubkey_file(
                &params.username, None, path, params.passphrase.as_deref(),
            ) {
                let tmp = std::env::temp_dir().join(format!("neo_rk_{}", uuid::Uuid::new_v4()));
                std::fs::copy(path, &tmp).map_err(|e2| format!("Copy key: {}", e2))?;
                let r = session.userauth_pubkey_file(&params.username, None, &tmp, params.passphrase.as_deref());
                let _ = std::fs::remove_file(&tmp);
                r.map_err(|e2| format!("Key auth failed: {}, retry: {}", e, e2))?;
            }
        }
        _ => return Err("Unknown auth type".into()),
    }

    if !session.authenticated() {
        return Err("Authentication failed on reconnect".into());
    }

    // Open interactive channel with PTY
    let mut channel = session
        .channel_session()
        .map_err(|e| format!("Channel failed: {}", e))?;
    channel
        .request_pty("xterm-256color", None, Some((120, 40, 0, 0)))
        .map_err(|e| format!("PTY failed: {}", e))?;

    if !minimal_mode {
        let _ = channel.setenv("LANG", "en_US.UTF-8");
        let _ = channel.setenv("LC_ALL", "en_US.UTF-8");
    }

    match mode {
        SessionMode::Persistent(name) => {
            let cmd = format!(
                "export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8; \
                 tmux set-option -t {n} escape-time 10 2>/dev/null; \
                 tmux attach-session -t {n} 2>/dev/null || exec $SHELL -l",
                n = name
            );
            channel
                .exec(&cmd)
                .map_err(|e| format!("Reattach failed: {}", e))?;
        }
        SessionMode::RawShell => {
            if minimal_mode {
                channel.shell().map_err(|e| format!("Shell failed: {}", e))?;
            } else {
                channel
                    .exec("LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 TERM=xterm-256color exec $SHELL -l")
                    .unwrap_or_else(|_| { let _ = channel.shell(); });
            }
        }
    }

    // Set non-blocking for the reader thread
    session.set_blocking(false);

    // Create a fresh exec session (only for non-minimal servers).
    let exec_sess = if minimal_mode {
        None
    } else {
        Some(create_exec_connection(params)?)
    };

    Ok((session, channel, exec_sess))
}

/// Check if a file can be quick-edited based on its extension.
pub fn is_editable_file(name: &str) -> bool {
    let editable_extensions = [
        ".sh", ".bash", ".zsh", ".fish",
        ".json", ".yaml", ".yml", ".toml", ".conf", ".cfg", ".ini",
        ".csv", ".tsv",
        ".py", ".rs", ".go", ".js", ".ts",
        ".txt", ".md", ".log",
        ".xml", ".html", ".css",
        ".env", ".properties",
        ".service", ".timer",
        ".dockerfile", ".gitignore",
    ];
    let lower = name.to_lowercase();
    editable_extensions.iter().any(|ext| lower.ends_with(ext))
        || lower == "makefile"
        || lower == "dockerfile"
        || lower == "rakefile"
        || lower == "gemfile"
}

/// Parse a human-readable size string (e.g. "1.5G", "500M", "2T") to gigabytes.
fn parse_size_to_gb(s: &str) -> f64 {
    let s = s.trim();
    if s.ends_with('T') || s.ends_with("Ti") {
        s.trim_end_matches(|c: char| c.is_alphabetic())
            .parse::<f64>()
            .unwrap_or(0.0)
            * 1024.0
    } else if s.ends_with('G') || s.ends_with("Gi") {
        s.trim_end_matches(|c: char| c.is_alphabetic())
            .parse::<f64>()
            .unwrap_or(0.0)
    } else if s.ends_with('M') || s.ends_with("Mi") {
        s.trim_end_matches(|c: char| c.is_alphabetic())
            .parse::<f64>()
            .unwrap_or(0.0)
            / 1024.0
    } else {
        s.parse::<f64>().unwrap_or(0.0)
    }
}

/// Escape a string for safe use in a shell command.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Verify that libssh2 (as compiled on this platform) exposes the algorithms
/// modern OpenSSH servers require. Called at startup so missing algorithms
/// are surfaced early, and as a unit test so CI catches regressions on any
/// platform build before shipping.
pub fn verify_required_algorithms() -> Result<(), String> {
    let sess = ssh2::Session::new().map_err(|e| format!("Session::new: {}", e))?;

    // Required = algorithms that OpenSSH 8+ picks by default.
    // Missing any of these means the client will fail to negotiate with modern servers.
    let required_kex = &[
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group14-sha256",
    ];
    let required_hostkey = &[
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ];
    let required_cipher = &[
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes256-ctr",
    ];

    let check = |method: ssh2::MethodType, required: &[&str], label: &str| -> Result<(), String> {
        let supported = sess
            .supported_algs(method)
            .map_err(|e| format!("supported_algs({}): {}", label, e))?;
        let missing: Vec<&str> = required
            .iter()
            .copied()
            .filter(|a| !supported.contains(a))
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "libssh2 missing required {} algorithms: {}. Available: {}",
                label,
                missing.join(","),
                supported.join(",")
            ))
        }
    };

    check(ssh2::MethodType::Kex, required_kex, "KEX")?;
    check(ssh2::MethodType::HostKey, required_hostkey, "HostKey")?;
    check(ssh2::MethodType::CryptCs, required_cipher, "Cipher")?;
    Ok(())
}

#[cfg(test)]
mod algorithm_tests {
    /// Guards against Windows builds that fall back to WinCNG (which lacks
    /// curve25519/ed25519) or OpenSSL builds that strip EC support.
    /// Runs in CI on every target; a failure blocks the release.
    #[test]
    fn required_algorithms_present() {
        match super::verify_required_algorithms() {
            Ok(()) => {}
            Err(e) => panic!("{}", e),
        }
    }
}

#[cfg(test)]
mod error_tests {
    use super::translate_ssh_error;

    // Hints are i18n'd — tests check that the translator appends a hint (via " — ")
    // for recognized patterns, without coupling to a specific locale's wording.

    #[test]
    fn auth_failure_gets_hint() {
        let s = translate_ssh_error("Authentication failed");
        assert!(s.contains(" — "), "expected hint appended, got: {}", s);
        assert!(s.len() > "Authentication failed".len());
    }

    #[test]
    fn connection_refused_gets_hint() {
        let s = translate_ssh_error("TCP connect to 10.0.0.1:22 failed: Connection refused");
        assert!(s.contains(" — "), "got: {}", s);
    }

    #[test]
    fn timeout_gets_hint() {
        let s = translate_ssh_error("TCP connect to 1.2.3.4:22 failed: operation timed out");
        assert!(s.contains(" — "), "got: {}", s);
    }

    #[test]
    fn host_key_mismatch_gets_hint() {
        let s = translate_ssh_error("host key verification mismatch");
        assert!(s.contains(" — "), "got: {}", s);
    }

    #[test]
    fn dns_gets_hint() {
        let s = translate_ssh_error("DNS resolve failed for 'bad.host': name or service not known");
        assert!(s.contains(" — "), "got: {}", s);
    }

    #[test]
    fn unknown_passes_through() {
        let s = translate_ssh_error("something completely novel");
        assert_eq!(s, "something completely novel");
    }

    #[test]
    fn bogus_test_connection_returns_error() {
        // Use an unroutable address to guarantee fast failure
        let r = super::SshManager::test_connection(
            "127.0.0.1",
            1,            // port 1 — very unlikely to be open
            "nobody",
            "password",
            Some("badpw"),
            None, None, None,
        );
        assert!(!r.ok);
        assert_eq!(r.stage, "tcp");
        assert!(r.error.is_some());
    }
}
