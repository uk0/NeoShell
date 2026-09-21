use std::collections::HashMap;
use std::io::{Read as IoRead, Seek, Write as IoWrite};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NOPAD};
use base64::Engine;
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

// ---------------------------------------------------------------------------
// Host key verification
//
// Mirrors OpenSSH's StrictHostKeyChecking=accept-new against the *system*
// ~/.ssh/known_hosts, so NeoShell and ssh(1) agree on what a host's key is
// instead of NeoShell keeping a private store nobody else can audit.
// ---------------------------------------------------------------------------

/// Prefix on every host-key failure. Contains "host key" + "verification", so
/// `translate_ssh_error` attaches the `ssh.err.host_key` hint, and callers can
/// recognise the class without matching on the whole sentence.
pub(crate) const HOST_KEY_FAIL: &str = "Host key verification failed";

/// Host key captured on a session's first handshake. Every further connection
/// opened for that same session — the exec channel, an auto-reconnect — is
/// pinned to it: those are not first contact, so trust-on-first-use must not
/// apply a second time.
#[derive(Clone)]
pub struct PinnedHostKey {
    /// Raw host key blob, exactly as `Session::host_key` returns it.
    pub key: Vec<u8>,
    /// known_hosts algorithm token, e.g. "ssh-ed25519".
    pub alg: String,
    /// "SHA256:…" fingerprint, for logs and the UI.
    pub fingerprint: String,
}

fn known_hosts_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh").join("known_hosts"))
}

/// known_hosts host pattern for an endpoint: the bare host on port 22,
/// `[host]:port` otherwise — the convention OpenSSH uses.
fn known_hosts_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{}]:{}", host, port)
    }
}

/// known_hosts algorithm token for a negotiated host key type.
fn host_key_alg_name(kind: ssh2::HostKeyType) -> &'static str {
    match kind {
        ssh2::HostKeyType::Rsa => "ssh-rsa",
        ssh2::HostKeyType::Dss => "ssh-dss",
        ssh2::HostKeyType::Ecdsa256 => "ecdsa-sha2-nistp256",
        ssh2::HostKeyType::Ecdsa384 => "ecdsa-sha2-nistp384",
        ssh2::HostKeyType::Ecdsa521 => "ecdsa-sha2-nistp521",
        ssh2::HostKeyType::Ed25519 => "ssh-ed25519",
        ssh2::HostKeyType::Unknown => "unknown",
    }
}

/// Expand a known_hosts algorithm token into the transport host-key algorithms
/// libssh2 can negotiate, strongest first. RSA keys are stored in known_hosts
/// as `ssh-rsa` but negotiate as rsa-sha2-*, so the expansion is not 1:1.
fn hostkey_algs_for(token: &str) -> &'static [&'static str] {
    match token {
        "ssh-rsa" => &["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
        "ssh-ed25519" => &["ssh-ed25519"],
        "ecdsa-sha2-nistp256" => &["ecdsa-sha2-nistp256"],
        "ecdsa-sha2-nistp384" => &["ecdsa-sha2-nistp384"],
        "ecdsa-sha2-nistp521" => &["ecdsa-sha2-nistp521"],
        "ssh-dss" => &["ssh-dss"],
        _ => &[],
    }
}

/// "SHA256:<base64>" fingerprint of the key the peer just presented.
fn fingerprint_sha256(session: &Session) -> String {
    match session.host_key_hash(ssh2::HashType::Sha256) {
        Some(h) => format!("SHA256:{}", B64_NOPAD.encode(h)),
        None => "SHA256:<unavailable>".to_string(),
    }
}

/// Same fingerprint format, for a key that is only available as the base64
/// blob stored in a known_hosts line.
fn fingerprint_of_stored_key(b64: &str) -> String {
    match B64.decode(b64) {
        Ok(raw) => format!("SHA256:{}", B64_NOPAD.encode(openssl::sha::sha256(&raw))),
        Err(_) => "SHA256:<unreadable>".to_string(),
    }
}

/// Split a known_hosts line into (algorithm token, base64 key), skipping an
/// optional leading `@cert-authority` / `@revoked` marker.
fn split_known_hosts_line(line: &str) -> Option<(&str, &str)> {
    let mut fields = line.split_whitespace();
    let mut first = fields.next()?;
    if first.starts_with('@') {
        first = fields.next()?;
    }
    let _ = first; // host pattern — matched by libssh2, not by us
    let alg = fields.next()?;
    let key = fields.next()?;
    Some((alg, key))
}

/// Every known_hosts line that applies to `host:port`, as (algorithm, base64 key).
///
/// Each line is handed to libssh2 on its own and checked against a key that
/// cannot match: `Mismatch` means the line's host pattern matched (so the line
/// is about this host), `NotFound` means it did not. That lets libssh2 resolve
/// hashed `|1|…` patterns with its own HMAC instead of us reimplementing it.
fn stored_host_entries(session: &Session, host: &str, port: u16) -> Vec<(String, String)> {
    let path = match known_hosts_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    stored_host_entries_in(session, &text, host, port)
}

/// `stored_host_entries` against known_hosts contents already in memory.
fn stored_host_entries_in(
    session: &Session,
    text: &str,
    host: &str,
    port: u16,
) -> Vec<(String, String)> {
    const NO_SUCH_KEY: &[u8] = b"neoshell-probe-key";

    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (alg, key) = match split_known_hosts_line(line) {
            Some(v) => v,
            None => continue,
        };
        if hostkey_algs_for(alg).is_empty() {
            continue;
        }
        let mut probe = match session.known_hosts() {
            Ok(k) => k,
            Err(_) => return out,
        };
        if probe
            .read_str(line, ssh2::KnownHostFileKind::OpenSSH)
            .is_err()
        {
            continue;
        }
        if matches!(
            probe.check_port(host, port, NO_SUCH_KEY),
            ssh2::CheckResult::Mismatch
        ) {
            out.push((alg.to_string(), key.to_string()));
        }
    }
    out
}

/// Offer the host-key algorithm this host is already trusted under first — the
/// same thing OpenSSH's `order_hostkeyalgs` does.
///
/// Without it libssh2 offers ed25519 first, a host pinned in known_hosts as
/// `ssh-rsa` answers with a key that is not stored there, and libssh2's
/// type-agnostic comparison reports Mismatch — turning a perfectly legitimate
/// server into a MitM alarm. Must run BEFORE `session.handshake()`.
fn prepare_host_key_prefs(session: &Session, params: &ConnectParams) {
    let tokens: Vec<String> = match params.pinned_host_key {
        // Later connection for an already-pinned session: negotiate exactly
        // what was pinned, so the blobs are directly comparable.
        Some(ref pin) => vec![pin.alg.clone()],
        None => stored_host_entries(session, &params.host, params.port)
            .into_iter()
            .map(|(alg, _)| alg)
            .collect(),
    };
    order_host_key_prefs(session, &tokens);
}

/// `prepare_host_key_prefs` for a host that has no `ConnectParams` of its own —
/// the bastion in `proxy.rs` and the tunnel endpoint in `tunnel.rs`. Same
/// contract: must run BEFORE `session.handshake()`.
pub(crate) fn prepare_host_key_prefs_for(session: &Session, host: &str, port: u16) {
    let tokens: Vec<String> = stored_host_entries(session, host, port)
        .into_iter()
        .map(|(alg, _)| alg)
        .collect();
    order_host_key_prefs(session, &tokens);
}

/// Put the algorithms behind `tokens` at the head of the HostKey preference
/// list, keeping everything else as a tail.
fn order_host_key_prefs(session: &Session, tokens: &[String]) {
    if tokens.is_empty() {
        return;
    }

    let supported = match session.supported_algs(MethodType::HostKey) {
        Ok(a) => a,
        Err(_) => return,
    };
    let mut ordered: Vec<&str> = Vec::with_capacity(supported.len());
    for token in tokens {
        for alg in hostkey_algs_for(token) {
            if supported.contains(alg) && !ordered.contains(alg) {
                ordered.push(alg);
            }
        }
    }
    if ordered.is_empty() {
        return;
    }
    // Keep the rest as a tail so a host that legitimately rotated to a new key
    // type is still reachable; the post-handshake check is what decides trust.
    for alg in &supported {
        if !ordered.contains(alg) {
            ordered.push(alg);
        }
    }
    let list = ordered.join(",");
    if let Err(e) = session.method_pref(MethodType::HostKey, &list) {
        log::warn!("method_pref(HostKey) ordering failed with list={}: {}", list, e);
    }
}

/// Append the entry just added to `known` to the on-disk known_hosts file.
///
/// Appending one line (rather than `KnownHosts::write_file`) keeps comments,
/// markers and any line libssh2 could not parse intact — this is the user's
/// file, shared with ssh(1), not ours to rewrite.
fn append_known_host_line(
    known: &ssh2::KnownHosts,
    path: &std::path::Path,
    pattern: &str,
) -> Result<(), String> {
    let hosts = known
        .hosts()
        .map_err(|e| format!("{}: cannot enumerate known_hosts: {}", HOST_KEY_FAIL, e))?;
    let entry = hosts
        .iter()
        .rev()
        .find(|h| h.name() == Some(pattern))
        .ok_or_else(|| format!("{}: cannot serialise the new entry for {}", HOST_KEY_FAIL, pattern))?;
    let mut line = known
        .write_string(entry, ssh2::KnownHostFileKind::OpenSSH)
        .map_err(|e| format!("{}: cannot serialise the new entry: {}", HOST_KEY_FAIL, e))?;
    if !line.ends_with('\n') {
        line.push('\n');
    }

    if let Some(dir) = path.parent() {
        crate::storage::create_dir_private(dir)
            .map_err(|e| format!("{}: cannot create {}: {}", HOST_KEY_FAIL, dir.display(), e))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("{}: cannot open {}: {}", HOST_KEY_FAIL, path.display(), e))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("{}: cannot write {}: {}", HOST_KEY_FAIL, path.display(), e))
}

/// Verify the server's host key against `~/.ssh/known_hosts`, recording it on
/// first contact (trust-on-first-use, same as `StrictHostKeyChecking=accept-new`).
///
/// A host whose stored key changed is refused outright — there is no override,
/// because the only two explanations are a reinstalled server and an active
/// man-in-the-middle, and only the user can tell them apart (out of band).
/// Any failure to read or parse known_hosts is also a refusal: this must never
/// fail open.
///
/// MUST be called immediately after `handshake()` and BEFORE any `userauth_*`,
/// so credentials are never offered to an unverified peer. Never prompts — it
/// runs on worker threads with no access to the UI.
pub(crate) fn verify_host_key(session: &Session, host: &str, port: u16) -> Result<(), String> {
    let (key, kind) = session
        .host_key()
        .ok_or_else(|| format!("{} for {}: the server presented no host key", HOST_KEY_FAIL, host))?;
    let alg = host_key_alg_name(kind);
    let fp = fingerprint_sha256(session);
    let pattern = known_hosts_pattern(host, port);

    let path = known_hosts_path().ok_or_else(|| {
        format!("{}: cannot locate the home directory for ~/.ssh/known_hosts", HOST_KEY_FAIL)
    })?;

    let mut known = session
        .known_hosts()
        .map_err(|e| format!("{}: cannot open the known_hosts store: {}", HOST_KEY_FAIL, e))?;

    // A missing file is first contact, not a read failure. Anything else is
    // fatal — an unreadable or corrupt known_hosts must not silently allow.
    if path.exists() {
        known
            .read_file(&path, ssh2::KnownHostFileKind::OpenSSH)
            .map_err(|e| {
                format!("{}: cannot read {}: {}", HOST_KEY_FAIL, path.display(), e)
            })?;
    }

    match known.check_port(host, port, key) {
        ssh2::CheckResult::Match => {
            log::debug!("host key verified for {} ({} {})", pattern, alg, fp);
            Ok(())
        }
        ssh2::CheckResult::NotFound => {
            if matches!(kind, ssh2::HostKeyType::Unknown) {
                return Err(format!(
                    "{} for {}: the server presented a host key of an unrecognised type, \
                     which cannot be recorded in known_hosts",
                    HOST_KEY_FAIL, pattern
                ));
            }
            // Trust on first use — record it the way ssh(1) would, so both
            // clients agree from here on.
            known
                .add(&pattern, key, "neoshell", kind.into())
                .map_err(|e| format!("{}: cannot pin {}: {}", HOST_KEY_FAIL, pattern, e))?;
            // Same call ssh(1) makes here, and the same reaction to a
            // known_hosts it cannot write: warn loudly, carry on. Accept-new
            // has already been decided for THIS connection; failing to record
            // it costs the next one its protection, which belongs in the log,
            // not in a refusal that would make a read-only HOME unusable.
            match append_known_host_line(&known, &path, &pattern) {
                Ok(()) => log::info!(
                    "new host key pinned for {} in {}: {} {}",
                    pattern,
                    path.display(),
                    alg,
                    fp
                ),
                Err(e) => log::error!(
                    "accepted {} on first use ({} {}) but could NOT record it — \
                     the next connection will not be protected: {}",
                    pattern,
                    alg,
                    fp,
                    e
                ),
            }
            Ok(())
        }
        ssh2::CheckResult::Mismatch => {
            let stored: Vec<String> = stored_host_entries(session, host, port)
                .into_iter()
                .map(|(a, k)| format!("{} {}", a, fingerprint_of_stored_key(&k)))
                .collect();
            let stored = if stored.is_empty() {
                "<none readable>".to_string()
            } else {
                stored.join(", ")
            };
            Err(format!(
                "{} for {}: host key mismatch. The server now presents {} {}, \
                 but {} stores {}. Someone may be impersonating this host. \
                 If the server really was reinstalled, remove the old entry with \
                 `ssh-keygen -R '{}'` and connect again.",
                HOST_KEY_FAIL,
                pattern,
                alg,
                fp,
                path.display(),
                stored,
                pattern
            ))
        }
        ssh2::CheckResult::Failure => Err(format!(
            "{} for {}: known_hosts could not be checked",
            HOST_KEY_FAIL, pattern
        )),
    }
}

/// Retry public-key auth with the key read straight into memory.
///
/// Replaces an older "fallback" that copied the key to `std::env::temp_dir()`
/// and called `userauth_pubkey_file` again on a byte-identical copy: that could
/// never succeed where the first call had failed, and it left private key
/// material in a world-traversable directory. `userauth_pubkey_memory` is a
/// genuinely different code path (libssh2 parses the PEM itself) and touches
/// no disk. Available on every target here because the build enables
/// `vendored-openssl` + `openssl-on-win32`.
fn userauth_pubkey_in_memory(
    session: &Session,
    username: &str,
    key_path: &std::path::Path,
    passphrase: Option<&str>,
) -> Result<(), String> {
    let key_data = std::fs::read_to_string(key_path)
        .map_err(|e| format!("Failed to read private key {}: {}", key_path.display(), e))?;
    session
        .userauth_pubkey_memory(username, None, &key_data, passphrase)
        .map_err(|e| e.to_string())
}

/// Snapshot the key the peer presented, so later connections for the same
/// session can be pinned to it.
fn capture_host_key(session: &Session) -> Option<PinnedHostKey> {
    let (key, kind) = session.host_key()?;
    Some(PinnedHostKey {
        key: key.to_vec(),
        alg: host_key_alg_name(kind).to_string(),
        fingerprint: fingerprint_sha256(session),
    })
}

/// Host key check for a connection that is NOT first contact: the exec channel
/// opened alongside a shell, or a reconnect after a link drop.
///
/// Compares byte-for-byte against the key pinned when the session first came
/// up. No TOFU write, no prompt — a change here is exactly the man-in-the-middle
/// signature, and on the reconnect path it must abort the retry loop rather
/// than be retried. Falls back to the known_hosts path when nothing is pinned.
fn verify_pinned_host_key(
    session: &Session,
    params: &ConnectParams,
    what: &str,
) -> Result<(), String> {
    let pin = match params.pinned_host_key {
        Some(ref p) => p,
        None => return verify_host_key(session, &params.host, params.port),
    };
    let (key, kind) = session.host_key().ok_or_else(|| {
        format!("{} ({}): the server presented no host key", HOST_KEY_FAIL, what)
    })?;
    if key == pin.key.as_slice() {
        return Ok(());
    }
    Err(format!(
        "{} ({}) for {}:{}: host key mismatch mid-session. The server now presents {} {}, \
         but this session pinned {} {}. Aborting.",
        HOST_KEY_FAIL,
        what,
        params.host,
        params.port,
        host_key_alg_name(kind),
        fingerprint_sha256(session),
        pin.alg,
        pin.fingerprint
    ))
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
    pub stage: String,          // "tcp" | "handshake" | "hostkey" | "auth" | "done"
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
    /// Host key captured on this session's first handshake. `None` on first
    /// contact (known_hosts decides); `Some` for every connection opened
    /// afterwards for the same session, which is then pinned to it.
    pub pinned_host_key: Option<PinnedHostKey>,
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
    prepare_host_key_prefs(&session, params);
    session
        .handshake()
        .map_err(|e| e.to_string())?;
    // Single choke point for both phases of the retry in `connect`, and it sits
    // behind `establish_tcp`, so a SOCKS5/HTTP/bastion-tunnelled connection has
    // the real target host verified rather than the hop.
    verify_pinned_host_key(&session, params, "shell")?;
    Ok(session)
}

/// Establish TCP connection, optionally through a proxy.
fn establish_tcp(params: &ConnectParams) -> Result<TcpStream, String> {
    use crate::proxy::{self, ProxyStore};

    if let Some(ref proxy_id) = params.proxy_id {
        let store = ProxyStore::new();
        let proxy_cfg = store.get(proxy_id).ok_or_else(|| {
            // Fail closed: the user asked for this traffic to cross a specific
            // network boundary. Dialling the target directly instead would leak
            // the connection onto a path they deliberately excluded.
            format!(
                "Proxy '{}' is configured for this connection but no longer exists. \
                 Refusing to connect directly — re-create the proxy or clear it from \
                 the connection.",
                proxy_id
            )
        })?;
        return proxy::connect_via_proxy(
            &proxy_cfg,
            &params.host,
            params.port,
            Duration::from_secs(15),
        );
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
    /// Set by `disconnect` to tell the reader thread to stop. Without it the
    /// reader keeps re-dialling and re-authenticating for ~3 minutes after the
    /// user closed the tab.
    pub stop: Arc<AtomicBool>,
    /// "SHA256:…" fingerprint of the verified host key, for display.
    pub host_key_fp: String,
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
            pinned_host_key: None,
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
        prepare_host_key_prefs(&session, &params);
        if let Err(e) = session.handshake() {
            return ConnectionTestResult {
                ok: false,
                latency_ms: start.elapsed().as_millis() as u64,
                stage: "handshake".into(),
                error: Some(translate_ssh_error(&e.to_string())),
            };
        }

        // --- Host key --- must come before auth: the test dialog otherwise
        // hands the password to an unverified peer. This is also the first
        // place a user should see a new host's fingerprint, so a successful
        // trust-on-first-use is logged rather than hidden.
        if let Err(e) = verify_host_key(&session, host, port) {
            return ConnectionTestResult {
                ok: false,
                latency_ms: start.elapsed().as_millis() as u64,
                stage: "hostkey".into(),
                error: Some(translate_ssh_error(&e)),
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
            pinned_host_key: None,
        };

        // --- Establish SSH handshake ---------------------------------------
        // (No pre-handshake banner peek: it opened a second throwaway TCP
        // connection — a second trip through the proxy/bastion — purely to log
        // a line that `session.banner()` already gives us for free below.)
        //
        // Attempt handshake — two-phase retry to handle both old and modern servers.
        // Phase 1: filtered algorithm list (our preferred path)
        // Phase 2: fall back to libssh2 defaults (uncustomized) to handle kex-strict servers
        let session = match try_handshake(&tmp_params, 15000, true) {
            Ok(s) => s,
            // A rejected host key is a verdict, not a negotiation failure —
            // retrying with different algorithms would only re-ask the same
            // question, so surface it straight away.
            Err(e1) if e1.contains(HOST_KEY_FAIL) => {
                return Err(translate_ssh_error(&e1));
            }
            Err(e1) => {
                log::warn!("First handshake attempt failed ({}), retrying with libssh2 defaults", e1);
                match try_handshake(&tmp_params, 15000, false) {
                    Ok(s) => {
                        log::info!("Fallback handshake (default algorithms) succeeded");
                        s
                    }
                    Err(e2) if e2.contains(HOST_KEY_FAIL) => {
                        return Err(translate_ssh_error(&e2));
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

        // --- Pin the verified host key -------------------------------------
        // `try_handshake` already checked it against known_hosts. Everything
        // opened from here on for this session (the exec connection, every
        // reconnect) is compared against this exact blob instead of repeating
        // trust-on-first-use.
        let host_key_pin = capture_host_key(&session).ok_or_else(|| {
            translate_ssh_error(&format!(
                "{} for {}: the server presented no host key",
                HOST_KEY_FAIL, host
            ))
        })?;
        let host_key_fp = host_key_pin.fingerprint.clone();
        let mut tmp_params = tmp_params;
        tmp_params.pinned_host_key = Some(host_key_pin);
        log::info!("host key pinned for {}:{} — {}", host, port, host_key_fp);

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

                // Try pubkey_file first, then the same key straight from memory.
                match session.userauth_pubkey_file(username, None, key_path, passphrase) {
                    Ok(()) => {
                        log::info!("SSH key auth succeeded via pubkey_file");
                    }
                    Err(e) => {
                        log::warn!("pubkey_file failed ({}), trying in-memory key auth", e);
                        userauth_pubkey_in_memory(&session, username, key_path, passphrase)
                            .map_err(|e2| format!("Key auth failed: {}, retry: {}", e, e2))?;
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

        // --- Capture SSH pre-auth banner (SSH_MSG_USERAUTH_BANNER). This is
        // the "Welcome" / legal notice the server sends BEFORE opening the
        // shell channel — separate from /etc/motd which flows through the
        // shell. Without this, users on servers with pre-auth banners just
        // never saw that text. We inject it into the terminal grid below,
        // AFTER the reader thread is spawned and has a session_id wired up.
        let auth_banner: Option<String> = session
            .userauth_banner()
            .ok()
            .flatten()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        if let Some(ref b) = auth_banner {
            log::info!("SSH pre-auth banner: {} bytes", b.len());
        }

        // --- Classify server — minimal SSH servers (MINA SSHD, embedded devices)
        // skip the second SSH connection (concurrency-limited). Exec commands
        // instead share the main session, serialized through the session mutex.
        let banner_lower = session.banner().unwrap_or("").to_ascii_lowercase();
        let minimal_mode = !banner_lower.contains("openssh");
        if minimal_mode {
            log::info!("Minimal SSH mode (banner {:?}) — sharing main session for exec; disabling keepalive / setenv / exec-start", banner_lower);
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
        // SSH session. For those, we reuse the main session below (after wrap).
        let separate_exec_session: Option<Arc<Mutex<Session>>> = if minimal_mode {
            None
        } else {
            let tcp2 = establish_tcp(&params)?;

            let mut sess2 = Session::new()
                .map_err(|e| format!("Failed to create exec session: {}", e))?;
            sess2.set_tcp_stream(tcp2);
            // Bound the handshake so an unresponsive peer cannot wedge connect()
            // forever; cleared again below so SFTP transfers stay unbounded.
            sess2.set_timeout(15_000);
            configure_session_algorithms(&sess2);
            prepare_host_key_prefs(&sess2, &params);
            sess2.handshake()
                .map_err(|e| format!("Exec SSH handshake failed: {}", e))?;
            // Second connection to a host whose key was pinned moments ago in
            // this same call — compare against that pin rather than running a
            // fresh trust-on-first-use, which would be an attacker-usable race.
            verify_pinned_host_key(&sess2, &params, "exec").map_err(|e| translate_ssh_error(&e))?;

            match auth_type {
                "password" => {
                    let pw = password.ok_or("Password required")?;
                    sess2.userauth_password(username, pw)
                        .map_err(|e| format!("Exec auth failed: {}", e))?;
                }
                "key" => {
                    let key_str = private_key.ok_or("Private key required")?;
                    let key_path = std::path::Path::new(key_str);
                    if let Err(e) = sess2.userauth_pubkey_file(username, None, key_path, passphrase) {
                        userauth_pubkey_in_memory(&sess2, username, key_path, passphrase)
                            .map_err(|e2| format!("Exec key auth failed: {}, retry: {}", e, e2))?;
                    }
                }
                _ => return Err(format!("Unknown auth type: {}", auth_type)),
            }

            // This session is also the SFTP transport — a per-operation timeout
            // here would abort a legitimately slow transfer. exec_command_inner
            // sets and restores its own bound around the exec read instead.
            sess2.set_timeout(0);
            sess2.set_keepalive(true, 15);

            Some(Arc::new(Mutex::new(sess2)))
        };

        // --- Detect session persistence capability --------------------------
        // Minimal mode: always RawShell, no probing at all.
        let session_name = format!("neo-{}", &session_id[..8]);
        let mode = if minimal_mode {
            SessionMode::RawShell
        } else if let Some(ref es) = separate_exec_session {
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

        // Don't setenv LC_ALL / LANG — many servers don't have en_US.UTF-8
        // installed, resulting in "bash: warning: setlocale: LC_ALL: cannot
        // change locale" noise on every new shell. Let the server-side login
        // flow (/etc/profile, ~/.bashrc) handle locale.

        match &mode {
            SessionMode::Persistent(name) => {
                // tmux attach/create. No locale prefix — server's own login
                // env handles it. `exec $SHELL -l` as fallback makes sure a
                // login shell starts so /etc/motd and PAM banner fire.
                let cmd = format!(
                    "tmux has-session -t {n} 2>/dev/null && tmux attach-session -t {n} || \
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
                // Standard SSH "shell" request — equivalent to `ssh host` at
                // the command line. The server runs the user's login shell,
                // which sources /etc/profile + /etc/motd through PAM. This
                // is the only path that gets the full Welcome motd flow.
                channel
                    .shell()
                    .map_err(|e| format!("Shell request failed: {}", e))?;
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

        // For minimal-mode servers we reuse the main session for exec too,
        // with the session Mutex serializing all libssh2 access.
        let exec_session: Option<Arc<Mutex<Session>>> = match separate_exec_session {
            Some(es) => Some(es),
            None if minimal_mode => Some(Arc::clone(&session)),
            None => None,
        };

        // Clone reconnection context for the reader thread.
        let reader_params = params.clone();
        let reader_mode = mode.clone();
        let reader_minimal = minimal_mode;
        let reader_exec = exec_session.clone();

        // Cancellation for the reader thread. `disconnect` sets it; without it
        // a closed tab keeps re-dialling and re-authenticating for ~3 minutes.
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);

        // --- Reader thread: reads from SSH channel, emits SshEvent ---------
        // On EOF or error (not WouldBlock), attempts auto-reconnect with
        // exponential backoff before giving up and sending Closed.
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            'outer: loop {
                if reader_stop.load(Ordering::Relaxed) {
                    // disconnect() already tore the session down and told the
                    // UI; emitting Closed here would double-handle it.
                    break 'outer;
                }
                // In minimal mode the exec path shares this session; acquire the
                // session mutex so libssh2 access from reader and exec is
                // serialized. For non-minimal, exec has its own session so this
                // is an uncontended lock (cheap).
                let result = {
                    let _sess_guard = session_reader.lock();
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
                        if reader_stop.load(Ordering::Relaxed) {
                            break 'outer;
                        }
                        continue 'outer;
                    }
                    Ok(_zero) => {
                        // EOF — remote closed the channel
                    }
                    Err(ref e) => {
                        if reader_stop.load(Ordering::Relaxed) {
                            // The read failed because disconnect() closed the
                            // channel under us — not something to report.
                            break 'outer;
                        }
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
                    if reader_stop.load(Ordering::Relaxed) {
                        break 'outer;
                    }
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

                    // Sleep in slices so a disconnect during a 30s backoff is
                    // noticed promptly instead of after the full wait.
                    let mut slept = 0u64;
                    while slept < backoff_ms {
                        if reader_stop.load(Ordering::Relaxed) {
                            break 'outer;
                        }
                        let slice = (backoff_ms - slept).min(100);
                        std::thread::sleep(Duration::from_millis(slice));
                        slept += slice;
                    }
                    backoff_ms = (backoff_ms * 2).min(30_000);

                    if reader_stop.load(Ordering::Relaxed) {
                        break 'outer;
                    }

                    match reconnect_ssh(&reader_params, &reader_mode, reader_minimal) {
                        // A host key that changed while the link was down is the
                        // exact man-in-the-middle signature. Abort the whole retry
                        // loop instead of handing the stored password to the next
                        // attempt.
                        Err(ref e) if e.contains(HOST_KEY_FAIL) => {
                            log::error!("reconnect aborted: {}", e);
                            let _ = event_tx.send(SshEvent::Error {
                                session_id: sid_reader.clone(),
                                error: translate_ssh_error(e),
                            });
                            let _ = event_tx.send(SshEvent::Closed {
                                session_id: sid_reader.clone(),
                            });
                            break 'outer;
                        }
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

                            if reader_stop.load(Ordering::Relaxed) {
                                break 'outer;
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
            // No `.expect` here: the crate is built with panic = "abort", so a
            // runtime that fails to build (OS out of fds / threads) would kill
            // the whole process — every other SSH session and the unsaved vault
            // with it. Report it and let this one thread go.
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = event_tx_w.send(SshEvent::Error {
                        session_id: sid_writer.clone(),
                        error: format!("Failed to build SSH writer runtime: {}", e),
                    });
                    return;
                }
            };

            rt.block_on(async move {
                while let Some(cmd) = cmd_rx.recv().await {
                    match cmd {
                        SshCommand::Write(data) => {
                            // Hold session lock for the entire write so the
                            // shell-reader and any exec_command run exclusively.
                            let sess = session_writer.lock();
                            sess.set_blocking(true);
                            let mut ch = channel_writer.lock();
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
                            sess.set_blocking(false);
                        }
                        SshCommand::Resize(cols, rows) => {
                            let sess = session_writer.lock();
                            sess.set_blocking(true);
                            let mut ch = channel_writer.lock();
                            if let Err(e) = ch.request_pty_size(cols, rows, None, None) {
                                let _ = event_tx_w.send(SshEvent::Error {
                                    session_id: sid_writer.clone(),
                                    error: format!("Resize error: {}", e),
                                });
                            }
                            sess.set_blocking(false);
                        }
                        SshCommand::Disconnect => {
                            let sess = session_writer.lock();
                            sess.set_blocking(true);
                            let mut ch = channel_writer.lock();
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
            stop,
            host_key_fp,
        };

        self.sessions.write().insert(session_id.clone(), ssh_session);

        // --- Inject pre-auth banner into the terminal feed AFTER UI has had
        // a chance to wire up the tab's session_id (the SshConnected message
        // maps session_id → tab asynchronously). A short delay is harmless
        // and avoids the banner being dropped by the Data handler when it
        // can't find a matching tab.
        if let Some(banner) = auth_banner {
            let tx = self.event_tx.clone();
            let sid = session_id.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(250));
                // Normalize line endings (pre-auth banner often uses bare LF).
                let mut bytes = Vec::with_capacity(banner.len() + 4);
                for line in banner.split('\n') {
                    bytes.extend_from_slice(line.as_bytes());
                    bytes.extend_from_slice(b"\r\n");
                }
                // Visual separator so it stands out above the shell motd.
                bytes.extend_from_slice(b"\r\n");
                let _ = tx.send(SshEvent::Data { session_id: sid, data: bytes });
            });
        }

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
        let (writer, stop) = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            (s.writer.clone(), Arc::clone(&s.stop))
        };
        // Raise the stop flag FIRST: closing the channel below makes the reader
        // see EOF, and without the flag already set it would enter its
        // reconnect loop and keep re-authenticating against a session the user
        // just closed.
        stop.store(true, Ordering::SeqCst);
        // sessions read lock dropped before sending command and taking write lock
        let _ = writer.try_send(SshCommand::Disconnect);
        self.sessions.write().remove(session_id);
        Ok(())
    }

    /// SHA-256 fingerprint of the verified host key for a live session,
    /// formatted the way `ssh-keygen -l` prints it ("SHA256:…").
    pub fn host_key_fingerprint(&self, session_id: &str) -> Option<String> {
        self.sessions
            .read()
            .get(session_id)
            .map(|s| s.host_key_fp.clone())
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
        let (exec_session, minimal) = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            let es = match &s.exec_session {
                Some(es) => es.clone(),
                None => return Err("exec not supported on this server".into()),
            };
            (es, s.minimal_mode)
        };

        let sess = exec_session.lock();
        // When exec shares the main session (minimal mode), we must restore
        // non-blocking mode afterwards so the shell reader keeps receiving
        // WouldBlock on empty reads. For a separate session, this still works.
        sess.set_blocking(true);
        // Bound every blocking libssh2 call for the duration of this exec.
        // Without it `read_to_string` below can block forever while holding
        // both this mutex and — in minimal mode, where exec shares the main
        // session — the terminal reader's lock. The previous value is restored
        // afterwards so SFTP transfers through the same session stay unbounded.
        let prev_timeout = sess.timeout();
        sess.set_timeout(30_000);

        // Use a closure so blocking mode is restored even on error paths.
        let result = (|| -> Result<String, String> {
            // For minimal servers, skip the setenv-style locale prefix — some
            // embedded devices don't implement `export` or `2>/dev/null`.
            let utf8_cmd = if minimal {
                command.to_string()
            } else {
                format!("export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 2>/dev/null; {}", command)
            };

            let mut channel = sess
                .channel_session()
                .map_err(|e| format!("Failed to open exec channel: {}", e))?;
            channel
                .exec(&utf8_cmd)
                .map_err(|e| format!("Failed to exec command: {}", e))?;

            let mut output = String::new();
            channel
                .read_to_string(&mut output)
                .map_err(|e| format!("Failed to read command output: {}", e))?;
            let _ = channel.wait_close();
            Ok(output)
        })();

        // Critical for minimal mode: shell reader expects non-blocking reads.
        sess.set_timeout(prev_timeout);
        sess.set_blocking(false);

        result
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
    /// For minimal-mode sessions (where exec_session aliases the main session),
    /// rebuild is a no-op — the main session reconnects on its own.
    fn rebuild_exec_session(&self, session_id: &str) -> Result<(), String> {
        let (params, has_slot, minimal) = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            (s.params.clone(), s.exec_session.is_some(), s.minimal_mode)
        };

        if !has_slot {
            return Err("no exec_session slot to rebuild".into());
        }
        if minimal {
            // exec_session is the main session; main session reconnects in its
            // own reader thread. Nothing to do here.
            return Ok(());
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
            for line in df_output.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let mount = parts[5];
                    // Skip pseudo/system mounts
                    if mount.starts_with("/snap") || mount.starts_with("/boot/efi") {
                        continue;
                    }
                    // Header guard: the section text starts with a newline, so
                    // a bare .skip(1) used to eat the blank line and let df's
                    // header row ("Filesystem Size Used Avail Use% Mounted on")
                    // through as a fake disk. Requiring the Use% column to
                    // parse as a number is locale-proof.
                    let pct: f64 = match parts[4].trim_end_matches('%').parse() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let total_gb = parse_size_to_gb(parts[1]);
                    let used_gb = parse_size_to_gb(parts[2]);

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
    // Bound handshake + auth; cleared below so SFTP transfers over this same
    // session are not cut off mid-file.
    session.set_timeout(15_000);
    configure_session_algorithms(&session);
    prepare_host_key_prefs(&session, params);
    session.handshake()
        .map_err(|e| format!("Exec handshake failed: {}", e))?;
    verify_pinned_host_key(&session, params, "exec")?;
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
                userauth_pubkey_in_memory(
                    &session, &params.username, key_path, params.passphrase.as_deref(),
                )
                .map_err(|e2| format!("Key auth failed: {}, retry: {}", e, e2))?;
            }
        }
        _ => return Err("Unknown auth type".into()),
    }

    if !session.authenticated() {
        return Err("Exec auth failed".into());
    }

    session.set_timeout(0);
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
    prepare_host_key_prefs(&session, params);
    session
        .handshake()
        .map_err(|e| format!("Handshake failed: {}", e))?;
    // A reconnect is not first contact: compare against the key pinned when
    // this session first came up, with no trust-on-first-use write. The caller
    // aborts the retry loop on this error rather than trying again.
    verify_pinned_host_key(&session, params, "reconnect")?;
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
                userauth_pubkey_in_memory(
                    &session, &params.username, path, params.passphrase.as_deref(),
                )
                .map_err(|e2| format!("Key auth failed: {}, retry: {}", e, e2))?;
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
                "tmux set-option -t {n} escape-time 10 2>/dev/null; \
                 tmux attach-session -t {n} 2>/dev/null || exec $SHELL -l",
                n = name
            );
            channel
                .exec(&cmd)
                .map_err(|e| format!("Reattach failed: {}", e))?;
        }
        SessionMode::RawShell => {
            channel.shell().map_err(|e| format!("Shell failed: {}", e))?;
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

/// Escape a string for safe use as a single shell *argument*.
///
/// Single-quoting is the right primitive for that, and it is not the weak link
/// here: a value that ends up as *file content* on the remote side (see
/// `validate_authorized_key_line`) needs its own validation, because quoting
/// preserves an embedded newline faithfully — which is exactly the problem when
/// the consumer is a line-oriented file.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Validate that `pubkey` is a single authorized_keys line, returning it trimmed.
///
/// Rejects rather than strips: silently dropping part of a key the user asked
/// to deploy would install something they never reviewed. NUL is rejected too —
/// it cannot survive the shell round-trip intact.
fn validate_authorized_key_line(pubkey: &str) -> Result<&str, String> {
    let line = pubkey.trim();
    if line.is_empty() {
        return Err("public key is empty".into());
    }
    if line.contains('\n') || line.contains('\r') {
        return Err(
            "public key must be a single line — a key containing a line break would append \
             more than one entry to the remote authorized_keys"
                .into(),
        );
    }
    if line.contains('\0') {
        return Err("public key contains a NUL byte".into());
    }
    Ok(line)
}

/// One-shot helper for the SSH key manager: connect with `config`, append
/// `pubkey` to the remote `~/.ssh/authorized_keys` (idempotent — grep
/// skips the append when the exact line is already present), then drop
/// the connection. Returns "user@host" on success. Goes through
/// `establish_tcp`, so bastion/proxy-routed connections work too.
pub fn deploy_pubkey(
    config: &crate::storage::ConnectionConfig,
    pubkey: &str,
) -> Result<String, String> {
    let params = ConnectParams {
        host: config.host.clone(),
        port: config.port,
        username: config.username.clone(),
        auth_type: config.auth_type.clone(),
        password: config.password.clone(),
        private_key: config.private_key.clone(),
        passphrase: config.passphrase.clone(),
        proxy_id: config.proxy_id.clone(),
        pinned_host_key: None,
    };

    // Reject anything that would not be a single authorized_keys line BEFORE
    // opening a connection. `echo 'a\nb' >> authorized_keys` writes two
    // entries, so an embedded newline silently injects a second key — or a
    // `command=` / `from=` option line — into a security-critical remote file,
    // and it defeats the `grep -qxF` idempotency guard as well.
    let key_line = validate_authorized_key_line(pubkey)?;

    let tcp = establish_tcp(&params).map_err(|e| translate_ssh_error(&e))?;
    let mut session = Session::new().map_err(|e| format!("Session::new: {}", e))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(15_000);
    configure_session_algorithms(&session);
    prepare_host_key_prefs(&session, &params);
    session
        .handshake()
        .map_err(|e| translate_ssh_error(&e.to_string()))?;
    // This path writes the user's public key into the remote authorized_keys.
    // An unverified peer would both harvest the credentials below and receive
    // a key the user now believes is trusted.
    verify_host_key(&session, &params.host, params.port).map_err(|e| translate_ssh_error(&e))?;

    match params.auth_type.as_str() {
        "password" => {
            let pw = params
                .password
                .as_deref()
                .ok_or_else(|| "password missing".to_string())?;
            session
                .userauth_password(&params.username, pw)
                .map_err(|e| translate_ssh_error(&e.to_string()))?;
        }
        "key" => {
            let key_path = params
                .private_key
                .as_deref()
                .ok_or_else(|| "private key path missing".to_string())?;
            session
                .userauth_pubkey_file(
                    &params.username,
                    None,
                    std::path::Path::new(key_path),
                    params.passphrase.as_deref(),
                )
                .map_err(|e| translate_ssh_error(&e.to_string()))?;
        }
        other => return Err(format!("unknown auth type: {}", other)),
    }
    if !session.authenticated() {
        return Err(translate_ssh_error("Authentication failed"));
    }

    let q = shell_escape(key_line);
    let cmd = format!(
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && \
         chmod 600 ~/.ssh/authorized_keys && \
         grep -qxF {q} ~/.ssh/authorized_keys || echo {q} >> ~/.ssh/authorized_keys",
        q = q
    );

    let mut channel = session
        .channel_session()
        .map_err(|e| format!("channel: {}", e))?;
    channel.exec(&cmd).map_err(|e| format!("exec: {}", e))?;
    let mut out = String::new();
    use std::io::Read as _;
    let _ = channel.read_to_string(&mut out);
    let _ = channel.wait_close();
    let status = channel.exit_status().unwrap_or(-1);
    if status != 0 {
        return Err(format!(
            "remote command failed (exit {}): {}",
            status,
            out.trim()
        ));
    }
    Ok(format!("{}@{}", config.username, config.host))
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
    fn host_key_failures_get_the_host_key_hint() {
        // Every message verify_host_key produces starts with HOST_KEY_FAIL, so
        // one check covers mismatch, unreadable known_hosts and "no host key".
        let s = translate_ssh_error(&format!("{} for example.com: host key mismatch", super::HOST_KEY_FAIL));
        assert!(s.contains(" — "), "got: {}", s);
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

#[cfg(test)]
mod host_key_tests {
    use super::*;

    // A real ed25519 host key blob is not needed: the probe path only cares
    // about the host pattern and the algorithm token, and the mismatch path is
    // exercised by handing libssh2 a key that cannot match anything.
    const ED25519_LINE: &str =
        "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEr0bPvzvxFqJv6FoUfYh0uKQ0Xk1pTTZAt1nTqzGw4a";
    const RSA_LINE_PORT: &str =
        "[example.com]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLmH0JmvUT2ZS8Jb7LJv2vLp3qzWlq9VWTqpZ4V5mYQ==";
    const OTHER_HOST: &str =
        "other.example.net ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2eF6hQ9v1YkYqk3nVJ0oT0mM7yQ6r8sN4uV1wX2yZ3";

    #[test]
    fn pattern_matches_openssh_convention() {
        assert_eq!(known_hosts_pattern("example.com", 22), "example.com");
        assert_eq!(known_hosts_pattern("example.com", 2222), "[example.com]:2222");
    }

    #[test]
    fn rsa_expands_to_the_sha2_variants() {
        // known_hosts stores RSA keys as "ssh-rsa" but the transport negotiates
        // rsa-sha2-*, so the expansion must not be 1:1 or the ordering fix
        // would never pick a pinned RSA host.
        assert_eq!(
            hostkey_algs_for("ssh-rsa"),
            &["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
        );
        assert_eq!(hostkey_algs_for("ssh-ed25519"), &["ssh-ed25519"]);
        assert!(hostkey_algs_for("sk-ssh-ed25519@openssh.com").is_empty());
    }

    #[test]
    fn line_split_skips_markers() {
        assert_eq!(
            split_known_hosts_line("example.com ssh-ed25519 AAAAC3Nz"),
            Some(("ssh-ed25519", "AAAAC3Nz"))
        );
        assert_eq!(
            split_known_hosts_line("@cert-authority *.example.com ssh-rsa AAAAB3Nz"),
            Some(("ssh-rsa", "AAAAB3Nz"))
        );
        assert_eq!(split_known_hosts_line("example.com"), None);
    }

    #[test]
    fn stored_entries_pick_only_the_matching_host() {
        let sess = Session::new().expect("Session::new");
        let text = format!("# a comment\n\n{}\n{}\n{}\n", OTHER_HOST, ED25519_LINE, RSA_LINE_PORT);

        // A "[host]:port" entry is scoped to that port, so it must not surface
        // for the default port.
        let got = stored_host_entries_in(&sess, &text, "example.com", 22);
        assert_eq!(got.len(), 1, "got {:?}", got);
        assert_eq!(got[0].0, "ssh-ed25519");

        // ...while a bare entry covers every port, same as OpenSSH — so both
        // lines apply here, and both belong in the ordering and in the
        // mismatch report.
        let got: Vec<String> = stored_host_entries_in(&sess, &text, "example.com", 2222)
            .into_iter()
            .map(|(alg, _)| alg)
            .collect();
        assert_eq!(got, ["ssh-ed25519", "ssh-rsa"]);

        assert!(stored_host_entries_in(&sess, &text, "unknown.example", 22).is_empty());
    }

    #[test]
    fn stored_entries_survive_a_malformed_line() {
        // An unparseable line must not take the whole file down — the
        // authoritative read_file check in verify_host_key is what fails closed.
        let sess = Session::new().expect("Session::new");
        let text = format!("garbage ssh-ed25519 !!!not-base64!!!\n{}\n", ED25519_LINE);
        let got = stored_host_entries_in(&sess, &text, "example.com", 22);
        assert_eq!(got.len(), 1, "got {:?}", got);
    }

    #[test]
    fn stored_key_fingerprint_is_openssh_shaped() {
        let fp = fingerprint_of_stored_key("AAAAC3NzaC1lZDI1NTE5AAAAIEr0bPvzvxFqJv6FoUfYh0uKQ0Xk1pTTZAt1nTqzGw4a");
        assert!(fp.starts_with("SHA256:"), "got {}", fp);
        assert!(!fp.ends_with('='), "OpenSSH strips base64 padding, got {}", fp);
        assert_eq!(fingerprint_of_stored_key("!!!"), "SHA256:<unreadable>");
    }

    #[test]
    fn multiline_pubkey_is_rejected_not_stripped() {
        // `echo 'a\nb' >> authorized_keys` writes TWO entries. Stripping would
        // deploy something the user never reviewed, so this must be an error.
        let ok = validate_authorized_key_line("  ssh-ed25519 AAAA user@host \n");
        assert_eq!(ok.unwrap(), "ssh-ed25519 AAAA user@host");

        for bad in [
            "ssh-ed25519 AAAA\nssh-rsa BBBB",
            "ssh-ed25519 AAAA\r\ncommand=\"sh\" ssh-rsa BBBB",
            "ssh-ed25519 AAAA\rssh-rsa BBBB",
        ] {
            let e = validate_authorized_key_line(bad).unwrap_err();
            assert!(e.contains("single line"), "got: {}", e);
        }
        assert!(validate_authorized_key_line("ssh-ed25519 A\0B").is_err());
        assert!(validate_authorized_key_line("   ").is_err());
    }
}
