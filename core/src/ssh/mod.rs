use std::collections::HashMap;
use std::io::{Read as IoRead, Seek, Write as IoWrite};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NOPAD};
use base64::Engine;
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use ssh2::{KeyboardInteractivePrompt, MethodType, Session};

use crate::i18n;

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

/// One round of keyboard-interactive challenges, handed to the GUI.
///
/// Each entry is `(text, echo)`; `echo == false` means the answer is a secret
/// and the modal must mask it (that is how a PAM password differs from an
/// "Enter your OTP code" prompt, which the server marks echoable).
#[derive(Debug, Clone, Default)]
pub struct AuthPrompt {
    pub prompts: Vec<(String, bool)>,
}

/// A keyboard-interactive challenge parked on the blocking SSH thread.
///
/// libssh2's prompt callback runs *inside* `userauth_keyboard_interactive`,
/// i.e. on the thread that owns the socket, and has to return the answers
/// synchronously. The GUI lives on another thread, so the callback sends this
/// struct down the channel registered with [`set_auth_prompter`] and blocks on
/// `reply` while the modal is on screen.
pub struct AuthChallenge {
    /// Id of the session asking: the id `connect` returns, known before the
    /// connect does through `SshManager::connect_config_with_id`. Closing the
    /// session's tab withdraws its challenges with [`Self::cancel`]. Empty for
    /// a connection test or a key deployment, which have no session.
    pub session_id: String,
    /// "user@host:port", for the modal title.
    pub target: String,
    /// Which connection is asking: "shell", "exec", "reconnect", "test" or
    /// "deploy". A 2FA server challenges the shell and the monitoring/SFTP
    /// connection separately, so the modal can say which one this is.
    pub purpose: String,
    /// Username the server is challenging. May differ from the one we sent,
    /// and may be empty.
    pub username: String,
    /// Free-form text the server wants shown above the prompts.
    pub instructions: String,
    pub prompt: AuthPrompt,
    /// One `String` per entry in `prompt.prompts`, in order. Dropping the
    /// sender without replying cancels the attempt.
    pub reply: mpsc::Sender<Vec<String>>,
    /// Raised by [`Self::cancel`]; read on the SSH thread once `reply` is gone.
    cancelled: Arc<AtomicBool>,
}

impl AuthChallenge {
    /// Decline to answer, as the user's decision: Esc, the Cancel button, or
    /// the tab the challenge belongs to closing. The sign-in stops — a
    /// reconnect gives up rather than asking again, an exec connection stays
    /// parked — however long the modal has been up.
    ///
    /// Just dropping the challenge is not that decision once the modal has
    /// been up for `AUTH_PROMPT_TIMEOUT` minus 20 s, or while the vault is
    /// locked: that is how the GUI retires a modal nobody answered and how the
    /// lock screen clears the queue, and the sign-in only stops waiting.
    pub fn cancel(self) {
        self.cancelled.store(true, Ordering::SeqCst);
        // `self` drops here, and `reply` with it: that is what wakes the SSH
        // thread, and it reads the flag only after.
    }
}

/// How long the SSH thread waits for the GUI before abandoning a challenge.
/// Without a bound, a dismissed modal would wedge the session thread — and in
/// minimal mode the terminal reader's lock along with it.
const AUTH_PROMPT_TIMEOUT: Duration = Duration::from_secs(180);

static AUTH_PROMPTER: Lazy<RwLock<Option<mpsc::Sender<AuthChallenge>>>> =
    Lazy::new(|| RwLock::new(None));

/// Register the GUI's challenge channel; `app.rs` calls this once at startup.
/// Until it does, a plain PAM password challenge still completes on its own
/// (see `GuiPrompter`), but a real 2FA question has nowhere to go.
pub fn set_auth_prompter(tx: mpsc::Sender<AuthChallenge>) {
    *AUTH_PROMPTER.write() = Some(tx);
}

/// Answers the server's keyboard-interactive challenges from the GUI.
struct GuiPrompter<'a> {
    /// See [`AuthChallenge::session_id`].
    session_id: &'a str,
    target: &'a str,
    purpose: &'a str,
    /// Where challenges go: the channel registered with
    /// [`set_auth_prompter`], read once when the login starts.
    gui: Option<mpsc::Sender<AuthChallenge>>,
    /// Password saved on the connection, for [`saved_password_answer`]:
    /// PAM-backed servers ask for the first factor through
    /// keyboard-interactive, and OpenSSH's own client answers it the same way.
    /// Taken on first use.
    password: Option<&'a str>,
    /// Set when a round could not be answered, so the caller can report why
    /// instead of libssh2's generic "Authentication failed".
    failure: Option<String>,
    /// The user dismissed a challenge of this login (see
    /// [`challenge_dismissed`]).
    dismissed: bool,
}

impl KeyboardInteractivePrompt for GuiPrompter<'_> {
    fn prompt<'p>(
        &mut self,
        username: &str,
        instructions: &str,
        prompts: &[ssh2::Prompt<'p>],
    ) -> Vec<String> {
        // libssh2 calls again for as long as the server keeps asking. A server
        // that re-prompts after the empty answers a dismissal sends must not
        // bring back the modal the user just closed.
        if self.dismissed {
            return vec![String::new(); prompts.len()];
        }
        let items: Vec<(String, bool)> = prompts
            .iter()
            .map(|p| (p.text.to_string(), p.echo))
            .collect();

        if let Some(answer) = saved_password_answer(&items, &mut self.password) {
            return answer;
        }

        let tx = match self.gui.clone() {
            Some(tx) => tx,
            None => {
                self.failure = Some(i18n::t("auth.err.no_handler").to_string());
                return vec![String::new(); items.len()];
            }
        };

        let (reply_tx, reply_rx) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let challenge = AuthChallenge {
            session_id: self.session_id.to_string(),
            target: self.target.to_string(),
            purpose: self.purpose.to_string(),
            username: username.to_string(),
            instructions: instructions.to_string(),
            prompt: AuthPrompt {
                prompts: items.clone(),
            },
            reply: reply_tx,
            cancelled: Arc::clone(&cancelled),
        };
        if tx.send(challenge).is_err() {
            self.failure = Some(i18n::t("auth.err.handler_gone").to_string());
            return vec![String::new(); items.len()];
        }

        let asked = std::time::Instant::now();
        match reply_rx.recv_timeout(AUTH_PROMPT_TIMEOUT) {
            Ok(mut answers) => {
                // libssh2 reads one answer per prompt positionally, so a short
                // or long Vec from the GUI must be normalised here.
                answers.resize(items.len(), String::new());
                answers
            }
            Err(e) => {
                self.dismissed = challenge_dismissed(
                    e,
                    asked.elapsed(),
                    vault_locked(),
                    cancelled.load(Ordering::SeqCst),
                );
                self.failure = Some(i18n::tf(
                    "auth.err.no_answer",
                    &[("err", &e.to_string())],
                ));
                vec![String::new(); items.len()]
            }
        }
    }
}

/// Words that make a masked prompt a second factor even when it also says
/// "password": "One-time password (OATH) for alice:", "动态密码：". Matched
/// case-insensitively anywhere in the prompt; a false match only means the
/// user types the answer.
const SECOND_FACTOR_WORDS: &[&str] = &[
    "one-time",
    "one time",
    "onetime",
    "otp",
    "verification",
    "token",
    "code",
    "passcode",
    "2fa",
    "mfa",
    "two-factor",
    "factor",
    "authenticator",
    "验证码",
    "验证",
    "动态",
    "令牌",
    "一次性",
    "双因素",
];

/// Whether a prompt asks for the account password and nothing else.
fn asks_account_password(text: &str) -> bool {
    let low = text.to_lowercase();
    (low.contains("password") || low.contains("密码"))
        && !SECOND_FACTOR_WORDS.iter().any(|w| low.contains(w))
}

/// The saved password as this round's answer: only for a round that is one
/// masked prompt for the account password, and only once per login.
///
/// `saved` is taken on use. A second password prompt means the first answer
/// was refused — the saved password is stale, or the server wants it typed —
/// and sending it again would only be refused again, so the user answers.
fn saved_password_answer(
    prompts: &[(String, bool)],
    saved: &mut Option<&str>,
) -> Option<Vec<String>> {
    match prompts {
        [(text, false)] if asks_account_password(text) => {
            saved.take().map(|pw| vec![pw.to_string()])
        }
        _ => None,
    }
}

/// How long before [`AUTH_PROMPT_TIMEOUT`] the GUI retires a modal nobody
/// answered — `AUTH_PROMPT_TTL` in app.rs, 170 s — with slack for its poll
/// tick.
const AUTH_PROMPT_RETIRE_WINDOW: Duration = Duration::from_secs(20);

/// Whether a challenge that ended without an answer was the user's decision.
///
/// [`AuthChallenge::cancel`] says so outright, `cancelled`, whenever it came.
/// A challenge that was only dropped is read by timing, for a GUI that drops
/// on Esc and the Cancel button: two things nobody decided look the same from
/// here — the lock screen clearing every pending challenge, and the GUI
/// retiring a modal left unanswered (see [`AUTH_PROMPT_RETIRE_WINDOW`]) — so
/// a drop late in the wait, or under a locked vault, is not a dismissal. That
/// used to be all there was, and a Cancel pressed after 160 s asked again.
/// This side's own timeout never means "stop".
fn challenge_dismissed(
    end: mpsc::RecvTimeoutError,
    waited: Duration,
    vault_locked: bool,
    cancelled: bool,
) -> bool {
    cancelled
        || (end == mpsc::RecvTimeoutError::Disconnected
            && !vault_locked
            && waited + AUTH_PROMPT_RETIRE_WINDOW < AUTH_PROMPT_TIMEOUT)
}

/// Whether the vault is locked at this moment: the lock screen cancels every
/// pending challenge on its way up.
fn vault_locked() -> bool {
    crate::storage::global_vault().is_some_and(|v| !v.is_unlocked())
}

/// Why a keyboard-interactive login did not complete.
#[derive(Debug)]
struct InteractiveAuthError {
    message: String,
    /// The user dismissed a challenge: a decision about this connection, not
    /// a failure to retry.
    dismissed: bool,
}

impl std::fmt::Display for InteractiveAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Keyboard-interactive auth (PAM challenges, OTP / 2FA).
///
/// Without it every server that requires a second factor was simply
/// unreachable: the auth match fell straight through to "Unknown auth type".
///
/// Every keyboard-interactive login in this file goes through here — shell,
/// exec, reconnect, test and deploy — so the timeout guard below covers all
/// of them.
fn userauth_interactive(
    session: &impl KeyboardInteractive,
    username: &str,
    password: Option<&str>,
    host: &str,
    port: u16,
    purpose: &str,
    session_id: &str,
) -> Result<(), InteractiveAuthError> {
    let target = format!("{}@{}:{}", username, host, port);
    let mut prompter = GuiPrompter {
        session_id,
        target: &target,
        purpose,
        gui: AUTH_PROMPTER.read().clone(),
        password,
        failure: None,
        dismissed: false,
    };
    let result = {
        // Spans exactly the call that waits on a human.
        let _no_timeout = PromptTimeoutScope::enter(session);
        session.keyboard_interactive(username, &mut prompter)
    };
    result.map_err(|e| InteractiveAuthError {
        message: match prompter.failure.take() {
            Some(why) => format!("{} ({})", why, e),
            None => e.to_string(),
        },
        dismissed: prompter.dismissed,
    })
}

/// `userauth_keyboard_interactive`, behind a trait only so that the timeout
/// handling around it can be tested without a server.
trait KeyboardInteractive: BlockingControl {
    fn keyboard_interactive(
        &self,
        username: &str,
        prompter: &mut GuiPrompter<'_>,
    ) -> Result<(), ssh2::Error>;
}

impl KeyboardInteractive for Session {
    fn keyboard_interactive(
        &self,
        username: &str,
        prompter: &mut GuiPrompter<'_>,
    ) -> Result<(), ssh2::Error> {
        self.userauth_keyboard_interactive(username, prompter)
    }
}

/// No libssh2 timeout for as long as the guard lives; the session's previous
/// one comes back on drop — on success, on failure, on every early return.
///
/// libssh2 measures a blocking call's timeout from the moment the call is
/// *entered*, and the prompt callback runs inside
/// `userauth_keyboard_interactive`. So the 10–15 s handshake timeout still on
/// the session was also a limit on the user: a TOTP code typed 20 s after the
/// modal opened failed with "API timeout expired". The human side is bounded
/// by `AUTH_PROMPT_TIMEOUT` instead. The price: the wait for the server's
/// verdict after an answer is bounded by keepalive where the session already
/// has it on, and only by TCP where it does not.
struct PromptTimeoutScope<'a, S: BlockingControl> {
    sess: &'a S,
    prev_timeout: u32,
}

impl<'a, S: BlockingControl> PromptTimeoutScope<'a, S> {
    fn enter(sess: &'a S) -> Self {
        let prev_timeout = sess.timeout();
        sess.set_timeout(0);
        Self { sess, prev_timeout }
    }
}

impl<S: BlockingControl> Drop for PromptTimeoutScope<'_, S> {
    fn drop(&mut self) {
        self.sess.set_timeout(self.prev_timeout);
    }
}

/// SSH agent auth, tried against *every* identity the agent holds.
///
/// `Session::userauth_agent` only ever tries the first one, which fails the
/// moment a user has more than one key loaded — the common case.
fn userauth_agent_identities(session: &Session, username: &str) -> Result<(), String> {
    let mut agent = session
        .agent()
        .map_err(|e| i18n::tf("auth.err.agent_unavailable", &[("err", &e.to_string())]))?;
    agent
        .connect()
        .map_err(|e| i18n::tf("auth.err.agent_connect", &[("err", &e.to_string())]))?;
    agent
        .list_identities()
        .map_err(|e| i18n::tf("auth.err.agent_list", &[("err", &e.to_string())]))?;
    let identities = agent
        .identities()
        .map_err(|e| i18n::tf("auth.err.agent_read", &[("err", &e.to_string())]))?;
    if identities.is_empty() {
        return Err(i18n::t("auth.err.agent_empty").into());
    }

    let mut last_err = String::new();
    for identity in &identities {
        match agent.userauth(username, identity) {
            Ok(()) => {
                log::info!("ssh-agent auth accepted identity {:?}", identity.comment());
                let _ = agent.disconnect();
                return Ok(());
            }
            Err(e) => {
                last_err = format!("{}: {}", identity.comment(), e);
            }
        }
    }
    let _ = agent.disconnect();
    Err(i18n::tf(
        "auth.err.agent_rejected",
        &[("count", &identities.len().to_string()), ("last", &last_err)],
    ))
}

/// Sanitize one path component that came from an untrusted source before it is
/// used to build either a local or a remote path.
///
/// The ssh-side twin of `app::safe_local_basename`, but strict where that one
/// is lenient: it *rejects* anything that is not already a single inert
/// component instead of trimming it down to one. A server that answers
/// `readdir` with `..`, `../../x` or an absolute path would otherwise get to
/// choose where a recursive download lands on the local disk, and silently
/// renaming such an entry to its basename would write a file the server never
/// actually named.
fn safe_path_component(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    // "." and ".." are traversal primitives; so is any all-dots name on the
    // servers that accept it.
    if name.chars().all(|c| c == '.') {
        return None;
    }
    // `\` is not a separator on unix, so it survives a `Path::file_name()`
    // round trip; reject it explicitly so the same name is safe on Windows.
    if name
        .chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
    {
        return None;
    }
    Some(name.to_string())
}

/// Validate a remote path before a mutating SFTP call.
///
/// mkdir / remove / rename / chmod are the first operations in the app that can
/// destroy remote data, so the guard is deliberately strict: absolute, no `..`
/// component, no control byte, no `\`, and never the filesystem root itself. A
/// relative path is refused rather than guessed at — the server would resolve
/// it against the SFTP start directory, which is not the directory the file
/// browser is showing.
///
/// `\` is refused on every platform: ssh2 on Windows sends each one as `/`
/// (`path2bytes`, vendor/ssh2/src/util.rs), so a remote name such as
/// `notes\..\..\home\victim\.ssh\id_ed25519` passed the `..` check and then
/// arrived as a traversal. A Linux name that really contains `\` is refused
/// with a clear error rather than silently rewritten.
///
/// Nothing is trimmed but trailing slashes, so `"/tmp/x/"` and `"/tmp/x"`
/// behave identically. Whitespace is part of a name: trimming it turned a
/// delete of `"project "` into a delete of the directory `"project"`.
fn validate_remote_path(path: &str) -> Result<String, String> {
    let raw = path;
    if raw.is_empty() {
        return Err(i18n::t("sftp.err.path_empty").into());
    }
    if raw.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(i18n::t("sftp.err.path_control").into());
    }
    if raw.contains('\\') {
        return Err(i18n::tf("sftp.err.path_backslash", &[("path", raw)]));
    }
    if !raw.starts_with('/') {
        return Err(i18n::tf("sftp.err.path_relative", &[("path", raw)]));
    }
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(i18n::t("sftp.err.path_root").into());
    }
    if trimmed.split('/').any(|c| c == "..") {
        return Err(i18n::tf("sftp.err.path_dotdot", &[("path", raw)]));
    }
    Ok(trimmed.to_string())
}

/// `path` as the `Path` an SFTP call takes, refused where ssh2 would not send
/// it as written: off unix it rewrites every `\` to `/`, which turns a name
/// like `a\..\..\x` into a traversal (see [`validate_remote_path`], which
/// refuses `\` everywhere). For the calls that take a path as given — open,
/// read, write, list — and keep working on unix with a `\` in a name.
fn sftp_sendable(path: &str) -> Result<&std::path::Path, String> {
    if cfg!(not(unix)) && path.contains('\\') {
        return Err(i18n::tf("sftp.err.path_backslash", &[("path", path)]));
    }
    Ok(std::path::Path::new(path))
}

/// Maximum directory depth any recursive SFTP walk will descend.
///
/// Guards against a server answering `readdir` with a cycle — or simply a
/// pathological tree — and blowing the stack.
const MAX_SFTP_DEPTH: usize = 64;

/// Join a remote directory and a single already-sanitized component.
fn join_remote(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{}{}", dir, name)
    } else {
        format!("{}/{}", dir, name)
    }
}

/// Append a chain of already-sanitized components to a remote root.
fn join_remote_all(root: &str, rel: &[String]) -> String {
    let mut p = root.to_string();
    for c in rel {
        p = join_remote(&p, c);
    }
    p
}

/// Append a chain of already-sanitized components to a local root.
fn join_local(root: &std::path::Path, rel: &[String]) -> std::path::PathBuf {
    let mut p = root.to_path_buf();
    for c in rel {
        p.push(c);
    }
    p
}

/// Upper bound, in milliseconds, on each blocking libssh2 call an SFTP
/// operation makes.
///
/// libssh2 measures it per call — one open, one 32 KiB read or write — not per
/// transfer, so a slow transfer that keeps moving never reaches it, while a
/// peer that stops answering releases the session mutex (and in minimal mode
/// the terminal with it) instead of holding it for ever.
const SFTP_TIMEOUT_MS: u32 = 60_000;

/// Upper bound, in milliseconds, on starting the SFTP subsystem — a channel,
/// the "sftp" subsystem request, the version exchange: round trips a live
/// server answers at once — and on the probe of the exec connection before a
/// file operation (`SshManager::get_exec_session`). Far below
/// [`SFTP_TIMEOUT_MS`]: a start on a black-holed link held the exec lock — in
/// minimal mode the terminal with it — for the whole of that, and only then
/// could anything rebuild the connection.
const SFTP_INIT_TIMEOUT_MS: u32 = 15_000;

/// Upper bound on the bare subsystem request that tells apart the ways a
/// start can fail ([`sftp_start_verdict`]): two round trips on a link that is
/// up.
const SFTP_PROBE_TIMEOUT_MS: u32 = 5_000;

/// The two pieces of libssh2 session state an exec or SFTP call switches:
/// blocking mode and the blocking-call timeout. A trait only so that
/// [`BlockingScope`] and [`PromptTimeoutScope`] can be tested without a server.
trait BlockingControl {
    fn is_blocking(&self) -> bool;
    fn set_blocking(&self, blocking: bool);
    fn timeout(&self) -> u32;
    fn set_timeout(&self, timeout_ms: u32);
}

impl BlockingControl for Session {
    fn is_blocking(&self) -> bool {
        Session::is_blocking(self)
    }
    fn set_blocking(&self, blocking: bool) {
        Session::set_blocking(self, blocking)
    }
    fn timeout(&self) -> u32 {
        Session::timeout(self)
    }
    fn set_timeout(&self, timeout_ms: u32) {
        Session::set_timeout(self, timeout_ms)
    }
}

/// Blocking mode with a bounded timeout for as long as the guard lives; the
/// session's previous mode and timeout come back on drop — on success, on `?`,
/// on every early return.
///
/// In minimal mode the exec/SFTP session *is* the shell session, and the shell
/// reader relies on non-blocking reads that return `WouldBlock`. An SFTP call
/// that left the session blocking turned every idle terminal read into a wait
/// of the full session timeout under the session lock: typing froze for ~15 s,
/// then the timed-out read forced a reconnect.
///
/// Create it right after locking the session and before any `Sftp` / `File`
/// handle, so those drop first and their close requests still run blocking and
/// bounded.
struct BlockingScope<'a, S: BlockingControl> {
    sess: &'a S,
    was_blocking: bool,
    prev_timeout: u32,
}

impl<'a, S: BlockingControl> BlockingScope<'a, S> {
    fn enter(sess: &'a S, timeout_ms: u32) -> Self {
        let was_blocking = sess.is_blocking();
        let prev_timeout = sess.timeout();
        sess.set_blocking(true);
        sess.set_timeout(timeout_ms);
        Self {
            sess,
            was_blocking,
            prev_timeout,
        }
    }
}

impl<S: BlockingControl> Drop for BlockingScope<'_, S> {
    fn drop(&mut self) {
        self.sess.set_timeout(self.prev_timeout);
        self.sess.set_blocking(self.was_blocking);
    }
}

/// Run `step` on `sess` bounded by `timeout_ms`, then leave [`SFTP_TIMEOUT_MS`]
/// for the SFTP operations that follow. Only inside a [`BlockingScope`], which
/// puts the session's own bound back.
fn bounded<S: BlockingControl, T>(sess: &S, timeout_ms: u32, step: impl FnOnce(&S) -> T) -> T {
    sess.set_timeout(timeout_ms);
    let out = step(sess);
    sess.set_timeout(SFTP_TIMEOUT_MS);
    out
}

/// Start the SFTP subsystem on `sess` — see [`start_sftp_with`].
fn start_sftp(sess: &Session) -> Result<ssh2::Sftp, ssh2::Error> {
    start_sftp_with(sess, Session::sftp)
}

/// `start` — `Session::sftp` — bounded by [`SFTP_INIT_TIMEOUT_MS`] rather than
/// the per-operation bound, and made once more when it fails other than by
/// timing out: libssh2 leaves the channel of a start that failed after
/// opening one for the next call to free, and that call only frees it and
/// fails (`sftp_init`'s error_closing state), so the next listing or transfer
/// failed for nothing. After a start that failed before opening a channel,
/// the second call is a plain retry. A timeout is not retried — that is the
/// dead link the short bound is there to catch. The first failure is the one
/// reported.
fn start_sftp_with<S: BlockingControl, T>(
    sess: &S,
    start: impl Fn(&S) -> Result<T, ssh2::Error>,
) -> Result<T, ssh2::Error> {
    let first = match bounded(sess, SFTP_INIT_TIMEOUT_MS, &start) {
        Ok(sftp) => return Ok(sftp),
        Err(e) => e,
    };
    if first.code() == ssh2::ErrorCode::Session(LIBSSH2_ERROR_TIMEOUT) {
        return Err(first);
    }
    bounded(sess, SFTP_INIT_TIMEOUT_MS, &start).map_err(|_| first)
}

/// Whether a file transfer may keep bytes already at the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeMode {
    /// Always truncate and write the whole file. Folder transfers use this: a
    /// same-named file already in the destination tree is far more often an
    /// older version than an interrupted copy, and proving otherwise would
    /// mean reading back every file in the tree.
    Never,
    /// Keep the destination's bytes only once they are proven identical to the
    /// source's first bytes; anything else is overwritten.
    IfPrefixMatches,
}

/// What a transfer does with an existing destination file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumePlan {
    /// Truncate and write everything.
    Overwrite,
    /// Keep the first `n` bytes — proven identical to the source's — and append
    /// the rest.
    Resume(u64),
}

/// Decide between resuming and overwriting.
///
/// Length alone proves nothing: a file that grew from 1000 to 1200 bytes and
/// was also edited in its first 1000 used to come out as "old first 1000 + new
/// last 200", silently. A resume now needs all three: the mode allows it, the
/// destination is a strict, non-empty prefix by length, and
/// `prefix_is_identical(dest_size)` confirms it byte for byte. An equal-size or
/// larger destination is overwritten, as before.
fn plan_resume(
    mode: ResumeMode,
    dest_size: u64,
    src_size: u64,
    prefix_is_identical: impl FnOnce(u64) -> bool,
) -> ResumePlan {
    if mode == ResumeMode::Never || dest_size == 0 || dest_size >= src_size {
        return ResumePlan::Overwrite;
    }
    if prefix_is_identical(dest_size) {
        ResumePlan::Resume(dest_size)
    } else {
        ResumePlan::Overwrite
    }
}

/// Whether the first `len` bytes of `a` and `b` are byte-for-byte identical.
///
/// Both sides are read in step and the walk stops at the first difference, so
/// a file edited near its start is rejected after one chunk. Either side ending
/// early, or any read error, counts as "different": the caller then overwrites,
/// which is always safe. Verified bytes count toward the progress bar (they
/// will not be sent again), and Cancel is honoured between chunks.
fn same_prefix(
    a: &mut impl IoRead,
    b: &mut impl IoRead,
    len: u64,
    progress: &TransferProgress,
    base: u64,
) -> bool {
    let mut buf_a = [0u8; 32768];
    let mut buf_b = [0u8; 32768];
    let mut done = 0u64;
    while done < len {
        if progress.finished.load(Ordering::Relaxed) {
            return false;
        }
        let n = (len - done).min(buf_a.len() as u64) as usize;
        if a.read_exact(&mut buf_a[..n]).is_err()
            || b.read_exact(&mut buf_b[..n]).is_err()
            || buf_a[..n] != buf_b[..n]
        {
            return false;
        }
        done += n as u64;
        progress.transferred.store(base + done, Ordering::Relaxed);
    }
    true
}

/// Settle where one file copy starts, and leave `src` positioned there.
///
/// Shared by upload (source = local file, destination = remote file) and
/// download (the reverse). `open_dest` reopens the existing destination
/// read-only and is only called when a resume is on the table. Returns the
/// offset the copy starts at: 0 means "truncate the destination", anything else
/// "append to it". Nothing has been written anywhere yet when this returns, so
/// a Cancel during the comparison leaves the destination untouched.
fn plan_copy<S: IoRead + Seek, D: IoRead>(
    mode: ResumeMode,
    src: &mut S,
    src_size: u64,
    dest_size: u64,
    open_dest: impl FnOnce() -> Option<D>,
    progress: &TransferProgress,
    base: u64,
) -> Result<u64, String> {
    progress.transferred.store(base, Ordering::Relaxed);
    let plan = plan_resume(mode, dest_size, src_size, |n| match open_dest() {
        Some(mut dest) => same_prefix(&mut dest, src, n, progress, base),
        None => false,
    });
    bail_if_cancelled(progress)?;
    let start = match plan {
        ResumePlan::Resume(n) => n,
        ResumePlan::Overwrite => 0,
    };
    // A comparison that failed part-way has already moved `src`; an overwrite
    // must start again from its first byte or the copy would lose its head.
    src.seek(std::io::SeekFrom::Start(start))
        .map_err(|e| format!("Seek failed: {}", e))?;
    progress.transferred.store(base + start, Ordering::Relaxed);
    Ok(start)
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
    if let Some(ref proxy_id) = params.proxy_id {
        return connect_through_proxy(&crate::proxy::ProxyStore::new(), proxy_id, params);
    }
    crate::proxy::connect_direct(&params.host, params.port, Duration::from_secs(10))
}

/// The proxied half of `establish_tcp`, with the store passed in so a test can
/// point it at a scratch file and a locked vault.
///
/// Fails closed on both counts. A proxy that no longer exists is not bypassed:
/// the user asked for this traffic to cross a specific network boundary, and
/// dialling the target directly would leak it onto a path they deliberately
/// excluded. A proxy whose password is locked in the vault — the idle re-lock
/// does that behind a live session — is not dialled either: `get` used to hand
/// back the config without its secret, and every auto-reconnect then offered
/// the proxy an empty password, enough to lock the account behind it.
fn connect_through_proxy(
    store: &crate::proxy::ProxyStore,
    proxy_id: &str,
    params: &ConnectParams,
) -> Result<TcpStream, String> {
    let proxy_cfg = store.get_for_connect(proxy_id)?;
    crate::proxy::connect_via_proxy(
        &proxy_cfg,
        &params.host,
        params.port,
        Duration::from_secs(15),
    )
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
    /// Swap, parsed out of the `free -m` output the stats command already
    /// returns — no extra round trip. Zero on a host with no swap configured.
    #[serde(default)]
    pub swap_total_mb: u64,
    #[serde(default)]
    pub swap_used_mb: u64,
    #[serde(default)]
    pub swap_percent: f64,
    /// True CPU utilisation from a `/proc/stat` delta against the previous
    /// poll of this session. Load average is a queue length, not a percentage,
    /// so it could never answer "how busy is this box right now".
    #[serde(default)]
    pub cpu_percent: f64,
    /// Same measure per core, in the kernel's `cpu0..cpuN` order. Empty when
    /// `/proc/stat` was unreadable (non-Linux remote).
    #[serde(default)]
    pub cpu_per_core: Vec<f64>,
}

/// One listening socket from `ss -tulnp` / `netstat -tulnp`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortInfo {
    /// "tcp", "tcp6", "udp", "udp6" — as the remote tool spelled it.
    pub proto: String,
    /// Bind address: "0.0.0.0", "[::]", "127.0.0.1", or "*" for a bare port.
    pub local_addr: String,
    pub port: u16,
    /// `None` when the login user may not see the socket's owner — that is the
    /// normal unprivileged case, not an error.
    pub pid: Option<u32>,
    pub process: String,
}

/// One `/proc/stat` cpu line reduced to the two numbers the delta needs.
#[derive(Debug, Clone, Copy, Default)]
struct CpuTimes {
    total: u64,
    idle: u64,
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

/// One row of the file browser's listing (see `SshManager::list_files`).
#[derive(Debug, Clone, Default)]
pub struct FileEntry {
    /// The name as text, for display: decoded lossily where the server's
    /// bytes are not UTF-8.
    pub name: String,
    pub is_dir: bool,
    pub size: String,
    pub permissions: String,
    pub modified: String,
    pub owner: String,
    /// The name exactly as the server sent it — what an operation on the row
    /// addresses ([`ConfirmedEntry`]). `name` joined back into a path sent
    /// "a\u{FFFD}" for the entry b"a\xff": another entry, or none.
    pub raw_name: Vec<u8>,
    /// Whether the row came from an SFTP listing, every field from the entry's
    /// own attributes. `false` for a row parsed from `ls -la` text, which a
    /// name holding a newline can forge and one holding "\r" or " -> " can
    /// mangle: `SshManager::sftp_remove_confirmed`, `sftp_rename_confirmed`
    /// and `sftp_chmod_confirmed` refuse such a row.
    pub verified: bool,
}

/// What a remote entry is: as the listing showed it ([`FileEntry::kind`]),
/// and as `lstat` finds it when a destructive operation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    /// A symbolic link, one to a directory included. Never followed.
    Symlink,
    /// A fifo, socket or device, or an entry the server gave no type.
    Other,
}

impl EntryKind {
    /// From an SFTP attribute block — `lstat`'s, so a symlink is a symlink.
    fn of(stat: &ssh2::FileStat) -> Self {
        let t = stat.file_type();
        if t.is_dir() {
            EntryKind::Dir
        } else if t.is_file() {
            EntryKind::File
        } else if t.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::Other
        }
    }
}

impl FileEntry {
    /// The kind this row shows: what `SshManager::sftp_remove_confirmed`,
    /// `sftp_rename_confirmed` and `sftp_chmod_confirmed` must be told the
    /// user confirmed. Read off the row's `ls`-style permissions ("d", "l",
    /// "-"); a row without any — the browser's own ".." — goes by `is_dir`.
    pub fn kind(&self) -> EntryKind {
        match self.permissions.chars().next() {
            Some('d') => EntryKind::Dir,
            Some('l') => EntryKind::Symlink,
            Some('-') => EntryKind::File,
            Some(_) => EntryKind::Other,
            None if self.is_dir => EntryKind::Dir,
            None => EntryKind::Other,
        }
    }
}

/// The row a destructive operation was confirmed on, as
/// `SshManager::sftp_remove_confirmed`, `sftp_rename_confirmed` and
/// `sftp_chmod_confirmed` check it before they act: the kind the row showed
/// ([`FileEntry::kind`]), its name as the server sent it
/// ([`FileEntry::raw_name`]) and whether its listing was verified
/// ([`FileEntry::verified`]). Made from the row: `ConfirmedEntry::from(&entry)`.
///
/// Transitional: from a bare [`EntryKind`], for a caller that kept only the
/// kind — the path is then sent as given and only the kind is checked, as
/// before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedEntry {
    kind: EntryKind,
    raw_name: Option<Vec<u8>>,
    verified: bool,
}

impl From<&FileEntry> for ConfirmedEntry {
    fn from(entry: &FileEntry) -> Self {
        ConfirmedEntry {
            kind: entry.kind(),
            raw_name: Some(entry.raw_name.clone()),
            verified: entry.verified,
        }
    }
}

impl From<EntryKind> for ConfirmedEntry {
    fn from(kind: EntryKind) -> Self {
        ConfirmedEntry {
            kind,
            raw_name: None,
            verified: true,
        }
    }
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

/// What a transfer returns once the progress bar's Cancel has set `finished`.
/// app.rs tells a cancel from a failure by exactly this text.
const TRANSFER_CANCELLED: &str = "Transfer cancelled";

/// Stop a transfer the progress bar's Cancel already reached.
///
/// Workers only ever set `finished`, never clear it: the bar's progress is
/// created with it clear, and a Cancel can land before the worker thread even
/// runs. Clearing it at the start of the worker lost that Cancel — while the
/// bar, and with it the only Cancel button, was already gone.
fn bail_if_cancelled(progress: &TransferProgress) -> Result<(), String> {
    if progress.is_finished() {
        Err(TRANSFER_CANCELLED.to_string())
    } else {
        Ok(())
    }
}

/// How long after one exec-connection rebuild the next may start. A failed
/// rebuild is not re-dialled before it runs out; a successful one is reused by
/// every caller that tripped over the same dead connection in the meantime.
const EXEC_REBUILD_COOLDOWN: Duration = Duration::from_secs(30);

/// Per-session bookkeeping that keeps exec-connection rebuilds to one at a
/// time — and, for keyboard-interactive, to none at all.
///
/// The monitor polls every 3 s with no in-flight guard of its own, and every
/// exec or SFTP call that hit a dead exec connection used to dial a new one.
/// For a 2FA session each dial was a fresh challenge: after a laptop sleep,
/// ~20 prompts a minute, each holding a thread for up to `AUTH_PROMPT_TIMEOUT`
/// and each burning a one-time code.
#[derive(Debug, Default)]
struct ExecGate {
    /// A rebuild is running right now.
    in_flight: bool,
    /// When the last rebuild ended, and whether it produced a session.
    last: Option<(std::time::Instant, bool)>,
    /// The exec connection is dead and is not re-dialled behind the user's
    /// back: keyboard-interactive only, where a dial is a new challenge.
    /// Monitoring and SFTP fail fast until the user resumes it
    /// (`SshManager::resume_exec`) — a reconnect of the shell does not.
    parked: bool,
}

/// What [`ExecGate::begin`] allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebuildDecision {
    /// The caller owns the rebuild and reports back through `finish`.
    Dial,
    /// A rebuild finished moments ago with a fresh session: retry on that.
    Fresh,
    /// Another thread is rebuilding right now.
    InFlight,
    /// The last rebuild failed; this much of the cooldown is left.
    CoolingDown(Duration),
    /// Keyboard-interactive: only the user may reconnect.
    Parked,
}

/// What [`ExecGate::begin_resume`] allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeDecision {
    /// The caller owns the rebuild and reports back through `finish`.
    Dial,
    /// Nothing is parked: the exec connection is used as it is.
    NotParked,
    /// Another thread is rebuilding right now.
    InFlight,
}

impl ExecGate {
    /// Claim this session's one rebuild, or say why not.
    fn begin(&mut self, auth_type: &str, now: std::time::Instant) -> RebuildDecision {
        if auth_type == "interactive" {
            self.parked = true;
            return RebuildDecision::Parked;
        }
        if self.in_flight {
            return RebuildDecision::InFlight;
        }
        if let Some((at, ok)) = self.last {
            let since = now.saturating_duration_since(at);
            if since < EXEC_REBUILD_COOLDOWN {
                return if ok {
                    RebuildDecision::Fresh
                } else {
                    RebuildDecision::CoolingDown(EXEC_REBUILD_COOLDOWN - since)
                };
            }
        }
        self.in_flight = true;
        RebuildDecision::Dial
    }

    /// Release the rebuild `begin` handed out, recording how it went.
    fn finish(&mut self, ok: bool, now: std::time::Instant) {
        self.in_flight = false;
        self.last = Some((now, ok));
    }

    /// Claim the rebuild the user asked for: resuming a parked connection.
    /// No cooldown, unlike [`Self::begin`] — a mistyped code deserves an
    /// immediate second try — and nothing to do unless something is parked.
    fn begin_resume(&mut self) -> ResumeDecision {
        if !self.parked {
            return ResumeDecision::NotParked;
        }
        if self.in_flight {
            return ResumeDecision::InFlight;
        }
        self.in_flight = true;
        ResumeDecision::Dial
    }

    /// An exec call found its connection gone (see
    /// [`exec_connection_failed`]). A keyboard-interactive session is parked
    /// on the spot, before the caller lets go of the exec lock, so the calls
    /// queued behind it fail fast instead of each waiting out the same dead
    /// socket.
    fn exec_failed(&mut self, auth_type: &str) {
        if auth_type == "interactive" {
            self.parked = true;
        }
    }

    /// A fresh exec session is in the slot: the shell's reconnect brought one,
    /// or the user resumed a parked one.
    fn exec_restored(&mut self, now: std::time::Instant) {
        self.parked = false;
        self.last = Some((now, true));
    }
}

/// The rebuild [`ExecGate::begin`] handed out. Dropping it reports the outcome,
/// so no way out of a rebuild — `?` included — leaves the gate claimed.
struct RebuildClaim<'a> {
    gate: &'a Mutex<ExecGate>,
    ok: bool,
}

impl Drop for RebuildClaim<'_> {
    fn drop(&mut self) {
        self.gate.lock().finish(self.ok, std::time::Instant::now());
    }
}

/// How one exec round trip ended, reduced to what [`exec_connection_failed`]
/// needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecOutcome {
    /// Never reached the connection: no such session, no exec support, or
    /// parked.
    NotRun,
    /// The command ran and exited with this status. Non-zero included: that
    /// is the remote's answer, not a fault of the link.
    Exited(i32),
    /// libssh2 failed a request: opening the channel or starting the command.
    RequestFailed(ssh2::ErrorCode),
    /// Reading the command's output failed. ssh2 hands libssh2's errors over
    /// as `io::Error` here and keeps only their kind.
    ReadFailed(std::io::ErrorKind),
}

/// libssh2's LIBSSH2_ERROR_CHANNEL_FAILURE and _CHANNEL_REQUEST_DENIED: the
/// server refused a channel or a request on it — MaxSessions reached, exec
/// not allowed. Spelled out like [`LIBSSH2_ERROR_FILE`].
const LIBSSH2_ERROR_CHANNEL_FAILURE: i32 = -21;
const LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED: i32 = -22;

/// libssh2's LIBSSH2_ERROR_TIMEOUT: a blocking call ran out of its bound.
const LIBSSH2_ERROR_TIMEOUT: i32 = -9;

/// Whether an exec round trip shows that the connection under it is gone —
/// the only case worth a rebuild, and, for keyboard-interactive, where a
/// rebuild is a new challenge, the only case that parks the session.
///
/// libssh2 session codes count — the socket, the transport, the channel layer
/// (closed, EOF, a request that timed out) — except a refused channel or
/// request: that is the server answering, on a link that is up. Neither does
/// a read that timed out once the command was running: a slow command — a
/// 100k-entry `ls` over a slow link — is not a dead connection, and parking a
/// 2FA session on it cost the user a sign-in challenge. A dead link still
/// shows on the next call, whose channel request times out. Output that is not
/// UTF-8 does not count either — it is data, and reads are lossy now anyway
/// (see [`read_output`]) — nor does a command exiting non-zero. An SFTP
/// status is the server answering, so the link is up.
fn exec_connection_failed(outcome: ExecOutcome) -> bool {
    use ssh2::ErrorCode::{Session as Ssh, SFTP};
    match outcome {
        ExecOutcome::NotRun | ExecOutcome::Exited(_) => false,
        ExecOutcome::RequestFailed(Ssh(
            LIBSSH2_ERROR_CHANNEL_FAILURE | LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED,
        )) => false,
        ExecOutcome::RequestFailed(Ssh(_)) => true,
        ExecOutcome::RequestFailed(SFTP(_)) => false,
        // What `read_to_string` reported for non-UTF-8 output.
        ExecOutcome::ReadFailed(std::io::ErrorKind::InvalidData) => false,
        // libssh2's timeout (ssh2 maps it to TimedOut) while the command ran.
        ExecOutcome::ReadFailed(std::io::ErrorKind::TimedOut) => false,
        ExecOutcome::ReadFailed(_) => true,
    }
}

/// What a bare request for the SFTP subsystem, on a channel of its own, said
/// ([`probe_sftp_subsystem`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubsystemProbe {
    /// No channel: libssh2's code for why.
    OpenFailed(ssh2::ErrorCode),
    /// A channel, but the "subsystem" request failed with this code.
    RequestFailed(ssh2::ErrorCode),
    /// The server accepted the request.
    Accepted,
}

/// Why SFTP could not be started, as the file browser acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SftpStartVerdict {
    /// The link is up and the server runs no SFTP on it: list with `ls -la`.
    Unavailable,
    /// The server refused a channel on a link that is up: `ls` would be
    /// refused the same way, and a new connection is not called for.
    Refused,
    /// The link under the connection is gone: rebuild it — park it, for
    /// keyboard-interactive — and never fall back to `ls`.
    ConnectionLost,
}

/// Tell apart, by `probe`, the failures `Session::sftp` reports alike.
/// libssh2's `sftp_init` overwrites the cause: a refused subsystem, a refused
/// channel and a dead socket all come back as CHANNEL_FAILURE. And a server
/// that accepts the subsystem but runs nothing behind it — dropbear built
/// with SFTP support, without the sftp-server binary: OpenWrt's default —
/// never answers, which reads as the timeout of a black-holed link. A bare
/// request on a channel of its own keeps each step's code.
///
/// Only a link that just answered falls back to `ls`. The fallback on any
/// failure sent a dead connection's listing through `ls`, whose exec rebuilt
/// the connection and then listed through the fresh one as text — forgeable
/// by a name holding a newline — without asking it for SFTP at all.
fn sftp_start_verdict(probe: SubsystemProbe) -> SftpStartVerdict {
    use ssh2::ErrorCode::Session as Ssh;
    match probe {
        // Refused outright: no SFTP subsystem.
        SubsystemProbe::RequestFailed(Ssh(LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED)) => {
            SftpStartVerdict::Unavailable
        }
        // Accepted on a link that just answered twice, yet the start failed:
        // nothing behind the subsystem speaks SFTP.
        SubsystemProbe::Accepted => SftpStartVerdict::Unavailable,
        // The server's answer on a link that is up: MaxSessions reached.
        SubsystemProbe::OpenFailed(Ssh(LIBSSH2_ERROR_CHANNEL_FAILURE)) => SftpStartVerdict::Refused,
        // A send or a read that failed, a timeout, a disconnect: the link.
        SubsystemProbe::OpenFailed(_) | SubsystemProbe::RequestFailed(_) => {
            SftpStartVerdict::ConnectionLost
        }
    }
}

/// Ask for the SFTP subsystem on a channel of its own, closed again at once.
fn probe_sftp_subsystem(sess: &Session) -> SubsystemProbe {
    let mut channel = match sess.channel_session() {
        Ok(channel) => channel,
        Err(e) => return SubsystemProbe::OpenFailed(e.code()),
    };
    match channel.subsystem("sftp") {
        Ok(()) => SubsystemProbe::Accepted,
        Err(e) => SubsystemProbe::RequestFailed(e.code()),
    }
}

/// An SFTP directory listing: each entry's raw name and attributes.
type RawListing = Vec<(Vec<u8>, ssh2::FileStat)>;

/// One try at an SFTP listing (`SshManager::read_dir_sftp_once`).
enum SftpListing {
    /// The directory listed, and what is in it.
    Listed(String, RawListing),
    /// No SFTP to list with, on a link that is up: `ls -la` it is.
    Unavailable,
    /// The exec connection is gone. `retry`: a rebuild can bring another —
    /// not in minimal mode, where the connection is the shell's.
    ConnectionLost { why: String, retry: bool },
}

/// An exec round trip that produced no output, and how it ended.
#[derive(Debug)]
struct ExecError {
    message: String,
    outcome: ExecOutcome,
}

impl ExecError {
    /// Refused before the connection was touched.
    fn not_run(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            outcome: ExecOutcome::NotRun,
        }
    }

    fn request(what: &str, e: ssh2::Error) -> Self {
        Self {
            outcome: ExecOutcome::RequestFailed(e.code()),
            message: format!("{}: {}", what, e),
        }
    }

    fn read(what: &str, e: std::io::Error) -> Self {
        Self {
            outcome: ExecOutcome::ReadFailed(e.kind()),
            message: format!("{}: {}", what, e),
        }
    }
}

/// Everything left on a channel stream, as text.
///
/// Command output is data: bytes that are not UTF-8 — a GBK file name in
/// `ls -la`, a server without the UTF-8 locale — come through as U+FFFD.
/// `read_to_string` failed the whole command on them instead, which for a
/// keyboard-interactive session also parked monitoring and SFTP.
fn read_output(stream: &mut impl IoRead) -> std::io::Result<String> {
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    Ok(match String::from_utf8(raw) {
        Ok(text) => text,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
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
    /// Serializes exec-connection rebuilds; shared with the reader thread,
    /// whose reconnect replaces the exec session too.
    exec_gate: Arc<Mutex<ExecGate>>,
}

/// Manages multiple concurrent SSH sessions.
pub struct SshManager {
    sessions: RwLock<HashMap<String, SshSession>>,
    event_tx: mpsc::Sender<SshEvent>,
    /// Previous `/proc/stat` sample per session id, for the CPU% delta.
    /// Index 0 is the aggregate `cpu` line, the rest are per-core in kernel
    /// order. Dropped by `disconnect`.
    cpu_samples: RwLock<HashMap<String, Vec<CpuTimes>>>,
    /// The remote host's UTC offset in seconds per session id, for SFTP
    /// listing times (see `server_utc_offset`). Dropped by `disconnect`.
    utc_offsets: RwLock<HashMap<String, i64>>,
    /// The login directory per session id — SFTP's `realpath(".")`, what a
    /// listed path's `~` stands for (see `login_dir`). Dropped by `disconnect`.
    login_dirs: RwLock<HashMap<String, String>>,
}

impl SshManager {
    pub fn new() -> (Self, mpsc::Receiver<SshEvent>) {
        let (event_tx, event_rx) = mpsc::channel();
        (
            SshManager {
                sessions: RwLock::new(HashMap::new()),
                event_tx,
                cpu_samples: RwLock::new(HashMap::new()),
                utc_offsets: RwLock::new(HashMap::new()),
                login_dirs: RwLock::new(HashMap::new()),
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
            "interactive" => {
                userauth_interactive(&session, username, password, host, port, "test", "")
                    .err()
                    .map(|e| e.message)
            }
            "agent" => userauth_agent_identities(&session, username).err(),
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

    /// [`Self::connect_config`] under a session id the caller picked up front
    /// with [`Self::new_session_id`]. The sign-in challenges this connect
    /// raises carry that id ([`AuthChallenge::session_id`]), so a tab closed
    /// while it is still connecting can withdraw them.
    pub fn connect_config_with_id(
        &self,
        session_id: &str,
        config: &crate::storage::ConnectionConfig,
    ) -> Result<String, String> {
        self.check_new_session_id(session_id)?;
        self.connect_as(
            session_id.to_string(),
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

    /// A fresh id for [`Self::connect_config_with_id`].
    pub fn new_session_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Refuse a caller-chosen session id that [`valid_session_id`] rejects or
    /// that a live session already has.
    fn check_new_session_id(&self, session_id: &str) -> Result<(), String> {
        if !valid_session_id(session_id) || self.sessions.read().contains_key(session_id) {
            return Err(i18n::tf("ssh.err.bad_session_id", &[("id", session_id)]));
        }
        Ok(())
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
        self.connect_as(
            Self::new_session_id(),
            connection_id,
            host,
            port,
            username,
            auth_type,
            password,
            private_key,
            passphrase,
            proxy_id,
        )
    }

    /// [`Self::connect`] under `session_id`, which [`valid_session_id`]
    /// accepts.
    #[allow(clippy::too_many_arguments)]
    fn connect_as(
        &self,
        session_id: String,
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
            "interactive" => {
                userauth_interactive(&session, username, password, host, port, "shell", &session_id)
                    .map_err(|e| {
                        translate_ssh_error(&format!("Keyboard-interactive auth failed: {}", e))
                    })?;
            }
            "agent" => {
                userauth_agent_identities(&session, username)
                    .map_err(|e| translate_ssh_error(&format!("SSH agent auth failed: {}", e)))?;
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
        // Where `exec_open_failure_parks` says so, a failure to open it — the
        // dial, the handshake or the sign-in — parks it instead: the shell
        // above is already signed in.
        let mut exec_parked = false;
        let separate_exec_session: Option<Arc<Mutex<Session>>> = if minimal_mode {
            None
        } else {
            let transport = open_exec_transport(&params);
            let opened: Result<Session, (ExecOpenStep, String)> = match transport {
                Err(failed) => Err(failed),
                Ok(sess2) => {
                    let signed_in: Result<(), String> = match auth_type {
                        "password" => {
                            let pw = password.ok_or("Password required")?;
                            sess2.userauth_password(username, pw)
                                .map_err(|e| format!("Exec auth failed: {}", e))
                        }
                        "key" => {
                            let key_str = private_key.ok_or("Private key required")?;
                            let key_path = std::path::Path::new(key_str);
                            match sess2.userauth_pubkey_file(username, None, key_path, passphrase) {
                                Ok(()) => Ok(()),
                                Err(e) => {
                                    userauth_pubkey_in_memory(&sess2, username, key_path, passphrase)
                                        .map_err(|e2| {
                                            format!("Exec key auth failed: {}, retry: {}", e, e2)
                                        })
                                }
                            }
                        }
                        // A 2FA server challenges this second connection separately —
                        // one prompt for the shell, one for monitoring/SFTP. The
                        // stored-password fast path in `GuiPrompter` covers the common
                        // single-factor PAM case without a second modal.
                        "interactive" => {
                            let asked = &session_id;
                            userauth_interactive(&sess2, username, password, host, port, "exec", asked)
                                .map_err(|e| {
                                    i18n::tf("auth.err.exec_interactive", &[("err", &e.to_string())])
                                })
                        }
                        "agent" => userauth_agent_identities(&sess2, username)
                            .map_err(|e| i18n::tf("auth.err.exec_agent", &[("err", &e)])),
                        _ => return Err(format!("Unknown auth type: {}", auth_type)),
                    };
                    signed_in
                        .map(|()| sess2)
                        .map_err(|why| (ExecOpenStep::SignIn, why))
                }
            };

            match opened {
                Ok(sess2) => {
                    // This session is also the SFTP transport, so no
                    // session-wide timeout here: exec_capture_inner bounds its
                    // read, and every SFTP entry point bounds each libssh2
                    // call through `BlockingScope`; both put this 0 back
                    // afterwards.
                    sess2.set_timeout(0);
                    sess2.set_keepalive(true, 15);
                    Some(Arc::new(Mutex::new(sess2)))
                }
                Err((step, why)) if exec_open_failure_parks(auth_type, step) => {
                    log::warn!(
                        "{} — shell kept; monitoring and SFTP parked until the user resumes them",
                        why
                    );
                    exec_parked = true;
                    // The half-open connection, if there was one, is gone
                    // already; the slot keeps an unconnected placeholder that
                    // nothing touches while parked, and `resume_exec` replaces.
                    let placeholder = Session::new()
                        .map_err(|e| format!("Failed to create exec session: {}", e))?;
                    Some(Arc::new(Mutex::new(placeholder)))
                }
                Err((_, why)) => return Err(why),
            }
        };

        // --- Detect session persistence capability --------------------------
        // Minimal mode: always RawShell, no probing at all.
        let session_name = format!("neo-{}", &session_id[..8]);
        let mode = if minimal_mode || exec_parked {
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
        let exec_gate = Arc::new(Mutex::new(ExecGate {
            parked: exec_parked,
            ..ExecGate::default()
        }));
        let reader_gate = Arc::clone(&exec_gate);

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

                    match reconnect_ssh(&reader_params, &reader_mode, reader_minimal, &sid_reader) {
                        Err(e) => match after_failed_reconnect(&e) {
                            RetryVerdict::GiveUp(why) => {
                                log::error!("reconnect aborted: {}", e);
                                // Closed under us while the attempt ran:
                                // disconnect() already told the UI.
                                if reader_stop.load(Ordering::Relaxed) {
                                    break 'outer;
                                }
                                let _ = event_tx.send(SshEvent::Error {
                                    session_id: sid_reader.clone(),
                                    error: why,
                                });
                                let _ = event_tx.send(SshEvent::Closed {
                                    session_id: sid_reader.clone(),
                                });
                                break 'outer;
                            }
                            // e.g. the vault re-locked under a proxied session:
                            // that fails closed without dialling, and a later
                            // attempt succeeds once the user unlocks.
                            RetryVerdict::Retry => {
                                log::warn!("reconnect attempt {} failed: {}", retry, e);
                                continue; // next retry
                            }
                        },
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
                            // Replace exec session for monitoring/SFTP (only if we
                            // have one). Keyboard-interactive brings none (see
                            // `reconnect_reopens_exec`): its exec connection is
                            // left as it was — alive, or parked until the user
                            // resumes it.
                            if let (Some(slot), Some(fresh)) = (reader_exec.as_ref(), new_exec) {
                                *slot.lock() = fresh;
                                reader_gate.lock().exec_restored(std::time::Instant::now());
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
        {
            let mut sessions = self.sessions.write();
            // Only a caller reusing an id it passed to `connect_config_with_id`
            // gets here; replacing the entry would orphan a live session.
            if sessions.contains_key(&session_id) {
                stop.store(true, Ordering::SeqCst);
                let _ = cmd_tx.try_send(SshCommand::Disconnect);
                return Err(i18n::tf("ssh.err.bad_session_id", &[("id", &session_id)]));
            }
            sessions.insert(
                session_id.clone(),
                SshSession {
                    session_id: session_id.clone(),
                    connection_id,
                    writer: cmd_tx,
                    exec_session,
                    params,
                    mode,
                    minimal_mode,
                    stop,
                    host_key_fp,
                    exec_gate,
                },
            );
        }

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
        // A stale /proc/stat sample would make the first poll of a *new*
        // session that reuses this id read as a huge negative delta.
        self.cpu_samples.write().remove(session_id);
        self.utc_offsets.write().remove(session_id);
        // After `stop` went up: `login_dir` checks it under this same lock.
        self.login_dirs.write().remove(session_id);
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
    /// Auto-reconnects the exec session when its connection is gone and retries
    /// once.
    pub fn exec_command(&self, session_id: &str, command: &str) -> Result<String, String> {
        self.exec_capture(session_id, command)
            .map(|(stdout, _stderr, _status)| stdout)
    }

    /// Like [`Self::exec_command`], but also returns stderr and the remote exit
    /// status. Needed by anything that must tell "the command ran and said no"
    /// from "the command produced no output" — `kill` being the first case.
    fn exec_capture(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<(String, String, i32), String> {
        match self.exec_capture_inner(session_id, command) {
            Ok(v) => Ok(v),
            // Only a dead connection is worth a new one: a refusal or a bad
            // read would say the same again on a fresh connection.
            Err(first) if exec_connection_failed(first.outcome) => {
                log::warn!("exec on session {} failed: {}", session_id, first.message);
                // Exec session may be dead — try to rebuild it
                self.rebuild_exec_session(session_id)?;
                // Retry once with the new session
                self.exec_capture_inner(session_id, command)
                    .map_err(|e| e.message)
            }
            Err(first) => {
                log::warn!("exec on session {} failed: {}", session_id, first.message);
                Err(first.message)
            }
        }
    }

    fn exec_capture_inner(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<(String, String, i32), ExecError> {
        let (exec_session, minimal, gate, auth_type) = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| ExecError::not_run(format!("Session '{}' not found", session_id)))?;
            let es = match &s.exec_session {
                Some(es) => es.clone(),
                None => return Err(ExecError::not_run("exec not supported on this server")),
            };
            (
                es,
                s.minimal_mode,
                Arc::clone(&s.exec_gate),
                s.params.auth_type.clone(),
            )
        };

        // A parked exec connection stays dead until the user reconnects: fail
        // fast instead of queueing on its lock and then waiting on its socket.
        // Asked again once the lock is held — the call ahead may have parked it.
        let parked = || gate.lock().parked;
        if parked() {
            return Err(ExecError::not_run(i18n::t("exec.err.needs_reconnect")));
        }
        let sess = exec_session.lock();
        if parked() {
            return Err(ExecError::not_run(i18n::t("exec.err.needs_reconnect")));
        }
        // When exec shares the main session (minimal mode), we must restore
        // non-blocking mode afterwards so the shell reader keeps receiving
        // WouldBlock on empty reads. For a separate session, this still works.
        sess.set_blocking(true);
        // Bound every blocking libssh2 call for the duration of this exec.
        // Without it `read_output` below can block forever while holding
        // both this mutex and — in minimal mode, where exec shares the main
        // session — the terminal reader's lock. The previous value is restored
        // afterwards; SFTP calls apply their own bound (`BlockingScope`).
        let prev_timeout = sess.timeout();
        sess.set_timeout(30_000);

        // Use a closure so blocking mode is restored even on error paths.
        let result = (|| -> Result<(String, String, i32), ExecError> {
            // For minimal servers, skip the setenv-style locale prefix — some
            // embedded devices don't implement `export` or `2>/dev/null`.
            let utf8_cmd = if minimal {
                command.to_string()
            } else {
                format!("export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 2>/dev/null; {}", command)
            };

            let mut channel = sess
                .channel_session()
                .map_err(|e| ExecError::request("Failed to open exec channel", e))?;
            channel
                .exec(&utf8_cmd)
                .map_err(|e| ExecError::request("Failed to exec command", e))?;

            let output = read_output(&mut channel)
                .map_err(|e| ExecError::read("Failed to read command output", e))?;
            // Read stderr after stdout: libssh2 buffers both substreams, and
            // every caller here produces output far below the window size.
            let errors = read_output(&mut channel.stderr()).unwrap_or_default();
            let _ = channel.wait_close();
            // -1 when the server never reported one; callers that care treat
            // any non-zero as failure, which is the right reading either way.
            let status = channel.exit_status().unwrap_or(-1);
            Ok((output, errors, status))
        })();

        // Before the lock is released (see `ExecGate::exec_failed`), and only
        // for a connection that is actually gone. Minimal mode is exempt: its
        // exec session is the shell's, which reconnects on its own.
        let outcome = match &result {
            Ok((_, _, status)) => ExecOutcome::Exited(*status),
            Err(e) => e.outcome,
        };
        if exec_connection_failed(outcome) && !minimal {
            gate.lock().exec_failed(&auth_type);
        }

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
            // Parked: dead until the user reconnects (see `ExecGate`). The
            // probe below would otherwise wait on its socket for up to
            // SFTP_TIMEOUT_MS before saying the same thing.
            if s.exec_gate.lock().parked {
                return Err(i18n::t("exec.err.needs_reconnect").into());
            }
            match &s.exec_session {
                Some(es) => es.clone(),
                None => return Err("exec not supported on this server (minimal SSH mode)".into()),
            }
        };

        // Quick health check: open a throwaway channel (fails if TCP is dead),
        // bounded like the start of SFTP so that a black-holed link reaches the
        // rebuild below quickly. Scoped like every SFTP call — in minimal mode
        // this is the shell's own session, which must be non-blocking again
        // afterwards.
        {
            let sess = exec_session.lock();
            let blocking = BlockingScope::enter(&*sess, SFTP_INIT_TIMEOUT_MS);
            // A `let`, so the probe channel is freed while still blocking.
            let alive = sess.channel_session().is_ok();
            drop(blocking);
            if !alive {
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
    ///
    /// At most one rebuild per session runs at a time, a failed one is not
    /// retried within `EXEC_REBUILD_COOLDOWN`, and a keyboard-interactive
    /// session is never rebuilt at all — that would be a new challenge the
    /// user did not ask for. See [`ExecGate`].
    fn rebuild_exec_session(&self, session_id: &str) -> Result<(), String> {
        let (params, has_slot, minimal, gate) = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            (
                s.params.clone(),
                s.exec_session.is_some(),
                s.minimal_mode,
                Arc::clone(&s.exec_gate),
            )
        };

        if !has_slot {
            return Err("no exec_session slot to rebuild".into());
        }
        if minimal {
            // exec_session is the main session; main session reconnects in its
            // own reader thread. Nothing to do here.
            return Ok(());
        }

        let decision = gate
            .lock()
            .begin(&params.auth_type, std::time::Instant::now());
        match decision {
            RebuildDecision::Dial => {}
            RebuildDecision::Fresh => return Ok(()),
            RebuildDecision::InFlight => return Err(i18n::t("exec.err.rebuilding").into()),
            RebuildDecision::CoolingDown(left) => {
                let secs = left.as_secs().max(1).to_string();
                return Err(i18n::tf("exec.err.cooldown", &[("secs", &secs)]));
            }
            RebuildDecision::Parked => return Err(i18n::t("exec.err.needs_reconnect").into()),
        }
        let mut claim = RebuildClaim {
            gate: &gate,
            ok: false,
        };

        let new_exec = create_exec_connection(&params, session_id)?;

        // Replace the exec session in-place
        let sessions = self.sessions.read();
        if let Some(ssh_session) = sessions.get(session_id) {
            if let Some(slot) = &ssh_session.exec_session {
                let mut old = slot.lock();
                *old = new_exec;
            }
        }
        claim.ok = true;
        Ok(())
    }

    /// Re-open a parked exec connection: the UI's deliberate "Reconnect
    /// monitoring". For keyboard-interactive that costs exactly one sign-in
    /// challenge, and it is the only way monitoring and SFTP come back once
    /// parked — neither a monitor tick nor a reconnect of the shell re-dials
    /// it (see [`ExecGate`], `reconnect_reopens_exec`).
    ///
    /// A no-op while nothing is parked, and refused while another rebuild
    /// runs. A failed or dismissed challenge leaves the connection parked, and
    /// the user may try again at once.
    pub fn resume_exec(&self, session_id: &str) -> Result<(), String> {
        let (params, slot, minimal, gate) = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            (
                s.params.clone(),
                s.exec_session.clone(),
                s.minimal_mode,
                Arc::clone(&s.exec_gate),
            )
        };
        // Minimal mode shares the shell's session, which reconnects itself.
        let Some(slot) = slot.filter(|_| !minimal) else {
            return Ok(());
        };
        let decision = gate.lock().begin_resume();
        match decision {
            ResumeDecision::Dial => {}
            ResumeDecision::NotParked => return Ok(()),
            ResumeDecision::InFlight => return Err(i18n::t("exec.err.rebuilding").into()),
        }
        let mut claim = RebuildClaim {
            gate: &gate,
            ok: false,
        };
        let fresh =
            create_exec_connection(&params, session_id).map_err(|e| translate_ssh_error(&e))?;
        *slot.lock() = fresh;
        gate.lock().exec_restored(std::time::Instant::now());
        claim.ok = true;
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
                   uptime -p 2>/dev/null || uptime; echo '---SEPARATOR---'; \
                   cat /proc/stat 2>/dev/null";
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
                } else if line.starts_with("Swap:") {
                    // Same output `free -m` already returned for Mem — the
                    // swap numbers were simply being thrown away.
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        stats.swap_total_mb = parts[1].parse().unwrap_or(0);
                        stats.swap_used_mb = parts[2].parse().unwrap_or(0);
                        if stats.swap_total_mb > 0 {
                            stats.swap_percent =
                                (stats.swap_used_mb as f64 / stats.swap_total_mb as f64) * 100.0;
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

        // Parse /proc/stat — CPU% is a delta, so it needs two samples. The
        // first poll of a session compares against an all-zero baseline, which
        // yields the average since boot (exactly what `top` shows on its first
        // screen) instead of a misleading flat 0%.
        if let Some(stat_output) = sections.get(6) {
            let current = parse_proc_stat(stat_output);
            if !current.is_empty() {
                let previous = self
                    .cpu_samples
                    .read()
                    .get(session_id)
                    .cloned()
                    .unwrap_or_default();
                stats.cpu_percent = cpu_percent_from(
                    previous.first().copied().unwrap_or_default(),
                    current[0],
                );
                stats.cpu_per_core = current
                    .iter()
                    .enumerate()
                    .skip(1)
                    .map(|(i, cur)| {
                        cpu_percent_from(previous.get(i).copied().unwrap_or_default(), *cur)
                    })
                    .collect();
                self.cpu_samples
                    .write()
                    .insert(session_id.to_string(), current);
            }
        }

        Ok(stats)
    }

    /// List the sockets the remote host is listening on.
    ///
    /// `ss` is the modern tool; `netstat` covers older and minimal images.
    /// Both print the owning process only for sockets the login user is allowed
    /// to inspect, so a missing pid is the normal unprivileged result rather
    /// than an error.
    pub fn fetch_listening_ports(&self, session_id: &str) -> Result<Vec<PortInfo>, String> {
        let cmd = "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null \
                   || netstat -tuln 2>/dev/null";
        let output = self.exec_command(session_id, cmd)?;
        Ok(parse_listening_ports(&output))
    }

    /// Send `signal` to `pid` on the remote host.
    ///
    /// `app.rs` gates this behind a confirmation modal; this end refuses
    /// anything outside four signals, refuses pid 0 (which means "my whole
    /// process group" to `kill`) and pid 1 (init — killing it panics the
    /// machine). The remote's stderr is returned verbatim on a non-zero exit so
    /// "Operation not permitted" reaches the user instead of a silent no-op.
    pub fn kill_process(&self, session_id: &str, pid: u32, signal: i32) -> Result<(), String> {
        let name = validate_kill(pid, signal)?;
        // `pid` is a u32 and `name` comes from the table above, so no part of
        // this command line is attacker-controlled text.
        let cmd = format!("kill -{} {}", name, pid);
        let (_out, err, status) = self.exec_capture(session_id, &cmd)?;
        if status != 0 {
            let detail = err.trim();
            let pid = pid.to_string();
            return Err(if detail.is_empty() {
                i18n::tf(
                    "process.err.kill_exit",
                    &[("signal", name), ("pid", &pid), ("status", &status.to_string())],
                )
            } else {
                i18n::tf(
                    "process.err.kill",
                    &[("signal", name), ("pid", &pid), ("detail", detail)],
                )
            });
        }
        Ok(())
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

    /// List a directory for the file browser: its absolute path and entries.
    ///
    /// Over SFTP where the server has it: every name exactly as the server
    /// stores it, every type from the entry's own attributes (`lstat`'s — a
    /// symlink is a symlink), and no text re-parsed. `ls -la` split on
    /// whitespace had collapsed "a  b" to "a b" and lost the space of
    /// "project ", so a rename, chmod or delete of one row could land on
    /// another entry. A server with no SFTP to list with, on a link that is
    /// up, is still listed with `ls -la`, each name the verbatim rest of its
    /// line ([`parse_ls_line`]) and every row unverified
    /// ([`FileEntry::verified`]).
    ///
    /// Otherwise as before: `path` is taken the way `cd '<path>'` took it —
    /// under the login directory unless absolute — except that `~` and `~/…`
    /// are the login directory ([`resolve_listing_dir`]). The path returned
    /// is what `pwd` would print, and a directory that cannot be opened lists
    /// as empty under `path` as given.
    pub fn list_files(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<(String, Vec<FileEntry>), String> {
        let (dir, raw) = match self.read_dir_sftp(session_id, path)? {
            Some(listing) => listing,
            None => return self.list_files_ls(session_id, path),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let offset = if raw.is_empty() {
            0
        } else {
            self.server_utc_offset(session_id)
        };
        let mut entries: Vec<FileEntry> = raw
            .iter()
            .filter_map(|(name, stat)| sftp_file_entry(name, stat, now, offset))
            .collect();
        sort_listing(&mut entries);
        Ok((dir, entries))
    }

    /// The SFTP listing behind [`Self::list_files`]: the directory and each
    /// entry's raw name and attributes. `None` when the server has no SFTP to
    /// list with on a link that is up ([`sftp_start_verdict`]) — the one case
    /// for `ls -la`.
    ///
    /// A dead exec connection is rebuilt — parked, for keyboard-interactive —
    /// and asked once more, as a failed exec is (`exec_capture`). It used to
    /// fall back to `ls`, whose exec rebuilt the connection and then listed
    /// through the fresh one as text, without asking it for SFTP at all.
    fn read_dir_sftp(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<Option<(String, RawListing)>, String> {
        match self.read_dir_sftp_once(session_id, path)? {
            SftpListing::Listed(dir, raw) => return Ok(Some((dir, raw))),
            SftpListing::Unavailable => return Ok(None),
            SftpListing::ConnectionLost { why, retry } => {
                log::warn!("SFTP on session {} failed: {}", session_id, why);
                // Minimal mode: the connection is the shell's, which
                // reconnects on its own; another try now would only wait out
                // the same dead link again, with the terminal held.
                if !retry {
                    return Err(i18n::tf("sftp.err.start", &[("err", &why)]));
                }
            }
        }
        self.rebuild_exec_session(session_id)?;
        match self.read_dir_sftp_once(session_id, path)? {
            SftpListing::Listed(dir, raw) => Ok(Some((dir, raw))),
            SftpListing::Unavailable => Ok(None),
            SftpListing::ConnectionLost { why, .. } => {
                Err(i18n::tf("sftp.err.start", &[("err", &why)]))
            }
        }
    }

    /// One try at [`Self::read_dir_sftp`], on the exec connection as it is.
    fn read_dir_sftp_once(&self, session_id: &str, path: &str) -> Result<SftpListing, String> {
        let (exec_session, gate, auth_type, minimal, stop) = {
            let sessions = self.sessions.read();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| format!("Session '{}' not found", session_id))?;
            match &s.exec_session {
                Some(es) => (
                    es.clone(),
                    Arc::clone(&s.exec_gate),
                    s.params.auth_type.clone(),
                    s.minimal_mode,
                    Arc::clone(&s.stop),
                ),
                // `ls` says why, as it always did.
                None => return Ok(SftpListing::Unavailable),
            }
        };
        // Like `exec_capture_inner`: fail fast while parked, and no probe of
        // the connection first — a dead one fails to start SFTP here, within
        // SFTP_INIT_TIMEOUT_MS.
        let parked = || gate.lock().parked;
        if parked() {
            return Err(i18n::t("exec.err.needs_reconnect").into());
        }
        let sess = exec_session.lock();
        if parked() {
            return Err(i18n::t("exec.err.needs_reconnect").into());
        }
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);
        let sftp = match start_sftp(&sess) {
            Ok(sftp) => sftp,
            Err(e) => {
                let probe = bounded(&*sess, SFTP_PROBE_TIMEOUT_MS, probe_sftp_subsystem);
                return match sftp_start_verdict(probe) {
                    SftpStartVerdict::Unavailable => {
                        log::info!(
                            "no SFTP on session {} ({}; {:?}): listing with ls -la",
                            session_id,
                            e,
                            probe
                        );
                        Ok(SftpListing::Unavailable)
                    }
                    SftpStartVerdict::Refused => {
                        Err(i18n::tf("sftp.err.start", &[("err", &e.to_string())]))
                    }
                    SftpStartVerdict::ConnectionLost => {
                        // Before the lock goes (see `ExecGate::exec_failed`),
                        // and not in minimal mode, as in `exec_capture_inner`.
                        if !minimal {
                            gate.lock().exec_failed(&auth_type);
                        }
                        Ok(SftpListing::ConnectionLost {
                            why: e.to_string(),
                            retry: !minimal,
                        })
                    }
                };
            }
        };
        // What `cd` refusing did: an empty listing under the path as given.
        let unopened = || Ok(SftpListing::Listed(path.to_string(), Vec::new()));
        let home = || self.login_dir(session_id, &sftp, &stop);
        let Some(dir) = resolve_listing_dir(path, home) else {
            return unopened();
        };
        let mut handle = match sftp.opendir(sftp_sendable(&dir)?) {
            Ok(handle) => handle,
            Err(e) => {
                log::info!("cannot list {:?} on session {}: {}", dir, session_id, e);
                return unopened();
            }
        };
        // `opendir` + `readdir` by hand, as in `entry_names`: `Sftp::readdir`
        // joins each name onto the directory and drops "..".
        let mut raw = Vec::new();
        loop {
            match handle.readdir() {
                Ok((name, stat)) => raw.push((listed_name_bytes(&name), stat)),
                Err(e) if e.code() == ssh2::ErrorCode::Session(LIBSSH2_ERROR_FILE) => break,
                Err(e) if e.code() == ssh2::ErrorCode::Session(LIBSSH2_ERROR_EAGAIN) => {}
                Err(e) => {
                    return Err(i18n::tf(
                        "sftp.err.list",
                        &[("path", &dir), ("err", &e.to_string())],
                    ))
                }
            }
        }
        Ok(SftpListing::Listed(dir, raw))
    }

    /// The session's login directory — where SFTP starts, `realpath(".")` —
    /// asked once per session. `None` when the server does not say, or says
    /// it in bytes that are not UTF-8.
    fn login_dir(&self, session_id: &str, sftp: &ssh2::Sftp, stop: &AtomicBool) -> Option<String> {
        if let Some(home) = self.login_dirs.read().get(session_id) {
            return Some(home.clone());
        }
        let home = sftp
            .realpath(std::path::Path::new("."))
            .ok()?
            .to_str()?
            .to_string();
        // Not for a session closed meanwhile: `disconnect` raises `stop`
        // before it takes this lock to drop the entry.
        let mut dirs = self.login_dirs.write();
        if !stop.load(Ordering::SeqCst) {
            dirs.insert(session_id.to_string(), home.clone());
        }
        Some(home)
    }

    /// [`Self::list_files`] for a server with no SFTP to list with: `ls -la`,
    /// each name the verbatim rest of its line and every row unverified
    /// ([`parse_ls_line`]), and nothing trimmed off the `pwd` line — a
    /// directory can end in a space.
    fn list_files_ls(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<(String, Vec<FileEntry>), String> {
        // Get canonical path + listing
        let cmd = format!("cd {} && pwd && ls -la", ls_cd_arg(path));
        let output = self.exec_command(session_id, &cmd)?;

        let mut lines = output.lines();
        let current_dir = lines.next().unwrap_or(path).to_string();
        Ok((current_dir, lines.filter_map(parse_ls_line).collect()))
    }

    /// The remote host's offset from UTC in seconds, for printing listing
    /// times the way its own `ls -la` did (see [`ls_time`]). Asked once per
    /// session with `date +%z`; UTC when the host gives no usable answer.
    ///
    /// Stdin comes from /dev/null: `date` with an argument under cmd.exe (a
    /// Windows host without the `export` prefix, see `exec_capture_inner`)
    /// would prompt for a new date and hold every listing for the exec read
    /// bound; the redirect makes cmd.exe fail at once instead.
    fn server_utc_offset(&self, session_id: &str) -> i64 {
        if let Some(offset) = self.utc_offsets.read().get(session_id) {
            return *offset;
        }
        match self.exec_command(session_id, "date +%z </dev/null") {
            Ok(out) => {
                let offset = parse_utc_offset(&out).unwrap_or(0);
                // Not for a session closed meanwhile: `disconnect` cleared it.
                if self.sessions.read().contains_key(session_id) {
                    self.utc_offsets.write().insert(session_id.to_string(), offset);
                }
                offset
            }
            // A dead or parked connection says nothing about the host: ask
            // again next time.
            Err(_) => 0,
        }
    }

    /// Run `f` with the SFTP subsystem open on this session's exec connection.
    ///
    /// A closure rather than a returned handle because the session mutex has to
    /// stay locked for the whole operation — it is what serialises SFTP against
    /// `exec_command` on the same connection — and a guard cannot be returned
    /// alongside the value borrowed from it.
    fn with_sftp<T>(
        &self,
        session_id: &str,
        f: impl FnOnce(&ssh2::Sftp) -> Result<T, String>,
    ) -> Result<T, String> {
        let exec_session = self.get_exec_session(session_id)?;
        let sess = exec_session.lock();
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);
        let sftp = start_sftp(&sess).map_err(|e| format!("SFTP init failed: {}", e))?;
        f(&sftp)
    }

    /// Create a remote directory (mode 0755).
    pub fn sftp_mkdir(&self, session_id: &str, path: &str) -> Result<(), String> {
        let path = validate_remote_path(path)?;
        self.with_sftp(session_id, |sftp| {
            sftp.mkdir(std::path::Path::new(&path), 0o755).map_err(|e| {
                i18n::tf("sftp.err.mkdir", &[("path", &path), ("err", &e.to_string())])
            })
        })
    }

    /// Delete the remote entry the user confirmed — its row, `confirmed`
    /// ([`ConfirmedEntry`]) — and, only when the row showed a directory,
    /// everything under it.
    ///
    /// A row whose listing was not verified ([`FileEntry::verified`]) is
    /// refused before anything is touched, and the row's name goes out as the
    /// server spelled it, not as it was shown ([`entry_path`]).
    ///
    /// `lstat` comes first, and an entry that is no longer that kind is
    /// refused as changed since it was listed, with nothing deleted: a
    /// co-tenant's 0-byte "project " beside a user's directory "project" used
    /// to read "project" in the listing, and a confirmed "Delete this file?"
    /// deleted the directory. A symlink is unlinked, never followed — one to
    /// a directory included. The recursion walks with `lstat` as well and
    /// checks the whole tree before the first delete — see
    /// [`sftp_remove_recursive`].
    pub fn sftp_remove_confirmed(
        &self,
        session_id: &str,
        path: &str,
        confirmed: impl Into<ConfirmedEntry>,
    ) -> Result<(), String> {
        self.sftp_remove_as(session_id, path, Some(confirmed.into()))
    }

    /// Transitional, until every caller says what the user confirmed (use
    /// [`Self::sftp_remove_confirmed`]): never recursive — a directory goes
    /// only when it is empty.
    pub fn sftp_remove(&self, session_id: &str, path: &str) -> Result<(), String> {
        self.sftp_remove_as(session_id, path, None)
    }

    fn sftp_remove_as(
        &self,
        session_id: &str,
        path: &str,
        confirmed: Option<ConfirmedEntry>,
    ) -> Result<(), String> {
        let path = validate_remote_path(path)?;
        let target = confirmed_target(&path, confirmed.as_ref())?;
        let kind = confirmed.map(|c| c.kind);
        self.with_sftp(session_id, |sftp| remove_confirmed(sftp, &target, kind))
    }

    /// Rename or move the remote entry the user confirmed; refused, as
    /// [`Self::sftp_remove_confirmed`] is, for a row whose listing was not
    /// verified and when `from` is no longer the kind the row showed.
    pub fn sftp_rename_confirmed(
        &self,
        session_id: &str,
        from: &str,
        to: &str,
        confirmed: impl Into<ConfirmedEntry>,
    ) -> Result<(), String> {
        self.sftp_rename_as(session_id, from, to, Some(confirmed.into()))
    }

    /// Transitional (use [`Self::sftp_rename_confirmed`]): no type check.
    pub fn sftp_rename(&self, session_id: &str, from: &str, to: &str) -> Result<(), String> {
        self.sftp_rename_as(session_id, from, to, None)
    }

    fn sftp_rename_as(
        &self,
        session_id: &str,
        from: &str,
        to: &str,
        confirmed: Option<ConfirmedEntry>,
    ) -> Result<(), String> {
        let from = validate_remote_path(from)?;
        let to = validate_remote_path(to)?;
        let source = confirmed_target(&from, confirmed.as_ref())?;
        if source == to.as_bytes() {
            return Ok(());
        }
        let kind = confirmed.map(|c| c.kind);
        self.with_sftp(session_id, |sftp| {
            if kind.is_some() {
                let actual = sftp.kind_nofollow(&source)?;
                check_unchanged(kind, actual, &from)?;
            }
            // Deliberately WITHOUT RenameFlags::OVERWRITE, which is part of
            // ssh2's default: renaming onto an existing name would destroy it
            // silently and the file browser has no undo. ATOMIC | NATIVE keeps
            // the server-side rename atomic where the server supports it.
            sftp.rename(
                &sftp_path(&source)?,
                std::path::Path::new(&to),
                Some(ssh2::RenameFlags::ATOMIC | ssh2::RenameFlags::NATIVE),
            )
            .map_err(|e| {
                i18n::tf(
                    "sftp.err.rename",
                    &[("from", &from), ("to", &to), ("err", &e.to_string())],
                )
            })
        })
    }

    /// Change the permission bits of the remote entry the user confirmed;
    /// refused, as [`Self::sftp_remove_confirmed`] is, for a row whose listing
    /// was not verified and when it is no longer the kind the row showed — and
    /// for a symlink, whose target SFTP would change instead (see
    /// [`check_chmod`]).
    pub fn sftp_chmod_confirmed(
        &self,
        session_id: &str,
        path: &str,
        mode: u32,
        confirmed: impl Into<ConfirmedEntry>,
    ) -> Result<(), String> {
        self.sftp_chmod_as(session_id, path, mode, Some(confirmed.into()))
    }

    /// Transitional (use [`Self::sftp_chmod_confirmed`]): no type check, but a
    /// symlink is still refused.
    pub fn sftp_chmod(&self, session_id: &str, path: &str, mode: u32) -> Result<(), String> {
        self.sftp_chmod_as(session_id, path, mode, None)
    }

    fn sftp_chmod_as(
        &self,
        session_id: &str,
        path: &str,
        mode: u32,
        confirmed: Option<ConfirmedEntry>,
    ) -> Result<(), String> {
        let path = validate_remote_path(path)?;
        // Only the 12 permission bits (setuid / setgid / sticky + rwxrwxrwx).
        // Anything above them belongs to the file-type field, and writing that
        // back would ask the server to change what kind of file this is.
        if mode & !0o7777 != 0 {
            return Err(i18n::tf("sftp.err.bad_mode", &[("mode", &format!("{:#o}", mode))]));
        }
        let target = confirmed_target(&path, confirmed.as_ref())?;
        let kind = confirmed.map(|c| c.kind);
        self.with_sftp(session_id, |sftp| {
            let actual = sftp.kind_nofollow(&target)?;
            check_chmod(kind, actual, &path)?;
            // Every other field left None so only ATTR_PERMISSIONS goes on the
            // wire — a FileStat carrying Some(size) would truncate the file.
            sftp.setstat(
                &sftp_path(&target)?,
                ssh2::FileStat {
                    size: None,
                    uid: None,
                    gid: None,
                    perm: Some(mode),
                    atime: None,
                    mtime: None,
                },
            )
            .map_err(|e| {
                i18n::tf(
                    "sftp.err.chmod",
                    &[("path", &path), ("mode", &format!("{:o}", mode)), ("err", &e.to_string())],
                )
            })
        })
    }

    /// Download a remote file to a local path using SFTP.
    pub fn download_file(&self, session_id: &str, remote_path: &str, local_path: &str) -> Result<(), String> {
        let exec_session = self.get_exec_session(session_id)?;
        let sess = exec_session.lock();
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);

        let sftp = start_sftp(&sess)
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
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);

        let contents = std::fs::read(local_path)
            .map_err(|e| format!("Failed to read local file '{}': {}", local_path, e))?;

        let sftp = start_sftp(&sess)
            .map_err(|e| format!("SFTP init failed: {}", e))?;

        let mut remote_file = sftp.create(std::path::Path::new(remote_path))
            .map_err(|e| format!("Failed to create remote file '{}': {}", remote_path, e))?;

        remote_file.write_all(&contents)
            .map_err(|e| format!("Failed to write remote file: {}", e))?;

        Ok(())
    }

    /// Upload a local file with progress reporting and resume support.
    ///
    /// Resumes only onto a remote file whose bytes are proven identical to the
    /// start of the local one (see [`plan_resume`]); anything else is
    /// overwritten.
    pub fn upload_file_with_progress(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        progress: Arc<TransferProgress>,
    ) -> Result<(), String> {
        bail_if_cancelled(&progress)?;
        sftp_sendable(remote_path)?;
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

        let sess = exec_session.lock();
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);
        let sftp = start_sftp(&sess).map_err(|e| format!("SFTP init failed: {}", e))?;

        // Record transfer start time for speed calculation
        *progress.start_time.lock() = Some(std::time::Instant::now());

        upload_one_file(
            &sftp,
            std::path::Path::new(local_path),
            remote_path,
            &progress,
            0,
            ResumeMode::IfPrefixMatches,
        )?;

        progress.finished.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Upload a whole local directory tree, with one aggregate progress bar.
    ///
    /// `remote_dir` is the destination directory *itself*, not its parent: it
    /// is created if missing, and `local_dir`'s children land directly inside
    /// it. Walks the local tree up front so `TransferProgress.total` is the
    /// real byte count of the whole transfer rather than of whichever file
    /// happens to be in flight, then reuses the same per-file path as the
    /// single-file upload — but never resumes: every file is written whole
    /// (see [`ResumeMode::Never`]).
    ///
    /// Follow-up, deliberately not done here: piping a `tar` through an exec
    /// channel would beat SFTP's per-file round trips on a deep tree, but it
    /// needs a BusyBox-tar fallback and careful shell-quoting of every remote
    /// path — a separate change with its own risk.
    pub fn upload_dir_with_progress(
        &self,
        session_id: &str,
        local_dir: &str,
        remote_dir: &str,
        progress: Arc<TransferProgress>,
    ) -> Result<(), String> {
        bail_if_cancelled(&progress)?;
        let remote_root = validate_remote_path(remote_dir)?;
        let local_root = std::path::Path::new(local_dir);
        if !local_root.is_dir() {
            return Err(i18n::tf("transfer.err.not_dir", &[("path", local_dir)]));
        }
        let exec_session = self.get_exec_session(session_id)?;

        let mut dirs: Vec<Vec<String>> = Vec::new();
        let mut files: Vec<TreeItem> = Vec::new();
        collect_local_tree(local_root, &mut Vec::new(), 0, &mut dirs, &mut files)?;
        let total: u64 = files.iter().map(|f| f.size).sum();

        *progress.filename.lock() = local_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(local_dir)
            .to_string();
        progress.total.store(total, Ordering::Relaxed);
        progress.transferred.store(0, Ordering::Relaxed);
        *progress.start_time.lock() = Some(std::time::Instant::now());

        let sess = exec_session.lock();
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);
        let sftp = start_sftp(&sess).map_err(|e| format!("SFTP init failed: {}", e))?;

        // The walk above can take a while; nothing remote exists yet.
        bail_if_cancelled(&progress)?;
        // Root first, then every subdirectory in walk order (parents first).
        mkdir_if_missing(&sftp, &remote_root)?;
        for d in &dirs {
            mkdir_if_missing(&sftp, &join_remote_all(&remote_root, d))?;
        }

        let mut done = 0u64;
        for f in &files {
            bail_if_cancelled(&progress)?;
            *progress.filename.lock() = f.rel.join("/");
            let remote_path = join_remote_all(&remote_root, &f.rel);
            done += upload_one_file(
                &sftp,
                &f.local,
                &remote_path,
                &progress,
                done,
                ResumeMode::Never,
            )?;
        }

        // A file that grew between the walk and its turn would otherwise leave
        // the bar reading over 100%.
        if done > total {
            progress.total.store(done, Ordering::Relaxed);
        }
        progress.transferred.store(done, Ordering::Relaxed);
        progress.finished.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Download a remote file with progress reporting and resume support.
    ///
    /// Resumes only onto a local file whose bytes are proven identical to the
    /// start of the remote one (see [`plan_resume`]); anything else is
    /// overwritten.
    pub fn download_file_with_progress(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        progress: Arc<TransferProgress>,
    ) -> Result<(), String> {
        bail_if_cancelled(&progress)?;
        let rp = sftp_sendable(remote_path)?;
        let exec_session = self.get_exec_session(session_id)?;

        let sess = exec_session.lock();
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);
        let sftp = start_sftp(&sess).map_err(|e| format!("SFTP init failed: {}", e))?;

        // Get remote file size
        let file_stat = sftp.stat(rp).map_err(|e| {
            i18n::tf("sftp.err.stat", &[("path", remote_path), ("err", &e.to_string())])
        })?;
        let total_size = file_stat.size.unwrap_or(0);

        // Setup progress
        let filename = std::path::Path::new(remote_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        *progress.filename.lock() = filename;
        progress.total.store(total_size, Ordering::Relaxed);

        // Record transfer start time for speed calculation
        *progress.start_time.lock() = Some(std::time::Instant::now());

        download_one_file(
            &sftp,
            remote_path,
            std::path::Path::new(local_path),
            &progress,
            0,
            ResumeMode::IfPrefixMatches,
        )?;

        progress.finished.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Download a whole remote directory tree, with one aggregate progress bar.
    ///
    /// `local_dir` is the destination directory *itself*, not its parent, and
    /// is created if missing. `sftp.readdir` drives the walk depth-first, and
    /// every name it returns is run through [`safe_path_component`] before it
    /// touches the local disk: a malicious server can answer with `..` or an
    /// absolute path, which would otherwise let it choose where the download
    /// lands. Like the upload, it never resumes: every file is written whole.
    ///
    /// Same tar-pipe follow-up as [`Self::upload_dir_with_progress`].
    pub fn download_dir_with_progress(
        &self,
        session_id: &str,
        remote_dir: &str,
        local_dir: &str,
        progress: Arc<TransferProgress>,
    ) -> Result<(), String> {
        bail_if_cancelled(&progress)?;
        let remote_root = validate_remote_path(remote_dir)?;
        let local_root = std::path::PathBuf::from(local_dir);
        if local_root.as_os_str().is_empty() {
            return Err(i18n::t("transfer.err.local_empty").into());
        }
        let exec_session = self.get_exec_session(session_id)?;

        // Name the bar before the remote walk: that walk is a round trip per
        // directory.
        *progress.filename.lock() = remote_root
            .rsplit('/')
            .next()
            .unwrap_or(&remote_root)
            .to_string();
        progress.total.store(0, Ordering::Relaxed);
        progress.transferred.store(0, Ordering::Relaxed);
        *progress.start_time.lock() = Some(std::time::Instant::now());

        let sess = exec_session.lock();
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);
        let sftp = start_sftp(&sess).map_err(|e| format!("SFTP init failed: {}", e))?;

        let mut dirs: Vec<Vec<String>> = Vec::new();
        let mut files: Vec<RemoteItem> = Vec::new();
        let mut skipped = 0usize;
        collect_remote_tree(
            &sftp,
            &remote_root,
            &mut Vec::new(),
            0,
            &mut dirs,
            &mut files,
            &mut skipped,
            &progress,
        )?;
        let total: u64 = files.iter().map(|f| f.size).sum();
        progress.total.store(total, Ordering::Relaxed);
        // Nothing local exists yet.
        bail_if_cancelled(&progress)?;

        let local_mkdir_err = |path: &std::path::Path, e: std::io::Error| {
            i18n::tf(
                "transfer.err.local_mkdir",
                &[
                    ("path", &path.display().to_string()),
                    ("err", &e.to_string()),
                ],
            )
        };
        std::fs::create_dir_all(&local_root).map_err(|e| local_mkdir_err(&local_root, e))?;
        for d in &dirs {
            let path = join_local(&local_root, d);
            std::fs::create_dir_all(&path).map_err(|e| local_mkdir_err(&path, e))?;
        }

        let mut done = 0u64;
        for f in &files {
            bail_if_cancelled(&progress)?;
            *progress.filename.lock() = f.rel.join("/");
            let local_path = join_local(&local_root, &f.rel);
            done += download_one_file(
                &sftp,
                &f.remote,
                &local_path,
                &progress,
                done,
                ResumeMode::Never,
            )?;
        }

        if done > total {
            progress.total.store(done, Ordering::Relaxed);
        }
        progress.transferred.store(done, Ordering::Relaxed);
        progress.finished.store(true, Ordering::Relaxed);
        // Everything that could be fetched was; say what could not.
        if skipped > 0 {
            return Err(skipped_names_message(skipped));
        }
        Ok(())
    }

    /// Read a remote file's content as a string (for editing).
    pub fn read_file_content(&self, session_id: &str, remote_path: &str) -> Result<String, String> {
        let rp = sftp_sendable(remote_path)?;
        let exec_session = self.get_exec_session(session_id)?;
        let sess = exec_session.lock();
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);

        let sftp = start_sftp(&sess)
            .map_err(|e| format!("SFTP init failed: {}", e))?;

        let mut remote_file = sftp.open(rp)
            .map_err(|e| format!("Failed to open remote file: {}", e))?;

        let mut contents = String::new();
        remote_file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        Ok(contents)
    }

    /// Write content to a remote file (for saving edits).
    pub fn write_file_content(&self, session_id: &str, remote_path: &str, content: &str) -> Result<(), String> {
        let rp = sftp_sendable(remote_path)?;
        let exec_session = self.get_exec_session(session_id)?;
        let sess = exec_session.lock();
        let _blocking = BlockingScope::enter(&*sess, SFTP_TIMEOUT_MS);

        let sftp = start_sftp(&sess)
            .map_err(|e| format!("SFTP init failed: {}", e))?;

        let mut remote_file = sftp.create(rp)
            .map_err(|e| format!("Failed to create remote file: {}", e))?;

        remote_file.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write file: {}", e))?;

        Ok(())
    }
}

/// One local file queued for upload, with its path below the transfer root.
struct TreeItem {
    local: std::path::PathBuf,
    /// Components below the transfer root, each already sanitized.
    rel: Vec<String>,
    size: u64,
}

/// One remote file queued for download.
struct RemoteItem {
    remote: String,
    rel: Vec<String>,
    size: u64,
}

/// Copy one local file to `remote_path` over an already-open SFTP channel.
///
/// `base` is the number of bytes already counted toward the aggregate
/// `progress.transferred`, so a single-file transfer passes 0 and the recursive
/// walk passes its running total. Returns the bytes this file contributed.
/// `progress.total` / `filename` / `finished` belong to the caller — the
/// recursive walk owns them for the whole tree. `mode` decides whether an
/// existing remote file may be continued rather than rewritten.
fn upload_one_file(
    sftp: &ssh2::Sftp,
    local_path: &std::path::Path,
    remote_path: &str,
    progress: &TransferProgress,
    base: u64,
    mode: ResumeMode,
) -> Result<u64, String> {
    let local_size = std::fs::metadata(local_path)
        .map(|m| m.len())
        .map_err(|e| format!("Local file error: {}", e))?;
    let rp = std::path::Path::new(remote_path);

    let remote_size = sftp.stat(rp).map(|s| s.size.unwrap_or(0)).unwrap_or(0);
    let mut local_file =
        std::fs::File::open(local_path).map_err(|e| format!("Open local: {}", e))?;
    // A resume reads the remote bytes back to prove they are ours: a download
    // of `remote_size` bytes, still cheaper than sending them again on the
    // usual asymmetric link, and it needs nothing but SFTP.
    let start_offset = plan_copy(
        mode,
        &mut local_file,
        local_size,
        remote_size,
        || sftp.open(rp).ok(),
        progress,
        base,
    )?;

    let mut remote_file = if start_offset > 0 {
        let mut f = sftp
            .open_mode(
                rp,
                ssh2::OpenFlags::WRITE | ssh2::OpenFlags::APPEND,
                0o644,
                ssh2::OpenType::File,
            )
            .map_err(|e| format!("Open for append failed: {}", e))?;
        f.seek(std::io::SeekFrom::Start(start_offset)).ok();
        f
    } else {
        sftp.create(rp)
            .map_err(|e| format!("Failed to create remote file '{}': {}", remote_path, e))?
    };

    let mut buf = [0u8; 32768];
    let mut uploaded = start_offset;
    loop {
        bail_if_cancelled(progress)?;
        let n = local_file.read(&mut buf).map_err(|e| format!("Read: {}", e))?;
        if n == 0 {
            break;
        }
        remote_file
            .write_all(&buf[..n])
            .map_err(|e| format!("Write: {}", e))?;
        uploaded += n as u64;
        progress
            .transferred
            .store(base + uploaded, Ordering::Relaxed);
    }
    Ok(uploaded)
}

/// Copy one remote file to `local_path`. Mirror of [`upload_one_file`].
fn download_one_file(
    sftp: &ssh2::Sftp,
    remote_path: &str,
    local_path: &std::path::Path,
    progress: &TransferProgress,
    base: u64,
    mode: ResumeMode,
) -> Result<u64, String> {
    let rp = std::path::Path::new(remote_path);
    let total_size = sftp
        .stat(rp)
        .map_err(|e| {
            i18n::tf("sftp.err.stat", &[("path", remote_path), ("err", &e.to_string())])
        })?
        .size
        .unwrap_or(0);
    let existing = std::fs::metadata(local_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let mut remote_file = sftp
        .open(rp)
        .map_err(|e| format!("Failed to open remote file '{}': {}", remote_path, e))?;
    // Over SFTP the server's bytes cross the wire either way, so a verified
    // resume here saves disk writes rather than traffic — but it can never
    // splice an old local head onto a new remote tail.
    let start = plan_copy(
        mode,
        &mut remote_file,
        total_size,
        existing,
        || std::fs::File::open(local_path).ok(),
        progress,
        base,
    )?;

    let mut local_file = if start > 0 {
        std::fs::OpenOptions::new()
            .append(true)
            .open(local_path)
            .map_err(|e| format!("Open local for append failed: {}", e))?
    } else {
        std::fs::File::create(local_path)
            .map_err(|e| format!("Create local file failed: {}", e))?
    };

    let mut buf = [0u8; 32768];
    let mut downloaded = start;
    loop {
        bail_if_cancelled(progress)?;
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
        progress
            .transferred
            .store(base + downloaded, Ordering::Relaxed);
    }
    Ok(downloaded)
}

/// `mkdir` that treats an existing directory as success, so re-running an
/// interrupted tree upload goes through instead of failing on the first
/// directory.
fn mkdir_if_missing(sftp: &ssh2::Sftp, path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    if let Ok(st) = sftp.stat(p) {
        if st.is_dir() {
            return Ok(());
        }
        return Err(i18n::tf("sftp.err.not_dir", &[("path", path)]));
    }
    sftp.mkdir(p, 0o755).map_err(|e| {
        i18n::tf("sftp.err.mkdir", &[("path", path), ("err", &e.to_string())])
    })
}

/// libssh2's "no more directory entries" and "would block" codes;
/// `libssh2-sys` is not a direct dependency, so they are spelled out here.
const LIBSSH2_ERROR_FILE: i32 = -16;
const LIBSSH2_ERROR_EAGAIN: i32 = -37;

/// Whether a name the server listed can be deleted exactly as listed.
///
/// Deleting writes nothing locally, so the download-side
/// [`safe_path_component`] is the wrong gate: a backslash, a control character
/// or a non-UTF-8 byte is a legal Linux file name and must not stop a delete.
/// Refused are only names that would address something other than this entry —
/// empty, `.`, `..`, or containing `/` or NUL — plus, off unix, the names ssh2
/// cannot send unchanged there (it takes only UTF-8 and rewrites `\` to `/`).
fn deletable_entry_name(name: &[u8]) -> bool {
    if name.is_empty()
        || name == b"."
        || name == b".."
        || name.contains(&b'/')
        || name.contains(&0)
    {
        return false;
    }
    if cfg!(not(unix)) && (std::str::from_utf8(name).is_err() || name.contains(&b'\\')) {
        return false;
    }
    true
}

/// The raw path a destructive operation on `path` acts on, once the row the
/// user confirmed it on allows it at all (`None`: a caller that does not
/// say). A row whose listing was not verified — `ls -la` text, which a name
/// holding a newline can forge — is refused before anything is touched. The
/// row's name as the server sent it stands in for the text it was shown as
/// ([`entry_path`]); a bare kind leaves `path` as it is.
fn confirmed_target(path: &str, confirmed: Option<&ConfirmedEntry>) -> Result<Vec<u8>, String> {
    let Some(confirmed) = confirmed else {
        return Ok(path.as_bytes().to_vec());
    };
    if !confirmed.verified {
        return Err(i18n::tf("sftp.err.unverified", &[("path", path)]));
    }
    match &confirmed.raw_name {
        Some(raw) => entry_path(path, raw, LISTED_NAMES_LOSSY),
        None => Ok(path.as_bytes().to_vec()),
    }
}

/// `path` — a row's directory joined with the name it was shown as — with
/// that name replaced by `raw`, the name as the server sent it. The text shown
/// for b"a\xff" is "a\u{FFFD}", and sent back it named the entry literally
/// called that, or none; on unix ssh2 sends a path's bytes verbatim, so the
/// raw name reaches the entry listed. `lossy`: ssh2 lists and sends UTF-8
/// only ([`LISTED_NAMES_LOSSY`], every platform but unix), so a name that is
/// not UTF-8, or whose U+FFFD may be ssh2's own, cannot be addressed and is
/// refused. Refused as well: a `raw` whose text is not the name in `path` —
/// the path is not that row's.
fn entry_path(path: &str, raw: &[u8], lossy: bool) -> Result<Vec<u8>, String> {
    let changed = || i18n::tf("sftp.err.changed", &[("path", path)]);
    let (dir, shown) = path.rsplit_once('/').ok_or_else(changed)?;
    if shown != String::from_utf8_lossy(raw) {
        return Err(changed());
    }
    if lossy && (std::str::from_utf8(raw).is_err() || has_replacement_char(raw)) {
        return Err(i18n::tf("sftp.err.not_utf8", &[("path", path)]));
    }
    if !deletable_entry_name(raw) {
        return Err(changed());
    }
    let mut target = Vec::with_capacity(dir.len() + 1 + raw.len());
    target.extend_from_slice(dir.as_bytes());
    target.push(b'/');
    target.extend_from_slice(raw);
    Ok(target)
}

/// A raw remote path as the `Path` ssh2 puts on the wire. On unix ssh2 sends a
/// path's bytes verbatim, so every listed name round-trips.
#[cfg(unix)]
fn remote_path_from_bytes(raw: &[u8]) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
}

/// Off unix ssh2 takes only UTF-8 paths and rewrites every `\` to `/`, so such
/// a path is refused rather than silently pointed at a different file.
#[cfg(not(unix))]
fn remote_path_from_bytes(raw: &[u8]) -> Option<std::path::PathBuf> {
    let s = std::str::from_utf8(raw).ok()?;
    if s.contains('\\') {
        return None;
    }
    Some(std::path::PathBuf::from(s))
}

/// The raw bytes of a name ssh2 read from a directory listing.
#[cfg(unix)]
fn listed_name_bytes(name: &std::path::Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_os_str().as_bytes().to_vec()
}

/// Off unix ssh2 builds listed names from UTF-8 only, so this is lossless.
#[cfg(not(unix))]
fn listed_name_bytes(name: &std::path::Path) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}

/// A raw remote path, readable in an error message.
fn shown(path: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(path)
}

/// A raw remote path ssh2 can send unchanged, or an error saying why not.
fn sftp_path(path: &[u8]) -> Result<std::path::PathBuf, String> {
    remote_path_from_bytes(path)
        .ok_or_else(|| i18n::tf("sftp.err.unaddressable", &[("path", &shown(path))]))
}

/// The four SFTP calls a recursive delete makes, over raw — possibly
/// non-UTF-8 — remote paths. A trait so the check-everything-first order can be
/// tested against an in-memory tree.
trait RemoteTree {
    /// `lstat`, never `stat`: a symlink is a symlink, one to a directory
    /// included.
    fn kind_nofollow(&self, path: &[u8]) -> Result<EntryKind, String>;
    /// Raw names in a directory, without `.` and `..`.
    fn entry_names(&self, path: &[u8]) -> Result<Vec<Vec<u8>>, String>;
    fn remove_file(&self, path: &[u8]) -> Result<(), String>;
    fn remove_dir(&self, path: &[u8]) -> Result<(), String>;
    /// Whether a listed name's U+FFFD may be ssh2's, not the server's (see
    /// [`LISTED_NAMES_LOSSY`]).
    fn lossy_names(&self) -> bool {
        LISTED_NAMES_LOSSY
    }
}

impl RemoteTree for ssh2::Sftp {
    fn kind_nofollow(&self, path: &[u8]) -> Result<EntryKind, String> {
        let p = sftp_path(path)?;
        self.lstat(&p).map(|st| EntryKind::of(&st)).map_err(|e| {
            i18n::tf("sftp.err.stat", &[("path", &shown(path)), ("err", &e.to_string())])
        })
    }

    fn entry_names(&self, path: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let list_err = |e: ssh2::Error| {
            i18n::tf("sftp.err.list", &[("path", &shown(path)), ("err", &e.to_string())])
        };
        let p = sftp_path(path)?;
        // `opendir` + `readdir` by hand rather than `Sftp::readdir`, which
        // joins each name onto the directory and so hides a name that itself
        // contains — or starts with — a `/`.
        let mut dir = self.opendir(&p).map_err(list_err)?;
        let mut names = Vec::new();
        loop {
            match dir.readdir() {
                Ok((name, _)) => {
                    let raw = listed_name_bytes(&name);
                    if raw != b"." && raw != b".." {
                        names.push(raw);
                    }
                }
                Err(e) if e.code() == ssh2::ErrorCode::Session(LIBSSH2_ERROR_FILE) => break,
                Err(e) if e.code() == ssh2::ErrorCode::Session(LIBSSH2_ERROR_EAGAIN) => {}
                Err(e) => return Err(list_err(e)),
            }
        }
        Ok(names)
    }

    fn remove_file(&self, path: &[u8]) -> Result<(), String> {
        let p = sftp_path(path)?;
        self.unlink(&p).map_err(|e| {
            i18n::tf("sftp.err.delete", &[("path", &shown(path)), ("err", &e.to_string())])
        })
    }

    fn remove_dir(&self, path: &[u8]) -> Result<(), String> {
        let p = sftp_path(path)?;
        self.rmdir(&p).map_err(|e| {
            i18n::tf("sftp.err.rmdir", &[("path", &shown(path)), ("err", &e.to_string())])
        })
    }
}

/// What a delete does with the entry at its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovePlan {
    /// `unlink`: a file, a symlink (never followed), anything not a directory.
    Unlink,
    /// `rmdir` alone: a directory nobody confirmed as one — only if empty.
    Rmdir,
    /// The directory and everything under it: confirmed as a directory.
    Tree,
}

/// Refuse an entry that is no longer the kind the user confirmed. `None` is a
/// caller that does not say, and is not refused here.
fn check_unchanged(
    confirmed: Option<EntryKind>,
    actual: EntryKind,
    path: &str,
) -> Result<(), String> {
    match confirmed {
        Some(kind) if kind != actual => Err(i18n::tf("sftp.err.changed", &[("path", path)])),
        _ => Ok(()),
    }
}

/// How to delete what `lstat` found to be `actual`, confirmed by the user as
/// `confirmed`: refused when those differ — a file confirmed where a
/// directory now is, the decoy — and recursive only for a directory confirmed
/// as one.
fn plan_remove(
    confirmed: Option<EntryKind>,
    actual: EntryKind,
    path: &str,
) -> Result<RemovePlan, String> {
    check_unchanged(confirmed, actual, path)?;
    Ok(match (confirmed, actual) {
        (Some(EntryKind::Dir), EntryKind::Dir) => RemovePlan::Tree,
        (_, EntryKind::Dir) => RemovePlan::Rmdir,
        _ => RemovePlan::Unlink,
    })
}

/// Whether a chmod may go ahead on what `lstat` found to be `actual`: refused
/// when it is no longer the kind the user confirmed, and for a symlink —
/// SFTP's setstat follows it, so the mode would land on its target, a file
/// the user never selected (and Linux keeps no mode of a link's own).
fn check_chmod(confirmed: Option<EntryKind>, actual: EntryKind, path: &str) -> Result<(), String> {
    check_unchanged(confirmed, actual, path)?;
    if actual == EntryKind::Symlink {
        return Err(i18n::tf("sftp.err.chmod_symlink", &[("path", path)]));
    }
    Ok(())
}

/// Delete `root` as [`plan_remove`] decides, after one `lstat` of it.
fn remove_confirmed(
    fs: &impl RemoteTree,
    root: &[u8],
    confirmed: Option<EntryKind>,
) -> Result<(), String> {
    let actual = fs.kind_nofollow(root)?;
    match plan_remove(confirmed, actual, &shown(root))? {
        RemovePlan::Tree => sftp_remove_recursive(fs, root),
        RemovePlan::Rmdir => fs.remove_dir(root),
        RemovePlan::Unlink => fs.remove_file(root),
    }
}

/// Delete a remote entry and, for a directory, everything under it.
///
/// Two phases. The whole tree is walked and every name checked first; only a
/// fully acceptable tree is then deleted, children before their parent. A
/// single pass that checked names while it deleted aborted half-way on the
/// first odd name deep in a tree, leaving a partial tree behind that the UI
/// could not finish off either. An entry ssh2 could only list lossily is
/// skipped instead, with every directory above it, and reported at the end.
fn sftp_remove_recursive(fs: &impl RemoteTree, root: &[u8]) -> Result<(), String> {
    let mut plan = Vec::new();
    let mut skipped = 0;
    plan_remote_delete(fs, root, 0, &mut plan, &mut skipped)?;
    for (path, is_dir) in &plan {
        if *is_dir {
            fs.remove_dir(path)?;
        } else {
            fs.remove_file(path)?;
        }
    }
    if skipped > 0 {
        return Err(skipped_names_message(skipped));
    }
    Ok(())
}

/// Phase one of [`sftp_remove_recursive`]: list `path` depth-first into `plan`,
/// children before their parent, and refuse the whole delete on the first name
/// that would address something other than the entry listed. A name ssh2
/// could only spell lossily is not deleted — that spelling names nothing on
/// the server, or another entry — but counted in `skipped`, and every
/// directory above it stays out of the plan: none of them can be emptied now,
/// and an `rmdir` failing on one would stop the delete half-way. Deletes
/// nothing. Returns whether `path` itself is in the plan.
fn plan_remote_delete(
    fs: &impl RemoteTree,
    path: &[u8],
    depth: usize,
    plan: &mut Vec<(Vec<u8>, bool)>,
    skipped: &mut usize,
) -> Result<bool, String> {
    if depth > MAX_SFTP_DEPTH {
        return Err(i18n::tf(
            "sftp.err.too_deep",
            &[("max", &MAX_SFTP_DEPTH.to_string()), ("path", &shown(path))],
        ));
    }
    // lstat, not stat: a symlink pointing at a directory must be unlinked, not
    // followed — following it would delete a tree the user never selected.
    let is_dir = fs.kind_nofollow(path)? == EntryKind::Dir;
    let mut whole = true;
    if is_dir {
        for name in fs.entry_names(path)? {
            if !deletable_entry_name(&name) {
                return Err(i18n::tf("sftp.err.bad_entry", &[("path", &shown(path))]));
            }
            if fs.lossy_names() && has_replacement_char(&name) {
                *skipped += 1;
                whole = false;
                continue;
            }
            let mut child = path.to_vec();
            child.push(b'/');
            child.extend_from_slice(&name);
            whole &= plan_remote_delete(fs, &child, depth + 1, plan, skipped)?;
        }
    }
    if whole {
        plan.push((path.to_vec(), is_dir));
    }
    Ok(whole)
}

/// Walk a local directory depth-first, collecting the files to send and the
/// directories to create (parents before children).
///
/// Symlinks are skipped: following them can loop, and silently materialising a
/// link's target as a real file on the remote side is not what was asked for.
fn collect_local_tree(
    root: &std::path::Path,
    rel: &mut Vec<String>,
    depth: usize,
    dirs: &mut Vec<Vec<String>>,
    files: &mut Vec<TreeItem>,
) -> Result<(), String> {
    if depth > MAX_SFTP_DEPTH {
        return Err(i18n::tf(
            "sftp.err.too_deep",
            &[
                ("max", &MAX_SFTP_DEPTH.to_string()),
                ("path", &root.display().to_string()),
            ],
        ));
    }
    let read_err = |e: std::io::Error| {
        i18n::tf(
            "transfer.err.local_read_dir",
            &[
                ("path", &root.display().to_string()),
                ("err", &e.to_string()),
            ],
        )
    };
    let entries = std::fs::read_dir(root).map_err(read_err)?;
    for entry in entries {
        let entry = entry.map_err(read_err)?;
        // file_type() here is lstat-based, so a symlink reports as a symlink
        // rather than as whatever it points at.
        let ft = entry.file_type().map_err(|e| {
            i18n::tf(
                "sftp.err.stat",
                &[
                    ("path", &entry.path().display().to_string()),
                    ("err", &e.to_string()),
                ],
            )
        })?;
        let name = match entry
            .file_name()
            .to_str()
            .and_then(safe_path_component)
        {
            Some(n) => n,
            None => {
                log::warn!(
                    "skipping local entry with a name that cannot be sent: {:?}",
                    entry.file_name()
                );
                continue;
            }
        };
        rel.push(name);
        if ft.is_dir() {
            dirs.push(rel.clone());
            collect_local_tree(&entry.path(), rel, depth + 1, dirs, files)?;
        } else if ft.is_file() {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            files.push(TreeItem {
                local: entry.path(),
                rel: rel.clone(),
                size,
            });
        }
        rel.pop();
    }
    Ok(())
}

/// `Sftp::readdir`, behind a trait so that the download walk — and a Cancel
/// landing in it — can be tested without a server.
trait RemoteLister {
    fn list(&self, dir: &str) -> Result<Vec<(std::path::PathBuf, ssh2::FileStat)>, String>;
}

impl RemoteLister for ssh2::Sftp {
    fn list(&self, dir: &str) -> Result<Vec<(std::path::PathBuf, ssh2::FileStat)>, String> {
        self.readdir(std::path::Path::new(dir))
            .map_err(|e| i18n::tf("sftp.err.list", &[("path", dir), ("err", &e.to_string())]))
    }
}

/// Walk a remote directory depth-first over SFTP. Mirror of
/// [`collect_local_tree`], but every name is server-controlled, so each one is
/// sanitized before it is used to build either path. Symlinks, sockets and
/// devices are left out by design; a file or directory whose name cannot be
/// used here (see [`download_entry_name`]) is left out and counted in
/// `skipped`, so the transfer carries on and can say so at the end instead of
/// failing on it half-way.
///
/// The progress bar's Cancel is honoured before every directory: the walk is
/// a round trip per directory, all of it under the exec session's lock, and
/// a Cancel used to wait for the whole tree to be listed.
#[allow(clippy::too_many_arguments)]
fn collect_remote_tree(
    sftp: &impl RemoteLister,
    dir: &str,
    rel: &mut Vec<String>,
    depth: usize,
    dirs: &mut Vec<Vec<String>>,
    files: &mut Vec<RemoteItem>,
    skipped: &mut usize,
    progress: &TransferProgress,
) -> Result<(), String> {
    bail_if_cancelled(progress)?;
    if depth > MAX_SFTP_DEPTH {
        return Err(i18n::tf(
            "sftp.err.too_deep",
            &[("max", &MAX_SFTP_DEPTH.to_string()), ("path", dir)],
        ));
    }
    let entries = sftp.list(dir)?;
    for (child, stat) in entries {
        if !stat.is_dir() && !stat.is_file() {
            continue;
        }
        // `Sftp::readdir` joins the raw name onto `dir`, so a name of "../x"
        // would already have escaped the tree. Take the component back out and
        // rebuild both paths from the sanitized form instead of trusting it.
        let listed = child.file_name().and_then(|n| n.to_str());
        let name = match download_entry_name(listed, LISTED_NAMES_LOSSY) {
            Some(n) => n,
            None => {
                log::warn!("skipping remote entry with an unusable name under '{}'", dir);
                *skipped += 1;
                continue;
            }
        };
        let remote = join_remote(dir, &name);
        rel.push(name);
        if stat.is_dir() {
            dirs.push(rel.clone());
            collect_remote_tree(sftp, &remote, rel, depth + 1, dirs, files, skipped, progress)?;
        } else {
            files.push(RemoteItem {
                remote,
                rel: rel.clone(),
                size: stat.size.unwrap_or(0),
            });
        }
        rel.pop();
    }
    Ok(())
}

/// Off unix, ssh2 builds the names it lists from UTF-8 only and puts U+FFFD
/// where the server's bytes were not (vendor/ssh2/PATCHES.md): such a name no
/// longer spells the entry on the server — it names nothing there, or a
/// different entry. On unix ssh2 hands the raw bytes over.
const LISTED_NAMES_LOSSY: bool = cfg!(not(unix));

/// Whether a raw listed name carries U+FFFD.
fn has_replacement_char(name: &[u8]) -> bool {
    name.windows(3).any(|w| w == "\u{FFFD}".as_bytes())
}

/// The name a recursive download gives a listed entry, or `None` to skip it:
/// no text at all (unix passes non-UTF-8 bytes through, and the transfer
/// builds its paths as text), a U+FFFD that `lossy` ssh2 put in (see
/// [`LISTED_NAMES_LOSSY`]), or a name [`safe_path_component`] refuses.
fn download_entry_name(listed: Option<&str>, lossy: bool) -> Option<String> {
    let name = listed?;
    if lossy && name.contains('\u{FFFD}') {
        return None;
    }
    safe_path_component(name)
}

/// The report for a recursive download or delete that left entries out.
fn skipped_names_message(count: usize) -> String {
    i18n::tf("sftp.err.skipped_names", &[("count", &count.to_string())])
}

// ---------------------------------------------------------------------------
// File browser listing
// ---------------------------------------------------------------------------

/// Whether a listed name can stand for one entry of the listed directory. The
/// browser joins it onto the directory to act on it, so "" and "." (the
/// directory itself) and a name with a `/` or NUL (another path) are left
/// out. ".." stays, as it always did, for navigation.
fn listable_name(name: &[u8]) -> bool {
    !(name.is_empty() || name == b"." || name.contains(&b'/') || name.contains(&0))
}

/// The absolute directory `cd '<path>' && pwd` lands in and prints: `path`
/// itself when absolute, else `path` under `home` — the login directory, and
/// `None` when that is needed and unknown. A leading `~` alone or before a
/// `/` is the login directory as well, as the shell's tilde expansion has
/// it: the file panel asks for "~" on every connect and split, and a prompt
/// such as `user@host:~/src$` names "~/src" — taken as a name, both listed
/// empty. `~user` and a `~` anywhere else are names like any other. `.` and
/// `..` are resolved by name, the way `cd` and `pwd` resolve them without
/// looking at symlinks. No other character, whitespace included, is dropped
/// or changed.
fn resolve_listing_dir(path: &str, home: impl FnOnce() -> Option<String>) -> Option<String> {
    let (base, path) = match path.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => (home()?, rest),
        _ if path.starts_with('/') => (String::new(), path),
        _ => (home()?, path),
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in base.split('/').chain(path.split('/')) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            name => parts.push(name),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// `path` as `cd`'s argument for the `ls -la` listing: quoted, except that a
/// leading `~` alone or before a `/` stays outside the quotes, so that the
/// shell expands it to the login directory as [`resolve_listing_dir`] does
/// for SFTP.
fn ls_cd_arg(path: &str) -> String {
    match path.strip_prefix('~') {
        Some("") => "~".to_string(),
        Some(rest) if rest.starts_with('/') => format!("~/{}", shell_escape(&rest[1..])),
        _ => shell_escape(path),
    }
}

/// A file-browser row from one SFTP directory entry; `None` for a name
/// [`listable_name`] refuses. The name is the server's, byte for byte — shown
/// lossily decoded where it is not UTF-8, as every listing was, and kept raw
/// for the operations on the row — and everything else comes from the
/// entry's attributes: `ls`-style permissions, size, the time as the host's
/// `ls -la` would print it, and the numeric owner. Verified, all of it.
fn sftp_file_entry(
    name: &[u8],
    stat: &ssh2::FileStat,
    now: u64,
    utc_offset: i64,
) -> Option<FileEntry> {
    if !listable_name(name) {
        return None;
    }
    Some(FileEntry {
        name: String::from_utf8_lossy(name).into_owned(),
        is_dir: EntryKind::of(stat) == EntryKind::Dir,
        size: stat.size.map(|s| s.to_string()).unwrap_or_default(),
        permissions: stat.perm.map(ls_permissions).unwrap_or_default(),
        modified: stat
            .mtime
            .map(|t| ls_time(t, now, utc_offset))
            .unwrap_or_default(),
        owner: stat.uid.map(|u| u.to_string()).unwrap_or_default(),
        raw_name: name.to_vec(),
        verified: true,
    })
}

/// SFTP lists in directory order; `ls` sorted. ".." first, then by name
/// without regard to case.
fn sort_listing(entries: &mut [FileEntry]) {
    entries.sort_by(|a, b| {
        (b.name == "..")
            .cmp(&(a.name == ".."))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// `st_mode` as `ls -l` prints it, e.g. "drwxr-xr-x" or "-rwsr-xr-x" — the
/// form the browser reads a row's type and chmod default from.
fn ls_permissions(mode: u32) -> String {
    let kind = match mode & 0o170_000 {
        0o040_000 => 'd',
        0o120_000 => 'l',
        0o100_000 => '-',
        0o020_000 => 'c',
        0o060_000 => 'b',
        0o010_000 => 'p',
        0o140_000 => 's',
        _ => '?',
    };
    let mut out = String::with_capacity(10);
    out.push(kind);
    for (shift, special, mark) in [(6, 0o4000, 's'), (3, 0o2000, 's'), (0, 0o1000, 't')] {
        let bits = (mode >> shift) & 0o7;
        out.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        out.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        out.push(match (bits & 0o1 != 0, mode & special != 0) {
            (true, true) => mark,
            (false, true) => mark.to_ascii_uppercase(),
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    out
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `ls -l`'s time column for `mtime` (seconds since the epoch) in a zone
/// `utc_offset` seconds east of UTC: "Sep 21 13:45" within half a year of
/// `now`, "Sep 21 2025" otherwise — single spaces, as the `ls -la` parser
/// always joined them.
fn ls_time(mtime: u64, now: u64, utc_offset: i64) -> String {
    /// Half of an average Gregorian year, GNU ls's "recent".
    const HALF_YEAR: u64 = 15_778_476;
    /// 9999-12-31T23:59:59Z: a hostile timestamp still prints as a date.
    const LAST: i64 = 253_402_300_799;
    let local = i64::try_from(mtime)
        .unwrap_or(LAST)
        .saturating_add(utc_offset)
        .clamp(0, LAST);
    let (year, month, day) = civil_from_days(local.div_euclid(86_400));
    let secs = local.rem_euclid(86_400);
    let month = MONTHS[(month - 1) as usize];
    if mtime.abs_diff(now) < HALF_YEAR {
        format!("{} {} {:02}:{:02}", month, day, secs / 3600, secs % 3600 / 60)
    } else {
        format!("{} {} {}", month, day, year)
    }
}

/// (year, month 1-12, day 1-31) of a day count since 1970-01-01, proleptic
/// Gregorian (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `date +%z` output ("+0800", "-0530") as seconds east of UTC.
fn parse_utc_offset(out: &str) -> Option<i64> {
    let s = out.trim();
    let (sign, digits) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i64 = digits[..2].parse().ok()?;
    let minutes: i64 = digits[2..].parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

/// The next column of an `ls -l` line: skip the run of spaces, take up to the
/// next space, and leave `rest` at that space.
fn next_ls_column<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let s = rest.trim_start_matches(' ');
    let end = s.find(' ')?;
    *rest = &s[end..];
    Some(&s[..end])
}

/// One `ls -la` line as a file-browser row; `None` for anything else ("total
/// 8", an error line, an entry `ls` could not stat) and for a name
/// [`listable_name`] refuses. The fixed columns — permissions, links, owner,
/// group, size (major and minor for a device), month, day, time or year — are
/// split on their runs of spaces; the name is everything after the one space
/// that follows them, byte for byte: leading, trailing and doubled spaces
/// and tabs included. A symlink's " -> target" is cut off. Every row is
/// unverified ([`FileEntry::verified`]): a name holding a newline still
/// splits the line — only SFTP lists that one exactly — and can forge a row
/// of its own.
fn parse_ls_line(line: &str) -> Option<FileEntry> {
    let mut rest = line;
    let perms = next_ls_column(&mut rest)?;
    if perms.len() < 10
        || !perms.starts_with(['-', 'd', 'l', 'c', 'b', 'p', 's'])
        || perms.contains('?')
    {
        return None;
    }
    // links, owner, group, size — two columns for a device — month, day, time.
    let fixed = if perms.starts_with(['c', 'b']) { 8 } else { 7 };
    let mut cols = Vec::with_capacity(fixed);
    for _ in 0..fixed {
        cols.push(next_ls_column(&mut rest)?);
    }
    let mut name = rest.strip_prefix(' ')?;
    if perms.starts_with('l') {
        name = name.split_once(" -> ").map_or(name, |(link, _)| link);
    }
    if !listable_name(name.as_bytes()) {
        return None;
    }
    Some(FileEntry {
        name: name.to_string(),
        is_dir: perms.starts_with('d'),
        size: cols[3..fixed - 3].join(" "),
        permissions: perms.to_string(),
        modified: cols[fixed - 3..].join(" "),
        owner: cols[1].to_string(),
        raw_name: name.as_bytes().to_vec(),
        verified: false,
    })
}

/// Signals the UI may send. Deliberately tiny: this is the first destructive
/// remote action in the app, and `kill -9` on the wrong pid is not undoable.
const ALLOWED_KILL_SIGNALS: &[(i32, &str)] =
    &[(1, "HUP"), (2, "INT"), (9, "KILL"), (15, "TERM")];

/// Check a kill request and return the signal's name for the command line.
fn validate_kill(pid: u32, signal: i32) -> Result<&'static str, String> {
    if pid <= 1 {
        return Err(format!(
            "refusing to signal pid {} (0 means the whole process group, 1 is init)",
            pid
        ));
    }
    ALLOWED_KILL_SIGNALS
        .iter()
        .find(|(s, _)| *s == signal)
        .map(|(_, n)| *n)
        .ok_or_else(|| {
            format!(
                "signal {} is not allowed — use one of {}",
                signal,
                ALLOWED_KILL_SIGNALS
                    .iter()
                    .map(|(s, n)| format!("{} ({})", n, s))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// Parse the `cpu` / `cpuN` lines of `/proc/stat` into totals.
///
/// Index 0 is the aggregate `cpu` line; the rest follow in the kernel's order.
/// Returns an empty Vec for anything that is not Linux `/proc/stat`.
fn parse_proc_stat(text: &str) -> Vec<CpuTimes> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("cpu") {
            continue;
        }
        let mut it = line.split_whitespace();
        let label = match it.next() {
            Some(l) => l,
            None => continue,
        };
        // "cpu" (aggregate) or "cpu<digits>". Anything else on a cpu-prefixed
        // line ("cpufreq" on some embedded kernels) is not ours.
        let suffix = &label[3..];
        if !suffix.is_empty() && !suffix.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // user nice system idle iowait irq softirq steal guest guest_nice
        let vals: Vec<u64> = it.filter_map(|v| v.parse::<u64>().ok()).collect();
        if vals.len() < 4 {
            continue;
        }
        // Saturating: these numbers come from the server, and a plain `+` on
        // two fields near u64::MAX panics a debug build (and wraps to a
        // nonsense percentage in release).
        out.push(CpuTimes {
            total: vals.iter().fold(0u64, |acc, v| acc.saturating_add(*v)),
            idle: vals[3].saturating_add(vals.get(4).copied().unwrap_or(0)),
        });
    }
    out
}

/// CPU utilisation between two `/proc/stat` samples.
///
/// Saturating throughout: a reboot between polls rewinds the counters, and the
/// honest answer to a negative delta is 0, not a panic or a wild percentage.
fn cpu_percent_from(prev: CpuTimes, cur: CpuTimes) -> f64 {
    let delta_total = cur.total.saturating_sub(prev.total);
    if delta_total == 0 {
        return 0.0;
    }
    let delta_idle = cur.idle.saturating_sub(prev.idle);
    let busy = delta_total.saturating_sub(delta_idle);
    (busy as f64 / delta_total as f64 * 100.0).clamp(0.0, 100.0)
}

/// Parse `ss -tulnp` or `netstat -tulnp` output into [`PortInfo`], one
/// strictly checked row per line (see [`parse_port_row`]).
fn parse_listening_ports(output: &str) -> Vec<PortInfo> {
    let mut ports: Vec<PortInfo> = output.lines().filter_map(parse_port_row).collect();
    ports.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.proto.cmp(&b.proto)));
    ports
}

/// One listening socket from one line of `ss -tulnp` or `netstat -tulnp`, or
/// `None` unless every column is what that layout puts there.
///
/// The two layouts are told apart by column 1: `ss` prints a state word
/// there ("LISTEN", "UNCONN"), `netstat` prints Recv-Q, a number.
///
/// Strict because a process names itself — comm, 15 bytes, prctl — and ss
/// prints that name inside its quotes as it is: a newline in it splits ss's
/// line in two, the second half being the name's own text followed by ss's
/// `",pid=<real pid>,fd=3))`. Read loosely, `\ntcp 0 0 :22 9/` forged a
/// netstat row "pid 9 listens on port 22" for the kill button to aim at. So
/// a row needs tcp/udp, numeric queues, a real address:port (local) and
/// address:port-or-`*` (peer), a state word where the layout has one, and the
/// owner column either absent or whole on this same line: ss's `users:((` …
/// `))`, or netstat's `-` or `<digits>/<name>`. The 14 bytes a name has after
/// its newline cannot supply all of that. (The `df` parser fixed in be39b6b
/// let a header row through for the lack of such checks.)
///
/// Each layout's owner column is read only its own way, so a program name
/// that looks like the other layout's column is just a name. The column is
/// absent, or `-`, when the login user may not see the owner: `None`, not 0.
fn parse_port_row(line: &str) -> Option<PortInfo> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let proto = tokens.first()?.to_ascii_lowercase();
    if !matches!(proto.as_str(), "tcp" | "tcp6" | "udp" | "udp6") {
        return None;
    }
    let number = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    // netstat: "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 456/sshd"
    // ss:      "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((…))"
    let netstat = number(tokens.get(1).copied()?);
    let queues = if netstat { tokens.get(1..3)? } else { tokens.get(2..4)? };
    if (!netstat && !state_word(tokens[1])) || !queues.iter().all(|&q| number(q)) {
        return None;
    }
    let first = if netstat { 3 } else { 4 };
    let (local, peer) = (*tokens.get(first)?, *tokens.get(first + 1)?);
    let (local_addr, port) = split_addr_port(local)?;
    let (peer_addr, peer_port) = peer.rsplit_once(':')?;
    if !(peer_port == "*" || number(peer_port)) || !socket_addr(peer_addr) {
        return None;
    }
    let mut owner = &tokens[first + 2..];
    let (pid, process) = if netstat {
        // TCP has a state column here; UDP leaves it blank.
        if owner.first().is_some_and(|w| state_word(w)) {
            owner = &owner[1..];
        }
        match owner {
            [] | ["-"] => (None, String::new()),
            [head, tail @ ..] => {
                // The program name may itself contain spaces
                // ("789/nginx: master process").
                let (num, name) = head.split_once('/')?;
                if !number(num) {
                    return None;
                }
                let mut name = name.to_string();
                for word in tail {
                    name.push(' ');
                    name.push_str(word);
                }
                (Some(num.parse::<u32>().ok()?), name.trim().to_string())
            }
        }
    } else if owner.is_empty() {
        (None, String::new())
    } else {
        let column = owner.join(" ");
        if !column.starts_with("users:((") || !column.ends_with("))") {
            return None;
        }
        parse_ss_users(&column).map_or((None, String::new()), |(pid, name)| (Some(pid), name))
    };
    Some(PortInfo {
        proto,
        local_addr,
        port,
        pid,
        process,
    })
}

/// A socket state as ss ("LISTEN", "UNCONN", "SYN-SENT") or netstat
/// ("LISTEN", "SYN_SENT") spells it.
fn state_word(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_uppercase())
        && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'-' || b == b'_')
}

/// Split "0.0.0.0:22", "[::]:80", "127.0.0.53%lo:53", ":::80" or "*:443" into
/// address and port. `None` unless the port is a number and the address a
/// real one ([`socket_addr`]) — which also filters out a header row's "Local
/// Address" cell.
fn split_addr_port(s: &str) -> Option<(String, u16)> {
    let (addr, port) = s.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) || !socket_addr(addr) {
        return None;
    }
    Some((addr.to_string(), port.parse().ok()?))
}

/// Whether a socket-table address is `*` or an IPv4 / IPv6 address, in
/// brackets or not, with or without an interface zone ("127.0.0.53%lo",
/// "[fe80::1]%eth0", "[fe80::1%eth0]"). Never empty.
fn socket_addr(addr: &str) -> bool {
    let unzoned = match addr.find('%') {
        Some(at) => {
            let end = addr[at..].find(']').map_or(addr.len(), |i| at + i);
            let zone = &addr[at + 1..end];
            if zone.is_empty()
                || !zone
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
            {
                return false;
            }
            format!("{}{}", &addr[..at], &addr[end..])
        }
        None => addr.to_string(),
    };
    let host = unzoned
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&unzoned);
    host == "*" || host.parse::<std::net::IpAddr>().is_ok()
}

/// The first owner in ss's process column, `users:(("sshd",pid=456,fd=3),…)`.
///
/// The name is the process's own comm — up to 15 bytes it chose itself with
/// prctl(PR_SET_NAME) — and ss prints it between quotes as it is: a `"`, `,`
/// or `(` inside it is not escaped. So the pid is not the first `pid=` on the
/// line, which a process named `pid=812` would supply and the kill button
/// would then aim at, but the one ss wrote after the name: a `",pid=<digits>`
/// whose remaining fields reach the entry's `)` without another quote. A name
/// cannot forge that: ss reads it from /proc/<pid>/stat with `%[^)]`, so it
/// never contains `)`. A quote behind a backslash is not taken as the closing
/// one either, in case an ss escapes them — so an entry whose name itself ends
/// in a backslash is passed over, for the next owner ss listed, or none.
fn parse_ss_users(field: &str) -> Option<(u32, String)> {
    let body = field.strip_prefix("users:((\"")?;
    let mut from = 0;
    while let Some(off) = body[from..].find("\",pid=") {
        let at = from + off;
        from = at + 1;
        let backslashes = body[..at].bytes().rev().take_while(|&b| b == b'\\').count();
        if backslashes % 2 == 1 {
            continue;
        }
        let rest = &body[at + "\",pid=".len()..];
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let fields = &rest[digits..];
        let end = match fields.find(')') {
            Some(end) => end,
            None => continue,
        };
        if digits == 0
            || !(fields.starts_with(',') || fields.starts_with(')'))
            || fields[..end].contains(['"', '('])
        {
            continue;
        }
        if let Ok(pid) = rest[..digits].parse() {
            return Some((pid, body[..at].to_string()));
        }
    }
    None
}

/// Create a standalone SSH session for exec/SFTP operations; `session_id` is
/// the session it serves, for its sign-in challenge.
fn create_exec_connection(params: &ConnectParams, session_id: &str) -> Result<Session, String> {
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
        "interactive" => {
            userauth_interactive(
                &session,
                &params.username,
                params.password.as_deref(),
                &params.host,
                params.port,
                "exec",
                session_id,
            )
            .map_err(|e| i18n::tf("auth.err.exec_interactive", &[("err", &e.to_string())]))?;
        }
        "agent" => {
            userauth_agent_identities(&session, &params.username)
                .map_err(|e| i18n::tf("auth.err.exec_agent", &[("err", &e)]))?;
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
        // Lossy: a login script that prints non-UTF-8 text must not hide tmux.
        let out = read_output(&mut ch).unwrap_or_default();
        let _ = ch.wait_close();
        Ok(out)
    })();

    match result {
        Ok(ref out) if out.contains("HAS_TMUX") => SessionMode::Persistent(name.to_string()),
        _ => SessionMode::RawShell,
    }
}

/// Why a reconnect attempt failed, as far as the retry loop cares.
#[derive(Debug)]
enum ReconnectError {
    /// The user dismissed the attempt's sign-in challenge.
    Dismissed,
    /// Anything else. A host-key failure is recognised by [`HOST_KEY_FAIL`].
    Failed(String),
}

impl From<String> for ReconnectError {
    fn from(e: String) -> Self {
        ReconnectError::Failed(e)
    }
}

impl From<&str> for ReconnectError {
    fn from(e: &str) -> Self {
        ReconnectError::Failed(e.to_string())
    }
}

impl std::fmt::Display for ReconnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconnectError::Dismissed => f.write_str("sign-in challenge dismissed"),
            ReconnectError::Failed(e) => f.write_str(e),
        }
    }
}

/// What the reader does after a failed reconnect attempt.
#[derive(Debug, PartialEq, Eq)]
enum RetryVerdict {
    /// Back off and try again.
    Retry,
    /// Stop reconnecting and close the tab, with this reason.
    GiveUp(String),
}

/// Whether a failed reconnect is worth another attempt.
///
/// Two failures are verdicts, not bad luck. A host key that changed while the
/// link was down is the exact man-in-the-middle signature: the next attempt
/// would hand it the stored password. And a sign-in challenge the user
/// dismissed is their decision: retrying raised up to ten more challenges,
/// each holding the reader for up to `AUTH_PROMPT_TIMEOUT`.
fn after_failed_reconnect(err: &ReconnectError) -> RetryVerdict {
    match err {
        ReconnectError::Dismissed => {
            RetryVerdict::GiveUp(i18n::t("ssh.err.reconnect_cancelled").to_string())
        }
        ReconnectError::Failed(e) if e.contains(HOST_KEY_FAIL) => {
            RetryVerdict::GiveUp(translate_ssh_error(e))
        }
        ReconnectError::Failed(_) => RetryVerdict::Retry,
    }
}

/// Whether a reconnect opens a fresh exec connection alongside the shell.
///
/// Never in minimal mode, where exec shares the shell's session, and never
/// for keyboard-interactive: that would be a second challenge in the same
/// breath, and a TOTP server that refuses to accept a code twice fails it.
/// The shell comes back on one answer; the exec connection stays as it is —
/// alive, or parked until the user resumes it (`SshManager::resume_exec`).
fn reconnect_reopens_exec(auth_type: &str, minimal_mode: bool) -> bool {
    !minimal_mode && auth_type != "interactive"
}

/// Whether `connect` parks the exec connection when its sign-in fails, and
/// returns the shell that has already signed in, instead of failing whole.
///
/// Only keyboard-interactive: there the exec connection is a second challenge
/// right after the shell's, and google-authenticator's default DISALLOW_REUSE
/// refuses the same TOTP code twice — the second one failing threw away a
/// working shell. Refused or dismissed, it waits for the user
/// (`SshManager::resume_exec`, one challenge). Every other method signs the
/// second connection in exactly like the first, so its failure is real.
fn exec_sign_in_parks(auth_type: &str) -> bool {
    auth_type == "interactive"
}

/// The step of opening the exec connection at connect that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecOpenStep {
    /// The TCP dial, direct or through the proxy.
    Dial,
    /// Setting up the SSH session and its handshake.
    Handshake,
    /// The host key, compared with the key the shell was pinned to.
    HostKey,
    /// The sign-in.
    SignIn,
}

/// Whether `connect` parks the exec connection when opening it failed at
/// `step`, and returns the shell that has already signed in: wherever
/// [`exec_sign_in_parks`] says so, for a dial or a handshake that failed as
/// much as for a sign-in — a link that dropped a second after the shell's own
/// dial threw a working 2FA shell away just the same. Never for the host key:
/// one other than the key the shell was pinned to a second earlier means the
/// peer changed between the two dials, and the whole connect is aborted.
fn exec_open_failure_parks(auth_type: &str, step: ExecOpenStep) -> bool {
    step != ExecOpenStep::HostKey && exec_sign_in_parks(auth_type)
}

/// Dial, handshake and host-key-check the exec connection `connect` opens
/// beside the shell; the step that failed comes with the error.
fn open_exec_transport(params: &ConnectParams) -> Result<Session, (ExecOpenStep, String)> {
    let tcp2 = establish_tcp(params).map_err(|e| (ExecOpenStep::Dial, e))?;
    let mut sess2 = Session::new().map_err(|e| {
        (ExecOpenStep::Handshake, format!("Failed to create exec session: {}", e))
    })?;
    sess2.set_tcp_stream(tcp2);
    // Bound the handshake so an unresponsive peer cannot wedge connect()
    // forever; cleared again once signed in — exec and SFTP set their own
    // bounds.
    sess2.set_timeout(15_000);
    configure_session_algorithms(&sess2);
    prepare_host_key_prefs(&sess2, params);
    sess2
        .handshake()
        .map_err(|e| (ExecOpenStep::Handshake, format!("Exec SSH handshake failed: {}", e)))?;
    // Second connection to a host whose key was pinned moments ago in this
    // same connect — compare against that pin rather than running a fresh
    // trust-on-first-use, which would be an attacker-usable race.
    verify_pinned_host_key(&sess2, params, "exec")
        .map_err(|e| (ExecOpenStep::HostKey, translate_ssh_error(&e)))?;
    Ok(sess2)
}

/// Whether a caller-chosen session id is usable. It names the tmux session —
/// `neo-` and its first 8 characters, unquoted on a shell command line — so
/// only ASCII letters, digits and `-`, 8 to 64 of them: a UUID fits.
fn valid_session_id(id: &str) -> bool {
    (8..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Re-establish an SSH connection for auto-reconnect.
///
/// Returns the interactive session (already set to non-blocking), the channel
/// (with PTY + tmux or shell), and — where [`reconnect_reopens_exec`] allows —
/// a fresh exec session for monitoring and SFTP.
fn reconnect_ssh(
    params: &ConnectParams,
    mode: &SessionMode,
    minimal_mode: bool,
    session_id: &str,
) -> Result<(Session, ssh2::Channel, Option<Session>), ReconnectError> {
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
        "interactive" => {
            userauth_interactive(
                &session,
                &params.username,
                params.password.as_deref(),
                &params.host,
                params.port,
                "reconnect",
                session_id,
            )
            .map_err(|e| {
                if e.dismissed {
                    ReconnectError::Dismissed
                } else {
                    ReconnectError::Failed(format!("Keyboard-interactive auth failed: {}", e))
                }
            })?;
        }
        "agent" => {
            userauth_agent_identities(&session, &params.username)
                .map_err(|e| format!("SSH agent auth failed: {}", e))?;
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

    // A fresh exec session, where the reconnect may open one; its failure —
    // a host-key failure included — fails the attempt.
    let exec_sess = if reconnect_reopens_exec(&params.auth_type, minimal_mode) {
        Some(create_exec_connection(params, session_id)?)
    } else {
        None
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
        "interactive" => {
            userauth_interactive(
                &session,
                &params.username,
                params.password.as_deref(),
                &params.host,
                params.port,
                "deploy",
                "",
            )
            .map_err(|e| translate_ssh_error(&e.message))?;
        }
        "agent" => {
            userauth_agent_identities(&session, &params.username)
                .map_err(|e| translate_ssh_error(&e))?;
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
    let out = read_output(&mut channel).unwrap_or_default();
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

#[cfg(test)]
mod remote_path_tests {
    use super::test_support::is_message;
    use super::{safe_path_component, sftp_sendable, validate_remote_path};

    #[test]
    fn traversal_components_are_rejected_not_trimmed() {
        // A readdir answer of "../.." must abort the walk, never quietly become
        // ".." -> "" -> some other directory.
        for bad in ["", ".", "..", "...", "a/b", "a\\b", "a\nb", "a\0b", "/etc"] {
            assert!(
                safe_path_component(bad).is_none(),
                "expected {:?} to be rejected",
                bad
            );
        }
        assert_eq!(safe_path_component("file.txt").as_deref(), Some("file.txt"));
        assert_eq!(safe_path_component(".hidden").as_deref(), Some(".hidden"));
        assert_eq!(safe_path_component("空格 名.txt").as_deref(), Some("空格 名.txt"));
    }

    #[test]
    fn mutating_ops_refuse_root_relative_and_escaping_paths() {
        for bad in ["", "   ", "/", "///", "tmp/x", "~/x", "/tmp/../etc", "/a/b/..", "/tmp/\u{1}"] {
            assert!(
                validate_remote_path(bad).is_err(),
                "expected {:?} to be rejected",
                bad
            );
        }
        assert_eq!(validate_remote_path("/tmp/x").unwrap(), "/tmp/x");
        // Trailing slashes collapse so rmdir("/tmp/x/") == rmdir("/tmp/x").
        assert_eq!(validate_remote_path("/tmp/x//").unwrap(), "/tmp/x");
        // ".." only as a whole component — "..foo" is a legal filename.
        assert_eq!(validate_remote_path("/tmp/..foo").unwrap(), "/tmp/..foo");
    }

    #[test]
    fn whitespace_is_part_of_a_name_and_never_trimmed() {
        // Trimming turned a delete of the decoy "project " into a delete of
        // the directory "project" beside it.
        assert_eq!(validate_remote_path("/srv/project ").unwrap(), "/srv/project ");
        assert_eq!(validate_remote_path("/srv/ lead").unwrap(), "/srv/ lead");
        assert_eq!(validate_remote_path("/srv/a  b/").unwrap(), "/srv/a  b");
        // Nor is a path around its leading slash: that one is relative.
        assert!(validate_remote_path(" /srv/x").is_err());
    }

    #[test]
    fn a_backslash_is_refused_on_every_platform() {
        // ssh2 on Windows sends every `\` as `/`: this passed the `..` check
        // and arrived as /home/alice/notes/../../home/victim/.ssh/id_ed25519.
        let traversal = r"/home/alice/notes\..\..\home\victim\.ssh\id_ed25519";
        let err = validate_remote_path(traversal).unwrap_err();
        assert!(
            is_message(&err, "sftp.err.path_backslash", &[("path", traversal)]),
            "{}",
            err
        );
        assert!(validate_remote_path(r"/srv/back\slash").is_err());
        // Open, read, write and list take a path as given, and refuse it only
        // where ssh2 would rewrite it.
        assert_eq!(sftp_sendable(traversal).is_err(), cfg!(not(unix)));
        assert!(sftp_sendable("/srv/plain name").is_ok());
    }
}

#[cfg(test)]
mod kill_tests {
    use super::validate_kill;

    #[test]
    fn only_four_signals_and_never_init() {
        assert_eq!(validate_kill(4242, 15).unwrap(), "TERM");
        assert_eq!(validate_kill(4242, 9).unwrap(), "KILL");
        assert_eq!(validate_kill(4242, 1).unwrap(), "HUP");
        assert_eq!(validate_kill(4242, 2).unwrap(), "INT");

        // 0 is "my whole process group" to kill(1); 1 is init.
        assert!(validate_kill(0, 15).is_err());
        assert!(validate_kill(1, 15).is_err());

        for sig in [-1, 0, 3, 11, 19, 137] {
            assert!(
                validate_kill(4242, sig).is_err(),
                "signal {} should be refused",
                sig
            );
        }
    }
}

#[cfg(test)]
mod port_tests {
    use super::parse_listening_ports;

    const SS: &str = "\
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   UNCONN 0      0      127.0.0.53%lo:53   0.0.0.0:*         users:((\"systemd-resolve\",pid=123,fd=12))
tcp   LISTEN 0      4096   0.0.0.0:22         0.0.0.0:*         users:((\"sshd\",pid=456,fd=3))
tcp   LISTEN 0      511    [::]:80            [::]:*
";

    const NETSTAT: &str = "\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      456/sshd
tcp6       0      0 :::80                   :::*                    LISTEN      789/nginx: master process
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
";

    #[test]
    fn ss_layout_is_parsed_and_the_header_is_not_a_row() {
        let got = parse_listening_ports(SS);
        assert_eq!(got.len(), 3, "got {:?}", got);

        let dns = got.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(dns.proto, "udp");
        assert_eq!(dns.local_addr, "127.0.0.53%lo");
        assert_eq!(dns.pid, Some(123));
        assert_eq!(dns.process, "systemd-resolve");

        let ssh = got.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(ssh.pid, Some(456));
        assert_eq!(ssh.process, "sshd");

        // ss without -p permission: no Process column at all.
        let http = got.iter().find(|p| p.port == 80).unwrap();
        assert_eq!(http.local_addr, "[::]");
        assert_eq!(http.pid, None);
        assert!(http.process.is_empty());
    }

    #[test]
    fn netstat_layout_is_parsed_including_a_spaced_program_name() {
        let got = parse_listening_ports(NETSTAT);
        assert_eq!(got.len(), 3, "got {:?}", got);

        let ssh = got.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(ssh.proto, "tcp");
        assert_eq!(ssh.local_addr, "0.0.0.0");
        assert_eq!(ssh.pid, Some(456));
        assert_eq!(ssh.process, "sshd");

        // netstat does not quote the program name, so it can carry spaces.
        let http = got.iter().find(|p| p.port == 80).unwrap();
        assert_eq!(http.proto, "tcp6");
        assert_eq!(http.local_addr, "::");
        assert_eq!(http.pid, Some(789));
        assert_eq!(http.process, "nginx: master process");

        // "-" in the PID column means "not allowed to look", not pid 0.
        let dns = got.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(dns.pid, None);
    }

    #[test]
    fn a_process_name_cannot_stand_in_for_the_pid() {
        // A process names itself (15 bytes, prctl), and ss prints the name
        // quoted as it is. The pid is the one ss wrote after it.
        let cases: &[(&str, &str, u32)] = &[
            // (name as parsed, ss's process column, real pid)
            ("pid=812", r#"users:(("pid=812",pid=31337,fd=3))"#, 31337),
            (
                r#"a",pid=812,fd=3"#,
                r#"users:(("a",pid=812,fd=3",pid=31337,fd=3))"#,
                31337,
            ),
            ("a,b", r#"users:(("a,b",pid=4242,fd=5))"#, 4242),
            ("x(y", r#"users:(("x(y",pid=77,fd=4))"#, 77),
            (r#"""#, r#"users:((""",pid=78,fd=4))"#, 78),
            (r#"a b"c"#, r#"users:(("a b"c",pid=79,fd=4))"#, 79),
            // Were ss to escape quotes, `\"` is not the closing one — not even
            // with a `)` in the name.
            (
                r#"\",pid=812,fd=3)"#,
                r#"users:(("\",pid=812,fd=3)",pid=31337,fd=3))"#,
                31337,
            ),
            // Several owners: the first. A thread id may come before fd.
            (
                "nginx",
                r#"users:(("nginx",pid=100,fd=6),("nginx",pid=101,fd=6))"#,
                100,
            ),
            ("java", r#"users:(("java",pid=200,tid=201,fd=7))"#, 200),
        ];
        for (name, users, pid) in cases {
            let line = format!(
                "tcp   LISTEN 0      128    0.0.0.0:8080   0.0.0.0:*   {}",
                users
            );
            let got = parse_listening_ports(&line);
            assert_eq!(got.len(), 1, "{}", line);
            assert_eq!(got[0].pid, Some(*pid), "{}", line);
            assert_eq!(got[0].process, *name, "{}", line);
        }
        // No pid ss could have written: none, rather than a guess.
        for users in [r#"users:(("x\",pid=5,fd=3))"#, r#"users:(("x",pid=,fd=3))"#] {
            let line = format!(
                "tcp   LISTEN 0      128    0.0.0.0:8080   0.0.0.0:*   {}",
                users
            );
            assert_eq!(parse_listening_ports(&line)[0].pid, None, "{}", line);
        }
        // An owner block that does not close on its own line is not a row.
        let open = "tcp   LISTEN 0      128    0.0.0.0:8080   0.0.0.0:*   users:((";
        assert!(parse_listening_ports(open).is_empty());
    }

    #[test]
    fn a_newline_in_a_process_name_cannot_forge_a_row() {
        // ss prints comm — 15 bytes the process picks itself — inside its
        // quotes as it is, so a newline in it splits the line in two. The
        // first name forged "pid 9 listens on port 22" as a netstat row.
        let names = ["\ntcp 0 0 :22 9/", "\nudp 0 0 *:2 1/", "\ntcp 0 0 *:22 -", "x\ntcp 0 0 *:2 "];
        for comm in names {
            assert!(comm.len() <= 15, "{:?}", comm);
            let out = format!(
                "tcp   LISTEN 0      128    0.0.0.0:8080   0.0.0.0:*   \
                 users:((\"{}\",pid=31337,fd=3))\n\
                 tcp   LISTEN 0      511    0.0.0.0:443    0.0.0.0:*   \
                 users:((\"nginx\",pid=100,fd=6))\n",
                comm
            );
            let got = parse_listening_ports(&out);
            // Only the honest row: neither half of the split one.
            assert_eq!(got.len(), 1, "{:?}: {:?}", comm, got);
            assert_eq!((got[0].port, got[0].pid), (443, Some(100)));
        }
    }

    #[test]
    fn every_column_must_be_what_its_layout_puts_there() {
        for bad in [
            // netstat: a pid that is not all digits
            "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN +5/sshd",
            "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 5x/sshd",
            "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN sshd",
            // no real local address, or no peer column
            "tcp 0 0 :22 0.0.0.0:* LISTEN 5/sshd",
            "tcp 0 0 0:22 0.0.0.0:* LISTEN 5/sshd",
            "tcp 0 0 0.0.0.0:22 9/sshd",
            "tcp 0 0 0.0.0.0:22 0.0.0.0:x LISTEN 5/sshd",
            // not tcp/udp, or queues that are not numbers
            "tcpx 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 5/sshd",
            "tcp LISTEN x 128 0.0.0.0:22 0.0.0.0:*",
            "tcp listen 0 128 0.0.0.0:22 0.0.0.0:*",
            // ss: an owner column that is not a whole users:((…)) block
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* 5/sshd",
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"a\"",
        ] {
            assert!(parse_listening_ports(bad).is_empty(), "{}", bad);
        }
        // Zones and brackets are real addresses.
        let ok = parse_listening_ports(
            "udp UNCONN 0 0 [fe80::1]%eth0:546 [::]:* users:((\"dhclient\",pid=77,fd=5))\n\
             udp UNCONN 0 0 0.0.0.0%enp0s3:68 0.0.0.0:*\n\
             udp UNCONN 0 0 [fe80::2%eth1]:547 *:*",
        );
        assert_eq!(ok.len(), 3, "{:?}", ok);
        let dhcp6 = ok.iter().find(|p| p.port == 546).unwrap();
        assert_eq!((dhcp6.local_addr.as_str(), dhcp6.pid), ("[fe80::1]%eth0", Some(77)));
    }

    #[test]
    fn netstat_program_names_are_never_read_as_ss_fields() {
        let out = "\
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      31337/pid=812
tcp        0      0 0.0.0.0:8081            0.0.0.0:*               LISTEN      31338/users:((\"x\",pid=1,fd=3))
";
        let got = parse_listening_ports(out);
        let pids: Vec<_> = got.iter().map(|p| p.pid).collect();
        assert_eq!(pids, vec![Some(31337), Some(31338)]);
        assert_eq!(got[0].process, "pid=812");
    }

    #[test]
    fn short_and_junk_lines_do_not_panic() {
        // The df parser fixed in be39b6b crashed on exactly this shape.
        let junk = "\n \ntcp\ntcp LISTEN\ntcp LISTEN 0\ntcp LISTEN 0 4096\n\
                    tcp 0 0\nProto Recv-Q Send-Q Local Address\n\
                    tcp LISTEN 0 4096 not-an-address 0.0.0.0:*\n\
                    tcp LISTEN 0 4096 0.0.0.0:99999 0.0.0.0:*\n\
                    total 4\nbash: ss: command not found\n";
        assert!(parse_listening_ports(junk).is_empty());
    }
}

#[cfg(test)]
mod cpu_tests {
    use super::{cpu_percent_from, parse_proc_stat, CpuTimes};

    const STAT: &str = "\
cpu  100 0 100 800 0 0 0 0 0 0
cpu0 50 0 50 400 0 0 0 0 0 0
cpu1 50 0 50 400 0 0 0 0 0 0
intr 12345 0 0
ctxt 99
cpufreq 1 2 3
";

    #[test]
    fn aggregate_first_then_each_core() {
        let got = parse_proc_stat(STAT);
        assert_eq!(got.len(), 3, "aggregate + 2 cores, got {:?}", got);
        assert_eq!(got[0].total, 1000);
        assert_eq!(got[0].idle, 800);
        assert_eq!(got[1].total, 500);
    }

    #[test]
    fn non_linux_output_yields_nothing() {
        assert!(parse_proc_stat("").is_empty());
        assert!(parse_proc_stat("cat: /proc/stat: No such file or directory").is_empty());
        // "cpu" prefixed but not a cpu line, and a truncated cpu line.
        assert!(parse_proc_stat("cpufreq 1 2 3\ncpu 1 2\n").is_empty());
    }

    #[test]
    fn percent_is_the_busy_share_of_the_delta() {
        let prev = CpuTimes { total: 1000, idle: 800 };
        let cur = CpuTimes { total: 2000, idle: 1550 };
        // 1000 ticks elapsed, 750 idle -> 25% busy.
        assert!((cpu_percent_from(prev, cur) - 25.0).abs() < 1e-9);

        // First sample of a session: compared against zero, i.e. since boot.
        assert!((cpu_percent_from(CpuTimes::default(), prev) - 20.0).abs() < 1e-9);

        // No elapsed time, and a reboot that rewound the counters.
        assert_eq!(cpu_percent_from(prev, prev), 0.0);
        assert_eq!(cpu_percent_from(cur, prev), 0.0);
    }

    #[test]
    fn hostile_counters_saturate_instead_of_panicking() {
        // /proc/stat is server-supplied text: nothing stops it claiming
        // u64::MAX ticks, and a plain `+` over these panics a debug build.
        let text = format!(
            "cpu  {m} {m} {m} {m} {m} 0 0 0 0 0\ncpu0 {m} 1 1 {m} {m}\n",
            m = u64::MAX
        );
        let got = parse_proc_stat(&text);
        assert_eq!(got.len(), 2, "got {:?}", got);
        assert_eq!(got[0].total, u64::MAX);
        assert_eq!(got[0].idle, u64::MAX);
        assert_eq!(got[1].total, u64::MAX);
        assert_eq!(got[1].idle, u64::MAX);
        let pct = cpu_percent_from(got[1], got[0]);
        assert!((0.0..=100.0).contains(&pct), "{}", pct);
    }
}

#[cfg(test)]
mod blocking_scope_tests {
    use super::{
        bounded, start_sftp_with, BlockingControl, BlockingScope, LIBSSH2_ERROR_CHANNEL_FAILURE,
        LIBSSH2_ERROR_TIMEOUT, SFTP_INIT_TIMEOUT_MS, SFTP_PROBE_TIMEOUT_MS, SFTP_TIMEOUT_MS,
    };
    use ssh2::ErrorCode::Session as Ssh;
    use std::cell::{Cell, RefCell};

    /// Stand-in for a libssh2 session: only the two settings the guard touches.
    struct FakeSession {
        blocking: Cell<bool>,
        timeout: Cell<u32>,
    }

    impl FakeSession {
        /// A minimal-mode shell session between calls: non-blocking, still
        /// carrying the 15 s handshake timeout.
        fn minimal_shell() -> Self {
            Self {
                blocking: Cell::new(false),
                timeout: Cell::new(15_000),
            }
        }
    }

    impl BlockingControl for FakeSession {
        fn is_blocking(&self) -> bool {
            self.blocking.get()
        }
        fn set_blocking(&self, blocking: bool) {
            self.blocking.set(blocking)
        }
        fn timeout(&self) -> u32 {
            self.timeout.get()
        }
        fn set_timeout(&self, timeout_ms: u32) {
            self.timeout.set(timeout_ms)
        }
    }

    fn sftp_init(fail: bool) -> Result<(), String> {
        if fail {
            Err("SFTP init failed: timed out".to_string())
        } else {
            Ok(())
        }
    }

    /// Shaped like `with_sftp`: the guard first, then a step that can leave
    /// through `?`. Records what the session looked like inside.
    fn sftp_op(sess: &FakeSession, fail: bool, inside: &mut (bool, u32)) -> Result<(), String> {
        let _blocking = BlockingScope::enter(sess, SFTP_TIMEOUT_MS);
        *inside = (sess.is_blocking(), sess.timeout());
        sftp_init(fail)?;
        Ok(())
    }

    #[test]
    fn blocking_and_bounded_inside_and_restored_on_drop() {
        let sess = FakeSession::minimal_shell();
        let mut inside = (false, 0);
        sftp_op(&sess, false, &mut inside).unwrap();
        assert_eq!(inside, (true, SFTP_TIMEOUT_MS));
        // The shell reader of a minimal-mode server needs WouldBlock back.
        assert!(!sess.is_blocking());
        assert_eq!(sess.timeout(), 15_000);
    }

    #[test]
    fn restored_when_the_operation_fails_part_way() {
        let sess = FakeSession::minimal_shell();
        let mut inside = (false, 0);
        assert!(sftp_op(&sess, true, &mut inside).is_err());
        assert_eq!(inside, (true, SFTP_TIMEOUT_MS));
        assert!(!sess.is_blocking());
        assert_eq!(sess.timeout(), 15_000);
    }

    #[test]
    fn restores_what_was_there_rather_than_forcing_a_mode() {
        // The separate exec session of an OpenSSH host: blocking, no timeout.
        let sess = FakeSession {
            blocking: Cell::new(true),
            timeout: Cell::new(0),
        };
        drop(BlockingScope::enter(&sess, SFTP_TIMEOUT_MS));
        assert!(sess.is_blocking());
        assert_eq!(sess.timeout(), 0);
    }

    #[test]
    fn the_real_session_type_round_trips_through_the_guard() {
        // Unconnected: only flips libssh2 flags, never touches a socket.
        let sess = ssh2::Session::new().unwrap();
        sess.set_blocking(false);
        sess.set_timeout(15_000);
        {
            let _blocking = BlockingScope::enter(&sess, SFTP_TIMEOUT_MS);
            assert!(sess.is_blocking());
            assert_eq!(sess.timeout(), SFTP_TIMEOUT_MS);
        }
        assert!(!sess.is_blocking());
        assert_eq!(sess.timeout(), 15_000);
    }

    /// `Session::sftp` as `start_sftp_with` calls it, scripted: each call
    /// takes the next outcome — `Err` a libssh2 code — and records the bound
    /// it ran under.
    fn scripted<'a>(
        outcomes: &'a RefCell<Vec<Result<(), i32>>>,
        bounds: &'a RefCell<Vec<u32>>,
    ) -> impl Fn(&FakeSession) -> Result<(), ssh2::Error> + 'a {
        move |sess| {
            bounds.borrow_mut().push(sess.timeout());
            outcomes
                .borrow_mut()
                .remove(0)
                .map_err(|code| ssh2::Error::new(Ssh(code), "scripted"))
        }
    }

    /// Start SFTP on `sess` against `script`: what came back, and how many
    /// calls it took.
    fn start(sess: &FakeSession, script: Vec<Result<(), i32>>) -> (Result<(), ssh2::ErrorCode>, usize) {
        let outcomes = RefCell::new(script);
        let bounds = RefCell::new(Vec::new());
        let got = start_sftp_with(sess, scripted(&outcomes, &bounds)).map_err(|e| e.code());
        assert!(bounds.borrow().iter().all(|b| *b == SFTP_INIT_TIMEOUT_MS));
        (got, bounds.into_inner().len())
    }

    #[test]
    fn sftp_starts_under_its_own_short_bound_and_leaves_the_long_one() {
        // On a black-holed link the start and the probe run out before the
        // rebuild can begin: seconds, where SFTP_TIMEOUT_MS alone was a minute.
        const _: () = assert!(SFTP_INIT_TIMEOUT_MS <= 15_000);
        const _: () = assert!(SFTP_INIT_TIMEOUT_MS + SFTP_PROBE_TIMEOUT_MS <= 20_000);
        const _: () = assert!(SFTP_INIT_TIMEOUT_MS * 4 <= SFTP_TIMEOUT_MS);
        let sess = FakeSession::minimal_shell();
        {
            let _blocking = BlockingScope::enter(&sess, SFTP_TIMEOUT_MS);
            assert_eq!(start(&sess, vec![Ok(())]), (Ok(()), 1));
            // What follows — the listing, the transfer — has the long bound.
            assert_eq!(sess.timeout(), SFTP_TIMEOUT_MS);
            let probe_bound = bounded(&sess, SFTP_PROBE_TIMEOUT_MS, |s| s.timeout());
            assert_eq!(probe_bound, SFTP_PROBE_TIMEOUT_MS);
            assert_eq!(sess.timeout(), SFTP_TIMEOUT_MS);
        }
        // And the session's own settings come back.
        assert!(!sess.is_blocking());
        assert_eq!(sess.timeout(), 15_000);
    }

    #[test]
    fn a_timed_out_start_is_not_waited_out_twice_and_any_other_is_made_once_more() {
        let sess = FakeSession::minimal_shell();
        // A black-holed link: straight on, no second wait.
        assert_eq!(
            start(&sess, vec![Err(LIBSSH2_ERROR_TIMEOUT)]),
            (Err(Ssh(LIBSSH2_ERROR_TIMEOUT)), 1)
        );
        // The call that frees the channel a failed start left open fails
        // without trying; it is made now, and the first failure is reported.
        assert_eq!(
            start(&sess, vec![Err(LIBSSH2_ERROR_CHANNEL_FAILURE), Err(i32::MIN)]),
            (Err(Ssh(LIBSSH2_ERROR_CHANNEL_FAILURE)), 2)
        );
        // After a start that failed before opening a channel, the second call
        // is a real try.
        assert_eq!(
            start(&sess, vec![Err(LIBSSH2_ERROR_CHANNEL_FAILURE), Ok(())]),
            (Ok(()), 2)
        );
    }
}

#[cfg(test)]
mod resume_tests {
    use super::{plan_copy, plan_resume, ResumeMode, ResumePlan, TransferProgress};
    use std::io::{Cursor, Read};
    use std::sync::atomic::Ordering;

    fn bytes(n: usize, salt: u8) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8 ^ salt).collect()
    }

    /// One file transfer, decided the way `upload_one_file` /
    /// `download_one_file` decide and written the way they write: append after
    /// a resume, truncate otherwise. Returns the start offset and what the
    /// destination holds afterwards.
    fn transfer(mode: ResumeMode, dest: &[u8], src: &[u8]) -> (u64, Vec<u8>) {
        let progress = TransferProgress::new();
        let mut source = Cursor::new(src.to_vec());
        let start = plan_copy(
            mode,
            &mut source,
            src.len() as u64,
            dest.len() as u64,
            || Some(Cursor::new(dest.to_vec())),
            &progress,
            0,
        )
        .unwrap();
        let mut rest = Vec::new();
        source.read_to_end(&mut rest).unwrap();
        let mut after = if start > 0 { dest.to_vec() } else { Vec::new() };
        after.extend_from_slice(&rest);
        (start, after)
    }

    #[test]
    fn grown_and_modified_file_is_overwritten_not_spliced() {
        // main.rs grew from 1000 to 1200 bytes and was edited in its first
        // 1000: length alone said "resume", which wrote old head + new tail.
        let old = bytes(1000, 0);
        let mut new = bytes(1200, 0);
        new[500] ^= 0xFF;
        let (start, after) = transfer(ResumeMode::IfPrefixMatches, &old, &new);
        assert_eq!(start, 0, "a modified prefix must never be resumed");
        assert_eq!(after, new);
    }

    #[test]
    fn interrupted_copy_with_an_identical_prefix_is_resumed() {
        // Several 32 KiB chunks, cut off mid-chunk.
        let full = bytes(200_000, 7);
        let (start, after) = transfer(ResumeMode::IfPrefixMatches, &full[..70_001], &full);
        assert_eq!(start, 70_001);
        assert_eq!(after, full);
    }

    #[test]
    fn a_difference_in_the_last_byte_of_the_prefix_is_caught() {
        let full = bytes(100_000, 3);
        let mut partial = full[..65_536].to_vec();
        *partial.last_mut().unwrap() ^= 1;
        let (start, after) = transfer(ResumeMode::IfPrefixMatches, &partial, &full);
        assert_eq!(start, 0);
        assert_eq!(after, full);
    }

    #[test]
    fn equal_larger_or_empty_destination_is_overwritten_without_reading_it() {
        for (dest_len, src_len) in [(1000u64, 1000u64), (1500, 1000), (0, 1000)] {
            let mut compared = false;
            let plan = plan_resume(ResumeMode::IfPrefixMatches, dest_len, src_len, |_| {
                compared = true;
                true
            });
            assert_eq!(plan, ResumePlan::Overwrite, "{} onto {}", src_len, dest_len);
            assert!(!compared, "nothing to compare for {} onto {}", src_len, dest_len);
        }
    }

    #[test]
    fn folder_transfers_never_resume_even_an_identical_prefix() {
        let full = bytes(10_000, 1);
        let (start, after) = transfer(ResumeMode::Never, &full[..4_000], &full);
        assert_eq!(start, 0);
        assert_eq!(after, full);
    }

    #[test]
    fn unreadable_or_short_destination_means_overwrite_from_byte_zero() {
        let progress = TransferProgress::new();

        let mut source = Cursor::new(bytes(10_000, 9));
        let start = plan_copy(
            ResumeMode::IfPrefixMatches,
            &mut source,
            10_000,
            4_000,
            || None::<Cursor<Vec<u8>>>,
            &progress,
            0,
        )
        .unwrap();
        assert_eq!(start, 0);

        // Claims 40 000 bytes but yields 35 000 identical ones: the first
        // 32 KiB chunk matched and consumed that much of the source, so the
        // rewrite must rewind it or the copy would lose its head.
        let full = bytes(50_000, 9);
        let mut source = Cursor::new(full.clone());
        let start = plan_copy(
            ResumeMode::IfPrefixMatches,
            &mut source,
            50_000,
            40_000,
            || Some(Cursor::new(full[..35_000].to_vec())),
            &progress,
            0,
        )
        .unwrap();
        assert_eq!(start, 0);
        assert_eq!(source.position(), 0);
    }

    #[test]
    fn cancel_during_the_comparison_stops_before_anything_is_written() {
        let full = bytes(10_000, 5);
        let progress = TransferProgress::new();
        progress.finished.store(true, Ordering::Relaxed);
        let mut source = Cursor::new(full.clone());
        let result = plan_copy(
            ResumeMode::IfPrefixMatches,
            &mut source,
            10_000,
            4_000,
            || Some(Cursor::new(full[..4_000].to_vec())),
            &progress,
            0,
        );
        assert_eq!(result, Err("Transfer cancelled".to_string()));
    }

    #[test]
    fn kept_bytes_count_toward_the_aggregate_bar() {
        let full = bytes(50_000, 2);
        let progress = TransferProgress::new();
        let mut source = Cursor::new(full.clone());
        let start = plan_copy(
            ResumeMode::IfPrefixMatches,
            &mut source,
            50_000,
            40_000,
            || Some(Cursor::new(full[..40_000].to_vec())),
            &progress,
            1_000,
        )
        .unwrap();
        assert_eq!(start, 40_000);
        assert_eq!(progress.transferred.load(Ordering::Relaxed), 41_000);
    }
}

#[cfg(test)]
mod remove_tests {
    use super::test_support::is_message;
    use super::{
        check_chmod, check_unchanged, deletable_entry_name, download_entry_name, plan_remove,
        remove_confirmed, sftp_remove_recursive, EntryKind, RemoteTree, RemovePlan,
        MAX_SFTP_DEPTH,
    };
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    /// In-memory remote tree: directory path -> raw entry names. `links` are
    /// symlinks, whatever they point at — `lstat` says so. Anything else not
    /// listed as a directory is a plain file. Every removal is logged in
    /// order, as (path, was_a_directory). `lossy` plays a Windows build's
    /// ssh2, whose listed names may carry its own U+FFFD.
    #[derive(Default)]
    struct FakeTree {
        dirs: HashMap<Vec<u8>, Vec<Vec<u8>>>,
        links: HashSet<Vec<u8>>,
        removed: RefCell<Vec<(Vec<u8>, bool)>>,
        lossy: bool,
    }

    impl FakeTree {
        fn dir(mut self, path: &[u8], names: &[&[u8]]) -> Self {
            self.dirs
                .insert(path.to_vec(), names.iter().map(|n| n.to_vec()).collect());
            self
        }
        fn link(mut self, path: &[u8]) -> Self {
            self.links.insert(path.to_vec());
            self
        }
        fn removed(&self) -> Vec<(Vec<u8>, bool)> {
            self.removed.borrow().clone()
        }
    }

    impl RemoteTree for FakeTree {
        fn kind_nofollow(&self, path: &[u8]) -> Result<EntryKind, String> {
            Ok(if self.links.contains(path) {
                EntryKind::Symlink
            } else if self.dirs.contains_key(path) {
                EntryKind::Dir
            } else {
                EntryKind::File
            })
        }
        fn entry_names(&self, path: &[u8]) -> Result<Vec<Vec<u8>>, String> {
            Ok(self.dirs.get(path).cloned().unwrap_or_default())
        }
        fn remove_file(&self, path: &[u8]) -> Result<(), String> {
            self.removed.borrow_mut().push((path.to_vec(), false));
            Ok(())
        }
        fn remove_dir(&self, path: &[u8]) -> Result<(), String> {
            self.removed.borrow_mut().push((path.to_vec(), true));
            Ok(())
        }
        fn lossy_names(&self) -> bool {
            self.lossy
        }
    }

    #[test]
    fn lossily_listed_names_are_skipped_with_the_directories_above_them() {
        // A GBK name as a Windows build lists it: U+FFFD where the bytes were.
        let gbk = "\u{FFFD}\u{FFFD}.txt".as_bytes();
        let tree = FakeTree {
            lossy: true,
            ..FakeTree::default()
        }
        .dir(b"/srv/app", &[b"a.txt", b"sub", b"keep"])
        .dir(b"/srv/app/sub", &[b"ok.txt", gbk, b"later.txt"])
        .dir(b"/srv/app/keep", &[b"x.txt"]);
        let err = sftp_remove_recursive(&tree, b"/srv/app").unwrap_err();
        assert!(
            is_message(&err, "sftp.err.skipped_names", &[("count", "1")]),
            "{}",
            err
        );
        // Everything else is gone. The lossy spelling was never sent, and the
        // two directories it keeps from being empty were never tried — an
        // rmdir failing there would have stopped the delete half-way.
        let expect: Vec<(Vec<u8>, bool)> = vec![
            (b"/srv/app/a.txt".to_vec(), false),
            (b"/srv/app/sub/ok.txt".to_vec(), false),
            (b"/srv/app/sub/later.txt".to_vec(), false),
            (b"/srv/app/keep/x.txt".to_vec(), false),
            (b"/srv/app/keep".to_vec(), true),
        ];
        assert_eq!(tree.removed(), expect);
    }

    #[test]
    fn a_lossy_listing_still_refuses_a_bad_name_before_any_delete() {
        let gbk = "\u{FFFD}.txt".as_bytes();
        let tree = FakeTree {
            lossy: true,
            ..FakeTree::default()
        }
        .dir(b"/srv/app", &[gbk, b"sub"])
        .dir(b"/srv/app/sub", &[b"ok.txt", b".."]);
        let err = sftp_remove_recursive(&tree, b"/srv/app").unwrap_err();
        assert!(
            is_message(&err, "sftp.err.bad_entry", &[("path", "/srv/app/sub")]),
            "{}",
            err
        );
        assert!(tree.removed().is_empty(), "deleted {:?}", tree.removed());
    }

    #[test]
    fn a_u_fffd_the_server_itself_listed_is_deleted_like_any_name() {
        // ssh2 on unix hands raw bytes over: the name is exactly the server's.
        let name = "caf\u{FFFD}".as_bytes();
        let tree = FakeTree::default().dir(b"/srv/app", &[name]);
        sftp_remove_recursive(&tree, b"/srv/app").unwrap();
        let expect: Vec<(Vec<u8>, bool)> = vec![
            ([&b"/srv/app/"[..], name].concat(), false),
            (b"/srv/app".to_vec(), true),
        ];
        assert_eq!(tree.removed(), expect);
    }

    #[test]
    fn a_download_skips_the_names_it_could_not_spell_back() {
        // Windows: U+FFFD from ssh2 names nothing on the server, or another file.
        assert_eq!(download_entry_name(Some("caf\u{FFFD}.txt"), true), None);
        // Unix: bytes come through, so a U+FFFD is the server's own.
        assert_eq!(
            download_entry_name(Some("caf\u{FFFD}.txt"), false).as_deref(),
            Some("caf\u{FFFD}.txt")
        );
        // Unix: not text at all, where the transfer builds its paths as text.
        assert_eq!(download_entry_name(None, false), None);
        for bad in ["", "..", "a/b", "a\\b", "ctl\u{1}"] {
            assert_eq!(download_entry_name(Some(bad), false), None, "{:?}", bad);
        }
        for lossy in [true, false] {
            assert_eq!(
                download_entry_name(Some("测试.txt"), lossy).as_deref(),
                Some("测试.txt")
            );
        }
    }

    #[test]
    fn one_bad_name_deep_in_the_tree_deletes_nothing() {
        // Good entries are listed before the bad one on purpose: a pass that
        // checked while it deleted had already removed them by then.
        for bad in [&b"x/../../etc"[..], b"", b"a\0b", b".."] {
            let tree = FakeTree::default()
                .dir(b"/srv/app", &[b"a.txt", b"sub", b"z.txt"])
                .dir(b"/srv/app/sub", &[b"ok.txt", bad, b"later.txt"]);
            let result = sftp_remove_recursive(&tree, b"/srv/app");
            assert!(result.is_err(), "{:?} must refuse the delete", bad);
            assert!(tree.removed().is_empty(), "{:?}: deleted {:?}", bad, tree.removed());
        }
    }

    #[cfg(unix)]
    #[test]
    fn legal_linux_names_are_deleted_children_first() {
        let odd: [&[u8]; 3] = [b"back\\slash", b"ctl\x01name", b"\xff\xfe-latin1"];
        let tree = FakeTree::default()
            .dir(b"/srv/app", &[odd[0], odd[1], odd[2], b"dir"])
            .dir(b"/srv/app/dir", &[b"inner"]);
        sftp_remove_recursive(&tree, b"/srv/app").unwrap();
        let expect: Vec<(Vec<u8>, bool)> = vec![
            ([&b"/srv/app/"[..], odd[0]].concat(), false),
            ([&b"/srv/app/"[..], odd[1]].concat(), false),
            ([&b"/srv/app/"[..], odd[2]].concat(), false),
            (b"/srv/app/dir/inner".to_vec(), false),
            (b"/srv/app/dir".to_vec(), true),
            (b"/srv/app".to_vec(), true),
        ];
        assert_eq!(tree.removed(), expect);
    }

    #[cfg(not(unix))]
    #[test]
    fn names_ssh2_would_rewrite_are_refused_before_any_delete() {
        let tree = FakeTree::default().dir(b"/srv/app", &[b"a.txt", b"back\\slash"]);
        assert!(sftp_remove_recursive(&tree, b"/srv/app").is_err());
        assert!(tree.removed().is_empty());
    }

    #[test]
    fn a_non_directory_root_is_unlinked_not_listed() {
        // What lstat reports for a symlink to a directory: not a directory.
        let tree = FakeTree::default();
        sftp_remove_recursive(&tree, b"/srv/link-to-dir").unwrap();
        assert_eq!(tree.removed(), vec![(b"/srv/link-to-dir".to_vec(), false)]);
    }

    #[test]
    fn a_tree_past_the_depth_limit_is_refused_before_any_delete() {
        let mut tree = FakeTree::default();
        let mut path = b"/deep".to_vec();
        for _ in 0..=MAX_SFTP_DEPTH + 1 {
            tree = tree.dir(&path, &[b"f.txt", b"d"]);
            path.extend_from_slice(b"/d");
        }
        assert!(sftp_remove_recursive(&tree, b"/deep").is_err());
        assert!(tree.removed().is_empty());
    }

    #[test]
    fn a_file_confirmed_where_a_directory_now_is_deletes_nothing() {
        // The decoy: "Delete this file?" confirmed on a row whose path names a
        // directory with a tree under it.
        let tree = FakeTree::default()
            .dir(b"/srv/project", &[b"src", b"README"])
            .dir(b"/srv/project/src", &[b"main.rs"]);
        let err = remove_confirmed(&tree, b"/srv/project", Some(EntryKind::File)).unwrap_err();
        assert!(
            is_message(&err, "sftp.err.changed", &[("path", "/srv/project")]),
            "{}",
            err
        );
        assert!(tree.removed().is_empty(), "deleted {:?}", tree.removed());
    }

    #[test]
    fn only_a_directory_confirmed_as_one_is_deleted_with_its_tree() {
        let tree = FakeTree::default().dir(b"/srv/project", &[b"a"]);
        remove_confirmed(&tree, b"/srv/project", Some(EntryKind::Dir)).unwrap();
        let expect: Vec<(Vec<u8>, bool)> = vec![
            (b"/srv/project/a".to_vec(), false),
            (b"/srv/project".to_vec(), true),
        ];
        assert_eq!(tree.removed(), expect);
        // A caller that does not say what the user confirmed never recurses:
        // rmdir alone, which a non-empty directory refuses.
        let tree = FakeTree::default().dir(b"/srv/project", &[b"a"]);
        remove_confirmed(&tree, b"/srv/project", None).unwrap();
        assert_eq!(tree.removed(), vec![(b"/srv/project".to_vec(), true)]);
    }

    #[test]
    fn a_symlink_to_a_directory_is_unlinked_never_recursed() {
        // The link, and what it points at, which must survive.
        let tree = FakeTree::default()
            .link(b"/srv/shared")
            .dir(b"/srv/shared", &[b"precious"]);
        remove_confirmed(&tree, b"/srv/shared", Some(EntryKind::Symlink)).unwrap();
        assert_eq!(tree.removed(), vec![(b"/srv/shared".to_vec(), false)]);
        // Confirmed as a directory — what a stat-based listing showed — it is
        // refused rather than followed.
        let tree = FakeTree::default()
            .link(b"/srv/shared")
            .dir(b"/srv/shared", &[b"precious"]);
        let err = remove_confirmed(&tree, b"/srv/shared", Some(EntryKind::Dir)).unwrap_err();
        assert!(is_message(&err, "sftp.err.changed", &[("path", "/srv/shared")]), "{}", err);
        assert!(tree.removed().is_empty());
        // Inside a confirmed tree a link is unlinked like a file.
        let tree = FakeTree::default()
            .dir(b"/srv/app", &[b"ln"])
            .link(b"/srv/app/ln")
            .dir(b"/srv/app/ln", &[b"precious"]);
        remove_confirmed(&tree, b"/srv/app", Some(EntryKind::Dir)).unwrap();
        let expect: Vec<(Vec<u8>, bool)> = vec![
            (b"/srv/app/ln".to_vec(), false),
            (b"/srv/app".to_vec(), true),
        ];
        assert_eq!(tree.removed(), expect);
    }

    #[test]
    fn what_a_delete_does_for_each_confirmed_and_actual_kind() {
        use EntryKind::*;
        for confirmed in [File, Dir, Symlink, Other] {
            for actual in [File, Dir, Symlink, Other] {
                let plan = plan_remove(Some(confirmed), actual, "/p");
                assert_eq!(plan.is_err(), confirmed != actual, "{:?} -> {:?}", confirmed, actual);
            }
        }
        assert_eq!(plan_remove(Some(Dir), Dir, "/p"), Ok(RemovePlan::Tree));
        for kind in [File, Symlink, Other] {
            assert_eq!(plan_remove(Some(kind), kind, "/p"), Ok(RemovePlan::Unlink));
        }
        assert_eq!(plan_remove(None, Dir, "/p"), Ok(RemovePlan::Rmdir));
        assert_eq!(plan_remove(None, Symlink, "/p"), Ok(RemovePlan::Unlink));
    }

    #[test]
    fn chmod_and_rename_refuse_a_changed_entry_and_chmod_a_symlink() {
        use EntryKind::*;
        let err = check_unchanged(Some(File), Dir, "/srv/x").unwrap_err();
        assert!(is_message(&err, "sftp.err.changed", &[("path", "/srv/x")]), "{}", err);
        assert!(check_unchanged(Some(Dir), Dir, "/srv/x").is_ok());
        assert!(check_unchanged(None, Dir, "/srv/x").is_ok());
        // setstat follows a link: a chmod 644 of "notes" -> ~/.ssh/id_ed25519
        // would have made the private key world-readable.
        for confirmed in [Some(Symlink), None] {
            let err = check_chmod(confirmed, Symlink, "/srv/notes").unwrap_err();
            assert!(
                is_message(&err, "sftp.err.chmod_symlink", &[("path", "/srv/notes")]),
                "{}",
                err
            );
        }
        assert!(check_chmod(Some(File), File, "/srv/f").is_ok());
        assert!(check_chmod(Some(File), Dir, "/srv/f").is_err());
    }

    #[test]
    fn delete_validator_refuses_only_names_that_address_something_else() {
        for bad in [&b""[..], b".", b"..", b"a/b", b"/etc", b"a\0b"] {
            assert!(!deletable_entry_name(bad), "{:?} should be refused", bad);
        }
        for good in [
            &b"file.txt"[..],
            b".hidden",
            b"...",
            b"-rf",
            b"a\nb",
            "空格 名.txt".as_bytes(),
        ] {
            assert!(deletable_entry_name(good), "{:?} should be accepted", good);
        }
        // Legal on the server, and sent verbatim by ssh2 on unix only.
        for name in [&b"a\\b"[..], b"\xff\xfe"] {
            assert_eq!(deletable_entry_name(name), cfg!(unix), "{:?}", name);
        }
    }
}

#[cfg(test)]
mod i18n_key_tests {
    /// This file and the translation tables, exactly as compiled.
    const SSH_SRC: &str = include_str!("mod.rs");
    const I18N_SRC: &str = include_str!("../i18n.rs");

    /// Every key this file passes to `i18n::t` / `i18n::tf` as a literal.
    fn keys_used_here() -> Vec<&'static str> {
        let mut keys = Vec::new();
        // Split so this function's own text does not match.
        for call in [concat!("i18n::", "t("), concat!("i18n::", "tf(")] {
            for (at, _) in SSH_SRC.match_indices(call) {
                let rest = SSH_SRC[at + call.len()..].trim_start();
                if let Some(lit) = rest.strip_prefix('"') {
                    if let Some(end) = lit.find('"') {
                        keys.push(&lit[..end]);
                    }
                }
            }
        }
        keys
    }

    /// One `static EN` / `static ZH` table's source text.
    fn table(name: &str) -> &'static str {
        let start = I18N_SRC
            .find(&format!("static {}:", name))
            .expect("translation table");
        let rest = &I18N_SRC[start..];
        &rest[..rest.find("\n});").expect("end of table")]
    }

    #[test]
    fn ssh_and_sftp_errors_are_translated_in_both_tables() {
        let used = keys_used_here();
        // The errors a review found shown raw in English under the Chinese UI.
        for key in [
            "sftp.err.path_relative",
            "sftp.err.mkdir",
            "sftp.err.not_dir",
            "sftp.err.bad_entry",
            "sftp.err.delete",
            "process.err.kill",
            "process.err.kill_exit",
            "auth.err.no_answer",
            "auth.err.agent_rejected",
            "exec.err.needs_reconnect",
            "exec.err.cooldown",
            "ssh.err.reconnect_cancelled",
            "sftp.err.skipped_names",
            "transfer.err.not_dir",
            "transfer.err.local_empty",
            "transfer.err.local_mkdir",
            "transfer.err.local_read_dir",
            "sftp.err.changed",
            "sftp.err.chmod_symlink",
            "sftp.err.path_backslash",
            "sftp.err.stat",
            "auth.err.exec_interactive",
            "auth.err.exec_agent",
            "ssh.err.bad_session_id",
            "sftp.err.unverified",
            "sftp.err.not_utf8",
            "sftp.err.start",
        ] {
            assert!(used.contains(&key), "{} is not routed through i18n", key);
        }
        // The literals a review found reaching the error dialog in English.
        // Split so this test's own text does not match.
        for literal in [
            concat!("is not a ", "directory\""),
            concat!("\"local directory ", "is empty\""),
            concat!("\"Failed to create ", "local directory"),
            concat!("\"Failed to read ", "local directory"),
            concat!("\"Exec keyboard-interactive ", "auth failed"),
            concat!("\"Exec SSH agent ", "auth failed"),
            concat!("\"Failed to stat ", "remote file"),
        ] {
            assert!(
                !SSH_SRC.contains(literal),
                "{} is still an English literal",
                literal
            );
        }
        let (en, zh) = (table("EN"), table("ZH"));
        for key in used {
            let entry = format!("m.insert(\"{}\",", key);
            assert!(en.contains(&entry), "{} is missing from the EN table", key);
            assert!(zh.contains(&entry), "{} is missing from the ZH table", key);
        }
    }
}

/// Helpers shared by the auth-pass test modules below.
#[cfg(test)]
mod test_support {
    use super::{
        ConnectParams, ExecGate, PinnedHostKey, Session, SessionMode, SshManager, SshSession,
    };
    use parking_lot::Mutex;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Every translation of `key`, with `params` filled in, read from the
    /// tables' source rather than through the process-wide locale — another
    /// test in this binary flips that locale while it runs.
    pub(super) fn translations(key: &str, params: &[(&str, &str)]) -> Vec<String> {
        const SRC: &str = include_str!("../i18n.rs");
        let needle = format!("m.insert(\"{}\", \"", key);
        SRC.match_indices(&needle)
            .map(|(at, _)| {
                let rest = &SRC[at + needle.len()..];
                let mut text = rest[..rest.find("\");").expect("end of entry")].to_string();
                for (name, value) in params {
                    text = text.replace(&format!("{{{}}}", name), value);
                }
                text
            })
            .collect()
    }

    /// `err` is exactly `key`'s message, in either language.
    pub(super) fn is_message(err: &str, key: &str, params: &[(&str, &str)]) -> bool {
        let all = translations(key, params);
        assert_eq!(all.len(), 2, "{} should be in both tables", key);
        all.iter().any(|t| t == err)
    }

    /// A registered session whose exec connection is dead and whose host
    /// answers every dial by hanging up.
    pub(super) fn manager_with(auth_type: &str, port: u16) -> (SshManager, String) {
        let (mgr, _events) = SshManager::new();
        let params = ConnectParams {
            host: "127.0.0.1".to_string(),
            port,
            username: "alice".to_string(),
            auth_type: auth_type.to_string(),
            password: Some("pw".to_string()),
            private_key: None,
            passphrase: None,
            proxy_id: None,
            // Pinned, so nothing here reads the real ~/.ssh/known_hosts.
            pinned_host_key: Some(PinnedHostKey {
                key: vec![7; 32],
                alg: "ssh-ed25519".to_string(),
                fingerprint: "SHA256:test".to_string(),
            }),
        };
        let sid = "exec-gate-test".to_string();
        mgr.sessions.write().insert(
            sid.clone(),
            SshSession {
                session_id: sid.clone(),
                connection_id: "c".to_string(),
                writer: tokio::sync::mpsc::channel(1).0,
                exec_session: Some(Arc::new(Mutex::new(Session::new().unwrap()))),
                params,
                mode: SessionMode::RawShell,
                minimal_mode: false,
                stop: Arc::new(AtomicBool::new(false)),
                host_key_fp: String::new(),
                exec_gate: Arc::new(Mutex::new(ExecGate::default())),
            },
        );
        (mgr, sid)
    }

    pub(super) fn dialled(dials: &AtomicUsize) -> usize {
        dials.load(Ordering::SeqCst)
    }

    /// A loopback "server" that accepts and hangs up at once, counting dials.
    /// A connection attempt against it fails its SSH handshake immediately —
    /// and only after the count went up, so the count is exact when the
    /// caller gets its error back.
    pub(super) fn hang_up_server() -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dials);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(conn);
            }
        });
        (port, dials)
    }
}

#[cfg(test)]
mod interactive_timeout_tests {
    use super::*;
    use std::cell::Cell;

    /// A session that records the libssh2 timeout in force while the
    /// keyboard-interactive exchange — and with it the user's think time —
    /// runs.
    struct FakeKbdSession {
        timeout: Cell<u32>,
        during_prompt: Cell<Option<u32>>,
        accept: bool,
    }

    impl FakeKbdSession {
        fn new(timeout: u32, accept: bool) -> Self {
            Self {
                timeout: Cell::new(timeout),
                during_prompt: Cell::new(None),
                accept,
            }
        }
    }

    impl BlockingControl for FakeKbdSession {
        fn is_blocking(&self) -> bool {
            true
        }
        fn set_blocking(&self, _blocking: bool) {}
        fn timeout(&self) -> u32 {
            self.timeout.get()
        }
        fn set_timeout(&self, timeout_ms: u32) {
            self.timeout.set(timeout_ms)
        }
    }

    impl KeyboardInteractive for FakeKbdSession {
        fn keyboard_interactive(
            &self,
            _username: &str,
            _prompter: &mut GuiPrompter<'_>,
        ) -> Result<(), ssh2::Error> {
            self.during_prompt.set(Some(self.timeout.get()));
            if self.accept {
                Ok(())
            } else {
                Err(ssh2::Error::new(
                    ssh2::ErrorCode::Session(-18),
                    "Authentication failed (keyboard-interactive)",
                ))
            }
        }
    }

    #[test]
    fn think_time_runs_with_no_timeout_and_the_old_bound_comes_back() {
        // The timeouts the call sites carry into auth: test_connection 10 s,
        // try_handshake / exec / deploy 15 s, reconnect none.
        for before in [10_000, 15_000, 0] {
            for accept in [true, false] {
                let sess = FakeKbdSession::new(before, accept);
                let result =
                    userauth_interactive(&sess, "alice", None, "host", 22, "shell", "sid-1");
                assert_eq!(result.is_ok(), accept, "{:?}", result);
                assert_eq!(
                    sess.during_prompt.get(),
                    Some(0),
                    "the prompt ran under a {} ms timeout — a code typed after it fails",
                    before
                );
                assert_eq!(
                    sess.timeout.get(),
                    before,
                    "timeout not restored (accept={})",
                    accept
                );
            }
        }
    }

    /// Shaped like an auth step: the guard first, then a step that can leave
    /// through `?`.
    fn guarded_step(sess: &FakeKbdSession, fail: bool, seen: &Cell<u32>) -> Result<(), String> {
        let _no_timeout = PromptTimeoutScope::enter(sess);
        seen.set(sess.timeout());
        if fail {
            Err("challenge cancelled".to_string())?;
        }
        Ok(())
    }

    #[test]
    fn the_guard_restores_on_every_way_out() {
        for fail in [false, true] {
            let sess = FakeKbdSession::new(15_000, true);
            let seen = Cell::new(u32::MAX);
            assert_eq!(guarded_step(&sess, fail, &seen).is_err(), fail);
            assert_eq!(seen.get(), 0);
            assert_eq!(sess.timeout.get(), 15_000, "fail={}", fail);
        }
    }

    #[test]
    fn the_real_session_type_round_trips_through_the_guard() {
        // Unconnected: only flips a libssh2 field, never touches a socket.
        let sess = ssh2::Session::new().unwrap();
        sess.set_timeout(15_000);
        {
            let _no_timeout = PromptTimeoutScope::enter(&sess);
            assert_eq!(sess.timeout(), 0);
        }
        assert_eq!(sess.timeout(), 15_000);
    }
}

#[cfg(test)]
mod prompter_tests {
    use super::*;
    use std::sync::mpsc::RecvTimeoutError::{Disconnected, Timeout};

    const SECOND: Duration = Duration::from_secs(1);

    fn prompter(gui: mpsc::Sender<AuthChallenge>, password: Option<&str>) -> GuiPrompter<'_> {
        GuiPrompter {
            session_id: "tab-7-session",
            target: "alice@host:22",
            purpose: "reconnect",
            gui: Some(gui),
            password,
            failure: None,
            dismissed: false,
        }
    }

    fn masked(text: &str) -> [ssh2::Prompt<'_>; 1] {
        [ssh2::Prompt {
            text: text.into(),
            echo: false,
        }]
    }

    fn one(text: &str, echo: bool) -> Vec<(String, bool)> {
        vec![(text.to_string(), echo)]
    }

    #[test]
    fn otp_prompts_that_mention_a_password_do_not_get_the_saved_one() {
        for otp in [
            "One-time password (OATH) for alice: ",
            "One time password: ",
            "OTP password: ",
            "Password + token: ",
            "Enter your 2FA password: ",
            "Verification password: ",
            "Google Authenticator password: ",
            "Passcode or password: ",
            "Second factor password: ",
            "动态密码：",
            "一次性密码：",
            "令牌密码：",
            "短信验证码或密码：",
            "二次验证密码：",
            "双因素认证密码：",
        ] {
            let mut saved = Some("pw");
            assert_eq!(
                saved_password_answer(&one(otp, false), &mut saved),
                None,
                "{}",
                otp
            );
            assert_eq!(saved, Some("pw"), "{:?} used up the saved password", otp);
        }
        for plain in [
            "Password: ",
            "alice@web's password: ",
            "PASSWORD:",
            "密码：",
        ] {
            let mut saved = Some("pw");
            assert_eq!(
                saved_password_answer(&one(plain, false), &mut saved),
                Some(vec!["pw".to_string()]),
                "{}",
                plain
            );
            // Once per login: a second ask means the first answer was refused.
            assert_eq!(
                saved_password_answer(&one(plain, false), &mut saved),
                None,
                "{}",
                plain
            );
        }
        // Echoed, or not alone in its round: the user answers.
        let mut saved = Some("pw");
        assert_eq!(
            saved_password_answer(&one("Password: ", true), &mut saved),
            None
        );
        let two = vec![
            ("Password: ".to_string(), false),
            ("Code: ".to_string(), true),
        ];
        assert_eq!(saved_password_answer(&two, &mut saved), None);
        assert_eq!(saved, Some("pw"));
    }

    #[test]
    fn the_saved_password_answers_one_plain_prompt_and_the_rest_go_to_the_user() {
        let (tx, rx) = mpsc::channel::<AuthChallenge>();
        let gui = std::thread::spawn(move || {
            let mut asked = Vec::new();
            while let Ok(challenge) = rx.recv() {
                asked.push(challenge.prompt.prompts[0].0.clone());
                challenge.reply.send(vec!["typed".to_string()]).unwrap();
            }
            asked
        });
        let mut p = prompter(tx, Some("saved-pw"));
        // From the vault, without a modal.
        assert_eq!(
            p.prompt("alice", "", &masked("Password: ")),
            vec!["saved-pw"]
        );
        // A second factor that says "password" goes to the user...
        let oath = "One-time password (OATH) for alice: ";
        assert_eq!(p.prompt("alice", "", &masked(oath)), vec!["typed"]);
        // ...and so does a re-prompt: the saved answer was refused already.
        assert_eq!(p.prompt("alice", "", &masked("Password: ")), vec!["typed"]);
        drop(p);
        assert_eq!(gui.join().unwrap(), vec![oath, "Password: "]);
    }

    #[test]
    fn only_esc_or_cancel_is_the_users_decision() {
        // A GUI that drops the challenge on Esc and Cancel: read by timing.
        assert!(challenge_dismissed(Disconnected, 5 * SECOND, false, false));
        assert!(challenge_dismissed(Disconnected, 150 * SECOND, false, false));
        // The GUI retiring a modal nobody answered (app.rs: after 170 s).
        assert!(!challenge_dismissed(Disconnected, 170 * SECOND, false, false));
        // The lock screen clearing every pending challenge.
        assert!(!challenge_dismissed(Disconnected, 5 * SECOND, true, false));
        // This side stopped waiting.
        assert!(!challenge_dismissed(Timeout, AUTH_PROMPT_TIMEOUT, false, false));
    }

    #[test]
    fn an_explicit_cancel_stops_the_sign_in_however_late_it_comes() {
        // Cancel pressed 165 s in: as a drop it reads as the GUI retiring the
        // modal, and the reconnect loop asked again.
        assert!(!challenge_dismissed(Disconnected, 165 * SECOND, false, false));
        assert!(challenge_dismissed(Disconnected, 165 * SECOND, false, true));
        for waited in [0u32, 159, 160, 179] {
            assert!(
                challenge_dismissed(Disconnected, waited * SECOND, false, true),
                "cancel after {} s",
                waited
            );
        }
        // Still the user's call if the vault locked meanwhile.
        assert!(challenge_dismissed(Disconnected, 5 * SECOND, true, true));
    }

    fn challenge_with(
        reply: mpsc::Sender<Vec<String>>,
        cancelled: &Arc<AtomicBool>,
    ) -> AuthChallenge {
        AuthChallenge {
            session_id: "s".to_string(),
            target: String::new(),
            purpose: "reconnect".to_string(),
            username: String::new(),
            instructions: String::new(),
            prompt: AuthPrompt::default(),
            reply,
            cancelled: Arc::clone(cancelled),
        }
    }

    #[test]
    fn cancel_raises_the_flag_before_the_ssh_side_wakes_and_a_drop_does_not() {
        let (reply, answers) = mpsc::channel::<Vec<String>>();
        let flag = Arc::new(AtomicBool::new(false));
        challenge_with(reply, &flag).cancel();
        assert_eq!(answers.recv_timeout(SECOND), Err(Disconnected));
        assert!(flag.load(Ordering::SeqCst));

        let (reply, answers) = mpsc::channel::<Vec<String>>();
        let flag = Arc::new(AtomicBool::new(false));
        drop(challenge_with(reply, &flag));
        assert_eq!(answers.recv_timeout(SECOND), Err(Disconnected));
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn a_challenge_names_its_session_and_withdrawing_it_stops_the_sign_in() {
        let (tx, rx) = mpsc::channel::<AuthChallenge>();
        // The tab closes while its challenge is up: the GUI withdraws it.
        let gui = std::thread::spawn(move || {
            let challenge = rx.recv().expect("the round reaches the GUI");
            let asked_for = challenge.session_id.clone();
            challenge.cancel();
            (asked_for, rx)
        });
        let mut p = prompter(tx, None);
        let code = [ssh2::Prompt {
            text: "Verification code: ".into(),
            echo: true,
        }];
        // The SSH thread is released at once, as by a cancel...
        assert_eq!(p.prompt("alice", "", &code), vec![String::new()]);
        assert!(p.dismissed, "a withdrawn challenge must stop the sign-in");
        let (asked_for, rx) = gui.join().unwrap();
        assert_eq!(asked_for, "tab-7-session");
        // ...and a server asking again raises no modal for the closed tab.
        assert_eq!(p.prompt("alice", "", &code), vec![String::new()]);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn after_a_dismissal_a_server_asking_again_raises_no_new_modal() {
        let (tx, rx) = mpsc::channel::<AuthChallenge>();
        // Esc on the first modal: the GUI drops the challenge, and with it
        // the reply sender.
        let gui = std::thread::spawn(move || {
            drop(rx.recv().expect("the first round reaches the modal"));
            rx
        });
        let mut p = prompter(tx, None);
        let code = [ssh2::Prompt {
            text: "Verification code: ".into(),
            echo: true,
        }];
        assert_eq!(p.prompt("alice", "", &code), vec![String::new()]);
        assert!(p.dismissed);
        let rx = gui.join().unwrap();
        // The server asks again after the empty answer.
        assert_eq!(p.prompt("alice", "", &code), vec![String::new()]);
        assert!(
            matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "the dismissed login raised another modal"
        );
    }
}

#[cfg(test)]
mod transfer_cancel_tests {
    use super::test_support::{dialled, hang_up_server, manager_with};
    use super::*;

    #[test]
    fn a_cancel_that_lands_before_the_worker_runs_is_kept() {
        let (port, dials) = hang_up_server();
        // A password session re-dials its dead exec connection on first use,
        // so a worker that got past the cancel would show up in the count.
        let (mgr, sid) = manager_with("password", port);
        let dir = std::env::temp_dir().join(format!("neoshell-cancel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let (dir, file) = (
            dir.to_string_lossy().to_string(),
            file.to_string_lossy().to_string(),
        );

        let expect_cancelled =
            |what: &str, run: &dyn Fn(Arc<TransferProgress>) -> Result<(), String>| {
                // The bar is claimed with a fresh progress, and its Cancel
                // pressed before the worker thread gets to run.
                let progress = Arc::new(TransferProgress::new());
                progress.finished.store(true, Ordering::Relaxed);
                assert_eq!(
                    run(Arc::clone(&progress)),
                    Err(TRANSFER_CANCELLED.to_string()),
                    "{}",
                    what
                );
                assert!(progress.is_finished(), "{} took the cancel back", what);
            };
        expect_cancelled("upload", &|p| {
            mgr.upload_file_with_progress(&sid, &file, "/tmp/a", p)
        });
        expect_cancelled("upload dir", &|p| {
            mgr.upload_dir_with_progress(&sid, &dir, "/tmp/d", p)
        });
        expect_cancelled("download", &|p| {
            mgr.download_file_with_progress(&sid, "/tmp/a", &file, p)
        });
        expect_cancelled("download dir", &|p| {
            mgr.download_dir_with_progress(&sid, "/tmp/d", &dir, p)
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(dialled(&dials), 0, "a cancelled transfer went on to dial");
    }
}

#[cfg(test)]
mod exec_gate_tests {
    use super::test_support::{dialled, hang_up_server, is_message, manager_with};
    use super::*;
    use std::time::Instant;

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn only_one_rebuild_runs_and_its_session_is_reused() {
        let mut gate = ExecGate::default();
        let t0 = Instant::now();
        assert_eq!(gate.begin("password", t0), RebuildDecision::Dial);
        // Every other caller that hit the same dead connection meanwhile.
        assert_eq!(gate.begin("password", t0), RebuildDecision::InFlight);
        assert_eq!(gate.begin("key", t0 + SECOND), RebuildDecision::InFlight);
        gate.finish(true, t0 + 2 * SECOND);
        // ...then retry on the fresh session instead of dialling another one.
        assert_eq!(
            gate.begin("password", t0 + 3 * SECOND),
            RebuildDecision::Fresh
        );
        let later = t0 + 2 * SECOND + EXEC_REBUILD_COOLDOWN;
        assert_eq!(gate.begin("password", later), RebuildDecision::Dial);
    }

    #[test]
    fn a_failed_rebuild_cools_down_before_the_next_dial() {
        let mut gate = ExecGate::default();
        let t0 = Instant::now();
        assert_eq!(gate.begin("agent", t0), RebuildDecision::Dial);
        gate.finish(false, t0);
        match gate.begin("agent", t0 + 5 * SECOND) {
            RebuildDecision::CoolingDown(left) => {
                assert_eq!(left, EXEC_REBUILD_COOLDOWN - 5 * SECOND)
            }
            other => panic!("redialled {:?} into the cooldown", other),
        }
        assert!(!gate.in_flight, "a refusal must not claim the rebuild");
        assert_eq!(
            gate.begin("agent", t0 + EXEC_REBUILD_COOLDOWN),
            RebuildDecision::Dial
        );
    }

    #[test]
    fn keyboard_interactive_is_parked_never_redialled() {
        let mut gate = ExecGate::default();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(gate.begin("interactive", t0), RebuildDecision::Parked);
        }
        assert!(gate.parked && !gate.in_flight);

        // An exec failure parks only a session whose rebuild would prompt.
        let mut other = ExecGate::default();
        for auth in ["password", "key", "agent"] {
            other.exec_failed(auth);
            assert!(!other.parked, "{} parked", auth);
        }
        other.exec_failed("interactive");
        assert!(other.parked);

        // The shell's reconnect brought a fresh exec session: unparked, and
        // it counts as a rebuild for callers still holding the old error.
        gate.exec_restored(t0 + SECOND);
        assert!(!gate.parked);
        assert_eq!(
            gate.begin("password", t0 + 2 * SECOND),
            RebuildDecision::Fresh
        );
    }

    #[test]
    fn a_claim_left_through_an_error_path_releases_the_gate() {
        fn rebuild(gate: &Mutex<ExecGate>, fail: bool) -> Result<(), String> {
            let mut claim = RebuildClaim { gate, ok: false };
            if fail {
                Err("Exec handshake failed".to_string())?;
            }
            claim.ok = true;
            Ok(())
        }
        for fail in [true, false] {
            let gate = Mutex::new(ExecGate::default());
            assert_eq!(
                gate.lock().begin("password", Instant::now()),
                RebuildDecision::Dial
            );
            assert_eq!(rebuild(&gate, fail).is_err(), fail);
            let g = gate.lock();
            assert!(!g.in_flight, "rebuild left claimed (fail={})", fail);
            assert!(
                matches!(g.last, Some((_, ok)) if ok != fail),
                "{:?}",
                g.last
            );
        }
    }

    #[test]
    fn a_2fa_reconnect_asks_once_and_leaves_the_exec_connection_alone() {
        // The shell's challenge is the only one: no exec dial rides along.
        assert!(!reconnect_reopens_exec("interactive", false));
        for auth in ["password", "key", "agent"] {
            assert!(reconnect_reopens_exec(auth, false), "{}", auth);
        }
        // Minimal mode: exec is the shell's own session.
        for auth in ["password", "interactive"] {
            assert!(!reconnect_reopens_exec(auth, true), "{}", auth);
        }
    }

    #[test]
    fn a_dismissed_challenge_or_a_changed_host_key_stops_the_reconnect() {
        match after_failed_reconnect(&ReconnectError::Dismissed) {
            RetryVerdict::GiveUp(why) => {
                assert!(
                    is_message(&why, "ssh.err.reconnect_cancelled", &[]),
                    "{}",
                    why
                )
            }
            other => panic!("a dismissed challenge was retried: {:?}", other),
        }
        let mitm = ReconnectError::Failed(format!(
            "{} (reconnect) for h:22: host key mismatch mid-session",
            HOST_KEY_FAIL
        ));
        assert!(matches!(
            after_failed_reconnect(&mitm),
            RetryVerdict::GiveUp(_)
        ));
        // Bad luck is retried: a refused code, a dead network, a locked vault.
        for e in [
            "Keyboard-interactive auth failed: Authentication failed",
            "Handshake failed: [Session(-13)] Failed getting banner",
            "Vault is locked — unlock it to reconnect through proxy 'p'.",
        ] {
            assert_eq!(
                after_failed_reconnect(&ReconnectError::Failed(e.to_string())),
                RetryVerdict::Retry,
                "{}",
                e
            );
        }
    }

    #[test]
    fn exec_failures_count_against_the_connection_only_when_it_is_gone() {
        use ssh2::ErrorCode::{Session as Ssh, SFTP};
        use std::io::ErrorKind as K;
        // The command ran: any exit status is the remote's answer.
        for status in [0, 1, 2, 127, 255, -1] {
            assert!(
                !exec_connection_failed(ExecOutcome::Exited(status)),
                "exit {}",
                status
            );
        }
        // Refused before the connection was touched.
        assert!(!exec_connection_failed(ExecOutcome::NotRun));
        // Non-UTF-8 output, the way `read_to_string` reported it: data.
        assert!(!exec_connection_failed(ExecOutcome::ReadFailed(
            K::InvalidData
        )));
        // An SFTP status: the server answered.
        assert!(!exec_connection_failed(ExecOutcome::RequestFailed(SFTP(2))));
        // libssh2 session codes: socket none/send/recv/bad, a request timed
        // out, disconnect, protocol, channel closed/EOF sent, socket timeout.
        for code in [-1, -7, -9, -13, -14, -26, -27, -30, -43, -45] {
            assert!(
                exec_connection_failed(ExecOutcome::RequestFailed(Ssh(code))),
                "session code {}",
                code
            );
        }
        // A channel or request the server refused (-21 CHANNEL_FAILURE, -22
        // CHANNEL_REQUEST_DENIED: MaxSessions, exec not allowed) is the server
        // answering on a live link.
        for code in [-21, -22] {
            assert!(
                !exec_connection_failed(ExecOutcome::RequestFailed(Ssh(code))),
                "session code {} parked a live connection",
                code
            );
        }
        // What a read reports when the link goes under it: EOF, reset, and
        // libssh2's own errors, which ssh2 maps to Other / WouldBlock.
        for kind in [
            K::UnexpectedEof,
            K::ConnectionReset,
            K::ConnectionAborted,
            K::BrokenPipe,
            K::WouldBlock,
            K::Other,
        ] {
            assert!(
                exec_connection_failed(ExecOutcome::ReadFailed(kind)),
                "{:?}",
                kind
            );
        }
        // The 30 s read bound running out while the command ran: a slow
        // command — a 100k-entry listing on a slow link — not a dead link.
        assert!(!exec_connection_failed(ExecOutcome::ReadFailed(K::TimedOut)));
    }

    #[test]
    fn a_2fa_exec_sign_in_that_fails_at_connect_parks_and_keeps_the_shell() {
        // Refused — DISALLOW_REUSE on the same TOTP code — or dismissed alike.
        assert!(exec_sign_in_parks("interactive"));
        // Every other method signs the second connection in exactly as it did
        // the shell: its failure is real, and connect fails as before.
        for auth in ["password", "key", "agent"] {
            assert!(!exec_sign_in_parks(auth), "{}", auth);
        }
        // The gate connect registers for it: nothing re-dials behind the
        // user's back, and one deliberate resume dials once.
        let mut gate = ExecGate {
            parked: true,
            ..ExecGate::default()
        };
        assert_eq!(gate.begin("interactive", Instant::now()), RebuildDecision::Parked);
        assert_eq!(gate.begin_resume(), ResumeDecision::Dial);
        assert_eq!(gate.begin_resume(), ResumeDecision::InFlight);
    }

    #[test]
    fn a_2fa_exec_connection_that_cannot_be_dialled_parks_unless_the_host_key_changed() {
        use ExecOpenStep::*;
        // A link that dropped a second after the shell's dial threw away a
        // working 2FA shell as surely as a refused second code did.
        for step in [Dial, Handshake, SignIn] {
            assert!(exec_open_failure_parks("interactive", step), "{:?}", step);
        }
        // A key other than the one the shell was pinned to a second earlier:
        // the peer changed between the two dials, and connect stops whole.
        assert!(!exec_open_failure_parks("interactive", HostKey));
        // Every other method: every failure is real, and connect fails as
        // before.
        for auth in ["password", "key", "agent"] {
            for step in [Dial, Handshake, HostKey, SignIn] {
                assert!(!exec_open_failure_parks(auth, step), "{} {:?}", auth, step);
            }
        }
    }

    #[test]
    fn opening_the_exec_connection_says_which_step_failed() {
        let params = |port: u16| ConnectParams {
            host: "127.0.0.1".to_string(),
            port,
            username: "alice".to_string(),
            auth_type: "interactive".to_string(),
            password: None,
            private_key: None,
            passphrase: None,
            proxy_id: None,
            // Pinned, so nothing here reads the real ~/.ssh/known_hosts.
            pinned_host_key: Some(PinnedHostKey {
                key: vec![7; 32],
                alg: "ssh-ed25519".to_string(),
                fingerprint: "SHA256:test".to_string(),
            }),
        };
        // Nothing listening: the dial.
        let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = gone.local_addr().unwrap().port();
        drop(gone);
        assert!(matches!(
            open_exec_transport(&params(port)),
            Err((ExecOpenStep::Dial, _))
        ));
        // A peer that hangs up: the handshake.
        let (port, dials) = hang_up_server();
        assert!(matches!(
            open_exec_transport(&params(port)),
            Err((ExecOpenStep::Handshake, _))
        ));
        assert_eq!(dialled(&dials), 1);
    }

    #[test]
    fn a_dead_exec_connection_is_rebuilt_for_a_listing_never_listed_with_ls() {
        // Password: the one rebuild dials, and its failure is the answer.
        let (port, dials) = hang_up_server();
        let (mgr, sid) = manager_with("password", port);
        let err = mgr.list_files(&sid, "/srv").unwrap_err();
        assert_eq!(dialled(&dials), 1, "{}", err);
        // Keyboard-interactive: parked on the spot, no dial, no challenge.
        let (port, dials) = hang_up_server();
        let (mgr, sid) = manager_with("interactive", port);
        let err = mgr.list_files(&sid, "/srv").unwrap_err();
        assert!(is_message(&err, "exec.err.needs_reconnect", &[]), "{}", err);
        assert!(mgr.sessions.read()[&sid].exec_gate.lock().parked);
        assert_eq!(dialled(&dials), 0);
    }

    #[test]
    fn a_parked_session_from_connect_fails_fast_and_resumes_on_request() {
        let (port, dials) = hang_up_server();
        let (mgr, sid) = manager_with("interactive", port);
        // What connect registers when the exec challenge fails.
        mgr.sessions.read()[&sid].exec_gate.lock().parked = true;
        let err = mgr.exec_command(&sid, "uptime").unwrap_err();
        assert!(is_message(&err, "exec.err.needs_reconnect", &[]), "{}", err);
        let err = mgr.list_files(&sid, "/srv").unwrap_err();
        assert!(is_message(&err, "exec.err.needs_reconnect", &[]), "{}", err);
        assert_eq!(dialled(&dials), 0);
        // "Reconnect monitoring": one dial, one challenge.
        mgr.resume_exec(&sid).unwrap_err();
        assert_eq!(dialled(&dials), 1);
    }

    #[test]
    fn non_utf8_command_output_is_text_not_a_failure() {
        // `pwd && ls -la` in a directory holding a GBK-encoded "测试.txt".
        let raw: &[u8] =
            b"/home/alice\ntotal 8\n-rw-r--r-- 1 alice alice 0 Jan 1 00:00 \xb2\xe2\xca\xd4.txt\n";
        // What exec did with it: fail the command — and park a 2FA session.
        let mut strict = String::new();
        let err = IoRead::read_to_string(&mut &raw[..], &mut strict).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(!exec_connection_failed(ExecOutcome::ReadFailed(err.kind())));

        let text = read_output(&mut &raw[..]).expect("output is data");
        assert!(text.starts_with("/home/alice\ntotal 8\n"), "{:?}", text);
        assert!(text.ends_with("\u{FFFD}\u{FFFD}.txt\n"), "{:?}", text);
        assert_eq!(
            read_output(&mut "h\u{e9}llo \u{4e16}\u{754c}\n".as_bytes()).unwrap(),
            "h\u{e9}llo \u{4e16}\u{754c}\n"
        );
    }

    #[test]
    fn resume_redials_a_parked_session_once_per_request() {
        let (port, dials) = hang_up_server();
        let (mgr, sid) = manager_with("interactive", port);
        let gate = Arc::clone(&mgr.sessions.read()[&sid].exec_gate);
        // Nothing parked: the exec connection is used as it is.
        mgr.resume_exec(&sid).unwrap();
        assert_eq!(dialled(&dials), 0);

        gate.lock().exec_failed("interactive");
        // The user asked: one dial — for 2FA, one challenge.
        let err = mgr.resume_exec(&sid).unwrap_err();
        assert_eq!(dialled(&dials), 1, "{}", err);
        {
            let g = gate.lock();
            assert!(g.parked, "a failed resume must stay parked");
            assert!(!g.in_flight, "a failed resume left the gate claimed");
        }
        // No cooldown on a request: a mistyped code gets its retry at once.
        mgr.resume_exec(&sid).unwrap_err();
        assert_eq!(dialled(&dials), 2);
        // Monitoring meanwhile still fails fast, without dialling.
        let err = mgr.exec_command(&sid, "uptime").unwrap_err();
        assert!(is_message(&err, "exec.err.needs_reconnect", &[]), "{}", err);
        assert_eq!(dialled(&dials), 2);
    }

    #[test]
    fn a_second_resume_while_one_runs_does_not_dial() {
        let (port, dials) = hang_up_server();
        let (mgr, sid) = manager_with("interactive", port);
        let gate = Arc::clone(&mgr.sessions.read()[&sid].exec_gate);
        {
            let mut g = gate.lock();
            g.exec_failed("interactive");
            assert_eq!(g.begin_resume(), ResumeDecision::Dial);
        }
        let err = mgr.resume_exec(&sid).unwrap_err();
        assert!(is_message(&err, "exec.err.rebuilding", &[]), "{}", err);
        assert_eq!(dialled(&dials), 0);
    }

    #[test]
    fn a_resume_that_lands_unparks_the_session() {
        // The gate's side of a resume whose dial succeeded (that needs a server).
        let mut gate = ExecGate::default();
        let t0 = Instant::now();
        gate.exec_failed("interactive");
        assert_eq!(gate.begin_resume(), ResumeDecision::Dial);
        assert_eq!(gate.begin_resume(), ResumeDecision::InFlight);
        gate.exec_restored(t0);
        gate.finish(true, t0);
        assert!(!gate.parked && !gate.in_flight);
        assert_eq!(gate.begin_resume(), ResumeDecision::NotParked);
        // Automatic rebuilds are still never allowed to prompt.
        assert_eq!(gate.begin("interactive", t0), RebuildDecision::Parked);
    }

    #[test]
    fn a_keyboard_interactive_session_never_redials_its_exec_connection() {
        let (port, dials) = hang_up_server();
        let (mgr, sid) = manager_with("interactive", port);
        // What the 3 s monitor tick and every SFTP click used to turn into a
        // fresh 2FA challenge each.
        for _ in 0..3 {
            let err = mgr.rebuild_exec_session(&sid).unwrap_err();
            assert!(is_message(&err, "exec.err.needs_reconnect", &[]), "{}", err);
        }
        // Parked: monitoring and SFTP fail fast, with no probe of the dead
        // connection and no dial.
        let err = mgr.exec_command(&sid, "uptime").unwrap_err();
        assert!(is_message(&err, "exec.err.needs_reconnect", &[]), "{}", err);
        let err = mgr
            .get_exec_session(&sid)
            .err()
            .expect("a parked exec session was handed out");
        assert!(is_message(&err, "exec.err.needs_reconnect", &[]), "{}", err);
        assert_eq!(
            dialled(&dials),
            0,
            "a 2FA session was re-dialled — each dial is a new challenge"
        );
    }

    #[test]
    fn a_failed_rebuild_is_not_redialled_inside_the_cooldown() {
        let (port, dials) = hang_up_server();
        let (mgr, sid) = manager_with("password", port);
        let first = mgr.rebuild_exec_session(&sid).unwrap_err();
        assert_eq!(
            dialled(&dials),
            1,
            "the first rebuild should dial: {}",
            first
        );
        let second = mgr.rebuild_exec_session(&sid).unwrap_err();
        assert_eq!(
            dialled(&dials),
            1,
            "redialled inside the cooldown: {}",
            second
        );
        let secs = EXEC_REBUILD_COOLDOWN.as_secs();
        assert!(
            (1..=secs).any(|n| is_message(
                &second,
                "exec.err.cooldown",
                &[("secs", &n.to_string())]
            )),
            "{}",
            second
        );
    }
}

#[cfg(test)]
mod proxy_connect_tests {
    use super::test_support::is_message;
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_locked_vault_stops_a_proxied_connect_before_it_dials() {
        let dir = std::env::temp_dir().join(format!("neoshell-ssh-proxy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Where the proxy would be. Anything reaching it is a failure.
        let wire = TcpListener::bind("127.0.0.1:0").unwrap();
        wire.set_nonblocking(true).unwrap();
        let path = dir.join("proxies.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"schema":1,"proxies":[{{"id":"p1","name":"corp-socks-locked",
                   "proxy_type":"socks5h","host":"127.0.0.1","port":{},"username":"alice"}}]}}"#,
                wire.local_addr().unwrap().port()
            ),
        )
        .unwrap();
        // No vault handle, and none registered in the test binary: exactly
        // what the idle re-lock leaves a live session's reader thread with.
        let store = crate::proxy::ProxyStore::at(path, None);
        let params = ConnectParams {
            host: "target.invalid".to_string(),
            port: 22,
            username: "alice".to_string(),
            auth_type: "password".to_string(),
            password: Some("pw".to_string()),
            private_key: None,
            passphrase: None,
            proxy_id: Some("p1".to_string()),
            pinned_host_key: None,
        };
        let result = connect_through_proxy(&store, "p1", &params);
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.unwrap_err();
        assert!(
            is_message(
                &err,
                "proxy.err.vault_locked",
                &[("name", "corp-socks-locked")]
            ),
            "{}",
            err
        );
        match wire.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("the proxy was dialled with its password locked in the vault"),
            Err(e) => panic!("listener: {}", e),
        }
    }
}

#[cfg(test)]
mod listing_tests {
    use super::*;
    use std::collections::HashSet;
    use EntryKind::{Dir, File, Other, Symlink};

    /// 2023-11-14 22:13:20 UTC.
    const T: u64 = 1_700_000_000;

    fn stat(perm: u32) -> ssh2::FileStat {
        ssh2::FileStat {
            size: Some(0),
            uid: Some(1000),
            gid: Some(1000),
            perm: Some(perm),
            atime: None,
            mtime: Some(T),
        }
    }

    fn row(name: &[u8], perm: u32) -> FileEntry {
        sftp_file_entry(name, &stat(perm), T, 0).expect("listed")
    }

    #[test]
    fn sftp_names_are_taken_byte_for_byte() {
        let names: [&[u8]; 7] = [
            b"project",
            b"project ",
            b" lead",
            b"a  b",
            b"a\tb",
            b"a b",
            b"\t x  \t",
        ];
        let rows: Vec<FileEntry> = names.iter().map(|n| row(n, 0o100_644)).collect();
        for (name, row) in names.iter().zip(&rows) {
            assert_eq!(row.name.as_bytes(), *name);
        }
        // Seven rows, seven paths: no name collapsed onto another.
        let distinct: HashSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(distinct.len(), names.len());
    }

    #[test]
    fn the_type_comes_from_the_attributes() {
        let dir = row(b"project", 0o040_755);
        assert!(dir.is_dir);
        assert_eq!((dir.kind(), dir.permissions.as_str()), (Dir, "drwxr-xr-x"));
        let decoy = row(b"project ", 0o100_644);
        assert!(!decoy.is_dir);
        assert_eq!(decoy.kind(), File);
        // lstat's attributes: a link to a directory is a link.
        let link = row(b"shared", 0o120_777);
        assert!(!link.is_dir);
        assert_eq!(link.kind(), Symlink);
        assert_eq!(row(b"pipe", 0o010_644).kind(), Other);
        // A server that sends no attributes: no type to go on, nothing made up.
        let none = ssh2::FileStat {
            size: None,
            uid: None,
            gid: None,
            perm: None,
            atime: None,
            mtime: None,
        };
        let bare = sftp_file_entry(b"x", &none, T, 0).unwrap();
        assert_eq!(bare.kind(), Other);
        assert!(bare.permissions.is_empty() && bare.size.is_empty() && bare.modified.is_empty());
        // Size, time and owner as the browser shows them.
        let file = sftp_file_entry(
            b"f",
            &ssh2::FileStat {
                size: Some(1234),
                ..stat(0o100_600)
            },
            T + 60,
            0,
        )
        .unwrap();
        assert_eq!(
            (file.size.as_str(), file.modified.as_str(), file.owner.as_str()),
            ("1234", "Nov 14 22:13", "1000")
        );
        // The browser's own ".." has no permissions and goes by is_dir.
        let up = FileEntry {
            name: "..".to_string(),
            is_dir: true,
            ..FileEntry::default()
        };
        assert_eq!(up.kind(), Dir);
    }

    #[test]
    fn names_that_are_not_one_entry_here_are_left_out() {
        for bad in [&b""[..], b".", b"a/b", b"../x", b"/etc", b"a\0b"] {
            assert!(sftp_file_entry(bad, &stat(0o100_644), T, 0).is_none(), "{:?}", bad);
        }
        assert_eq!(row(b"..", 0o040_755).name, "..");
    }

    #[test]
    fn ls_names_are_the_verbatim_rest_of_the_line() {
        let out = "total 16\n\
            drwxr-xr-x  2 alice alice 4096 Sep 21 13:45 .\n\
            drwxr-xr-x 18 alice alice 4096 Jan  1  2025 ..\n\
            drwxr-xr-x  2 alice alice 4096 Sep 21 13:45 project\n\
            -rw-r--r--  1 bob   bob      0 Sep 21 13:46 project\x20\n\
            -rw-r--r--  1 bob   bob      0 Sep 21 13:46 \x20lead\n\
            -rw-r--r--  1 bob   bob      0 Sep 21 13:46 a  b\n\
            -rw-r--r--  1 bob   bob      0 Sep 21 13:46 a\tb\n\
            lrwxrwxrwx  1 alice alice   11 Sep 21 13:47 link -> /etc/passwd\n\
            crw-rw-rw-  1 root  root  1, 3 Sep 21 13:48 null\n\
            ls: cannot access 'gone': No such file or directory\n\
            -?????????  ? ?     ?        ?            ? unstatable\n";
        let rows: Vec<FileEntry> = out.lines().filter_map(parse_ls_line).collect();
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            ["..", "project", "project ", " lead", "a  b", "a\tb", "link", "null"]
        );
        let kinds: Vec<EntryKind> = rows.iter().map(FileEntry::kind).collect();
        assert_eq!(kinds, [Dir, Dir, File, File, File, File, Symlink, Other]);
        let project = &rows[1];
        assert_eq!(
            (project.owner.as_str(), project.size.as_str(), project.modified.as_str()),
            ("alice", "4096", "Sep 21 13:45")
        );
        assert_eq!(rows[0].modified, "Jan 1 2025");
        assert_eq!(rows[7].size, "1, 3");
    }

    #[test]
    fn permissions_print_like_ls() {
        for (mode, want) in [
            (0o100_644, "-rw-r--r--"),
            (0o040_755, "drwxr-xr-x"),
            (0o120_777, "lrwxrwxrwx"),
            (0o104_755, "-rwsr-xr-x"),
            (0o102_644, "-rw-r-Sr--"),
            (0o041_777, "drwxrwxrwt"),
            (0o041_776, "drwxrwxrwT"),
            (0o020_666, "crw-rw-rw-"),
            (0o060_660, "brw-rw----"),
            (0o140_755, "srwxr-xr-x"),
            (0o010_600, "prw-------"),
            (0o000_644, "?rw-r--r--"),
        ] {
            assert_eq!(ls_permissions(mode), want, "{:o}", mode);
        }
    }

    #[test]
    fn times_print_like_the_hosts_ls() {
        // Recent: month, day, time — in the host's zone, as its ls printed.
        assert_eq!(ls_time(T, T + 60, 0), "Nov 14 22:13");
        assert_eq!(ls_time(T, T + 60, 8 * 3600), "Nov 15 06:13");
        assert_eq!(ls_time(T, T + 60, -(5 * 3600 + 30 * 60)), "Nov 14 16:43");
        // Half a year or more away, either way: the year.
        assert_eq!(ls_time(T, T + 200 * 86_400, 0), "Nov 14 2023");
        assert_eq!(ls_time(T + 200 * 86_400, T, 0), "Jun 1 2024");
        assert_eq!(ls_time(0, T, 0), "Jan 1 1970");
        // A leap day; a hostile timestamp still prints as a date.
        assert_eq!(ls_time(951_782_400, 951_782_400, 0), "Feb 29 00:00");
        assert_eq!(ls_time(u64::MAX, T, 0), "Dec 31 9999");
    }

    #[test]
    fn the_hosts_utc_offset_is_read_from_date() {
        assert_eq!(parse_utc_offset("+0800\n"), Some(8 * 3600));
        assert_eq!(parse_utc_offset("-0530"), Some(-(5 * 3600 + 30 * 60)));
        assert_eq!(parse_utc_offset("+0000"), Some(0));
        for bad in ["", "%z", "0800", "+08", "+08:00", "+2400", "+0860", "UTC", "+08000"] {
            assert_eq!(parse_utc_offset(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn the_listed_directory_is_spelled_the_way_cd_and_pwd_would() {
        let home = || Some("/home/alice".to_string());
        let dir = |p: &str| resolve_listing_dir(p, home);
        assert_eq!(dir("/srv/app/").as_deref(), Some("/srv/app"));
        assert_eq!(dir("/srv/./app/../data").as_deref(), Some("/srv/data"));
        assert_eq!(dir("/").as_deref(), Some("/"));
        assert_eq!(dir("/..").as_deref(), Some("/"));
        // Only "." and ".." change anything: a space is part of a name.
        assert_eq!(dir("/srv/project ").as_deref(), Some("/srv/project "));
        assert_eq!(dir("/srv/ a/b  c").as_deref(), Some("/srv/ a/b  c"));
        // Under the login directory; `~` is that directory too.
        assert_eq!(dir("docs").as_deref(), Some("/home/alice/docs"));
        assert_eq!(dir("~").as_deref(), Some("/home/alice"));
        assert_eq!(dir("").as_deref(), Some("/home/alice"));
        assert_eq!(resolve_listing_dir("docs", || None), None);
        // An absolute path never asks for the login directory.
        assert_eq!(
            resolve_listing_dir("/srv", || panic!("asked for home")).as_deref(),
            Some("/srv")
        );
    }

    #[test]
    fn a_leading_tilde_is_the_login_directory() {
        let home = || Some("/home/alice".to_string());
        let dir = |p: &str| resolve_listing_dir(p, home);
        // What the panel asks for on every connect and split, and what a
        // `user@host:~/src$` prompt names: both listed empty before.
        assert_eq!(dir("~").as_deref(), Some("/home/alice"));
        assert_eq!(dir("~/").as_deref(), Some("/home/alice"));
        assert_eq!(dir("~/src/app").as_deref(), Some("/home/alice/src/app"));
        assert_eq!(dir("~/src/../docs").as_deref(), Some("/home/alice/docs"));
        assert_eq!(dir("~/my  dir ").as_deref(), Some("/home/alice/my  dir "));
        // Only a leading `~` alone or before a `/`: anything else is a name.
        assert_eq!(dir("~bob").as_deref(), Some("/home/alice/~bob"));
        assert_eq!(dir("a/~").as_deref(), Some("/home/alice/a/~"));
        assert_eq!(dir("/srv/~").as_deref(), Some("/srv/~"));
        // A login directory the server would not tell: nothing to list.
        assert_eq!(resolve_listing_dir("~", || None), None);
        assert_eq!(resolve_listing_dir("~/x", || None), None);
        // `ls` over exec: the shell expands it the same way.
        assert_eq!(ls_cd_arg("~"), "~");
        assert_eq!(ls_cd_arg("~/"), "~/''");
        assert_eq!(ls_cd_arg("~/my dir"), "~/'my dir'");
        assert_eq!(ls_cd_arg("~/it's"), "~/'it'\\''s'");
        assert_eq!(ls_cd_arg("~bob"), "'~bob'");
        assert_eq!(ls_cd_arg("/srv/~"), "'/srv/~'");
        assert_eq!(ls_cd_arg("$(reboot)"), "'$(reboot)'");
    }

    #[test]
    fn sftp_rows_are_verified_and_keep_the_raw_name_and_ls_rows_are_not() {
        let r = row(b"a\xff", 0o100_644);
        assert!(r.verified);
        assert_eq!(r.raw_name, b"a\xff");
        assert_eq!(r.name, "a\u{FFFD}");
        assert_eq!(row(b"project ", 0o040_755).raw_name, b"project ");
        // `ls -la` text, where a name holding a newline forges a row: here
        // "x\n-rwxrwxrwx 1 root root 0 Sep 21 13:46 important".
        let out = "-rw-r--r-- 1 bob bob 0 Sep 21 13:46 x\n\
                   -rwxrwxrwx 1 root root 0 Sep 21 13:46 important\n";
        let rows: Vec<FileEntry> = out.lines().filter_map(parse_ls_line).collect();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| !r.verified));
        assert_eq!(rows[1].raw_name, b"important");
        // The browser's own ".." is nothing an operation may act on.
        assert!(!FileEntry::default().verified);
    }

    #[test]
    fn rows_come_sorted_by_name_with_the_parent_first() {
        let mut rows: Vec<FileEntry> = ["b", "..", "A", "a", ".env"]
            .iter()
            .map(|n| FileEntry {
                name: n.to_string(),
                ..FileEntry::default()
            })
            .collect();
        sort_listing(&mut rows);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["..", ".env", "A", "a", "b"]);
    }
}

#[cfg(test)]
mod confirmed_entry_tests {
    use super::test_support::{dialled, hang_up_server, is_message, manager_with};
    use super::*;

    fn stat(perm: u32) -> ssh2::FileStat {
        ssh2::FileStat {
            size: Some(0),
            uid: Some(1000),
            gid: Some(1000),
            perm: Some(perm),
            atime: None,
            mtime: Some(1_700_000_000),
        }
    }

    /// A row as an SFTP listing gives it.
    fn sftp_row(name: &[u8]) -> FileEntry {
        sftp_file_entry(name, &stat(0o100_644), 1_700_000_000, 0).expect("listed")
    }

    #[test]
    fn only_a_link_that_just_answered_is_listed_with_ls() {
        use ssh2::ErrorCode::Session as Ssh;
        use SftpStartVerdict::*;
        use SubsystemProbe::*;
        // No SFTP subsystem: refused outright, or accepted with nothing behind
        // it that answers (dropbear without the sftp-server binary).
        assert_eq!(
            sftp_start_verdict(RequestFailed(Ssh(LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED))),
            Unavailable
        );
        assert_eq!(sftp_start_verdict(Accepted), Unavailable);
        // The server refused a channel: `ls` would be refused as well.
        assert_eq!(
            sftp_start_verdict(OpenFailed(Ssh(LIBSSH2_ERROR_CHANNEL_FAILURE))),
            Refused
        );
        // A send that failed (what an unconnected session answers), a
        // timeout, a disconnect, a read that failed, a session never signed
        // in, a code libssh2 never set: the link — rebuilt, never `ls`.
        for code in [-7, LIBSSH2_ERROR_TIMEOUT, -13, -43, -34, i32::MIN] {
            assert_eq!(sftp_start_verdict(OpenFailed(Ssh(code))), ConnectionLost, "{}", code);
            assert_eq!(sftp_start_verdict(RequestFailed(Ssh(code))), ConnectionLost, "{}", code);
        }
        // What an unconnected session really answers the probe with.
        let sess = Session::new().unwrap();
        sess.set_blocking(true);
        sess.set_timeout(2_000);
        assert_eq!(sftp_start_verdict(probe_sftp_subsystem(&sess)), ConnectionLost);
    }

    #[test]
    fn an_unverified_row_is_refused_before_the_session_is_touched() {
        let (port, dials) = hang_up_server();
        let (mgr, sid) = manager_with("password", port);
        let row = parse_ls_line("-rw-r--r-- 1 bob bob 0 Sep 21 13:46 notes").unwrap();
        let refused = |result: Result<(), String>| {
            let err = result.unwrap_err();
            assert!(
                is_message(&err, "sftp.err.unverified", &[("path", "/srv/notes")]),
                "{}",
                err
            );
        };
        refused(mgr.sftp_remove_confirmed(&sid, "/srv/notes", &row));
        refused(mgr.sftp_rename_confirmed(&sid, "/srv/notes", "/srv/n2", &row));
        refused(mgr.sftp_chmod_confirmed(&sid, "/srv/notes", 0o600, &row));
        // Nothing was probed or rebuilt for them: the dead exec connection
        // would have been re-dialled.
        assert_eq!(dialled(&dials), 0);
        // A verified row gets as far as the connection.
        assert!(mgr.sftp_remove_confirmed(&sid, "/srv/notes", &sftp_row(b"notes")).is_err());
        assert_eq!(dialled(&dials), 1);
    }

    #[test]
    fn a_row_is_addressed_by_its_raw_name_not_the_text_it_was_shown_as() {
        // b"a\xff" is shown as "a\u{FFFD}"; sent back as that text it named the
        // entry literally called "a\u{FFFD}", or none.
        let shown = "/srv/a\u{FFFD}";
        // Where names go out raw (unix), those bytes are what is addressed.
        // Off unix ssh2 cannot put non-UTF-8 bytes on the wire at all, so the
        // name is refused on this branch too (deletable_entry_name) — in
        // production that platform takes the lossy branch below anyway.
        if cfg!(unix) {
            assert_eq!(entry_path(shown, b"a\xff", false).unwrap(), b"/srv/a\xff");
            assert_eq!(entry_path("/a\u{FFFD}", b"a\xff", false).unwrap(), b"/a\xff");
        } else {
            assert!(entry_path(shown, b"a\xff", false).is_err());
            assert!(entry_path("/a\u{FFFD}", b"a\xff", false).is_err());
        }
        // Where names go out raw, a server's own U+FFFD is a name like any.
        assert_eq!(
            entry_path(shown, "a\u{FFFD}".as_bytes(), false).unwrap(),
            shown.as_bytes()
        );
        // Where ssh2 sends UTF-8 only, neither can be addressed exactly.
        for raw in [&b"a\xff"[..], "a\u{FFFD}".as_bytes()] {
            let err = entry_path(shown, raw, true).unwrap_err();
            assert!(is_message(&err, "sftp.err.not_utf8", &[("path", shown)]), "{}", err);
        }
        // UTF-8 names go out as they are, everywhere.
        for lossy in [false, true] {
            let path = "/srv/项目 a\tb ";
            assert_eq!(entry_path(path, "项目 a\tb ".as_bytes(), lossy).unwrap(), path.as_bytes());
        }
        // A path that is not the row's, or a name that is the directory itself.
        for (path, raw) in [("/srv/b", &b"a"[..]), ("/srv/.", &b"."[..])] {
            let err = entry_path(path, raw, false).unwrap_err();
            assert!(is_message(&err, "sftp.err.changed", &[("path", path)]), "{}", err);
        }
    }

    #[test]
    fn a_confirmed_row_carries_its_raw_name_to_the_wire() {
        let confirmed = ConfirmedEntry::from(&sftp_row(b"a\xff"));
        let target = confirmed_target("/srv/a\u{FFFD}", Some(&confirmed));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let target = target.unwrap();
            assert_eq!(target, b"/srv/a\xff");
            // And ssh2 is handed exactly those bytes.
            assert_eq!(sftp_path(&target).unwrap().as_os_str().as_bytes(), b"/srv/a\xff");
        }
        #[cfg(not(unix))]
        {
            let err = target.unwrap_err();
            assert!(
                is_message(&err, "sftp.err.not_utf8", &[("path", "/srv/a\u{FFFD}")]),
                "{}",
                err
            );
        }
        // A caller that kept only the kind: the path as given, as before.
        let kind_only = ConfirmedEntry::from(EntryKind::File);
        assert_eq!(confirmed_target("/srv/x", Some(&kind_only)).unwrap(), b"/srv/x");
        assert_eq!(confirmed_target("/srv/x", None).unwrap(), b"/srv/x");
    }
}

#[cfg(test)]
mod download_walk_tests {
    use super::*;
    use std::cell::RefCell;

    /// A remote tree for the download walk: directory -> (name, is a
    /// directory). Cancel is pressed while the `cancel_at`-th directory is
    /// being listed.
    struct FakeLister {
        tree: HashMap<String, Vec<(String, bool)>>,
        listed: RefCell<Vec<String>>,
        cancel_at: usize,
        progress: Arc<TransferProgress>,
    }

    impl RemoteLister for FakeLister {
        fn list(&self, dir: &str) -> Result<Vec<(std::path::PathBuf, ssh2::FileStat)>, String> {
            self.listed.borrow_mut().push(dir.to_string());
            if self.listed.borrow().len() == self.cancel_at {
                self.progress.finished.store(true, Ordering::Relaxed);
            }
            let entries = self.tree.get(dir).cloned().unwrap_or_default();
            Ok(entries
                .into_iter()
                .map(|(name, is_dir)| {
                    let stat = ssh2::FileStat {
                        size: Some(1),
                        uid: None,
                        gid: None,
                        perm: Some(if is_dir { 0o040_755 } else { 0o100_644 }),
                        atime: None,
                        mtime: None,
                    };
                    // Joined onto the directory, as `Sftp::readdir` does.
                    (std::path::Path::new(dir).join(name), stat)
                })
                .collect())
        }
    }

    fn walk(cancel_at: usize) -> (Result<(), String>, usize, usize) {
        let mut tree = HashMap::new();
        tree.insert(
            "/srv/data".to_string(),
            (0..50).map(|i| (format!("d{}", i), true)).collect(),
        );
        for i in 0..50 {
            tree.insert(format!("/srv/data/d{}", i), vec![("f".to_string(), false)]);
        }
        let progress = Arc::new(TransferProgress::new());
        let lister = FakeLister {
            tree,
            listed: RefCell::new(Vec::new()),
            cancel_at,
            progress: Arc::clone(&progress),
        };
        let (mut dirs, mut files, mut skipped) = (Vec::new(), Vec::new(), 0);
        let result = collect_remote_tree(
            &lister,
            "/srv/data",
            &mut Vec::new(),
            0,
            &mut dirs,
            &mut files,
            &mut skipped,
            &progress,
        );
        let listed = lister.listed.borrow().len();
        (result, listed, files.len())
    }

    #[test]
    fn a_cancel_during_the_remote_listing_stops_the_walk() {
        // Uncancelled: the root and all 50 subdirectories, 50 files.
        assert_eq!(walk(usize::MAX), (Ok(()), 51, 50));
        // Cancel while the third directory is listed: no fourth listing, and
        // the exec session's lock goes back with the error.
        let (result, listed, _) = walk(3);
        assert_eq!(result, Err(TRANSFER_CANCELLED.to_string()));
        assert_eq!(listed, 3);
    }
}

#[cfg(test)]
mod session_id_tests {
    use super::test_support::{hang_up_server, is_message, manager_with};
    use super::*;

    #[test]
    fn a_caller_chosen_session_id_must_be_fresh_and_shell_safe() {
        let (port, _dials) = hang_up_server();
        let (mgr, live) = manager_with("password", port);
        let fresh = SshManager::new_session_id();
        assert!(valid_session_id(&fresh), "{}", fresh);
        assert!(mgr.check_new_session_id(&fresh).is_ok());
        // A live session's id: the new session would replace — and orphan —
        // the old one.
        let err = mgr.check_new_session_id(&live).unwrap_err();
        assert!(is_message(&err, "ssh.err.bad_session_id", &[("id", &live)]), "{}", err);
        // It names the tmux session on a shell command line, unquoted.
        let long = "a".repeat(65);
        for bad in [
            "",
            "short",
            "has space-12",
            "$(reboot)-x",
            "a;b|c&d-1234",
            "日本語日本語日本語",
            long.as_str(),
        ] {
            assert!(!valid_session_id(bad), "{:?}", bad);
            assert!(mgr.check_new_session_id(bad).is_err(), "{:?}", bad);
        }
    }
}

#[cfg(test)]
mod scratch_probe_tests {
    #[test]
    fn scratch_unconnected_session_probe() {
        let sess = ssh2::Session::new().unwrap();
        sess.set_blocking(true);
        sess.set_timeout(2_000);
        let t = std::time::Instant::now();
        let ch = sess.channel_session();
        eprintln!("channel_session: {:?} after {:?}", ch.as_ref().err(), t.elapsed());
        let t = std::time::Instant::now();
        let sf = sess.sftp();
        eprintln!("sftp: {:?} after {:?}", sf.as_ref().err(), t.elapsed());
        eprintln!("last_error: {:?}", ssh2::Error::last_session_error(&sess).map(|e| e.code()));
    }
}
