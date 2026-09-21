//! SSH tunnel manager — persistent local port forwarding through an SSH
//! jump host to an internal target. Each tunnel runs in its own background
//! thread with its own SSH session; lifecycle is independent of the terminal
//! tabs (a tunnel can be active without any open SSH shell tab).
//!
//! Config inspired by https://github.com/uk0/sshrw — a single SSH session
//! forwards one or more `LOCAL_PORT → REMOTE_HOST:REMOTE_PORT` mappings.
//! Each mapping becomes its own `TcpListener` + direct-tcpip loop.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ForwardRule {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

impl ForwardRule {
    /// Parse "REMOTE_HOST:REMOTE_PORT->LOCAL_PORT" or "LOCAL:REMOTE_HOST:REMOTE_PORT".
    /// Accepts both sshrw-style arrow syntax and `L:H:P` compact form.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some((remote, local)) = s.split_once("->") {
            let (rh, rp) = remote.trim().rsplit_once(':')
                .ok_or_else(|| format!("invalid remote: {}", remote))?;
            let rp: u16 = rp.trim().parse().map_err(|e| format!("bad remote port: {}", e))?;
            let lp: u16 = local.trim().split_once(':')
                .map(|(_h, p)| p.trim()).unwrap_or(local.trim())
                .parse().map_err(|e| format!("bad local port: {}", e))?;
            Ok(ForwardRule { local_port: lp, remote_host: rh.trim().to_string(), remote_port: rp })
        } else {
            let parts: Vec<&str> = s.split(':').collect();
            match parts.len() {
                3 => Ok(ForwardRule {
                    local_port: parts[0].parse().map_err(|e| format!("bad local port: {}", e))?,
                    remote_host: parts[1].to_string(),
                    remote_port: parts[2].parse().map_err(|e| format!("bad remote port: {}", e))?,
                }),
                _ => Err(format!("expected 'LOCAL:REMOTE_HOST:REMOTE_PORT' or 'REMOTE:PORT->LOCAL:PORT', got '{}'", s)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Config store (plain JSON, owner-only on disk — same convention as the proxy
// store, including the fact that `password` and `passphrase` are still written
// in the clear. Moving them into the vault is tracked separately; until then
// 0600 and an owner-only directory are the whole protection, so every write
// goes through `storage::write_private` rather than `std::fs::write`.)
// ---------------------------------------------------------------------------

pub struct TunnelStore {
    path: PathBuf,
}

impl TunnelStore {
    pub fn new() -> Self {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("neoshell");
        if let Err(e) = crate::storage::create_dir_private(&dir) {
            log::error!("failed to create data dir {}: {}", dir.display(), e);
        }
        let store = Self { path: dir.join("tunnels.json") };
        // A file written by a pre-0.7.0 build is 0644 on disk; narrow it now
        // rather than waiting for the next save to rewrite it.
        crate::storage::tighten_permissions(&store.path);
        store
    }

    pub fn load(&self) -> Vec<TunnelConfig> {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Replace the stored list, atomically and owner-only.
    ///
    /// Returns the failure instead of discarding it: a tunnel that did not
    /// reach disk is gone on the next launch, and silently pretending
    /// otherwise is how a user loses a forward without noticing.
    pub fn save(&self, list: &[TunnelConfig]) -> Result<(), String> {
        let json = serde_json::to_string_pretty(list)
            .map_err(|e| format!("cannot serialise tunnels: {}", e))?;
        crate::storage::write_private(&self.path, json.as_bytes())
            .map_err(|e| format!("cannot write {}: {}", self.path.display(), e))
    }

    /// `save`, reporting a failure to the log.
    ///
    /// The mutators below keep returning `()` so the UI call sites are
    /// untouched; surfacing this in the UI is the follow-up.
    fn save_logged(&self, list: &[TunnelConfig], what: &str) {
        if let Err(e) = self.save(list) {
            log::error!("tunnel store: {} was NOT saved: {}", what, e);
        }
    }

    pub fn upsert(&self, cfg: TunnelConfig) {
        let mut list = self.load();
        if let Some(existing) = list.iter_mut().find(|t| t.id == cfg.id) {
            *existing = cfg;
        } else {
            list.push(cfg);
        }
        self.save_logged(&list, "upsert");
    }

    pub fn delete(&self, id: &str) {
        let mut list = self.load();
        list.retain(|t| t.id != id);
        self.save_logged(&list, "delete");
    }

    pub fn get(&self, id: &str) -> Option<TunnelConfig> {
        self.load().into_iter().find(|t| t.id == id)
    }
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
    session.set_blocking(true);
    let session = Arc::new(Mutex::new(session));

    // 2. Bind every listener up-front so port-in-use errors surface early.
    let mut listeners: Vec<(TcpListener, ForwardRule)> = Vec::new();
    for rule in &cfg.forwards {
        let addr = format!("127.0.0.1:{}", rule.local_port);
        let lst = TcpListener::bind(&addr)
            .map_err(|e| format!("bind {}: {}", addr, e))?;
        lst.set_nonblocking(true).ok();
        log::info!("tunnel '{}' listening {} -> {}:{}",
            cfg.name, addr, rule.remote_host, rule.remote_port);
        listeners.push((lst, rule.clone()));
    }

    *state.lock() = TunnelState::Running { connections: 0, started: Instant::now() };

    // 3. Poll-accept on all listeners; for each new connection open a
    //    direct-tcpip channel and spawn a pump thread.
    let conn_count = Arc::new(parking_lot::Mutex::new(0u32));
    while !stop_flag.load(Ordering::Relaxed) {
        let mut had_work = false;
        for (lst, rule) in &listeners {
            match lst.accept() {
                Ok((client, peer)) => {
                    had_work = true;
                    log::info!("tunnel '{}' accepted {} → {}:{}", cfg.name, peer, rule.remote_host, rule.remote_port);
                    client.set_nonblocking(false).ok();

                    let sess_clone = session.clone();
                    let rule_clone = rule.clone();
                    let state_clone = state.clone();
                    let conn_counter = conn_count.clone();

                    {
                        let mut c = conn_counter.lock();
                        *c += 1;
                        bump_state(&state_clone, *c);
                    }

                    std::thread::spawn(move || {
                        let result = (|| -> Result<(), String> {
                            let channel = {
                                let s = sess_clone.lock();
                                s.channel_direct_tcpip(&rule_clone.remote_host, rule_clone.remote_port, None)
                                    .map_err(|e| format!("direct-tcpip {}:{}: {}", rule_clone.remote_host, rule_clone.remote_port, e))?
                            };
                            pump_bidir(client, channel, sess_clone.clone())
                        })();
                        if let Err(e) = result {
                            log::warn!("tunnel pump error: {}", e);
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
        if !had_work {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    log::info!("tunnel '{}' stopping", cfg.name);
    Ok(())
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
            let pass = cfg.password.as_deref().unwrap_or("");
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
    session: Arc<Mutex<ssh2::Session>>,
) -> Result<(), String> {
    use std::io::ErrorKind;

    local.set_nonblocking(true).ok();
    {
        let s = session.lock();
        s.set_blocking(false);
    }

    let mut up = [0u8; 32 * 1024];
    let mut dn = [0u8; 32 * 1024];
    let mut local_eof = false;
    let mut channel_eof = false;

    loop {
        let mut did_work = false;

        // local -> channel
        if !local_eof {
            match local.read(&mut up) {
                Ok(0) => {
                    local_eof = true;
                    let _s = session.lock();
                    let _ = channel.send_eof();
                }
                Ok(n) => {
                    let _s = session.lock();
                    let mut w = 0;
                    while w < n {
                        match channel.write(&up[w..n]) {
                            Ok(k) => { w += k; did_work = true; }
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                                drop(_s);
                                std::thread::sleep(Duration::from_millis(5));
                                break;
                            }
                            Err(e) => return Err(format!("ch write: {}", e)),
                        }
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("local read: {}", e)),
            }
        }

        // channel -> local
        if !channel_eof {
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
                Ok(n) => {
                    let mut w = 0;
                    while w < n {
                        match local.write(&dn[w..n]) {
                            Ok(k) => { w += k; did_work = true; }
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(e) => return Err(format!("local write: {}", e)),
                        }
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("ch read: {}", e)),
            }
        }

        if local_eof && channel_eof {
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

// Needed for UI lint silencing on unused fields.
#[allow(dead_code)]
fn _unused_mpsc_stub() -> Option<mpsc::Receiver<()>> { None }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_rule_parses_arrow_form() {
        let r = ForwardRule::parse("192.168.1.10:3306->localhost:13306").unwrap();
        assert_eq!(r.local_port, 13306);
        assert_eq!(r.remote_host, "192.168.1.10");
        assert_eq!(r.remote_port, 3306);
    }

    #[test]
    fn forward_rule_parses_compact_form() {
        let r = ForwardRule::parse("9000:10.0.0.5:80").unwrap();
        assert_eq!(r.local_port, 9000);
        assert_eq!(r.remote_host, "10.0.0.5");
        assert_eq!(r.remote_port, 80);
    }

    #[test]
    fn forward_rule_rejects_garbage() {
        assert!(ForwardRule::parse("not-a-rule").is_err());
    }
}
