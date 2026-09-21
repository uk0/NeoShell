//! Proxy support: SOCKS5(H) and HTTP CONNECT tunnels for SSH connections.
//!
//! Implements the proxy handshake at TCP level — returns a connected TcpStream
//! that can be passed directly to ssh2::Session::set_tcp_stream().

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    pub id: String,
    pub name: String,
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    // SSH bastion additional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,         // "password" | "key"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,       // path to private key file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,        // private key passphrase
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    Socks5h,
    Http,
    SshBastion,
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::Socks5h => write!(f, "SOCKS5H"),
            ProxyType::Http => write!(f, "HTTP"),
            ProxyType::SshBastion => write!(f, "SSH Bastion"),
        }
    }
}

/// Result of a proxy latency test.
#[derive(Debug, Clone)]
pub struct ProxyTestResult {
    pub reachable: bool,
    pub latency_ms: u64,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Proxy storage (plain JSON, owner-only on disk)
//
// NOT encrypted: `password` and `passphrase` are still written in the clear.
// Moving them into the vault is tracked separately; until then 0600 and an
// owner-only directory are the whole protection, which is why every write goes
// through `storage::write_private` rather than `std::fs::write`.
// ---------------------------------------------------------------------------

pub struct ProxyStore {
    path: std::path::PathBuf,
}

impl ProxyStore {
    pub fn new() -> Self {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("neoshell");
        if let Err(e) = crate::storage::create_dir_private(&dir) {
            log::error!("failed to create data dir {}: {}", dir.display(), e);
        }
        let store = Self {
            path: dir.join("proxies.json"),
        };
        // A file written by a pre-0.7.0 build is 0644 on disk; narrow it now
        // rather than waiting for the next save to rewrite it.
        crate::storage::tighten_permissions(&store.path);
        store
    }

    pub fn load(&self) -> Vec<ProxyConfig> {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        serde_json::from_str(&data).unwrap_or_default()
    }

    /// Replace the stored list, atomically and owner-only.
    ///
    /// Returns the failure instead of discarding it: a proxy that did not
    /// reach disk is gone on the next launch, and silently pretending
    /// otherwise is how a user loses a bastion definition without noticing.
    pub fn save(&self, proxies: &[ProxyConfig]) -> Result<(), String> {
        let json = serde_json::to_string_pretty(proxies)
            .map_err(|e| format!("cannot serialise proxies: {}", e))?;
        crate::storage::write_private(&self.path, json.as_bytes())
            .map_err(|e| format!("cannot write {}: {}", self.path.display(), e))
    }

    /// `save`, reporting a failure to the log.
    ///
    /// The mutators below keep returning `()` so the UI call sites are
    /// untouched; surfacing this in the UI is the follow-up.
    fn save_logged(&self, proxies: &[ProxyConfig], what: &str) {
        if let Err(e) = self.save(proxies) {
            log::error!("proxy store: {} was NOT saved: {}", what, e);
        }
    }

    pub fn add(&self, proxy: ProxyConfig) {
        let mut list = self.load();
        list.push(proxy);
        self.save_logged(&list, "add");
    }

    pub fn update(&self, proxy: &ProxyConfig) {
        let mut list = self.load();
        if let Some(existing) = list.iter_mut().find(|p| p.id == proxy.id) {
            *existing = proxy.clone();
        }
        self.save_logged(&list, "update");
    }

    pub fn delete(&self, id: &str) {
        let mut list = self.load();
        list.retain(|p| p.id != id);
        self.save_logged(&list, "delete");
    }

    pub fn get(&self, id: &str) -> Option<ProxyConfig> {
        self.load().into_iter().find(|p| p.id == id)
    }
}

// ---------------------------------------------------------------------------
// TCP connection through proxy
// ---------------------------------------------------------------------------

/// Connect to `target_host:target_port` through the given proxy.
/// Returns a TcpStream tunneled through the proxy, ready for SSH handshake.
pub fn connect_via_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    // Bastion owns its own SSH transport — don't preconnect a raw TCP socket.
    if proxy.proxy_type == ProxyType::SshBastion {
        return connect_via_ssh_bastion(proxy, target_host, target_port, timeout);
    }

    // Connect to proxy server
    let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
    let tcp = TcpStream::connect_timeout(
        &proxy_addr
            .to_socket_addrs()
            .map_err(|e| format!("Proxy DNS failed for '{}': {}", proxy_addr, e))?
            .next()
            .ok_or_else(|| format!("No address for proxy '{}'", proxy_addr))?,
        timeout,
    )
    .map_err(|e| format!("Proxy TCP connect to {} failed: {}", proxy_addr, e))?;

    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();

    match proxy.proxy_type {
        ProxyType::Socks5h => socks5_handshake(tcp, target_host, target_port, proxy),
        ProxyType::Http => http_connect_handshake(tcp, target_host, target_port, proxy),
        ProxyType::SshBastion => unreachable!("handled above"),
    }
}

/// Connect directly (no proxy) — same interface for uniform calling.
pub fn connect_direct(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolve failed for '{}': {}", addr, e))?
            .next()
            .ok_or_else(|| format!("No address found for '{}'", addr))?,
        timeout,
    )
    .map_err(|e| format!("TCP connect to {} failed: {}", addr, e))?;
    Ok(tcp)
}

// ---------------------------------------------------------------------------
// SOCKS5H handshake (RFC 1928 — with remote DNS resolution)
// ---------------------------------------------------------------------------

fn socks5_handshake(
    mut tcp: TcpStream,
    target_host: &str,
    target_port: u16,
    proxy: &ProxyConfig,
) -> Result<TcpStream, String> {
    let has_auth = proxy.username.is_some();

    // 1. Greeting: VER=5, NMETHODS, METHODS
    if has_auth {
        // Offer: no-auth (0x00) + username/password (0x02)
        tcp.write_all(&[0x05, 0x02, 0x00, 0x02])
            .map_err(|e| format!("SOCKS5 greeting write failed: {}", e))?;
    } else {
        // Offer: no-auth only
        tcp.write_all(&[0x05, 0x01, 0x00])
            .map_err(|e| format!("SOCKS5 greeting write failed: {}", e))?;
    }

    // 2. Server method selection
    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp)
        .map_err(|e| format!("SOCKS5 greeting read failed: {}", e))?;
    if resp[0] != 0x05 {
        return Err(format!("SOCKS5: invalid version {}", resp[0]));
    }

    match resp[1] {
        0x00 => {} // No auth needed
        0x02 => {
            // Username/password auth (RFC 1929)
            let user = proxy.username.as_deref().unwrap_or("");
            let pass = proxy.password.as_deref().unwrap_or("");
            let mut auth_req = vec![0x01]; // VER
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            tcp.write_all(&auth_req)
                .map_err(|e| format!("SOCKS5 auth write failed: {}", e))?;

            let mut auth_resp = [0u8; 2];
            tcp.read_exact(&mut auth_resp)
                .map_err(|e| format!("SOCKS5 auth read failed: {}", e))?;
            if auth_resp[1] != 0x00 {
                return Err("SOCKS5: authentication failed".to_string());
            }
        }
        0xFF => return Err("SOCKS5: no acceptable auth method".to_string()),
        m => return Err(format!("SOCKS5: unsupported auth method {}", m)),
    }

    // 3. CONNECT request — use DOMAINNAME (0x03) for SOCKS5H (remote DNS)
    let host_bytes = target_host.as_bytes();
    let mut req = vec![
        0x05, // VER
        0x01, // CMD: CONNECT
        0x00, // RSV
        0x03, // ATYP: DOMAINNAME
        host_bytes.len() as u8,
    ];
    req.extend_from_slice(host_bytes);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xFF) as u8);
    tcp.write_all(&req)
        .map_err(|e| format!("SOCKS5 connect write failed: {}", e))?;

    // 4. Read response
    let mut resp_head = [0u8; 4];
    tcp.read_exact(&mut resp_head)
        .map_err(|e| format!("SOCKS5 connect read failed: {}", e))?;
    if resp_head[0] != 0x05 {
        return Err(format!("SOCKS5: invalid response version {}", resp_head[0]));
    }
    if resp_head[1] != 0x00 {
        let err_msg = match resp_head[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(format!("SOCKS5 connect failed: {}", err_msg));
    }

    // Consume the bound address (skip it)
    match resp_head[3] {
        0x01 => {
            let mut skip = [0u8; 6]; // IPv4 (4) + port (2)
            tcp.read_exact(&mut skip).ok();
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).ok();
            let mut skip = vec![0u8; len[0] as usize + 2]; // domain + port
            tcp.read_exact(&mut skip).ok();
        }
        0x04 => {
            let mut skip = [0u8; 18]; // IPv6 (16) + port (2)
            tcp.read_exact(&mut skip).ok();
        }
        _ => {}
    }

    // Clear timeouts for SSH use
    tcp.set_read_timeout(None).ok();
    tcp.set_write_timeout(None).ok();
    tcp.set_nonblocking(false).ok();

    Ok(tcp)
}

// ---------------------------------------------------------------------------
// HTTP CONNECT handshake (RFC 7231)
// ---------------------------------------------------------------------------

fn http_connect_handshake(
    mut tcp: TcpStream,
    target_host: &str,
    target_port: u16,
    proxy: &ProxyConfig,
) -> Result<TcpStream, String> {
    let mut request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
        target_host, target_port, target_host, target_port
    );

    // Add proxy auth if configured
    if let Some(ref user) = proxy.username {
        let pass = proxy.password.as_deref().unwrap_or("");
        let cred = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", user, pass),
        );
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", cred));
    }
    request.push_str("\r\n");

    tcp.write_all(request.as_bytes())
        .map_err(|e| format!("HTTP CONNECT write failed: {}", e))?;

    // Read response (we need at least the status line)
    let mut buf = [0u8; 1024];
    let mut total = 0;
    loop {
        let n = tcp
            .read(&mut buf[total..])
            .map_err(|e| format!("HTTP CONNECT read failed: {}", e))?;
        if n == 0 {
            return Err("HTTP CONNECT: proxy closed connection".to_string());
        }
        total += n;
        // Check for end of headers
        if let Some(pos) = find_subsequence(&buf[..total], b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&buf[..pos]);
            // Parse status code from "HTTP/1.x 200 ..."
            if let Some(status_line) = header.lines().next() {
                let parts: Vec<&str> = status_line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let code: u16 = parts[1].parse().unwrap_or(0);
                    if code == 200 {
                        break; // Tunnel established
                    } else {
                        return Err(format!("HTTP CONNECT failed: {}", status_line));
                    }
                }
            }
            return Err(format!("HTTP CONNECT: invalid response: {}", header));
        }
        if total >= buf.len() {
            return Err("HTTP CONNECT: response too large".to_string());
        }
    }

    tcp.set_read_timeout(None).ok();
    tcp.set_write_timeout(None).ok();
    tcp.set_nonblocking(false).ok();

    Ok(tcp)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// SSH Bastion (ProxyJump) — tunnel via direct-tcpip channel
// ---------------------------------------------------------------------------

/// Connect to `target_host:target_port` via an SSH bastion host.
/// Uses `channel_direct_tcpip` over an SSH session to the bastion, then pumps
/// bytes through a local TCP loopback pair so the caller gets a normal TcpStream.
pub fn connect_via_ssh_bastion(
    bastion: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    // Create a local loopback pair so ssh2 can operate on a regular TcpStream:
    //   listener on 127.0.0.1:ephemeral — the relay thread accepts().
    //   client_end — connect back; caller uses this as the SSH transport.
    // The bind+connect+accept sequence is racy in theory (a local process could
    // hijack by connecting to the ephemeral port first), but the window is microseconds
    // on a single-user desktop. A stricter fix would exchange a one-shot token first.
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Bastion loopback bind failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("Bastion loopback local_addr failed: {}", e))?;

    // Connect first to the bastion SSH port & authenticate before returning —
    // this way any auth error is reported synchronously to the caller.
    let bastion_addr = format!("{}:{}", bastion.host, bastion.port);
    let bastion_tcp = TcpStream::connect_timeout(
        &bastion_addr
            .to_socket_addrs()
            .map_err(|e| format!("Bastion DNS failed for '{}': {}", bastion_addr, e))?
            .next()
            .ok_or_else(|| format!("No address for bastion '{}'", bastion_addr))?,
        timeout,
    )
    .map_err(|e| format!("Bastion TCP connect to {} failed: {}", bastion_addr, e))?;
    bastion_tcp.set_read_timeout(Some(timeout)).ok();
    bastion_tcp.set_write_timeout(Some(timeout)).ok();

    let mut session = ssh2::Session::new()
        .map_err(|e| format!("Bastion ssh2::Session::new failed: {}", e))?;
    session.set_tcp_stream(bastion_tcp);
    session.set_timeout(timeout.as_millis() as u32);
    // Offer the algorithm this bastion is already trusted under first, or a
    // host pinned as ssh-rsa answers with ed25519 and the check below reports
    // a mismatch on a perfectly legitimate server.
    crate::ssh::prepare_host_key_prefs_for(&session, &bastion.host, bastion.port);
    session
        .handshake()
        .map_err(|e| format!("Bastion SSH handshake failed: {}", e))?;
    // The bastion is a distinct host from the target behind it, so it needs
    // its own check — `try_handshake` only covers the target. Must happen
    // before the credentials below are offered to it.
    crate::ssh::verify_host_key(&session, &bastion.host, bastion.port)
        .map_err(|e| crate::ssh::translate_ssh_error(&e))?;

    // Authenticate to bastion
    let user = bastion
        .username
        .as_deref()
        .ok_or_else(|| "Bastion: username required".to_string())?;
    let auth_type = bastion.auth_type.as_deref().unwrap_or("password");
    match auth_type {
        "key" => {
            let key_path = bastion
                .private_key
                .as_deref()
                .ok_or_else(|| "Bastion: private_key path required".to_string())?;
            let passphrase = bastion.passphrase.as_deref();
            session
                .userauth_pubkey_file(user, None, &PathBuf::from(key_path), passphrase)
                .map_err(|e| format!("Bastion key auth failed: {}", e))?;
        }
        _ => {
            let pass = bastion.password.as_deref().unwrap_or("");
            session
                .userauth_password(user, pass)
                .map_err(|e| format!("Bastion password auth failed: {}", e))?;
        }
    }
    if !session.authenticated() {
        return Err("Bastion authentication failed".to_string());
    }

    // Open direct-tcpip channel to target
    let channel = session
        .channel_direct_tcpip(target_host, target_port, None)
        .map_err(|e| {
            format!(
                "Bastion direct-tcpip to {}:{} failed: {}",
                target_host, target_port, e
            )
        })?;

    // Accept connection from caller, then spawn relay thread.
    // Session must survive the relay; we move it into the thread.
    let client_end = TcpStream::connect_timeout(&local_addr, timeout)
        .map_err(|e| format!("Bastion loopback connect failed: {}", e))?;
    let (local_sock, _) = listener
        .accept()
        .map_err(|e| format!("Bastion loopback accept failed: {}", e))?;

    std::thread::spawn(move || {
        if let Err(e) = run_bastion_relay(session, channel, local_sock) {
            log::warn!("bastion relay ended: {}", e);
        }
    });

    // Caller-side socket is a plain blocking TCP stream
    client_end.set_nonblocking(false).ok();
    client_end.set_read_timeout(None).ok();
    client_end.set_write_timeout(None).ok();

    Ok(client_end)
}

/// Pump bytes between a local TCP socket and an SSH direct-tcpip channel.
/// Uses non-blocking polling — ssh2 channels aren't thread-safe for split
/// read/write, so we poll both sides in one thread.
fn run_bastion_relay(
    session: ssh2::Session,
    mut channel: ssh2::Channel,
    mut local: TcpStream,
) -> Result<(), String> {
    use std::io::ErrorKind;

    session.set_blocking(false);
    local
        .set_nonblocking(true)
        .map_err(|e| format!("loopback set_nonblocking failed: {}", e))?;

    let mut buf_up = [0u8; 32 * 1024]; // local -> channel
    let mut buf_dn = [0u8; 32 * 1024]; // channel -> local

    let mut local_closed = false;
    let mut channel_eof = false;

    loop {
        let mut did_work = false;

        // local -> channel
        if !local_closed {
            match local.read(&mut buf_up) {
                Ok(0) => {
                    local_closed = true;
                    // send_eof can return EAGAIN under non-blocking; retry briefly so the peer sees EOF.
                    let eof_deadline = Instant::now() + Duration::from_secs(5);
                    loop {
                        match channel.send_eof() {
                            Ok(()) => break,
                            Err(e)
                                if e.code() == ssh2::ErrorCode::Session(-37)
                                    && Instant::now() < eof_deadline =>
                            {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => break, // best-effort — log nothing to avoid noise
                        }
                    }
                }
                Ok(n) => {
                    let mut written = 0;
                    while written < n {
                        match channel.write(&buf_up[written..n]) {
                            Ok(w) => {
                                written += w;
                                did_work = true;
                            }
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(e) => return Err(format!("channel write: {}", e)),
                        }
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("local read: {}", e)),
            }
        }

        // channel -> local
        if !channel_eof {
            match channel.read(&mut buf_dn) {
                Ok(0) => {
                    if channel.eof() {
                        channel_eof = true;
                        let _ = local.shutdown(std::net::Shutdown::Write);
                    }
                }
                Ok(n) => {
                    let mut written = 0;
                    while written < n {
                        match local.write(&buf_dn[written..n]) {
                            Ok(w) => {
                                written += w;
                                did_work = true;
                            }
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(e) => return Err(format!("local write: {}", e)),
                        }
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("channel read: {}", e)),
            }
        }

        if local_closed && channel_eof {
            break;
        }
        if !did_work {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    let _ = channel.close();
    Ok(())
}

// ---------------------------------------------------------------------------
// Proxy latency test
// ---------------------------------------------------------------------------

/// Test proxy reachability and latency by performing a SOCKS5/HTTP handshake
/// to a well-known target (or just TCP connect to the proxy itself).
pub fn test_proxy(proxy: &ProxyConfig) -> ProxyTestResult {
    let start = Instant::now();
    let proxy_addr = format!("{}:{}", proxy.host, proxy.port);

    // Just test TCP connectivity + handshake to the proxy
    let result = TcpStream::connect_timeout(
        &match proxy_addr.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => {
                    return ProxyTestResult {
                        reachable: false,
                        latency_ms: 0,
                        error: Some("No address found".to_string()),
                    }
                }
            },
            Err(e) => {
                return ProxyTestResult {
                    reachable: false,
                    latency_ms: 0,
                    error: Some(format!("DNS: {}", e)),
                }
            }
        },
        Duration::from_secs(5),
    );

    match result {
        Ok(mut tcp) => {
            // Try a SOCKS5 greeting or HTTP HEAD to verify it's actually a proxy
            let latency = start.elapsed().as_millis() as u64;
            match proxy.proxy_type {
                ProxyType::Socks5h => {
                    // Send SOCKS5 greeting
                    if tcp.write_all(&[0x05, 0x01, 0x00]).is_ok() {
                        let mut resp = [0u8; 2];
                        if tcp.read_exact(&mut resp).is_ok() && resp[0] == 0x05 {
                            return ProxyTestResult {
                                reachable: true,
                                latency_ms: start.elapsed().as_millis() as u64,
                                error: None,
                            };
                        }
                    }
                    ProxyTestResult {
                        reachable: true,
                        latency_ms: latency,
                        error: Some("TCP OK but SOCKS5 handshake failed".to_string()),
                    }
                }
                ProxyType::Http => {
                    ProxyTestResult {
                        reachable: true,
                        latency_ms: latency,
                        error: None,
                    }
                }
                ProxyType::SshBastion => {
                    // Full SSH handshake + auth to bastion — this is the real test.
                    drop(tcp);
                    match test_ssh_bastion(proxy) {
                        Ok(ms) => ProxyTestResult {
                            reachable: true,
                            latency_ms: ms,
                            error: None,
                        },
                        Err(e) => ProxyTestResult {
                            reachable: false,
                            latency_ms: start.elapsed().as_millis() as u64,
                            error: Some(e),
                        },
                    }
                }
            }
        }
        Err(e) => ProxyTestResult {
            reachable: false,
            latency_ms: start.elapsed().as_millis() as u64,
            error: Some(format!("{}", e)),
        },
    }
}

fn test_ssh_bastion(bastion: &ProxyConfig) -> Result<u64, String> {
    let start = Instant::now();
    let addr = format!("{}:{}", bastion.host, bastion.port);
    let tcp = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .map_err(|e| format!("DNS: {}", e))?
            .next()
            .ok_or_else(|| "No address".to_string())?,
        Duration::from_secs(5),
    )
    .map_err(|e| format!("TCP: {}", e))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(10))).ok();

    let mut session = ssh2::Session::new().map_err(|e| format!("Session: {}", e))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(10_000);
    crate::ssh::prepare_host_key_prefs_for(&session, &bastion.host, bastion.port);
    session
        .handshake()
        .map_err(|e| format!("Handshake: {}", e))?;
    // A host-key failure is surfaced as unreachable-with-reason rather than an
    // auth error — this dialog is where a user should first see it.
    crate::ssh::verify_host_key(&session, &bastion.host, bastion.port)
        .map_err(|e| crate::ssh::translate_ssh_error(&e))?;

    let user = bastion
        .username
        .as_deref()
        .ok_or_else(|| "Username required".to_string())?;
    let auth_type = bastion.auth_type.as_deref().unwrap_or("password");
    match auth_type {
        "key" => {
            let key_path = bastion
                .private_key
                .as_deref()
                .ok_or_else(|| "Key path required".to_string())?;
            session
                .userauth_pubkey_file(
                    user,
                    None,
                    &PathBuf::from(key_path),
                    bastion.passphrase.as_deref(),
                )
                .map_err(|e| format!("Key auth: {}", e))?;
        }
        _ => {
            let pass = bastion.password.as_deref().unwrap_or("");
            session
                .userauth_password(user, pass)
                .map_err(|e| format!("Password auth: {}", e))?;
        }
    }
    if !session.authenticated() {
        return Err("Auth failed".to_string());
    }
    Ok(start.elapsed().as_millis() as u64)
}
