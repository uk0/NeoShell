//! Proxy support: SOCKS5(H) and HTTP CONNECT tunnels for SSH connections.
//!
//! Implements the proxy handshake at TCP level — returns a connected TcpStream
//! that can be passed directly to ssh2::Session::set_tcp_stream().

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::storage::{ConnectionStore, ProxySecret};

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
// Proxy storage
//
// proxies.json keeps only what the UI needs to list a proxy while the vault is
// locked — id, name, type, host, port, username. `password`, `private_key` and
// `passphrase` live in the vault under `proxy:<id>`, AES-256-GCM under the same
// DEK as a connection. A bastion is usually the more privileged hop, so it gets
// the same protection as the host behind it rather than 0600 alone.
//
// Entries written before 0.7.0 still carry the secret inline; `migrate_secrets`
// moves them across exactly once, and `schema` records that it happened.
// ---------------------------------------------------------------------------

/// On-disk schema for proxies.json.
///
/// * 0 — bare JSON array, `password` / `private_key` / `passphrase` inline.
/// * 1 — `{ "schema": 1, "proxies": [...] }`, secrets in the vault.
pub const PROXY_SCHEMA: u32 = 1;

/// Vault key holding this proxy's credentials.
pub fn proxy_secret_key(id: &str) -> String {
    format!("proxy:{}", id)
}

/// The schema-1 document. Both fields default, so `{}` and a file written by a
/// future build that adds a field still parse.
#[derive(Serialize, Deserialize, Default)]
struct ProxyFile {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    proxies: Vec<ProxyConfig>,
}

pub struct ProxyStore {
    path: PathBuf,
    /// An explicitly supplied vault. `None` means "ask the process-wide
    /// registry at the point of use" — `new()` runs inside the app's `Default`,
    /// which is before the vault has been registered.
    vault: Option<Arc<ConnectionStore>>,
}

impl ProxyStore {
    /// The normal entry point. Resolves the process-wide vault lazily —
    /// `establish_tcp` builds a store from an SSH worker thread that has no
    /// other way to reach one.
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
        let store = Self::at(dir.join("proxies.json"), vault);
        // A file written by a pre-0.7.0 build is 0644 on disk; narrow it now
        // rather than waiting for the next save to rewrite it.
        crate::storage::tighten_permissions(&store.path);
        store
    }

    /// Explicit path — `new()` is the real entry point; this is for tests,
    /// including the ones in `ssh` that drive the connect path.
    pub(crate) fn at(path: PathBuf, vault: Option<Arc<ConnectionStore>>) -> Self {
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
    /// a credential into proxies.json in the clear.
    fn vault(&self) -> Result<Arc<ConnectionStore>, String> {
        self.vault_handle()
            .ok_or_else(|| crate::i18n::t("vault.locked_secret").to_string())
    }

    fn read_file(&self) -> ProxyFile {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(d) => d,
            // No file yet: nothing to migrate, so start at the current schema.
            Err(_) => return ProxyFile { schema: PROXY_SCHEMA, proxies: Vec::new() },
        };
        if let Ok(file) = serde_json::from_str::<ProxyFile>(&data) {
            return file;
        }
        // Pre-0.7.0 shape: a bare array with the secrets inline.
        match serde_json::from_str::<Vec<ProxyConfig>>(&data) {
            Ok(proxies) => ProxyFile { schema: 0, proxies },
            Err(e) => {
                // Report the current schema so nothing rewrites — and thereby
                // destroys — a file we simply failed to understand.
                log::error!("cannot parse {}: {}", self.path.display(), e);
                ProxyFile { schema: PROXY_SCHEMA, proxies: Vec::new() }
            }
        }
    }

    /// Fill in `cfg`'s secrets from the vault. `Err` means they exist but are
    /// out of reach, which is not the same as a proxy that has none.
    fn resolve_secret(&self, schema: u32, cfg: &mut ProxyConfig) -> Result<(), String> {
        if schema < PROXY_SCHEMA {
            return Ok(()); // not migrated yet — the secret is still inline
        }
        if let Some(s) = self.vault()?.get_secret(&proxy_secret_key(&cfg.id))? {
            cfg.password = s.password;
            cfg.private_key = s.private_key;
            cfg.passphrase = s.passphrase;
        }
        Ok(())
    }

    /// Move `cfg`'s secrets into the vault, leaving `cfg` secret-free and ready
    /// to serialize. Clearing every field deletes the stored secret, so a
    /// password the user emptied in the form does not come back.
    fn store_secret(&self, cfg: &mut ProxyConfig) -> Result<(), String> {
        let secret = ProxySecret {
            password: cfg.password.take(),
            private_key: cfg.private_key.take(),
            passphrase: cfg.passphrase.take(),
        };
        let key = proxy_secret_key(&cfg.id);
        let vault = self.vault()?;
        if secret.is_empty() {
            vault.delete_secret(&key)
        } else {
            vault.put_secret(&key, &secret)
        }
    }

    /// Every proxy, with its credentials filled in when the vault allows.
    ///
    /// A proxy whose secret cannot be read is still listed — the manager panel
    /// has to show it — just without the credential. The connect path uses
    /// `get_for_connect`, which refuses instead.
    pub fn load(&self) -> Vec<ProxyConfig> {
        let mut file = self.read_file();
        for p in file.proxies.iter_mut() {
            if let Err(e) = self.resolve_secret(file.schema, p) {
                log::debug!("proxy '{}': credentials unavailable: {}", p.id, e);
            }
        }
        file.proxies
    }

    fn write(&self, file: &ProxyFile, scrubbing: bool) -> Result<(), String> {
        let json = serde_json::to_string_pretty(file)
            .map_err(|e| format!("cannot serialise proxies: {}", e))?;
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
    /// confirmed to hold the secret — a failure anywhere leaves proxies.json
    /// untouched and the migration is simply retried.
    pub fn migrate_secrets(&self) -> Result<bool, String> {
        let mut file = self.read_file();
        if file.schema >= PROXY_SCHEMA {
            return Ok(false);
        }

        let pending = file.proxies.iter().filter(|p| has_inline_secret(p)).count();
        if pending > 0 {
            let vault = match self.vault_handle() {
                Some(v) => v,
                None => {
                    log::info!(
                        "proxy store: {} entries still hold an inline credential; \
                         deferring migration until the vault is unlocked",
                        pending
                    );
                    return Ok(false);
                }
            };
            for p in file.proxies.iter_mut() {
                let secret = ProxySecret {
                    password: p.password.take(),
                    private_key: p.private_key.take(),
                    passphrase: p.passphrase.take(),
                };
                if secret.is_empty() {
                    continue;
                }
                let key = proxy_secret_key(&p.id);
                vault.put_secret(&key, &secret)?;
                // Read it back before the cleartext is destroyed below.
                if vault.get_secret(&key)?.as_ref() != Some(&secret) {
                    return Err(format!(
                        "vault did not retain the credential for proxy '{}' — \
                         leaving {} as it is",
                        p.id,
                        self.path.display()
                    ));
                }
            }
        }

        file.schema = PROXY_SCHEMA;
        // The bytes being replaced are the ones holding the cleartext.
        self.write(&file, true)?;
        log::info!("proxy store: migrated {} credentials into the vault", pending);
        Ok(true)
    }

    /// Migrate if needed, then hand back the file — or refuse, because writing
    /// on top of a deferred migration would either strand the secrets that
    /// never moved or mark them migrated when they were not.
    fn file_for_write(&self) -> Result<ProxyFile, String> {
        self.migrate_secrets()?;
        let file = self.read_file();
        if file.schema < PROXY_SCHEMA {
            return Err(crate::i18n::t("vault.locked_secret").to_string());
        }
        Ok(file)
    }

    /// Append `proxy`, its credentials moved into the vault.
    pub fn try_add(&self, mut proxy: ProxyConfig) -> Result<(), String> {
        let mut file = self.file_for_write()?;
        self.store_secret(&mut proxy)?;
        file.proxies.push(proxy);
        self.write(&file, false)
    }

    /// Replace the entry with `proxy.id`, its credentials moved into the vault.
    pub fn try_update(&self, proxy: &ProxyConfig) -> Result<(), String> {
        let mut file = self.file_for_write()?;
        let mut proxy = proxy.clone();
        self.store_secret(&mut proxy)?;
        if let Some(existing) = file.proxies.iter_mut().find(|p| p.id == proxy.id) {
            *existing = proxy;
        }
        self.write(&file, false)
    }

    /// Remove the entry with `id`, and its credentials from the vault.
    pub fn try_delete(&self, id: &str) -> Result<(), String> {
        let mut file = self.file_for_write()?;
        file.proxies.retain(|p| p.id != id);
        match self.vault_handle() {
            Some(v) => v.delete_secret(&proxy_secret_key(id))?,
            // Harmless — an unreferenced blob — but worth knowing about.
            None => log::warn!("proxy '{}' deleted; its vault secret was left behind", id),
        }
        self.write(&file, false)
    }

    /// One proxy, credentials filled in where possible. Same caveat as `load`.
    ///
    /// Test-only: it answers a locked vault with a config that silently lacks
    /// its secret, which is exactly how `establish_tcp` came to offer proxies
    /// an empty password. Anything that connects uses `get_for_connect`.
    #[cfg(test)]
    pub fn get(&self, id: &str) -> Option<ProxyConfig> {
        let file = self.read_file();
        let mut cfg = file.proxies.into_iter().find(|p| p.id == id)?;
        if let Err(e) = self.resolve_secret(file.schema, &mut cfg) {
            log::debug!("proxy '{}': credentials unavailable: {}", id, e);
        }
        Some(cfg)
    }

    /// One proxy, for actually connecting through it.
    ///
    /// Fails closed. A proxy that no longer exists is an error, not a reason to
    /// dial the target directly, and one whose credential is locked in the
    /// vault surfaces as "unlock first" instead of a handshake that offers the
    /// proxy an empty password. A proxy configured without authentication
    /// takes nothing from the vault, so it keeps working while it is locked.
    pub fn get_for_connect(&self, id: &str) -> Result<ProxyConfig, String> {
        let file = self.read_file();
        let mut cfg = file
            .proxies
            .into_iter()
            .find(|p| p.id == id)
            .ok_or_else(|| crate::i18n::tf("proxy.err.missing", &[("id", id)]))?;
        if !needs_credential(&cfg) {
            return Ok(cfg);
        }
        if file.schema >= PROXY_SCHEMA && self.vault_handle().is_none() {
            return Err(crate::i18n::tf(
                "proxy.err.vault_locked",
                &[("name", &cfg.name)],
            ));
        }
        self.resolve_secret(file.schema, &mut cfg)?;
        Ok(cfg)
    }
}

/// Does this entry still carry a credential in the JSON file?
fn has_inline_secret(p: &ProxyConfig) -> bool {
    p.password.is_some() || p.private_key.is_some() || p.passphrase.is_some()
}

/// Whether connecting through `p` takes a secret from the vault: a bastion
/// always authenticates, a SOCKS5 / HTTP proxy only when it has a username.
fn needs_credential(p: &ProxyConfig) -> bool {
    p.proxy_type == ProxyType::SshBastion || p.username.is_some()
}

/// The username and password a SOCKS5 or HTTP proxy authenticates with, or
/// `None` when it is configured without authentication.
///
/// A username with no password is an error, never an empty password. With the
/// secret in the vault, "no password" far more often means "out of reach" than
/// "deliberately blank", and an auto-reconnect offers it again on every retry —
/// enough to lock the account behind the proxy.
fn proxy_credentials(proxy: &ProxyConfig) -> Result<Option<(&str, &str)>, String> {
    match (proxy.username.as_deref(), proxy.password.as_deref()) {
        (None, _) => Ok(None),
        (Some(user), Some(pass)) => Ok(Some((user, pass))),
        (Some(_), None) => Err(crate::i18n::tf(
            "proxy.err.no_password",
            &[("name", &proxy.name)],
        )),
    }
}

/// How an SSH bastion authenticates.
enum BastionAuth<'a> {
    Password(&'a str),
    Key {
        path: &'a str,
        passphrase: Option<&'a str>,
    },
}

/// The bastion's username and credential, or why there is none. Called before
/// anything is dialled: no credential, no network traffic.
fn bastion_credentials(bastion: &ProxyConfig) -> Result<(&str, BastionAuth<'_>), String> {
    let user = bastion
        .username
        .as_deref()
        .ok_or_else(|| "Bastion: username required".to_string())?;
    if bastion.auth_type.as_deref() == Some("key") {
        let path = bastion
            .private_key
            .as_deref()
            .ok_or_else(|| "Bastion: private_key path required".to_string())?;
        let passphrase = bastion.passphrase.as_deref();
        return Ok((user, BastionAuth::Key { path, passphrase }));
    }
    // No fallback to "": the password now lives in the vault, and offering an
    // empty one to a bastion because the vault is locked is exactly the silent
    // failure this must not have.
    let pass = bastion
        .password
        .as_deref()
        .ok_or_else(|| crate::i18n::tf("proxy.err.no_password", &[("name", &bastion.name)]))?;
    Ok((user, BastionAuth::Password(pass)))
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

    // Credentials before the socket: a proxy we could not authenticate to is
    // not dialled at all.
    proxy_credentials(proxy)?;

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
    let creds = proxy_credentials(proxy)?;
    let has_auth = creds.is_some();

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

    match (resp[1], creds) {
        (0x00, _) => {} // No auth needed
        // Username/password auth (RFC 1929). Only ever offered with a real
        // credential in hand: a server that picks it anyway gets the
        // "unsupported" error below, not an empty username and password.
        (0x02, Some((user, pass))) => {
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
        (0xFF, _) => return Err("SOCKS5: no acceptable auth method".to_string()),
        (m, _) => return Err(format!("SOCKS5: unsupported auth method {}", m)),
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

    // Add proxy auth if configured — a username without a password is refused
    // before a byte is sent, never offered as "user:".
    if let Some((user, pass)) = proxy_credentials(proxy)? {
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
    // Credentials first. Nothing — not the loopback listener, not a packet to
    // the bastion — is opened for a hop we could not authenticate to; a locked
    // vault used to cost a TCP connect, a handshake and a host-key check
    // before failing here.
    let (user, auth) = bastion_credentials(bastion)?;

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

    // Authenticate to bastion, with the credential resolved above.
    match auth {
        BastionAuth::Key { path, passphrase } => {
            session
                .userauth_pubkey_file(user, None, &PathBuf::from(path), passphrase)
                .map_err(|e| format!("Bastion key auth failed: {}", e))?;
        }
        BastionAuth::Password(pass) => {
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
    // As in `connect_via_ssh_bastion`: no credential, no handshake.
    let (user, auth) = bastion_credentials(bastion)?;
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

    match auth {
        BastionAuth::Key { path, passphrase } => {
            session
                .userauth_pubkey_file(user, None, &PathBuf::from(path), passphrase)
                .map_err(|e| format!("Key auth: {}", e))?;
        }
        BastionAuth::Password(pass) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PW: &str = "correct horse battery staple";

    /// A scratch directory holding a vault plus a proxies.json, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "neoshell-proxy-test-{}-{}-{}",
                std::process::id(),
                tag,
                N.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn proxies(&self) -> PathBuf {
            self.0.join("proxies.json")
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
        fn store(&self, vault: Option<Arc<ConnectionStore>>) -> ProxyStore {
            ProxyStore::at(self.proxies(), vault)
        }

        fn raw(&self) -> String {
            std::fs::read_to_string(self.proxies()).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Exactly what a pre-0.7.0 build left on disk: a bare array, secrets inline.
    fn write_legacy(s: &Scratch) {
        std::fs::write(
            s.proxies(),
            r#"[
              {"id":"p1","name":"bastion","proxy_type":"sshbastion","host":"10.0.0.9",
               "port":22,"username":"jump","password":"hunter2","auth_type":"password"},
              {"id":"p2","name":"corp","proxy_type":"socks5h","host":"127.0.0.1","port":1080}
            ]"#,
        )
        .unwrap();
    }

    fn sample(id: &str) -> ProxyConfig {
        ProxyConfig {
            id: id.to_string(),
            name: "bastion".to_string(),
            proxy_type: ProxyType::SshBastion,
            host: "10.0.0.9".to_string(),
            port: 22,
            username: Some("jump".to_string()),
            password: Some("hunter2".to_string()),
            auth_type: Some("password".to_string()),
            private_key: None,
            passphrase: None,
        }
    }

    #[test]
    fn an_unmigrated_file_still_loads_with_its_secrets() {
        let s = Scratch::new("legacy-load");
        write_legacy(&s);

        // Even with no vault at all: the secrets are still inline.
        let list = s.store(None).load();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].password.as_deref(), Some("hunter2"));
        assert_eq!(list[1].password, None);
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
        assert!(raw.contains("10.0.0.9"));
        assert!(raw.contains("jump"));

        assert_eq!(
            vault.get_secret("proxy:p1").unwrap(),
            Some(ProxySecret { password: Some("hunter2".into()), ..Default::default() })
        );
        // A proxy that had no credential gets no blob.
        assert_eq!(vault.get_secret("proxy:p2").unwrap(), None);

        // And the round trip still produces the original config.
        assert_eq!(store.get("p1").unwrap().password.as_deref(), Some("hunter2"));
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
        assert_eq!(store.get("p1").unwrap().password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn a_locked_vault_defers_migration_instead_of_destroying_the_secret() {
        let s = Scratch::new("migrate-locked");
        write_legacy(&s);
        let before = s.raw();

        for store in [s.store(None), s.store(Some(s.locked_vault()))] {
            assert!(!store.migrate_secrets().unwrap());
            assert_eq!(s.raw(), before, "a locked vault must not touch the file");
            // The secret is still readable, because it never moved.
            assert_eq!(store.get("p1").unwrap().password.as_deref(), Some("hunter2"));
            // And nothing may be written on top of a deferred migration.
            assert!(store.try_delete("p2").is_err());
        }

        // Unlocking later completes it.
        let store = s.store(Some(s.vault()));
        assert!(store.migrate_secrets().unwrap());
        assert!(!s.raw().contains("hunter2"));
    }

    #[test]
    fn add_writes_the_credential_to_the_vault_and_not_to_the_file() {
        let s = Scratch::new("add");
        let vault = s.vault();
        let store = s.store(Some(vault.clone()));

        store.try_add(sample("p1")).unwrap();
        assert!(!s.raw().contains("hunter2"), "cleartext in proxies.json: {}", s.raw());
        assert_eq!(store.get("p1").unwrap().password.as_deref(), Some("hunter2"));
        assert_eq!(store.get_for_connect("p1").unwrap().password.as_deref(), Some("hunter2"));

        // Clearing the field in the form drops the stored secret rather than
        // leaving the old one to be resurrected on the next read.
        let mut cleared = sample("p1");
        cleared.password = None;
        store.try_update(&cleared).unwrap();
        assert_eq!(vault.get_secret("proxy:p1").unwrap(), None);
        assert_eq!(store.get("p1").unwrap().password, None);

        store.try_delete("p1").unwrap();
        assert!(store.get("p1").is_none());
        assert!(store.get_for_connect("p1").is_err());
    }

    #[test]
    fn a_locked_vault_refuses_to_connect_rather_than_offering_no_credential() {
        let s = Scratch::new("connect-locked");
        s.store(Some(s.vault())).try_add(sample("p1")).unwrap();

        let locked = s.store(Some(s.locked_vault()));
        // Listing still works — the manager panel needs it.
        assert_eq!(locked.load().len(), 1);
        assert_eq!(locked.load()[0].host, "10.0.0.9");
        assert_eq!(locked.load()[0].password, None);
        // Connecting does not — and it says which proxy, and why.
        let err = locked.get_for_connect("p1").unwrap_err();
        assert!(
            is_message(&err, "proxy.err.vault_locked", &[("name", "bastion")]),
            "{}",
            err
        );
        assert!(locked.try_add(sample("p2")).is_err());
        assert!(locked.try_update(&sample("p1")).is_err());
    }

    #[test]
    fn a_proxy_without_authentication_still_connects_while_the_vault_is_locked() {
        let s = Scratch::new("connect-locked-open");
        let unlocked = s.store(Some(s.vault()));
        let mut open = sample("p2");
        open.proxy_type = ProxyType::Socks5h;
        open.username = None;
        open.password = None;
        open.auth_type = None;
        unlocked.try_add(open).unwrap();
        let mut authed = sample("p3");
        authed.proxy_type = ProxyType::Socks5h;
        authed.name = "corp-socks".to_string();
        unlocked.try_add(authed).unwrap();

        let locked = s.store(Some(s.locked_vault()));
        // Nothing of p2's lives in the vault, so the lock is no reason to
        // strand a session that reconnects through it.
        assert_eq!(locked.get_for_connect("p2").unwrap().host, "10.0.0.9");
        // p3 authenticates: refused, by name.
        let err = locked.get_for_connect("p3").unwrap_err();
        assert!(
            is_message(&err, "proxy.err.vault_locked", &[("name", "corp-socks")]),
            "{}",
            err
        );
        // A proxy that is gone is refused too, never bypassed.
        let err = locked.get_for_connect("gone").unwrap_err();
        assert!(
            is_message(&err, "proxy.err.missing", &[("id", "gone")]),
            "{}",
            err
        );
    }

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

    /// A live local port that records whether anything connected to it: the
    /// proof that a refused credential cost no network traffic.
    struct Tripwire(TcpListener);

    impl Tripwire {
        fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            Tripwire(listener)
        }

        fn port(&self) -> u16 {
            self.0.local_addr().unwrap().port()
        }

        fn tripped(&self) -> bool {
            match self.0.accept() {
                Ok(_) => true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(e) => panic!("tripwire: {}", e),
            }
        }
    }

    #[test]
    fn a_bastion_with_no_password_fails_before_the_handshake() {
        // A live listener where the bastion would be. While the credential
        // was only checked after connecting, this saw a connection and the
        // error was the SSH handshake timing out against it.
        let wire = Tripwire::new();
        let mut cfg = sample("p1");
        cfg.name = "jump-no-password".to_string();
        cfg.password = None;
        cfg.host = "127.0.0.1".to_string();
        cfg.port = wire.port();
        let name = [("name", "jump-no-password")];

        let err =
            connect_via_ssh_bastion(&cfg, "target", 22, Duration::from_millis(300)).unwrap_err();
        assert!(is_message(&err, "proxy.err.no_password", &name), "{}", err);
        assert!(
            !wire.tripped(),
            "the bastion was dialled without a credential"
        );

        // The proxy dialog's "Test" button takes the same path.
        let err = test_ssh_bastion(&cfg).unwrap_err();
        assert!(is_message(&err, "proxy.err.no_password", &name), "{}", err);
        assert!(
            !wire.tripped(),
            "the bastion test dialled without a credential"
        );
    }

    #[test]
    fn a_proxy_username_without_a_password_is_refused_before_dialling() {
        for kind in [ProxyType::Socks5h, ProxyType::Http] {
            let wire = Tripwire::new();
            let cfg = ProxyConfig {
                id: "p9".to_string(),
                name: "corp-no-password".to_string(),
                proxy_type: kind.clone(),
                host: "127.0.0.1".to_string(),
                port: wire.port(),
                username: Some("alice".to_string()),
                password: None,
                auth_type: None,
                private_key: None,
                passphrase: None,
            };
            let err =
                connect_via_proxy(&cfg, "target", 22, Duration::from_millis(300)).unwrap_err();
            assert!(
                is_message(
                    &err,
                    "proxy.err.no_password",
                    &[("name", "corp-no-password")]
                ),
                "{:?}: {}",
                kind,
                err
            );
            assert!(!wire.tripped(), "{:?} proxy dialled with no password", kind);
        }
    }

    /// What a fake SOCKS5 server received: the greeting, then everything after.
    type Received = (Vec<u8>, Vec<u8>);

    /// A one-shot SOCKS5 server that answers any greeting by choosing
    /// username/password auth, then records everything the client sends.
    fn socks5_demanding_auth() -> (u16, std::thread::JoinHandle<Received>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut greeting = vec![0u8; 2];
            if s.read_exact(&mut greeting).is_err() {
                return (Vec::new(), Vec::new());
            }
            let mut methods = vec![0u8; greeting[1] as usize];
            let _ = s.read_exact(&mut methods);
            greeting.extend_from_slice(&methods);
            let _ = s.write_all(&[0x05, 0x02]);
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
            (greeting, rest)
        });
        (port, server)
    }

    fn socks(name: &str, port: u16, username: Option<&str>) -> ProxyConfig {
        ProxyConfig {
            id: "p8".to_string(),
            name: name.to_string(),
            proxy_type: ProxyType::Socks5h,
            host: "127.0.0.1".to_string(),
            port,
            username: username.map(str::to_string),
            password: None,
            auth_type: None,
            private_key: None,
            passphrase: None,
        }
    }

    fn client(port: u16) -> TcpStream {
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp
    }

    #[test]
    fn the_socks5_handshake_never_sends_an_empty_credential() {
        // A username with no password: refused before even the greeting.
        let (port, server) = socks5_demanding_auth();
        let cfg = socks("corp-socks", port, Some("alice"));
        let err = socks5_handshake(client(port), "target", 22, &cfg).unwrap_err();
        assert!(
            is_message(&err, "proxy.err.no_password", &[("name", "corp-socks")]),
            "{}",
            err
        );
        assert_eq!(
            server.join().unwrap(),
            (Vec::new(), Vec::new()),
            "bytes reached the proxy"
        );

        // No username, and a server that picks username/password anyway: it
        // used to be sent an empty username and password.
        let (port, server) = socks5_demanding_auth();
        let cfg = socks("corp-socks", port, None);
        let err = socks5_handshake(client(port), "target", 22, &cfg).unwrap_err();
        assert_eq!(err, "SOCKS5: unsupported auth method 2");
        let (greeting, rest) = server.join().unwrap();
        assert_eq!(
            greeting,
            vec![0x05, 0x01, 0x00],
            "offered more than no-auth"
        );
        assert!(
            rest.is_empty(),
            "sent {:?} after an unoffered method was picked",
            rest
        );
    }

    #[test]
    fn the_http_handshake_never_sends_user_colon_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut got = Vec::new();
            let _ = s.read_to_end(&mut got);
            got
        });
        let mut cfg = socks("corp-http", port, Some("alice"));
        cfg.proxy_type = ProxyType::Http;
        let err = http_connect_handshake(client(port), "target", 22, &cfg).unwrap_err();
        assert!(
            is_message(&err, "proxy.err.no_password", &[("name", "corp-http")]),
            "{}",
            err
        );
        let got = server.join().unwrap();
        assert!(got.is_empty(), "sent {:?}", String::from_utf8_lossy(&got));
    }

    #[test]
    fn a_garbled_file_is_reported_and_never_silently_replaced() {
        let s = Scratch::new("garbled");
        std::fs::write(s.proxies(), "{not json").unwrap();
        let store = s.store(Some(s.vault()));
        assert!(store.load().is_empty());
        // Migration must not "fix" it by writing an empty list over the top.
        assert!(!store.migrate_secrets().unwrap());
        assert_eq!(s.raw(), "{not json");
    }
}
