use std::collections::HashMap;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpStream;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use ssh2::Session;

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

/// A handle to a single active SSH session.
pub struct SshSession {
    pub session_id: String,
    pub connection_id: String,
    /// Channel for sending commands (write, resize, disconnect) into the
    /// session's background thread.
    pub writer: tokio::sync::mpsc::Sender<SshCommand>,
    /// Shared SSH session handle for opening exec channels.
    pub session: Arc<Mutex<Session>>,
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
    ) -> Result<String, String> {
        let session_id = uuid::Uuid::new_v4().to_string();

        // --- Establish TCP + SSH handshake (blocking) ----------------------
        let addr = format!("{}:{}", host, port);
        let tcp = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| format!("Invalid address '{}': {}", addr, e))?,
            Duration::from_secs(10),
        )
        .map_err(|e| format!("TCP connect to {} failed: {}", addr, e))?;

        tcp.set_nonblocking(false)
            .map_err(|e| format!("Failed to set blocking mode: {}", e))?;

        let mut session =
            Session::new().map_err(|e| format!("Failed to create SSH session: {}", e))?;
        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|e| format!("SSH handshake failed: {}", e))?;

        // --- Authenticate --------------------------------------------------
        match auth_type {
            "password" => {
                let pw = password.ok_or("Password required for password auth")?;
                session
                    .userauth_password(username, pw)
                    .map_err(|e| format!("Password auth failed: {}", e))?;
            }
            "key" => {
                let key_path_str =
                    private_key.ok_or("Private key path required for key auth")?;
                let key_path = std::path::Path::new(key_path_str);
                session
                    .userauth_pubkey_file(username, None, key_path, passphrase)
                    .map_err(|e| format!("Public-key auth failed: {}", e))?;
            }
            other => {
                return Err(format!("Unknown auth type: {}", other));
            }
        }

        if !session.authenticated() {
            return Err("Authentication failed".to_string());
        }

        // --- Open channel, request PTY, start shell ------------------------
        let mut channel = session
            .channel_session()
            .map_err(|e| format!("Failed to open channel: {}", e))?;

        channel
            .request_pty("xterm-256color", None, Some((80, 24, 0, 0)))
            .map_err(|e| format!("PTY request failed: {}", e))?;
        channel
            .shell()
            .map_err(|e| format!("Shell request failed: {}", e))?;

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

        // --- Reader thread: reads from SSH channel, emits SshEvent ---------
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                let result = {
                    let mut ch = channel_reader.lock();
                    ch.read(&mut buf)
                };
                match result {
                    Ok(0) => {
                        // Channel closed by remote
                        let _ = event_tx.send(SshEvent::Closed { session_id: sid_reader.clone() });
                        break;
                    }
                    Ok(n) => {
                        let data = buf[..n].to_vec();
                        if event_tx
                            .send(SshEvent::Data { session_id: sid_reader.clone(), data })
                            .is_err()
                        {
                            break; // receiver dropped
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Non-blocking read: nothing available yet, sleep briefly.
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        let _ = event_tx.send(SshEvent::Error {
                            session_id: sid_reader.clone(),
                            error: format!("Read error: {}", e),
                        });
                        let _ = event_tx.send(SshEvent::Closed { session_id: sid_reader.clone() });
                        break;
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
            session,
        };

        self.sessions.write().insert(session_id.clone(), ssh_session);

        Ok(session_id)
    }

    /// Send raw bytes to the remote shell.
    pub fn write(&self, session_id: &str, data: &[u8]) -> Result<(), String> {
        let sessions = self.sessions.read();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("Session '{}' not found", session_id))?;
        session
            .writer
            .try_send(SshCommand::Write(data.to_vec()))
            .map_err(|e| format!("Failed to send write command: {}", e))
    }

    /// Request a PTY resize on the remote end.
    pub fn resize(&self, session_id: &str, cols: u32, rows: u32) -> Result<(), String> {
        let sessions = self.sessions.read();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("Session '{}' not found", session_id))?;
        session
            .writer
            .try_send(SshCommand::Resize(cols, rows))
            .map_err(|e| format!("Failed to send resize command: {}", e))
    }

    /// Disconnect a session.
    pub fn disconnect(&self, session_id: &str) -> Result<(), String> {
        let sessions = self.sessions.read();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("Session '{}' not found", session_id))?;
        let _ = session.writer.try_send(SshCommand::Disconnect);
        drop(sessions);
        self.sessions.write().remove(session_id);
        Ok(())
    }

    /// Get a list of active session ids.
    pub fn active_sessions(&self) -> Vec<String> {
        self.sessions.read().keys().cloned().collect()
    }

    /// Execute a single command on the SSH session and return stdout.
    /// Opens a new exec channel (separate from the interactive shell).
    pub fn exec_command(&self, session_id: &str, command: &str) -> Result<String, String> {
        let sessions = self.sessions.read();
        let ssh_session = sessions
            .get(session_id)
            .ok_or_else(|| format!("Session '{}' not found", session_id))?;

        let sess = ssh_session.session.lock();
        // Must be blocking for exec
        sess.set_blocking(true);

        let mut channel = sess
            .channel_session()
            .map_err(|e| format!("Failed to open exec channel: {}", e))?;
        channel
            .exec(command)
            .map_err(|e| format!("Failed to exec command: {}", e))?;

        let mut output = String::new();
        channel
            .read_to_string(&mut output)
            .map_err(|e| format!("Failed to read command output: {}", e))?;
        channel
            .wait_close()
            .map_err(|e| format!("Channel close error: {}", e))?;

        // Restore non-blocking for the interactive session
        sess.set_blocking(false);

        Ok(output)
    }

    /// Fetch server stats by running monitoring commands.
    pub fn fetch_server_stats(&self, session_id: &str) -> Result<ServerStats, String> {
        // Single compound command for efficiency
        let cmd = "cat /proc/loadavg; echo '---SEPARATOR---'; \
                   free -m; echo '---SEPARATOR---'; \
                   df -h / 2>/dev/null || df -h . 2>/dev/null; echo '---SEPARATOR---'; \
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

        // Parse df -h /
        if let Some(df_output) = sections.get(2) {
            for line in df_output.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    stats.disk_total_gb = parse_size_to_gb(parts[1]);
                    stats.disk_used_gb = parse_size_to_gb(parts[2]);
                    stats.disk_percent =
                        parts[4].trim_end_matches('%').parse().unwrap_or(0.0);
                    break;
                }
            }
        }

        // Parse /proc/net/dev (sum all interfaces except lo)
        if let Some(net_output) = sections.get(3) {
            for line in net_output.lines() {
                let line = line.trim();
                if line.starts_with("lo:") || !line.contains(':') {
                    continue;
                }
                let after_colon = line.split(':').nth(1).unwrap_or("");
                let parts: Vec<&str> = after_colon.split_whitespace().collect();
                if parts.len() >= 9 {
                    stats.net_rx_bytes += parts[0].parse::<u64>().unwrap_or(0);
                    stats.net_tx_bytes += parts[8].parse::<u64>().unwrap_or(0);
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
