use iced::widget::{
    button, canvas, column, container, horizontal_space, row, scrollable, stack, text,
    text_editor, text_input, vertical_space, Space,
};
use iced::{
    alignment, event, keyboard, mouse, time, Color, Element, Fill, Font,
    Length, Padding, Pixels, Point, Rectangle, Renderer, Size, Subscription,
    Task, Theme,
};

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::ssh::{FileEntry, ProcessInfo, ServerStats, SshEvent, SshManager, TransferProgress};
use crate::storage::{ConnectionConfig, ConnectionInfo, ConnectionStore};
use crate::terminal::TerminalGrid;
use crate::ui::theme;

/// System CJK font for rendering Chinese/Japanese/Korean characters.
/// iced canvas doesn't do font fallback, so we must specify explicitly.
#[cfg(target_os = "macos")]
const CJK_FONT: Font = Font {
    family: iced::font::Family::Name("PingFang SC"),
    weight: iced::font::Weight::Normal,
    stretch: iced::font::Stretch::Normal,
    style: iced::font::Style::Normal,
};

#[cfg(target_os = "windows")]
const CJK_FONT: Font = Font {
    family: iced::font::Family::Name("Microsoft YaHei"),
    weight: iced::font::Weight::Normal,
    stretch: iced::font::Stretch::Normal,
    style: iced::font::Style::Normal,
};

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const CJK_FONT: Font = Font {
    family: iced::font::Family::Name("Noto Sans CJK SC"),
    weight: iced::font::Weight::Normal,
    stretch: iced::font::Stretch::Normal,
    style: iced::font::Style::Normal,
};

// ---------------------------------------------------------------------------
// ZMODEM protocol detection
// ---------------------------------------------------------------------------

/// ZMODEM cancel sequence: 5x CAN + 5x BS.
const ZMODEM_CANCEL: &[u8] = &[0x18, 0x18, 0x18, 0x18, 0x18, 0x08, 0x08, 0x08, 0x08, 0x08];

/// Detect ZMODEM from `rz` command.
fn detect_zmodem_rz(data: &[u8]) -> bool {
    data.windows(6).any(|w| w.starts_with(b"**\x18B0"))
        || data.windows(4).any(|w| w == b"**B0")
        || data.windows(22).any(|w| w.starts_with(b"rz waiting to receive"))
}

/// Extract CWD from the shell prompt in the terminal grid.
/// Matches common prompt patterns like:
///   user@host:/path$    user@host:~$    (env) user@host:/path$
fn extract_cwd_from_prompt(grid: &TerminalGrid) -> Option<String> {
    // Scan bottom-up for a line with a prompt pattern
    for y in (0..grid.rows).rev() {
        let line: String = grid.cells[y].iter()
            .filter(|c| !c.wide_cont)
            .map(|c| c.c)
            .collect();
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        // Match pattern: ...@...:PATH$ or ...@...:PATH#
        // Find the last occurrence of @...:/path$ pattern
        if let Some(at_pos) = trimmed.rfind('@') {
            let after_at = &trimmed[at_pos + 1..];
            if let Some(colon_pos) = after_at.find(':') {
                let after_colon = &after_at[colon_pos + 1..];
                // Extract path: everything until $ or # or end
                let path: String = after_colon
                    .chars()
                    .take_while(|&c| c != '$' && c != '#')
                    .collect();
                let path = path.trim().to_string();
                if !path.is_empty() {
                    // Expand ~ to actual home if needed
                    return Some(path);
                }
            }
        }
        // Only check the last non-empty line with prompt
        break;
    }
    None
}

/// Extract "sz filename" from the terminal grid (shell echo already rendered).
/// Scans recent lines bottom-up for "sz " pattern.
fn extract_sz_from_grid(grid: &TerminalGrid) -> Option<String> {
    for y in (0..grid.rows).rev() {
        let line: String = grid.cells[y].iter()
            .filter(|c| !c.wide_cont)
            .map(|c| c.c)
            .collect();
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        // Stop if we hit ZMODEM garbage or NeoShell messages
        if trimmed.starts_with("**") || trimmed.contains("[NeoShell]") { continue; }

        if let Some(pos) = trimmed.rfind("sz ") {
            let after = trimmed[pos + 3..].trim();
            // Take filename (everything before ZMODEM or control chars)
            let fname: String = after
                .chars()
                .take_while(|&c| c != '*' && c != '\r' && c != '\n' && c.is_ascii_graphic() || c == ' ' || c > '\x7f')
                .collect();
            let fname = fname.trim().to_string();
            if !fname.is_empty() && fname.len() > 1 {
                return Some(fname);
            }
        }
        // Only check the last few non-empty lines
        break;
    }
    None
}

/// Extract filename from "sz filename" echo in SSH data stream.
/// Handles: "sz file.txt\r\n", "$ sz  my file.tar\r\n", ANSI escape codes stripped.
fn extract_sz_filename(data: &str) -> Option<String> {
    // Strip ANSI escape codes for cleaner matching
    let clean: String = data.chars().filter(|&c| c != '\x1b').collect();

    // Find "sz " in the text (could be "$ sz file" or just "sz file")
    for line in clean.lines() {
        let trimmed = line.trim();
        // Match "sz filename" at end of line or after shell prompt
        if let Some(pos) = trimmed.rfind("sz ") {
            let after_sz = trimmed[pos + 3..].trim();
            // Take everything until ZMODEM garbage or end
            let fname = after_sz
                .split(|c: char| c == '*' || c == '\r' || c == '\n')
                .next()
                .unwrap_or("")
                .trim();
            if !fname.is_empty() && fname.len() > 1 {
                return Some(fname.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct NeoShell {
    screen: Screen,

    // Password screens
    password_input: String,
    confirm_input: String,
    error_message: String,

    // Connection management
    store: Arc<ConnectionStore>,
    connections: Vec<ConnectionInfo>,

    // SSH
    ssh_manager: Arc<SshManager>,
    ssh_event_rx: Option<mpsc::Receiver<SshEvent>>,

    // Terminal tabs
    tabs: Vec<TerminalTab>,
    active_tab: Option<usize>,

    // Connection form
    show_form: bool,
    form: ConnectionFormData,
    edit_id: Option<String>,

    // Sidebar
    search_query: String,

    // Server monitoring (per active tab)
    server_stats: HashMap<String, ServerStats>,
    top_processes: HashMap<String, Vec<ProcessInfo>>,

    // File browser (per active tab)
    file_entries: HashMap<String, Vec<FileEntry>>,
    current_dir: HashMap<String, String>,

    // File editor (modal)
    editor_content: text_editor::Content,
    editor_file_path: Option<String>,
    editor_session_id: Option<String>,
    editor_dirty: bool,

    // Transfer progress tracking
    transfer_progress: Option<Arc<TransferProgress>>,

    // Network detail popup
    selected_interface: Option<crate::ssh::NetInterface>,

    // Prevent duplicate tab creation during async connect
    connecting_ids: HashSet<String>,

    // Quick-connect dialog (shows saved connections list)
    show_connect_dialog: bool,

    // Network rate tracking (bytes/sec)
    prev_net_rx: HashMap<String, u64>,
    prev_net_tx: HashMap<String, u64>,
    prev_net_time: HashMap<String, std::time::Instant>,
    net_rx_rate: HashMap<String, f64>,
    net_tx_rate: HashMap<String, f64>,

    // Track last command typed per session (for sz filename capture)
    cmd_buffer: HashMap<String, String>,
    sz_filename: HashMap<String, String>,  // session_id -> captured filename from "sz xxx"

    // ZMODEM: suppress residual binary data for ~2s after detection
    zmodem_active: HashMap<String, std::time::Instant>,

    // Terminal text selection
    selection_start: Option<(usize, usize)>,  // (col, row) in grid coords
    selection_end: Option<(usize, usize)>,
    selecting: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Setup,
    Locked,
    Main,
}

#[allow(dead_code)]
struct TerminalTab {
    id: String,
    session_id: String,
    connection_id: String,
    title: String,
    terminal: Arc<parking_lot::Mutex<TerminalGrid>>,
}

#[derive(Default, Clone)]
struct ConnectionFormData {
    name: String,
    host: String,
    port: String,
    username: String,
    auth_type: String,
    password: String,
    private_key: String,
    passphrase: String,
    group: String,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Message {
    // Password
    PasswordChanged(String),
    ConfirmChanged(String),
    CreateVault,
    VaultCreated,
    UnlockVault,
    VaultUnlocked,

    // Connections
    LoadConnections,
    ConnectionsLoaded(Vec<ConnectionInfo>),
    ConnectTo(String),
    DeleteConnection(String),
    ShowConnectDialog,
    HideConnectDialog,

    // Tab switching
    SwitchToNextTab,
    SwitchToPrevTab,
    SwitchToTab(usize),

    // Form
    ShowForm(Option<String>),
    HideForm,
    FormNameChanged(String),
    FormHostChanged(String),
    FormPortChanged(String),
    FormUsernameChanged(String),
    FormAuthTypeChanged(String),
    FormPasswordChanged(String),
    FormPrivateKeyChanged(String),
    FormPassphraseChanged(String),
    FormGroupChanged(String),
    SaveForm,

    // Terminal
    SshConnected(String, String, String, String),  // tab_id, session_id, title, connection_id
    SshData(String, Vec<u8>),
    SshClosed(String),
    TerminalInput(String, String),
    TabSelected(usize),
    TabClosed(usize),

    // Polling / keyboard
    PollSshEvents,
    KeyboardEvent(keyboard::Key, keyboard::Modifiers, Option<String>),
    PasteClipboard,
    CancelTransfer,

    // Search
    SearchChanged(String),

    // Monitor
    FetchMonitorData,
    MonitorDataReceived(String, ServerStats, Vec<ProcessInfo>),
    MonitorError(String),
    ShowNetworkDetail(crate::ssh::NetInterface),
    HideNetworkDetail,

    // File browser
    FilesReceived(String, String, Vec<FileEntry>),
    ChangeDir(String, String),
    FileClicked(String, FileEntry),

    // File operations
    UploadFile,
    UploadComplete(String),
    DownloadFile(String, String),
    DownloadComplete(String),

    // Editor
    OpenEditor(String, String),
    EditorContentLoaded(String, String, String),
    EditorAction(text_editor::Action),
    SaveEditor,
    EditorSaved,
    CloseEditor,

    // SSH Config / Key file picker
    BrowseKeyFile,
    KeyFileSelected(String),
    ImportSshConfig(crate::sshconfig::SshHostConfig),

    // rz/sz ZMODEM
    RzDetected(String),      // session_id — rz wants to receive a file
    SzDetected(String),      // session_id — sz wants to send a file
    RzUploadDone(String),    // session_id — upload finished

    // Terminal scrollback & selection
    TerminalScrollUp(usize),
    TerminalScrollDown(usize),
    TerminalMouseDown,
    TerminalMouseUp,
    TerminalMouseMove(f32, f32),
    CopySelection,

    // Misc
    Tick,
    None,
    Error(String),
}

// ---------------------------------------------------------------------------
// Default (initial state before run_with)
// ---------------------------------------------------------------------------

impl Default for NeoShell {
    fn default() -> Self {
        let store = Arc::new(ConnectionStore::new());
        let (ssh_manager, ssh_event_rx) = SshManager::new();

        let screen = if store.vault_exists() {
            Screen::Locked
        } else {
            Screen::Setup
        };

        Self {
            screen,
            password_input: String::new(),
            confirm_input: String::new(),
            error_message: String::new(),
            store,
            connections: Vec::new(),
            ssh_manager: Arc::new(ssh_manager),
            ssh_event_rx: Some(ssh_event_rx),
            tabs: Vec::new(),
            active_tab: None,
            show_form: false,
            form: ConnectionFormData::default(),
            edit_id: None,
            search_query: String::new(),
            server_stats: HashMap::new(),
            top_processes: HashMap::new(),
            file_entries: HashMap::new(),
            current_dir: HashMap::new(),
            editor_content: text_editor::Content::new(),
            editor_file_path: None,
            editor_session_id: None,
            editor_dirty: false,
            transfer_progress: None,
            selected_interface: None,
            connecting_ids: HashSet::new(),
            show_connect_dialog: false,
            prev_net_rx: HashMap::new(),
            prev_net_tx: HashMap::new(),
            prev_net_time: HashMap::new(),
            net_rx_rate: HashMap::new(),
            net_tx_rate: HashMap::new(),
            cmd_buffer: HashMap::new(),
            sz_filename: HashMap::new(),
            zmodem_active: HashMap::new(),
            selection_start: None,
            selection_end: None,
            selecting: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Application entry point
// ---------------------------------------------------------------------------

pub fn run() -> iced::Result {
    iced::application("NeoShell", update, view)
        .subscription(subscription)
        .theme(|_state| Theme::Dark)
        .window_size(Size::new(1200.0, 800.0))
        .antialiasing(true)
        .decorations(true)
        .default_font(CJK_FONT)
        .run()
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

fn update(state: &mut NeoShell, message: Message) -> Task<Message> {
    match message {
        // ---- password / vault ------------------------------------------------
        Message::PasswordChanged(v) => {
            state.password_input = v;
            Task::none()
        }
        Message::ConfirmChanged(v) => {
            state.confirm_input = v;
            Task::none()
        }
        Message::CreateVault => {
            if state.password_input.len() < 4 {
                state.error_message = "Password must be at least 4 characters".into();
                return Task::none();
            }
            if state.password_input != state.confirm_input {
                state.error_message = "Passwords do not match".into();
                return Task::none();
            }
            let store = state.store.clone();
            let pw = state.password_input.clone();
            Task::perform(
                async move { store.set_master_password(&pw) },
                |result| match result {
                    Ok(()) => Message::VaultCreated,
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::VaultCreated => {
            state.screen = Screen::Main;
            state.password_input.clear();
            state.confirm_input.clear();
            state.error_message.clear();
            Task::done(Message::LoadConnections)
        }
        Message::UnlockVault => {
            let store = state.store.clone();
            let pw = state.password_input.clone();
            Task::perform(
                async move { store.unlock(&pw) },
                |result| match result {
                    Ok(true) => Message::VaultUnlocked,
                    Ok(false) => Message::Error("Invalid password".into()),
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::VaultUnlocked => {
            state.screen = Screen::Main;
            state.password_input.clear();
            state.error_message.clear();
            Task::done(Message::LoadConnections)
        }

        // ---- connections -----------------------------------------------------
        Message::LoadConnections => {
            let store = state.store.clone();
            Task::perform(
                async move { store.get_connections() },
                |result| match result {
                    Ok(conns) => Message::ConnectionsLoaded(conns),
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::ConnectionsLoaded(conns) => {
            state.connections = conns;
            Task::none()
        }
        Message::ConnectTo(id) => {
            if state.connecting_ids.contains(&id) {
                return Task::none();
            }
            state.connecting_ids.insert(id.clone());
            state.show_connect_dialog = false;

            // Create a placeholder tab immediately so user sees feedback
            let tab_id = uuid::Uuid::new_v4().to_string();
            let terminal = Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24)));
            {
                let mut grid = terminal.lock();
                grid.write(b"\x1b[33mConnecting...\x1b[0m\r\n");
            }
            state.tabs.push(TerminalTab {
                id: tab_id.clone(),
                session_id: String::new(), // placeholder
                connection_id: id.clone(),
                title: "Connecting...".to_string(),
                terminal,
            });
            state.active_tab = Some(state.tabs.len() - 1);

            let store = state.store.clone();
            let ssh = state.ssh_manager.clone();
            let tab_id2 = tab_id.clone();
            Task::perform(
                async move {
                    use std::io::Write;
                    let mut log = std::fs::OpenOptions::new().create(true).append(true)
                        .open("/tmp/neoshell-connect.log").ok();
                    macro_rules! dbg_log {
                        ($($arg:tt)*) => { if let Some(ref mut f) = log { let _ = writeln!(f, $($arg)*); } }
                    }

                    // Run blocking SSH connect on dedicated thread
                    tokio::task::spawn_blocking(move || {
                        let config = store.get_connection(&id)?;
                        let session_id = ssh.connect_config(&config)?;
                        let title = format!("{}@{}:{}", config.username, config.host, config.port);
                        Ok((tab_id2, session_id, title, id))
                    }).await.map_err(|e| format!("Task: {}", e))?
                },
                |result: Result<(String, String, String, String), String>| match result {
                    Ok((tab_id, session_id, title, conn_id)) => {
                        Message::SshConnected(tab_id, session_id, title, conn_id)
                    }
                    Err(e) => {
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
                            .open("/tmp/neoshell-connect.log") {
                            use std::io::Write;
                            let _ = writeln!(f, "FAILED: {}", e);
                        }
                        Message::Error(e)
                    }
                },
            )
        }
        Message::ShowConnectDialog => {
            state.show_connect_dialog = true;
            Task::done(Message::LoadConnections)
        }
        Message::HideConnectDialog => {
            state.show_connect_dialog = false;
            Task::none()
        }
        Message::SwitchToNextTab => {
            if !state.tabs.is_empty() {
                let next = match state.active_tab {
                    Some(idx) => (idx + 1) % state.tabs.len(),
                    None => 0,
                };
                state.active_tab = Some(next);
            }
            Task::none()
        }
        Message::SwitchToPrevTab => {
            if !state.tabs.is_empty() {
                let prev = match state.active_tab {
                    Some(0) | None => state.tabs.len() - 1,
                    Some(idx) => idx - 1,
                };
                state.active_tab = Some(prev);
            }
            Task::none()
        }
        Message::SwitchToTab(idx) => {
            if idx < state.tabs.len() {
                state.active_tab = Some(idx);
            }
            Task::none()
        }
        Message::DeleteConnection(id) => {
            let store = state.store.clone();
            Task::perform(
                async move {
                    store.delete_connection(&id)?;
                    store.get_connections()
                },
                |result| match result {
                    Ok(conns) => Message::ConnectionsLoaded(conns),
                    Err(e) => Message::Error(e),
                },
            )
        }

        // ---- form ------------------------------------------------------------
        Message::ShowForm(maybe_id) => {
            state.show_form = true;
            state.show_connect_dialog = false;
            if let Some(id) = maybe_id.clone() {
                state.edit_id = Some(id.clone());
                if let Some(info) = state.connections.iter().find(|c| c.id == id) {
                    state.form = ConnectionFormData {
                        name: info.name.clone(),
                        host: info.host.clone(),
                        port: info.port.to_string(),
                        username: info.username.clone(),
                        auth_type: info.auth_type.clone(),
                        group: info.group.clone(),
                        ..Default::default()
                    };
                }
            } else {
                state.edit_id = None;
                state.form = ConnectionFormData {
                    port: "22".into(),
                    auth_type: "password".into(),
                    ..Default::default()
                };
            }
            Task::none()
        }
        Message::HideForm => {
            state.show_form = false;
            state.edit_id = None;
            state.form = ConnectionFormData::default();
            Task::none()
        }
        Message::FormNameChanged(v) => {
            state.form.name = v;
            Task::none()
        }
        Message::FormHostChanged(v) => {
            state.form.host = v;
            Task::none()
        }
        Message::FormPortChanged(v) => {
            state.form.port = v;
            Task::none()
        }
        Message::FormUsernameChanged(v) => {
            state.form.username = v;
            Task::none()
        }
        Message::FormAuthTypeChanged(v) => {
            state.form.auth_type = v;
            Task::none()
        }
        Message::FormPasswordChanged(v) => {
            state.form.password = v;
            Task::none()
        }
        Message::FormPrivateKeyChanged(v) => {
            state.form.private_key = v;
            Task::none()
        }
        Message::FormPassphraseChanged(v) => {
            state.form.passphrase = v;
            Task::none()
        }
        Message::FormGroupChanged(v) => {
            state.form.group = v;
            Task::none()
        }
        Message::SaveForm => {
            let port: u16 = state.form.port.parse().unwrap_or(22);
            let config = ConnectionConfig {
                id: state.edit_id.clone().unwrap_or_default(),
                name: state.form.name.clone(),
                host: state.form.host.clone(),
                port,
                username: state.form.username.clone(),
                auth_type: state.form.auth_type.clone(),
                password: if state.form.password.is_empty() {
                    None
                } else {
                    Some(state.form.password.clone())
                },
                private_key: if state.form.private_key.is_empty() {
                    None
                } else {
                    Some(state.form.private_key.clone())
                },
                passphrase: if state.form.passphrase.is_empty() {
                    None
                } else {
                    Some(state.form.passphrase.clone())
                },
                group: state.form.group.clone(),
                color: String::new(),
            };

            let store = state.store.clone();
            let is_edit = state.edit_id.is_some();

            state.show_form = false;
            state.edit_id = None;
            state.form = ConnectionFormData::default();

            Task::perform(
                async move {
                    if is_edit {
                        store.update_connection(config)?;
                    } else {
                        store.save_connection(config)?;
                    }
                    store.get_connections()
                },
                |result| match result {
                    Ok(conns) => Message::ConnectionsLoaded(conns),
                    Err(e) => Message::Error(e),
                },
            )
        }

        // ---- terminal --------------------------------------------------------
        Message::SshConnected(tab_id, session_id, title, connection_id) => {
            state.connecting_ids.remove(&connection_id);
            state.show_connect_dialog = false;
            let sid_for_fetch = session_id.clone();

            // Update existing placeholder tab (created in ConnectTo)
            if let Some(tab) = state.tabs.iter_mut().find(|t| t.id == tab_id) {
                tab.session_id = session_id;
                tab.connection_id = connection_id;
                tab.title = title;
                // Clear the "Connecting..." message
                let mut grid = tab.terminal.lock();
                grid.write(b"\x1b[2J\x1b[H"); // Clear screen + home
            }

            state.current_dir.insert(sid_for_fetch.clone(), "~".to_string());
            Task::done(Message::ChangeDir(sid_for_fetch, "~".to_string()))
        }
        Message::SshData(session_id, data) => {
            if let Some(tab) = state.tabs.iter().find(|t| t.session_id == session_id) {
                let mut grid = tab.terminal.lock();
                grid.write(&data);
                grid.scroll_offset = 0; // Auto-scroll to bottom on new data
            }
            Task::none()
        }
        Message::SshClosed(session_id) => {
            if let Some(idx) = state.tabs.iter().position(|t| t.session_id == session_id) {
                state.tabs.remove(idx);
                // Cleanup monitoring/file data for this session
                state.server_stats.remove(&session_id);
                state.top_processes.remove(&session_id);
                state.file_entries.remove(&session_id);
                state.current_dir.remove(&session_id);
                if state.tabs.is_empty() {
                    state.active_tab = None;
                } else {
                    state.active_tab = Some(idx.min(state.tabs.len() - 1));
                }
            }
            Task::none()
        }
        Message::TerminalInput(session_id, data) => {
            // Track typed commands to capture "sz filename"
            let buf = state.cmd_buffer.entry(session_id.clone()).or_default();
            if data == "\r" || data == "\n" {
                // Enter pressed — check for sz command
                let cmd = buf.trim().to_string();
                if cmd.starts_with("sz ") {
                    let filename = cmd[3..].trim().to_string();
                    if !filename.is_empty() {
                        state.sz_filename.insert(session_id.clone(), filename);
                    }
                }
                buf.clear();
            } else if data == "\x7f" || data == "\x08" {
                buf.pop(); // Backspace
            } else if data.chars().all(|c| !c.is_control()) {
                buf.push_str(&data);
            }

            let ssh = state.ssh_manager.clone();
            Task::perform(
                async move {
                    ssh.send_data(&session_id, data.as_bytes())?;
                    Ok(())
                },
                |result: Result<(), String>| match result {
                    Ok(()) => Message::None,
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::TabSelected(idx) => {
            if idx < state.tabs.len() {
                state.active_tab = Some(idx);
            }
            Task::none()
        }
        Message::TabClosed(idx) => {
            if idx < state.tabs.len() {
                let session_id = state.tabs[idx].session_id.clone();
                let ssh = state.ssh_manager.clone();
                state.tabs.remove(idx);
                // Cleanup monitoring/file data for this session
                state.server_stats.remove(&session_id);
                state.top_processes.remove(&session_id);
                state.file_entries.remove(&session_id);
                state.current_dir.remove(&session_id);
                if state.tabs.is_empty() {
                    state.active_tab = None;
                } else {
                    state.active_tab = Some(idx.min(state.tabs.len() - 1));
                }
                Task::perform(
                    async move {
                        let _ = ssh.disconnect(&session_id);
                    },
                    |_| Message::None,
                )
            } else {
                Task::none()
            }
        }

        // ---- SSH event polling -----------------------------------------------
        Message::PollSshEvents => {
            let mut rz_sessions: Vec<String> = Vec::new();
            let mut sz_sessions: Vec<String> = Vec::new();

            if let Some(rx) = &state.ssh_event_rx {
                while let Ok(event) = rx.try_recv() {
                    match event {
                        SshEvent::Data { session_id, data } => {
                            // Skip ZMODEM residual binary data for 2s after detection
                            if let Some(detected_at) = state.zmodem_active.get(&session_id) {
                                if detected_at.elapsed() < Duration::from_secs(2) {
                                    continue;
                                } else {
                                    state.zmodem_active.remove(&session_id);
                                }
                            }

                            // Detect ZMODEM (both rz and sz send **B0 pattern)
                            if data.len() >= 4 && detect_zmodem_rz(&data) {
                                let _ = state.ssh_manager.send_data(&session_id, ZMODEM_CANCEL);
                                state.zmodem_active.insert(session_id.clone(), std::time::Instant::now());

                                // Extract sz filename from:
                                // 1. Terminal grid (shell echo already rendered)
                                // 2. Current data packet echo
                                // 3. Keyboard buffer fallback
                                let sz_from_grid = state.tabs.iter()
                                    .find(|t| t.session_id == session_id)
                                    .and_then(|tab| {
                                        let grid = tab.terminal.lock();
                                        extract_sz_from_grid(&grid)
                                    });

                                let data_str = String::from_utf8_lossy(&data);
                                let sz_fname = sz_from_grid
                                    .or_else(|| extract_sz_filename(&data_str))
                                    .or_else(|| state.sz_filename.remove(&session_id));

                                if let Some(fname) = sz_fname {
                                    if let Some(tab) = state.tabs.iter().find(|t| t.session_id == session_id) {
                                        tab.terminal.lock().write(
                                            format!("\r\n\x1b[36m[NeoShell] sz: downloading {} via SFTP...\x1b[0m\r\n", fname).as_bytes(),
                                        );
                                    }
                                    state.sz_filename.insert(session_id.clone(), fname);
                                    sz_sessions.push(session_id.clone());
                                } else if data_str.contains("rz waiting") {
                                    if let Some(tab) = state.tabs.iter().find(|t| t.session_id == session_id) {
                                        tab.terminal.lock().write(
                                            b"\r\n\x1b[36m[NeoShell] rz detected - opening file picker...\x1b[0m\r\n",
                                        );
                                    }
                                    rz_sessions.push(session_id.clone());
                                } else {
                                    // Default: rz upload
                                    if let Some(tab) = state.tabs.iter().find(|t| t.session_id == session_id) {
                                        tab.terminal.lock().write(
                                            b"\r\n\x1b[36m[NeoShell] rz detected - opening file picker...\x1b[0m\r\n",
                                        );
                                    }
                                    rz_sessions.push(session_id.clone());
                                }
                                continue;
                            }

                            // Normal data — write to terminal
                            if let Some(tab) =
                                state.tabs.iter().find(|t| t.session_id == session_id)
                            {
                                let mut grid = tab.terminal.lock();
                                grid.write(&data);
                                grid.scroll_offset = 0; // Auto-scroll to bottom on new data
                            }
                        }
                        SshEvent::Closed { session_id } => {
                            state.zmodem_active.remove(&session_id);
                            if let Some(idx) =
                                state.tabs.iter().position(|t| t.session_id == session_id)
                            {
                                state.tabs.remove(idx);
                                state.server_stats.remove(&session_id);
                                state.top_processes.remove(&session_id);
                                state.file_entries.remove(&session_id);
                                state.current_dir.remove(&session_id);
                                if state.tabs.is_empty() {
                                    state.active_tab = None;
                                } else {
                                    state.active_tab = Some(idx.min(state.tabs.len() - 1));
                                }
                            }
                        }
                        SshEvent::Error { session_id, error } => {
                            log::error!("SSH error for {}: {}", session_id, error);
                        }
                        SshEvent::Reconnecting { session_id, attempt } => {
                            if let Some(tab) =
                                state.tabs.iter_mut().find(|t| t.session_id == session_id)
                            {
                                let base = tab.title.split(" [").next().unwrap_or(&tab.title).to_string();
                                tab.title = format!("{} [Reconnecting...{}]", base, attempt);
                            }
                        }
                        SshEvent::Reconnected { session_id } => {
                            if let Some(tab) =
                                state.tabs.iter_mut().find(|t| t.session_id == session_id)
                            {
                                let base = tab.title.split(" [").next().unwrap_or(&tab.title).to_string();
                                tab.title = base;
                            }
                        }
                    }
                }
            }

            // Dispatch ZMODEM messages (only one Task can be returned per update)
            if let Some(sid) = rz_sessions.into_iter().next() {
                return Task::done(Message::RzDetected(sid));
            }
            if let Some(sid) = sz_sessions.into_iter().next() {
                return Task::done(Message::SzDetected(sid));
            }

            Task::none()
        }

        // ---- keyboard -------------------------------------------------------
        Message::KeyboardEvent(key, modifiers, text) => {
            if state.screen != Screen::Main { return Task::none(); }
            if state.editor_file_path.is_some() {
                // Allow Cmd+S to save the open editor
                if modifiers.command() {
                    if let keyboard::Key::Character(c) = &key {
                        if c.as_str() == "s" {
                            return Task::done(Message::SaveEditor);
                        }
                    }
                }
                return Task::none();
            }
            if state.show_form { return Task::none(); }
            if state.selected_interface.is_some() { return Task::none(); }

            // Cmd+key shortcuts
            if modifiers.command() {
                if let keyboard::Key::Character(c) = &key {
                    match c.as_str() {
                        "v" => return Task::done(Message::PasteClipboard),
                        "t" => return Task::done(Message::ShowConnectDialog),
                        "w" => {
                            // Cmd+W = close current tab
                            if let Some(idx) = state.active_tab {
                                return Task::done(Message::TabClosed(idx));
                            }
                        }
                        "1" => return Task::done(Message::SwitchToTab(0)),
                        "2" => return Task::done(Message::SwitchToTab(1)),
                        "3" => return Task::done(Message::SwitchToTab(2)),
                        "4" => return Task::done(Message::SwitchToTab(3)),
                        "5" => return Task::done(Message::SwitchToTab(4)),
                        "6" => return Task::done(Message::SwitchToTab(5)),
                        "7" => return Task::done(Message::SwitchToTab(6)),
                        "8" => return Task::done(Message::SwitchToTab(7)),
                        "9" => {
                            // Cmd+9 = last tab
                            if !state.tabs.is_empty() {
                                return Task::done(Message::SwitchToTab(state.tabs.len() - 1));
                            }
                        }
                        "+" | "=" | "-" | "0" => return Task::none(), // Block zoom
                        _ => {}
                    }
                }
                return Task::none();
            }

            // Ctrl+Tab / Ctrl+Shift+Tab = switch tabs
            if modifiers.control() {
                if let keyboard::Key::Named(keyboard::key::Named::Tab) = &key {
                    return if modifiers.shift() {
                        Task::done(Message::SwitchToPrevTab)
                    } else {
                        Task::done(Message::SwitchToNextTab)
                    };
                }
            }

            // Close connect dialog with ESC
            if state.show_connect_dialog {
                if let keyboard::Key::Named(keyboard::key::Named::Escape) = &key {
                    state.show_connect_dialog = false;
                    return Task::none();
                }
            }

            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let session_id = tab.session_id.clone();
                    if let Some(data) = key_to_terminal_bytes(&key, &modifiers, text.as_deref()) {
                        return Task::done(Message::TerminalInput(session_id, data));
                    }
                }
            }
            Task::none()
        }

        Message::PasteClipboard => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let session_id = tab.session_id.clone();
                    let ssh = state.ssh_manager.clone();
                    return Task::perform(
                        async move {
                            let mut clipboard = arboard::Clipboard::new()
                                .map_err(|e| format!("Clipboard error: {}", e))?;
                            let content = clipboard.get_text()
                                .map_err(|e| format!("Clipboard read error: {}", e))?;
                            ssh.send_data(&session_id, content.as_bytes())?;
                            Ok(())
                        },
                        |r: Result<(), String>| match r {
                            Ok(()) => Message::None,
                            Err(e) => Message::Error(e),
                        },
                    );
                }
            }
            Task::none()
        }

        Message::CancelTransfer => {
            if let Some(ref progress) = state.transfer_progress {
                progress.finished.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            state.transfer_progress = None;
            Task::none()
        }

        // ---- search ----------------------------------------------------------
        Message::SearchChanged(v) => {
            state.search_query = v;
            Task::none()
        }

        // ---- monitor ---------------------------------------------------------
        Message::FetchMonitorData => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let ssh = state.ssh_manager.clone();
                    let sid = tab.session_id.clone();
                    return Task::perform(
                        async move {
                            tokio::task::spawn_blocking(move || {
                                let stats = ssh.fetch_server_stats(&sid)?;
                                let procs = ssh.fetch_top_processes(&sid, 15)?;
                                Ok((sid, stats, procs))
                            }).await.map_err(|e| format!("{}", e))?
                        },
                        |r: Result<(String, ServerStats, Vec<ProcessInfo>), String>| match r {
                            Ok((sid, stats, procs)) => {
                                Message::MonitorDataReceived(sid, stats, procs)
                            }
                            Err(e) => Message::MonitorError(e),
                        },
                    );
                }
            }
            Task::none()
        }
        Message::MonitorDataReceived(sid, stats, procs) => {
            // Calculate network speed
            let now = std::time::Instant::now();
            if let Some(prev_time) = state.prev_net_time.get(&sid) {
                let elapsed = now.duration_since(*prev_time).as_secs_f64();
                if elapsed > 0.5 {
                    let prev_rx = state.prev_net_rx.get(&sid).copied().unwrap_or(0);
                    let prev_tx = state.prev_net_tx.get(&sid).copied().unwrap_or(0);
                    if prev_rx > 0 && stats.net_rx_bytes >= prev_rx {
                        state.net_rx_rate.insert(sid.clone(), (stats.net_rx_bytes - prev_rx) as f64 / elapsed);
                        state.net_tx_rate.insert(sid.clone(), (stats.net_tx_bytes - prev_tx) as f64 / elapsed);
                    }
                }
            }
            state.prev_net_rx.insert(sid.clone(), stats.net_rx_bytes);
            state.prev_net_tx.insert(sid.clone(), stats.net_tx_bytes);
            state.prev_net_time.insert(sid.clone(), now);

            state.server_stats.insert(sid.clone(), stats);
            state.top_processes.insert(sid.clone(), procs);

            // Sync file browser with shell CWD (extracted from terminal prompt)
            if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
                let grid = tab.terminal.lock();
                if let Some(cwd) = extract_cwd_from_prompt(&grid) {
                    let prev_dir = state.current_dir.get(&sid).cloned().unwrap_or_default();
                    if prev_dir != cwd {
                        drop(grid);
                        state.current_dir.insert(sid.clone(), cwd.clone());
                        return Task::done(Message::ChangeDir(sid, cwd));
                    }
                }
            }
            Task::none()
        }
        Message::MonitorError(e) => {
            log::warn!("Monitor fetch error: {}", e);
            Task::none()
        }
        Message::ShowNetworkDetail(iface) => {
            state.selected_interface = Some(iface);
            Task::none()
        }
        Message::HideNetworkDetail => {
            state.selected_interface = None;
            Task::none()
        }

        // ---- file browser ----------------------------------------------------
        Message::FilesReceived(sid, path, entries) => {
            state.current_dir.insert(sid.clone(), path);
            state.file_entries.insert(sid, entries);
            Task::none()
        }
        Message::ChangeDir(sid, path) => {
            let ssh = state.ssh_manager.clone();
            let sid_for_state = sid.clone();
            let sid_for_async = sid.clone();
            let path_async = path.clone();
            state.current_dir.insert(sid_for_state, path);
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || ssh.list_files(&sid_for_async, &path_async))
                        .await.map_err(|e| format!("{}", e))?
                },
                move |result: Result<(String, Vec<FileEntry>), String>| match result {
                    Ok((real_path, entries)) => Message::FilesReceived(sid.clone(), real_path, entries),
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::FileClicked(sid, entry) => {
            if entry.is_dir || entry.name == ".." {
                let current = state
                    .current_dir
                    .get(&sid)
                    .cloned()
                    .unwrap_or_else(|| "~".to_string());
                let new_path = if entry.name == ".." {
                    // Go up one directory
                    let path = std::path::PathBuf::from(&current);
                    path.parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "/".to_string())
                } else {
                    format!("{}/{}", current.trim_end_matches('/'), entry.name)
                };
                return Task::done(Message::ChangeDir(sid, new_path));
            }
            Task::none()
        }

        // ---- file operations -------------------------------------------------
        Message::UploadFile => {
            let sid = state.active_tab
                .and_then(|idx| state.tabs.get(idx))
                .map(|t| t.session_id.clone());
            let current = sid.as_ref()
                .and_then(|s| state.current_dir.get(s))
                .cloned()
                .unwrap_or_else(|| "~".to_string());

            if let Some(sid) = sid {
                let ssh = state.ssh_manager.clone();
                let progress = Arc::new(TransferProgress::new());
                state.transfer_progress = Some(progress.clone());
                Task::perform(
                    async move {
                        let default_dir = dirs::download_dir()
                            .or_else(dirs::desktop_dir)
                            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default());
                        let file = rfd::AsyncFileDialog::new()
                            .set_title("Select file to upload")
                            .set_directory(&default_dir)
                            .pick_file()
                            .await;

                        if let Some(file) = file {
                            let local_path = file.path().to_string_lossy().to_string();
                            let file_name = file.file_name();
                            let remote_path = format!("{}/{}", current.trim_end_matches('/'), file_name);

                            // Run blocking SFTP on dedicated thread to avoid starving tokio runtime
                            tokio::task::spawn_blocking(move || {
                                ssh.upload_file_with_progress(&sid, &local_path, &remote_path, progress)
                                    .map(|_| sid)
                            }).await.map_err(|e| format!("Task: {}", e))?
                        } else {
                            Err("cancelled".to_string())
                        }
                    },
                    |result: Result<String, String>| match result {
                        Ok(sid) => Message::UploadComplete(sid),
                        Err(e) if e == "cancelled" => Message::None,
                        Err(e) => Message::Error(e),
                    },
                )
            } else {
                Task::none()
            }
        }
        Message::UploadComplete(sid) => {
            state.transfer_progress = None;
            let path = state.current_dir.get(&sid).cloned().unwrap_or("~".to_string());
            Task::done(Message::ChangeDir(sid, path))
        }
        Message::DownloadFile(sid, remote_path) => {
            let ssh = state.ssh_manager.clone();
            let filename = remote_path.split('/').last().unwrap_or("file").to_string();
            let progress = Arc::new(TransferProgress::new());
            state.transfer_progress = Some(progress.clone());
            Task::perform(
                async move {
                    // Default to user's Downloads or Desktop directory
                    let default_dir = dirs::download_dir()
                        .or_else(dirs::desktop_dir)
                        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default());

                    let save_path = rfd::AsyncFileDialog::new()
                        .set_title("Save file as")
                        .set_file_name(&filename)
                        .set_directory(&default_dir)
                        .save_file()
                        .await;

                    if let Some(save_handle) = save_path {
                        // Use the full canonical path
                        let local_path = save_handle.path().to_string_lossy().to_string();
                        if local_path.is_empty() {
                            return Err("Empty save path".to_string());
                        }
                        // Run blocking SFTP on dedicated thread
                        tokio::task::spawn_blocking(move || {
                            ssh.download_file_with_progress(&sid, &remote_path, &local_path, progress)
                                .map(|_| format!("Downloaded"))
                        }).await.map_err(|e| format!("Task: {}", e))?
                    } else {
                        Err("cancelled".to_string())
                    }
                },
                |result: Result<String, String>| match result {
                    Ok(msg) => Message::DownloadComplete(msg),
                    Err(e) if e == "cancelled" => Message::None,
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::DownloadComplete(_msg) => {
            state.transfer_progress = None;
            Task::none()
        }

        // ---- editor ----------------------------------------------------------
        Message::OpenEditor(sid, path) => {
            let ssh = state.ssh_manager.clone();
            let sid2 = sid.clone();
            let path2 = path.clone();
            Task::perform(
                async move {
                    let content = ssh.read_file_content(&sid2, &path2)?;
                    Ok((sid2, path2, content))
                },
                |result: Result<(String, String, String), String>| match result {
                    Ok((sid, path, content)) => Message::EditorContentLoaded(sid, path, content),
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::EditorContentLoaded(sid, path, content) => {
            state.editor_content = text_editor::Content::with_text(&content);
            state.editor_file_path = Some(path);
            state.editor_session_id = Some(sid);
            state.editor_dirty = false;
            Task::none()
        }
        Message::EditorAction(action) => {
            let is_edit = action.is_edit();
            state.editor_content.perform(action);
            if is_edit {
                state.editor_dirty = true;
            }
            Task::none()
        }
        Message::SaveEditor => {
            if let (Some(sid), Some(path)) = (state.editor_session_id.clone(), state.editor_file_path.clone()) {
                let ssh = state.ssh_manager.clone();
                let content = state.editor_content.text();
                Task::perform(
                    async move {
                        ssh.write_file_content(&sid, &path, &content)?;
                        Ok(())
                    },
                    |result: Result<(), String>| match result {
                        Ok(()) => Message::EditorSaved,
                        Err(e) => Message::Error(e),
                    },
                )
            } else {
                Task::none()
            }
        }
        Message::EditorSaved => {
            state.editor_dirty = false;
            Task::none()
        }
        Message::CloseEditor => {
            state.editor_content = text_editor::Content::new();
            state.editor_file_path = None;
            state.editor_session_id = None;
            state.editor_dirty = false;
            Task::none()
        }

        // ---- SSH config / key file picker --------------------------------------
        Message::BrowseKeyFile => {
            Task::perform(
                async {
                    let file = rfd::AsyncFileDialog::new()
                        .set_title("Select Private Key")
                        .set_directory(dirs::home_dir().unwrap_or_default().join(".ssh"))
                        .pick_file()
                        .await;
                    file.map(|f| f.path().to_string_lossy().to_string())
                },
                |path| match path {
                    Some(p) => Message::KeyFileSelected(p),
                    None => Message::None,
                },
            )
        }
        Message::KeyFileSelected(path) => {
            state.form.private_key = path;
            Task::none()
        }
        Message::ImportSshConfig(config) => {
            state.show_form = true;
            state.show_connect_dialog = false;
            state.edit_id = None;
            state.form = ConnectionFormData {
                name: config.alias.clone(),
                host: if config.hostname.is_empty() {
                    config.alias
                } else {
                    config.hostname
                },
                port: config.port.to_string(),
                username: config.user,
                auth_type: if config.identity_file.is_empty() {
                    "password".to_string()
                } else {
                    "key".to_string()
                },
                private_key: config.identity_file,
                group: "SSH Config".to_string(),
                ..Default::default()
            };
            Task::none()
        }

        // ---- rz/sz ZMODEM handlers -------------------------------------------
        Message::RzDetected(sid) => {
            let current_dir = state.current_dir.get(&sid).cloned()
                .unwrap_or_else(|| "~".to_string());
            let ssh = state.ssh_manager.clone();
            let progress = Arc::new(TransferProgress::new());
            state.transfer_progress = Some(progress.clone());

            Task::perform(
                async move {
                    let default_dir = dirs::download_dir()
                        .or_else(dirs::desktop_dir)
                        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default());
                    let file = rfd::AsyncFileDialog::new()
                        .set_title("rz: Select file to upload")
                        .set_directory(&default_dir)
                        .pick_file()
                        .await;

                    if let Some(file) = file {
                        let local_path = file.path().to_string_lossy().to_string();
                        let file_name = file.file_name();
                        let remote_path = format!(
                            "{}/{}",
                            current_dir.trim_end_matches('/'),
                            file_name
                        );
                        tokio::task::spawn_blocking(move || {
                            ssh.upload_file_with_progress(&sid, &local_path, &remote_path, progress)
                                .map(|_| sid)
                        })
                        .await
                        .map_err(|e| format!("Task: {}", e))?
                    } else {
                        Err("cancelled".to_string())
                    }
                },
                |result: Result<String, String>| match result {
                    Ok(sid) => Message::RzUploadDone(sid),
                    Err(e) if e == "cancelled" => Message::None,
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::RzUploadDone(sid) => {
            state.transfer_progress = None;
            if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
                tab.terminal.lock().write(
                    b"\r\n\x1b[32m[NeoShell] Upload complete.\x1b[0m\r\n",
                );
            }
            let path = state.current_dir.get(&sid).cloned()
                .unwrap_or_else(|| "~".to_string());
            Task::done(Message::ChangeDir(sid, path))
        }
        Message::SzDetected(sid) => {
            // Prevent duplicate: skip if already downloading
            if state.transfer_progress.is_some() {
                return Task::none();
            }

            let filename = state.sz_filename.remove(&sid);
            let current_dir = state.current_dir.get(&sid).cloned().unwrap_or("~".to_string());

            if let Some(fname) = filename {
                let ssh = state.ssh_manager.clone();
                let progress = Arc::new(TransferProgress::new());
                state.transfer_progress = Some(progress.clone());

                // Download directly to ~/Downloads
                let default_dir = dirs::download_dir()
                    .or_else(|| dirs::desktop_dir())
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_default());
                let local_path = default_dir.join(&fname).to_string_lossy().to_string();

                if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
                    tab.terminal.lock().write(
                        format!("\r\n\x1b[32m[NeoShell] sz: {} → {}\x1b[0m\r\n", fname, local_path).as_bytes(),
                    );
                }

                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            // Resolve absolute path on remote (shell CWD may differ from file browser)
                            let remote_path = if fname.starts_with('/') {
                                fname.clone()
                            } else {
                                let pwd = ssh.exec_command(&sid, "pwd")
                                    .unwrap_or_else(|_| "~".to_string());
                                let cwd = pwd.trim();
                                format!("{}/{}", cwd.trim_end_matches('/'), fname)
                            };

                            ssh.download_file_with_progress(&sid, &remote_path, &local_path, progress)
                                .map(|_| format!("Downloaded to {}", local_path))
                        }).await.map_err(|e| format!("{}", e))?
                    },
                    |result: Result<String, String>| match result {
                        Ok(msg) => Message::DownloadComplete(msg),
                        Err(e) => Message::Error(e),
                    },
                )
            } else {
                // No filename captured — refresh file browser
                if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
                    tab.terminal.lock().write(
                        b"\r\n\x1b[33m[NeoShell] sz: no filename captured. Use file browser to download.\x1b[0m\r\n",
                    );
                }
                Task::done(Message::ChangeDir(sid, current_dir))
            }
        }

        // ---- terminal scrollback & selection ------------------------------------
        Message::TerminalScrollUp(lines) => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    tab.terminal.lock().scroll_view_up(lines);
                }
            }
            Task::none()
        }
        Message::TerminalScrollDown(lines) => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    tab.terminal.lock().scroll_view_down(lines);
                }
            }
            Task::none()
        }
        Message::TerminalMouseDown => {
            state.selecting = true;
            state.selection_start = None;
            state.selection_end = None;
            // Invalidate canvas cache so old selection is cleared
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let mut grid = tab.terminal.lock();
                    grid.generation = grid.generation.wrapping_add(1);
                }
            }
            Task::none()
        }
        Message::TerminalMouseMove(x, y) => {
            if state.selecting {
                if let Some(pos) = pixel_to_grid(x, y) {
                    if state.selection_start.is_none() {
                        state.selection_start = Some(pos);
                    }
                    state.selection_end = Some(pos);
                    // Invalidate canvas cache to update selection highlight
                    if let Some(idx) = state.active_tab {
                        if let Some(tab) = state.tabs.get(idx) {
                            let mut grid = tab.terminal.lock();
                            grid.generation = grid.generation.wrapping_add(1);
                        }
                    }
                }
            }
            Task::none()
        }
        Message::TerminalMouseUp => {
            state.selecting = false;
            if state.selection_start.is_some() && state.selection_end.is_some() {
                return Task::done(Message::CopySelection);
            }
            Task::none()
        }
        Message::CopySelection => {
            if let (Some(start), Some(end)) = (state.selection_start, state.selection_end) {
                if let Some(idx) = state.active_tab {
                    if let Some(tab) = state.tabs.get(idx) {
                        let grid = tab.terminal.lock();
                        let text = extract_selection(&grid, start, end);
                        if !text.is_empty() {
                            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                                let _ = clipboard.set_text(&text);
                            }
                        }
                    }
                }
            }
            state.selection_start = None;
            state.selection_end = None;
            // Invalidate canvas cache to clear selection highlight
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let mut grid = tab.terminal.lock();
                    grid.generation = grid.generation.wrapping_add(1);
                }
            }
            Task::none()
        }

        // ---- misc ------------------------------------------------------------
        Message::Tick => Task::none(),
        Message::None => Task::none(),
        Message::Error(e) => {
            // Remove placeholder "Connecting..." tabs and get their connection_ids
            let failed_ids: Vec<String> = state.tabs.iter()
                .filter(|t| t.session_id.is_empty())
                .map(|t| t.connection_id.clone())
                .collect();
            state.tabs.retain(|t| !t.session_id.is_empty());
            if state.tabs.is_empty() {
                state.active_tab = None;
            } else if let Some(idx) = state.active_tab {
                if idx >= state.tabs.len() {
                    state.active_tab = Some(state.tabs.len().saturating_sub(1));
                }
            }
            // Clear connecting state for failed connections (allow manual retry)
            for fid in &failed_ids {
                state.connecting_ids.remove(fid);
            }
            // Don't clear ALL connecting_ids — other connections may still be in flight
            state.error_message = e;
            state.transfer_progress = None;
            Task::none()
        }
    }
}

// ---------------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------------

fn subscription(state: &NeoShell) -> Subscription<Message> {
    let mut subs = vec![
        time::every(Duration::from_millis(50)).map(|_| Message::PollSshEvents),
    ];

    // Monitor refresh every 3 seconds when there is an active tab
    if state.screen == Screen::Main && state.active_tab.is_some() {
        subs.push(time::every(Duration::from_secs(3)).map(|_| Message::FetchMonitorData));
    }

    // Listen for keyboard events when we are on the main screen with an active
    // terminal tab. We use event::listen so we can capture raw key events
    // even when the canvas does not have focus.
    if state.screen == Screen::Main && state.active_tab.is_some() {
        subs.push(event::listen().map(|evt| {
            match evt {
                iced::Event::Keyboard(keyboard::Event::KeyPressed {
                    key, modifiers, text, ..
                }) => {
                    Message::KeyboardEvent(key, modifiers, text.map(|s| s.to_string()))
                }
                iced::Event::Mouse(mouse::Event::WheelScrolled { delta }) => {
                    match delta {
                        mouse::ScrollDelta::Lines { y, .. } => {
                            if y > 0.0 {
                                Message::TerminalScrollUp(3)
                            } else if y < 0.0 {
                                Message::TerminalScrollDown(3)
                            } else {
                                Message::None
                            }
                        }
                        mouse::ScrollDelta::Pixels { y, .. } => {
                            if y > 0.0 {
                                Message::TerminalScrollUp(1)
                            } else if y < 0.0 {
                                Message::TerminalScrollDown(1)
                            } else {
                                Message::None
                            }
                        }
                    }
                }
                iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                    Message::TerminalMouseDown
                }
                iced::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                    Message::TerminalMouseUp
                }
                iced::Event::Mouse(mouse::Event::CursorMoved { position }) => {
                    Message::TerminalMouseMove(position.x, position.y)
                }
                _ => Message::None,
            }
        }));
    }

    Subscription::batch(subs)
}


// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

fn view(state: &NeoShell) -> Element<'_, Message> {
    match &state.screen {
        Screen::Setup => view_setup(state),
        Screen::Locked => view_unlock(state),
        Screen::Main => view_main(state),
    }
}

// ---- Setup screen --------------------------------------------------------

fn view_setup(state: &NeoShell) -> Element<'_, Message> {
    let title = text("Welcome to NeoShell")
        .size(28)
        .color(theme::TEXT_PRIMARY);

    let subtitle = text("Create a master password to protect your connections")
        .size(14)
        .color(theme::TEXT_SECONDARY);

    let pw_input = text_input("Master password", &state.password_input)
        .on_input(Message::PasswordChanged)
        .secure(true)
        .padding(10)
        .size(16)
        .id(iced::widget::text_input::Id::new("setup_pw"));

    let confirm_input = text_input("Confirm password", &state.confirm_input)
        .on_input(Message::ConfirmChanged)
        .on_submit(Message::CreateVault)
        .secure(true)
        .padding(10)
        .size(16)
        .id(iced::widget::text_input::Id::new("setup_confirm"));

    let create_btn = button(
        text("Create Vault").color(theme::TEXT_PRIMARY).size(16),
    )
    .on_press(Message::CreateVault)
    .padding(Padding::from([10, 24]))
    .style(accent_button_style);

    let error_text = if state.error_message.is_empty() {
        text("").size(1)
    } else {
        text(&state.error_message).color(theme::DANGER).size(14)
    };

    let form = column![title, subtitle, pw_input, confirm_input, error_text, create_btn]
        .spacing(16)
        .align_x(alignment::Horizontal::Center)
        .width(360);

    container(form)
        .center_x(Fill)
        .center_y(Fill)
        .width(Fill)
        .height(Fill)
        .style(bg_primary_container)
        .into()
}

// ---- Unlock screen -------------------------------------------------------

fn view_unlock(state: &NeoShell) -> Element<'_, Message> {
    let title = text("NeoShell")
        .size(28)
        .color(theme::TEXT_PRIMARY);

    let subtitle = text("Enter master password to unlock")
        .size(14)
        .color(theme::TEXT_SECONDARY);

    let pw_input = text_input("Master password", &state.password_input)
        .on_input(Message::PasswordChanged)
        .on_submit(Message::UnlockVault)
        .secure(true)
        .padding(10)
        .size(16);

    let unlock_btn = button(
        text("Unlock").color(theme::TEXT_PRIMARY).size(16),
    )
    .on_press(Message::UnlockVault)
    .padding(Padding::from([10, 24]))
    .style(accent_button_style);

    let error_text = if state.error_message.is_empty() {
        text("").size(1)
    } else {
        text(&state.error_message).color(theme::DANGER).size(14)
    };

    let form = column![title, subtitle, pw_input, error_text, unlock_btn]
        .spacing(16)
        .align_x(alignment::Horizontal::Center)
        .width(360);

    container(form)
        .center_x(Fill)
        .center_y(Fill)
        .width(Fill)
        .height(Fill)
        .style(bg_primary_container)
        .into()
}

// ---- Main screen (tabs + sidebar + terminal + file browser) ---------------

fn view_main(state: &NeoShell) -> Element<'_, Message> {
    let tab_bar = view_tab_bar(state);
    let status_bar = view_status_bar(state);

    let body: Element<'_, Message> = if state.active_tab.is_some() {
        // Connected view: monitor sidebar + (terminal + file browser)
        let sidebar = view_monitor_sidebar(state);
        let terminal = view_terminal_area(state);
        let file_browser = view_file_browser(state);

        let mut right_col = column![
            container(terminal).height(Fill),
        ];
        if let Some(progress) = &state.transfer_progress {
            if !progress.is_finished() {
                right_col = right_col.push(view_transfer_progress(progress));
            }
        }
        right_col = right_col.push(file_browser);

        let right_panel: Element<'_, Message> = right_col
            .width(Fill)
            .height(Fill)
            .into();

        row![
            container(sidebar).width(280).height(Fill),
            right_panel,
        ]
        .height(Fill)
        .into()
    } else {
        // Not connected: connection list sidebar + welcome
        let sidebar = view_sidebar(state);
        let welcome = view_welcome();
        row![
            container(sidebar).width(280).height(Fill),
            container(welcome).width(Fill).height(Fill),
        ]
        .height(Fill)
        .into()
    };

    let main_layout: Element<'_, Message> = column![tab_bar, body, status_bar]
        .height(Fill)
        .into();

    // Editor overlay (highest priority — on top of everything)
    if state.editor_file_path.is_some() {
        let editor_overlay = view_editor(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            editor_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Network detail popup
    if state.selected_interface.is_some() {
        let net_overlay = view_network_detail(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            net_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Quick-connect dialog
    if state.show_connect_dialog {
        let dialog = view_connect_dialog(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            dialog,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Modal overlay for connection form
    if state.show_form {
        let form_overlay = view_connection_form_overlay(state);
        container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            form_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into()
    } else {
        container(main_layout)
            .width(Fill)
            .height(Fill)
            .style(bg_primary_container)
            .into()
    }
}

// ---- Welcome screen (no active tab) --------------------------------------

fn view_welcome() -> Element<'static, Message> {
    let placeholder = column![
        vertical_space().height(80),
        text("NeoShell").size(36).color(theme::TEXT_MUTED),
        text("Select a connection from the sidebar to begin")
            .size(14)
            .color(theme::TEXT_MUTED),
    ]
    .spacing(12)
    .align_x(alignment::Horizontal::Center);

    container(placeholder)
        .width(Fill)
        .height(Fill)
        .center_x(Fill)
        .center_y(Fill)
        .style(|_theme| container::Style {
            background: Some(theme::BG_PRIMARY.into()),
            ..Default::default()
        })
        .into()
}

// ---- Tab bar -------------------------------------------------------------

fn view_tab_bar(state: &NeoShell) -> Element<'_, Message> {
    let mut tabs_row = row![].spacing(0);

    for (i, tab) in state.tabs.iter().enumerate() {
        let is_active = state.active_tab == Some(i);
        let bg_color = if is_active {
            theme::BG_TERTIARY
        } else {
            theme::BG_SECONDARY
        };
        let text_color = if is_active {
            theme::TEXT_PRIMARY
        } else {
            theme::TEXT_SECONDARY
        };

        // Connection status indicator dot
        let status_dot = if tab.session_id.is_empty() {
            text("● ").color(theme::WARNING).size(10) // Connecting...
        } else if tab.title.contains("[Reconnecting") {
            text("● ").color(theme::WARNING).size(10) // Reconnecting
        } else {
            text("● ").color(theme::SUCCESS).size(10) // Connected
        };

        let label = text(&tab.title).color(text_color).size(13);
        let close_btn = button(text("x").color(theme::TEXT_MUTED).size(11))
            .on_press(Message::TabClosed(i))
            .padding(Padding::from([2, 6]))
            .style(transparent_button_style);

        let tab_content = row![status_dot, label, close_btn]
            .spacing(8)
            .align_y(alignment::Vertical::Center);

        let tab_btn = button(tab_content)
            .on_press(Message::TabSelected(i))
            .padding(Padding::from([6, 14]))
            .style(move |_theme: &Theme, status| {
                let mut s = button::Style::default();
                s.background = Some(bg_color.into());
                s.text_color = text_color;
                if let button::Status::Hovered = status {
                    s.background = Some(theme::BG_HOVER.into());
                }
                s
            });

        tabs_row = tabs_row.push(tab_btn);
    }

    // If no tabs, show placeholder
    if state.tabs.is_empty() {
        tabs_row = tabs_row.push(
            container(text("No open tabs").color(theme::TEXT_MUTED).size(12))
                .padding(Padding::from([8, 14])),
        );
    }

    // "+" button to open new connection + fill remaining space
    tabs_row = tabs_row.push(
        button(text("+").color(theme::TEXT_MUTED).size(14))
            .on_press(Message::ShowConnectDialog)
            .padding(Padding::from([6, 10]))
            .style(transparent_button_style),
    );
    tabs_row = tabs_row.push(horizontal_space());

    container(tabs_row)
        .width(Fill)
        .height(34)
        .style(|_theme| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            ..Default::default()
        })
        .into()
}

// ---- Sidebar (connection list, shown when no active tab) -----------------

fn view_sidebar(state: &NeoShell) -> Element<'_, Message> {
    let header = row![
        text("Connections").color(theme::TEXT_PRIMARY).size(15),
        horizontal_space(),
        button(text("+").color(theme::ACCENT).size(18))
            .on_press(Message::ShowForm(None))
            .padding(Padding::from([2, 8]))
            .style(transparent_button_style),
    ]
    .align_y(alignment::Vertical::Center)
    .padding(Padding::from([8, 12]));

    let search = text_input("Search...", &state.search_query)
        .on_input(Message::SearchChanged)
        .padding(8)
        .size(13);

    let search_container = container(search).padding(Padding::new(8.0).top(0.0));

    // Group connections
    let query = state.search_query.to_lowercase();
    let filtered: Vec<&ConnectionInfo> = state
        .connections
        .iter()
        .filter(|c| {
            if query.is_empty() {
                return true;
            }
            c.name.to_lowercase().contains(&query)
                || c.host.to_lowercase().contains(&query)
                || c.username.to_lowercase().contains(&query)
                || c.group.to_lowercase().contains(&query)
        })
        .collect();

    // Build grouped list
    let mut groups: HashMap<String, Vec<&ConnectionInfo>> = HashMap::new();
    for conn in &filtered {
        let group_name = if conn.group.is_empty() {
            "Ungrouped".to_string()
        } else {
            conn.group.clone()
        };
        groups.entry(group_name).or_default().push(conn);
    }

    let mut list_col = column![].spacing(2);

    let mut group_names: Vec<String> = groups.keys().cloned().collect();
    group_names.sort();

    for group_name in group_names {
        let conns = &groups[&group_name];

        let group_label = text(group_name.clone()).color(theme::TEXT_MUTED).size(11);

        list_col = list_col.push(
            container(group_label).padding(Padding::new(12.0).top(6.0).bottom(2.0)),
        );

        for conn in conns {
            let status_dot = text("\u{25CF} ").color(theme::SUCCESS).size(10);
            let name_label = text(&conn.name).color(theme::TEXT_PRIMARY).size(13);
            let host_label = text(format!("{}@{}:{}", conn.username, conn.host, conn.port))
                .color(theme::TEXT_MUTED)
                .size(11);

            let conn_content = column![
                row![status_dot, name_label].align_y(alignment::Vertical::Center),
                host_label,
            ]
            .spacing(2);

            let conn_id = conn.id.clone();

            let connect_btn = button(conn_content)
                .on_press(Message::ConnectTo(conn_id))
                .padding(Padding::from([6, 12]))
                .width(Fill)
                .style(sidebar_item_style);

            list_col = list_col.push(connect_btn);
        }
    }

    if filtered.is_empty() {
        list_col = list_col.push(
            container(
                text("No connections found")
                    .color(theme::TEXT_MUTED)
                    .size(13),
            )
            .padding(Padding::from([16, 12])),
        );
    }

    let sidebar_content = column![header, search_container, scrollable(list_col).height(Fill)]
        .height(Fill);

    container(sidebar_content)
        .width(280)
        .height(Fill)
        .style(|_theme| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}

// ---- Monitor sidebar (when terminal active) ------------------------------

fn view_monitor_sidebar(state: &NeoShell) -> Element<'_, Message> {
    let active_session = state
        .active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.session_id.as_str());

    let stats = active_session.and_then(|sid| state.server_stats.get(sid));
    let processes = active_session.and_then(|sid| state.top_processes.get(sid));

    let mut col = column![].spacing(0);

    // ── Header ──────────────────────────────────────────────────────────
    let header = container(
        row![
            text("System").color(theme::TEXT_PRIMARY).size(13),
            horizontal_space(),
            button(text("+").color(theme::ACCENT).size(16))
                .on_press(Message::ShowConnectDialog)
                .padding(Padding::from([2, 6]))
                .style(transparent_button_style),
        ]
        .align_y(alignment::Vertical::Center)
        .padding(Padding::from([8, 10])),
    )
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        ..Default::default()
    })
    .width(Fill);
    col = col.push(header);

    if let Some(stats) = stats {
        // Load — label left, values right
        col = col.push(sys_row("Load",
            &format!("{:.2} / {:.2} / {:.2}", stats.load_1m, stats.load_5m, stats.load_15m)));
        col = col.push(sys_row("CPU", &format!("{} cores", stats.cpu_cores)));

        // Memory — label left, usage right + progress bar
        col = col.push(sys_row("Mem",
            &format!("{} / {} MB ({:.0}%)", stats.mem_used_mb, stats.mem_total_mb, stats.mem_percent)));
        col = col.push(progress_bar_widget(stats.mem_percent));

        // Disks
        if stats.disks.is_empty() {
            col = col.push(sys_row("Disk",
                &format!("{:.1} / {:.1} GB ({:.0}%)", stats.disk_used_gb, stats.disk_total_gb, stats.disk_percent)));
            col = col.push(progress_bar_widget(stats.disk_percent));
        } else {
            for d in &stats.disks {
                col = col.push(sys_row(
                    &truncate_str(&d.mount_point, 8),
                    &format!("{}/{} ({:.0}%)", d.used, d.total, d.percent),
                ));
                col = col.push(progress_bar_widget(d.percent));
            }
        }

        // Uptime
        if !stats.uptime.is_empty() {
            col = col.push(sys_row("Up", &stats.uptime));
        }
    } else {
        col = col.push(
            container(text("Connecting...").color(theme::TEXT_MUTED).size(12))
                .padding(Padding::from([8, 10])),
        );
    }

    // ── Divider ─────────────────────────────────────────────────────────
    col = col.push(sidebar_divider());

    // ── Top Processes (BEFORE Network) ──────────────────────────────────
    col = col.push(section_header("Top Processes"));

    if let Some(procs) = processes {
        // Column-aligned header
        let hdr_row = row![
            container(text("PID").color(theme::TEXT_MUTED).size(9)).width(42),
            container(text("CPU").color(theme::TEXT_MUTED).size(9)).width(38),
            container(text("MEM").color(theme::TEXT_MUTED).size(9)).width(36),
            container(text("CMD").color(theme::TEXT_MUTED).size(9)).width(Fill),
        ]
        .spacing(2)
        .padding(Padding::from([4, 8]));

        let mut proc_col = column![hdr_row, sidebar_divider()].spacing(0);

        for (i, p) in procs.iter().take(15).enumerate() {
            let bar_len = ((p.cpu / 100.0) * 6.0).ceil() as usize;
            let bar: String = "\u{2588}".repeat(bar_len.min(6));
            let pad: String = "\u{2591}".repeat(6_usize.saturating_sub(bar_len));

            let color = if p.cpu > 50.0 { theme::DANGER }
                       else if p.cpu > 20.0 { theme::WARNING }
                       else { theme::TEXT_SECONDARY };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };

            let pid_text = format!("{}", p.pid);
            let cpu_text = format!("{:.1}", p.cpu);
            let mem_text = format!("{:.1}", p.mem);
            let cmd_text = truncate_str(&p.command, 10);

            let proc_row = row![
                container(text(pid_text).color(color).size(9)).width(42),
                container(text(cpu_text).color(color).size(9)).width(38),
                container(text(mem_text).color(color).size(9)).width(36),
                text(cmd_text).color(color).size(9),
                horizontal_space(),
                text(format!("{}{}", bar, pad)).color(color).size(7).font(Font::MONOSPACE),
            ]
            .spacing(2)
            .align_y(alignment::Vertical::Center);

            proc_col = proc_col.push(
                container(proc_row)
                    .padding(Padding::from([3, 8]))
                    .width(Fill)
                    .style(move |_| container::Style {
                        background: Some(row_bg.into()),
                        ..Default::default()
                    })
            );
        }
        col = col.push(proc_col);
    } else {
        col = col.push(
            container(text("Loading...").color(theme::TEXT_MUTED).size(11))
                .padding(Padding::from([8, 10])),
        );
    }

    // ── Divider ─────────────────────────────────────────────────────────
    col = col.push(sidebar_divider());

    // ── Network (compact: only physical + total, clickable) ─────────────
    col = col.push(section_header("Network"));

    if let Some(stats) = stats {
        // Filter: skip lo, show physical first, then virtual (limit 5)
        let mut physical: Vec<&crate::ssh::NetInterface> = Vec::new();
        let mut virtual_ifs: Vec<&crate::ssh::NetInterface> = Vec::new();
        for iface in &stats.interfaces {
            if iface.name == "lo" { continue; }
            if iface.name.starts_with("eth") || iface.name.starts_with("en")
                || iface.name.starts_with("wl") || iface.name.starts_with("bond")
                || iface.name.starts_with("ib") {
                physical.push(iface);
            } else {
                virtual_ifs.push(iface);
            }
        }

        // Show physical interfaces (column-aligned)
        for iface in &physical {
            let iface_clone = (*iface).clone();
            let net_row = row![
                container(text(truncate_str(&iface.name, 10)).color(theme::ACCENT).size(10)).width(Fill),
                container(text(format!("\u{2193}{}", format_bytes(iface.rx_bytes))).color(theme::TEXT_MUTED).size(9))
                    .width(80).align_x(alignment::Horizontal::Right),
                container(text(format!("\u{2191}{}", format_bytes(iface.tx_bytes))).color(theme::TEXT_MUTED).size(9))
                    .width(80).align_x(alignment::Horizontal::Right),
            ].spacing(2).align_y(alignment::Vertical::Center);

            col = col.push(
                button(net_row)
                    .on_press(Message::ShowNetworkDetail(iface_clone))
                    .padding(Padding::from([2, 10]))
                    .width(Fill)
                    .style(sidebar_item_style)
            );
        }

        // Show virtual count as summary
        if !virtual_ifs.is_empty() {
            let virt_rx: u64 = virtual_ifs.iter().map(|i| i.rx_bytes).sum();
            let virt_tx: u64 = virtual_ifs.iter().map(|i| i.tx_bytes).sum();
            let virt_row = row![
                container(text(format!("virtual({})", virtual_ifs.len())).color(theme::TEXT_MUTED).size(10)).width(Fill),
                container(text(format!("\u{2193}{}", format_bytes(virt_rx))).color(theme::TEXT_MUTED).size(9))
                    .width(80).align_x(alignment::Horizontal::Right),
                container(text(format!("\u{2191}{}", format_bytes(virt_tx))).color(theme::TEXT_MUTED).size(9))
                    .width(80).align_x(alignment::Horizontal::Right),
            ].spacing(2).align_y(alignment::Vertical::Center);
            col = col.push(container(virt_row).padding(Padding::from([2, 10])));
        }

        // Total
        let total_row = row![
            container(text("Total").color(theme::TEXT_SECONDARY).size(10)).width(Fill),
            container(text(format!("\u{2193}{}", format_bytes(stats.net_rx_bytes))).color(theme::TEXT_SECONDARY).size(9))
                .width(80).align_x(alignment::Horizontal::Right),
            container(text(format!("\u{2191}{}", format_bytes(stats.net_tx_bytes))).color(theme::TEXT_SECONDARY).size(9))
                .width(80).align_x(alignment::Horizontal::Right),
        ].spacing(2).align_y(alignment::Vertical::Center);
        col = col.push(container(total_row).padding(Padding::from([2, 10])));

        // Network speed (bytes/sec)
        if let Some(sid) = active_session {
            let rx_rate = state.net_rx_rate.get(sid).copied().unwrap_or(0.0);
            let tx_rate = state.net_tx_rate.get(sid).copied().unwrap_or(0.0);
            col = col.push(
                container(
                    text(format!(
                        "Speed: \u{2193}{}/s \u{2191}{}/s",
                        format_bytes(rx_rate as u64),
                        format_bytes(tx_rate as u64),
                    ))
                    .color(theme::SUCCESS)
                    .size(10)
                )
                .padding(Padding::from([3, 10]))
            );
        }
    }

    // Wrap everything in a scrollable
    let sidebar_content = scrollable(col).height(Fill);

    container(sidebar_content)
        .width(280)
        .height(Fill)
        .style(|_theme| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}

fn sidebar_divider() -> Element<'static, Message> {
    container(Space::new(Fill, 1))
        .style(|_| container::Style {
            background: Some(theme::BORDER.into()),
            ..Default::default()
        })
        .width(Fill)
        .height(1)
        .into()
}

fn section_header(title: &str) -> Element<'static, Message> {
    container(text(title.to_string()).color(theme::TEXT_PRIMARY).size(12))
        .padding(Padding::from([6, 10]))
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            ..Default::default()
        })
        .width(Fill)
        .into()
}

/// A single stat row in the sidebar (owns its content to avoid borrow issues).
fn stat_row(icon: &str, text_content: &str) -> Element<'static, Message> {
    let content = format!("{} {}", icon, text_content);
    let label = text(content).color(theme::TEXT_SECONDARY).size(11);
    container(label)
        .padding(Padding::from([3, 10]))
        .width(Fill)
        .into()
}

/// System info row: label(left, 60px) | value(right, fill)
fn sys_row(label_str: &str, value_str: &str) -> Element<'static, Message> {
    let l = label_str.to_string();
    let v = value_str.to_string();
    container(
        row![
            container(text(l).color(theme::TEXT_MUTED).size(10)).width(55),
            container(text(v).color(theme::TEXT_SECONDARY).size(10))
                .width(Fill).align_x(alignment::Horizontal::Right),
        ]
        .spacing(4)
        .align_y(alignment::Vertical::Center)
    )
    .padding(Padding::from([3, 10]))
    .width(Fill)
    .into()
}

/// A small progress bar widget for memory/disk usage.
fn progress_bar_widget(percent: f64) -> Element<'static, Message> {
    let clamped = percent.max(0.0).min(100.0);
    let width = (clamped / 100.0 * 196.0) as f32;
    let bar_color = if clamped > 90.0 {
        theme::DANGER
    } else if clamped > 70.0 {
        theme::WARNING
    } else {
        theme::SUCCESS
    };

    container(
        container(Space::new(width, 3))
            .style(move |_| container::Style {
                background: Some(bar_color.into()),
                border: iced::Border {
                    radius: 2.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
    )
    .padding(Padding::new(1.0).left(10.0).right(10.0).bottom(4.0))
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        ..Default::default()
    })
    .into()
}

// ---- Terminal area -------------------------------------------------------

fn view_terminal_area(state: &NeoShell) -> Element<'_, Message> {
    if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            let term_view = TerminalView {
                grid: tab.terminal.clone(),
                selection_start: state.selection_start,
                selection_end: state.selection_end,
            };

            return canvas(term_view).width(Fill).height(Fill).into();
        }
    }

    // Empty state (fallback)
    let placeholder = column![
        vertical_space().height(80),
        text("NeoShell").size(36).color(theme::TEXT_MUTED),
        text("Select a connection from the sidebar to begin")
            .size(14)
            .color(theme::TEXT_MUTED),
    ]
    .spacing(12)
    .align_x(alignment::Horizontal::Center);

    container(placeholder)
        .width(Fill)
        .height(Fill)
        .center_x(Fill)
        .center_y(Fill)
        .style(|_theme| container::Style {
            background: Some(theme::BG_PRIMARY.into()),
            ..Default::default()
        })
        .into()
}

// ---- Transfer progress bar -----------------------------------------------

fn view_transfer_progress(progress: &TransferProgress) -> Element<'static, Message> {
    use std::sync::atomic::Ordering;
    let pct = progress.percent();
    let transferred = progress.transferred.load(Ordering::Relaxed);
    let total = progress.total.load(Ordering::Relaxed);
    let filename = progress.filename.lock().clone();

    // Calculate transfer speed from start_time
    let speed = if let Some(start) = progress.start_time.lock().as_ref() {
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed > 0.5 && transferred > 0 {
            format!(" — {}/s", format_bytes((transferred as f64 / elapsed) as u64))
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let label = if total > 0 {
        format!(
            "{} — {} / {} ({:.0}%){}",
            filename,
            format_bytes(transferred),
            format_bytes(total),
            pct,
            speed
        )
    } else {
        format!("{} — preparing...", filename)
    };

    let progress_text = text(label).color(theme::TEXT_PRIMARY).size(11);
    let cancel_btn = button(text("Cancel").color(theme::DANGER).size(11))
        .on_press(Message::CancelTransfer)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let header_row = row![progress_text, horizontal_space(), cancel_btn]
        .align_y(alignment::Vertical::Center);

    // Progress bar: fixed-width filled portion inside full-width background
    let bar_width_px = 600.0; // approximate usable width
    let filled_px = (pct / 100.0).min(1.0).max(0.0) * bar_width_px;

    let filled_bar = container(Space::new(filled_px as f32, 6))
        .style(|_| container::Style {
            background: Some(theme::ACCENT.into()),
            border: iced::Border { radius: 3.0.into(), ..Default::default() },
            ..Default::default()
        });

    let bar_bg = container(filled_bar)
        .width(Fill)
        .height(6)
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border { radius: 3.0.into(), ..Default::default() },
            ..Default::default()
        });

    container(
        column![header_row, bar_bg].spacing(4).padding(Padding::from([6, 10]))
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        ..Default::default()
    })
    .into()
}

// ---- File browser --------------------------------------------------------

fn view_file_browser(state: &NeoShell) -> Element<'_, Message> {
    let active_session = state
        .active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.session_id.clone());

    let sid = match &active_session {
        Some(s) => s.clone(),
        None => return Space::new(Fill, 0).into(),
    };

    let current_path = state
        .current_dir
        .get(&sid)
        .map(|s| s.as_str())
        .unwrap_or("~");

    let entries = state.file_entries.get(&sid);

    // Header with path and upload button
    let path_label = text(format!("[DIR] {}", current_path))
        .color(theme::TEXT_PRIMARY)
        .size(12);

    let upload_btn = button(text("^ Upload").color(theme::SUCCESS).size(11))
        .on_press(Message::UploadFile)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let header = container(
        row![path_label, horizontal_space(), upload_btn]
            .align_y(alignment::Vertical::Center),
    )
    .padding(Padding::from([6, 10]))
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border {
            color: theme::BORDER,
            width: 1.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    });

    let mut file_col = column![].spacing(0);

    if let Some(entries) = entries {
        // Build unified file entries (including ".." parent)
        let mut all_entries: Vec<&FileEntry> = Vec::new();
        // Create a static parent entry
        let parent_entry = FileEntry {
            name: "..".to_string(),
            is_dir: true,
            size: String::new(),
            permissions: String::new(),
            modified: String::new(),
            owner: String::new(),
        };
        all_entries.push(&parent_entry);
        for e in entries.iter().filter(|e| e.name != "..") {
            all_entries.push(e);
        }

        for entry in &all_entries {
            let (icon, name_color) = if entry.name == ".." {
                ("..", theme::ACCENT)
            } else if entry.is_dir {
                ("D", theme::ACCENT)
            } else {
                ("F", theme::TEXT_PRIMARY)
            };

            let display_name = if entry.name == ".." {
                "..".to_string()
            } else {
                format!("{} {}", icon, truncate_str(&entry.name, 24))
            };

            let human_size = if entry.size.is_empty() { "".to_string() } else { humanize_file_size(&entry.size) };
            let date_str = if entry.modified.is_empty() { "".to_string() } else { entry.modified.clone() };

            // Build action buttons (fixed 50px column, always present for alignment)
            let actions: Element<'_, Message> = if !entry.is_dir && entry.name != ".." {
                let current = state.current_dir.get(&sid).cloned().unwrap_or("~".to_string());
                let full_path = format!("{}/{}", current.trim_end_matches('/'), entry.name);

                let dl_btn = button(text("v").color(theme::ACCENT).size(10))
                    .on_press(Message::DownloadFile(sid.clone(), full_path.clone()))
                    .padding(Padding::from([1, 3]))
                    .style(transparent_button_style);

                if crate::ssh::is_editable_file(&entry.name) {
                    let edit_btn = button(text("E").color(theme::SUCCESS).size(10))
                        .on_press(Message::OpenEditor(sid.clone(), full_path))
                        .padding(Padding::from([1, 3]))
                        .style(transparent_button_style);
                    row![dl_btn, edit_btn].spacing(2).into()
                } else {
                    dl_btn.into()
                }
            } else {
                Space::new(0, 0).into()
            };

            // Unified columns: Name(left,fill) | Size(right,80) | Date(center,110) | Actions(right,50)
            let entry_row = row![
                container(text(display_name).color(name_color).size(11)).width(Fill),
                container(text(human_size).color(theme::TEXT_MUTED).size(10))
                    .width(80).align_x(alignment::Horizontal::Right),
                container(text(date_str).color(theme::TEXT_MUTED).size(10))
                    .width(120).align_x(alignment::Horizontal::Center),
                container(actions).width(70).align_x(alignment::Horizontal::Right)
                    .padding(Padding::new(0.0).right(14.0)),
            ]
            .spacing(4)
            .align_y(alignment::Vertical::Center);

            // All entries use same wrapper (button for dirs, container for files)
            if entry.is_dir {
                let entry_clone = (*entry).clone();
                let sid_clone = sid.clone();
                file_col = file_col.push(
                    button(entry_row)
                        .on_press(Message::FileClicked(sid_clone, entry_clone))
                        .padding(Padding::from([2, 8]))
                        .width(Fill)
                        .style(sidebar_item_style),
                );
            } else {
                file_col = file_col.push(
                    container(entry_row)
                        .padding(Padding::from([2, 8]))
                        .width(Fill),
                );
            }
        }
    } else {
        file_col = file_col.push(
            container(text("Loading files...").color(theme::TEXT_MUTED).size(12))
                .padding(Padding::from([8, 10])),
        );
    }

    column![header, scrollable(file_col).height(Fill)]
        .height(Length::Fixed(200.0))
        .into()
}

// ---- Network detail popup ------------------------------------------------

// ---- Quick-connect dialog (open new tab to any saved connection) ----------

fn view_connect_dialog(state: &NeoShell) -> Element<'_, Message> {
    let title = row![
        text("Connect to Server").color(theme::TEXT_PRIMARY).size(18),
        horizontal_space(),
        button(text("+ New").color(theme::ACCENT).size(13))
            .on_press(Message::ShowForm(None))
            .padding(Padding::from([4, 12]))
            .style(transparent_button_style),
        button(text("x").color(theme::TEXT_MUTED).size(14))
            .on_press(Message::HideConnectDialog)
            .padding(Padding::from([4, 8]))
            .style(transparent_button_style),
    ]
    .align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(2);

    if state.connections.is_empty() {
        list_col = list_col.push(
            container(text("No saved connections").color(theme::TEXT_MUTED).size(13))
                .padding(Padding::from([16, 12])),
        );
    } else {
        for conn in &state.connections {
            let conn_id = conn.id.clone();
            let conn_id_edit = conn.id.clone();
            let conn_id_del = conn.id.clone();
            let conn_name = conn.name.clone();

            let info_col = column![
                text(&conn.name).color(theme::TEXT_PRIMARY).size(14),
                text(format!("{}@{}:{}", conn.username, conn.host, conn.port))
                    .color(theme::TEXT_MUTED).size(11),
            ].spacing(2);

            let connect_btn = button(
                row![
                    text("\u{25CF} ").color(theme::SUCCESS).size(10),
                    info_col,
                ].spacing(8).align_y(alignment::Vertical::Center)
            )
            .on_press(Message::ConnectTo(conn_id))
            .padding(Padding::from([8, 8]))
            .style(sidebar_item_style);

            let edit_btn = button(text("Edit").color(theme::ACCENT).size(11))
                .on_press(Message::ShowForm(Some(conn_id_edit)))
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style);

            let del_btn = button(text("Del").color(theme::DANGER).size(11))
                .on_press(Message::DeleteConnection(conn_id_del))
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style);

            let entry_row = row![
                connect_btn,
                horizontal_space(),
                text(&conn.group).color(theme::TEXT_MUTED).size(10),
                edit_btn,
                del_btn,
            ]
            .align_y(alignment::Vertical::Center)
            .spacing(4)
            .padding(Padding::from([0, 4]));

            list_col = list_col.push(entry_row);
        }
    }

    // SSH config hosts
    let ssh_configs = crate::sshconfig::parse_ssh_config();
    if !ssh_configs.is_empty() {
        list_col = list_col.push(
            container(
                text("From ~/.ssh/config")
                    .color(theme::TEXT_MUTED)
                    .size(11),
            )
            .padding(Padding::from([8, 12])),
        );

        for config in ssh_configs {
            let display_host = if config.hostname.is_empty() {
                config.alias.clone()
            } else {
                config.hostname.clone()
            };
            let alias_text = config.alias.clone();
            let user_display = if config.user.is_empty() {
                "?".to_string()
            } else {
                config.user.clone()
            };
            let detail = format!("{}@{}:{}", user_display, display_host, config.port);

            let config_row = row![
                text("\u{25CB} ").color(theme::ACCENT).size(10),
                column![
                    text(alias_text).color(theme::TEXT_SECONDARY).size(13),
                    text(detail).color(theme::TEXT_MUTED).size(11),
                ]
                .spacing(2),
                horizontal_space(),
                text("ssh config").color(theme::TEXT_MUTED).size(9),
            ]
            .align_y(alignment::Vertical::Center)
            .spacing(8);

            list_col = list_col.push(
                button(config_row)
                    .on_press(Message::ImportSshConfig(config))
                    .padding(Padding::from([6, 12]))
                    .width(Fill)
                    .style(sidebar_item_style),
            );
        }
    }

    let hint = text("Cmd+T open | Cmd+1-9 switch tabs | Ctrl+Tab next | Cmd+W close")
        .color(theme::TEXT_MUTED)
        .size(10);

    let content = column![title, scrollable(list_col).height(300), hint]
        .spacing(12)
        .padding(24)
        .width(480);

    let card = container(content).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border {
            color: theme::BORDER,
            width: 1.0,
            radius: 10.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 24.0,
        },
        ..Default::default()
    });

    container(card)
        .width(Fill)
        .height(Fill)
        .center_x(Fill)
        .center_y(Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.6).into()),
            ..Default::default()
        })
        .into()
}

fn view_network_detail(state: &NeoShell) -> Element<'_, Message> {
    let iface = match &state.selected_interface {
        Some(i) => i,
        None => return Space::new(0, 0).into(),
    };

    let title = text(format!("Interface: {}", iface.name))
        .color(theme::TEXT_PRIMARY).size(16);

    let close_btn = button(text("Close").color(theme::TEXT_SECONDARY).size(13))
        .on_press(Message::HideNetworkDetail)
        .padding(Padding::from([6, 16]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), close_btn]
        .align_y(alignment::Vertical::Center);

    let rx_text = format_bytes(iface.rx_bytes);
    let tx_text = format_bytes(iface.tx_bytes);
    let total = format_bytes(iface.rx_bytes + iface.tx_bytes);

    let mut info_col = column![].spacing(8);
    info_col = info_col.push(detail_row("Interface", &iface.name));
    info_col = info_col.push(detail_row("Received (Rx)", &rx_text));
    info_col = info_col.push(detail_row("Transmitted (Tx)", &tx_text));
    info_col = info_col.push(detail_row("Total Traffic", &total));

    // Determine interface type
    let if_type = if iface.name.starts_with("eth") || iface.name.starts_with("en") {
        "Ethernet"
    } else if iface.name.starts_with("wl") {
        "Wireless"
    } else if iface.name.starts_with("br-") || iface.name.starts_with("docker") {
        "Docker Bridge"
    } else if iface.name.starts_with("veth") {
        "Virtual Ethernet (Container)"
    } else if iface.name.starts_with("bond") {
        "Bond"
    } else if iface.name.starts_with("tun") || iface.name.starts_with("tap") {
        "VPN Tunnel"
    } else if iface.name.starts_with("lo") {
        "Loopback"
    } else {
        "Other"
    };
    info_col = info_col.push(detail_row("Type", if_type));

    let content = column![header, info_col].spacing(16).padding(24).width(380);

    let card = container(content).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 8.0.into() },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    });

    container(card)
        .width(Fill)
        .height(Fill)
        .center_x(Fill)
        .center_y(Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.6).into()),
            ..Default::default()
        })
        .into()
}

fn detail_row(label: &str, value: &str) -> Element<'static, Message> {
    let l = label.to_string();
    let v = value.to_string();
    row![
        text(l).color(theme::TEXT_MUTED).size(13).width(140),
        text(v).color(theme::TEXT_PRIMARY).size(13),
    ]
    .spacing(8)
    .into()
}

// ---- File editor (modal overlay) -----------------------------------------

fn view_editor(state: &NeoShell) -> Element<'_, Message> {
    let file_name = state.editor_file_path.as_deref().unwrap_or("untitled");

    let title_text = if state.editor_dirty {
        format!("* {} (modified)", file_name)
    } else {
        format!("  {}", file_name)
    };

    let title = text(title_text).color(theme::TEXT_PRIMARY).size(14);

    let save_btn = button(text("Save").color(theme::TEXT_PRIMARY).size(13))
        .on_press(Message::SaveEditor)
        .padding(Padding::from([6, 16]))
        .style(accent_button_style);

    let close_btn = button(text("Close").color(theme::TEXT_SECONDARY).size(13))
        .on_press(Message::CloseEditor)
        .padding(Padding::from([6, 16]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), save_btn, close_btn]
        .spacing(8)
        .align_y(alignment::Vertical::Center)
        .padding(Padding::from([8, 12]));

    let header_bar = container(header)
        .width(Fill)
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        });

    let editor = text_editor(&state.editor_content)
        .on_action(Message::EditorAction)

        .size(13)
        .height(Fill);

    let content = column![header_bar, editor].height(Fill);

    // Full-screen modal overlay
    container(
        container(content)
            .width(Fill)
            .height(Fill)
            .max_width(1000)
            .max_height(700)
            .style(|_| container::Style {
                background: Some(theme::BG_SECONDARY.into()),
                border: iced::Border {
                    color: theme::BORDER,
                    width: 1.0,
                    radius: 8.0.into(),
                },
                shadow: iced::Shadow {
                    color: Color::from_rgba(0.0, 0.0, 0.0, 0.6),
                    offset: iced::Vector::new(0.0, 8.0),
                    blur_radius: 32.0,
                },
                ..Default::default()
            }),
    )
    .width(Fill)
    .height(Fill)
    .center_x(Fill)
    .center_y(Fill)
    .style(|_| container::Style {
        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.7).into()),
        ..Default::default()
    })
    .into()
}

// ---- Status bar ----------------------------------------------------------

fn view_status_bar(state: &NeoShell) -> Element<'_, Message> {
    let left = text("NeoShell v0.1.0").color(theme::TEXT_MUTED).size(12);

    let right = if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            text(&tab.title).color(theme::TEXT_SECONDARY).size(12)
        } else {
            text("").size(12)
        }
    } else {
        text("No active session").color(theme::TEXT_MUTED).size(12)
    };

    let bar = row![left, horizontal_space(), right]
        .padding(Padding::from([4, 12]))
        .align_y(alignment::Vertical::Center);

    container(bar)
        .width(Fill)
        .height(24)
        .style(|_theme| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}

// ---- Connection form (modal overlay) -------------------------------------

fn view_connection_form_overlay(state: &NeoShell) -> Element<'_, Message> {
    let title_text = if state.edit_id.is_some() {
        "Edit Connection"
    } else {
        "New Connection"
    };

    let title = text(title_text).size(20).color(theme::TEXT_PRIMARY);

    let name_input = labeled_input("Name", &state.form.name, Message::FormNameChanged);
    let host_input = labeled_input("Host", &state.form.host, Message::FormHostChanged);
    let port_input = labeled_input("Port", &state.form.port, Message::FormPortChanged);
    let user_input = labeled_input(
        "Username",
        &state.form.username,
        Message::FormUsernameChanged,
    );

    let auth_row = row![
        button(
            text("Password")
                .color(if state.form.auth_type == "password" {
                    theme::TEXT_PRIMARY
                } else {
                    theme::TEXT_MUTED
                })
                .size(13)
        )
        .on_press(Message::FormAuthTypeChanged("password".into()))
        .padding(Padding::from([6, 12]))
        .style(if state.form.auth_type == "password" {
            accent_button_style
        } else {
            transparent_button_style
        }),
        button(
            text("Private Key")
                .color(if state.form.auth_type == "key" {
                    theme::TEXT_PRIMARY
                } else {
                    theme::TEXT_MUTED
                })
                .size(13)
        )
        .on_press(Message::FormAuthTypeChanged("key".into()))
        .padding(Padding::from([6, 12]))
        .style(if state.form.auth_type == "key" {
            accent_button_style
        } else {
            transparent_button_style
        }),
    ]
    .spacing(8);

    let auth_label = text("Auth Type").color(theme::TEXT_SECONDARY).size(12);

    let auth_fields: Element<'_, Message> = if state.form.auth_type == "key" {
        let key_label = text("Private Key Path").color(theme::TEXT_SECONDARY).size(12);
        let key_input = text_input("", &state.form.private_key)
            .on_input(Message::FormPrivateKeyChanged)
            .padding(8)
            .size(14);
        let browse_btn = button(text("Browse...").color(theme::ACCENT).size(12))
            .on_press(Message::BrowseKeyFile)
            .padding(Padding::from([6, 12]))
            .style(transparent_button_style);
        let key_field: Element<'_, Message> = column![
            key_label,
            row![key_input, browse_btn]
                .spacing(8)
                .align_y(alignment::Vertical::Center),
        ]
        .spacing(4)
        .into();

        column![
            key_field,
            labeled_input(
                "Passphrase (optional)",
                &state.form.passphrase,
                Message::FormPassphraseChanged
            ),
        ]
        .spacing(12)
        .into()
    } else {
        labeled_input("Password", &state.form.password, Message::FormPasswordChanged)
    };

    let group_input: Element<'_, Message> = {
        let label_text = text("Group (optional)").color(theme::TEXT_SECONDARY).size(12);
        let input = text_input("", &state.form.group)
            .on_input(Message::FormGroupChanged)
            .on_submit(Message::SaveForm)
            .padding(8)
            .size(14);
        column![label_text, input].spacing(4).into()
    };

    let error_text = if state.error_message.is_empty() {
        text("").size(1)
    } else {
        text(&state.error_message).color(theme::DANGER).size(13)
    };

    let buttons = row![
        button(text("Cancel").color(theme::TEXT_SECONDARY).size(14))
            .on_press(Message::HideForm)
            .padding(Padding::from([8, 20]))
            .style(transparent_button_style),
        button(text("Save").color(theme::TEXT_PRIMARY).size(14))
            .on_press(Message::SaveForm)
            .padding(Padding::from([8, 20]))
            .style(accent_button_style),
    ]
    .spacing(12);

    let form = column![
        title,
        name_input,
        host_input,
        port_input,
        user_input,
        auth_label,
        auth_row,
        auth_fields,
        group_input,
        error_text,
        buttons,
    ]
    .spacing(12)
    .width(440)
    .padding(24);

    let card = container(form).style(|_theme| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border {
            color: theme::BORDER,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    });

    // Center the card as a modal overlay with dark backdrop
    container(card)
        .width(Fill)
        .height(Fill)
        .center_x(Fill)
        .center_y(Fill)
        .style(|_theme| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.6).into()),
            ..Default::default()
        })
        .into()
}

/// Helper: a labeled text input field.
fn labeled_input<'a>(
    label: &'a str,
    value: &'a str,
    on_change: impl Fn(String) -> Message + 'a,
) -> Element<'a, Message> {
    let label_text = text(label).color(theme::TEXT_SECONDARY).size(12);
    let input = text_input("", value).on_input(on_change).padding(8).size(14);
    column![label_text, input].spacing(4).into()
}

// ---------------------------------------------------------------------------
// Terminal canvas program
// ---------------------------------------------------------------------------

struct TerminalView {
    grid: Arc<parking_lot::Mutex<TerminalGrid>>,
    selection_start: Option<(usize, usize)>,
    selection_end: Option<(usize, usize)>,
}

/// Persistent state for the terminal canvas. Created once by iced and reused
/// across frames. The `cache` uses interior mutability so `clear()` / `draw()`
/// work through `&self`. `last_generation` is an `AtomicU64` so we can
/// compare-and-store without `&mut`.
struct TerminalViewState {
    cache: canvas::Cache,
    last_generation: AtomicU64,
}

impl Default for TerminalViewState {
    fn default() -> Self {
        Self {
            cache: canvas::Cache::new(),
            last_generation: AtomicU64::new(0),
        }
    }
}

/// Check whether a row consists entirely of default-background blank cells
/// (space or NUL, no inverse). Such rows need no rendering at all.
#[inline]
fn is_row_empty(row: &[crate::terminal::Cell]) -> bool {
    row.iter().all(|cell| {
        (cell.c == ' ' || cell.c == '\0')
            && cell.style.bg.r == 26
            && cell.style.bg.g == 27
            && cell.style.bg.b == 46
            && !cell.style.inverse
    })
}

impl<Message> canvas::Program<Message> for TerminalView {
    type State = TerminalViewState;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let grid = self.grid.lock();
        let current_gen = grid.generation;

        // Invalidate the geometry cache when the terminal content changes.
        let last_gen = state.last_generation.load(Ordering::Relaxed);
        if current_gen != last_gen {
            state.cache.clear();
            state.last_generation.store(current_gen, Ordering::Relaxed);
        }

        let geometry = state.cache.draw(renderer, bounds.size(), |frame| {
            let font_size: f32 = 14.0;
            let cell_w = font_size * 0.6;
            let cell_h = font_size * 1.5;

            // Background fill
            frame.fill_rectangle(Point::ORIGIN, bounds.size(), theme::BG_PRIMARY);

            // Pre-allocated buffer for batching consecutive same-style ASCII
            // characters into single fill_text calls.
            let mut run_buf = String::with_capacity(256);
            let mut run_start_x: usize = 0;
            let mut run_fg = Color::TRANSPARENT;
            #[allow(unused_assignments)]
            let mut run_y: usize = 0;

            // Flush the current ASCII text run as a single fill_text call.
            let flush_run = |frame: &mut canvas::Frame,
                             buf: &mut String,
                             start_x: usize,
                             y: usize,
                             fg: Color,
                             cell_w: f32,
                             cell_h: f32,
                             font_size: f32| {
                if !buf.is_empty() {
                    frame.fill_text(canvas::Text {
                        content: buf.clone(),
                        position: Point::new(start_x as f32 * cell_w, y as f32 * cell_h),
                        color: fg,
                        size: Pixels(font_size),
                        font: Font::MONOSPACE,
                        ..canvas::Text::default()
                    });
                    buf.clear();
                }
            };

            for y in 0..grid.rows {
                let line = if grid.scroll_offset > 0 {
                    grid.get_visible_line(y)
                } else {
                    &grid.cells[y]
                };

                // Skip entirely empty rows — no iteration needed.
                if is_row_empty(line) {
                    continue;
                }

                run_buf.clear();
                run_y = y;

                let mut x = 0;
                while x < grid.cols {
                    let cell = if x < line.len() { &line[x] } else { break };

                    // Skip continuation cells (right half of wide chars)
                    if cell.wide_cont {
                        x += 1;
                        continue;
                    }

                    let char_cols: usize = if cell.wide { 2 } else { 1 };

                    // Skip empty cells with default background
                    if (cell.c == ' ' || cell.c == '\0')
                        && cell.style.bg.r == 26
                        && cell.style.bg.g == 27
                        && cell.style.bg.b == 46
                        && !cell.style.inverse
                    {
                        // Flush any pending ASCII run before the gap
                        flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
                        x += char_cols;
                        continue;
                    }

                    let is_inv = cell.style.inverse;
                    let bg = cell_color_to_iced(if is_inv { cell.style.fg } else { cell.style.bg });
                    let fg = cell_color_to_iced(if is_inv { cell.style.bg } else { cell.style.fg });

                    // Draw background if non-default (cheap GPU op, always per-cell)
                    if bg != theme::BG_PRIMARY {
                        frame.fill_rectangle(
                            Point::new(x as f32 * cell_w, y as f32 * cell_h),
                            Size::new(char_cols as f32 * cell_w, cell_h),
                            bg,
                        );
                    }

                    // Draw character
                    if cell.c != ' ' && cell.c != '\0' {
                        if cell.wide {
                            // Wide (CJK) characters: flush any ASCII run, then
                            // draw individually with the CJK font.
                            flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);

                            frame.fill_text(canvas::Text {
                                content: cell.c.to_string(),
                                position: Point::new(
                                    x as f32 * cell_w + cell_w * 0.1,
                                    y as f32 * cell_h,
                                ),
                                color: fg,
                                size: Pixels(font_size * 1.3),
                                font: CJK_FONT,
                                ..canvas::Text::default()
                            });
                        } else {
                            // Narrow ASCII: try to batch into a text run.
                            if run_buf.is_empty() {
                                // Start a new run
                                run_start_x = x;
                                run_fg = fg;
                                run_buf.push(cell.c);
                            } else if fg == run_fg {
                                // Continue the run — same foreground color
                                run_buf.push(cell.c);
                            } else {
                                // Foreground changed — flush old run, start new
                                flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
                                run_start_x = x;
                                run_fg = fg;
                                run_buf.push(cell.c);
                            }
                        }
                    } else {
                        // Space/NUL with non-default bg: flush run (bg was drawn above)
                        flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
                    }

                    x += char_cols;
                }

                // Flush any remaining run at end of row
                flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
            }

            // Draw selection highlight
            if let (Some(sel_start), Some(sel_end)) = (self.selection_start, self.selection_end) {
                let (mut sc, mut sr) = sel_start;
                let (mut ec, mut er) = sel_end;
                if sr > er || (sr == er && sc > ec) {
                    std::mem::swap(&mut sr, &mut er);
                    std::mem::swap(&mut sc, &mut ec);
                }

                let highlight_color = Color::from_rgba(0.39, 0.40, 0.95, 0.3);

                for row in sr..=er.min(grid.rows.saturating_sub(1)) {
                    let start_col = if row == sr { sc } else { 0 };
                    let end_col = if row == er { ec } else { grid.cols.saturating_sub(1) };

                    if end_col >= start_col {
                        frame.fill_rectangle(
                            Point::new(start_col as f32 * cell_w, row as f32 * cell_h),
                            Size::new((end_col - start_col + 1) as f32 * cell_w, cell_h),
                            highlight_color,
                        );
                    }
                }
            }

            // Cursor (only when not scrolled into history)
            if grid.scroll_offset == 0 && grid.cursor_visible && grid.cursor_y < grid.rows && grid.cursor_x < grid.cols {
                frame.fill_rectangle(
                    Point::new(
                        grid.cursor_x as f32 * cell_w,
                        grid.cursor_y as f32 * cell_h,
                    ),
                    Size::new(2.0, cell_h),
                    theme::ACCENT,
                );
            }

            // Scroll indicator when viewing history
            if grid.scroll_offset > 0 {
                let indicator = format!("\u{2191} {} lines", grid.scroll_offset);
                let text_width = indicator.len() as f32 * cell_w;
                let indicator_x = bounds.size().width - text_width - 8.0;

                // Background for readability
                frame.fill_rectangle(
                    Point::new(indicator_x - 4.0, 2.0),
                    Size::new(text_width + 8.0, cell_h + 2.0),
                    Color::from_rgba(0.1, 0.1, 0.2, 0.85),
                );
                frame.fill_text(canvas::Text {
                    content: indicator,
                    position: Point::new(indicator_x, 2.0),
                    color: Color::from_rgb(0.6, 0.65, 0.95),
                    size: Pixels(font_size),
                    font: Font::MONOSPACE,
                    ..canvas::Text::default()
                });
            }
        });

        vec![geometry]
    }
}

/// Convert our terminal color (r, g, b fields) to an iced Color.
fn cell_color_to_iced(c: crate::terminal::Color) -> Color {
    Color::from_rgb(c.r as f32 / 255.0, c.g as f32 / 255.0, c.b as f32 / 255.0)
}

/// Convert pixel position to terminal grid coordinates (col, row).
/// The terminal canvas starts after the sidebar (280px) and tab bar (34px).
fn pixel_to_grid(x: f32, y: f32) -> Option<(usize, usize)> {
    let term_x = x - 280.0;  // sidebar width
    let term_y = y - 34.0;   // tab bar height
    if term_x < 0.0 || term_y < 0.0 {
        return None;
    }

    let font_size = 14.0_f32;
    let cell_w = font_size * 0.6;
    let cell_h = font_size * 1.5;

    let col = (term_x / cell_w) as usize;
    let row = (term_y / cell_h) as usize;
    Some((col, row))
}

/// Extract selected text from the terminal grid given start and end positions
/// in (col, row) format.
fn extract_selection(grid: &TerminalGrid, start: (usize, usize), end: (usize, usize)) -> String {
    let (mut sc, mut sr) = start;
    let (mut ec, mut er) = end;

    // Normalize: start should be before end
    if sr > er || (sr == er && sc > ec) {
        std::mem::swap(&mut sc, &mut ec);
        std::mem::swap(&mut sr, &mut er);
    }

    let mut result = String::new();
    for row in sr..=er.min(grid.rows.saturating_sub(1)) {
        let start_col = if row == sr { sc.min(grid.cols.saturating_sub(1)) } else { 0 };
        let end_col = if row == er { ec.min(grid.cols.saturating_sub(1)) } else { grid.cols.saturating_sub(1) };

        let line = if grid.scroll_offset > 0 {
            grid.get_visible_line(row)
        } else {
            &grid.cells[row]
        };

        for col in start_col..=end_col {
            if col < line.len() && !line[col].wide_cont {
                result.push(line[col].c);
            }
        }
        // Trim trailing spaces per line
        if row < er {
            let trimmed = result.trim_end_matches(' ');
            result = trimmed.to_string();
            result.push('\n');
        }
    }
    result.trim_end().to_string()
}

// ---------------------------------------------------------------------------
// Keyboard -> terminal byte conversion
// ---------------------------------------------------------------------------

fn key_to_terminal_bytes(
    key: &keyboard::Key,
    modifiers: &keyboard::Modifiers,
    text: Option<&str>,
) -> Option<String> {
    use keyboard::key::Named;
    use keyboard::Key;

    // Ctrl+key → control characters
    if modifiers.control() {
        // Extract the base letter from various sources
        let base_char = match key {
            Key::Character(c) => c.as_str().chars().next(),
            Key::Named(Named::Space) => return Some("\x00".to_string()),
            _ => None,
        };

        if let Some(ch) = base_char {
            if ch.is_ascii_alphabetic() {
                let ctrl_byte = (ch.to_ascii_uppercase() as u8) - b'A' + 1;
                return Some(String::from(ctrl_byte as char));
            }
            // Special ctrl combos
            match ch {
                '[' | '3' => return Some("\x1b".to_string()), // ESC
                '\\' | '4' => return Some("\x1c".to_string()),
                ']' | '5' => return Some("\x1d".to_string()),
                '2' | '@' | '`' => return Some("\x00".to_string()),
                '6' | '^' | '~' => return Some("\x1e".to_string()),
                '7' | '?' => return Some("\x1f".to_string()),
                '8' => return Some("\x7f".to_string()), // DEL
                _ => {}
            }
        }

        // If text field has a control character, send it directly
        if let Some(t) = text {
            if t.len() == 1 {
                let ch = t.chars().next().unwrap();
                if (ch as u32) < 32 {
                    return Some(t.to_string());
                }
            }
        }
    }

    // Alt/Option+key → ESC prefix
    if modifiers.alt() {
        if let Some(t) = text {
            if !t.is_empty() {
                return Some(format!("\x1b{}", t));
            }
        }
        if let Key::Character(c) = key {
            return Some(format!("\x1b{}", c.as_str()));
        }
    }

    // Named/special keys
    if let Key::Named(named) = key {
        // Modified arrow keys (Shift/Ctrl/Alt + arrow)
        if modifiers.shift() || modifiers.control() || modifiers.alt() {
            let base = match named {
                Named::ArrowUp => "A", Named::ArrowDown => "B",
                Named::ArrowRight => "C", Named::ArrowLeft => "D",
                Named::Home => "H", Named::End => "F",
                _ => "",
            };
            if !base.is_empty() {
                let m = match (modifiers.shift(), modifiers.alt(), modifiers.control()) {
                    (true, false, false) => 2, (false, true, false) => 3,
                    (true, true, false) => 4, (false, false, true) => 5,
                    (true, false, true) => 6, (false, true, true) => 7,
                    (true, true, true) => 8, _ => 1,
                };
                if m > 1 { return Some(format!("\x1b[1;{}{}", m, base)); }
            }
        }

        let seq = match named {
            Named::Enter => "\r",
            Named::Backspace => "\x7f",
            Named::Tab if modifiers.shift() => return Some("\x1b[Z".to_string()),
            Named::Tab => "\t",
            Named::Escape => "\x1b",
            Named::ArrowUp => "\x1b[A",
            Named::ArrowDown => "\x1b[B",
            Named::ArrowRight => "\x1b[C",
            Named::ArrowLeft => "\x1b[D",
            Named::Home => "\x1b[H",
            Named::End => "\x1b[F",
            Named::PageUp => "\x1b[5~",
            Named::PageDown => "\x1b[6~",
            Named::Insert => "\x1b[2~",
            Named::Delete => "\x1b[3~",
            Named::F1 => "\x1bOP", Named::F2 => "\x1bOQ",
            Named::F3 => "\x1bOR", Named::F4 => "\x1bOS",
            Named::F5 => "\x1b[15~", Named::F6 => "\x1b[17~",
            Named::F7 => "\x1b[18~", Named::F8 => "\x1b[19~",
            Named::F9 => "\x1b[20~", Named::F10 => "\x1b[21~",
            Named::F11 => "\x1b[23~", Named::F12 => "\x1b[24~",
            Named::Space if modifiers.control() => return Some("\x00".to_string()),
            Named::Space => " ",
            _ => return None,
        };
        return Some(seq.to_string());
    }

    // Character input: use `text` field (contains actual typed character
    // including Shift transformations like ; → :, 9 → (, etc.)
    if let Some(t) = text {
        if !t.is_empty() && !modifiers.control() {
            return Some(t.to_string());
        }
    }

    // Fallback to Key::Character (unmodified)
    if let Key::Character(c) = key {
        Some(c.as_str().to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn chrono_now() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("{}.{:03}", d.as_secs(), d.subsec_millis())
}

fn format_bytes(bytes: u64) -> String {
    if bytes > 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes > 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes > 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Convert raw size string from `ls -la` (bytes) to human-readable KB/MB/GB.
fn humanize_file_size(size_str: &str) -> String {
    match size_str.trim().parse::<u64>() {
        Ok(bytes) => {
            if bytes >= 1_099_511_627_776 {
                format!("{:.1} TB", bytes as f64 / 1_099_511_627_776.0)
            } else if bytes >= 1_073_741_824 {
                format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
            } else if bytes >= 1_048_576 {
                format!("{:.1} MB", bytes as f64 / 1_048_576.0)
            } else if bytes >= 1024 {
                format!("{:.1} KB", bytes as f64 / 1024.0)
            } else {
                format!("{} B", bytes)
            }
        }
        Err(_) => size_str.to_string(), // Already formatted or not a number
    }
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}...", truncated)
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Style helpers
// ---------------------------------------------------------------------------

fn bg_primary_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(theme::BG_PRIMARY.into()),
        ..Default::default()
    }
}

fn accent_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Color::from_rgb(
            theme::ACCENT.r * 1.15,
            theme::ACCENT.g * 1.15,
            theme::ACCENT.b * 1.15,
        ),
        _ => theme::ACCENT,
    };
    button::Style {
        background: Some(bg.into()),
        text_color: theme::TEXT_PRIMARY,
        border: iced::Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn transparent_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Some(theme::BG_HOVER.into()),
        _ => None,
    };
    button::Style {
        background: bg,
        text_color: theme::TEXT_PRIMARY,
        border: iced::Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn sidebar_item_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Some(theme::BG_HOVER.into()),
        _ => Some(Color::TRANSPARENT.into()),
    };
    button::Style {
        background: bg,
        text_color: theme::TEXT_PRIMARY,
        border: iced::Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}
