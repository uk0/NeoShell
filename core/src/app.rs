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
use crate::i18n;
use crate::ui::theme;
use crate::updater::Updater;

/// Single source of truth for UI + terminal CJK rendering. Always points at
/// the embedded NotoSansSC-Min.ttf (family "Noto Sans CJK SC"). We used to
/// try a Latin-first platform font (Segoe UI / PingFang SC) as UI_FONT and
/// rely on glyph-level fallback, but iced/cosmic-text's Family::Name match
/// is exact — no per-glyph fallback — so CJK text on buttons and labels
/// rendered as tofu under any non-CJK-covering family. Using the embedded
/// CJK family for everything guarantees uniform rendering on every install;
/// Latin glyphs from Noto Sans CJK SC look fine in a UI context.
const CJK_FONT: Font = Font {
    family: iced::font::Family::Name("Noto Sans CJK SC"),
    weight: iced::font::Weight::Normal,
    stretch: iced::font::Stretch::Normal,
    style: iced::font::Style::Normal,
};

const UI_FONT: Font = CJK_FONT;

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

    // Auto-updater
    updater: Updater,
    last_update_check: std::time::Instant,

    // i18n locale
    locale: String,

    // UI state
    sidebar_collapsed: bool,
    show_settings: bool,
    show_about: bool,
    ui_scale: f32,
    bottom_panel_tab: BottomTab,
    bottom_panel_height: f32,
    dragging_splitter: bool,
    drag_start_y: f32,
    drag_start_height: f32,
    cursor_y: f32,
    window_height: f32,
    path_input: String,
    quick_cmd_input: String,
    last_term_size: (usize, usize),
    font_size: f32,                  // terminal font size (default 13)
    local_path: String,              // local file browser path
    local_entries: Vec<LocalFileEntry>,
    selected_local_file: Option<String>, // selected local file full path
    context_menu: Option<ContextMenu>,
    process_detail: Option<ProcessDetailInfo>,
    confirm_delete: Option<(String, String)>,  // (conn_id, conn_name) pending delete  // clicked process detail popup

    // Command history (per session + global)
    cmd_history: Vec<CmdRecord>,
    show_history: bool,
    history_filter: String,

    // Proxy management
    proxy_store: crate::proxy::ProxyStore,
    proxies: Vec<crate::proxy::ProxyConfig>,
    show_proxy_manager: bool,
    show_proxy_form: bool,
    proxy_form: ProxyFormData,
    proxy_edit_id: Option<String>,
    proxy_test_results: HashMap<String, crate::proxy::ProxyTestResult>,
    // Connection form test result & list test results
    form_test_result: Option<crate::ssh::ConnectionTestResult>,
    form_testing: bool,
    conn_test_results: HashMap<String, crate::ssh::ConnectionTestResult>,
    show_shortcuts_help: bool,
    // Error dialog (non-form failures — connection errors, etc.)
    show_error_dialog: bool,
    // Log viewer
    show_log_viewer: bool,
    log_viewer_content: String,
    // Tunnel management
    tunnel_store: crate::tunnel::TunnelStore,
    tunnel_manager: Arc<crate::tunnel::TunnelManager>,
    tunnels: Vec<crate::tunnel::TunnelConfig>,
    show_tunnel_manager: bool,
    show_tunnel_form: bool,
    tunnel_form: TunnelFormData,
    tunnel_edit_id: Option<String>,
    // Theme customization — load from theme.json on startup
    theme_cfg: crate::ui::theme_config::ThemeConfig,
    /// Zone currently expanded for RGB editing in Settings → Appearance.
    theme_editing_zone: Option<crate::ui::theme_config::ThemeZone>,
    // ---- v0.6.21 additions ----
    /// Broadcast dialog: send one command to N connected sessions.
    show_broadcast_dialog: bool,
    broadcast_text: String,
    broadcast_selected: HashSet<String>,
    /// Snippets panel: named command/script presets the user can reuse.
    show_snippets_panel: bool,
    snippets: Vec<Snippet>,
    snippet_edit_id: Option<String>,
    snippet_form_name: String,
    snippet_form_body: String,
    // ---- v0.6.22: Cmd+F terminal search ----
    term_search_active: bool,
    term_search_query: String,
    term_search_case_insensitive: bool,
    term_search_matches: Vec<crate::terminal::SearchMatch>,
    term_search_current: usize,
    /// When true, hide the bottom panel (Monitor/Files/QuickCmd) entirely so
    /// the terminal takes the full height. Toggled by the chevron button in
    /// the splitter.
    bottom_panel_collapsed: bool,
}

/// A reusable command snippet (named command/script) persisted in snippets.json.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Snippet {
    pub id: String,
    pub name: String,
    pub body: String,
}

fn snippets_path() -> std::path::PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("neoshell");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("snippets.json")
}

fn load_snippets() -> Vec<Snippet> {
    std::fs::read_to_string(snippets_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_snippets(list: &[Snippet]) {
    if let Ok(json) = serde_json::to_string_pretty(list) {
        let _ = std::fs::write(snippets_path(), json);
    }
}

/// Stable widget id for the Cmd+F search input so we can focus it on open.
const TERM_SEARCH_INPUT_ID: &str = "term_search";

/// Re-run search against the focused terminal's scrollback + grid.
fn rerun_terminal_search(state: &mut NeoShell) {
    state.term_search_matches.clear();
    state.term_search_current = 0;
    if state.term_search_query.is_empty() {
        return;
    }
    if let Some(term) = state.focused_terminal().cloned() {
        let grid = term.lock();
        state.term_search_matches =
            grid.search(&state.term_search_query, state.term_search_case_insensitive);
    }
}

/// Adjust the terminal's scroll_offset so the current match sits roughly in
/// the middle of the viewport. No-op if there are no matches.
fn scroll_to_current_match(state: &mut NeoShell) {
    let m_opt = state
        .term_search_matches
        .get(state.term_search_current)
        .copied();
    let term_opt = state.focused_terminal().cloned();
    if let (Some(term), Some(m)) = (term_opt, m_opt) {
        let mut grid = term.lock();
        let sb_len = grid.scrollback.len();
        let rows = grid.rows;
        if m.abs_line >= sb_len {
            grid.scroll_offset = 0;
        } else {
            let target = (sb_len as isize - m.abs_line as isize + (rows / 2) as isize).max(0) as usize;
            grid.scroll_offset = target.min(sb_len);
        }
        grid.generation = grid.generation.wrapping_add(1);
    }
}

#[derive(Default, Clone)]
struct TunnelFormData {
    name: String,
    ssh_host: String,
    ssh_port: String,
    username: String,
    auth_type: String,  // "password" | "key"
    password: String,
    private_key: String,
    passphrase: String,
    /// Multi-line forwards, one per line, in "LOCAL:REMOTE_HOST:REMOTE_PORT"
    /// or "REMOTE_HOST:REMOTE_PORT->LOCAL" format.
    forwards_text: String,
    auto_start: bool,
}

#[derive(Debug, Clone)]
struct CmdRecord {
    cmd: String,
    session_title: String,
    timestamp: std::time::Instant,
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
    proxy_id: String,
}

#[derive(Debug, Clone)]
struct ProcessDetailInfo {
    pid: u32,
    fields: Vec<(String, String)>,
    children: Vec<String>,      // child process lines
    threads: Vec<String>,       // thread IDs
    net_conns: Vec<String>,     // network connections (ss output)
    listen_ports: Vec<String>,  // listening ports
    open_fds: Vec<String>,      // file descriptors
}

#[derive(Debug, Clone)]
struct LocalFileEntry {
    name: String,
    is_dir: bool,
    size: u64,
    path: String,
}

#[derive(Debug, Clone)]
struct ContextMenu {
    conn_id: String,
    conn_name: String,
    x: f32,
    y: f32,
}

#[derive(Debug, Clone, PartialEq)]
enum BottomTab {
    Monitor,
    Files,
    QuickCmd,
}

#[derive(Default, Clone)]
struct ProxyFormData {
    name: String,
    proxy_type: String, // "socks5h" | "http" | "bastion"
    host: String,
    port: String,
    username: String,
    password: String,
    // SSH bastion fields
    auth_type: String,   // "password" | "key"
    private_key: String, // file path
    passphrase: String,
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

    // Form focus (Tab cycling)
    FocusNext,

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
    TestFormConnection,
    TestFormConnectionDone(crate::ssh::ConnectionTestResult),
    CloneConnection(String),
    ToggleShortcutsHelp,
    TestConnectionInList(String),
    TestConnectionInListDone(String, crate::ssh::ConnectionTestResult),
    DismissErrorDialog,
    ShowLogViewer,
    HideLogViewer,
    RefreshLogViewer,
    OpenLogFolder,
    // Window lifecycle — close button minimizes to taskbar/dock instead of exiting
    WindowCloseRequested(iced::window::Id),
    QuitApp,
    // Tunnel management
    ShowTunnelManager,
    HideTunnelManager,
    ShowTunnelForm(Option<String>),
    HideTunnelForm,
    TunnelFormNameChanged(String),
    TunnelFormHostChanged(String),
    TunnelFormPortChanged(String),
    TunnelFormUserChanged(String),
    TunnelFormAuthTypeChanged(String),
    TunnelFormPasswordChanged(String),
    TunnelFormKeyChanged(String),
    TunnelFormPassphraseChanged(String),
    TunnelFormForwardsChanged(String),
    TunnelFormAutoStartChanged(bool),
    TunnelFormBrowseKey,
    SaveTunnel,
    DeleteTunnel(String),
    StartTunnel(String),
    StopTunnel(String),
    TunnelStateTick,
    // Theme editor
    ThemeSelectZone(crate::ui::theme_config::ThemeZone),
    ThemeCloseZone,
    ThemeRChanged(u8),
    ThemeGChanged(u8),
    ThemeBChanged(u8),
    ThemeHexChanged(String),
    ThemeTerminalFontSize(f32),
    ThemeUiFontSize(f32),
    ThemeReset,

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
    ImportAllSshConfigs,
    // Command broadcast — send a one-off command to many sessions at once
    ShowBroadcastDialog,
    HideBroadcastDialog,
    BroadcastTextChanged(String),
    BroadcastToggleSession(String),
    BroadcastSendNow,
    // Snippets
    ShowSnippetsPanel,
    HideSnippetsPanel,
    SnippetSend(String),
    SnippetEdit(Option<String>),
    SnippetFormNameChanged(String),
    SnippetFormBodyChanged(String),
    SnippetSave,
    SnippetDelete(String),

    // rz/sz ZMODEM
    RzDetected(String),      // session_id — rz wants to receive a file
    SzDetected(String),      // session_id — sz wants to send a file
    RzUploadDone(String),    // session_id — upload finished

    // Bottom panel collapse / expand
    ToggleBottomPanel,

    // Terminal search (Cmd+F)
    ToggleTerminalSearch,
    TerminalSearchChanged(String),
    TerminalSearchNext,
    TerminalSearchPrev,
    TerminalSearchClose,
    ToggleTerminalSearchCase,

    // Terminal scrollback & selection
    TerminalScrollUp(usize),
    TerminalScrollDown(usize),
    TerminalMouseDown(f32, f32),  // (x, y) cursor position
    TerminalMouseUp,
    TerminalMouseMove(f32, f32),
    CopySelection,

    // Update
    CheckForUpdate,
    DownloadUpdate,
    RestartForUpdate,
    DismissUpdate,

    // Language & UI
    ToggleLanguage,
    ToggleSidebar,
    ShowSettings,
    HideSettings,
    ShowAbout,
    HideAbout,
    SetUiScale(f32),

    // Bottom panel
    SwitchBottomTab(BottomTab),
    PathInputChanged(String),
    PathInputSubmit,
    ShowContextMenu(String, String, f32, f32),
    HideContextMenu,
    InspectProcess(u32),
    ProcessDetailReceived(ProcessDetailInfo),
    HideProcessDetail,
    ConfirmDelete(String, String),  // (conn_id, conn_name)
    CancelDelete,
    ExecuteDelete,

    // Command history
    ShowHistory,
    HideHistory,
    HistoryFilterChanged(String),
    ReplayCommand(String),
    ClearHistory,
    QuickCmdInputChanged(String),
    SendQuickCmd,
    SetFontSize(f32),
    ResizeBottomPanel(f32),
    SplitterDragStart(f32),       // mouse y position
    SplitterDragMove(f32),        // mouse y position
    SplitterDragEnd,
    // Local file browser
    LocalPathChanged(String),
    LocalPathSubmit,
    LocalFileClicked(String),     // full path — if dir, navigate; if file, select
    SelectLocalFile(String),
    UploadLocalFile,
    RefreshLocalFiles,
    RefreshRemoteFiles,

    // Proxy management
    ShowProxyManager,
    HideProxyManager,
    ShowProxyForm(Option<String>), // None=new, Some(id)=edit
    HideProxyForm,
    ProxyFormNameChanged(String),
    ProxyFormTypeChanged(String),
    ProxyFormHostChanged(String),
    ProxyFormPortChanged(String),
    ProxyFormUsernameChanged(String),
    ProxyFormPasswordChanged(String),
    ProxyFormAuthTypeChanged(String),
    ProxyFormPrivateKeyChanged(String),
    ProxyFormPassphraseChanged(String),
    ProxyFormBrowsePrivateKey,
    SaveProxy,
    DeleteProxy(String),
    TestProxy(String),
    ProxyTestDone(String, crate::proxy::ProxyTestResult),
    FormProxyChanged(String), // connection form: select proxy

    // Misc
    Tick,
    None,
    Error(String),
}

// ---------------------------------------------------------------------------
// Default (initial state before run_with)
// ---------------------------------------------------------------------------

/// Load persisted locale preference or detect from system.
fn load_locale() -> String {
    if let Some(config_dir) = dirs::config_dir() {
        let lang_file = config_dir.join("neoshell").join("lang");
        if let Ok(lang) = std::fs::read_to_string(&lang_file) {
            let lang = lang.trim().to_string();
            if !lang.is_empty() {
                return lang;
            }
        }
    }
    // Auto-detect: check LANG / LC_ALL env
    for var in &["LC_ALL", "LANG", "LANGUAGE"] {
        if let Ok(val) = std::env::var(var) {
            let lower = val.to_lowercase();
            if lower.starts_with("zh") {
                return "zh-CN".to_string();
            }
        }
    }
    "en".to_string()
}

/// Load persisted UI scale factor.
fn load_ui_scale() -> f32 {
    if let Some(config_dir) = dirs::config_dir() {
        let scale_file = config_dir.join("neoshell").join("scale");
        if let Ok(s) = std::fs::read_to_string(&scale_file) {
            if let Ok(v) = s.trim().parse::<f32>() {
                if (0.5..=3.0).contains(&v) {
                    return v;
                }
            }
        }
    }
    1.0
}

/// Persist UI scale factor.
fn save_ui_scale(scale: f32) {
    if let Some(config_dir) = dirs::config_dir() {
        let neo_dir = config_dir.join("neoshell");
        let _ = std::fs::create_dir_all(&neo_dir);
        let _ = std::fs::write(neo_dir.join("scale"), format!("{:.2}", scale));
    }
}

/// Load persisted font size.
fn load_font_size() -> f32 {
    if let Some(d) = dirs::config_dir() {
        if let Ok(s) = std::fs::read_to_string(d.join("neoshell").join("fontsize")) {
            if let Ok(v) = s.trim().parse::<f32>() {
                if (8.0..=30.0).contains(&v) { return v; }
            }
        }
    }
    13.0
}

fn save_font_size(size: f32) {
    if let Some(d) = dirs::config_dir() {
        let dir = d.join("neoshell");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("fontsize"), format!("{:.1}", size));
    }
}

/// List local directory entries.
fn list_local_dir(path: &str) -> Vec<LocalFileEntry> {
    let mut entries = Vec::new();
    let dir = std::path::Path::new(path);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            entries.push(LocalFileEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                is_dir,
                size,
                path: entry.path().to_string_lossy().to_string(),
            });
        }
    }
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    entries
}

/// Persist locale choice to config dir.
fn save_locale(locale: &str) {
    if let Some(config_dir) = dirs::config_dir() {
        let neo_dir = config_dir.join("neoshell");
        let _ = std::fs::create_dir_all(&neo_dir);
        let _ = std::fs::write(neo_dir.join("lang"), locale);
    }
}

impl Default for NeoShell {
    fn default() -> Self {
        let store = Arc::new(ConnectionStore::new());
        let (ssh_manager, ssh_event_rx) = SshManager::new();

        let screen = if store.vault_exists() {
            Screen::Locked
        } else {
            Screen::Setup
        };

        let locale = load_locale();
        i18n::set_locale(&locale);

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
            updater: Updater::new(),
            last_update_check: std::time::Instant::now(),
            locale,
            sidebar_collapsed: false,
            show_settings: false,
            show_about: false,
            ui_scale: load_ui_scale(),
            bottom_panel_tab: BottomTab::Monitor,
            bottom_panel_height: 220.0,
            dragging_splitter: false,
            drag_start_y: 0.0,
            drag_start_height: 220.0,
            cursor_y: 0.0,
            window_height: 800.0,
            path_input: String::new(),
            quick_cmd_input: String::new(),
            last_term_size: (0, 0),
            font_size: load_font_size(),
            local_path: dirs::home_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "/".into()),
            local_entries: Vec::new(),
            selected_local_file: None,
            context_menu: None,
            process_detail: None,
            confirm_delete: None,
            cmd_history: Vec::new(),
            show_history: false,
            history_filter: String::new(),
            proxy_store: crate::proxy::ProxyStore::new(),
            proxies: {
                let ps = crate::proxy::ProxyStore::new();
                ps.load()
            },
            show_proxy_manager: false,
            show_proxy_form: false,
            proxy_form: ProxyFormData::default(),
            proxy_edit_id: None,
            proxy_test_results: HashMap::new(),
            form_test_result: None,
            form_testing: false,
            conn_test_results: HashMap::new(),
            show_shortcuts_help: false,
            show_error_dialog: false,
            show_log_viewer: false,
            log_viewer_content: String::new(),
            tunnel_store: crate::tunnel::TunnelStore::new(),
            tunnel_manager: {
                // Auto-start any tunnel with auto_start = true on app launch.
                let mgr = Arc::new(crate::tunnel::TunnelManager::new());
                let ts = crate::tunnel::TunnelStore::new();
                for t in ts.load() {
                    if t.auto_start {
                        log::info!("auto-starting tunnel '{}'", t.name);
                        if let Err(e) = mgr.start(t.clone()) {
                            log::warn!("auto-start failed for '{}': {}", t.name, e);
                        }
                    }
                }
                mgr
            },
            tunnels: {
                let ts = crate::tunnel::TunnelStore::new();
                ts.load()
            },
            show_tunnel_manager: false,
            show_tunnel_form: false,
            tunnel_form: TunnelFormData::default(),
            tunnel_edit_id: None,
            theme_cfg: crate::ui::theme_config::ThemeConfig::load(),
            theme_editing_zone: None,
            show_broadcast_dialog: false,
            broadcast_text: String::new(),
            broadcast_selected: HashSet::new(),
            show_snippets_panel: false,
            snippets: load_snippets(),
            snippet_edit_id: None,
            snippet_form_name: String::new(),
            snippet_form_body: String::new(),
            term_search_active: false,
            term_search_query: String::new(),
            term_search_case_insensitive: true,
            term_search_matches: Vec::new(),
            term_search_current: 0,
            bottom_panel_collapsed: false,
        }
    }
}

impl NeoShell {
    /// UI font-size scale factor. Every size(N) in a themed view should multiply
    /// by this so the whole interface resizes from Settings → Appearance.
    #[inline]
    fn ui_scale(&self) -> f32 { self.theme_cfg.ui_font_size / 12.0 }
    #[inline] fn c_primary(&self)   -> Color { self.theme_cfg.text_primary.to_color() }
    #[inline] fn c_accent(&self)    -> Color { self.theme_cfg.accent.to_color() }
    #[inline] fn c_success(&self)   -> Color { self.theme_cfg.success.to_color() }
    #[inline] fn c_danger(&self)    -> Color { self.theme_cfg.danger.to_color() }

    /// Returns true when any modal / side panel is open. Used by the global
    /// event subscription to suppress terminal scroll + mouse-down events
    /// that would otherwise pass through to the terminal canvas beneath.
    fn any_overlay_open(&self) -> bool {
        self.show_settings
            || self.show_about
            || self.show_history
            || self.show_proxy_manager
            || self.show_tunnel_manager
            || self.show_connect_dialog
            || self.show_form
            || self.show_shortcuts_help
            || self.show_error_dialog
            || self.show_log_viewer
            || self.show_broadcast_dialog
            || self.show_snippets_panel
            || self.process_detail.is_some()
            || self.selected_interface.is_some()
            || self.editor_file_path.is_some()
    }

    /// Terminal grid of the currently focused pane. For v0.6.22 there is still
    /// exactly one terminal per tab; v0.6.24 will route this through the pane
    /// tree without touching any of the callers.
    #[inline]
    fn focused_terminal(&self) -> Option<&Arc<parking_lot::Mutex<TerminalGrid>>> {
        self.active_tab
            .and_then(|i| self.tabs.get(i))
            .map(|t| &t.terminal)
    }

    /// Terminal grid that belongs to the given SSH `session_id`, regardless of
    /// which tab it lives in. When split panes land, this will scan extra panes
    /// as well — keeping the lookup behind a single helper means the ZMODEM /
    /// data-event / close-event paths don't have to be rewritten.
    #[inline]
    fn find_terminal_for_session(
        &self,
        session_id: &str,
    ) -> Option<&Arc<parking_lot::Mutex<TerminalGrid>>> {
        self.tabs
            .iter()
            .find(|t| t.session_id == session_id)
            .map(|t| &t.terminal)
    }
}

// ---------------------------------------------------------------------------
// Application entry point
// ---------------------------------------------------------------------------

pub fn run() -> iced::Result {
    let initial_scale = load_ui_scale() as f64;

    // Load window icon from embedded PNG
    let window_icon = iced::window::icon::from_file_data(
        include_bytes!("../../assets/icon_256.png"),
        Some(image::ImageFormat::Png),
    ).ok();

    let win_settings = iced::window::Settings {
        size: Size::new(1200.0, 800.0),
        icon: window_icon,
        ..Default::default()
    };

    // Embedded glyph-fallback fonts — cosmic-text uses them per-codepoint when
    // the primary font doesn't cover a glyph. Bundling guarantees correct
    // rendering on Windows installs that don't ship the expected system fonts
    // (Win11 in particular — some installs have malformed mstmc.ttf that
    // breaks fontdb enumeration, leaving CJK text as tofu).
    const NERD_FONT: &[u8] = include_bytes!(
        "../../assets/fonts/SymbolsNerdFontMono-Regular.ttf"
    );
    const CJK_EMBED: &[u8] = include_bytes!(
        "../../assets/fonts/NotoSansSC-Min.ttf"
    );

    iced::application("NeoShell", update, view)
        .subscription(subscription)
        .theme(|_state| Theme::Dark)
        .window(win_settings)
        .scale_factor(move |_state| initial_scale)
        .antialiasing(true)
        .decorations(true)
        .font(NERD_FONT)
        .font(CJK_EMBED)
        .default_font(UI_FONT)
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
                state.error_message = i18n::t("setup.err_too_short").to_string();
                return Task::none();
            }
            if state.password_input != state.confirm_input {
                state.error_message = i18n::t("setup.err_mismatch").to_string();
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
                    Ok(false) => Message::Error(i18n::t("unlock.err_invalid").to_string()),
                    Err(e) => Message::Error(e),
                },
            )
        }
        Message::VaultUnlocked => {
            state.screen = Screen::Main;
            state.password_input.clear();
            state.error_message.clear();
            Task::batch(vec![
                Task::done(Message::LoadConnections),
                Task::done(Message::CheckForUpdate),
            ])
        }

        // ---- connections -----------------------------------------------------
        Message::FocusNext => {
            return iced::widget::focus_next();
        }
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
            let terminal = Arc::new(parking_lot::Mutex::new(TerminalGrid::new(120, 40)));
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
            let conn_id_for_log = id.clone();
            Task::perform(
                async move {
                    log::info!("connect_to: attempting connection to id={}", conn_id_for_log);
                    // Run blocking SSH connect on dedicated thread
                    tokio::task::spawn_blocking(move || {
                        let config = store.get_connection(&id)?;
                        log::info!("connect_to: resolved {}@{}:{} (auth={}, proxy={:?})",
                            config.username, config.host, config.port,
                            config.auth_type, config.proxy_id);
                        let session_id = ssh.connect_config(&config)?;
                        let title = format!("{}@{}:{}", config.username, config.host, config.port);
                        Ok((tab_id2, session_id, title, id))
                    }).await.map_err(|e| format!("Task: {}", e))?
                },
                |result: Result<(String, String, String, String), String>| match result {
                    Ok((tab_id, session_id, title, conn_id)) => {
                        Message::SshConnected(tab_id, session_id, title, conn_id)
                    }
                    Err(e) => Message::Error(e),
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
            // Find name for confirm dialog
            let name = state.connections.iter()
                .find(|c| c.id == id)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| id.clone());
            state.confirm_delete = Some((id, name));
            Task::none()
        }
        Message::ConfirmDelete(id, name) => {
            state.confirm_delete = Some((id, name));
            Task::none()
        }
        Message::CancelDelete => {
            state.confirm_delete = None;
            Task::none()
        }
        Message::ExecuteDelete => {
            if let Some((id, _)) = state.confirm_delete.take() {
                state.conn_test_results.remove(&id);
                let store = state.store.clone();
                return Task::perform(
                    async move {
                        store.delete_connection(&id)?;
                        store.get_connections()
                    },
                    |result| match result {
                        Ok(conns) => Message::ConnectionsLoaded(conns),
                        Err(e) => Message::Error(e),
                    },
                );
            }
            Task::none()
        }

        // ---- form ------------------------------------------------------------
        Message::ShowForm(maybe_id) => {
            state.show_form = true;
            state.show_connect_dialog = false;
            state.form_test_result = None;
            state.form_testing = false;
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
                        proxy_id: info.proxy_id.clone().unwrap_or_default(),
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
            state.form_test_result = None;
            state.form_testing = false;
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
            let is_edit = state.edit_id.is_some();
            let edit_id = state.edit_id.clone();

            // When editing, preserve existing secrets if form fields are empty
            // (ConnectionInfo doesn't expose secrets, so form shows them as empty)
            let (preserved_pw, preserved_key, preserved_pass) = if let Some(ref id) = edit_id {
                match state.store.get_connection(id) {
                    Ok(existing) => (
                        existing.password.clone(),
                        existing.private_key.clone(),
                        existing.passphrase.clone(),
                    ),
                    Err(_) => (None, None, None),
                }
            } else {
                (None, None, None)
            };

            let password = if !state.form.password.is_empty() {
                Some(state.form.password.clone())
            } else if is_edit {
                preserved_pw // keep existing password
            } else {
                None
            };

            let private_key = if !state.form.private_key.is_empty() {
                Some(state.form.private_key.clone())
            } else if is_edit {
                preserved_key
            } else {
                None
            };

            let passphrase = if !state.form.passphrase.is_empty() {
                Some(state.form.passphrase.clone())
            } else if is_edit {
                preserved_pass
            } else {
                None
            };

            let config = ConnectionConfig {
                id: edit_id.clone().unwrap_or_default(),
                name: state.form.name.clone(),
                host: state.form.host.clone(),
                port,
                username: state.form.username.clone(),
                auth_type: state.form.auth_type.clone(),
                password,
                private_key,
                passphrase,
                group: state.form.group.clone(),
                color: String::new(),
                proxy_id: if state.form.proxy_id.is_empty() {
                    None
                } else {
                    Some(state.form.proxy_id.clone())
                },
            };

            let store = state.store.clone();

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

        Message::TestFormConnection => {
            // Gather form values + preserved secrets (same logic as SaveForm)
            let port: u16 = state.form.port.parse().unwrap_or(22);
            let is_edit = state.edit_id.is_some();
            let (preserved_pw, preserved_key, preserved_pass) = if let Some(ref id) = state.edit_id {
                match state.store.get_connection(id) {
                    Ok(existing) => (existing.password.clone(), existing.private_key.clone(), existing.passphrase.clone()),
                    Err(_) => (None, None, None),
                }
            } else { (None, None, None) };

            let password = if !state.form.password.is_empty() { Some(state.form.password.clone()) }
                else if is_edit { preserved_pw } else { None };
            let private_key = if !state.form.private_key.is_empty() { Some(state.form.private_key.clone()) }
                else if is_edit { preserved_key } else { None };
            let passphrase = if !state.form.passphrase.is_empty() { Some(state.form.passphrase.clone()) }
                else if is_edit { preserved_pass } else { None };

            let host = state.form.host.clone();
            let username = state.form.username.clone();
            let auth_type = state.form.auth_type.clone();
            let proxy_id = if state.form.proxy_id.is_empty() { None } else { Some(state.form.proxy_id.clone()) };

            state.form_testing = true;
            state.form_test_result = None;

            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || {
                        crate::ssh::SshManager::test_connection(
                            &host, port, &username, &auth_type,
                            password.as_deref(), private_key.as_deref(),
                            passphrase.as_deref(), proxy_id.as_deref(),
                        )
                    }).await.unwrap_or(crate::ssh::ConnectionTestResult {
                        ok: false, latency_ms: 0, stage: "internal".into(),
                        error: Some("test task failed".into()),
                    })
                },
                Message::TestFormConnectionDone,
            )
        }
        Message::TestFormConnectionDone(result) => {
            state.form_testing = false;
            state.form_test_result = Some(result);
            Task::none()
        }
        Message::CloneConnection(id) => {
            if let Ok(src) = state.store.get_connection(&id) {
                let mut clone = src.clone();
                clone.id = uuid::Uuid::new_v4().to_string();
                clone.name = format!("{} (Copy)", src.name);
                let store = state.store.clone();
                return Task::perform(
                    async move {
                        store.save_connection(clone)?;
                        store.get_connections()
                    },
                    |r| match r {
                        Ok(conns) => Message::ConnectionsLoaded(conns),
                        Err(e) => Message::Error(e),
                    },
                );
            }
            Task::none()
        }
        Message::ToggleShortcutsHelp => {
            state.show_shortcuts_help = !state.show_shortcuts_help;
            Task::none()
        }
        Message::TestConnectionInList(id) => {
            if let Ok(cfg) = state.store.get_connection(&id) {
                let host = cfg.host.clone();
                let port = cfg.port;
                let username = cfg.username.clone();
                let auth_type = cfg.auth_type.clone();
                let password = cfg.password.clone();
                let private_key = cfg.private_key.clone();
                let passphrase = cfg.passphrase.clone();
                let proxy_id = cfg.proxy_id.clone();
                let id_clone = id.clone();
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            crate::ssh::SshManager::test_connection(
                                &host, port, &username, &auth_type,
                                password.as_deref(), private_key.as_deref(),
                                passphrase.as_deref(), proxy_id.as_deref(),
                            )
                        }).await.unwrap_or(crate::ssh::ConnectionTestResult {
                            ok: false, latency_ms: 0, stage: "internal".into(),
                            error: Some("test task failed".into()),
                        })
                    },
                    move |r| Message::TestConnectionInListDone(id_clone.clone(), r),
                );
            }
            Task::none()
        }
        Message::TestConnectionInListDone(id, result) => {
            state.conn_test_results.insert(id, result);
            Task::none()
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
                // Enter pressed — record to history
                let cmd = buf.trim().to_string();
                if !cmd.is_empty() {
                    // Find session title
                    let title = state.tabs.iter()
                        .find(|t| t.session_id == session_id)
                        .map(|t| t.title.clone())
                        .unwrap_or_default();
                    state.cmd_history.push(CmdRecord {
                        cmd: cmd.clone(),
                        session_title: title,
                        timestamp: std::time::Instant::now(),
                    });
                    // Cap at 500 entries
                    if state.cmd_history.len() > 500 {
                        state.cmd_history.drain(..state.cmd_history.len() - 500);
                    }
                }
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

            // Check if terminal grid was resized and notify remote PTY
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    if !tab.session_id.is_empty() {
                        let grid = tab.terminal.lock();
                        let cur = (grid.cols, grid.rows);
                        if cur != state.last_term_size && cur.0 > 0 && cur.1 > 0 {
                            state.last_term_size = cur;
                            let session_id = tab.session_id.clone();
                            let ssh = state.ssh_manager.clone();
                            let cols = cur.0 as u32;
                            let rows = cur.1 as u32;
                            drop(grid);
                            return Task::perform(
                                async move {
                                    tokio::task::spawn_blocking(move || {
                                        ssh.resize(&session_id, cols, rows)
                                    }).await.ok();
                                    ()
                                },
                                |_| Message::None,
                            );
                        }
                    }
                }
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

            // Cmd/Ctrl+key shortcuts. Note the C/V special case below:
            //   macOS:        ⌘+C / ⌘+V copy & paste (no shift).
            //   Win / Linux:  Ctrl+Shift+C / Ctrl+Shift+V copy & paste,
            //                 so plain Ctrl+C still reaches the terminal as
            //                 the SIGINT byte 0x03 and Ctrl+V as a literal
            //                 0x16 (quoted-insert). This matches Windows
            //                 Terminal / Tabby / Xshell / mintty.
            if modifiers.command() {
                let clipboard_mod = if cfg!(target_os = "macos") {
                    !modifiers.shift()
                } else {
                    modifiers.shift()
                };
                if let keyboard::Key::Character(c) = &key {
                    match c.as_str() {
                        "v" | "V" if clipboard_mod => return Task::done(Message::PasteClipboard),
                        "c" | "C" if clipboard_mod => {
                            if state.selection_start.is_some() && state.selection_end.is_some() {
                                return Task::done(Message::CopySelection);
                            }
                            return Task::none();
                        }
                        // Plain Ctrl+C / Ctrl+V on non-macOS: fall through
                        // to the terminal byte handler (SIGINT / literal).
                        "c" | "C" | "v" | "V" if !cfg!(target_os = "macos") => {}
                        "f" | "F" => return Task::done(Message::ToggleTerminalSearch),
                        "j" | "J" => return Task::done(Message::ToggleBottomPanel),
                        "t" | "T" => return Task::done(Message::ShowConnectDialog),
                        "w" | "W" => {
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
                        "h" | "H" => {
                            state.show_history = !state.show_history;
                            state.history_filter.clear();
                            return Task::none();
                        }
                        "/" | "?" => {
                            state.show_shortcuts_help = !state.show_shortcuts_help;
                            return Task::none();
                        }
                        // Cmd/Ctrl + Shift + Q → true quit (bypasses close-to-taskbar)
                        "q" | "Q" if modifiers.shift() => {
                            return Task::done(Message::QuitApp);
                        }
                        "+" | "=" | "-" | "0" => return Task::none(), // Block zoom
                        _ => {}
                    }
                }
                // macOS: any unmatched ⌘+key is swallowed (GUI convention).
                // Win/Linux: let unmatched Ctrl+key fall through to the
                // terminal byte handler so Ctrl+C/V (and Ctrl+A, Ctrl+R,
                // Ctrl+L, etc.) reach the remote shell.
                if cfg!(target_os = "macos") {
                    return Task::none();
                }
            }

            // F1 toggles shortcut help (no modifier required)
            if let keyboard::Key::Named(keyboard::key::Named::F1) = &key {
                state.show_shortcuts_help = !state.show_shortcuts_help;
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

            // ESC closes open dialogs
            if let keyboard::Key::Named(keyboard::key::Named::Escape) = &key {
                if state.term_search_active {
                    return Task::done(Message::TerminalSearchClose);
                }
                if state.show_error_dialog {
                    state.show_error_dialog = false;
                    state.error_message.clear();
                    return Task::none();
                }
                if state.show_log_viewer {
                    state.show_log_viewer = false;
                    state.log_viewer_content.clear();
                    return Task::none();
                }
                if state.show_shortcuts_help {
                    state.show_shortcuts_help = false;
                    return Task::none();
                }
                if state.process_detail.is_some() {
                    state.process_detail = None;
                    return Task::none();
                }
                if state.show_history {
                    state.show_history = false;
                    return Task::none();
                }
                if state.show_settings {
                    state.show_settings = false;
                    return Task::none();
                }
                if state.show_about {
                    state.show_about = false;
                    return Task::none();
                }
                if state.show_connect_dialog {
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
            // Right-click paste is terminal-only. If an overlay is open, a
            // right-click on the overlay backdrop shouldn't send paste chars
            // into the hidden terminal.
            if state.any_overlay_open() { return Task::none(); }
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
            state.path_input = path.clone();
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
                            .set_title(i18n::t("filedialog.upload"))
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
                        .set_title(i18n::t("filedialog.save"))
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
                        .set_title(i18n::t("filedialog.select_key"))
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

        Message::ImportAllSshConfigs => {
            // Bulk-import every non-wildcard host from ~/.ssh/config, skipping
            // entries that already match an existing connection (by user@host:port).
            let configs = crate::sshconfig::parse_ssh_config();
            let existing_keys: HashSet<String> = state.connections.iter()
                .map(|c| format!("{}@{}:{}", c.username, c.host, c.port))
                .collect();
            let store = state.store.clone();
            let mut added = 0usize;
            for cfg in configs {
                let host = if cfg.hostname.is_empty() { cfg.alias.clone() } else { cfg.hostname.clone() };
                if host.is_empty() { continue; }
                let key = format!("{}@{}:{}", cfg.user, host, cfg.port);
                if existing_keys.contains(&key) { continue; }
                let conn = ConnectionConfig {
                    id: String::new(),
                    name: cfg.alias.clone(),
                    host,
                    port: cfg.port,
                    username: cfg.user.clone(),
                    auth_type: if cfg.identity_file.is_empty() { "password".into() } else { "key".into() },
                    password: None,
                    private_key: if cfg.identity_file.is_empty() { None } else { Some(cfg.identity_file.clone()) },
                    passphrase: None,
                    group: "SSH Config".into(),
                    color: String::new(),
                    proxy_id: None,
                };
                if store.save_connection(conn).is_ok() {
                    added += 1;
                }
            }
            log::info!("Imported {} entries from ~/.ssh/config", added);
            state.show_connect_dialog = false;
            return Task::perform(
                async move { store.get_connections() },
                |r| match r {
                    Ok(conns) => Message::ConnectionsLoaded(conns),
                    Err(e) => Message::Error(e),
                },
            );
        }

        // ---- broadcast -------------------------------------------------------
        Message::ShowBroadcastDialog => {
            state.show_broadcast_dialog = !state.show_broadcast_dialog;
            if state.show_broadcast_dialog {
                // Pre-select all currently-active sessions
                state.broadcast_selected.clear();
                for tab in &state.tabs {
                    if !tab.session_id.is_empty() {
                        state.broadcast_selected.insert(tab.session_id.clone());
                    }
                }
            }
            Task::none()
        }
        Message::HideBroadcastDialog => {
            state.show_broadcast_dialog = false;
            Task::none()
        }
        Message::BroadcastTextChanged(v) => { state.broadcast_text = v; Task::none() }
        Message::BroadcastToggleSession(sid) => {
            if state.broadcast_selected.contains(&sid) {
                state.broadcast_selected.remove(&sid);
            } else {
                state.broadcast_selected.insert(sid);
            }
            Task::none()
        }
        Message::BroadcastSendNow => {
            let cmd = state.broadcast_text.clone();
            if cmd.is_empty() { return Task::none(); }
            // Append newline if the user didn't so the server actually runs it
            let payload = if cmd.ends_with('\n') { cmd } else { format!("{}\n", cmd) };
            let ssh = state.ssh_manager.clone();
            let ids: Vec<String> = state.broadcast_selected.iter().cloned().collect();
            log::info!("Broadcast: sending {} bytes to {} sessions", payload.len(), ids.len());
            for sid in ids {
                let _ = ssh.send_data(&sid, payload.as_bytes());
            }
            state.broadcast_text.clear();
            state.show_broadcast_dialog = false;
            Task::none()
        }

        // ---- snippets --------------------------------------------------------
        Message::ShowSnippetsPanel => {
            state.show_snippets_panel = !state.show_snippets_panel;
            if state.show_snippets_panel {
                state.snippets = load_snippets();
                state.snippet_edit_id = None;
                state.snippet_form_name.clear();
                state.snippet_form_body.clear();
            }
            Task::none()
        }
        Message::HideSnippetsPanel => {
            state.show_snippets_panel = false;
            Task::none()
        }
        Message::SnippetSend(id) => {
            if let Some(sn) = state.snippets.iter().find(|s| s.id == id).cloned() {
                if let Some(idx) = state.active_tab {
                    if let Some(tab) = state.tabs.get(idx) {
                        let sid = tab.session_id.clone();
                        if !sid.is_empty() {
                            let body = if sn.body.ends_with('\n') { sn.body.clone() } else { format!("{}\n", sn.body) };
                            let _ = state.ssh_manager.send_data(&sid, body.as_bytes());
                        }
                    }
                }
                state.show_snippets_panel = false;
            }
            Task::none()
        }
        Message::SnippetEdit(maybe_id) => {
            state.snippet_edit_id = maybe_id.clone();
            if let Some(id) = maybe_id {
                if let Some(s) = state.snippets.iter().find(|s| s.id == id) {
                    state.snippet_form_name = s.name.clone();
                    state.snippet_form_body = s.body.clone();
                }
            } else {
                state.snippet_form_name.clear();
                state.snippet_form_body.clear();
            }
            Task::none()
        }
        Message::SnippetFormNameChanged(v) => { state.snippet_form_name = v; Task::none() }
        Message::SnippetFormBodyChanged(v) => { state.snippet_form_body = v; Task::none() }
        Message::SnippetSave => {
            let name = state.snippet_form_name.trim().to_string();
            let body = state.snippet_form_body.trim().to_string();
            if name.is_empty() || body.is_empty() { return Task::none(); }
            let id = state.snippet_edit_id.clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            if let Some(existing) = state.snippets.iter_mut().find(|s| s.id == id) {
                existing.name = name;
                existing.body = body;
            } else {
                state.snippets.push(Snippet { id, name, body });
            }
            save_snippets(&state.snippets);
            state.snippet_edit_id = None;
            state.snippet_form_name.clear();
            state.snippet_form_body.clear();
            Task::none()
        }
        Message::SnippetDelete(id) => {
            state.snippets.retain(|s| s.id != id);
            save_snippets(&state.snippets);
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
                        .set_title(i18n::t("filedialog.rz_upload"))
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
        Message::ToggleBottomPanel => {
            state.bottom_panel_collapsed = !state.bottom_panel_collapsed;
            Task::none()
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

        // ---- terminal search (Cmd+F) ---------------------------------------
        Message::ToggleTerminalSearch => {
            state.term_search_active = !state.term_search_active;
            if state.term_search_active {
                rerun_terminal_search(state);
                scroll_to_current_match(state);
                text_input::focus(text_input::Id::new(TERM_SEARCH_INPUT_ID))
            } else {
                state.term_search_matches.clear();
                Task::none()
            }
        }
        Message::TerminalSearchChanged(q) => {
            state.term_search_query = q;
            rerun_terminal_search(state);
            scroll_to_current_match(state);
            Task::none()
        }
        Message::TerminalSearchNext => {
            if !state.term_search_matches.is_empty() {
                state.term_search_current =
                    (state.term_search_current + 1) % state.term_search_matches.len();
                scroll_to_current_match(state);
            }
            Task::none()
        }
        Message::TerminalSearchPrev => {
            if !state.term_search_matches.is_empty() {
                let n = state.term_search_matches.len();
                state.term_search_current = (state.term_search_current + n - 1) % n;
                scroll_to_current_match(state);
            }
            Task::none()
        }
        Message::TerminalSearchClose => {
            state.term_search_active = false;
            state.term_search_matches.clear();
            Task::none()
        }
        Message::ToggleTerminalSearchCase => {
            state.term_search_case_insensitive = !state.term_search_case_insensitive;
            rerun_terminal_search(state);
            scroll_to_current_match(state);
            Task::none()
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
            // Passthrough guard: if any overlay is open, the user is scrolling
            // inside it — don't let the event also scroll the terminal below.
            if state.any_overlay_open() { return Task::none(); }
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    tab.terminal.lock().scroll_view_up(lines);
                }
            }
            Task::none()
        }
        Message::TerminalScrollDown(lines) => {
            if state.any_overlay_open() { return Task::none(); }
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    tab.terminal.lock().scroll_view_down(lines);
                }
            }
            Task::none()
        }
        Message::TerminalMouseDown(_x, _y) => {
            // Passthrough guard: clicks inside an open overlay don't reach here
            // when they hit a widget; this guards the "click outside the modal
            // card but inside the page" case from triggering terminal actions.
            if state.any_overlay_open() { return Task::none(); }
            state.context_menu = None;

            // Check if click is on the splitter zone
            // Layout from top: toolbar(30) + tabbar(34) + terminal(Fill) + splitter(4) + bottom(H) + status(24)
            // Splitter center Y ≈ window_height - bottom_panel_height - 24 - 2
            let splitter_y = state.window_height - state.bottom_panel_height - 24.0 - 2.0;
            let hit = !state.bottom_panel_collapsed
                && (state.cursor_y - splitter_y).abs() < 8.0;

            if hit && !state.dragging_splitter {
                state.dragging_splitter = true;
                state.drag_start_y = state.cursor_y;
                state.drag_start_height = state.bottom_panel_height;
                return Task::none();
            }

            // Normal terminal click — don't start selection if dragging
            if state.dragging_splitter {
                return Task::none();
            }
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
            state.cursor_y = y;
            // Handle splitter drag
            if state.dragging_splitter {
                let delta = state.drag_start_y - y;
                state.bottom_panel_height = (state.drag_start_height + delta).clamp(80.0, 600.0);
                return Task::none();
            }
            if state.selecting {
                let sidebar_w = if state.sidebar_collapsed { 0.0 } else { 220.0 };
                let top_off = 30.0 + 34.0; // toolbar + tabbar
                if let Some(pos) = pixel_to_grid_with(x, y, sidebar_w, top_off, state.font_size) {
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
            // Always reset splitter drag
            state.dragging_splitter = false;
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

        // ---- update ----------------------------------------------------------
        Message::CheckForUpdate => {
            state.updater.check_async();
            Task::none()
        }
        Message::DownloadUpdate => {
            state.updater.download_async();
            Task::none()
        }
        Message::RestartForUpdate => {
            // Exit code 42 signals the launcher to swap the new core library and restart
            std::process::exit(42);
        }
        Message::DismissUpdate => {
            state.updater.state.lock().available = false;
            Task::none()
        }

        // ---- bottom panel ----------------------------------------------------
        Message::SwitchBottomTab(tab) => {
            state.bottom_panel_tab = tab;
            Task::none()
        }
        Message::PathInputChanged(v) => {
            state.path_input = v;
            Task::none()
        }
        Message::InspectProcess(pid) => {
            // Get session for exec
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let session_id = tab.session_id.clone();
                    let ssh = state.ssh_manager.clone();
                    return Task::perform(
                        async move {
                            tokio::task::spawn_blocking(move || {
                                // Comprehensive /proc-based process inspection
                                let cmd = format!(
                                    concat!(
                                        "echo '___STATUS___' && cat /proc/{pid}/status 2>/dev/null; ",
                                        "echo '___CMDLINE___' && tr '\\0' ' ' < /proc/{pid}/cmdline 2>/dev/null; echo; ",
                                        "echo '___IO___' && cat /proc/{pid}/io 2>/dev/null; ",
                                        "echo '___CWD___' && readlink /proc/{pid}/cwd 2>/dev/null; ",
                                        "echo '___EXE___' && readlink /proc/{pid}/exe 2>/dev/null; ",
                                        "echo '___FD_COUNT___' && ls /proc/{pid}/fd 2>/dev/null | wc -l; ",
                                        "echo '___PS___' && ps -p {pid} -o pid,ppid,user,nice,vsz,rss,etime,stat,args --no-headers 2>/dev/null; ",
                                        "echo '___CHILDREN___' && ps --ppid {pid} -o pid,pcpu,pmem,comm --no-headers 2>/dev/null; ",
                                        "echo '___THREADS___' && ls /proc/{pid}/task 2>/dev/null | head -50; ",
                                        "echo '___NET___' && ss -tnp 2>/dev/null | grep 'pid={pid},' | head -20; ",
                                        "echo '___LISTEN___' && ss -tlnp 2>/dev/null | grep 'pid={pid},' | head -10; ",
                                        "echo '___LIMITS___' && cat /proc/{pid}/limits 2>/dev/null | grep -E 'open files|processes|memory' ; ",
                                        "echo '___OOM___' && cat /proc/{pid}/oom_score 2>/dev/null; ",
                                        "echo '___FDS___' && ls -la /proc/{pid}/fd 2>/dev/null | tail -15; ",
                                    ),
                                    pid = pid
                                );
                                let output = ssh.exec_command(&session_id, &cmd)?;
                                Ok(parse_process_detail(pid, &output))
                            }).await.map_err(|e| format!("{}", e))?
                        },
                        |result: Result<ProcessDetailInfo, String>| match result {
                            Ok(detail) => Message::ProcessDetailReceived(detail),
                            Err(e) => Message::Error(e),
                        },
                    );
                }
            }
            Task::none()
        }
        Message::ProcessDetailReceived(detail) => {
            state.process_detail = Some(detail);
            Task::none()
        }
        Message::HideProcessDetail => {
            state.process_detail = None;
            Task::none()
        }
        Message::ShowContextMenu(id, name, x, y) => {
            state.context_menu = Some(ContextMenu { conn_id: id, conn_name: name, x, y });
            Task::none()
        }
        Message::HideContextMenu => {
            state.context_menu = None;
            Task::none()
        }
        Message::PathInputSubmit => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let sid = tab.session_id.clone();
                    let path = state.path_input.clone();
                    if !path.is_empty() {
                        return Task::done(Message::ChangeDir(sid, path));
                    }
                }
            }
            Task::none()
        }

        // ---- UI state -------------------------------------------------------
        Message::ToggleSidebar => {
            state.sidebar_collapsed = !state.sidebar_collapsed;
            Task::none()
        }
        Message::ShowSettings => {
            // Toggle: second click closes the panel.
            state.show_settings = !state.show_settings;
            Task::none()
        }
        Message::HideSettings => {
            state.show_settings = false;
            Task::none()
        }
        Message::ShowAbout => {
            // Toggle: second click closes.
            state.show_settings = false;
            state.show_about = !state.show_about;
            Task::none()
        }
        Message::HideAbout => {
            state.show_about = false;
            Task::none()
        }
        Message::SetUiScale(scale) => {
            state.ui_scale = scale;
            save_ui_scale(scale);
            Task::none()
        }

        // ---- command history -------------------------------------------------
        Message::ShowHistory => {
            // Toggle: second click closes.
            state.show_history = !state.show_history;
            state.history_filter.clear();
            Task::none()
        }
        Message::HideHistory => {
            state.show_history = false;
            state.history_filter.clear();
            Task::none()
        }
        Message::HistoryFilterChanged(v) => {
            state.history_filter = v;
            Task::none()
        }
        Message::ReplayCommand(cmd) => {
            state.show_history = false;
            state.history_filter.clear();
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let session_id = tab.session_id.clone();
                    let ssh = state.ssh_manager.clone();
                    let full_cmd = format!("{}\n", cmd);
                    return Task::perform(
                        async move {
                            ssh.send_data(&session_id, full_cmd.as_bytes())?;
                            Ok(())
                        },
                        |result: Result<(), String>| match result {
                            Ok(()) => Message::None,
                            Err(e) => Message::Error(e),
                        },
                    );
                }
            }
            Task::none()
        }
        Message::ClearHistory => {
            state.cmd_history.clear();
            Task::none()
        }
        Message::QuickCmdInputChanged(v) => {
            state.quick_cmd_input = v;
            Task::none()
        }
        Message::SplitterDragStart(y) => {
            state.dragging_splitter = true;
            state.drag_start_y = y;
            state.drag_start_height = state.bottom_panel_height;
            Task::none()
        }
        Message::SplitterDragMove(y) => {
            if state.dragging_splitter {
                let delta = state.drag_start_y - y;
                state.bottom_panel_height = (state.drag_start_height + delta).clamp(80.0, 600.0);
            }
            Task::none()
        }
        Message::SplitterDragEnd => {
            state.dragging_splitter = false;
            Task::none()
        }
        Message::SetFontSize(size) => {
            state.font_size = size.clamp(8.0, 30.0);
            save_font_size(state.font_size);
            // Force terminal re-layout
            state.last_term_size = (0, 0);
            Task::none()
        }
        Message::ResizeBottomPanel(delta) => {
            if delta < -1000.0 {
                // Magic: window height update
                state.window_height = -(delta + 10000.0);
            } else {
                state.bottom_panel_height = (state.bottom_panel_height + delta).clamp(80.0, 600.0);
            }
            Task::none()
        }
        Message::LocalPathChanged(v) => { state.local_path = v; Task::none() }
        Message::LocalPathSubmit => {
            state.local_entries = list_local_dir(&state.local_path);
            Task::none()
        }
        Message::LocalFileClicked(path) => {
            let p = std::path::Path::new(&path);
            if p.is_dir() {
                state.local_path = path;
                state.local_entries = list_local_dir(&state.local_path);
                state.selected_local_file = None;
            } else {
                state.selected_local_file = Some(path);
            }
            Task::none()
        }
        Message::SelectLocalFile(path) => {
            state.selected_local_file = Some(path);
            Task::none()
        }
        Message::RefreshLocalFiles => {
            state.local_entries = list_local_dir(&state.local_path);
            Task::none()
        }
        Message::RefreshRemoteFiles => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let sid = tab.session_id.clone();
                    let path = state.current_dir.get(&sid).cloned().unwrap_or_else(|| "~".into());
                    return Task::done(Message::ChangeDir(sid, path));
                }
            }
            Task::none()
        }
        Message::UploadLocalFile => {
            // Upload selected local file to remote current dir
            if let Some(ref local_file) = state.selected_local_file.clone() {
                if let Some(idx) = state.active_tab {
                    if let Some(tab) = state.tabs.get(idx) {
                        let sid = tab.session_id.clone();
                        let remote_dir = state.current_dir.get(&sid).cloned().unwrap_or_else(|| "~".into());
                        let file_name = std::path::Path::new(local_file).file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let remote_path = format!("{}/{}", remote_dir.trim_end_matches('/'), file_name);
                        let ssh = state.ssh_manager.clone();
                        let local = local_file.clone();
                        let progress = Arc::new(TransferProgress::new());
                        *progress.filename.lock() = file_name;
                        state.transfer_progress = Some(progress.clone());
                        state.selected_local_file = None;
                        return Task::perform(
                            async move {
                                tokio::task::spawn_blocking(move || {
                                    ssh.upload_file_with_progress(&sid, &local, &remote_path, progress)
                                }).await.map_err(|e| format!("{}", e))?
                            },
                            |result| match result {
                                Ok(()) => Message::UploadComplete(String::new()),
                                Err(e) => Message::Error(e),
                            },
                        );
                    }
                }
            }
            Task::none()
        }
        Message::SendQuickCmd => {
            let cmd = state.quick_cmd_input.trim().to_string();
            if !cmd.is_empty() {
                state.quick_cmd_input.clear();
                return Task::done(Message::ReplayCommand(cmd));
            }
            Task::none()
        }

        // ---- proxy management ------------------------------------------------
        Message::ShowProxyManager => {
            // Toggle: second click closes the side panel.
            state.show_proxy_manager = !state.show_proxy_manager;
            if state.show_proxy_manager {
                state.proxies = state.proxy_store.load();
                state.proxy_edit_id = None;
            }
            Task::none()
        }
        Message::HideProxyManager => {
            state.show_proxy_manager = false;
            Task::none()
        }
        Message::ShowProxyForm(maybe_id) => {
            state.show_proxy_form = true;
            if let Some(id) = maybe_id {
                if let Some(p) = state.proxies.iter().find(|p| p.id == id) {
                    state.proxy_edit_id = Some(id);
                    state.proxy_form = ProxyFormData {
                        name: p.name.clone(),
                        proxy_type: match p.proxy_type {
                            crate::proxy::ProxyType::Socks5h => "socks5h".into(),
                            crate::proxy::ProxyType::Http => "http".into(),
                            crate::proxy::ProxyType::SshBastion => "bastion".into(),
                        },
                        host: p.host.clone(),
                        port: p.port.to_string(),
                        username: p.username.clone().unwrap_or_default(),
                        password: p.password.clone().unwrap_or_default(),
                        auth_type: p.auth_type.clone().unwrap_or_else(|| "password".into()),
                        private_key: p.private_key.clone().unwrap_or_default(),
                        passphrase: p.passphrase.clone().unwrap_or_default(),
                    };
                }
            } else {
                state.proxy_edit_id = None;
                state.proxy_form = ProxyFormData {
                    proxy_type: "socks5h".into(),
                    port: "1080".into(),
                    ..Default::default()
                };
            }
            Task::none()
        }
        Message::HideProxyForm => {
            state.show_proxy_form = false;
            state.proxy_edit_id = None;
            state.proxy_form = ProxyFormData::default();
            Task::none()
        }
        Message::ProxyFormNameChanged(v) => { state.proxy_form.name = v; Task::none() }
        Message::ProxyFormTypeChanged(v) => { state.proxy_form.proxy_type = v; Task::none() }
        Message::ProxyFormHostChanged(v) => { state.proxy_form.host = v; Task::none() }
        Message::ProxyFormPortChanged(v) => { state.proxy_form.port = v; Task::none() }
        Message::ProxyFormUsernameChanged(v) => { state.proxy_form.username = v; Task::none() }
        Message::ProxyFormPasswordChanged(v) => { state.proxy_form.password = v; Task::none() }
        Message::ProxyFormAuthTypeChanged(v) => { state.proxy_form.auth_type = v; Task::none() }
        Message::ProxyFormPrivateKeyChanged(v) => { state.proxy_form.private_key = v; Task::none() }
        Message::ProxyFormPassphraseChanged(v) => { state.proxy_form.passphrase = v; Task::none() }
        Message::ProxyFormBrowsePrivateKey => {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select Private Key")
                .pick_file()
            {
                state.proxy_form.private_key = path.to_string_lossy().to_string();
            }
            Task::none()
        }
        Message::SaveProxy => {
            let ptype = match state.proxy_form.proxy_type.as_str() {
                "http" => crate::proxy::ProxyType::Http,
                "bastion" => crate::proxy::ProxyType::SshBastion,
                _ => crate::proxy::ProxyType::Socks5h,
            };
            let default_port: u16 = match ptype {
                crate::proxy::ProxyType::Http => 8080,
                crate::proxy::ProxyType::SshBastion => 22,
                _ => 1080,
            };
            let port: u16 = state.proxy_form.port.parse().unwrap_or(default_port);
            let is_bastion = matches!(ptype, crate::proxy::ProxyType::SshBastion);
            let proxy = crate::proxy::ProxyConfig {
                id: state.proxy_edit_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                name: state.proxy_form.name.clone(),
                proxy_type: ptype,
                host: state.proxy_form.host.clone(),
                port,
                username: if state.proxy_form.username.is_empty() { None } else { Some(state.proxy_form.username.clone()) },
                password: if state.proxy_form.password.is_empty() { None } else { Some(state.proxy_form.password.clone()) },
                auth_type: if is_bastion { Some(state.proxy_form.auth_type.clone()) } else { None },
                private_key: if is_bastion && !state.proxy_form.private_key.is_empty() { Some(state.proxy_form.private_key.clone()) } else { None },
                passphrase: if is_bastion && !state.proxy_form.passphrase.is_empty() { Some(state.proxy_form.passphrase.clone()) } else { None },
            };
            if state.proxy_edit_id.is_some() {
                state.proxy_store.update(&proxy);
            } else {
                state.proxy_store.add(proxy);
            }
            state.proxies = state.proxy_store.load();
            state.show_proxy_form = false;
            state.proxy_edit_id = None;
            state.proxy_form = ProxyFormData::default();
            Task::none()
        }
        Message::DeleteProxy(id) => {
            state.proxy_store.delete(&id);
            state.proxies = state.proxy_store.load();
            Task::none()
        }
        Message::TestProxy(id) => {
            if let Some(proxy) = state.proxies.iter().find(|p| p.id == id).cloned() {
                let pid = id.clone();
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            crate::proxy::test_proxy(&proxy)
                        }).await.unwrap_or(crate::proxy::ProxyTestResult {
                            reachable: false, latency_ms: 0,
                            error: Some("Task failed".into()),
                        })
                    },
                    move |result| Message::ProxyTestDone(pid.clone(), result),
                );
            }
            Task::none()
        }
        Message::ProxyTestDone(id, result) => {
            state.proxy_test_results.insert(id, result);
            Task::none()
        }
        Message::FormProxyChanged(v) => {
            state.form.proxy_id = v;
            Task::none()
        }

        // ---- tunnels ---------------------------------------------------------
        Message::ShowTunnelManager => {
            // Toggle: second click closes.
            state.show_tunnel_manager = !state.show_tunnel_manager;
            if state.show_tunnel_manager {
                state.tunnels = state.tunnel_store.load();
            }
            Task::none()
        }
        Message::HideTunnelManager => {
            state.show_tunnel_manager = false;
            Task::none()
        }
        Message::ShowTunnelForm(edit_id) => {
            state.show_tunnel_form = true;
            state.tunnel_edit_id = edit_id.clone();
            if let Some(id) = edit_id {
                if let Some(t) = state.tunnels.iter().find(|x| x.id == id) {
                    state.tunnel_form = TunnelFormData {
                        name: t.name.clone(),
                        ssh_host: t.ssh_host.clone(),
                        ssh_port: t.ssh_port.to_string(),
                        username: t.username.clone(),
                        auth_type: t.auth_type.clone(),
                        password: t.password.clone().unwrap_or_default(),
                        private_key: t.private_key.clone().unwrap_or_default(),
                        passphrase: t.passphrase.clone().unwrap_or_default(),
                        forwards_text: t.forwards.iter()
                            .map(|f| format!("{}:{}:{}", f.local_port, f.remote_host, f.remote_port))
                            .collect::<Vec<_>>().join("\n"),
                        auto_start: t.auto_start,
                    };
                }
            } else {
                state.tunnel_form = TunnelFormData {
                    ssh_port: "22".into(),
                    auth_type: "password".into(),
                    ..Default::default()
                };
            }
            Task::none()
        }
        Message::HideTunnelForm => {
            state.show_tunnel_form = false;
            state.tunnel_edit_id = None;
            state.tunnel_form = TunnelFormData::default();
            Task::none()
        }
        Message::TunnelFormNameChanged(v) => { state.tunnel_form.name = v; Task::none() }
        Message::TunnelFormHostChanged(v) => { state.tunnel_form.ssh_host = v; Task::none() }
        Message::TunnelFormPortChanged(v) => { state.tunnel_form.ssh_port = v; Task::none() }
        Message::TunnelFormUserChanged(v) => { state.tunnel_form.username = v; Task::none() }
        Message::TunnelFormAuthTypeChanged(v) => { state.tunnel_form.auth_type = v; Task::none() }
        Message::TunnelFormPasswordChanged(v) => { state.tunnel_form.password = v; Task::none() }
        Message::TunnelFormKeyChanged(v) => { state.tunnel_form.private_key = v; Task::none() }
        Message::TunnelFormPassphraseChanged(v) => { state.tunnel_form.passphrase = v; Task::none() }
        Message::TunnelFormForwardsChanged(v) => { state.tunnel_form.forwards_text = v; Task::none() }
        Message::TunnelFormAutoStartChanged(v) => { state.tunnel_form.auto_start = v; Task::none() }
        Message::TunnelFormBrowseKey => {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select Private Key")
                .pick_file()
            {
                state.tunnel_form.private_key = path.to_string_lossy().to_string();
            }
            Task::none()
        }
        Message::SaveTunnel => {
            let forwards: Result<Vec<_>, String> = state.tunnel_form.forwards_text
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .map(crate::tunnel::ForwardRule::parse)
                .collect();
            let forwards = match forwards {
                Ok(f) if !f.is_empty() => f,
                Ok(_) => {
                    state.error_message = "At least one forward rule is required".into();
                    state.show_error_dialog = true;
                    return Task::none();
                }
                Err(e) => {
                    state.error_message = format!("Forward parse error: {}", e);
                    state.show_error_dialog = true;
                    return Task::none();
                }
            };
            let port: u16 = state.tunnel_form.ssh_port.parse().unwrap_or(22);
            let cfg = crate::tunnel::TunnelConfig {
                id: state.tunnel_edit_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                name: state.tunnel_form.name.clone(),
                ssh_host: state.tunnel_form.ssh_host.clone(),
                ssh_port: port,
                username: state.tunnel_form.username.clone(),
                auth_type: state.tunnel_form.auth_type.clone(),
                password: if state.tunnel_form.password.is_empty() { None } else { Some(state.tunnel_form.password.clone()) },
                private_key: if state.tunnel_form.private_key.is_empty() { None } else { Some(state.tunnel_form.private_key.clone()) },
                passphrase: if state.tunnel_form.passphrase.is_empty() { None } else { Some(state.tunnel_form.passphrase.clone()) },
                forwards,
                auto_start: state.tunnel_form.auto_start,
            };
            state.tunnel_store.upsert(cfg);
            state.tunnels = state.tunnel_store.load();
            state.show_tunnel_form = false;
            state.tunnel_edit_id = None;
            state.tunnel_form = TunnelFormData::default();
            Task::none()
        }
        Message::DeleteTunnel(id) => {
            state.tunnel_manager.stop(&id);
            state.tunnel_store.delete(&id);
            state.tunnels = state.tunnel_store.load();
            Task::none()
        }
        Message::StartTunnel(id) => {
            if let Some(cfg) = state.tunnel_store.get(&id) {
                if let Err(e) = state.tunnel_manager.start(cfg) {
                    state.error_message = format!("Start tunnel: {}", e);
                    state.show_error_dialog = true;
                }
            }
            Task::none()
        }
        Message::StopTunnel(id) => {
            state.tunnel_manager.stop(&id);
            Task::none()
        }
        Message::TunnelStateTick => Task::none(),

        // ---- theme editor ---------------------------------------------------
        Message::ThemeSelectZone(z) => {
            state.theme_editing_zone = Some(z);
            Task::none()
        }
        Message::ThemeCloseZone => {
            state.theme_editing_zone = None;
            Task::none()
        }
        Message::ThemeRChanged(r) => {
            if let Some(z) = state.theme_editing_zone {
                let mut v = z.get(&state.theme_cfg);
                v.r = r;
                z.set(&mut state.theme_cfg, v);
                state.theme_cfg.save();
            }
            Task::none()
        }
        Message::ThemeGChanged(g) => {
            if let Some(z) = state.theme_editing_zone {
                let mut v = z.get(&state.theme_cfg);
                v.g = g;
                z.set(&mut state.theme_cfg, v);
                state.theme_cfg.save();
            }
            Task::none()
        }
        Message::ThemeBChanged(b) => {
            if let Some(z) = state.theme_editing_zone {
                let mut v = z.get(&state.theme_cfg);
                v.b = b;
                z.set(&mut state.theme_cfg, v);
                state.theme_cfg.save();
            }
            Task::none()
        }
        Message::ThemeHexChanged(hex) => {
            if let Some(z) = state.theme_editing_zone {
                let s = hex.trim().trim_start_matches('#');
                if s.len() == 6 {
                    if let Ok(n) = u32::from_str_radix(s, 16) {
                        let rgb = crate::ui::theme_config::Rgb::new(
                            ((n >> 16) & 0xFF) as u8,
                            ((n >> 8) & 0xFF) as u8,
                            (n & 0xFF) as u8,
                        );
                        z.set(&mut state.theme_cfg, rgb);
                        state.theme_cfg.save();
                    }
                }
            }
            Task::none()
        }
        Message::ThemeTerminalFontSize(s) => {
            state.theme_cfg.terminal_font_size = s.clamp(8.0, 28.0);
            state.font_size = state.theme_cfg.terminal_font_size;
            state.theme_cfg.save();
            Task::none()
        }
        Message::ThemeUiFontSize(s) => {
            state.theme_cfg.ui_font_size = s.clamp(10.0, 18.0);
            state.theme_cfg.save();
            Task::none()
        }
        Message::ThemeReset => {
            state.theme_cfg = crate::ui::theme_config::ThemeConfig::default();
            state.font_size = state.theme_cfg.terminal_font_size;
            state.theme_editing_zone = None;
            state.theme_cfg.save();
            Task::none()
        }

        // ---- language --------------------------------------------------------
        Message::ToggleLanguage => {
            state.locale = if state.locale == "zh-CN" {
                "en".to_string()
            } else {
                "zh-CN".to_string()
            };
            i18n::set_locale(&state.locale);
            save_locale(&state.locale);
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
            log::error!("{}", e);
            state.error_message = e;
            state.show_error_dialog = true;
            state.transfer_progress = None;
            Task::none()
        }
        Message::DismissErrorDialog => {
            state.show_error_dialog = false;
            state.error_message.clear();
            Task::none()
        }
        Message::ShowLogViewer => {
            // Toggle: second click closes.
            if state.show_log_viewer {
                state.show_log_viewer = false;
                state.log_viewer_content.clear();
                return Task::none();
            }
            let path = crate::log_file_path();
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => {
                    const MAX: usize = 200 * 1024;
                    if c.len() > MAX {
                        let start = c.len() - MAX;
                        let aligned = c[start..].find('\n').map(|i| start + i + 1).unwrap_or(start);
                        format!("…(showing last {} KB)…\n{}", (c.len() - aligned) / 1024, &c[aligned..])
                    } else {
                        c
                    }
                }
                Err(e) => format!("<cannot read log file {}: {}>", path.display(), e),
            };
            state.log_viewer_content = content;
            state.show_log_viewer = true;
            Task::none()
        }
        Message::HideLogViewer => {
            state.show_log_viewer = false;
            state.log_viewer_content.clear();
            Task::none()
        }
        Message::RefreshLogViewer => {
            Task::done(Message::ShowLogViewer)
        }
        Message::OpenLogFolder => {
            let path = crate::log_file_path();
            let dir = path.parent().unwrap_or(std::path::Path::new("."));
            #[cfg(target_os = "macos")]
            let _ = std::process::Command::new("open").arg(dir).spawn();
            #[cfg(target_os = "windows")]
            let _ = std::process::Command::new("explorer").arg(dir).spawn();
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
            Task::none()
        }
        Message::WindowCloseRequested(id) => {
            // Intercept × button — minimize so SSH sessions survive. Use
            // Cmd/Ctrl+Shift+Q (or status bar QUIT button) for real exit.
            log::info!("Window close requested — minimizing to taskbar (sessions preserved)");
            let t: Task<Message> = iced::window::minimize(id, true);
            t
        }
        Message::QuitApp => {
            log::info!("User requested quit — closing all SSH sessions and tunnels");
            for sid in state.ssh_manager.active_sessions() {
                let _ = state.ssh_manager.disconnect(&sid);
            }
            state.tunnel_manager.stop_all();
            let t: Task<Message> = iced::window::get_latest()
                .and_then(|id| iced::window::close(id));
            t
        }
    }
}

// ---------------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------------

fn subscription(state: &NeoShell) -> Subscription<Message> {
    let mut subs = vec![
        time::every(Duration::from_millis(50)).map(|_| Message::PollSshEvents),
        // Check for updates every hour
        time::every(Duration::from_secs(3600)).map(|_| Message::CheckForUpdate),
        // Always-on listener for CloseRequested — the × button is intercepted
        // and converted to a minimize so SSH sessions survive. Cmd/Ctrl+Shift+Q
        // is the explicit quit shortcut.
        event::listen_with(|evt, _status, window| match evt {
            iced::Event::Window(iced::window::Event::CloseRequested) => {
                Some(Message::WindowCloseRequested(window))
            }
            _ => None,
        }),
    ];

    // Monitor refresh every 3 seconds when there is an active tab
    if state.screen == Screen::Main && state.active_tab.is_some() {
        subs.push(time::every(Duration::from_secs(3)).map(|_| Message::FetchMonitorData));
    }

    // When the tunnel panel is open, tick every 2s to refresh connection counts.
    if state.show_tunnel_manager {
        subs.push(time::every(Duration::from_secs(2)).map(|_| Message::TunnelStateTick));
    }

    // Capture ALL events. Terminal-targeted messages are filtered in update()
    // against state.any_overlay_open() so scroll / clicks / right-click-paste
    // can't pass through an open overlay to the terminal canvas.
    if state.screen == Screen::Main {
        subs.push(event::listen_with(|evt, status, _window| {
            match evt {
                iced::Event::Window(iced::window::Event::Resized(size)) => {
                    Some(Message::ResizeBottomPanel(-(size.height + 10000.0)))
                }
                iced::Event::Keyboard(keyboard::Event::KeyPressed {
                    key, modifiers, text, ..
                }) => {
                    Some(Message::KeyboardEvent(key, modifiers, text.map(|s| s.to_string())))
                }
                iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left))
                    if matches!(status, event::Status::Ignored) =>
                {
                    Some(Message::TerminalMouseDown(0.0, 0.0))
                }
                iced::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                    Some(Message::TerminalMouseUp)
                }
                iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Right)) => {
                    Some(Message::PasteClipboard)
                }
                iced::Event::Mouse(mouse::Event::CursorMoved { position }) => {
                    Some(Message::TerminalMouseMove(position.x, position.y))
                }
                iced::Event::Mouse(mouse::Event::WheelScrolled { delta })
                    if matches!(status, event::Status::Ignored) =>
                {
                    match delta {
                        mouse::ScrollDelta::Lines { y, .. } | mouse::ScrollDelta::Pixels { y, .. } => {
                            if y > 0.0 { Some(Message::TerminalScrollUp(3)) }
                            else if y < 0.0 { Some(Message::TerminalScrollDown(3)) }
                            else { None }
                        }
                    }
                }
                _ => None,
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
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("setup.title"))
        .size(28.0 * scale)
        .color(c_primary);

    let subtitle = text(i18n::t("setup.subtitle"))
        .size(14.0 * scale)
        .color(theme::TEXT_SECONDARY);

    let pw_input = text_input(&i18n::t("setup.password_placeholder"), &state.password_input)
        .on_input(Message::PasswordChanged)
        .secure(true)
        .padding(10)
        .size(16.0 * scale)
        .id(iced::widget::text_input::Id::new("setup_pw"));

    let confirm_input = text_input(&i18n::t("setup.confirm_placeholder"), &state.confirm_input)
        .on_input(Message::ConfirmChanged)
        .on_submit(Message::CreateVault)
        .secure(true)
        .padding(10)
        .size(16.0 * scale)
        .id(iced::widget::text_input::Id::new("setup_confirm"));

    let create_btn = button(
        text(i18n::t("setup.create_vault")).color(c_primary).size(16.0 * scale),
    )
    .on_press(Message::CreateVault)
    .padding(Padding::from([10, 24]))
    .style(accent_button_style);

    let error_text = if state.error_message.is_empty() {
        text("").size(1.0 * scale)
    } else {
        text(&state.error_message).color(c_danger).size(14.0 * scale)
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
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("unlock.title"))
        .size(28.0 * scale)
        .color(c_primary);

    let subtitle = text(i18n::t("unlock.subtitle"))
        .size(14.0 * scale)
        .color(theme::TEXT_SECONDARY);

    let pw_input = text_input(&i18n::t("unlock.password_placeholder"), &state.password_input)
        .on_input(Message::PasswordChanged)
        .on_submit(Message::UnlockVault)
        .secure(true)
        .padding(10)
        .size(16.0 * scale);

    let unlock_btn = button(
        text(i18n::t("unlock.btn")).color(c_primary).size(16.0 * scale),
    )
    .on_press(Message::UnlockVault)
    .padding(Padding::from([10, 24]))
    .style(accent_button_style);

    let error_text = if state.error_message.is_empty() {
        text("").size(1.0 * scale)
    } else {
        text(&state.error_message).color(c_danger).size(14.0 * scale)
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

// ---- Main screen (FinalShell-inspired layout) -----------------------------
//
//  ┌──────────────────────────────────────────────────────┐
//  │  Toolbar  [+New] [Proxy] [History] [Settings]        │
//  ├──────────────────────────────────────────────────────┤
//  │  Tab bar  [tab1] [tab2] [+]                          │
//  ├────────────┬─────────────────────────────────────────┤
//  │ Connections│           Terminal                       │
//  │ (left 220) │       (center, Fill)                    │
//  │            ├─────────────────────────────────────────┤
//  │  search    │ [Monitor|Files|Cmd]  bottom panel 220px │
//  │  list...   │  (tabbed panel with content)            │
//  ├────────────┴─────────────────────────────────────────┤
//  │  Status bar                                          │
//  └──────────────────────────────────────────────────────┘

fn view_main(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let toolbar = view_toolbar(state);
    let tab_bar = view_tab_bar(state);
    let status_bar = view_status_bar(state);

    let sidebar_width: f32 = if state.sidebar_collapsed { 0.0 } else { 220.0 };

    // ── Left: connection list (always visible) ──────────────────────
    let left_panel: Element<'_, Message> = if state.sidebar_collapsed {
        Space::new(0, 0).into()
    } else {
        container(view_sidebar(state))
            .width(sidebar_width)
            .height(Fill)
            .into()
    };

    // ── Right side ──────────────────────────────────────────────────
    let right_content: Element<'_, Message> = if state.active_tab.is_some() {
        // Terminal (upper) + bottom panel (lower)
        let terminal = view_terminal_area(state);

        // Transfer progress bar (if active)
        let mut terminal_col = column![
            container(terminal).height(Fill),
        ];
        if let Some(progress) = &state.transfer_progress {
            if !progress.is_finished() {
                terminal_col = terminal_col.push(view_transfer_progress(progress));
            }
        }

        // Drag splitter handle with centered collapse/expand chevron button.
        // Drag still works on either side of the chevron (button captures its
        // own click, everything else on the splitter bar hits TerminalMouseDown
        // via the Ignored-status path).
        let drag_color = if state.dragging_splitter { theme::ACCENT } else { theme::BORDER };
        let chevron_label = if state.bottom_panel_collapsed { "∧" } else { "∨" };
        let collapsed = state.bottom_panel_collapsed;
        let _ = collapsed;
        let chevron_btn = button(
            text(chevron_label)
                .size(11.0 * scale)
                .color(theme::TEXT_SECONDARY),
        )
        .on_press(Message::ToggleBottomPanel)
        .padding(Padding::from([0, 14]))
        .style(|_, _| button::Style {
            background: Some(theme::BG_TERTIARY.into()),
            text_color: theme::TEXT_SECONDARY,
            border: iced::Border {
                radius: 4.0.into(),
                width: 1.0,
                color: theme::BORDER,
            },
            ..Default::default()
        });
        let splitter: Element<'_, Message> = container(
            row![
                Space::with_width(Fill),
                chevron_btn,
                Space::with_width(Fill),
            ]
            .align_y(alignment::Vertical::Center),
        )
        .width(Fill)
        .height(Length::Fixed(14.0))
        .style(move |_| container::Style {
            background: Some(drag_color.into()),
            ..Default::default()
        })
        .into();

        if state.bottom_panel_collapsed {
            column![
                terminal_col.height(Fill),
                splitter,
            ]
            .height(Fill)
            .into()
        } else {
            // Bottom panel with tabs: Monitor | Files | QuickCmd
            let bottom_panel = view_bottom_panel(state);
            column![
                terminal_col.height(Fill),
                splitter,
                container(bottom_panel).height(state.bottom_panel_height),
            ]
            .height(Fill)
            .into()
        }
    } else {
        // No active tab → welcome screen
        view_welcome()
    };

    // ── Compose main body ────────────────────────────────────────────
    let body: Element<'_, Message> = row![
        left_panel,
        container(right_content).width(Fill).height(Fill),
    ]
    .height(Fill)
    .into();

    let mut main_col = column![];
    // Update notification bar
    if let Some(update_bar) = view_update_bar(state) {
        main_col = main_col.push(update_bar);
    }
    main_col = main_col.push(toolbar);
    main_col = main_col.push(tab_bar);
    main_col = main_col.push(body);
    main_col = main_col.push(status_bar);

    // If context menu is open, wrap main_col with the menu overlay
    let main_layout: Element<'_, Message> = if let Some(ref ctx) = state.context_menu {
        let menu = view_context_menu(ctx);
        container(stack([
            main_col.height(Fill).into(),
            menu,
        ]))
        .width(Fill)
        .height(Fill)
        .into()
    } else {
        main_col.height(Fill).into()
    };

    // Delete confirmation dialog
    if let Some((_, ref name)) = state.confirm_delete {
        let msg = i18n::tf("confirm.delete", &[("name", name)]);
        let confirm_card = container(
            column![
                text(msg).color(c_primary).size(14.0 * scale),
                vertical_space().height(12),
                row![
                    button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
                        .on_press(Message::CancelDelete)
                        .padding(Padding::from([6, 16]))
                        .style(transparent_button_style),
                    button(text(i18n::t("dialog.delete")).color(Color::WHITE).size(13.0 * scale))
                        .on_press(Message::ExecuteDelete)
                        .padding(Padding::from([6, 16]))
                        .style(|_: &Theme, _| button::Style {
                            background: Some(theme::DANGER.into()),
                            text_color: Color::WHITE,
                            border: iced::Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                ].spacing(12),
            ]
            .align_x(alignment::Horizontal::Center)
            .padding(24)
        )
        .style(|_| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border { color: theme::BORDER, width: 1.0, radius: 8.0.into() },
            shadow: iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.5), offset: iced::Vector::new(0.0, 4.0), blur_radius: 16.0 },
            ..Default::default()
        });
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            container(confirm_card).width(Fill).height(Fill).center_x(Fill).center_y(Fill)
                .style(|_| container::Style { background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.5).into()), ..Default::default() }).into(),
        ])).width(Fill).height(Fill).into();
    }

    // Process detail popup
    if state.process_detail.is_some() {
        let detail_overlay = view_process_detail(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            detail_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

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

    // Command history panel
    if state.show_history {
        let history_overlay = view_history_panel(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            history_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Proxy manager
    if state.show_proxy_manager {
        let proxy_overlay = view_proxy_manager(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            proxy_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Tunnel manager
    if state.show_tunnel_manager {
        let tunnel_overlay = view_tunnel_manager(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            tunnel_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Keyboard shortcuts help panel
    if state.show_shortcuts_help {
        let help_overlay = view_shortcuts_help();
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            help_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Broadcast dialog
    if state.show_broadcast_dialog {
        let overlay = view_broadcast_dialog(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            overlay,
        ]))
        .width(Fill).height(Fill).into();
    }

    // Snippets panel
    if state.show_snippets_panel {
        let overlay = view_snippets_panel(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            overlay,
        ]))
        .width(Fill).height(Fill).into();
    }

    // Log viewer
    if state.show_log_viewer {
        let log_overlay = view_log_viewer(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            log_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Error dialog (full non-truncated error + "See log" action)
    if state.show_error_dialog && !state.error_message.is_empty() {
        let err_overlay = view_error_dialog(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            err_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // About dialog
    if state.show_about {
        let about_overlay = view_about_dialog(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            about_overlay,
        ]))
        .width(Fill)
        .height(Fill)
        .into();
    }

    // Settings menu
    if state.show_settings {
        let settings_overlay = view_settings_menu(state);
        return container(stack([
            container(main_layout).width(Fill).height(Fill).into(),
            settings_overlay,
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

// ---- Process detail popup ---------------------------------------------------

fn view_process_detail(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let detail = match &state.process_detail {
        Some(d) => d,
        None => return Space::new(0, 0).into(),
    };

    let title = text(format!("Process {} Detail", detail.pid))
        .size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideProcessDetail)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), close_btn]
        .align_y(alignment::Vertical::Center);

    let mut body_col = column![].spacing(2);

    // ── Basic Info ──────────────────────────────
    body_col = body_col.push(
        container(text(i18n::t("process.title")).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0]))
    );
    for (key, val) in &detail.fields {
        body_col = body_col.push(
            row![
                text(format!("{}:", key)).color(theme::TEXT_MUTED).size(10.0 * scale).width(95),
                text(val.clone()).font(Font::MONOSPACE).color(c_primary).size(10.0 * scale),
            ].spacing(8)
        );
    }

    // ── Children ────────────────────────────────
    if !detail.children.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.child"), detail.children.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        // Header
        body_col = body_col.push(
            row![
                text("PID").color(theme::TEXT_MUTED).size(9.0 * scale).width(60),
                text("CPU%").color(theme::TEXT_MUTED).size(9.0 * scale).width(40),
                text("MEM%").color(theme::TEXT_MUTED).size(9.0 * scale).width(40),
                text("CMD").color(theme::TEXT_MUTED).size(9.0 * scale),
            ].spacing(4)
        );
        for line in &detail.children {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let child_pid: u32 = parts[0].parse().unwrap_or(0);
                let row_content = row![
                    text(parts[0]).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(60),
                    text(parts[1]).color(theme::WARNING).size(9.0 * scale).width(40),
                    text(parts[2]).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(40),
                    text(parts[3..].join(" ")).color(c_primary).size(9.0 * scale),
                ].spacing(4);
                body_col = body_col.push(
                    button(row_content)
                        .on_press(Message::InspectProcess(child_pid))
                        .padding(Padding::from([1, 0]))
                        .style(|_: &Theme, s| {
                            let mut st = button::Style::default();
                            if let button::Status::Hovered = s { st.background = Some(theme::BG_HOVER.into()); }
                            st
                        })
                );
            }
        }
    }

    // ── Listening Ports ─────────────────────────
    if !detail.listen_ports.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.listen"), detail.listen_ports.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        for line in &detail.listen_ports {
            body_col = body_col.push(
                text(line).font(Font::MONOSPACE).color(c_success).size(9.0 * scale)
            );
        }
    }

    // ── Network Connections ─────────────────────
    if !detail.net_conns.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.net"), detail.net_conns.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        for line in &detail.net_conns {
            body_col = body_col.push(
                text(line).font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(9.0 * scale)
            );
        }
    }

    // ── Open File Descriptors ───────────────────
    if !detail.open_fds.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.fds"), detail.open_fds.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        for fd in &detail.open_fds {
            body_col = body_col.push(
                text(fd).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(9.0 * scale)
            );
        }
    }

    // ── Threads ─────────────────────────────────
    if !detail.threads.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.threads"), detail.threads.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        let thread_ids = detail.threads.join(", ");
        body_col = body_col.push(
            text(thread_ids).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(9.0 * scale)
        );
    }

    let content = column![
        header,
        scrollable(body_col).height(Fill),
    ]
    .spacing(6)
    .padding(16)
    .width(560);

    let card = container(content)
        .height(500)
        .style(|_| container::Style {
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
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.5).into()),
            ..Default::default()
        })
        .into()
}

// ---- Context menu (right-click on connection) -------------------------------

fn view_context_menu(ctx: &ContextMenu) -> Element<'static, Message> {
    let conn_id = ctx.conn_id.clone();
    let conn_id2 = ctx.conn_id.clone();
    let conn_id3 = ctx.conn_id.clone();

    let connect_item = button(
        text(i18n::t("dialog.connect_title").to_string()).color(theme::TEXT_PRIMARY).size(12)
    )
    .on_press(Message::ConnectTo(conn_id))
    .padding(Padding::from([6, 16]))
    .width(Fill)
    .style(sidebar_item_style);

    let edit_item = button(
        text(i18n::t("dialog.edit").to_string()).color(theme::TEXT_PRIMARY).size(12)
    )
    .on_press(Message::ShowForm(Some(conn_id2)))
    .padding(Padding::from([6, 16]))
    .width(Fill)
    .style(sidebar_item_style);

    let delete_item = button(
        text(i18n::t("dialog.delete").to_string()).color(theme::DANGER).size(12)
    )
    .on_press(Message::DeleteConnection(conn_id3))
    .padding(Padding::from([6, 16]))
    .width(Fill)
    .style(sidebar_item_style);

    let menu_card = container(
        column![connect_item, edit_item, delete_item].spacing(1).width(140)
    )
    .style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 6.0.into() },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(2.0, 2.0),
            blur_radius: 10.0,
        },
        ..Default::default()
    })
    .padding(4);

    // Position the menu at the click coordinates using padding trick
    let x = ctx.x.max(0.0);
    let y = ctx.y.max(0.0);

    // Transparent full-screen backdrop that closes menu on click
    let backdrop = button(Space::new(Fill, Fill))
        .on_press(Message::HideContextMenu)
        .style(|_: &Theme, _| button::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.01).into()),
            ..Default::default()
        });

    stack([
        backdrop.width(Fill).height(Fill).into(),
        container(menu_card)
            .padding(Padding::new(0.0).top(y).left(x))
            .width(Fill)
            .height(Fill)
            .into(),
    ])
    .into()
}

// ---- Toolbar (top action bar) -----------------------------------------------

fn view_toolbar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_accent = state.c_accent();
    let c_success = state.c_success();

    let toolbar_style = |_: &Theme, status: button::Status| {
        let mut s = button::Style::default();
        s.background = None;
        if let button::Status::Hovered = status {
            s.background = Some(theme::BG_HOVER.into());
            s.border = iced::Border { radius: 4.0.into(), ..Default::default() };
        }
        s
    };

    let sidebar_icon = if state.sidebar_collapsed { "|>" } else { "<|" };
    let sidebar_btn = button(text(sidebar_icon).font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(11.0 * scale))
        .on_press(Message::ToggleSidebar)
        .padding(Padding::from([4, 8]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
                s.border = iced::Border { radius: 4.0.into(), ..Default::default() };
            }
            s
        });

    let sep: Element<'_, Message> = container(Space::new(1, 16))
        .style(|_| container::Style { background: Some(theme::BORDER.into()), ..Default::default() })
        .into();

    let active_count = state.tabs.iter().filter(|t| !t.session_id.is_empty()).count();
    let session_info = text(format!("{}/{}", active_count, state.connections.len()))
        .color(theme::TEXT_MUTED).size(10.0 * scale);

    let btn_new = button(text(i18n::t("dialog.new_btn")).color(c_accent).size(12.0 * scale))
        .on_press(Message::ShowConnectDialog).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_proxy = button(text(i18n::t("proxy.title")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowProxyManager).padding(Padding::from([4, 10])).style(toolbar_style);
    let running_tun = state.tunnel_manager.states().iter()
        .filter(|(_, s)| s.is_running()).count();
    let tun_label = if running_tun > 0 {
        format!("{} ({})", i18n::t("tunnel.title"), running_tun)
    } else {
        i18n::t("tunnel.title").to_string()
    };
    let btn_tunnel = button(text(tun_label).color(
        if running_tun > 0 { c_success } else { theme::TEXT_SECONDARY }).size(12.0 * scale))
        .on_press(Message::ShowTunnelManager).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_history = button(text(i18n::t("history.title")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowHistory).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_snippets = button(text(i18n::t("btn.snippets")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowSnippetsPanel).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_broadcast = button(text(i18n::t("btn.broadcast")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowBroadcastDialog).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_settings = button(text(i18n::t("settings.title")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowSettings).padding(Padding::from([4, 10])).style(toolbar_style);

    let bar = row![
        sidebar_btn,
        sep,
        btn_new,
        btn_proxy,
        btn_tunnel,
        btn_snippets,
        btn_broadcast,
        btn_history,
        horizontal_space(),
        session_info,
        btn_settings,
    ]
    .spacing(2)
    .padding(Padding::from([2, 8]))
    .align_y(alignment::Vertical::Center);

    container(bar)
        .width(Fill)
        .height(30)
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 0.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}

// ---- Bottom panel (Monitor / Files / QuickCmd tabs) -------------------------

fn view_bottom_panel(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    // Tab strip
    let mon_active = state.bottom_panel_tab == BottomTab::Monitor;
    let files_active = state.bottom_panel_tab == BottomTab::Files;
    let cmd_active = state.bottom_panel_tab == BottomTab::QuickCmd;

    let tab_monitor = button(
        text(i18n::t("monitor.system")).color(if mon_active { theme::ACCENT } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::Monitor))
    .padding(Padding::from([5, 14]))
    .style(move |_theme: &Theme, status| {
        let mut s = button::Style::default();
        s.background = None;
        if mon_active {
            s.border = iced::Border { color: theme::ACCENT, width: 2.0, radius: 0.0.into() };
        }
        if let button::Status::Hovered = status {
            s.background = Some(theme::BG_HOVER.into());
        }
        s
    });

    let tab_files = button(
        text(i18n::t("bottom.files")).color(if files_active { theme::ACCENT } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::Files))
    .padding(Padding::from([5, 14]))
    .style(move |_theme: &Theme, status| {
        let mut s = button::Style::default();
        s.background = None;
        if files_active {
            s.border = iced::Border { color: theme::ACCENT, width: 2.0, radius: 0.0.into() };
        }
        if let button::Status::Hovered = status {
            s.background = Some(theme::BG_HOVER.into());
        }
        s
    });

    let tab_cmd = button(
        text(i18n::t("bottom.cmd")).color(if cmd_active { theme::ACCENT } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::QuickCmd))
    .padding(Padding::from([5, 14]))
    .style(move |_theme: &Theme, status| {
        let mut s = button::Style::default();
        s.background = None;
        if cmd_active {
            s.border = iced::Border { color: theme::ACCENT, width: 2.0, radius: 0.0.into() };
        }
        if let button::Status::Hovered = status {
            s.background = Some(theme::BG_HOVER.into());
        }
        s
    });

    let tab_strip = container(
        row![tab_monitor, tab_files, tab_cmd].spacing(2).padding(Padding::from([2, 6]))
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        ..Default::default()
    });

    // Panel content based on selected tab
    let panel_content: Element<'_, Message> = match state.bottom_panel_tab {
        BottomTab::Monitor => view_monitor_panel(state),
        BottomTab::Files => {
            // Dual pane: local (left) | separator | remote (right)
            let local_panel = view_local_files(state);
            let remote_panel = view_file_browser(state);
            let sep: Element<'_, Message> = container(Space::new(1, Fill))
                .style(|_| container::Style { background: Some(theme::BORDER.into()), ..Default::default() })
                .into();
            row![
                container(local_panel).width(Fill).height(Fill),
                sep,
                container(remote_panel).width(Fill).height(Fill),
            ].height(Fill).into()
        }
        BottomTab::QuickCmd => view_quick_commands(state),
    };

    column![
        tab_strip,
        container(panel_content).width(Fill).height(Fill),
    ]
    .into()
}

// ---- Monitor panel (horizontal layout for bottom area) ----------------------

fn view_monitor_panel(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let active_session = state.active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.session_id.as_str());
    // Every font size in this panel is scaled by (ui_font_size / 12) so the
    // Appearance slider in Settings updates monitor labels + process table
    // + network table immediately.
    let scale = state.theme_cfg.ui_font_size / 12.0;
    let c_primary = state.theme_cfg.text_primary.to_color();
    let c_danger  = state.theme_cfg.danger.to_color();
    let c_success = state.theme_cfg.success.to_color();
    let pb_color  = Some(state.theme_cfg.progress_bar.to_color());

    let sid = match active_session {
        Some(s) if !s.is_empty() => s,
        _ => return container(text(i18n::t("monitor.connecting")).color(theme::TEXT_MUTED).size(12.0 * scale))
            .padding(Padding::from([12, 12])).into(),
    };

    let stats = state.server_stats.get(sid);
    let processes = state.top_processes.get(sid);

    // ── Column 1: System info ──────────────────────────────────────
    let mut sys_col = column![
        text(i18n::t("monitor.system")).color(c_primary).size(11.0 * scale),
    ].spacing(2);
    let sys_size = 10.0 * scale;
    if let Some(s) = stats {
        sys_col = sys_col.push(sys_row_sized(&i18n::t("monitor.load"), &format!("{:.2} / {:.2} / {:.2}", s.load_1m, s.load_5m, s.load_15m), sys_size));
        sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.cpu"), &i18n::tf("monitor.cpu_cores", &[("count", &s.cpu_cores.to_string())]), sys_size));
        sys_col = sys_col.push(sys_row_sized(&i18n::t("monitor.mem"), &format!("{} / {} MB ({:.0}%)", s.mem_used_mb, s.mem_total_mb, s.mem_percent), sys_size));
        sys_col = sys_col.push(progress_bar_widget_with_color(s.mem_percent, pb_color));
        if !s.disks.is_empty() {
            for d in &s.disks {
                sys_col = sys_col.push(sys_row_sized(&truncate_str(&d.mount_point, 10), &format!("{}/{} ({:.0}%)", d.used, d.total, d.percent), sys_size));
                sys_col = sys_col.push(progress_bar_widget_with_color(d.percent, pb_color));
            }
        }
        if !s.uptime.is_empty() {
            sys_col = sys_col.push(sys_row_sized(&i18n::t("monitor.uptime"), &s.uptime, sys_size));
        }
    } else {
        sys_col = sys_col.push(text(i18n::t("monitor.connecting")).color(theme::TEXT_MUTED).size(11.0 * scale));
    }

    // ── Column 2: Network interfaces ───────────────────────────────
    let mut net_col = column![
        text(i18n::t("monitor.network")).color(c_primary).size(11.0 * scale),
    ].spacing(1);

    if let Some(s) = stats {
        let rx_rate = state.net_rx_rate.get(sid).copied().unwrap_or(0.0);
        let tx_rate = state.net_tx_rate.get(sid).copied().unwrap_or(0.0);
        net_col = net_col.push(
            row![
                text(i18n::t("net.speed")).color(theme::TEXT_MUTED).size(9.0 * scale).width(80),
                text(format!("D {}/s", format_bytes(rx_rate as u64))).color(c_success).size(9.0 * scale).width(80),
                text(format!("U {}/s", format_bytes(tx_rate as u64))).color(c_success).size(9.0 * scale),
            ].spacing(4)
        );

        net_col = net_col.push(
            row![
                text(i18n::t("net.interface")).color(theme::TEXT_MUTED).size(8.0 * scale).width(80),
                text(i18n::t("net.received")).color(theme::TEXT_MUTED).size(8.0 * scale).width(80),
                text(i18n::t("net.sent")).color(theme::TEXT_MUTED).size(8.0 * scale),
            ].spacing(4)
        );

        for (i, iface) in s.interfaces.iter().enumerate() {
            if iface.name == "lo" { continue; }
            let is_physical = iface.name.starts_with("eth") || iface.name.starts_with("en")
                || iface.name.starts_with("wl") || iface.name.starts_with("bond");
            let name_color = if is_physical { c_primary } else { theme::TEXT_MUTED };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };

            let iface_row = row![
                text(truncate_str(&iface.name, 10)).color(name_color).size(9.0 * scale).width(80),
                text(format_bytes(iface.rx_bytes)).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(80),
                text(format_bytes(iface.tx_bytes)).color(theme::TEXT_SECONDARY).size(9.0 * scale),
            ].spacing(4);

            let iface_clone = iface.clone();
            net_col = net_col.push(
                button(
                    container(iface_row)
                        .padding(Padding::from([1, 2]))
                        .width(Fill)
                        .style(move |_| container::Style { background: Some(row_bg.into()), ..Default::default() })
                )
                .on_press(Message::ShowNetworkDetail(iface_clone))
                .padding(0)
                .width(Fill)
                .style(transparent_button_style)
            );
        }

        net_col = net_col.push(
            container(
                row![
                    text(i18n::t("monitor.total")).color(c_accent).size(9.0 * scale).width(80),
                    text(format_bytes(s.net_rx_bytes)).color(c_accent).size(9.0 * scale).width(80),
                    text(format_bytes(s.net_tx_bytes)).color(c_accent).size(9.0 * scale),
                ].spacing(4)
            ).padding(Padding::from([2, 2]))
        );
    }

    // ── Column 3: Processes ────────────────────────────────────────
    let mut proc_col = column![
        text(i18n::t("monitor.processes")).color(c_primary).size(11.0 * scale),
        row![
            text("PID").color(theme::TEXT_MUTED).size(8.0 * scale).width(44),
            text("CPU").color(theme::TEXT_MUTED).size(8.0 * scale).width(32),
            text("MEM").color(theme::TEXT_MUTED).size(8.0 * scale).width(32),
            text("CMD").color(theme::TEXT_MUTED).size(8.0 * scale),
        ].spacing(1),
    ].spacing(1);

    if let Some(procs) = processes {
        let row_size = 9.0 * scale;
        for (i, p) in procs.iter().take(15).enumerate() {
            let color = if p.cpu > 50.0 { c_danger }
                       else if p.cpu > 20.0 { theme::WARNING }
                       else { theme::TEXT_SECONDARY };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
            let pid_val = p.pid;
            let prow = row![
                text(format!("{}", p.pid)).color(color).size(row_size).width(44),
                text(format!("{:.1}", p.cpu)).color(color).size(row_size).width(32),
                text(format!("{:.1}", p.mem)).color(color).size(row_size).width(32),
                text(&p.command).color(color).size(row_size),
            ].spacing(1);
            proc_col = proc_col.push(
                button(
                    container(prow).padding(Padding::from([2, 2])).width(Fill)
                        .style(move |_| container::Style { background: Some(row_bg.into()), ..Default::default() })
                )
                .on_press(Message::InspectProcess(pid_val))
                .padding(0)
                .width(Fill)
                .style(|_: &Theme, status| {
                    let mut s = button::Style::default();
                    s.background = None;
                    if let button::Status::Hovered = status {
                        s.background = Some(theme::BG_HOVER.into());
                    }
                    s
                })
            );
        }
    }

    // ── Layout: 2 main columns (left=sys+net, right=processes) ─────
    let left_combined = column![].push(sys_col).push(net_col).spacing(4);

    let left_panel = scrollable(left_combined).height(Fill);
    let right_panel = scrollable(proc_col).height(Fill);

    // Separator
    let sep: Element<'_, Message> = container(Space::new(1, Fill))
        .style(|_| container::Style {
            background: Some(theme::BORDER.into()),
            ..Default::default()
        })
        .into();

    row![
        container(left_panel).width(Fill).padding(Padding::from([4, 6])),
        sep,
        container(right_panel).width(Fill).padding(Padding::from([4, 4])),
    ]
    .height(Fill)
    .into()
}

// ---- Quick commands panel ---------------------------------------------------

fn view_quick_commands(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    // Input bar at top
    let cmd_input = text_input("Enter command...", &state.quick_cmd_input)
        .on_input(Message::QuickCmdInputChanged)
        .on_submit(Message::SendQuickCmd)
        .padding(6)
        .size(12.0 * scale);

    let send_btn = button(
        text(i18n::t("btn.send")).color(Color::WHITE).size(11.0 * scale)
    )
    .on_press(Message::SendQuickCmd)
    .padding(Padding::from([6, 14]))
    .style(accent_button_style);

    let input_bar = container(
        row![cmd_input, send_btn].spacing(4).align_y(alignment::Vertical::Center)
    )
    .padding(Padding::from([4, 6]))
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        ..Default::default()
    });

    // Recent unique commands list
    let mut col = column![].spacing(2);

    let mut seen = std::collections::HashSet::new();
    let mut count = 0;
    for record in state.cmd_history.iter().rev() {
        if seen.contains(&record.cmd) { continue; }
        seen.insert(record.cmd.clone());
        if count >= 30 { break; }
        count += 1;

        let cmd_display = record.cmd.clone();
        let cmd_action = record.cmd.clone();
        let i = count;
        let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
        let btn = button(
            text(cmd_display).font(Font::MONOSPACE).color(c_primary).size(11.0 * scale)
        )
        .on_press(Message::ReplayCommand(cmd_action))
        .padding(Padding::from([3, 8]))
        .width(Fill)
        .style(move |_theme: &Theme, status| {
            let mut s = button::Style::default();
            s.background = Some(row_bg.into());
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });
        col = col.push(btn);
    }

    if count == 0 {
        col = col.push(
            container(text(i18n::t("history.empty")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([12, 8]))
        );
    }

    column![
        input_bar,
        scrollable(col).height(Fill),
    ].into()
}

// ---- Welcome screen (no active tab) ----------------------------------------

fn view_welcome() -> Element<'static, Message> {
    let wtitle = i18n::t("welcome.title").to_string();
    let wsub = i18n::t("welcome.subtitle").to_string();
    let placeholder = column![
        vertical_space().height(80),
        text(wtitle).size(36).color(theme::TEXT_MUTED),
        text(wsub)
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

// ---- Update notification bar ---------------------------------------------

fn view_update_bar(state: &NeoShell) -> Option<Element<'_, Message>> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let (available, ready, version, progress) = {
        let s = state.updater.state.lock();
        (s.available, s.ready, s.version.clone(), s.download_progress)
    };

    if ready {
        // Update downloaded and ready to install
        Some(
            container(
                row![
                    text(i18n::tf("update.ready", &[("version", &version)]))
                        .color(c_success)
                        .size(12.0 * scale),
                    horizontal_space(),
                    button(text(i18n::t("update.restart")).color(Color::WHITE).size(11.0 * scale))
                        .on_press(Message::RestartForUpdate)
                        .padding(Padding::from([4, 14]))
                        .style(accent_button_style),
                    button(text(i18n::t("update.later")).color(theme::TEXT_MUTED).size(11.0 * scale))
                        .on_press(Message::DismissUpdate)
                        .padding(Padding::from([4, 8]))
                        .style(transparent_button_style),
                ]
                .align_y(alignment::Vertical::Center)
                .padding(Padding::from([6, 16])),
            )
            .width(Fill)
            .style(|_| container::Style {
                background: Some(Color::from_rgb(0.05, 0.15, 0.05).into()),
                border: iced::Border {
                    color: theme::SUCCESS,
                    width: 1.0,
                    radius: 0.0.into(),
                },
                ..Default::default()
            })
            .into(),
        )
    } else if available && progress > 0.0 && progress < 1.0 {
        // Download in progress
        Some(
            container(
                row![text(i18n::tf("update.downloading", &[("version", &version), ("percent", &format!("{:.0}", progress * 100.0))]))
                .color(c_accent)
                .size(12.0 * scale),]
                .padding(Padding::from([6, 16])),
            )
            .width(Fill)
            .style(|_| container::Style {
                background: Some(Color::from_rgb(0.05, 0.05, 0.15).into()),
                ..Default::default()
            })
            .into(),
        )
    } else if available {
        // Update available, not yet downloading
        Some(
            container(
                row![
                    text(i18n::tf("update.available", &[("version", &version)]))
                        .color(c_accent)
                        .size(12.0 * scale),
                    horizontal_space(),
                    button(text(i18n::t("update.download_btn")).color(Color::WHITE).size(11.0 * scale))
                        .on_press(Message::DownloadUpdate)
                        .padding(Padding::from([4, 14]))
                        .style(accent_button_style),
                    button(text("x").color(theme::TEXT_MUTED).size(11.0 * scale))
                        .on_press(Message::DismissUpdate)
                        .padding(Padding::from([4, 6]))
                        .style(transparent_button_style),
                ]
                .align_y(alignment::Vertical::Center)
                .padding(Padding::from([6, 16])),
            )
            .width(Fill)
            .style(|_| container::Style {
                background: Some(Color::from_rgb(0.05, 0.05, 0.15).into()),
                border: iced::Border {
                    color: theme::ACCENT,
                    width: 1.0,
                    radius: 0.0.into(),
                },
                ..Default::default()
            })
            .into(),
        )
    } else {
        None
    }
}

// ---- Tab bar -------------------------------------------------------------

fn view_tab_bar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_success = state.c_success();

    let mut tabs_row = row![].spacing(0);

    for (i, tab) in state.tabs.iter().enumerate() {
        let is_active = state.active_tab == Some(i);
        let bg_color = if is_active {
            theme::BG_TERTIARY
        } else {
            theme::BG_SECONDARY
        };
        let text_color = if is_active { c_primary } else { theme::TEXT_SECONDARY };

        let status_dot = if tab.session_id.is_empty() {
            text("● ").color(theme::WARNING).size(10.0 * scale)
        } else if tab.title.contains("[Reconnecting") {
            text("● ").color(theme::WARNING).size(10.0 * scale)
        } else {
            text("● ").color(c_success).size(10.0 * scale)
        };

        let label = text(&tab.title).color(text_color).size(13.0 * scale);
        let close_btn = button(text("x").color(theme::TEXT_MUTED).size(11.0 * scale))
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

    if state.tabs.is_empty() {
        tabs_row = tabs_row.push(
            container(text(i18n::t("tab.no_tabs")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([8, 14])),
        );
    }

    tabs_row = tabs_row.push(
        button(text("+").color(theme::TEXT_MUTED).size(14.0 * scale))
            .on_press(Message::ShowConnectDialog)
            .padding(Padding::from([6, 10]))
            .style(transparent_button_style),
    );

    tabs_row = tabs_row.push(horizontal_space());

    let history_count = state.cmd_history.len();
    let history_label = if history_count > 0 {
        format!("H:{}", history_count)
    } else {
        "H".to_string()
    };
    tabs_row = tabs_row.push(
        button(text(history_label).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::ShowHistory)
            .padding(Padding::from([6, 10]))
            .style(transparent_button_style),
    );

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
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_success = state.c_success();
    let c_danger = state.c_danger();

    let header = row![
        text(i18n::t("sidebar.connections")).color(c_primary).size(15.0 * scale),
        horizontal_space(),
        button(text("+").color(c_accent).size(18.0 * scale))
            .on_press(Message::ShowForm(None))
            .padding(Padding::from([2, 8]))
            .style(transparent_button_style),
    ]
    .align_y(alignment::Vertical::Center)
    .padding(Padding::from([8, 12]));

    let search = text_input(&i18n::t("sidebar.search"), &state.search_query)
        .on_input(Message::SearchChanged)
        .padding(8)
        .size(13.0 * scale);

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
            i18n::t("sidebar.ungrouped").to_string()
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

        let group_label = text(group_name.clone()).color(theme::TEXT_MUTED).size(11.0 * scale);

        list_col = list_col.push(
            container(group_label).padding(Padding::new(12.0).top(6.0).bottom(2.0)),
        );

        for conn in conns {
            let is_connected = state.tabs.iter().any(|t| t.connection_id == conn.id && !t.session_id.is_empty());
            let dot_color = if is_connected { c_success } else { theme::TEXT_MUTED };
            let status_dot = text("\u{25CF} ").color(dot_color).size(10.0 * scale);
            let name_label = text(&conn.name).color(c_primary).size(13.0 * scale);
            let host_label = text(format!("{}@{}:{}", conn.username, conn.host, conn.port))
                .color(theme::TEXT_MUTED)
                .size(11.0 * scale);

            let proxy_tag: Element<'_, Message> = if conn.proxy_id.is_some() {
                text("P").font(Font::MONOSPACE).color(theme::WARNING).size(9.0 * scale).into()
            } else {
                Space::new(0, 0).into()
            };

            let conn_id = conn.id.clone();
            let conn_id_edit = conn.id.clone();
            let conn_id_del = conn.id.clone();
            let conn_id_test = conn.id.clone();
            let conn_id_clone = conn.id.clone();

            let test_badge: Element<'_, Message> = if let Some(r) = state.conn_test_results.get(&conn.id) {
                if r.ok {
                    text(format!("{} ms", r.latency_ms)).color(c_success).size(9.0 * scale).into()
                } else {
                    text("!").color(c_danger).size(9.0 * scale).into()
                }
            } else { Space::new(0, 0).into() };

            let edit_btn = button(text(i18n::t("btn.edit")).color(theme::TEXT_MUTED).size(9.0 * scale))
                .on_press(Message::ShowForm(Some(conn_id_edit)))
                .padding(Padding::from([2, 4]))
                .style(transparent_button_style);

            let test_btn = button(text(i18n::t("conn.test")).color(c_accent).size(9.0 * scale))
                .on_press(Message::TestConnectionInList(conn_id_test))
                .padding(Padding::from([2, 4]))
                .style(transparent_button_style);

            let clone_btn = button(text(i18n::t("conn.clone")).color(theme::TEXT_MUTED).size(9.0 * scale))
                .on_press(Message::CloneConnection(conn_id_clone))
                .padding(Padding::from([2, 4]))
                .style(transparent_button_style);

            let del_btn = button(text(i18n::t("dialog.delete")).color(c_danger).size(9.0 * scale))
                .on_press(Message::DeleteConnection(conn_id_del))
                .padding(Padding::from([2, 4]))
                .style(transparent_button_style);

            let info_col = column![
                row![status_dot, name_label, proxy_tag, horizontal_space(), test_badge]
                    .spacing(4).align_y(alignment::Vertical::Center),
                host_label,
            ].spacing(2);

            let conn_row = row![
                button(info_col)
                    .on_press(Message::ConnectTo(conn_id))
                    .padding(Padding::from([6, 8]))
                    .width(Fill)
                    .style(sidebar_item_style),
                column![row![test_btn, clone_btn].spacing(0), row![edit_btn, del_btn].spacing(0)].spacing(0),
            ]
            .spacing(0)
            .align_y(alignment::Vertical::Center);

            list_col = list_col.push(conn_row);
        }
    }

    if filtered.is_empty() {
        list_col = list_col.push(
            container(
                text(i18n::t("sidebar.no_results"))
                    .color(theme::TEXT_MUTED)
                    .size(13.0 * scale),
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
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let active_session = state
        .active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.session_id.as_str());

    let stats = active_session.and_then(|sid| state.server_stats.get(sid));
    let processes = active_session.and_then(|sid| state.top_processes.get(sid));

    // Scale factor applied to every monitor font size. 12 is the baseline
    // UI font size; when the user bumps it in Settings → Appearance, every
    // label/value/table-cell in this panel grows proportionally.
    let scale = state.theme_cfg.ui_font_size / 12.0;
    // text_primary / text_muted from the user's theme (defaults fall back
    // to the hard-coded constants if the user hasn't touched the picker).
    let c_primary = state.theme_cfg.text_primary.to_color();

    let mut col = column![].spacing(0);

    // ── Header ──────────────────────────────────────────────────────────
    let header = container(
        row![
            text(i18n::t("monitor.system")).color(c_primary).size(13.0 * scale),
            horizontal_space(),
            button(text("+").color(c_accent).size(16.0 * scale))
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

    let sys_size = 10.0 * scale;

    if let Some(stats) = stats {
        col = col.push(sys_row_sized(&i18n::t("monitor.load"),
            &format!("{:.2} / {:.2} / {:.2}", stats.load_1m, stats.load_5m, stats.load_15m), sys_size));
        col = col.push(sys_row_sized(i18n::t("monitor.cpu"),
            &i18n::tf("monitor.cpu_cores", &[("count", &stats.cpu_cores.to_string())]), sys_size));

        let pb_color = Some(state.theme_cfg.progress_bar.to_color());
        col = col.push(sys_row_sized(&i18n::t("monitor.mem"),
            &format!("{} / {} MB ({:.0}%)", stats.mem_used_mb, stats.mem_total_mb, stats.mem_percent), sys_size));
        col = col.push(progress_bar_widget_with_color(stats.mem_percent, pb_color));

        if stats.disks.is_empty() {
            col = col.push(sys_row_sized(&i18n::t("monitor.disk"),
                &format!("{:.1} / {:.1} GB ({:.0}%)", stats.disk_used_gb, stats.disk_total_gb, stats.disk_percent), sys_size));
            col = col.push(progress_bar_widget_with_color(stats.disk_percent, pb_color));
        } else {
            for d in &stats.disks {
                col = col.push(sys_row_sized(
                    &truncate_str(&d.mount_point, 8),
                    &format!("{}/{} ({:.0}%)", d.used, d.total, d.percent),
                    sys_size,
                ));
                col = col.push(progress_bar_widget_with_color(d.percent, pb_color));
            }
        }

        if !stats.uptime.is_empty() {
            col = col.push(sys_row_sized(&i18n::t("monitor.uptime"), &stats.uptime, sys_size));
        }
    } else {
        col = col.push(
            container(text(i18n::t("monitor.connecting")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([8, 10])),
        );
    }

    col = col.push(sidebar_divider());

    // ── Top Processes ──────────────────────────────────────────────────
    col = col.push(section_header_sized(&i18n::t("monitor.processes"), 12.0 * scale));

    if let Some(procs) = processes {
        let hdr_size = 9.0 * scale;
        let hdr_row = row![
            container(text(i18n::t("monitor.pid")).color(theme::TEXT_MUTED).size(hdr_size)).width(42),
            container(text(i18n::t("monitor.proc_cpu")).color(theme::TEXT_MUTED).size(hdr_size)).width(38),
            container(text(i18n::t("monitor.proc_mem")).color(theme::TEXT_MUTED).size(hdr_size)).width(36),
            container(text(i18n::t("monitor.proc_cmd")).color(theme::TEXT_MUTED).size(hdr_size)).width(Fill),
        ]
        .spacing(2)
        .padding(Padding::from([4, 8]));

        let mut proc_col = column![hdr_row, sidebar_divider()].spacing(0);

        let row_size = 9.0 * scale;
        let bar_size = 7.0 * scale;

        for (i, p) in procs.iter().take(15).enumerate() {
            let bar_len = ((p.cpu / 100.0) * 6.0).ceil() as usize;
            let bar: String = "\u{2588}".repeat(bar_len.min(6));
            let pad: String = "\u{2591}".repeat(6_usize.saturating_sub(bar_len));

            let color = if p.cpu > 50.0 { state.theme_cfg.danger.to_color() }
                       else if p.cpu > 20.0 { theme::WARNING }
                       else { theme::TEXT_SECONDARY };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };

            let proc_row = row![
                container(text(format!("{}", p.pid)).color(color).size(row_size)).width(42),
                container(text(format!("{:.1}", p.cpu)).color(color).size(row_size)).width(38),
                container(text(format!("{:.1}", p.mem)).color(color).size(row_size)).width(36),
                text(truncate_str(&p.command, 10)).color(color).size(row_size),
                horizontal_space(),
                text(format!("{}{}", bar, pad)).color(color).size(bar_size).font(Font::MONOSPACE),
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
            container(text(i18n::t("monitor.loading")).color(theme::TEXT_MUTED).size(11.0 * scale))
                .padding(Padding::from([8, 10])),
        );
    }

    // ── Divider ─────────────────────────────────────────────────────────
    col = col.push(sidebar_divider());

    // ── Network (compact: only physical + total, clickable) ─────────────
    col = col.push(section_header(&i18n::t("monitor.network")));

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
                container(text(truncate_str(&iface.name, 10)).color(c_accent).size(10.0 * scale)).width(Fill),
                container(text(format!("\u{2193}{}", format_bytes(iface.rx_bytes))).color(theme::TEXT_MUTED).size(9.0 * scale))
                    .width(80).align_x(alignment::Horizontal::Right),
                container(text(format!("\u{2191}{}", format_bytes(iface.tx_bytes))).color(theme::TEXT_MUTED).size(9.0 * scale))
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
                container(text(i18n::tf("monitor.virtual_count", &[("count", &virtual_ifs.len().to_string())])).color(theme::TEXT_MUTED).size(10.0 * scale)).width(Fill),
                container(text(format!("\u{2193}{}", format_bytes(virt_rx))).color(theme::TEXT_MUTED).size(9.0 * scale))
                    .width(80).align_x(alignment::Horizontal::Right),
                container(text(format!("\u{2191}{}", format_bytes(virt_tx))).color(theme::TEXT_MUTED).size(9.0 * scale))
                    .width(80).align_x(alignment::Horizontal::Right),
            ].spacing(2).align_y(alignment::Vertical::Center);
            col = col.push(container(virt_row).padding(Padding::from([2, 10])));
        }

        // Total
        let total_row = row![
            container(text(i18n::t("monitor.total")).color(theme::TEXT_SECONDARY).size(10.0 * scale)).width(Fill),
            container(text(format!("\u{2193}{}", format_bytes(stats.net_rx_bytes))).color(theme::TEXT_SECONDARY).size(9.0 * scale))
                .width(80).align_x(alignment::Horizontal::Right),
            container(text(format!("\u{2191}{}", format_bytes(stats.net_tx_bytes))).color(theme::TEXT_SECONDARY).size(9.0 * scale))
                .width(80).align_x(alignment::Horizontal::Right),
        ].spacing(2).align_y(alignment::Vertical::Center);
        col = col.push(container(total_row).padding(Padding::from([2, 10])));

        // Network speed (bytes/sec)
        if let Some(sid) = active_session {
            let rx_rate = state.net_rx_rate.get(sid).copied().unwrap_or(0.0);
            let tx_rate = state.net_tx_rate.get(sid).copied().unwrap_or(0.0);
            col = col.push(
                container(
                    text(i18n::tf("monitor.speed", &[
                        ("down", &format_bytes(rx_rate as u64)),
                        ("up", &format_bytes(tx_rate as u64)),
                    ]))
                    .color(c_success)
                    .size(10.0 * scale)
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

/// Overlay search bar that floats in the upper-right corner of the terminal.
/// Rendered on top of the terminal canvas via `stack![]`. Uses `pick_next`
/// wiring: typing into the input fires `TerminalSearchChanged`, pressing Enter
/// fires `TerminalSearchNext`. ↑ / ↓ / Aa / × are explicit buttons.
fn view_terminal_search_bar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();

    let count_label = if state.term_search_query.is_empty() {
        String::new()
    } else if state.term_search_matches.is_empty() {
        i18n::t("search.no_matches").to_string()
    } else {
        format!(
            "{}/{}",
            state.term_search_current + 1,
            state.term_search_matches.len()
        )
    };

    let input = text_input(
        &i18n::t("search.placeholder"),
        &state.term_search_query,
    )
    .id(text_input::Id::new(TERM_SEARCH_INPUT_ID))
    .on_input(Message::TerminalSearchChanged)
    .on_submit(Message::TerminalSearchNext)
    .padding(Padding::from([4, 8]))
    .size(12.0 * scale)
    .width(Length::Fixed(200.0 * scale));

    let case_active = !state.term_search_case_insensitive;
    let case_btn = button(
        text("Aa")
            .size(11.0 * scale)
            .color(if case_active { Color::WHITE } else { c_primary }),
    )
    .on_press(Message::ToggleTerminalSearchCase)
    .padding(Padding::from([4, 6]))
    .style(move |_, _| button::Style {
        background: Some(if case_active {
            c_accent.into()
        } else {
            theme::BG_TERTIARY.into()
        }),
        text_color: if case_active { Color::WHITE } else { c_primary },
        border: iced::Border {
            radius: 4.0.into(),
            width: 1.0,
            color: theme::BORDER,
        },
        ..Default::default()
    });

    let nav_btn = |label: &'static str, msg: Message| {
        button(text(label).size(12.0 * scale).color(c_primary))
            .on_press(msg)
            .padding(Padding::from([4, 8]))
            .style(|_, _| button::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border {
                    radius: 4.0.into(),
                    width: 1.0,
                    color: theme::BORDER,
                },
                ..Default::default()
            })
    };

    let bar = container(
        row![
            input,
            text(count_label)
                .size(11.0 * scale)
                .color(theme::TEXT_MUTED)
                .width(Length::Fixed(56.0 * scale)),
            nav_btn(i18n::t("search.prev"), Message::TerminalSearchPrev),
            nav_btn(i18n::t("search.next"), Message::TerminalSearchNext),
            case_btn,
            nav_btn(i18n::t("search.close"), Message::TerminalSearchClose),
        ]
        .spacing(6)
        .align_y(alignment::Vertical::Center),
    )
    .padding(Padding::from([8, 10]))
    .style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border {
            radius: 8.0.into(),
            width: 1.0,
            color: theme::BORDER,
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 12.0,
        },
        ..Default::default()
    });

    // Push the bar to the top-right using a column + row with Fill spacers.
    column![
        row![Space::with_width(Fill), bar, Space::with_width(Length::Fixed(12.0))]
            .align_y(alignment::Vertical::Center),
        Space::with_height(Fill),
    ]
    .padding(Padding::from([8, 0]))
    .into()
}

fn section_header(title: &str) -> Element<'static, Message> {
    section_header_sized(title, 12.0)
}

fn section_header_sized(title: &str, size: f32) -> Element<'static, Message> {
    container(text(title.to_string()).color(theme::TEXT_PRIMARY).size(size))
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
    sys_row_sized(label_str, value_str, 10.0)
}

fn sys_row_sized(label_str: &str, value_str: &str, size: f32) -> Element<'static, Message> {
    let l = label_str.to_string();
    let v = value_str.to_string();
    container(
        row![
            container(text(l).color(theme::TEXT_MUTED).size(size)).width(55),
            container(text(v).color(theme::TEXT_SECONDARY).size(size))
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
    progress_bar_widget_with_color(percent, None)
}

fn progress_bar_widget_with_color(percent: f64, user_color: Option<Color>) -> Element<'static, Message> {
    let clamped = percent.max(0.0).min(100.0);
    let width = (clamped / 100.0 * 196.0) as f32;
    // When the user set a custom progress color in the theme editor, use it.
    // Otherwise keep the heat-gauge (green/orange/red) behavior.
    let bar_color = user_color.unwrap_or_else(|| {
        if clamped > 90.0 { theme::DANGER }
        else if clamped > 70.0 { theme::WARNING }
        else { theme::SUCCESS }
    });

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
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            let term_view = TerminalView {
                grid: tab.terminal.clone(),
                selection_start: state.selection_start,
                selection_end: state.selection_end,
                font_size: state.theme_cfg.terminal_font_size,
                session_id: tab.session_id.clone(),
                ssh_manager: state.ssh_manager.clone(),
                terminal_bg: state.theme_cfg.terminal_bg.to_color(),
                terminal_fg: state.theme_cfg.terminal_fg.to_color(),
                search_matches: state.term_search_matches.clone(),
                search_current: if state.term_search_active && !state.term_search_matches.is_empty() {
                    Some(state.term_search_current)
                } else {
                    None
                },
            };

            let canvas_el: Element<'_, Message> =
                canvas(term_view).width(Fill).height(Fill).into();

            if state.term_search_active {
                return stack![canvas_el, view_terminal_search_bar(state)].into();
            }
            return canvas_el;
        }
    }

    // Empty state (fallback)
    let placeholder = column![
        vertical_space().height(80),
        text("NeoShell").size(36.0 * scale).color(theme::TEXT_MUTED),
        text(i18n::t("welcome.select"))
            .size(14.0 * scale)
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
        i18n::tf("transfer.preparing", &[("name", &filename)])
    };

    let progress_text = text(label).color(theme::TEXT_PRIMARY).size(11);
    let cancel_btn = button(text(i18n::t("transfer.cancel")).color(theme::DANGER).size(11))
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

// ---- Local file panel (left side of Files tab) ------------------------------

fn view_local_files(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let path_input = text_input("Local path...", &state.local_path)
        .on_input(Message::LocalPathChanged)
        .on_submit(Message::LocalPathSubmit)
        .padding(4)
        .size(11.0 * scale);

    let refresh_btn = button(text(i18n::t("btn.refresh")).color(c_accent).size(11.0 * scale))
        .on_press(Message::RefreshLocalFiles)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    // Upload button (visible when a file is selected)
    let upload_area: Element<'_, Message> = if let Some(ref sel) = state.selected_local_file {
        let fname = std::path::Path::new(sel).file_name()
            .map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        button(
            text(format!("{} {}", i18n::t("file.send_prefix"), fname)).color(Color::WHITE).size(10.0 * scale)
        )
        .on_press(Message::UploadLocalFile)
        .padding(Padding::from([3, 8]))
        .style(accent_button_style)
        .into()
    } else {
        Space::new(0, 0).into()
    };

    let header = container(
        column![
            row![path_input, refresh_btn].spacing(2).align_y(alignment::Vertical::Center).padding(Padding::from([2, 4])),
            upload_area,
        ].spacing(2)
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        ..Default::default()
    });

    // File list
    let entries = if state.local_entries.is_empty() {
        list_local_dir(&state.local_path)
    } else {
        state.local_entries.clone()
    };

    let mut file_col = column![].spacing(0);

    // Parent directory
    if let Some(parent) = std::path::Path::new(&state.local_path).parent() {
        let parent_path = parent.to_string_lossy().to_string();
        file_col = file_col.push(
            button(text("..").color(c_accent).size(10.0 * scale))
                .on_press(Message::LocalFileClicked(parent_path))
                .padding(Padding::from([2, 6]))
                .width(Fill)
                .style(sidebar_item_style)
        );
    }

    for (i, entry) in entries.iter().enumerate() {
        let (icon, color) = if entry.is_dir { ("D", theme::ACCENT) } else { ("F", theme::TEXT_PRIMARY) };
        let size_str = if entry.is_dir { String::new() } else { format_bytes(entry.size) };
        let path = entry.path.clone();
        let is_selected = state.selected_local_file.as_deref() == Some(&entry.path);
        let row_bg = if is_selected {
            theme::BG_HOVER
        } else if i % 2 == 0 {
            theme::BG_SECONDARY
        } else {
            theme::BG_TERTIARY
        };

        let entry_row = row![
            text(format!("{} {}", icon, &entry.name)).color(color).size(10.0 * scale).width(Fill),
            text(size_str).color(theme::TEXT_MUTED).size(9.0 * scale),
        ].spacing(4);

        file_col = file_col.push(
            button(
                container(entry_row).padding(Padding::from([2, 6])).width(Fill)
                    .style(move |_| container::Style { background: Some(row_bg.into()), ..Default::default() })
            )
            .on_press(Message::LocalFileClicked(path))
            .padding(0).width(Fill)
            .style(|_: &Theme, status| {
                let mut s = button::Style::default();
                if let button::Status::Hovered = status { s.background = Some(theme::BG_HOVER.into()); }
                s
            })
        );
    }

    column![header, scrollable(file_col).height(Fill)]
        .width(Fill)
        .height(Fill)
        .into()
}

fn view_file_browser(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
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

    // Header with editable path input and upload button
    let path_value = if state.path_input.is_empty() {
        current_path.to_string()
    } else {
        state.path_input.clone()
    };

    let path_input = text_input("/path/to/dir", &path_value)
        .on_input(Message::PathInputChanged)
        .on_submit(Message::PathInputSubmit)
        .padding(4)
        .size(12.0 * scale);

    let upload_btn = button(text(i18n::t("filebrowser.upload")).color(c_success).size(11.0 * scale))
        .on_press(Message::UploadFile)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let remote_refresh = button(text(i18n::t("btn.refresh")).color(c_accent).size(11.0 * scale))
        .on_press(Message::RefreshRemoteFiles)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let header = container(
        row![path_input, remote_refresh, upload_btn]
            .spacing(4)
            .align_y(alignment::Vertical::Center),
    )
    .padding(Padding::from([4, 6]))
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

    // Column headers
    let file_header = container(
        row![
            container(text(i18n::t("file.name")).color(theme::TEXT_MUTED).size(10.0 * scale)).width(Fill),
            container(text(i18n::t("file.size")).color(theme::TEXT_MUTED).size(10.0 * scale)).width(80).align_x(alignment::Horizontal::Right),
            container(text(i18n::t("file.modified")).color(theme::TEXT_MUTED).size(10.0 * scale)).width(120).align_x(alignment::Horizontal::Center),
            container(Space::new(70, 0)).width(70),
        ].spacing(4).padding(Padding::from([2, 8]))
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        ..Default::default()
    });

    let mut file_col = column![file_header].spacing(0);

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

                let dl_btn = button(text(i18n::t("btn.download")).color(c_accent).size(10.0 * scale))
                    .on_press(Message::DownloadFile(sid.clone(), full_path.clone()))
                    .padding(Padding::from([1, 3]))
                    .style(transparent_button_style);

                if crate::ssh::is_editable_file(&entry.name) {
                    let edit_btn = button(text(i18n::t("btn.edit")).color(c_success).size(10.0 * scale))
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
                container(text(display_name).color(name_color).size(11.0 * scale)).width(Fill),
                container(text(human_size).color(theme::TEXT_MUTED).size(10.0 * scale))
                    .width(80).align_x(alignment::Horizontal::Right),
                container(text(date_str).color(theme::TEXT_MUTED).size(10.0 * scale))
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
            container(text(i18n::t("filebrowser.loading")).color(theme::TEXT_MUTED).size(12.0 * scale))
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
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = row![
        text(i18n::t("dialog.connect_title")).color(c_primary).size(18.0 * scale),
        horizontal_space(),
        button(text(i18n::t("dialog.new_btn")).color(c_accent).size(13.0 * scale))
            .on_press(Message::ShowForm(None))
            .padding(Padding::from([4, 12]))
            .style(transparent_button_style),
        button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
            .on_press(Message::HideConnectDialog)
            .padding(Padding::from([4, 8]))
            .style(transparent_button_style),
    ]
    .align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(2);

    if state.connections.is_empty() {
        list_col = list_col.push(
            container(text(i18n::t("dialog.no_saved")).color(theme::TEXT_MUTED).size(13.0 * scale))
                .padding(Padding::from([16, 12])),
        );
    } else {
        for conn in &state.connections {
            let conn_id = conn.id.clone();
            let conn_id_edit = conn.id.clone();
            let conn_id_del = conn.id.clone();
            let conn_name = conn.name.clone();

            let info_col = column![
                text(&conn.name).color(c_primary).size(14.0 * scale),
                text(format!("{}@{}:{}", conn.username, conn.host, conn.port))
                    .color(theme::TEXT_MUTED).size(11.0 * scale),
            ].spacing(2);

            let connect_btn = button(
                row![
                    text("\u{25CF} ").color(c_success).size(10.0 * scale),
                    info_col,
                ].spacing(8).align_y(alignment::Vertical::Center)
            )
            .on_press(Message::ConnectTo(conn_id))
            .padding(Padding::from([8, 8]))
            .style(sidebar_item_style);

            let edit_btn = button(text(i18n::t("dialog.edit")).color(c_accent).size(11.0 * scale))
                .on_press(Message::ShowForm(Some(conn_id_edit)))
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style);

            let del_btn = button(text(i18n::t("dialog.delete")).color(c_danger).size(11.0 * scale))
                .on_press(Message::DeleteConnection(conn_id_del))
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style);

            let entry_row = row![
                connect_btn,
                horizontal_space(),
                text(&conn.group).color(theme::TEXT_MUTED).size(10.0 * scale),
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
        let import_all_btn = button(
            text(i18n::tf("dialog.ssh_config_import_all", &[("count", &ssh_configs.len().to_string())]))
                .color(c_accent).size(10.0 * scale)
        )
        .on_press(Message::ImportAllSshConfigs)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

        list_col = list_col.push(
            container(
                row![
                    text(i18n::t("dialog.ssh_config"))
                        .color(theme::TEXT_MUTED)
                        .size(11.0 * scale),
                    horizontal_space(),
                    import_all_btn,
                ].align_y(alignment::Vertical::Center)
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
                text("\u{25CB} ").color(c_accent).size(10.0 * scale),
                column![
                    text(alias_text).color(theme::TEXT_SECONDARY).size(13.0 * scale),
                    text(detail).color(theme::TEXT_MUTED).size(11.0 * scale),
                ]
                .spacing(2),
                horizontal_space(),
                text(i18n::t("dialog.ssh_config_label")).color(theme::TEXT_MUTED).size(9.0 * scale),
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

    let hint = text(i18n::t("dialog.keyboard_hint"))
        .color(theme::TEXT_MUTED)
        .size(10.0 * scale);

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

fn net_detail_labels(iface_name: &str) -> (String, String, String, String, String, String, String, String) {
    let title = i18n::tf("netdetail.title", &[("name", iface_name)]);
    let close = i18n::t("netdetail.close").to_string();
    let lbl_iface = i18n::t("netdetail.interface").to_string();
    let lbl_rx = i18n::t("netdetail.rx").to_string();
    let lbl_tx = i18n::t("netdetail.tx").to_string();
    let lbl_total = i18n::t("netdetail.total_traffic").to_string();
    let lbl_type = i18n::t("netdetail.type").to_string();
    let if_type = if iface_name.starts_with("eth") || iface_name.starts_with("en") {
        i18n::t("netdetail.ethernet")
    } else if iface_name.starts_with("wl") {
        i18n::t("netdetail.wireless")
    } else if iface_name.starts_with("br-") || iface_name.starts_with("docker") {
        i18n::t("netdetail.docker")
    } else if iface_name.starts_with("veth") {
        i18n::t("netdetail.veth")
    } else if iface_name.starts_with("bond") {
        i18n::t("netdetail.bond")
    } else if iface_name.starts_with("tun") || iface_name.starts_with("tap") {
        i18n::t("netdetail.vpn")
    } else if iface_name.starts_with("lo") {
        i18n::t("netdetail.loopback")
    } else {
        i18n::t("netdetail.other")
    }.to_string();
    (title, close, lbl_iface, lbl_rx, lbl_tx, lbl_total, lbl_type, if_type)
}

fn view_network_detail(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let iface = match &state.selected_interface {
        Some(i) => i,
        None => return Space::new(0, 0).into(),
    };

    let (title_str, close_str, lbl_iface, lbl_rx, lbl_tx, lbl_total, lbl_type, if_type_str)
        = net_detail_labels(&iface.name);

    let title = text(title_str).color(c_primary).size(16.0 * scale);

    let close_btn = button(text(close_str).color(theme::TEXT_SECONDARY).size(13.0 * scale))
        .on_press(Message::HideNetworkDetail)
        .padding(Padding::from([6, 16]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), close_btn]
        .align_y(alignment::Vertical::Center);

    let rx_text = format_bytes(iface.rx_bytes);
    let tx_text = format_bytes(iface.tx_bytes);
    let total = format_bytes(iface.rx_bytes + iface.tx_bytes);

    let mut info_col = column![].spacing(8);
    info_col = info_col.push(detail_row(&lbl_iface, &iface.name));
    info_col = info_col.push(detail_row(&lbl_rx, &rx_text));
    info_col = info_col.push(detail_row(&lbl_tx, &tx_text));
    info_col = info_col.push(detail_row(&lbl_total, &total));
    info_col = info_col.push(detail_row(&lbl_type, &if_type_str));

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
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let file_name = state.editor_file_path.as_deref().unwrap_or("untitled");

    let title_text = if state.editor_dirty {
        format!("* {} (modified)", file_name)
    } else {
        format!("  {}", file_name)
    };

    let title = text(title_text).color(c_primary).size(14.0 * scale);

    let save_btn = button(text(i18n::t("editor.save")).color(c_primary).size(13.0 * scale))
        .on_press(Message::SaveEditor)
        .padding(Padding::from([6, 16]))
        .style(accent_button_style);

    let close_btn = button(text(i18n::t("editor.close")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
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

        .size(13.0 * scale)
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

// ---- Proxy manager ----------------------------------------------------------

fn view_proxy_manager(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("proxy.title")).size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideProxyManager)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let add_btn = button(text(i18n::t("proxy.add")).color(c_accent).size(11.0 * scale))
        .on_press(Message::ShowProxyForm(None))
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), add_btn, close_btn]
        .align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(4);

    // Proxy form (inline)
    if state.show_proxy_form {
        let form_title = if state.proxy_edit_id.is_some() {
            i18n::t("proxy.edit")
        } else {
            i18n::t("proxy.add")
        };
        let name_input = text_input(i18n::t("proxy.name"), &state.proxy_form.name)
            .on_input(Message::ProxyFormNameChanged).padding(6).size(12.0 * scale);
        let host_input = text_input(i18n::t("proxy.host"), &state.proxy_form.host)
            .on_input(Message::ProxyFormHostChanged).padding(6).size(12.0 * scale);
        let port_input = text_input(i18n::t("proxy.port"), &state.proxy_form.port)
            .on_input(Message::ProxyFormPortChanged).padding(6).size(12.0 * scale).width(80);
        let user_input = text_input(i18n::t("proxy.username"), &state.proxy_form.username)
            .on_input(Message::ProxyFormUsernameChanged).padding(6).size(12.0 * scale);
        let pass_input = text_input(i18n::t("proxy.password"), &state.proxy_form.password)
            .on_input(Message::ProxyFormPasswordChanged).padding(6).size(12.0 * scale).secure(true);

        let type_socks = button(
            text("SOCKS5H").color(if state.proxy_form.proxy_type == "socks5h" { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("socks5h".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "socks5h" { accent_button_style } else { transparent_button_style });
        let type_http = button(
            text("HTTP").color(if state.proxy_form.proxy_type == "http" { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("http".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "http" { accent_button_style } else { transparent_button_style });
        let type_bastion = button(
            text(i18n::t("proxy.type.bastion")).color(if state.proxy_form.proxy_type == "bastion" { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("bastion".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "bastion" { accent_button_style } else { transparent_button_style });

        let save_btn = button(text(i18n::t("proxy.save")).color(c_primary).size(11.0 * scale))
            .on_press(Message::SaveProxy).padding(Padding::from([4, 12])).style(accent_button_style);
        let cancel_btn = button(text(i18n::t("proxy.cancel")).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::HideProxyForm).padding(Padding::from([4, 8])).style(transparent_button_style);

        let is_bastion = state.proxy_form.proxy_type == "bastion";
        let mut form_content = column![
            text(form_title).color(c_primary).size(13.0 * scale),
            name_input,
            row![type_socks, type_http, type_bastion].spacing(4),
            row![host_input, port_input].spacing(4),
            user_input,
        ].spacing(6).padding(10).width(Fill);

        if is_bastion {
            let auth_pwd_btn = button(
                text(i18n::t("proxy.bastion.auth_password"))
                    .color(if state.proxy_form.auth_type == "password" || state.proxy_form.auth_type.is_empty() { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED })
                    .size(11.0 * scale)
            ).on_press(Message::ProxyFormAuthTypeChanged("password".into())).padding(Padding::from([4, 8]))
             .style(if state.proxy_form.auth_type == "password" || state.proxy_form.auth_type.is_empty() { accent_button_style } else { transparent_button_style });
            let auth_key_btn = button(
                text(i18n::t("proxy.bastion.auth_key"))
                    .color(if state.proxy_form.auth_type == "key" { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED })
                    .size(11.0 * scale)
            ).on_press(Message::ProxyFormAuthTypeChanged("key".into())).padding(Padding::from([4, 8]))
             .style(if state.proxy_form.auth_type == "key" { accent_button_style } else { transparent_button_style });

            form_content = form_content.push(row![auth_pwd_btn, auth_key_btn].spacing(4));

            if state.proxy_form.auth_type == "key" {
                let key_input = text_input(i18n::t("proxy.bastion.key_path"), &state.proxy_form.private_key)
                    .on_input(Message::ProxyFormPrivateKeyChanged).padding(6).size(12.0 * scale);
                let browse_btn = button(text(i18n::t("proxy.bastion.browse")).color(c_accent).size(11.0 * scale))
                    .on_press(Message::ProxyFormBrowsePrivateKey).padding(Padding::from([4, 8]))
                    .style(transparent_button_style);
                let passphrase_input = text_input(i18n::t("proxy.bastion.passphrase"), &state.proxy_form.passphrase)
                    .on_input(Message::ProxyFormPassphraseChanged).padding(6).size(12.0 * scale).secure(true);
                form_content = form_content
                    .push(row![key_input, browse_btn].spacing(4))
                    .push(passphrase_input);
            } else {
                form_content = form_content.push(pass_input);
            }
        } else {
            form_content = form_content.push(pass_input);
        }

        form_content = form_content.push(row![cancel_btn, save_btn].spacing(8));

        list_col = list_col.push(
            container(form_content).style(|_| container::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                ..Default::default()
            })
        );
    }

    // Proxy list
    if state.proxies.is_empty() && state.proxy_edit_id.is_none() {
        list_col = list_col.push(
            container(text(i18n::t("proxy.empty")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([16, 8])),
        );
    }
    for proxy in &state.proxies {
        let pid = proxy.id.clone();
        let pid2 = proxy.id.clone();
        let pid3 = proxy.id.clone();

        let type_label = format!("{}", proxy.proxy_type);
        let addr = format!("{}:{}", proxy.host, proxy.port);

        let test_status: Element<'_, Message> = if let Some(result) = state.proxy_test_results.get(&proxy.id) {
            if result.reachable {
                text(format!("{} {}ms", i18n::t("proxy.ok"), result.latency_ms))
                    .color(c_success).size(10.0 * scale).into()
            } else {
                text(format!("{} {}", i18n::t("proxy.fail"), result.error.as_deref().unwrap_or("")))
                    .color(c_danger).size(10.0 * scale).into()
            }
        } else {
            text("").size(1.0 * scale).into()
        };

        let test_btn = button(text(i18n::t("proxy.test")).color(c_accent).size(10.0 * scale))
            .on_press(Message::TestProxy(pid.clone())).padding(Padding::from([2, 6])).style(transparent_button_style);
        let edit_btn = button(text(i18n::t("proxy.edit")).color(theme::TEXT_SECONDARY).size(10.0 * scale))
            .on_press(Message::ShowProxyForm(Some(pid2))).padding(Padding::from([2, 6])).style(transparent_button_style);
        let del_btn = button(text(i18n::t("proxy.delete")).color(c_danger).size(10.0 * scale))
            .on_press(Message::DeleteProxy(pid3)).padding(Padding::from([2, 6])).style(transparent_button_style);

        let entry = row![
            column![
                text(&proxy.name).color(c_primary).size(12.0 * scale),
                row![text(type_label).color(theme::TEXT_MUTED).size(10.0 * scale), text(addr).color(theme::TEXT_MUTED).size(10.0 * scale)].spacing(8),
            ].spacing(2).width(Fill),
            test_status,
            test_btn,
            edit_btn,
            del_btn,
        ].spacing(4).align_y(alignment::Vertical::Center);

        list_col = list_col.push(
            container(entry).padding(Padding::from([6, 10])).width(Fill)
                .style(|_| container::Style {
                    background: Some(theme::BG_TERTIARY.into()),
                    border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                    ..Default::default()
                })
        );
    }

    let content = column![header, scrollable(list_col).height(Fill)]
        .spacing(10).padding(16).width(420);

    let card = container(content).height(Fill).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        shadow: iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.4), offset: iced::Vector::new(-4.0, 0.0), blur_radius: 16.0 },
        ..Default::default()
    });

    let overlay = row![horizontal_space(), card];
    container(overlay).width(Fill).height(Fill)
        .style(|_| container::Style { background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.3).into()), ..Default::default() })
        .into()
}

// ---- Command history panel --------------------------------------------------

fn view_history_panel(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("history.title")).size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideHistory)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let clear_btn = button(text(i18n::t("history.clear")).color(c_danger).size(11.0 * scale))
        .on_press(Message::ClearHistory)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), clear_btn, close_btn]
        .align_y(alignment::Vertical::Center);

    let filter_input = text_input(i18n::t("history.filter"), &state.history_filter)
        .on_input(Message::HistoryFilterChanged)
        .padding(8)
        .size(13.0 * scale);

    let filter_lower = state.history_filter.to_lowercase();

    // Build list (newest first), filtered
    let mut list_col = column![].spacing(2);
    let mut shown = 0;
    for record in state.cmd_history.iter().rev() {
        if !filter_lower.is_empty() && !record.cmd.to_lowercase().contains(&filter_lower) {
            continue;
        }
        if shown >= 100 { break; }
        shown += 1;

        let elapsed = record.timestamp.elapsed();
        let ago = if elapsed.as_secs() < 60 {
            format!("{}s", elapsed.as_secs())
        } else if elapsed.as_secs() < 3600 {
            format!("{}m", elapsed.as_secs() / 60)
        } else {
            format!("{}h", elapsed.as_secs() / 3600)
        };

        let cmd_text = text(truncate_str(&record.cmd, 50))
            .font(Font::MONOSPACE)
            .color(c_primary)
            .size(12.0 * scale);
        let session_text = text(truncate_str(&record.session_title, 15))
            .color(theme::TEXT_MUTED)
            .size(10.0 * scale);
        let ago_text = text(ago).color(theme::TEXT_MUTED).size(10.0 * scale);

        let replay_btn = button(text(">").font(Font::MONOSPACE).color(c_success).size(12.0 * scale))
            .on_press(Message::ReplayCommand(record.cmd.clone()))
            .padding(Padding::from([2, 8]))
            .style(transparent_button_style);

        let entry_row = row![
            column![cmd_text, session_text].spacing(2).width(Fill),
            ago_text,
            replay_btn,
        ]
        .spacing(8)
        .align_y(alignment::Vertical::Center);

        let i = shown;
        let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
        list_col = list_col.push(
            button(entry_row)
                .on_press(Message::ReplayCommand(record.cmd.clone()))
                .padding(Padding::from([6, 10]))
                .width(Fill)
                .style(move |_theme: &Theme, status| {
                    let mut s = button::Style::default();
                    s.background = Some(row_bg.into());
                    if let button::Status::Hovered = status {
                        s.background = Some(theme::BG_HOVER.into());
                    }
                    s
                }),
        );
    }

    if shown == 0 {
        list_col = list_col.push(
            container(text(i18n::t("history.empty")).color(theme::TEXT_MUTED).size(13.0 * scale))
                .padding(Padding::from([20, 12])),
        );
    }

    let content = column![
        header,
        filter_input,
        scrollable(list_col).height(Fill),
    ]
    .spacing(8)
    .padding(16)
    .width(500)
    .height(Fill);

    let card = container(content)
        .height(Fill)
        .style(|_| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.4),
                offset: iced::Vector::new(-4.0, 0.0),
                blur_radius: 16.0,
            },
            ..Default::default()
        });

    // Slide in from right
    let overlay = row![horizontal_space(), card];

    container(overlay)
        .width(Fill)
        .height(Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.3).into()),
            ..Default::default()
        })
        .into()
}

// ---- Settings menu (dropdown-style overlay) --------------------------------

fn view_settings_menu(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();

    let title = text(i18n::t("settings.title")).size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideSettings)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), close_btn]
        .align_y(alignment::Vertical::Center);

    let lang_label = text(i18n::t("settings.language")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let lang_value = if state.locale == "zh-CN" { "中文" } else { "English" };
    let lang_btn = button(
        text(lang_value).color(c_accent).size(13.0 * scale)
    )
    .on_press(Message::ToggleLanguage)
    .padding(Padding::from([4, 12]))
    .style(transparent_button_style);
    let lang_row = row![lang_label, horizontal_space(), lang_btn]
        .align_y(alignment::Vertical::Center);

    let scale_label = text(i18n::t("settings.scale")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let scale_pct = format!("{:.0}%", state.ui_scale * 100.0);
    let scale_down = button(text("-").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetUiScale((state.ui_scale - 0.1).max(0.5)))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let scale_up = button(text("+").color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetUiScale((state.ui_scale + 0.1).min(3.0)))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let scale_row = row![scale_label, horizontal_space(), scale_down, text(scale_pct).color(c_primary).size(13.0 * scale), scale_up]
        .spacing(4)
        .align_y(alignment::Vertical::Center);

    let sidebar_label = text(i18n::t("settings.sidebar")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let sidebar_icon = if state.sidebar_collapsed { "OFF" } else { "ON" };
    let sidebar_btn = button(text(sidebar_icon).color(c_accent).size(14.0 * scale))
        .on_press(Message::ToggleSidebar)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let sidebar_row = row![sidebar_label, horizontal_space(), sidebar_btn]
        .align_y(alignment::Vertical::Center);

    let font_label = text(i18n::t("settings.font_size")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let font_pct = format!("{:.0}px", state.font_size);
    let font_down = button(text("-").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetFontSize(state.font_size - 1.0))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let font_up = button(text("+").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetFontSize(state.font_size + 1.0))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let font_row = row![font_label, horizontal_space(), font_down, text(font_pct).color(c_primary).size(13.0 * scale), font_up]
        .spacing(4)
        .align_y(alignment::Vertical::Center);

    // Divider
    let divider: Element<'_, Message> = container(Space::new(Fill, 1))
        .width(Fill)
        .style(|_| container::Style {
            background: Some(theme::BORDER.into()),
            ..Default::default()
        })
        .into();

    let proxy_btn = button(
        row![
            text(i18n::t("proxy.title")).color(theme::TEXT_SECONDARY).size(13.0 * scale),
            horizontal_space(),
            text(">").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(12.0 * scale),
        ]
        .align_y(alignment::Vertical::Center)
    )
    .on_press(Message::ShowProxyManager)
    .padding(Padding::from([8, 0]))
    .width(Fill)
    .style(transparent_button_style);

    let about_btn = button(
        row![
            text(i18n::t("settings.about")).color(theme::TEXT_SECONDARY).size(13.0 * scale),
            horizontal_space(),
            text(">").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(12.0 * scale),
        ]
        .align_y(alignment::Vertical::Center)
    )
    .on_press(Message::ShowAbout)
    .padding(Padding::from([8, 0]))
    .width(Fill)
    .style(transparent_button_style);

    // --- Appearance section: color zones + font sizes + picker --------------
    let appearance = view_theme_editor(state);

    let menu_content = column![
        header,
        lang_row,
        font_row,
        scale_row,
        sidebar_row,
        divider,
        appearance,
        proxy_btn,
        about_btn,
    ]
    .spacing(12)
    .padding(20)
    .width(360);

    let card = container(scrollable(menu_content).height(Fill))
        .max_height(620)
        .style(|_| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border { color: theme::BORDER, width: 1.0, radius: 8.0.into() },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.4),
                offset: iced::Vector::new(0.0, 4.0),
                blur_radius: 16.0,
            },
            ..Default::default()
        });

    // Position near bottom-right (above status bar)
    let overlay_content = column![
        vertical_space(),
        row![horizontal_space(), container(card).padding(Padding::from([0, 16]))],
    ];

    container(overlay_content)
        .width(Fill)
        .height(Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.3).into()),
            ..Default::default()
        })
        .into()
}

// ---- Theme editor (colors + per-zone font sizes) --------------------------

fn view_theme_editor(state: &NeoShell) -> Element<'_, Message> {
    use crate::ui::theme_config::ThemeZone;
    use iced::widget::slider;

    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_danger = state.c_danger();
    let t = &state.theme_cfg;

    let section_title = text(i18n::t("theme.title"))
        .color(c_primary).size(13.0 * scale);

    let mut swatches = column![].spacing(6);
    for zone in ThemeZone::ALL {
        let rgb = zone.get(t);
        let selected = state.theme_editing_zone == Some(zone);
        let swatch = container(Space::new(24, 20))
            .style(move |_| container::Style {
                background: Some(rgb.to_color().into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                ..Default::default()
            });
        let label_color = if selected { c_accent } else { theme::TEXT_SECONDARY };
        let label = text(i18n::t(zone.label_key())).color(label_color).size(12.0 * scale);
        let hex = text(rgb.to_hex()).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale);

        let press_msg = if selected {
            Message::ThemeCloseZone
        } else {
            Message::ThemeSelectZone(zone)
        };
        let row_el = button(
            row![swatch, label, horizontal_space(), hex]
                .spacing(10)
                .align_y(alignment::Vertical::Center)
        )
        .on_press(press_msg)
        .padding(Padding::from([4, 6]))
        .width(Fill)
        .style(if selected { sidebar_item_style } else { transparent_button_style });
        swatches = swatches.push(row_el);

        if selected {
            let current = rgb;
            let r_slider = slider(0..=255u8, current.r, Message::ThemeRChanged).step(1u8);
            let g_slider = slider(0..=255u8, current.g, Message::ThemeGChanged).step(1u8);
            let b_slider = slider(0..=255u8, current.b, Message::ThemeBChanged).step(1u8);
            let r_lbl = text(format!("R {:>3}", current.r)).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale).width(50);
            let g_lbl = text(format!("G {:>3}", current.g)).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale).width(50);
            let b_lbl = text(format!("B {:>3}", current.b)).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale).width(50);
            let hex_input = text_input("#RRGGBB", &current.to_hex())
                .on_input(Message::ThemeHexChanged)
                .padding(4).size(11.0 * scale).width(90);
            let preview = container(Space::new(Fill, 24))
                .style(move |_| container::Style {
                    background: Some(current.to_color().into()),
                    border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                    ..Default::default()
                });
            let editor = column![
                row![r_lbl, r_slider].spacing(6).align_y(alignment::Vertical::Center),
                row![g_lbl, g_slider].spacing(6).align_y(alignment::Vertical::Center),
                row![b_lbl, b_slider].spacing(6).align_y(alignment::Vertical::Center),
                row![hex_input, horizontal_space(), preview].spacing(8),
            ].spacing(6).padding(8).width(Fill);
            let editor_container = container(editor).style(|_| container::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 6.0.into() },
                ..Default::default()
            });
            swatches = swatches.push(editor_container);
        }
    }

    let term_size = t.terminal_font_size;
    let ui_size = t.ui_font_size;
    let term_size_row = row![
        text(i18n::t("theme.terminal_font_size")).color(theme::TEXT_SECONDARY).size(12.0 * scale).width(Fill),
        text(format!("{:.0}px", term_size)).font(Font::MONOSPACE).color(c_primary).size(11.0 * scale).width(40),
    ].align_y(alignment::Vertical::Center);
    let term_slider = slider(8.0..=28.0f32, term_size, Message::ThemeTerminalFontSize).step(1.0f32);

    let ui_size_row = row![
        text(i18n::t("theme.ui_font_size")).color(theme::TEXT_SECONDARY).size(12.0 * scale).width(Fill),
        text(format!("{:.0}px", ui_size)).font(Font::MONOSPACE).color(c_primary).size(11.0 * scale).width(40),
    ].align_y(alignment::Vertical::Center);
    let ui_slider = slider(10.0..=18.0f32, ui_size, Message::ThemeUiFontSize).step(1.0f32);

    let reset_btn = button(text(i18n::t("theme.reset")).color(c_danger).size(11.0 * scale))
        .on_press(Message::ThemeReset)
        .padding(Padding::from([4, 10]))
        .style(transparent_button_style);

    column![
        section_title,
        swatches,
        term_size_row, term_slider,
        ui_size_row, ui_slider,
        row![horizontal_space(), reset_btn],
    ]
    .spacing(8)
    .into()
}

// ---- About dialog ----------------------------------------------------------

fn view_about_dialog(_state: &NeoShell) -> Element<'static, Message> {
    // About dialog returns 'static; use static theme consts rather than state lookups.
    let title = text(i18n::t("about.title").to_string()).size(22).color(theme::TEXT_PRIMARY);
    let version_str = i18n::tf("about.version", &[("version", env!("CARGO_PKG_VERSION"))]);
    let version = text(version_str).size(14).color(theme::ACCENT);
    let desc = text(i18n::t("about.desc").to_string()).size(13).color(theme::TEXT_SECONDARY);
    let tech = text(i18n::t("about.tech").to_string()).size(11).color(theme::TEXT_MUTED);
    let copyright = text(i18n::t("about.copyright").to_string()).size(11).color(theme::TEXT_MUTED);

    let close_btn = button(
        text(i18n::t("about.close").to_string()).color(theme::TEXT_SECONDARY).size(13)
    )
    .on_press(Message::HideAbout)
    .padding(Padding::from([6, 20]))
    .style(transparent_button_style);

    let content = column![
        text("NeoShell").font(Font::MONOSPACE).size(32).color(theme::ACCENT),
        title,
        version,
        vertical_space().height(8),
        desc,
        vertical_space().height(4),
        tech,
        vertical_space().height(12),
        copyright,
        vertical_space().height(8),
        close_btn,
    ]
    .spacing(4)
    .align_x(alignment::Horizontal::Center)
    .padding(32)
    .width(360);

    let card = container(content)
        .style(|_| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border { color: theme::BORDER, width: 1.0, radius: 12.0.into() },
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

// ---- Keyboard shortcuts help ----------------------------------------------

fn view_shortcuts_help() -> Element<'static, Message> {
    // Platform-specific modifier key label. On macOS the command key is the
    // primary modifier, on Windows/Linux it's Ctrl. Same binding code — the
    // `modifiers.command()` check in update() maps to whichever is native.
    #[cfg(target_os = "macos")]
    let m_key = "⌘";
    #[cfg(not(target_os = "macos"))]
    let m_key = "Ctrl";

    // Groups of shortcuts. Each entry is (accelerator-label, i18n-desc-key).
    // The accelerator column is rendered in a monospace pill so Cmd/Ctrl
    // columns stay aligned regardless of translation width.
    let groups: &[(&'static str, Vec<(String, &'static str)>)] = &[
        (
            "shortcuts.group.tabs",
            vec![
                (format!("{}+T", m_key), "shortcuts.desc.connect"),
                (format!("{}+W", m_key), "shortcuts.desc.close_tab"),
                (format!("{}+1…9", m_key), "shortcuts.desc.switch_tab"),
                ("Ctrl+Tab".into(), "shortcuts.desc.next_tab"),
                ("Ctrl+Shift+Tab".into(), "shortcuts.desc.prev_tab"),
            ],
        ),
        (
            "shortcuts.group.terminal",
            vec![
                // Platform-aware copy/paste accelerators. Win/Linux uses
                // Ctrl+Shift+C/V so plain Ctrl+C still sends SIGINT.
                (
                    if cfg!(target_os = "macos") { format!("{}+V", m_key) } else { "Ctrl+Shift+V".into() },
                    "shortcuts.desc.paste",
                ),
                (
                    if cfg!(target_os = "macos") { format!("{}+C", m_key) } else { "Ctrl+Shift+C".into() },
                    "shortcuts.desc.copy",
                ),
                ("Drag".into(),       "shortcuts.desc.mouse_select"),
                ("Right-click".into(),"shortcuts.desc.right_click"),
                ("Ctrl+C".into(),     "shortcuts.desc.sigint"),
                (format!("{}+F", m_key), "shortcuts.desc.search"),
                ("Enter".into(), "shortcuts.desc.search_next"),
                ("Esc".into(), "shortcuts.desc.search_close"),
            ],
        ),
        (
            "shortcuts.group.panels",
            vec![
                (format!("{}+J", m_key), "shortcuts.desc.bottom_toggle"),
                (format!("{}+H", m_key), "shortcuts.desc.history"),
                (format!("{}+/", m_key), "shortcuts.desc.help"),
                ("F1".into(), "shortcuts.desc.help"),
            ],
        ),
        (
            "shortcuts.group.other",
            vec![
                (format!("{}+S", m_key), "shortcuts.desc.editor_save"),
                ("Esc".into(), "shortcuts.desc.close_dialog"),
                (format!("{}+Shift+Q", m_key), "shortcuts.desc.quit"),
            ],
        ),
    ];

    let title = text(i18n::t("shortcuts.title").to_string())
        .size(22).color(theme::TEXT_PRIMARY);

    let mut rows_col = column![].spacing(14);
    for (group_key, entries) in groups {
        rows_col = rows_col.push(
            text(i18n::t(group_key).to_string())
                .color(theme::TEXT_MUTED)
                .size(11)
        );
        let mut group_col = column![].spacing(4);
        for (accel, desc_key) in entries {
            group_col = group_col.push(
                row![
                    container(
                        text(accel.clone())
                            .font(Font::MONOSPACE)
                            .color(theme::ACCENT)
                            .size(12)
                    )
                    .padding(Padding::from([2, 8]))
                    .style(|_| container::Style {
                        background: Some(theme::BG_TERTIARY.into()),
                        border: iced::Border {
                            radius: 4.0.into(),
                            width: 1.0,
                            color: theme::BORDER,
                        },
                        ..Default::default()
                    })
                    .width(Length::Fixed(150.0)),
                    text(i18n::t(desc_key).to_string())
                        .color(theme::TEXT_SECONDARY)
                        .size(12),
                ]
                .spacing(12)
                .align_y(alignment::Vertical::Center),
            );
        }
        rows_col = rows_col.push(group_col);
    }

    let close_btn = button(
        text(i18n::t("shortcuts.close").to_string()).color(theme::TEXT_SECONDARY).size(13)
    )
    .on_press(Message::ToggleShortcutsHelp)
    .padding(Padding::from([6, 20]))
    .style(transparent_button_style);

    let content = column![
        title,
        vertical_space().height(14),
        rows_col,
        vertical_space().height(18),
        close_btn,
    ]
    .align_x(alignment::Horizontal::Center)
    .padding(28)
    .width(500);

    let card = container(content).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 12.0.into() },
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

// ---- Error dialog ----------------------------------------------------------

fn view_error_dialog(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("err.title")).size(16.0 * scale).color(c_danger);

    // Full error, wrapped; no truncation
    let msg = text(state.error_message.clone()).size(13.0 * scale).color(c_primary);

    let log_btn = button(text(i18n::t("err.view_log")).color(c_accent).size(12.0 * scale))
        .on_press(Message::ShowLogViewer)
        .padding(Padding::from([6, 14]))
        .style(transparent_button_style);

    let dismiss_btn = button(text(i18n::t("err.dismiss")).color(c_primary).size(12.0 * scale))
        .on_press(Message::DismissErrorDialog)
        .padding(Padding::from([6, 18]))
        .style(accent_button_style);

    let content = column![
        title,
        vertical_space().height(8),
        scrollable(container(msg).padding(8)).height(180),
        vertical_space().height(8),
        row![log_btn, horizontal_space(), dismiss_btn]
            .align_y(alignment::Vertical::Center),
    ]
    .spacing(4)
    .padding(24)
    .width(540);

    let card = container(content).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::DANGER, width: 1.0, radius: 10.0.into() },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    });

    container(card)
        .width(Fill).height(Fill)
        .center_x(Fill).center_y(Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.6).into()),
            ..Default::default()
        })
        .into()
}

// ---- Log viewer ------------------------------------------------------------

fn view_log_viewer(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("log.title")).size(18.0 * scale).color(c_primary);
    let path_hint = {
        let p = crate::log_file_path();
        text(format!("{}", p.display())).color(theme::TEXT_MUTED).size(10.0 * scale)
    };

    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(13.0 * scale))
        .on_press(Message::HideLogViewer)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let refresh_btn = button(text(i18n::t("log.refresh")).color(c_accent).size(11.0 * scale))
        .on_press(Message::RefreshLogViewer)
        .padding(Padding::from([4, 10]))
        .style(transparent_button_style);

    let open_folder_btn = button(text(i18n::t("log.open_folder")).color(c_accent).size(11.0 * scale))
        .on_press(Message::OpenLogFolder)
        .padding(Padding::from([4, 10]))
        .style(transparent_button_style);

    let header = row![
        title, horizontal_space(), refresh_btn, open_folder_btn, close_btn,
    ].spacing(6).align_y(alignment::Vertical::Center);

    // Render log content as monospace text, scrollable
    let body = text(state.log_viewer_content.clone())
        .font(Font::MONOSPACE)
        .color(theme::TEXT_SECONDARY)
        .size(11.0 * scale);

    let content = column![
        header,
        path_hint,
        vertical_space().height(8),
        scrollable(container(body).padding(10).width(Fill)).height(Fill),
    ]
    .spacing(4)
    .padding(20)
    .width(780)
    .height(520);

    let card = container(content).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 10.0.into() },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    });

    container(card)
        .width(Fill).height(Fill)
        .center_x(Fill).center_y(Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.55).into()),
            ..Default::default()
        })
        .into()
}

// ---- Broadcast dialog ------------------------------------------------------

fn view_broadcast_dialog(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_success = state.c_success();

    let title = text(i18n::t("broadcast.title")).color(c_primary).size(16.0 * scale);
    let close_btn = button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideBroadcastDialog).padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), close_btn].align_y(alignment::Vertical::Center);
    let hint = text(i18n::t("broadcast.hint")).color(theme::TEXT_MUTED).size(11.0 * scale);

    let cmd_input = text_input("echo hello", &state.broadcast_text)
        .on_input(Message::BroadcastTextChanged)
        .on_submit(Message::BroadcastSendNow)
        .padding(8).size(13.0 * scale).font(Font::MONOSPACE);

    let sessions_title = text(i18n::t("broadcast.sessions")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
    let mut sessions_col = column![].spacing(4);
    let active_tabs: Vec<_> = state.tabs.iter().filter(|t| !t.session_id.is_empty()).collect();
    if active_tabs.is_empty() {
        sessions_col = sessions_col.push(
            text(i18n::t("broadcast.empty")).color(theme::TEXT_MUTED).size(11.0 * scale)
        );
    } else {
        for tab in active_tabs {
            let sid = tab.session_id.clone();
            let selected = state.broadcast_selected.contains(&sid);
            let marker = if selected { "●" } else { "○" };
            let marker_color = if selected { c_success } else { theme::TEXT_MUTED };
            let label = text(format!(" {}", tab.title)).color(c_primary).size(12.0 * scale);
            let row_btn = button(
                row![text(marker).color(marker_color).size(12.0 * scale), label]
                    .align_y(alignment::Vertical::Center)
            )
            .on_press(Message::BroadcastToggleSession(sid))
            .padding(Padding::from([4, 8]))
            .width(Fill)
            .style(sidebar_item_style);
            sessions_col = sessions_col.push(row_btn);
        }
    }

    let count = state.broadcast_selected.len();
    let send_btn = button(
        text(format!("{} ({})", i18n::t("broadcast.send"), count))
            .color(theme::TEXT_PRIMARY).size(12.0 * scale)
    )
    .on_press(Message::BroadcastSendNow)
    .padding(Padding::from([6, 16]))
    .style(accent_button_style);

    let body = column![header, hint, cmd_input, sessions_title, scrollable(sessions_col).height(240),
        row![horizontal_space(), send_btn]
    ].spacing(10).padding(20).width(520);

    let card = container(body).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 10.0.into() },
        shadow: iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.5), offset: iced::Vector::new(0.0, 4.0), blur_radius: 20.0 },
        ..Default::default()
    });

    container(card).width(Fill).height(Fill).center_x(Fill).center_y(Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.55).into()),
            ..Default::default()
        })
        .into()
}

// ---- Snippets panel --------------------------------------------------------

fn view_snippets_panel(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_danger = state.c_danger();

    let title = text(i18n::t("snippet.title")).color(c_primary).size(16.0 * scale);
    let close_btn = button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideSnippetsPanel).padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let header = row![title, horizontal_space(), close_btn].align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(4);
    if state.snippets.is_empty() {
        list_col = list_col.push(text(i18n::t("snippet.empty")).color(theme::TEXT_MUTED).size(12.0 * scale));
    } else {
        for sn in &state.snippets {
            let id = sn.id.clone();
            let id2 = sn.id.clone();
            let id3 = sn.id.clone();
            let snip_row = row![
                column![
                    text(sn.name.clone()).color(c_primary).size(13.0 * scale),
                    text(sn.body.lines().next().unwrap_or("").to_string())
                        .font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale),
                ].spacing(2).width(Fill),
                button(text(i18n::t("snippet.send")).color(c_accent).size(10.0 * scale))
                    .on_press(Message::SnippetSend(id))
                    .padding(Padding::from([2, 6])).style(transparent_button_style),
                button(text(i18n::t("btn.edit")).color(theme::TEXT_SECONDARY).size(10.0 * scale))
                    .on_press(Message::SnippetEdit(Some(id2)))
                    .padding(Padding::from([2, 6])).style(transparent_button_style),
                button(text("×").color(c_danger).size(12.0 * scale))
                    .on_press(Message::SnippetDelete(id3))
                    .padding(Padding::from([2, 6])).style(transparent_button_style),
            ].spacing(4).align_y(alignment::Vertical::Center);
            list_col = list_col.push(
                container(snip_row).padding(Padding::from([6, 10])).width(Fill)
                    .style(|_| container::Style {
                        background: Some(theme::BG_TERTIARY.into()),
                        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                        ..Default::default()
                    })
            );
        }
    }

    let form_title_key = if state.snippet_edit_id.is_some() { "btn.edit" } else { "snippet.new" };
    let form_title = text(i18n::t(form_title_key)).color(theme::TEXT_SECONDARY).size(12.0 * scale);
    let name_input = text_input(i18n::t("snippet.name_placeholder"), &state.snippet_form_name)
        .on_input(Message::SnippetFormNameChanged)
        .padding(6).size(12.0 * scale);
    let body_input = text_input(i18n::t("snippet.body_placeholder"), &state.snippet_form_body)
        .on_input(Message::SnippetFormBodyChanged)
        .padding(6).size(12.0 * scale).font(Font::MONOSPACE);
    let save_btn = button(text(i18n::t("snippet.save")).color(theme::TEXT_PRIMARY).size(11.0 * scale))
        .on_press(Message::SnippetSave).padding(Padding::from([4, 12])).style(accent_button_style);
    let cancel_btn: Element<'_, Message> = if state.snippet_edit_id.is_some() {
        button(text(i18n::t("form.cancel")).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::SnippetEdit(None)).padding(Padding::from([4, 8]))
            .style(transparent_button_style).into()
    } else {
        Space::new(0, 0).into()
    };

    let body = column![
        header,
        scrollable(list_col).height(280),
        container(Space::new(Fill, 1)).style(|_| container::Style {
            background: Some(theme::BORDER.into()), ..Default::default()
        }),
        form_title,
        name_input,
        body_input,
        row![horizontal_space(), cancel_btn, save_btn].spacing(8),
    ].spacing(10).padding(20).width(560);

    let card = container(body).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 10.0.into() },
        shadow: iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.5), offset: iced::Vector::new(0.0, 4.0), blur_radius: 20.0 },
        ..Default::default()
    });

    container(card).width(Fill).height(Fill).center_x(Fill).center_y(Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.55).into()),
            ..Default::default()
        })
        .into()
}

// ---- Status bar ------------------------------------------------------------

fn view_status_bar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_accent = state.c_accent();
    let c_danger = state.c_danger();

    let version = text(i18n::tf("status.version", &[("version", env!("CARGO_PKG_VERSION"))]))
        .color(theme::TEXT_MUTED).size(10.0 * scale);

    let session_text = if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            text(&tab.title).color(theme::TEXT_SECONDARY).size(10.0 * scale)
        } else {
            text("").size(10.0 * scale)
        }
    } else {
        text(i18n::t("status.no_session")).color(theme::TEXT_MUTED).size(10.0 * scale)
    };

    let tab_count = text(format!("{}T", state.tabs.len()))
        .font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(9.0 * scale);

    let hist_count = text(format!("{}H", state.cmd_history.len()))
        .font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(9.0 * scale);

    let lang_label = if state.locale == "zh-CN" { "EN" } else { "CN" };
    let lang_btn = button(text(lang_label).font(Font::MONOSPACE).color(c_accent).size(9.0 * scale))
        .on_press(Message::ToggleLanguage)
        .padding(Padding::from([1, 5]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            s.border = iced::Border { color: theme::BORDER, width: 1.0, radius: 3.0.into() };
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });

    let mod_key = if cfg!(target_os = "macos") { "Cmd" } else { "Ctrl" };
    let shortcuts_str = i18n::t("status.shortcuts").replace("{mod}", mod_key);
    let shortcuts = text(shortcuts_str).color(theme::TEXT_MUTED).size(9.0 * scale);

    let help_btn = button(text("?").font(Font::MONOSPACE).color(c_accent).size(10.0 * scale))
        .on_press(Message::ToggleShortcutsHelp)
        .padding(Padding::from([1, 5]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            s.border = iced::Border { color: theme::BORDER, width: 1.0, radius: 3.0.into() };
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });

    let log_btn = button(text(i18n::t("status.log")).color(c_accent).size(9.0 * scale))
        .on_press(Message::ShowLogViewer)
        .padding(Padding::from([1, 5]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            s.border = iced::Border { color: theme::BORDER, width: 1.0, radius: 3.0.into() };
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });

    let quit_btn = button(text(i18n::t("status.quit")).color(c_danger).size(9.0 * scale))
        .on_press(Message::QuitApp)
        .padding(Padding::from([1, 6]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            s.border = iced::Border { color: theme::DANGER, width: 1.0, radius: 3.0.into() };
            if let button::Status::Hovered = status {
                s.background = Some(Color::from_rgba(1.0, 0.3, 0.3, 0.15).into());
            }
            s
        });

    let bar = row![version, shortcuts, horizontal_space(), tab_count, hist_count, log_btn, help_btn, lang_btn, quit_btn, session_text]
        .spacing(10)
        .padding(Padding::from([3, 10]))
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

// ---- Tunnel manager ---------------------------------------------------------

fn view_tunnel_manager(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("tunnel.title")).size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideTunnelManager)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let add_btn = button(text(i18n::t("tunnel.add")).color(c_accent).size(11.0 * scale))
        .on_press(Message::ShowTunnelForm(None))
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);
    let header = row![title, horizontal_space(), add_btn, close_btn]
        .align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(4);

    // Inline form
    if state.show_tunnel_form {
        let form_title = if state.tunnel_edit_id.is_some() { i18n::t("tunnel.edit") } else { i18n::t("tunnel.add") };
        let name_in = text_input(i18n::t("tunnel.name"), &state.tunnel_form.name)
            .on_input(Message::TunnelFormNameChanged).padding(6).size(12.0 * scale);
        let host_in = text_input(i18n::t("tunnel.ssh_host"), &state.tunnel_form.ssh_host)
            .on_input(Message::TunnelFormHostChanged).padding(6).size(12.0 * scale);
        let port_in = text_input(i18n::t("tunnel.ssh_port"), &state.tunnel_form.ssh_port)
            .on_input(Message::TunnelFormPortChanged).padding(6).size(12.0 * scale).width(80);
        let user_in = text_input(i18n::t("tunnel.user"), &state.tunnel_form.username)
            .on_input(Message::TunnelFormUserChanged).padding(6).size(12.0 * scale);

        let auth_pwd_btn = button(text(i18n::t("proxy.bastion.auth_password"))
            .color(if state.tunnel_form.auth_type != "key" { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(11.0 * scale))
            .on_press(Message::TunnelFormAuthTypeChanged("password".into()))
            .padding(Padding::from([4, 8]))
            .style(if state.tunnel_form.auth_type != "key" { accent_button_style } else { transparent_button_style });
        let auth_key_btn = button(text(i18n::t("proxy.bastion.auth_key"))
            .color(if state.tunnel_form.auth_type == "key" { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(11.0 * scale))
            .on_press(Message::TunnelFormAuthTypeChanged("key".into()))
            .padding(Padding::from([4, 8]))
            .style(if state.tunnel_form.auth_type == "key" { accent_button_style } else { transparent_button_style });

        let secret: Element<'_, Message> = if state.tunnel_form.auth_type == "key" {
            let key_in = text_input(i18n::t("proxy.bastion.key_path"), &state.tunnel_form.private_key)
                .on_input(Message::TunnelFormKeyChanged).padding(6).size(12.0 * scale);
            let browse = button(text(i18n::t("proxy.bastion.browse")).color(c_accent).size(11.0 * scale))
                .on_press(Message::TunnelFormBrowseKey)
                .padding(Padding::from([4, 8])).style(transparent_button_style);
            let pass = text_input(i18n::t("proxy.bastion.passphrase"), &state.tunnel_form.passphrase)
                .on_input(Message::TunnelFormPassphraseChanged).padding(6).size(12.0 * scale).secure(true);
            column![row![key_in, browse].spacing(4), pass].spacing(6).into()
        } else {
            text_input(i18n::t("proxy.password"), &state.tunnel_form.password)
                .on_input(Message::TunnelFormPasswordChanged).padding(6).size(12.0 * scale).secure(true).into()
        };

        let fwd_label = text(i18n::t("tunnel.forwards_label")).color(theme::TEXT_SECONDARY).size(11.0 * scale);
        let fwd_hint = text(i18n::t("tunnel.forwards_hint")).color(theme::TEXT_MUTED).size(10.0 * scale);
        let fwd_in = text_input("", &state.tunnel_form.forwards_text)
            .on_input(Message::TunnelFormForwardsChanged).padding(6).size(12.0 * scale);

        let save = button(text(i18n::t("proxy.save")).color(c_primary).size(11.0 * scale))
            .on_press(Message::SaveTunnel).padding(Padding::from([4, 12])).style(accent_button_style);
        let cancel = button(text(i18n::t("proxy.cancel")).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::HideTunnelForm).padding(Padding::from([4, 8])).style(transparent_button_style);

        let form_col = column![
            text(form_title).color(c_primary).size(13.0 * scale),
            name_in,
            row![host_in, port_in].spacing(4),
            user_in,
            row![auth_pwd_btn, auth_key_btn].spacing(4),
            secret,
            fwd_label,
            fwd_hint,
            fwd_in,
            row![cancel, save].spacing(8),
        ].spacing(6).padding(10).width(Fill);

        list_col = list_col.push(
            container(form_col).style(|_| container::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                ..Default::default()
            })
        );
    }

    if state.tunnels.is_empty() && !state.show_tunnel_form {
        list_col = list_col.push(
            container(text(i18n::t("tunnel.empty")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([16, 8])),
        );
    }

    let states = state.tunnel_manager.states();
    for t in &state.tunnels {
        let id = t.id.clone();
        let tid1 = id.clone();
        let tid2 = id.clone();
        let tid3 = id.clone();
        let st = states.get(&id).cloned().unwrap_or(crate::tunnel::TunnelState::Stopped);

        let (status_text, status_color) = match &st {
            crate::tunnel::TunnelState::Stopped => (i18n::t("tunnel.stopped").to_string(), theme::TEXT_MUTED),
            crate::tunnel::TunnelState::Starting => (i18n::t("tunnel.starting").to_string(), theme::WARNING),
            crate::tunnel::TunnelState::Running { connections, .. } =>
                (format!("{} ({})", i18n::t("tunnel.running"), connections), theme::SUCCESS),
            crate::tunnel::TunnelState::Failed(e) => (format!("ERR: {}", e), theme::DANGER),
        };

        let running = st.is_running();
        let run_btn: Element<'_, Message> = if running {
            button(text(i18n::t("tunnel.stop")).color(c_danger).size(10.0 * scale))
                .on_press(Message::StopTunnel(tid1))
                .padding(Padding::from([2, 6])).style(transparent_button_style).into()
        } else {
            button(text(i18n::t("tunnel.start")).color(c_success).size(10.0 * scale))
                .on_press(Message::StartTunnel(tid1))
                .padding(Padding::from([2, 6])).style(transparent_button_style).into()
        };
        let edit = button(text(i18n::t("proxy.edit")).color(theme::TEXT_SECONDARY).size(10.0 * scale))
            .on_press(Message::ShowTunnelForm(Some(tid2)))
            .padding(Padding::from([2, 6])).style(transparent_button_style);
        let del = button(text(i18n::t("proxy.delete")).color(c_danger).size(10.0 * scale))
            .on_press(Message::DeleteTunnel(tid3))
            .padding(Padding::from([2, 6])).style(transparent_button_style);

        let forwards_summary = t.forwards.iter()
            .map(|f| format!("{}→{}:{}", f.local_port, f.remote_host, f.remote_port))
            .collect::<Vec<_>>().join(", ");

        let entry = row![
            column![
                text(&t.name).color(c_primary).size(12.0 * scale),
                text(format!("{}@{}:{}", t.username, t.ssh_host, t.ssh_port)).color(theme::TEXT_MUTED).size(10.0 * scale),
                text(forwards_summary).color(theme::TEXT_MUTED).size(10.0 * scale),
                text(status_text).color(status_color).size(10.0 * scale),
            ].spacing(2).width(Fill),
            run_btn, edit, del,
        ].spacing(4).align_y(alignment::Vertical::Center);

        list_col = list_col.push(
            container(entry).padding(Padding::from([6, 10])).width(Fill)
                .style(|_| container::Style {
                    background: Some(theme::BG_TERTIARY.into()),
                    border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                    ..Default::default()
                })
        );
    }

    let content = column![header, scrollable(list_col).height(Fill)]
        .spacing(10).padding(16).width(480);

    let card = container(content).height(Fill).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        shadow: iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.4), offset: iced::Vector::new(-4.0, 0.0), blur_radius: 16.0 },
        ..Default::default()
    });
    let overlay = row![horizontal_space(), card];
    container(overlay).width(Fill).height(Fill).into()
}

// ---- Connection form (modal overlay) -------------------------------------

fn view_connection_form_overlay(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title_text = if state.edit_id.is_some() {
        i18n::t("form.edit_title")
    } else {
        i18n::t("form.new_title")
    };

    let title = text(title_text).size(20.0 * scale).color(c_primary);

    let name_input = labeled_input(&i18n::t("form.name"), &state.form.name, Message::FormNameChanged);
    let host_input = labeled_input(&i18n::t("form.host"), &state.form.host, Message::FormHostChanged);
    let port_input = labeled_input(&i18n::t("form.port"), &state.form.port, Message::FormPortChanged);
    let user_input = labeled_input(
        &i18n::t("form.username"),
        &state.form.username,
        Message::FormUsernameChanged,
    );

    let auth_row = row![
        button(
            text(i18n::t("form.password"))
                .color(if state.form.auth_type == "password" {
                    theme::TEXT_PRIMARY
                } else {
                    theme::TEXT_MUTED
                })
                .size(13.0 * scale)
        )
        .on_press(Message::FormAuthTypeChanged("password".into()))
        .padding(Padding::from([6, 12]))
        .style(if state.form.auth_type == "password" {
            accent_button_style
        } else {
            transparent_button_style
        }),
        button(
            text(i18n::t("form.private_key"))
                .color(if state.form.auth_type == "key" {
                    theme::TEXT_PRIMARY
                } else {
                    theme::TEXT_MUTED
                })
                .size(13.0 * scale)
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

    let auth_label = text(i18n::t("form.auth_type")).color(theme::TEXT_SECONDARY).size(12.0 * scale);

    // Placeholder hint for secret fields during edit (empty = keep existing)
    let is_editing = state.edit_id.is_some();
    let secret_placeholder = if is_editing { i18n::t("form.keep_existing") } else { "" };

    let auth_fields: Element<'_, Message> = if state.form.auth_type == "key" {
        let key_label = text(i18n::t("form.key_path")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let key_input = text_input(secret_placeholder, &state.form.private_key)
            .on_input(Message::FormPrivateKeyChanged)
            .padding(8)
            .size(14.0 * scale);
        let browse_btn = button(text(i18n::t("form.browse")).color(c_accent).size(12.0 * scale))
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

        let pass_label = text(i18n::t("form.passphrase")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let pass_input = text_input(secret_placeholder, &state.form.passphrase)
            .on_input(Message::FormPassphraseChanged)
            .padding(8)
            .size(14.0 * scale);

        column![key_field, column![pass_label, pass_input].spacing(4)]
            .spacing(12)
            .into()
    } else {
        let pw_label = text(i18n::t("form.password")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let pw_input = text_input(secret_placeholder, &state.form.password)
            .on_input(Message::FormPasswordChanged)
            .secure(true)
            .padding(8)
            .size(14.0 * scale);
        column![pw_label, pw_input].spacing(4).into()
    };

    let group_input: Element<'_, Message> = {
        let label_text = text(i18n::t("form.group")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let input = text_input("", &state.form.group)
            .on_input(Message::FormGroupChanged)
            .on_submit(Message::SaveForm)
            .padding(8)
            .size(14.0 * scale);
        column![label_text, input].spacing(4).into()
    };

    // Proxy selection
    let proxy_label = text(i18n::t("proxy.select")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
    let mut proxy_row = row![
        button(
            text(i18n::t("proxy.none"))
                .color(if state.form.proxy_id.is_empty() { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED })
                .size(11.0 * scale)
        )
        .on_press(Message::FormProxyChanged(String::new()))
        .padding(Padding::from([4, 8]))
        .style(if state.form.proxy_id.is_empty() { accent_button_style } else { transparent_button_style }),
    ].spacing(4);
    for p in &state.proxies {
        let is_sel = state.form.proxy_id == p.id;
        let label = format!("{} ({})", p.name, p.proxy_type);
        let pid = p.id.clone();
        proxy_row = proxy_row.push(
            button(text(label).color(if is_sel { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(11.0 * scale))
                .on_press(Message::FormProxyChanged(pid))
                .padding(Padding::from([4, 8]))
                .style(if is_sel { accent_button_style } else { transparent_button_style }),
        );
    }
    let proxy_input: Element<'_, Message> = column![proxy_label, proxy_row].spacing(4).into();

    // Error: show truncated, single-line
    let error_row: Element<'_, Message> = if state.error_message.is_empty() {
        Space::new(0, 0).into()
    } else {
        let short = if state.error_message.len() > 60 {
            format!("{}...", &state.error_message[..57])
        } else {
            state.error_message.clone()
        };
        text(short).color(c_danger).size(11.0 * scale).into()
    };

    // Test result row
    let test_row: Element<'_, Message> = if state.form_testing {
        text(i18n::t("form.testing")).color(c_accent).size(12.0 * scale).into()
    } else if let Some(r) = &state.form_test_result {
        if r.ok {
            text(format!("{} {} ms", i18n::t("form.test_ok"), r.latency_ms))
                .color(c_success).size(12.0 * scale).into()
        } else {
            let msg = r.error.clone().unwrap_or_else(|| "unknown".into());
            column![
                text(format!("{} [{}]", i18n::t("form.test_fail"), r.stage))
                    .color(c_danger).size(12.0 * scale),
                text(msg).color(theme::TEXT_MUTED).size(11.0 * scale),
            ].spacing(2).into()
        }
    } else { Space::new(0, 0).into() };

    let test_btn: Element<'_, Message> = if state.form_testing {
        button(text(i18n::t("form.testing")).color(theme::TEXT_MUTED).size(14.0 * scale))
            .padding(Padding::from([8, 16]))
            .style(transparent_button_style).into()
    } else {
        button(text(i18n::t("form.test")).color(c_accent).size(14.0 * scale))
            .on_press(Message::TestFormConnection)
            .padding(Padding::from([8, 16]))
            .style(transparent_button_style).into()
    };

    let buttons = row![
        button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(14.0 * scale))
            .on_press(Message::HideForm)
            .padding(Padding::from([8, 20]))
            .style(transparent_button_style),
        horizontal_space(),
        test_btn,
        button(text(i18n::t("form.save")).color(c_primary).size(14.0 * scale))
            .on_press(Message::SaveForm)
            .padding(Padding::from([8, 20]))
            .style(accent_button_style),
    ]
    .spacing(12)
    .align_y(alignment::Vertical::Center);

    let form_content = column![
        title,
        name_input,
        host_input,
        port_input,
        user_input,
        auth_label,
        auth_row,
        auth_fields,
        group_input,
        proxy_input,
    ]
    .spacing(12);

    // Scrollable form + fixed bottom (test result + error + buttons)
    let form = column![
        scrollable(form_content).height(Fill),
        test_row,
        error_row,
        buttons,
    ]
    .spacing(8)
    .width(440)
    .padding(24);

    let card = container(form).max_height(650).style(|_theme| container::Style {
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
    font_size: f32,
    /// Carried so the canvas can propagate local-grid resizes to the remote
    /// SSH PTY — otherwise the server keeps formatting `ls`, `top`, etc. for
    /// the initial 120×40 while the client only has space for ~90 columns,
    /// and the last few columns of every row get clipped off-screen.
    session_id: String,
    ssh_manager: Arc<crate::ssh::SshManager>,
    /// User-configured terminal background / default foreground colors.
    terminal_bg: Color,
    #[allow(dead_code)]
    terminal_fg: Color,
    /// All Cmd+F matches in absolute-line coords; painted as yellow/orange
    /// rectangles on top of the cell background.
    search_matches: Vec<crate::terminal::SearchMatch>,
    /// Index into `search_matches` for the currently selected match; painted
    /// in a brighter color than the rest.
    search_current: Option<usize>,
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

        // Resize terminal grid to fit canvas bounds.
        // cell_h was 1.5x font_size — too loose, top/htop output looked
        // double-spaced. 1.2x matches iTerm2/Windows Terminal defaults.
        let font_size: f32 = self.font_size;
        let cell_w = font_size * 0.6;
        let cell_h = font_size * 1.2;
        let new_cols = ((bounds.width / cell_w).floor() as usize).max(2);
        let new_rows = ((bounds.height / cell_h).floor() as usize).max(2);
        let needs_resize = new_cols != grid.cols || new_rows != grid.rows;
        drop(grid); // release lock

        if needs_resize {
            self.grid.lock().resize(new_cols, new_rows);
            state.cache.clear(); // force redraw at new size
            // Propagate to the remote SSH PTY so the server wraps its output
            // to the actual visible width. Without this, `ls`, `top`, etc.
            // output gets clipped because the server still thinks we have
            // the original 120 columns.
            if !self.session_id.is_empty() {
                let _ = self.ssh_manager.resize(
                    &self.session_id,
                    new_cols as u32,
                    new_rows as u32,
                );
            }
        }

        let grid = self.grid.lock();

        let bg_color = self.terminal_bg;
        let geometry = state.cache.draw(renderer, bounds.size(), |frame| {
            // Background fill — user-configured terminal background.
            frame.fill_rectangle(Point::ORIGIN, bounds.size(), bg_color);

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

                            // Render at 1.1x monospace size — keeps CJK legible
                            // without overflowing the 2-cell slot. (Previously
                            // 1.3x caused rows with wide chars to drift visually,
                            // especially in TUI programs like top/htop/nmon.)
                            frame.fill_text(canvas::Text {
                                content: cell.c.to_string(),
                                position: Point::new(
                                    x as f32 * cell_w,
                                    y as f32 * cell_h,
                                ),
                                color: fg,
                                size: Pixels(font_size * 1.1),
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

            // Cmd+F search highlights — draw after content so hits are clearly
            // visible even over colored backgrounds. Current match uses a
            // brighter fill than the rest.
            if !self.search_matches.is_empty() {
                let sb_len = grid.scrollback.len();
                let top_abs = sb_len.saturating_sub(grid.scroll_offset);
                let yellow = Color::from_rgba(0.95, 0.85, 0.20, 0.35);
                let orange = Color::from_rgba(0.95, 0.50, 0.10, 0.70);
                for (i, m) in self.search_matches.iter().enumerate() {
                    if m.abs_line < top_abs { continue; }
                    let vy = m.abs_line - top_abs;
                    if vy >= grid.rows { continue; }
                    let span = m.col_end.saturating_sub(m.col_start);
                    if span == 0 { continue; }
                    let color = if self.search_current == Some(i) { orange } else { yellow };
                    frame.fill_rectangle(
                        Point::new(m.col_start as f32 * cell_w, vy as f32 * cell_h),
                        Size::new(span as f32 * cell_w, cell_h),
                        color,
                    );
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
fn pixel_to_grid_with(x: f32, y: f32, sidebar_w: f32, top_offset: f32, font_size: f32) -> Option<(usize, usize)> {
    let term_x = x - sidebar_w;
    let term_y = y - top_offset;
    if term_x < 0.0 || term_y < 0.0 {
        return None;
    }

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

/// Parse /proc-based process detail output into structured fields.
fn parse_process_detail(pid: u32, output: &str) -> ProcessDetailInfo {
    let mut fields = Vec::new();
    let mut children = Vec::new();
    let mut threads = Vec::new();
    let mut net_conns = Vec::new();
    let mut listen_ports = Vec::new();
    let mut open_fds = Vec::new();

    fields.push(("PID".into(), pid.to_string()));

    // Output format: ___TAG___\nbody\n___TAG2___\nbody2\n...
    // split("___") gives: ["", "TAG", "\nbody\n", "TAG2", "\nbody2\n", ...]
    // Tags are at odd indices (1,3,5,...), bodies at even indices (2,4,6,...)
    let sections: Vec<&str> = output.split("___").collect();
    let mut i = 1; // start at first tag
    while i + 1 < sections.len() {
        let tag = sections[i].trim();
        let body = sections.get(i + 1).map(|s| s.trim()).unwrap_or("");
        i += 2;
        match tag {
            "STATUS" => {
                for line in body.lines() {
                    if let Some((key, val)) = line.split_once(':') {
                        let key = key.trim();
                        // Replace tabs with spaces for clean display
                        let val: String = val.trim().chars()
                            .map(|c| if c == '\t' { ' ' } else { c })
                            .collect();
                        let val = val.trim().to_string();
                        match key {
                            "Name" | "State" | "PPid" | "Threads" => {
                                fields.push((key.into(), val));
                            }
                            "Uid" => {
                                // "0  0  0  0" → take first value
                                let first = val.split_whitespace().next().unwrap_or(&val);
                                fields.push(("Uid".into(), first.to_string()));
                            }
                            "Gid" => {
                                let first = val.split_whitespace().next().unwrap_or(&val);
                                fields.push(("Gid".into(), first.to_string()));
                            }
                            "VmRSS" | "VmSize" | "VmPeak" | "VmSwap" => {
                                fields.push((key.into(), val));
                            }
                            "voluntary_ctxt_switches" => {
                                fields.push(("CtxSwitch(V)".into(), val));
                            }
                            "nonvoluntary_ctxt_switches" => {
                                fields.push(("CtxSwitch(NV)".into(), val));
                            }
                            _ => {}
                        }
                    }
                }
            }
            "CMDLINE" => {
                if !body.is_empty() { fields.push(("Cmdline".into(), body.into())); }
            }
            "IO" => {
                for line in body.lines() {
                    if let Some((key, val)) = line.split_once(':') {
                        let (k, v) = (key.trim(), val.trim());
                        if let Ok(bytes) = v.parse::<u64>() {
                            fields.push((k.into(), format_bytes(bytes)));
                        }
                    }
                }
            }
            "CWD" => {
                if !body.is_empty() { fields.push(("CWD".into(), body.into())); }
            }
            "EXE" => {
                if !body.is_empty() { fields.push(("Executable".into(), body.into())); }
            }
            "FD_COUNT" => {
                if !body.is_empty() { fields.push(("Open FDs".into(), body.into())); }
            }
            "OOM" => {
                if !body.is_empty() { fields.push(("OOM Score".into(), body.into())); }
            }
            "PS" => {
                let parts: Vec<&str> = body.split_whitespace().collect();
                if parts.len() >= 8 {
                    fields.push(("User".into(), parts[2].into()));
                    fields.push(("Nice".into(), parts[3].into()));
                    fields.push(("VSZ".into(), format!("{} KB", parts[4])));
                    fields.push(("RSS".into(), format!("{} KB", parts[5])));
                    fields.push(("Elapsed".into(), parts[6].into()));
                    fields.push(("Stat".into(), parts[7].into()));
                }
            }
            "CHILDREN" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() { children.push(l.to_string()); }
                }
            }
            "THREADS" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() { threads.push(l.to_string()); }
                }
            }
            "NET" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() { net_conns.push(l.to_string()); }
                }
            }
            "LISTEN" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() { listen_ports.push(l.to_string()); }
                }
            }
            "LIMITS" => {
                for line in body.lines() {
                    let l = line.trim();
                    if l.is_empty() || l.starts_with("Limit") { continue; }
                    // Format: "Max open files            1048576              1048576              files"
                    // Clean up: replace multi-spaces/tabs → single space
                    let clean: String = l.split_whitespace().collect::<Vec<&str>>().join(" ");
                    if !clean.is_empty() {
                        fields.push(("Limit".into(), clean));
                    }
                }
            }
            "FDS" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() && !l.starts_with("total") {
                        // Extract just the symlink target: "... -> /path"
                        if let Some(pos) = l.find("->") {
                            open_fds.push(l[pos+3..].trim().to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    ProcessDetailInfo { pid, fields, children, threads, net_conns, listen_ports, open_fds }
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
