use iced::widget::{
    button, canvas, container, horizontal_space, row, stack, text,
    text_editor, text_input, vertical_space, Space,
};
use iced::{
    alignment, event, keyboard, mouse, time, Color, Element, Fill, Font,
    Length, Padding, Pixels, Point, Rectangle, Renderer, Size, Subscription,
    Task, Theme,
};

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use zeroize::Zeroize;

use crate::ssh::{
    ConfirmedEntry, EntryKind, FileEntry, ProcessInfo, ServerStats, SshEvent, SshManager, TransferProgress,
};
use crate::storage::{ConnectionConfig, ConnectionInfo, ConnectionStore};
use crate::terminal::{MouseButton, MouseMode, TerminalGrid};
use crate::i18n;
use crate::ui::{theme, theme_config};
use crate::updater::Updater;


// Split out of this file; each module holds one concern of the app.
mod auth;
mod events;
mod files;
mod focus;
mod forms;
mod groups;
mod history;
mod monitor;
mod palette;
mod settings;
mod style;
mod terminal_view;
mod view;
use auth::*;
use events::*;
use files::*;
use focus::*;
use forms::*;
use groups::*;
use history::*;
use monitor::*;
use palette::*;
use settings::*;
use style::*;
use terminal_view::*;
use view::*;

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

/// The embedded Symbols Nerd Font (loaded in `run()`), for the icon glyphs the
/// CJK font lacks: the sidebar's group chevrons and fold-all toggle.
const NERD_ICON_FONT: Font = Font::with_name("Symbols Nerd Font Mono");

/// Rendered width of the connection sidebar. The layout, the sidebar's own
/// container and the terminal selection hit-test all read this one value —
/// they used to disagree (280 declared, 220 rendered and hit-tested).
const SIDEBAR_W: f32 = 240.0;

/// Thickness of the draggable divider between the two panes of a split tab.
const SPLIT_DIVIDER: f32 = 6.0;
/// Neither split pane may be dragged below 15% of the area.
const SPLIT_MIN: f32 = 0.15;
const SPLIT_MAX: f32 = 0.85;

/// 4pt spacing scale, with a 2pt half-step for dense data rows. New layout
/// code picks from here; existing `.spacing()` calls were only moved when
/// they sat off the scale.
mod space {
    pub const XXS: f32 = 2.0;
    pub const XS: f32 = 4.0;
    pub const S: f32 = 8.0;
    pub const M: f32 = 12.0;
    pub const L: f32 = 16.0;
    pub const XL: f32 = 24.0;
}

// ---------------------------------------------------------------------------
// ZMODEM protocol detection
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
    /// An event for a session whose tab was still connecting, held back
    /// ahead of everything still queued until the tab shows the session
    /// (see [`next_ssh_event`]).
    ssh_held: Option<SshEvent>,

    // Terminal tabs
    tabs: Vec<TerminalTab>,
    active_tab: Option<usize>,

    // Connection form
    show_form: bool,
    form: ConnectionFormData,
    /// `form` as it was opened; ESC only closes a form still equal to it.
    /// Built by `opened_connection_form`, so it never holds a secret.
    form_opened: ConnectionFormData,
    edit_id: Option<String>,

    // Sidebar
    search_query: String,

    // Server monitoring (per active tab)
    server_stats: HashMap<String, ServerStats>,
    top_processes: HashMap<String, Vec<ProcessInfo>>,

    // File browser (per active tab)
    /// The listing on screen for each session, with the directory it was
    /// produced for: every row action resolves against that directory.
    file_entries: HashMap<String, Listing>,
    /// The directory last asked for — ahead of the listing while its
    /// listing is on the way.
    current_dir: HashMap<String, String>,
    /// The directory each session's prompt showed when the browser last
    /// followed the shell, as the prompt spells it (`~`, not `/home/u`).
    /// The browser follows the shell when this changes (see
    /// [`follow_prompt_cwd`]).
    prompt_cwd: HashMap<String, String>,

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
    window_width: f32,
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

    // ---- v0.7.0: command palette (Cmd+K) ----
    show_palette: bool,
    palette_query: String,
    palette_selected: usize,
    // ---- v0.7.0: tab rename (double-click a tab) ----
    tab_rename: Option<usize>,
    tab_rename_input: String,
    last_tab_click: Option<(usize, std::time::Instant)>,
    // ---- v0.7.0: collapsible sidebar groups ----
    /// Groups folded in the sidebar, by the connections' stored `group` ("" is
    /// the ungrouped bucket). Group names say what the vault holds, so the set
    /// is sealed with the vault (`groups_file`): read after unlock, emptied on
    /// lock, and saved a moment after the last change, off the UI thread.
    collapsed_groups: HashSet<String>,
    /// `collapsed_groups.enc`; shared with the threads that write it.
    groups_file: Arc<GroupsFile>,
    /// `collapsed_groups` holds changes the file does not have yet.
    groups_dirty: bool,
    /// Counts changes to `collapsed_groups`: only the save scheduled by the
    /// latest one runs (see `Message::SaveCollapsedGroups`).
    groups_gen: u64,
    // ---- v0.7.0: live sync input (fan keystrokes out to N sessions) ----
    sync_input_on: bool,
    // ---- v0.7.0: resource threshold alerts ----
    alert_cfg: AlertConfig,
    /// session_id -> list of breach descriptions ("CPU 95%", ...)
    alerts_active: HashMap<String, Vec<String>>,
    // ---- v0.7.0: SSH key manager ----
    show_key_manager: bool,
    local_keys: Vec<crate::sshkeys::LocalKey>,
    key_form_name: String,
    key_form_comment: String,
    /// Key path currently in "pick a connection to deploy to" mode.
    key_deploying: Option<String>,
    key_deploy_status: Option<String>,

    // ---- v0.7.0: vault re-lock ----
    /// Idle minutes before the vault re-locks itself. 0 = never.
    lock_timeout_mins: u32,
    /// Last keyboard / mouse activity the app observed. Only meaningful on
    /// `Screen::Main`; re-armed on every unlock.
    last_activity: std::time::Instant,

    // ---- UI pass ----
    /// Sidebar connection row under the mouse; its actions show on hover.
    hovered_conn: Option<String>,
    /// `~/.ssh/config` as last read. Refreshed on `ConnectionsLoaded` (which
    /// opening the connect dialog triggers), never from a view — views run on
    /// every redraw.
    ssh_config_hosts: Vec<crate::sshconfig::SshHostConfig>,
    /// Fingerprint of the error text the Copy button last put on the
    /// clipboard, so the button reads "Copied" for exactly that message.
    error_copied: Option<u64>,
    /// Title of the error dialog for the message on it, when that message is
    /// not a connection error: an i18n key, bound to the message's
    /// fingerprint so that an error put up anywhere else afterwards keeps the
    /// usual title (`show_notice`).
    error_title: Option<(u64, &'static str)>,
    /// Last cursor x seen by the global mouse listener (y is `cursor_y`).
    cursor_x: f32,
    /// Split-divider drag in progress: (cursor position along the split
    /// axis at the press, ratio at the press).
    split_drag: Option<(f32, f32)>,

    // ---- v0.7.0 feature wiring ----
    /// Live modifier state. Shift keeps the mouse for local selection while
    /// an application has mouse reporting switched on.
    modifiers: keyboard::Modifiers,
    /// Press reported to an application, awaiting its release.
    mouse_report: Option<MouseReport>,
    /// Last cell a bare-motion (DEC 1003) report went out for.
    mouse_motion_cell: Option<(usize, usize)>,
    /// Where SSH threads park keyboard-interactive challenges.
    auth_rx: Option<mpsc::Receiver<crate::ssh::AuthChallenge>>,
    /// Challenges waiting for the modal, oldest first, with their arrival
    /// time. Each holds the reply channel its SSH thread is blocked on;
    /// dropping one cancels that attempt.
    auth_queue: VecDeque<(crate::ssh::AuthChallenge, std::time::Instant)>,
    /// Answers being typed for the front challenge, one per prompt.
    auth_answers: Vec<String>,
    /// The first answer field is owed the keyboard focus: a challenge reached
    /// the front while the modal was not on screen to take it.
    auth_focus_owed: bool,
    /// When the front challenge's modal came on screen, for as long as it
    /// stays there. Its answer fields take no keys for `AUTH_ARM_DELAY` after
    /// that (see [`auth_armed`]).
    auth_shown_at: Option<std::time::Instant>,
    /// Last key press seen anywhere in the window. A sign-in modal that comes
    /// up while keys are still arriving does not take the keyboard.
    last_keypress: Option<std::time::Instant>,
    /// Whether, and when, `cmd_history` reaches `history_file`.
    history_sync: HistorySync,
    /// The sealed history on disk; shared with the threads that write it.
    history_file: Arc<HistoryFile>,
    /// Best guess at whether the quick-command input has keyboard focus. It
    /// gates the autocomplete dropdown; Tab / Down confirm it against the
    /// real widget focus before taking the key from the terminal.
    quick_cmd_focused: bool,
    remote_menu: Option<RemoteFileMenu>,
    sftp_input: Option<SftpInputDialog>,
    confirm_action: Option<ConfirmAction>,
    /// Drops waiting for the single progress bar, oldest first.
    drop_queue: VecDeque<DropJob>,
    /// A `start_upload` transfer is in flight; its `UploadFinished` starts
    /// the next queued drop.
    upload_job_running: bool,
    /// Sessions with a monitor fetch still out (see [`InFlight`]).
    monitor_inflight: InFlight,
    /// Sessions whose monitoring is parked until the user reconnects it.
    monitor_parked: ParkedMonitors,
    // Listening-ports tab of the bottom panel; the list belongs to
    // `ports_session`, and is kept in the table's sort order: the view draws
    // it as it is, on every frame.
    ports_session: String,
    ports: Vec<crate::ssh::PortInfo>,
    /// Sessions with a ports fetch still out.
    ports_inflight: InFlight,
    ports_error: Option<String>,
    ports_fetched_at: Option<std::time::Instant>,
    ports_sort: PortSort,
    ports_sort_desc: bool,
    /// Which text input has the keyboard focus: what the input method may do
    /// hangs on it (see `sync_input_method`).
    focus: FocusTracker,
    /// Where the input method's candidate window was last anchored for the
    /// terminal; `None` once anything else may have moved it.
    ime_area: Option<(f32, f32, f32)>,
}

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Setup,
    Locked,
    Main,
}

struct TerminalTab {
    id: String,
    session_id: String,
    connection_id: String,
    title: String,
    terminal: Arc<parking_lot::Mutex<TerminalGrid>>,
    /// User-set tab name (double-click the tab to edit). Overrides `title`
    /// in the tab bar; cleared by renaming to an empty string.
    custom_title: Option<String>,
    /// Optional second pane (v0.7.0 split). At most one split per tab.
    split: Option<SplitPane>,
    /// When a split exists: true = the split pane has keyboard focus.
    focus_split: bool,
    /// Where the main pane's canvas last drew.
    bounds: PaneBounds,
    /// While the tab is still connecting (`session_id` stays empty until
    /// `SshConnected`): the id the connect runs under, picked up front with
    /// `SshManager::new_session_id`. Its sign-in challenges carry it, so
    /// closing the tab can withdraw them. Empty once connected.
    pending_session_id: String,
    /// The same for a split being opened on this tab: the id its connect
    /// runs under, until `SplitConnected` or `SplitFailed`.
    split_pending: Option<String>,
}

impl TerminalTab {
    /// Title shown in the tab bar (custom name wins).
    fn display_title(&self) -> &str {
        self.custom_title.as_deref().unwrap_or(&self.title)
    }

    /// Session id of the pane that currently has keyboard focus. It is also
    /// the session the bottom panel — monitor, ports, files — shows and acts
    /// on: a split pane's own session is reachable there, "Reconnect
    /// monitoring" for its parked exec connection included.
    fn focused_session(&self) -> &str {
        match (&self.split, self.focus_split) {
            (Some(sp), true) => &sp.session_id,
            _ => &self.session_id,
        }
    }

    /// Terminal grid of the pane that currently has keyboard focus.
    fn focused_grid(&self) -> &Arc<parking_lot::Mutex<TerminalGrid>> {
        match (&self.split, self.focus_split) {
            (Some(sp), true) => &sp.terminal,
            _ => &self.terminal,
        }
    }
}

/// Second pane of a split tab. `vertical == true` means panes sit
/// side-by-side (vertical divider); false stacks them (horizontal divider).
struct SplitPane {
    session_id: String,
    terminal: Arc<parking_lot::Mutex<TerminalGrid>>,
    vertical: bool,
    /// Share of the area the main (first) pane gets, in
    /// `SPLIT_MIN..=SPLIT_MAX`. Dragging the divider changes it.
    ratio: f32,
    /// Where this pane's canvas last drew.
    bounds: PaneBounds,
}

/// A destructive action held until the user confirms it, in the same modal
/// shape as the connection delete. Each variant carries exactly what it will
/// touch, because that is what the confirmation shows.
#[derive(Debug, Clone)]
enum ConfirmAction {
    /// `name` is the row's exact name and `kind` what the row showed: the
    /// confirmation quotes the one and states the other, and the SSH layer
    /// refuses the delete if the entry is no longer that kind.
    SftpDelete {
        session_id: String,
        dir: String,
        path: String,
        name: String,
        kind: EntryKind,
        confirmed: ConfirmedEntry,
    },
    SftpChmod {
        session_id: String,
        dir: String,
        path: String,
        name: String,
        kind: EntryKind,
        confirmed: ConfirmedEntry,
        mode: u32,
    },
    /// `command` is what the confirmation shows, read from /proc as it
    /// opened; `identity` the process it was read from, looked up again
    /// right before the signal goes.
    Kill { session_id: String, pid: u32, command: String, signal: i32, identity: ProcIdentity },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BottomTab {
    Monitor,
    Files,
    QuickCmd,
    Ports,
}

#[derive(Debug, Clone)]
pub enum Message {
    // Password
    PasswordChanged(String),
    ConfirmChanged(String),
    CreateVault,
    VaultCreated,
    UnlockVault,
    VaultUnlocked,
    /// Start every tunnel flagged `auto_start`. Dispatched only after the vault
    /// is open — never from `Default`, see the `tunnel_manager` field.
    AutoStartTunnels,
    /// Re-lock the vault now: wipe the DEK and drop back to the lock screen.
    /// Live SSH sessions are deliberately left running.
    LockNow,
    /// Idle tick. Locks when `lock_timeout_mins` has elapsed with no input.
    IdleCheck,
    /// Change the idle re-lock timeout (minutes; 0 = never).
    SetLockTimeout(u32),

    // Keyboard focus, which the input method follows
    /// A mouse press a widget claimed — a text input it focused, say — or one
    /// the terminal never gets: another input may hold the focus now.
    FocusMayHaveMoved,
    /// What the widget tree said holds the focus: (query number, its id).
    FocusFound(u64, Option<iced::advanced::widget::Id>),

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
    /// Put the full text of the error dialog on the clipboard.
    CopyErrorText,
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
    /// The connect behind a placeholder tab failed: (tab id, connection id,
    /// error). Only that tab goes, and only if it is still open.
    ConnectFailed(String, String, String),
    TerminalInput(String, String),
    TabSelected(usize),
    TabClosed(usize),

    // Polling / keyboard
    PollSshEvents,
    /// The bool is true when a widget — a focused text input — already
    /// consumed the key. Such a key must not also be typed into the shell.
    KeyboardEvent(keyboard::Key, keyboard::Modifiers, Option<String>, bool),
    /// Modifier keys changed; tracked so Shift can override mouse reporting.
    ModifiersChanged(keyboard::Modifiers),
    PasteClipboard,
    CancelTransfer,

    // Search
    SearchChanged(String),

    // Monitor
    FetchMonitorData,
    MonitorDataReceived(String, ServerStats, Vec<ProcessInfo>),
    /// (session, error)
    MonitorError(String, String),
    /// "Reconnect monitoring", on a session whose monitoring is parked.
    ResumeMonitoring(String),
    /// (session, result) of that reconnect.
    ResumeMonitoringDone(String, Result<(), String>),
    /// A file listing found the session's exec connection parked: the
    /// panels show the reconnect instead of an error dialog.
    ExecParked(String),
    ShowNetworkDetail(crate::ssh::NetInterface),
    HideNetworkDetail,

    // File browser
    FilesReceived(String, String, Vec<FileEntry>),
    ChangeDir(String, String),
    /// Listing a directory failed: (session, the directory asked for, error).
    ListingFailed(String, String, String),
    /// A row of the listing on screen: (session, the listing's directory,
    /// the row).
    FileClicked(String, String, FileEntry),

    // File operations
    UploadFile,
    DownloadFile(String, String),
    /// (session, remote path, where to save it or None if cancelled)
    DownloadPicked(String, String, Option<std::path::PathBuf>),
    /// A single-file download ended. The progress it was started with rides
    /// along: only that bar may be taken down.
    DownloadDone(Arc<TransferProgress>, Result<(), String>),

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
    /// (session, remote directory, picked file or None if cancelled)
    RzPicked(String, String, Option<std::path::PathBuf>),
    /// (session, the upload's progress, result)
    RzUploadDone(String, Arc<TransferProgress>, Result<(), String>),

    // Bottom panel collapse / expand
    ToggleBottomPanel,
    /// Window size in logical pixels — tracked for split-pane hit math.
    WindowResized(f32, f32),

    // ---- v0.7.0 ----
    // Command palette (Cmd+K)
    TogglePalette,
    PaletteQueryChanged(String),
    PaletteNavUp,
    PaletteNavDown,
    PaletteExecute,
    PaletteExecuteIndex(usize),
    // Tab rename (double-click)
    TabRenameInput(String),
    TabRenameCommit,
    TabRenameCancel,
    // Sidebar group collapse, by the connections' stored group ("" is the
    // ungrouped bucket)
    ToggleGroupCollapsed(String),
    /// Collapse (true) or expand (false) every group at once.
    SetAllGroupsCollapsed(bool),
    /// Pointer entered (true) or left (false) a sidebar connection row.
    SidebarHover(String, bool),
    // Live sync input
    ToggleSyncInput,
    // Threshold alerts
    AlertEnabledToggled(bool),
    AlertCpuChanged(f32),
    AlertMemChanged(f32),
    AlertDiskChanged(f32),
    // SSH key manager
    ShowKeyManager,
    HideKeyManager,
    KeyFormNameChanged(String),
    KeyFormCommentChanged(String),
    KeyGenerate,
    KeyCopyPubkey(String),       // key path
    KeyDeployStart(String),      // key path → show connection picker
    KeyDeployTo(String, String), // (key path, connection id)
    KeyDeployDone(Result<String, String>),
    KeyDeployCancel,
    // Split panes
    SplitTab(bool),                          // vertical?
    SplitConnected(String, bool, String),    // (tab_id, vertical, session_id)
    /// A split's connect failed: (tab id, error).
    SplitFailed(String, String),
    SplitFocusToggle,
    CloseFocusedPane,
    /// Left button went down on the split divider: start a ratio drag.
    SplitDividerPressed,

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
    /// A press no widget claimed; the pointer is `cursor_x` / `cursor_y`.
    TerminalMouseDown(MouseButton),
    TerminalMouseUp(MouseButton),
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
    HideContextMenu,
    InspectProcess(u32),
    ProcessDetailReceived(ProcessDetailInfo),
    HideProcessDetail,
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
    // Local file browser
    LocalPathChanged(String),
    LocalPathSubmit,
    LocalFileClicked(String),     // full path — if dir, navigate; if file, select
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

    // ---- v0.7.0 feature wiring ----
    /// Right-click in the remote file browser: (session, directory, row).
    RemoteMenuOpen(String, String, Option<FileEntry>),
    RemoteMenuClose,
    SftpNewFolder,
    SftpRename,
    SftpChmod,
    SftpDelete,
    SftpInputChanged(String),
    SftpInputSubmit,
    SftpInputCancel,
    /// A mutating SFTP call finished: (session, directory, result).
    SftpOpDone(String, String, Result<(), String>),
    ConfirmActionExecute,
    ConfirmActionCancel,
    /// Pick a local folder and upload it into the browser's directory.
    UploadDir,
    /// (session, remote directory, picked file or folder or None if
    /// cancelled). Upload and folder upload both end up here.
    UploadPicked(String, String, Option<std::path::PathBuf>),
    /// Download a remote folder: (session, remote path).
    DownloadDir(String, String),
    /// (session, remote path, local parent or None if cancelled)
    DownloadDirPicked(String, String, Option<std::path::PathBuf>),
    DownloadDirDone(Arc<TransferProgress>, Result<(), String>),
    /// An upload started by `start_upload` ended: (session, its progress,
    /// result).
    UploadFinished(String, Arc<TransferProgress>, Result<(), String>),
    /// A file or folder was dropped on the window.
    FileDropped(std::path::PathBuf),
    /// Write pending command history to disk, if a paced write is due.
    FlushHistory,
    /// A sealed history write finished on its blocking thread.
    HistoryWritten(Result<(), String>),
    /// The unlock-time load came back from its blocking thread: (its number,
    /// what it found).
    HistoryLoaded(u64, HistoryLoad),
    /// Fill the quick-command input with a suggestion.
    QuickCmdAccept(String),
    AuthAnswerChanged(usize, String),
    AuthFocus(usize),
    AuthSubmit,
    /// Enter in the last answer field: a submit, unless the key arrived too
    /// soon after the modal did to have been meant for it.
    AuthEnter,
    AuthCancel,
    /// Signal the process in the open detail popup — after a confirmation.
    KillProcessRequest(i32),
    /// The fresh /proc read the kill confirmation shows came back: (session,
    /// pid, signal, the process now, or None when there is none).
    KillIdentityRead(String, u32, i32, Result<Option<ProcIdentity>, String>),
    KillProcessDone(Result<(), String>),
    FetchPorts,
    PortsReceived(String, Result<Vec<crate::ssh::PortInfo>, String>),
    PortsSortBy(PortSort),
    /// Apply a colour-scheme preset, by its name in `preset_names()`.
    ThemeApplyPreset(String),
    /// Save the folded sidebar groups, if no change came after the one that
    /// scheduled this (its `groups_gen`).
    SaveCollapsedGroups(u64),
    /// A sealed write of the folded groups finished.
    GroupsWritten(Result<(), String>),

    // Misc
    None,
    Error(String),
}

// ---------------------------------------------------------------------------
// Default (initial state before run_with)
// ---------------------------------------------------------------------------

impl Default for NeoShell {
    fn default() -> Self {
        let store = Arc::new(ConnectionStore::new());
        // Register before any ProxyStore / TunnelStore is built: both resolve
        // their credentials through this handle, including from inside a
        // background SSH thread that never sees `state`. The lookup is lazy,
        // so field order in the literal below does not matter — but a store
        // built before this line would have nowhere to put a secret and would
        // refuse to save.
        crate::storage::set_global_vault(store.clone());
        let (ssh_manager, ssh_event_rx) = SshManager::new();

        let screen = if store.vault_exists() {
            Screen::Locked
        } else {
            Screen::Setup
        };

        let locale = load_locale();
        i18n::set_locale(&locale);

        // Publish the theme before any widget or TerminalGrid exists: the
        // shared style fns and `TerminalGrid::new()` read the live palette,
        // not `state`.
        let theme_cfg = crate::ui::theme_config::ThemeConfig::load();
        theme_config::set_live(&theme_cfg);

        // Keyboard-interactive auth: SSH threads park their challenges on
        // this channel and block until the modal answers. Registered once,
        // with the event channel's waker: a challenge wakes the drain too.
        let (auth_tx, auth_rx) = mpsc::channel();
        crate::ssh::set_auth_prompter(crate::ssh::UiSender::new(auth_tx, ssh_manager.waker()));

        Self {
            screen,
            password_input: String::new(),
            confirm_input: String::new(),
            error_message: String::new(),
            store,
            connections: Vec::new(),
            ssh_manager: Arc::new(ssh_manager),
            ssh_event_rx: Some(ssh_event_rx),
            ssh_held: None,
            tabs: Vec::new(),
            active_tab: None,
            show_form: false,
            form: ConnectionFormData::default(),
            form_opened: ConnectionFormData::default(),
            edit_id: None,
            search_query: String::new(),
            server_stats: HashMap::new(),
            top_processes: HashMap::new(),
            file_entries: HashMap::new(),
            current_dir: HashMap::new(),
            prompt_cwd: HashMap::new(),
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
            window_width: 1200.0,
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
            // Sealed under the vault key: read after unlock, not here.
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
            // Auto-start deliberately does NOT happen here: Default runs before
            // the lock screen is drawn, so starting tunnels would open forwarded
            // ports into the internal network — authenticating with the
            // credentials in tunnels.json — without a master password. It is
            // dispatched by Message::AutoStartTunnels once the vault is open.
            tunnel_manager: Arc::new(crate::tunnel::TunnelManager::new()),
            tunnels: {
                let ts = crate::tunnel::TunnelStore::new();
                ts.load()
            },
            show_tunnel_manager: false,
            show_tunnel_form: false,
            tunnel_form: TunnelFormData::default(),
            tunnel_edit_id: None,
            theme_cfg,
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
            show_palette: false,
            palette_query: String::new(),
            palette_selected: 0,
            tab_rename: None,
            tab_rename_input: String::new(),
            last_tab_click: None,
            // Sealed under the vault key: read after unlock, not here.
            collapsed_groups: HashSet::new(),
            groups_file: Arc::new(GroupsFile::in_data_dir()),
            groups_dirty: false,
            groups_gen: 0,
            sync_input_on: false,
            alert_cfg: load_alerts(),
            alerts_active: HashMap::new(),
            show_key_manager: false,
            local_keys: Vec::new(),
            key_form_name: String::new(),
            key_form_comment: String::new(),
            key_deploying: None,
            key_deploy_status: None,
            lock_timeout_mins: load_lock_timeout(),
            last_activity: std::time::Instant::now(),
            hovered_conn: None,
            ssh_config_hosts: Vec::new(),
            error_copied: None,
            error_title: None,
            cursor_x: 0.0,
            split_drag: None,
            modifiers: keyboard::Modifiers::default(),
            mouse_report: None,
            mouse_motion_cell: None,
            auth_rx: Some(auth_rx),
            auth_queue: VecDeque::new(),
            auth_answers: Vec::new(),
            auth_focus_owed: false,
            auth_shown_at: None,
            last_keypress: None,
            history_sync: HistorySync::default(),
            history_file: Arc::new(HistoryFile::in_data_dir()),
            quick_cmd_focused: false,
            remote_menu: None,
            sftp_input: None,
            confirm_action: None,
            drop_queue: VecDeque::new(),
            upload_job_running: false,
            monitor_inflight: InFlight::default(),
            monitor_parked: ParkedMonitors::default(),
            ports_session: String::new(),
            ports: Vec::new(),
            ports_inflight: InFlight::default(),
            ports_error: None,
            ports_fetched_at: None,
            ports_sort: PortSort::Port,
            ports_sort_desc: false,
            focus: FocusTracker::default(),
            ime_area: None,
        }
    }
}

/// Every modal / drawer `view_main` can draw over the main layout. At most one
/// is drawn: the first open one in [`Overlay::Z_ORDER`]. `view_main` renders
/// from that and ESC closes from it, so what is on screen and what ESC
/// dismisses cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Overlay {
    Palette,
    ConfirmDelete,
    AuthPrompt,
    ConfirmAction,
    LogViewer,
    ErrorDialog,
    ProcessDetail,
    Editor,
    NetworkDetail,
    ConnectDialog,
    History,
    ProxyManager,
    TunnelManager,
    TabRename,
    SftpInput,
    KeyManager,
    ShortcutsHelp,
    Broadcast,
    Snippets,
    About,
    Settings,
    ConnectionForm,
}

impl Overlay {
    /// The overlays with a secret input: the connection, proxy and tunnel
    /// forms (their password and passphrase, see [`SECRET_INPUT_IDS`]) and
    /// the sign-in modal (a non-echo answer). Keep in step with those ids.
    const HOLDS_SECRETS: [Overlay; 4] = [
        Overlay::ConnectionForm,
        Overlay::ProxyManager,
        Overlay::TunnelManager,
        Overlay::AuthPrompt,
    ];

    /// Topmost first. Three entries sit above where they used to:
    /// - `Palette` is summoned over anything (Cmd+K works with a panel open)
    ///   and already had first claim on the keyboard.
    /// - `ErrorDialog` reports failures raised *inside* panels — a proxy or
    ///   tunnel save refused by a locked vault, an editor save — and was
    ///   drawn underneath the very panel that raised it.
    /// - `LogViewer` stays above `ErrorDialog`, because the dialog's own
    ///   "View log" button opens it.
    ///
    /// `AuthPrompt` sits right under the delete confirmation: an SSH thread is
    /// blocked on it, and a test or key deploy can raise it from inside a
    /// panel. `ConfirmAction` must clear `ProcessDetail`, which opens it.
    const Z_ORDER: [Overlay; 22] = [
        Overlay::Palette,
        Overlay::ConfirmDelete,
        Overlay::AuthPrompt,
        Overlay::ConfirmAction,
        Overlay::LogViewer,
        Overlay::ErrorDialog,
        Overlay::ProcessDetail,
        Overlay::Editor,
        Overlay::NetworkDetail,
        Overlay::ConnectDialog,
        Overlay::History,
        Overlay::ProxyManager,
        Overlay::TunnelManager,
        Overlay::TabRename,
        Overlay::SftpInput,
        Overlay::KeyManager,
        Overlay::ShortcutsHelp,
        Overlay::Broadcast,
        Overlay::Snippets,
        Overlay::About,
        Overlay::Settings,
        Overlay::ConnectionForm,
    ];
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
    ///
    /// Defined as "view_main is drawing an overlay", so input is never
    /// blocked by something invisible — e.g. `show_error_dialog` left set
    /// with an empty message (lock_vault clears the text, not the flag) —
    /// and the delete confirmation, which is drawn, now counts too.
    fn any_overlay_open(&self) -> bool {
        self.topmost_overlay().is_some()
    }

    fn is_overlay_open(&self, overlay: Overlay) -> bool {
        match overlay {
            Overlay::Palette => self.show_palette,
            Overlay::ConfirmDelete => self.confirm_delete.is_some(),
            Overlay::AuthPrompt => !self.auth_queue.is_empty(),
            Overlay::ConfirmAction => self.confirm_action.is_some(),
            Overlay::LogViewer => self.show_log_viewer,
            // An empty message would be an empty dialog; it was never drawn.
            Overlay::ErrorDialog => self.show_error_dialog && !self.error_message.is_empty(),
            Overlay::ProcessDetail => self.process_detail.is_some(),
            Overlay::Editor => self.editor_file_path.is_some(),
            Overlay::NetworkDetail => self.selected_interface.is_some(),
            Overlay::ConnectDialog => self.show_connect_dialog,
            Overlay::History => self.show_history,
            Overlay::ProxyManager => self.show_proxy_manager,
            Overlay::TunnelManager => self.show_tunnel_manager,
            Overlay::TabRename => self.tab_rename.is_some(),
            Overlay::SftpInput => self.sftp_input.is_some(),
            Overlay::KeyManager => self.show_key_manager,
            Overlay::ShortcutsHelp => self.show_shortcuts_help,
            Overlay::Broadcast => self.show_broadcast_dialog,
            Overlay::Snippets => self.show_snippets_panel,
            Overlay::About => self.show_about,
            Overlay::Settings => self.show_settings,
            Overlay::ConnectionForm => self.show_form,
        }
    }

    /// The overlay `view_main` draws — the first open one in z-order.
    /// Whether an overlay that holds a secret field is open — the only
    /// places a click can focus one on the main screen (see
    /// [`Overlay::HOLDS_SECRETS`]).
    fn secret_overlay_open(&self) -> bool {
        Overlay::HOLDS_SECRETS
            .into_iter()
            .any(|overlay| self.is_overlay_open(overlay))
    }

    fn topmost_overlay(&self) -> Option<Overlay> {
        Overlay::Z_ORDER
            .into_iter()
            .find(|&overlay| self.is_overlay_open(overlay))
    }

    /// Close whatever [`topmost_overlay`](Self::topmost_overlay) names and
    /// report whether anything was dismissed. ESC calls this, so it always
    /// closes exactly what the user is looking at. Panels with an inline
    /// sub-view — the proxy / tunnel form, the key deploy picker, an open
    /// colour editor, a snippet being edited — back out of that first.
    ///
    /// An editor holding unsaved changes stays open, but the key is still
    /// consumed: ESC is muscle memory for vim users and closing would throw
    /// their edits away. Save and Close remain explicit. A form works the
    /// same way — the connection form, the proxy / tunnel form, the snippet
    /// editor: ESC puts one away only while it still reads exactly as it was
    /// opened; once anything was typed into it, only Save or Cancel does.
    fn close_topmost_overlay(&mut self) -> bool {
        let Some(top) = self.topmost_overlay() else {
            // Not a modal, but still something ESC should put away.
            let conn_menu = self.context_menu.take().is_some();
            let file_menu = self.remote_menu.take().is_some();
            return conn_menu || file_menu;
        };
        match top {
            Overlay::Palette => self.show_palette = false,
            Overlay::ConfirmDelete => self.confirm_delete = None,
            // ESC is the user declining to answer: a cancel, which the SSH
            // thread tells apart from a modal retired unanswered. Not an Esc
            // typed before the modal appeared — in vim, say: it is swallowed.
            Overlay::AuthPrompt => {
                if !auth_armed(self.auth_shown_at, std::time::Instant::now()) {
                    return true;
                }
                if let Some((challenge, _)) = self.auth_queue.pop_front() {
                    challenge.cancel();
                }
                self.reset_auth_answers();
                self.auth_shown_at = None;
                // The next challenge, if any — and if it may — takes the focus
                // on the next poll tick; Esc just took it off the field it
                // was in.
                self.auth_focus_owed = self.front_may_take_focus() && !self.auth_answers.is_empty();
            }
            Overlay::ConfirmAction => self.confirm_action = None,
            Overlay::LogViewer => {
                self.show_log_viewer = false;
                self.log_viewer_content.clear();
            }
            Overlay::ErrorDialog => {
                self.show_error_dialog = false;
                self.error_message.clear();
            }
            Overlay::ProcessDetail => self.process_detail = None,
            Overlay::Editor => {
                if !self.editor_dirty {
                    self.editor_content = text_editor::Content::new();
                    self.editor_file_path = None;
                    self.editor_session_id = None;
                }
            }
            Overlay::NetworkDetail => self.selected_interface = None,
            Overlay::ConnectDialog => self.show_connect_dialog = false,
            Overlay::History => {
                self.show_history = false;
                self.history_filter.clear();
            }
            Overlay::ProxyManager => {
                if !self.show_proxy_form {
                    self.show_proxy_manager = false;
                } else if proxy_form_pristine(
                    &self.proxy_form,
                    self.proxy_edit_id.as_deref(),
                    &self.proxies,
                ) {
                    self.show_proxy_form = false;
                    self.proxy_edit_id = None;
                    self.proxy_form = ProxyFormData::default();
                }
            }
            Overlay::TunnelManager => {
                if !self.show_tunnel_form {
                    self.show_tunnel_manager = false;
                } else if tunnel_form_pristine(
                    &self.tunnel_form,
                    self.tunnel_edit_id.as_deref(),
                    &self.tunnels,
                ) {
                    self.show_tunnel_form = false;
                    self.tunnel_edit_id = None;
                    self.tunnel_form = TunnelFormData::default();
                }
            }
            Overlay::TabRename => self.tab_rename = None,
            Overlay::SftpInput => self.sftp_input = None,
            Overlay::KeyManager => {
                if self.key_deploying.take().is_none() {
                    self.show_key_manager = false;
                }
            }
            Overlay::ShortcutsHelp => self.show_shortcuts_help = false,
            Overlay::Broadcast => self.show_broadcast_dialog = false,
            Overlay::Snippets => {
                // The new-snippet fields sit in the panel itself, and the
                // panel clears them when it next opens: closing the panel
                // over typed text throws it away just the same. Holding
                // typing, the panel stays; Save or Cancel decides.
                let pristine = snippet_form_pristine(
                    &self.snippet_form_name,
                    &self.snippet_form_body,
                    self.snippet_edit_id.as_deref(),
                    &self.snippets,
                );
                if pristine {
                    if self.snippet_edit_id.take().is_some() {
                        self.snippet_form_name.clear();
                        self.snippet_form_body.clear();
                    } else {
                        self.show_snippets_panel = false;
                    }
                }
            }
            Overlay::About => self.show_about = false,
            Overlay::Settings => {
                if self.theme_editing_zone.take().is_none() {
                    self.show_settings = false;
                }
            }
            Overlay::ConnectionForm => {
                if self.form == self.form_opened {
                    self.show_form = false;
                    self.edit_id = None;
                    self.form = ConnectionFormData::default();
                    self.form_test_result = None;
                    self.form_testing = false;
                }
            }
        }
        true
    }

    /// True while any tab holds a live session for this saved connection.
    /// The sidebar and the connect dialog both draw their status dot from it.
    fn is_connected(&self, conn_id: &str) -> bool {
        self.tabs
            .iter()
            .any(|t| t.connection_id == conn_id && !t.session_id.is_empty())
    }

    /// Hosts in `~/.ssh/config` (as last read) that "Import all" would add,
    /// i.e. not yet saved under the same user@host:port.
    fn ssh_config_pending(&self) -> usize {
        let saved: HashSet<String> = self
            .connections
            .iter()
            .map(|c| format!("{}@{}:{}", c.username, c.host, c.port))
            .collect();
        self.ssh_config_hosts
            .iter()
            .filter_map(ssh_config_key)
            .filter(|key| !saved.contains(key))
            .count()
    }

    /// Length of the split-pane area along the split axis, minus the divider:
    /// the space `view_terminal_area` shares out between the two panes. The
    /// selection hit-test and the divider drag both measure against it.
    ///
    /// Measured — the two canvases as last drawn — once both have drawn, so
    /// the update banner and the transfer bar are accounted for. Before that,
    /// the fixed chrome: toolbar 30 + tab bar 34 above, status bar 24 +
    /// bottom-panel splitter 14 below.
    fn split_extent(&self, vertical: bool) -> f32 {
        if let Some((main, split)) = self
            .active_tab
            .and_then(|i| self.tabs.get(i))
            .and_then(drawn_split)
        {
            return if vertical {
                main.width + split.width
            } else {
                main.height + split.height
            };
        }
        if vertical {
            let sidebar_w = if self.sidebar_collapsed { 0.0 } else { SIDEBAR_W };
            (self.window_width - sidebar_w - SPLIT_DIVIDER).max(0.0)
        } else {
            let bottom = if self.bottom_panel_collapsed {
                0.0
            } else {
                self.bottom_panel_height
            };
            (self.window_height - (30.0 + 34.0) - 24.0 - 14.0 - bottom - SPLIT_DIVIDER).max(0.0)
        }
    }

    /// Terminal grid of the currently focused pane (split-aware).
    #[inline]
    fn focused_terminal(&self) -> Option<&Arc<parking_lot::Mutex<TerminalGrid>>> {
        self.active_tab
            .and_then(|i| self.tabs.get(i))
            .map(|t| t.focused_grid())
    }

    /// SSH session id of the currently focused pane (split-aware).
    #[inline]
    fn focused_session_id(&self) -> Option<String> {
        self.active_tab
            .and_then(|i| self.tabs.get(i))
            .map(|t| t.focused_session().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Terminal grid that belongs to the given SSH `session_id`, regardless of
    /// which tab or pane it lives in.
    #[inline]
    fn find_terminal_for_session(
        &self,
        session_id: &str,
    ) -> Option<&Arc<parking_lot::Mutex<TerminalGrid>>> {
        for t in &self.tabs {
            if t.session_id == session_id {
                return Some(&t.terminal);
            }
            if let Some(sp) = &t.split {
                if sp.session_id == session_id {
                    return Some(&sp.terminal);
                }
            }
        }
        None
    }

    /// Window-pixel origin of a tab's main pane canvas: where it last drew
    /// (see [`PaneBounds`]), or — before its first frame — past the sidebar
    /// and the fixed toolbar 30 + tab bar 34.
    fn main_pane_origin(&self, tab: &TerminalTab) -> (f32, f32) {
        let sidebar_w = if self.sidebar_collapsed {
            0.0
        } else {
            SIDEBAR_W
        };
        pane_origin(tab.bounds.get(), (sidebar_w, 30.0 + 34.0))
    }

    /// Window-pixel origin of the focused pane's terminal canvas: where the
    /// selection hit-test and mouse reporting both measure from. Shared so
    /// the two cannot drift apart again. Measured from where the canvas drew,
    /// so a banner or bar above it shifts the origin with it; until a split
    /// pane has drawn, it sits past the main pane and the divider (8b17f55).
    fn focused_pane_origin(&self) -> (f32, f32) {
        let sidebar_w = if self.sidebar_collapsed { 0.0 } else { SIDEBAR_W };
        let Some(tab) = self.active_tab.and_then(|i| self.tabs.get(i)) else {
            return (sidebar_w, 30.0 + 34.0);
        };
        let main = self.main_pane_origin(tab);
        match (&tab.split, tab.focus_split) {
            (Some(sp), true) => {
                let main_len = self.split_extent(sp.vertical) * sp.ratio;
                let past_main = if sp.vertical {
                    (main.0 + main_len + SPLIT_DIVIDER, main.1)
                } else {
                    (main.0, main.1 + main_len + SPLIT_DIVIDER)
                };
                pane_origin(sp.bounds.get(), past_main)
            }
            _ => main,
        }
    }

    /// 1-based cell of the focused pane under window point `(x, y)`, for
    /// mouse reporting; see [`grid_cell_at`] for `clamp`.
    fn focused_pane_cell(&self, x: f32, y: f32, clamp: bool) -> Option<(usize, usize)> {
        let size = {
            let grid = self.focused_terminal()?.lock();
            (grid.cols, grid.rows)
        };
        grid_cell_at(
            x,
            y,
            self.focused_pane_origin(),
            self.theme_cfg.terminal_font_size,
            size,
            clamp,
        )
    }

    /// The focused pane, when its application switched mouse reporting on
    /// and Shift is not held. Shift keeps the mouse for local selection, as
    /// in every other terminal.
    fn mouse_report_target(&self) -> Option<(String, Arc<parking_lot::Mutex<TerminalGrid>>)> {
        if self.modifiers.shift() {
            return None;
        }
        let session_id = self.focused_session_id()?;
        let term = self.focused_terminal()?;
        if term.lock().mouse_mode() == MouseMode::Off {
            return None;
        }
        Some((session_id, term.clone()))
    }

    /// Sessions a keystroke typed into the focused pane goes to: that pane,
    /// plus every ticked session while live sync is on.
    fn keystroke_targets(&self, focused: String) -> Vec<String> {
        if self.sync_input_on && !self.broadcast_selected.is_empty() {
            let mut targets = self.broadcast_selected.clone();
            targets.insert(focused);
            targets.into_iter().collect()
        } else {
            vec![focused]
        }
    }

    /// A transfer holds the single progress bar.
    fn transfer_busy(&self) -> bool {
        bar_busy(self.transfer_progress.as_ref(), self.upload_job_running)
    }

    /// A progress bar is on screen whose counters another thread moves: a
    /// transfer's, or the update download's. No message comes as they move,
    /// so the view only catches up on a drain (see [`poll_interval`]).
    fn progress_moving(&self) -> bool {
        let transfer = self
            .transfer_progress
            .as_ref()
            .is_some_and(|p| !p.is_finished());
        let update = {
            let s = self.updater.state.lock();
            s.available && !s.ready && s.download_progress > 0.0 && s.download_progress < 1.0
        };
        transfer || update
    }

    /// While a transfer holds the bar, say so and return true. Starting
    /// another would take the bar — and with it the only Cancel — away from
    /// the one in flight.
    fn transfer_refused_busy(&mut self) -> bool {
        if !self.transfer_busy() {
            return false;
        }
        self.error_message = i18n::t("transfer.busy").to_string();
        self.show_error_dialog = true;
        true
    }

    /// [`claim_bar`] for a transfer about to start, reporting a busy bar the
    /// way [`transfer_refused_busy`](Self::transfer_refused_busy) does. Only
    /// called once a picker has produced a path.
    fn claim_transfer_bar(&mut self) -> Option<Arc<TransferProgress>> {
        let claimed = claim_bar(&mut self.transfer_progress, self.upload_job_running);
        if claimed.is_none() {
            self.transfer_refused_busy();
        }
        claimed
    }

    /// Put `message` on the error dialog under `title` (an i18n key) instead
    /// of the connection-error one: something the user has to see that is no
    /// failure of a connection.
    fn show_notice(&mut self, title: &'static str, message: String) {
        self.error_title = Some((fingerprint(&message), title));
        self.error_message = message;
        self.show_error_dialog = true;
    }

    /// The directory the file browser shows for `session_id`: its listing's,
    /// or — before the first listing lands — the one asked for. What an
    /// upload into "this folder" targets, like every row action.
    fn browser_dir(&self, session_id: &str) -> Option<String> {
        self.file_entries
            .get(session_id)
            .map(|listing| listing.dir.clone())
            .or_else(|| self.current_dir.get(session_id).cloned())
    }

    /// Session and remote directory a file dropped on the window uploads to.
    ///
    /// winit reports a drop with no position, so the pane is picked from the
    /// last pointer position the app saw, measured against the tracked window
    /// size the way the split layout divides it. The directory is the file
    /// browser's ([`browser_dir`](Self::browser_dir)). A session without one
    /// falls back to the cwd in that pane's prompt, then to the main pane's
    /// directory (same host). Only absolute paths qualify: SFTP cannot
    /// expand `~`.
    fn drop_target(&self) -> Option<(String, String)> {
        let tab = self.active_tab.and_then(|i| self.tabs.get(i))?;
        if tab.session_id.is_empty() {
            return None;
        }
        let (mut session_id, mut grid) = (tab.session_id.clone(), &tab.terminal);
        if let Some(sp) = &tab.split {
            let main_len = match drawn_split(tab) {
                Some((main, _)) if sp.vertical => main.width,
                Some((main, _)) => main.height,
                None => self.split_extent(sp.vertical) * sp.ratio,
            };
            let pointer = (self.cursor_x, self.cursor_y);
            if in_second_pane(pointer, self.main_pane_origin(tab), main_len, sp.vertical) {
                session_id = sp.session_id.clone();
                grid = &sp.terminal;
            }
        }
        let absolute = |p: &String| p.starts_with('/');
        let dir = self
            .browser_dir(&session_id)
            .filter(absolute)
            .or_else(|| extract_cwd_from_prompt(&grid.lock()).filter(absolute))
            .or_else(|| self.browser_dir(&tab.session_id).filter(absolute))?;
        Some((session_id, dir))
    }

    /// Drop what is kept about a session that is gone: its monitor figures,
    /// alerts, listing, sync membership and ZMODEM guard — what the
    /// `SshEvent::Closed` handler drops.
    fn forget_session(&mut self, session_id: &str) {
        self.zmodem_active.remove(session_id);
        self.broadcast_selected.remove(session_id);
        self.alerts_active.remove(session_id);
        self.server_stats.remove(session_id);
        self.top_processes.remove(session_id);
        self.monitor_parked.unpark(session_id);
        self.file_entries.remove(session_id);
        self.current_dir.remove(session_id);
        self.prompt_cwd.remove(session_id);
    }

    /// The tab a session lives in, as its main pane or its split.
    fn tab_for_session(&self, session_id: &str) -> Option<&TerminalTab> {
        self.tabs.iter().find(|t| {
            t.session_id == session_id
                || t.split.as_ref().is_some_and(|s| s.session_id == session_id)
        })
    }

    /// Host a session is connected to, for the command history.
    fn session_host(&self, session_id: &str) -> String {
        let Some(tab) = self.tab_for_session(session_id) else {
            return String::new();
        };
        self.connections
            .iter()
            .find(|c| c.id == tab.connection_id)
            .map(|c| c.host.clone())
            .unwrap_or_else(|| host_from_title(&tab.title))
    }

    /// "user@host:port" of a session, without a reconnect marker — what a
    /// destructive confirmation names alongside the path or pid.
    fn session_label(&self, session_id: &str) -> String {
        self.tab_for_session(session_id)
            .map(|t| title_base(&t.title).to_string())
            .unwrap_or_default()
    }

    /// Autocomplete candidates for the quick-command input; empty unless its
    /// dropdown can be on screen.
    fn quick_cmd_suggestions(&self) -> Vec<String> {
        let visible = self.quick_cmd_focused
            && self.active_tab.is_some()
            && !self.bottom_panel_collapsed
            && self.bottom_panel_tab == BottomTab::QuickCmd;
        if !visible {
            return Vec::new();
        }
        quick_cmd_matches(&self.quick_cmd_input, &self.cmd_history, &self.snippets)
    }

    /// Fresh answer slots for whichever challenge is now at the front of the
    /// queue; what was typed for the previous one is scrubbed first.
    fn reset_auth_answers(&mut self) {
        scrub_answers(&mut self.auth_answers);
        if let Some((challenge, _)) = self.auth_queue.front() {
            self.auth_answers = vec![String::new(); challenge.prompt.prompts.len()];
        }
    }

    /// [`reset_auth_answers`](Self::reset_auth_answers), then give the first
    /// answer field the focus — once the modal is on screen to take it, and
    /// only for a challenge that may take it ([`challenge_may_take_focus`]).
    fn begin_auth_prompt(&mut self) -> Task<Message> {
        self.reset_auth_answers();
        // A new modal: its fields wait out `AUTH_ARM_DELAY` again.
        self.auth_shown_at = None;
        let may_focus = self.front_may_take_focus();
        self.auth_focus_owed = may_focus && !self.auth_answers.is_empty();
        // The modal is rebuilt in place, so the field the last answer was
        // typed in would keep the focus for this challenge. One that may not
        // take the keyboard gets it given up.
        let release = if may_focus || self.auth_queue.is_empty() {
            Task::none()
        } else {
            self.focus.then_query(release_auth_focus())
        };
        Task::batch([release, self.deliver_auth_focus()])
    }

    /// Hand the owed focus to the first answer field, but only while the
    /// modal is what the user is looking at. iced's focus operation unfocuses
    /// every other input, so focusing a field that is not drawn takes the keys
    /// away from the lock screen's password or the palette's query — and a
    /// reconnecting session can raise a challenge at any time. Until the modal
    /// is uncovered the focus stays owed; `poll_auth_prompts` retries it.
    ///
    /// Nor while keys are still arriving: they are meant for wherever the user
    /// is typing, and would land in this server's answer instead. The focus is
    /// then dropped, not kept owed — the field waits for a click.
    fn deliver_auth_focus(&mut self) -> Task<Message> {
        let now = std::time::Instant::now();
        let visible = auth_modal_visible(&self.screen, self.topmost_overlay());
        note_auth_shown(&mut self.auth_shown_at, visible, now);
        if take_owed_focus(&mut self.auth_focus_owed, visible)
            && !typing_recently(self.last_keypress, now)
        {
            self.focus.focus(auth_input_id(0))
        } else {
            Task::none()
        }
    }

    /// Whether the user's own click is what `session_id` is signing in for
    /// right now: a Connect or a split still connecting under that id, or a
    /// "Reconnect monitoring" still out for it.
    fn auth_user_started(&self, session_id: &str) -> bool {
        !session_id.is_empty()
            && (self.tabs.iter().any(|t| {
                t.pending_session_id == session_id || t.split_pending.as_deref() == Some(session_id)
            }) || self.monitor_parked.get(session_id).is_some_and(|p| p.resuming))
    }

    /// Whether the challenge at the front of the queue may take the keyboard.
    fn front_may_take_focus(&self) -> bool {
        self.auth_queue.front().is_some_and(|(challenge, _)| {
            challenge_may_take_focus(
                &challenge.purpose,
                self.auth_user_started(&challenge.session_id),
            )
        })
    }

    /// The monitor tick should refresh the ports tab too: it is on screen and
    /// its list is another session's, or older than 10 s.
    fn ports_due(&self, session_id: &str) -> bool {
        self.bottom_panel_tab == BottomTab::Ports
            && !self.bottom_panel_collapsed
            && !self.ports_inflight.contains(session_id)
            && !session_id.is_empty()
            && (self.ports_session != session_id
                || self
                    .ports_fetched_at
                    .is_none_or(|t| t.elapsed() >= Duration::from_secs(10)))
    }

    /// The Cmd+K palette for the current query; see [`build_palette_items`].
    fn palette_items(&self) -> Vec<PaletteItem> {
        build_palette_items(
            &self.palette_query,
            &self.connections,
            &self.snippets,
            &self.collapsed_groups,
        )
    }
}

pub fn run() -> iced::Result {
    let initial_scale = load_ui_scale() as f64;

    // The app opens on the setup or the lock screen, which hold nothing but
    // master-password fields: no input method there, from the first frame.
    // Recorded before the window exists, which opens with this setting.
    iced_winit::ime::set_allowed(false);

    // Load window icon from embedded PNG
    let window_icon = iced::window::icon::from_file_data(
        include_bytes!("../../../assets/icon_256.png"),
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
        "../../../assets/fonts/SymbolsNerdFontMono-Regular.ttf"
    );
    const CJK_EMBED: &[u8] = include_bytes!(
        "../../../assets/fonts/NotoSansSC-Min.ttf"
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
// Input method: kept away from secrets
// ---------------------------------------------------------------------------

/// `handle_message`, then the input method brought in line with where the
/// keyboard focus is now.
fn update(state: &mut NeoShell, message: Message) -> Task<Message> {
    let moved = moves_focus(&message);
    if matches!(message, Message::TerminalMouseDown(_) | Message::FocusMayHaveMoved) {
        // The runtime anchored the candidate window at the click.
        state.ime_area = None;
    }
    let before = (state.screen.clone(), state.topmost_overlay());
    let issued = state.focus.issued;
    let task = handle_message(state, message);
    // A modal or a screen that came or went took its fields — and perhaps
    // the focus — with it. One query per update, and none when this update
    // moved the focus itself: that move asks after it has landed.
    let changed = (state.screen.clone(), state.topmost_overlay()) != before;
    let task = if (moved || changed) && state.focus.issued == issued {
        Task::batch([task, state.focus.query()])
    } else {
        task
    };
    sync_input_method(state);
    task
}

/// Persist an edited theme and publish it to everything that cannot see
/// `state`: the shared style fns (through `theme_config::live()`) and the
/// ANSI palette of every open terminal. Grids are only re-paletted when the
/// table actually changed — `set_palette` forces a full repaint, and the
/// RGB sliders fire this on every step of a drag.
fn apply_theme(state: &mut NeoShell) {
    state.theme_cfg.save();
    let ansi_changed = theme_config::live().ansi != state.theme_cfg.ansi;
    theme_config::set_live(&state.theme_cfg);
    if ansi_changed {
        for tab in &state.tabs {
            tab.terminal.lock().set_palette(state.theme_cfg.ansi);
            if let Some(sp) = &tab.split {
                sp.terminal.lock().set_palette(state.theme_cfg.ansi);
            }
        }
    }
}

fn handle_message(state: &mut NeoShell, message: Message) -> Task<Message> {
    // Any real user input re-arms the idle re-lock timer. Kept here rather
    // than in each arm so a new input message cannot forget to do it.
    if matches!(
        message,
        Message::KeyboardEvent(..)
            | Message::TerminalMouseDown(..)
            | Message::TerminalMouseMove(..)
            | Message::TerminalMouseUp(..)
            | Message::TerminalScrollUp(..)
            | Message::TerminalScrollDown(..)
            | Message::PasteClipboard
            | Message::SidebarHover(..)
            | Message::SplitDividerPressed
            | Message::FileDropped(..)
    ) {
        state.last_activity = std::time::Instant::now();
    }
    // Keys only: a sign-in modal that comes up mid-typing must not take the
    // keyboard (see `deliver_auth_focus`).
    if matches!(message, Message::KeyboardEvent(..)) {
        state.last_keypress = Some(std::time::Instant::now());
    }

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
            state.last_activity = std::time::Instant::now();
            // proxies.json / tunnels.json survive a deleted vault, so a fresh
            // vault can still inherit cleartext credentials to move.
            migrate_store_secrets(state);
            // So does a cleartext history.json, imported the same way.
            let history = unlock_history(state);
            // And a cleartext collapsed_groups.json.
            let groups = unlock_groups(state);
            // tunnels.json survives a deleted vault, so this path needs the
            // auto-start too.
            Task::batch(vec![
                Task::done(Message::LoadConnections),
                Task::done(Message::AutoStartTunnels),
                history,
                groups,
            ])
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
            state.last_activity = std::time::Instant::now();
            // Synchronous, and before the auto-start below: the migration is
            // what moves the jump-host credentials out of tunnels.json and
            // into the vault, and `AutoStartTunnels` needs them resolved.
            // Doing it as another `Task::done` would leave the ordering to
            // the runtime.
            migrate_store_secrets(state);
            let history = unlock_history(state);
            // Before `LoadConnections` lands: it prunes this set.
            let groups = unlock_groups(state);
            Task::batch(vec![
                Task::done(Message::LoadConnections),
                Task::done(Message::CheckForUpdate),
                Task::done(Message::AutoStartTunnels),
                history,
                groups,
            ])
        }
        Message::AutoStartTunnels => {
            for t in state.tunnel_store.load() {
                if !t.auto_start {
                    continue;
                }
                let name = t.name.clone();
                // Re-entrant: an idle re-lock followed by an unlock dispatches
                // this again, and every already-running tunnel would otherwise
                // come back as "auto-start failed: tunnel already running".
                if state.tunnel_manager.is_running(&t.id) {
                    continue;
                }
                log::info!("auto-starting tunnel '{}'", name);
                // `load()` fills credentials in best-effort and logs at debug
                // on failure; re-fetch through `get_for_connect` so a locked
                // vault is a real error instead of a jump-host handshake that
                // offers an empty password.
                let cfg = match state.tunnel_store.get_for_connect(&t.id) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        log::warn!("auto-start skipped for '{}': {}", name, e);
                        continue;
                    }
                };
                if let Err(e) = state.tunnel_manager.start(cfg) {
                    log::warn!("auto-start failed for '{}': {}", name, e);
                }
            }
            Task::none()
        }

        // ---- vault re-lock ---------------------------------------------------
        Message::LockNow => {
            if state.screen != Screen::Main {
                return Task::none();
            }
            lock_vault(state)
        }
        Message::IdleCheck => {
            if state.screen == Screen::Main
                && idle_lock_due(state.lock_timeout_mins, state.last_activity.elapsed())
            {
                log::info!(
                    "vault re-locked after {} idle minutes",
                    state.lock_timeout_mins
                );
                return lock_vault(state);
            }
            Task::none()
        }
        Message::SetLockTimeout(mins) => {
            let mins = clamp_lock_timeout(mins);
            state.lock_timeout_mins = mins;
            state.last_activity = std::time::Instant::now();
            save_lock_timeout(mins);
            Task::none()
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
        Message::ConnectionsLoaded(mut conns) => {
            // In the order every list shows them: the vault is a map.
            conns.sort_by(connection_order);
            state.connections = conns;
            // Re-read ~/.ssh/config alongside the list it is compared with:
            // the connect dialog and the welcome screen's importer render
            // from this copy instead of parsing the file on every frame.
            // Opening the connect dialog lands here via LoadConnections.
            state.ssh_config_hosts = crate::sshconfig::parse_ssh_config();
            // A group whose last connection was deleted or moved away is not
            // folded any more: were it to come back, it would come back open.
            if prune_collapsed_groups(&mut state.collapsed_groups, &state.connections) {
                return schedule_groups_save(state);
            }
            Task::none()
        }
        Message::ConnectTo(id) => {
            if state.connecting_ids.contains(&id) {
                return Task::none();
            }
            state.connecting_ids.insert(id.clone());
            state.show_connect_dialog = false;
            // The key that started this — Enter in the palette — is not
            // typing somewhere else: this connect's sign-in may still take
            // the keyboard (see `deliver_auth_focus`).
            state.last_keypress = None;

            // Create a placeholder tab immediately so user sees feedback
            let tab_id = uuid::Uuid::new_v4().to_string();
            // The session's id, known before the connect is: its sign-in
            // challenges carry it, so closing this tab can withdraw them.
            let session_id = SshManager::new_session_id();
            let terminal = Arc::new(parking_lot::Mutex::new(TerminalGrid::new(120, 40)));
            {
                let mut grid = terminal.lock();
                let connecting = i18n::t("monitor.connecting");
                grid.write(format!("\x1b[33m{}\x1b[0m\r\n", connecting).as_bytes());
            }
            state.tabs.push(TerminalTab {
                id: tab_id.clone(),
                session_id: String::new(), // placeholder
                connection_id: id.clone(),
                title: i18n::t("monitor.connecting").to_string(),
                terminal,
                custom_title: None,
                split: None,
                focus_split: false,
                bounds: PaneBounds::default(),
                pending_session_id: session_id.clone(),
                split_pending: None,
            });
            state.active_tab = Some(state.tabs.len() - 1);

            let store = state.store.clone();
            let ssh = state.ssh_manager.clone();
            let tab_id2 = tab_id.clone();
            let conn_id_for_log = id.clone();
            let conn_id = id.clone();
            Task::perform(
                async move {
                    log::info!("connect_to: attempting connection to id={}", conn_id_for_log);
                    // Run blocking SSH connect on dedicated thread
                    tokio::task::spawn_blocking(move || {
                        let config = store.get_connection(&id)?;
                        log::info!("connect_to: resolved {}@{}:{} (auth={}, proxy={:?})",
                            config.username, config.host, config.port,
                            config.auth_type, config.proxy_id);
                        let session_id = ssh.connect_config_with_id(&session_id, &config)?;
                        let title = format!("{}@{}:{}", config.username, config.host, config.port);
                        Ok((tab_id2, session_id, title, id))
                    }).await.map_err(|e| format!("Task: {}", e))?
                },
                // A failure belongs to this tab alone: it goes, the others
                // connecting beside it stay (see `ConnectFailed`).
                move |result: Result<(String, String, String, String), String>| match result {
                    Ok((tab_id, session_id, title, conn_id)) => {
                        Message::SshConnected(tab_id, session_id, title, conn_id)
                    }
                    Err(e) => Message::ConnectFailed(tab_id.clone(), conn_id.clone(), e),
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
            state.form_opened = opened_connection_form(&state.form);
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
            // Nothing is saved on a port that does not read as one: the form
            // stays open under the message.
            let port = match form_port(&state.form.port, 22) {
                Ok(port) => port,
                Err(message) => {
                    state.show_notice("form.err.title", message);
                    return Task::none();
                }
            };
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
            // The form has no colour field; an edit must not wipe the tag the
            // sidebar draws from it.
            let preserved_color = edit_id
                .as_ref()
                .and_then(|id| state.connections.iter().find(|c| &c.id == id))
                .map(|c| c.color.clone())
                .unwrap_or_default();

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
                // Trimmed: the group is the sidebar's grouping and folding
                // key, and "生产 " — a stray space an input method left —
                // would be a second group that reads exactly like "生产".
                group: state.form.group.trim().to_string(),
                color: preserved_color,
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
            let port = match form_port(&state.form.port, 22) {
                Ok(port) => port,
                Err(message) => {
                    state.show_notice("form.err.title", message);
                    return Task::none();
                }
            };
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
                clone.name = i18n::tf("conn.copy_name", &[("name", &src.name)]);
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
            // Output held back until this connect landed (see
            // `next_ssh_event`) is drained in a later update: after the
            // screen clear below, or dropped if the tab is gone.
            if state.ssh_held.is_some() {
                state.ssh_manager.waker().notify_one();
            }
            // Update existing placeholder tab (created in ConnectTo)
            let Some(tab) = state.tabs.iter_mut().find(|t| t.id == tab_id) else {
                // Closed while it connected — `TabClosed` already gave the
                // connection back. Nothing would ever show or close this
                // session: close it now.
                let ssh = state.ssh_manager.clone();
                return Task::perform(
                    async move {
                        let _ = ssh.disconnect(&session_id);
                    },
                    |_| Message::None,
                );
            };
            let sid_for_fetch = session_id.clone();
            tab.session_id = session_id;
            tab.pending_session_id.clear();
            tab.connection_id = connection_id.clone();
            tab.title = title;
            // Clear the "Connecting..." message
            tab.terminal.lock().write(b"\x1b[2J\x1b[H"); // Clear screen + home
            state.connecting_ids.remove(&connection_id);
            state.show_connect_dialog = false;

            state.current_dir.insert(sid_for_fetch.clone(), "~".to_string());
            Task::done(Message::ChangeDir(sid_for_fetch, "~".to_string()))
        }
        Message::ConnectFailed(tab_id, connection_id, e) => {
            log::error!("{}", e);
            let Some(idx) = state.tabs.iter().position(|t| t.id == tab_id) else {
                // The tab was closed while it connected — a sign-in withdrawn
                // by that close ends here too. Nobody is waiting for this.
                return Task::none();
            };
            state.tabs.remove(idx);
            state.active_tab = active_after_removal(state.active_tab, idx, state.tabs.len());
            // Allow a manual retry.
            state.connecting_ids.remove(&connection_id);
            state.error_message = e;
            state.show_error_dialog = true;
            Task::none()
        }
        Message::TerminalInput(session_id, data) => {
            // Track typed commands to capture "sz filename". Scoped so the
            // cmd_buffer borrow ends before command_was_echoed reads the grid.
            let submitted: Option<String> = {
                let buf = state.cmd_buffer.entry(session_id.clone()).or_default();
                if data == "\r" || data == "\n" {
                    let cmd = buf.trim().to_string();
                    buf.clear();
                    Some(cmd)
                } else if data == "\x7f" || data == "\x08" {
                    buf.pop(); // Backspace
                    None
                } else if data.chars().all(|c| !c.is_control()) {
                    buf.push_str(&data);
                    None
                } else {
                    None
                }
            };
            if let Some(cmd) = submitted {
                // Enter pressed — record to history, but ONLY when the remote
                // echoed the line. These characters came from the keyboard, so
                // at a no-echo prompt they are a password, not a command. And
                // never while locked: the lock wiped the history, and it only
                // comes back with the key.
                if !cmd.is_empty()
                    && state.screen == Screen::Main
                    && command_was_echoed(state, &session_id, &cmd)
                {
                    // Find session title
                    let title = state.tabs.iter()
                        .find(|t| t.session_id == session_id)
                        .map(|t| t.title.clone())
                        .unwrap_or_default();
                    let host = state.session_host(&session_id);
                    // The only producer of history records — and so of
                    // history.enc, which is written from `cmd_history` alone.
                    // Keep it inside this gate.
                    state.cmd_history.push(CmdRecord {
                        cmd: cmd.clone(),
                        session_title: title,
                        host,
                        timestamp: unix_now(),
                    });
                    if state.cmd_history.len() > HISTORY_MAX {
                        state.cmd_history.drain(..state.cmd_history.len() - HISTORY_MAX);
                    }
                    // Written by a paced FlushHistory, not per Enter:
                    // write_private fsyncs.
                    state.history_sync.dirty = true;
                }
                if cmd.starts_with("sz ") {
                    let filename = cmd[3..].trim().to_string();
                    if !filename.is_empty() {
                        state.sz_filename.insert(session_id.clone(), filename);
                    }
                }
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
            // Double-click (two clicks on the same tab within 400 ms) opens
            // the rename dialog instead of just re-selecting.
            let now = std::time::Instant::now();
            if let Some((last_idx, t)) = state.last_tab_click {
                if last_idx == idx
                    && now.duration_since(t) < Duration::from_millis(400)
                    && idx < state.tabs.len()
                {
                    state.last_tab_click = None;
                    state.tab_rename = Some(idx);
                    state.tab_rename_input =
                        state.tabs[idx].display_title().to_string();
                    return state.focus.focus(text_input::Id::new(TAB_RENAME_INPUT_ID));
                }
            }
            state.last_tab_click = Some((idx, now));
            if idx < state.tabs.len() {
                state.active_tab = Some(idx);
            }
            Task::none()
        }
        Message::TabClosed(idx) => {
            if idx < state.tabs.len() {
                let session_id = state.tabs[idx].session_id.clone();
                // Closing a tab also tears down its split pane's session.
                let split_sid = state.tabs[idx]
                    .split
                    .as_ref()
                    .map(|s| s.session_id.clone());
                // Every sign-in the tab is waiting on — its connect, its
                // split's, a reconnect of either — is withdrawn as a cancel:
                // the modal goes, and each SSH thread stops waiting for an
                // answer nobody will give.
                let asking = tab_auth_sessions(&state.tabs[idx]);
                let (withdrawn, front) =
                    take_challenges(&mut state.auth_queue, |c| asking.contains(&c.session_id));
                for challenge in withdrawn {
                    challenge.cancel();
                }
                // Closed while connecting: the connection can be opened again
                // at once — the connect's own end no longer finds this tab.
                if session_id.is_empty() {
                    state.connecting_ids.remove(&state.tabs[idx].connection_id);
                }
                let ssh = state.ssh_manager.clone();
                state.tabs.remove(idx);
                // The modal moves on to the next challenge, if the one on it
                // was this tab's.
                let auth = if front { state.begin_auth_prompt() } else { Task::none() };
                // Cleanup monitoring/file data for this session
                state.server_stats.remove(&session_id);
                state.top_processes.remove(&session_id);
                state.monitor_parked.unpark(&session_id);
                state.file_entries.remove(&session_id);
                state.current_dir.remove(&session_id);
                state.prompt_cwd.remove(&session_id);
                state.alerts_active.remove(&session_id);
                state.broadcast_selected.remove(&session_id);
                if let Some(sp) = &split_sid {
                    state.alerts_active.remove(sp);
                    state.broadcast_selected.remove(sp);
                }
                if state.tabs.is_empty() {
                    state.active_tab = None;
                } else {
                    state.active_tab = Some(idx.min(state.tabs.len() - 1));
                }
                let disconnect = Task::perform(
                    async move {
                        let _ = ssh.disconnect(&session_id);
                        if let Some(sp) = split_sid {
                            let _ = ssh.disconnect(&sp);
                        }
                    },
                    |_| Message::None,
                );
                Task::batch([auth, disconnect])
            } else {
                Task::none()
            }
        }

        // ---- SSH event polling -----------------------------------------------
        Message::PollSshEvents => {
            // Keyboard-interactive challenges ride this drain rather than a
            // timer of their own; a new one comes back as a focus task.
            let auth = poll_auth_prompts(state);
            let mut rz_sessions: Vec<String> = Vec::new();
            let mut sz_sessions: Vec<String> = Vec::new();

            let mut budget = DrainBudget::new(SSH_DRAIN_BYTES, SSH_DRAIN_EVENTS);
            if let Some(rx) = &state.ssh_event_rx {
                while let Some(event) =
                    next_ssh_event(&mut state.ssh_held, rx, &mut budget, &state.tabs)
                {
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
                            // Split-aware lookup: data may belong to a main
                            // pane or a split pane.
                            if let Some(term) =
                                state.find_terminal_for_session(&session_id).cloned()
                            {
                                let mut grid = term.lock();
                                grid.write(&data);
                                grid.scroll_offset = 0; // Auto-scroll to bottom on new data
                            }
                        }
                        SshEvent::Closed { session_id } => {
                            // What `forget_session` drops; spelled out here,
                            // where the event receiver holds `state`.
                            state.zmodem_active.remove(&session_id);
                            state.broadcast_selected.remove(&session_id);
                            state.alerts_active.remove(&session_id);
                            state.server_stats.remove(&session_id);
                            state.top_processes.remove(&session_id);
                            state.monitor_parked.unpark(&session_id);
                            state.file_entries.remove(&session_id);
                            state.current_dir.remove(&session_id);
                            state.prompt_cwd.remove(&session_id);

                            // Split pane closed → drop just that pane; main
                            // pane closed with a live split → promote the
                            // split to main. Only a tab with no split left
                            // is removed outright.
                            let handled = remove_split_pane(&mut state.tabs, &session_id);
                            if !handled {
                                if let Some(idx) = state
                                    .tabs
                                    .iter()
                                    .position(|t| t.session_id == session_id)
                                {
                                    state.tabs.remove(idx);
                                    if state.tabs.is_empty() {
                                        state.active_tab = None;
                                    } else {
                                        state.active_tab =
                                            Some(idx.min(state.tabs.len() - 1));
                                    }
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
                                tab.title = reconnecting_title(title_base(&tab.title), attempt);
                            }
                        }
                        SshEvent::Reconnected { session_id } => {
                            if let Some(tab) =
                                state.tabs.iter_mut().find(|t| t.session_id == session_id)
                            {
                                tab.title = title_base(&tab.title).to_string();
                            }
                        }
                    }
                }
            }
            // Out of budget with output perhaps still queued: the rest comes
            // in a fresh update, so the window redraws and takes input in
            // between instead of freezing until a flood is through. A message
            // rather than a wake, so the wakes' frame pacing (`ssh_wakes`)
            // does not throttle a backlog. Not while output is held for a
            // connect: `SshConnected` wakes the drain for that.
            let auth = if !budget.has_room() && state.ssh_held.is_none() {
                Task::batch([auth, Task::done(Message::PollSshEvents)])
            } else {
                auth
            };

            // Dispatch ZMODEM messages (only one Task can be returned per update)
            if let Some(sid) = rz_sessions.into_iter().next() {
                return Task::batch([auth, Task::done(Message::RzDetected(sid))]);
            }
            if let Some(sid) = sz_sessions.into_iter().next() {
                return Task::batch([auth, Task::done(Message::SzDetected(sid))]);
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
                            let resize = Task::perform(
                                async move {
                                    tokio::task::spawn_blocking(move || {
                                        ssh.resize(&session_id, cols, rows)
                                    }).await.ok();
                                    ()
                                },
                                |_| Message::None,
                            );
                            return Task::batch([auth, resize]);
                        }
                    }
                }
            }

            auth
        }

        // ---- keyboard -------------------------------------------------------
        Message::KeyboardEvent(key, modifiers, text, captured) => {
            if state.screen != Screen::Main { return Task::none(); }

            // ESC dismisses what is on top: the overlay view_main is drawing
            // (one z-order, see `Overlay`), then the terminal search bar.
            // With nothing to dismiss it falls through and reaches the shell
            // as a plain ESC byte, which vim and friends depend on.
            if let keyboard::Key::Named(keyboard::key::Named::Escape) = &key {
                // A text input drops its focus on Esc.
                state.quick_cmd_focused = false;
                if state.close_topmost_overlay() {
                    return Task::none();
                }
                if state.term_search_active {
                    return Task::done(Message::TerminalSearchClose);
                }
            }

            // Palette gets first dibs on navigation keys; typed characters
            // reach the focused text_input through the widget tree, so we
            // swallow everything else here.
            if state.show_palette {
                match &key {
                    keyboard::Key::Named(keyboard::key::Named::ArrowUp) => {
                        return Task::done(Message::PaletteNavUp);
                    }
                    keyboard::Key::Named(keyboard::key::Named::ArrowDown) => {
                        return Task::done(Message::PaletteNavDown);
                    }
                    keyboard::Key::Named(keyboard::key::Named::Enter) => {
                        return Task::done(Message::PaletteExecute);
                    }
                    keyboard::Key::Character(c)
                        if modifiers.command() && matches!(c.as_str(), "k" | "K") =>
                    {
                        state.show_palette = false;
                        return Task::none();
                    }
                    _ => return Task::none(),
                }
            }

            // Tab-rename modal: Enter commits (Esc is handled above).
            if state.tab_rename.is_some() {
                match &key {
                    keyboard::Key::Named(keyboard::key::Named::Enter) => {
                        return Task::done(Message::TabRenameCommit);
                    }
                    _ => return Task::none(),
                }
            }

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
                        // A focused text input pastes on its own; the terminal
                        // must not receive the clipboard as well.
                        "v" | "V" if clipboard_mod => {
                            if captured {
                                return Task::none();
                            }
                            return Task::done(Message::PasteClipboard);
                        }
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
                        "k" | "K" => return Task::done(Message::TogglePalette),
                        // Cmd+D / Cmd+Shift+D — split the active tab
                        // (vertical divider / horizontal divider).
                        "d" | "D" => return Task::done(Message::SplitTab(!modifiers.shift())),
                        // Cmd+] — toggle pane focus inside a split tab.
                        "]" => return Task::done(Message::SplitFocusToggle),
                        "t" | "T" => return Task::done(Message::ShowConnectDialog),
                        "w" | "W" => {
                            // Cmd+Shift+W = close focused pane (split-aware);
                            // Cmd+W = close current tab.
                            if modifiers.shift() {
                                return Task::done(Message::CloseFocusedPane);
                            }
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
                        // Cmd/Ctrl + Shift + L → re-lock the vault now.
                        // Shift-qualified so it cannot be hit by accident and
                        // so plain Ctrl+L still clears the remote screen.
                        "l" | "L" if modifiers.shift() => {
                            return Task::done(Message::LockNow);
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

            // Overlay guard: when any modal / panel is open, keystrokes are
            // meant for its inputs — never forward them to the terminal.
            // (Fixes hex typed in Settings → Appearance echoing in the shell.)
            if state.any_overlay_open() {
                return Task::none();
            }

            // Quick-command autocomplete: Tab / Down take the top suggestion.
            // A text input lets exactly these keys through uncaptured even
            // while it has focus, so the focus guess is confirmed against the
            // widget tree first. If the input turns out not to be focused,
            // the key still goes to the terminal.
            if !captured && state.quick_cmd_focused && is_autocomplete_key(&key, &modifiers) {
                let accept = state.quick_cmd_suggestions().into_iter().next();
                let fallback: Vec<Message> = state
                    .focused_session_id()
                    .zip(key_to_terminal_bytes(&key, &modifiers, text.as_deref()))
                    .map(|(sid, data)| {
                        state
                            .keystroke_targets(sid)
                            .into_iter()
                            .map(|target| Message::TerminalInput(target, data.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                return quick_cmd_input_focused().then(move |focused| {
                    if focused {
                        accept
                            .clone()
                            .map_or_else(Task::none, |s| Task::done(Message::QuickCmdAccept(s)))
                    } else {
                        Task::batch(fallback.clone().into_iter().map(Task::done))
                    }
                });
            }

            // A key a focused text input consumed was typed into that input
            // (quick command box, path fields, search bar). It used to reach
            // the shell too — every quick command ran twice.
            if captured {
                return Task::none();
            }
            // A printable key arriving uncaptured proves no text input has focus.
            if text.as_deref().is_some_and(|t| t.chars().any(|c| !c.is_control())) {
                state.quick_cmd_focused = false;
            }

            if let Some(session_id) = state.focused_session_id() {
                if let Some(data) = key_to_terminal_bytes(&key, &modifiers, text.as_deref()) {
                    // Live sync mode fans the keystroke out to every ticked
                    // session (the focused one included, deduped).
                    let tasks: Vec<Task<Message>> = state
                        .keystroke_targets(session_id)
                        .into_iter()
                        .map(|sid| Task::done(Message::TerminalInput(sid, data.clone())))
                        .collect();
                    return Task::batch(tasks);
                }
            }
            Task::none()
        }

        Message::PasteClipboard => {
            // A right-click away from the open file menu just closes it.
            if state.remote_menu.take().is_some() { return Task::none(); }
            // Right-click paste is terminal-only. If an overlay is open, a
            // right-click on the overlay backdrop shouldn't send paste chars
            // into the hidden terminal.
            if state.any_overlay_open() { return Task::none(); }
            if let Some(session_id) = state.focused_session_id() {
                let ssh = state.ssh_manager.clone();
                // Sync mode mirrors the paste to every ticked session too.
                let mut targets: Vec<String> = if state.sync_input_on {
                    state.broadcast_selected.iter().cloned().collect()
                } else {
                    Vec::new()
                };
                if !targets.contains(&session_id) {
                    targets.push(session_id);
                }
                // Bracketed paste (DEC 2004) is switched per terminal, so each
                // target's own flag is read here, while the grids are at hand.
                // With it on, a multi-line paste into vim or a shell arrives
                // as text instead of executing line by line.
                let targets: Vec<(String, bool)> = targets
                    .into_iter()
                    .map(|sid| {
                        let bracketed = state
                            .find_terminal_for_session(&sid)
                            .is_some_and(|t| t.lock().bracketed_paste());
                        (sid, bracketed)
                    })
                    .collect();
                return Task::perform(
                    async move {
                        let mut clipboard = arboard::Clipboard::new()
                            .map_err(|e| format!("Clipboard error: {}", e))?;
                        let content = clipboard.get_text()
                            .map_err(|e| format!("Clipboard read error: {}", e))?;
                        for (sid, bracketed) in &targets {
                            ssh.send_data(sid, &crate::terminal::encode_paste(&content, *bracketed))?;
                        }
                        Ok(())
                    },
                    |r: Result<(), String>| match r {
                        Ok(()) => Message::None,
                        Err(e) => Message::Error(e),
                    },
                );
            }
            Task::none()
        }

        Message::CancelTransfer => {
            if let Some(ref progress) = state.transfer_progress {
                progress.finished.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            state.transfer_progress = None;
            // Cancel means the whole drop, not just the file in flight.
            state.drop_queue.clear();
            Task::none()
        }

        Message::ModifiersChanged(modifiers) => {
            state.modifiers = modifiers;
            Task::none()
        }
        // `update` asks the widget tree after it (see `moves_focus`).
        Message::FocusMayHaveMoved => Task::none(),
        Message::FocusFound(seq, id) => {
            state.focus.found(seq, id);
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
                    let sid = tab.focused_session().to_string();
                    // The ports tab rides the same tick, at a slower rate.
                    let ports = state
                        .ports_due(&sid)
                        .then(|| Task::done(Message::FetchPorts));
                    // One fetch per session at a time (see `InFlight`).
                    if !state.monitor_inflight.start(&sid) {
                        return ports.unwrap_or_else(Task::none);
                    }
                    let fetch = Task::perform(
                        async move {
                            let session_id = sid.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                let stats = ssh.fetch_server_stats(&session_id)?;
                                let procs = ssh.fetch_top_processes(&session_id, 15)?;
                                Ok((stats, procs))
                            })
                            .await
                            .unwrap_or_else(|e| Err(format!("{}", e)));
                            (sid, result)
                        },
                        |(sid, result)| match result {
                            Ok((stats, procs)) => Message::MonitorDataReceived(sid, stats, procs),
                            Err(e) => Message::MonitorError(sid, e),
                        },
                    );
                    return match ports {
                        Some(ports) => Task::batch([fetch, ports]),
                        None => fetch,
                    };
                }
            }
            Task::none()
        }
        Message::MonitorDataReceived(sid, stats, procs) => {
            state.monitor_inflight.finish(&sid);
            state.monitor_parked.unpark(&sid);
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

            // Threshold alerts: CPU is approximated as load_1m / cores
            // (matches what the monitor panel shows); mem/disk straight %.
            if state.alert_cfg.enabled {
                let mut breaches: Vec<String> = Vec::new();
                let cpu_pct = if stats.cpu_cores > 0 {
                    (stats.load_1m / stats.cpu_cores as f64 * 100.0).min(999.0)
                } else {
                    0.0
                };
                if cpu_pct >= state.alert_cfg.cpu_pct as f64 {
                    breaches.push(format!("CPU {:.0}%", cpu_pct));
                }
                if stats.mem_percent >= state.alert_cfg.mem_pct as f64 {
                    breaches.push(format!("MEM {:.0}%", stats.mem_percent));
                }
                if stats.disk_percent >= state.alert_cfg.disk_pct as f64 {
                    breaches.push(format!("DISK {:.0}%", stats.disk_percent));
                }
                if breaches.is_empty() {
                    state.alerts_active.remove(&sid);
                } else {
                    state.alerts_active.insert(sid.clone(), breaches);
                }
            }

            state.server_stats.insert(sid.clone(), stats);
            state.top_processes.insert(sid.clone(), procs);

            // Sync file browser with shell CWD (extracted from terminal
            // prompt) — a split pane's too, now that the panel can show it.
            if let Some(term) = state.find_terminal_for_session(&sid) {
                let grid = term.lock();
                if let Some(cwd) = extract_cwd_from_prompt(&grid) {
                    drop(grid);
                    if follow_prompt_cwd(
                        &mut state.prompt_cwd,
                        &mut state.current_dir,
                        &state.file_entries,
                        &sid,
                        &cwd,
                    ) {
                        return Task::done(Message::ChangeDir(sid, cwd));
                    }
                }
            }
            Task::none()
        }
        Message::MonitorError(sid, e) => {
            state.monitor_inflight.finish(&sid);
            if !exec_parked(&e) {
                log::warn!("Monitor fetch error: {}", e);
            } else if state.monitor_parked.park(&sid) {
                // Every tick fails this way until the user reconnects: the
                // panel says so from now on, the log says it once.
                log::warn!("Monitoring parked for {}: {}", sid, e);
            }
            Task::none()
        }
        Message::ResumeMonitoring(sid) => {
            // One press, one challenge: nothing more goes out while one is.
            if !state.monitor_parked.begin_resume(&sid) {
                return Task::none();
            }
            // The user's own action: its challenge may take the keyboard.
            state.last_keypress = None;
            let ssh = state.ssh_manager.clone();
            Task::perform(
                async move {
                    let session_id = sid.clone();
                    let result = tokio::task::spawn_blocking(move || ssh.resume_exec(&session_id))
                        .await
                        .unwrap_or_else(|e| Err(format!("Task: {}", e)));
                    (sid, result)
                },
                |(sid, result)| Message::ResumeMonitoringDone(sid, result),
            )
        }
        Message::ExecParked(sid) => {
            if state.monitor_parked.park(&sid) {
                log::warn!("Exec connection parked for {}: file listing refused", sid);
            }
            Task::none()
        }
        Message::ResumeMonitoringDone(sid, result) => {
            if let Err(e) = &result {
                log::warn!("Monitoring reconnect for {} failed: {}", sid, e);
            }
            if state.monitor_parked.finish_resume(&sid, result) {
                // Fill the panel now rather than on the next tick.
                return Task::done(Message::FetchMonitorData);
            }
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
            state.current_dir.insert(sid.clone(), path.clone());
            state.file_entries.insert(sid, Listing::new(path, entries));
            Task::none()
        }
        Message::ChangeDir(sid, path) => {
            let ssh = state.ssh_manager.clone();
            let sid_for_state = sid.clone();
            let sid_for_async = sid.clone();
            let path_async = path.clone();
            state.current_dir.insert(sid_for_state, path.clone());
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || ssh.list_files(&sid_for_async, &path_async))
                        .await.map_err(|e| format!("{}", e))?
                },
                move |result: Result<(String, Vec<FileEntry>), String>| match result {
                    Ok((real_path, entries)) => Message::FilesReceived(sid.clone(), real_path, entries),
                    Err(e) => Message::ListingFailed(sid.clone(), path.clone(), e),
                },
            )
        }
        Message::ListingFailed(sid, requested, error) => {
            note_listing_failed(&mut state.current_dir, &mut state.file_entries, &sid, &requested);
            Task::done(listing_failed(&sid, error))
        }
        Message::FileClicked(sid, dir, entry) => {
            // `dir` is the listing the row was on, which the view handed over
            // with it — not `current_dir`, which may name another directory
            // by now.
            if entry.is_dir || entry.name == ".." {
                let new_path = if entry.name == ".." {
                    remote_parent(&dir)
                } else {
                    join_remote_path(&dir, &entry.name)
                };
                return Task::done(Message::ChangeDir(sid, new_path));
            }
            Task::none()
        }

        // ---- file operations -------------------------------------------------
        Message::UploadFile => {
            let Some(sid) = state
                .active_tab
                .and_then(|idx| state.tabs.get(idx))
                .map(|t| t.focused_session().to_string())
                .filter(|s| !s.is_empty())
            else {
                return Task::none();
            };
            // Before the picker, not after the user has chosen a file.
            if state.transfer_refused_busy() {
                return Task::none();
            }
            let dir = state.browser_dir(&sid).unwrap_or_else(|| "~".to_string());
            // The bar is claimed in `UploadPicked`, once there is a file to
            // send: a cancelled picker leaves nothing behind.
            Task::perform(
                async move {
                    let file = rfd::AsyncFileDialog::new()
                        .set_title(i18n::t("filedialog.upload"))
                        .set_directory(default_download_dir())
                        .pick_file()
                        .await
                        .map(|f| f.path().to_path_buf());
                    (sid, dir, file)
                },
                |(sid, dir, file)| Message::UploadPicked(sid, dir, file),
            )
        }
        Message::DownloadFile(sid, remote_path) => {
            if state.transfer_refused_busy() {
                return Task::none();
            }
            // Only prefills the save dialog (the user still picks the path),
            // but the name comes from the remote listing — sanitise it anyway.
            let filename = safe_local_basename(&remote_path).unwrap_or_else(|| "file".to_string());
            Task::perform(
                async move {
                    let local = rfd::AsyncFileDialog::new()
                        .set_title(i18n::t("filedialog.save"))
                        .set_file_name(&filename)
                        .set_directory(default_download_dir())
                        .save_file()
                        .await
                        .map(|f| f.path().to_path_buf());
                    (sid, remote_path, local)
                },
                |(sid, remote_path, local)| Message::DownloadPicked(sid, remote_path, local),
            )
        }
        Message::DownloadPicked(sid, remote_path, local) => {
            let Some(local) = local.filter(|p| !p.as_os_str().is_empty()) else {
                return Task::none();
            };
            // Another transfer may have started while the dialog was open.
            let Some(progress) = state.claim_transfer_bar() else {
                return Task::none();
            };
            let ssh = state.ssh_manager.clone();
            let local = local.to_string_lossy().to_string();
            Task::perform(
                async move {
                    let bar = progress.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        ssh.download_file_with_progress(&sid, &remote_path, &local, progress)
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("Task: {}", e)));
                    (bar, result)
                },
                |(bar, result)| Message::DownloadDone(bar, result),
            )
        }
        Message::DownloadDone(bar, result) => {
            release_bar(&mut state.transfer_progress, &bar);
            report_transfer_error(state, result);
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
            state.form_opened = opened_connection_form(&state.form);
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
                // Same key the welcome screen counts pending imports with.
                let Some(key) = ssh_config_key(&cfg) else { continue };
                if existing_keys.contains(&key) { continue; }
                let host = if cfg.hostname.is_empty() { cfg.alias.clone() } else { cfg.hostname.clone() };
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
                // Split-aware: snippet lands in the focused pane.
                if let Some(sid) = state.focused_session_id() {
                    let body = if sn.body.ends_with('\n') { sn.body.clone() } else { format!("{}\n", sn.body) };
                    let _ = state.ssh_manager.send_data(&sid, body.as_bytes());
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
            if state.transfer_refused_busy() {
                return Task::none();
            }
            let current_dir = state.current_dir.get(&sid).cloned()
                .unwrap_or_else(|| "~".to_string());
            // The bar is claimed in `RzPicked`, once a file is chosen.
            Task::perform(
                async move {
                    let file = rfd::AsyncFileDialog::new()
                        .set_title(i18n::t("filedialog.rz_upload"))
                        .set_directory(default_download_dir())
                        .pick_file()
                        .await
                        .map(|f| f.path().to_path_buf());
                    (sid, current_dir, file)
                },
                |(sid, dir, file)| Message::RzPicked(sid, dir, file),
            )
        }
        Message::RzPicked(sid, dir, file) => {
            let Some((local, name)) = file.and_then(|f| {
                let name = f.file_name()?.to_string_lossy().to_string();
                Some((f, name))
            }) else {
                return Task::none();
            };
            let Some(progress) = state.claim_transfer_bar() else {
                return Task::none();
            };
            let remote_path = join_remote_path(&dir, &name);
            let local_path = local.to_string_lossy().to_string();
            let ssh = state.ssh_manager.clone();
            Task::perform(
                async move {
                    let sid2 = sid.clone();
                    let bar = progress.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        ssh.upload_file_with_progress(&sid2, &local_path, &remote_path, progress)
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("Task: {}", e)));
                    (sid, bar, result)
                },
                |(sid, bar, result)| Message::RzUploadDone(sid, bar, result),
            )
        }
        Message::ToggleBottomPanel => {
            state.bottom_panel_collapsed = !state.bottom_panel_collapsed;
            state.quick_cmd_focused = false;
            Task::none()
        }

        // ---- v0.7.0: command palette (Cmd+K) --------------------------------
        Message::TogglePalette => {
            state.show_palette = !state.show_palette;
            if state.show_palette {
                state.palette_query.clear();
                state.palette_selected = 0;
                return Task::batch(vec![
                    Task::done(Message::LoadConnections),
                    state.focus.focus(text_input::Id::new(PALETTE_INPUT_ID)),
                ]);
            }
            Task::none()
        }
        Message::PaletteQueryChanged(q) => {
            state.palette_query = q;
            state.palette_selected = 0;
            Task::none()
        }
        Message::PaletteNavUp => {
            let n = state.palette_items().len();
            if n > 0 {
                state.palette_selected = (state.palette_selected + n - 1) % n;
            }
            Task::none()
        }
        Message::PaletteNavDown => {
            let n = state.palette_items().len();
            if n > 0 {
                state.palette_selected = (state.palette_selected + 1) % n;
            }
            Task::none()
        }
        Message::PaletteExecute => {
            let sel = state.palette_selected;
            return Task::done(Message::PaletteExecuteIndex(sel));
        }
        Message::PaletteExecuteIndex(i) => {
            let items = state.palette_items();
            if let Some(item) = items.into_iter().nth(i) {
                state.show_palette = false;
                return Task::done(item.msg);
            }
            Task::none()
        }

        // ---- v0.7.0: tab rename ---------------------------------------------
        Message::TabRenameInput(s) => {
            state.tab_rename_input = s;
            Task::none()
        }
        Message::TabRenameCommit => {
            if let Some(idx) = state.tab_rename.take() {
                if let Some(tab) = state.tabs.get_mut(idx) {
                    let v = state.tab_rename_input.trim().to_string();
                    tab.custom_title = if v.is_empty() { None } else { Some(v) };
                }
            }
            Task::none()
        }
        Message::TabRenameCancel => {
            state.tab_rename = None;
            Task::none()
        }

        // ---- v0.7.0: sidebar group collapse -----------------------------------
        Message::ToggleGroupCollapsed(g) => {
            if !state.collapsed_groups.remove(&g) {
                state.collapsed_groups.insert(g);
            }
            schedule_groups_save(state)
        }
        Message::SetAllGroupsCollapsed(collapse) => {
            if collapse {
                let all = state.connections.iter().map(|c| c.group.clone());
                state.collapsed_groups.extend(all);
            } else {
                state.collapsed_groups.clear();
            }
            schedule_groups_save(state)
        }
        Message::SaveCollapsedGroups(gen) => {
            // Only the save the latest change scheduled; a lock since has
            // sealed the change already and emptied the set.
            if gen == state.groups_gen && state.groups_dirty {
                return persist_groups(state, false);
            }
            Task::none()
        }
        Message::GroupsWritten(result) => {
            if let Err(e) = result {
                log::warn!("folded groups not saved: {}", e);
                // The next change, or the lock, tries again — unless the
                // vault is locked already, which forgot the set.
                if state.screen == Screen::Main {
                    state.groups_dirty = true;
                }
            }
            Task::none()
        }
        Message::SidebarHover(id, entered) => {
            if entered {
                state.hovered_conn = Some(id);
            } else if state.hovered_conn.as_deref() == Some(id.as_str()) {
                // Only clear our own row: the next row's enter can arrive
                // before this row's exit.
                state.hovered_conn = None;
            }
            Task::none()
        }

        // ---- v0.7.0: live sync input ------------------------------------------
        Message::ToggleSyncInput => {
            state.sync_input_on = !state.sync_input_on;
            Task::none()
        }

        // ---- v0.7.0: threshold alerts -----------------------------------------
        Message::AlertEnabledToggled(v) => {
            state.alert_cfg.enabled = v;
            if !v {
                state.alerts_active.clear();
            }
            save_alerts(&state.alert_cfg);
            Task::none()
        }
        Message::AlertCpuChanged(v) => {
            state.alert_cfg.cpu_pct = v;
            save_alerts(&state.alert_cfg);
            Task::none()
        }
        Message::AlertMemChanged(v) => {
            state.alert_cfg.mem_pct = v;
            save_alerts(&state.alert_cfg);
            Task::none()
        }
        Message::AlertDiskChanged(v) => {
            state.alert_cfg.disk_pct = v;
            save_alerts(&state.alert_cfg);
            Task::none()
        }

        // ---- v0.7.0: SSH key manager ------------------------------------------
        Message::ShowKeyManager => {
            // Toolbar buttons toggle (v0.6.19 convention).
            if state.show_key_manager {
                state.show_key_manager = false;
                state.key_deploying = None;
                return Task::none();
            }
            state.show_key_manager = true;
            state.local_keys = crate::sshkeys::list_keys();
            state.key_deploy_status = None;
            Task::done(Message::LoadConnections)
        }
        Message::HideKeyManager => {
            state.show_key_manager = false;
            state.key_deploying = None;
            Task::none()
        }
        Message::KeyFormNameChanged(s) => {
            state.key_form_name = s;
            Task::none()
        }
        Message::KeyFormCommentChanged(s) => {
            state.key_form_comment = s;
            Task::none()
        }
        Message::KeyGenerate => {
            let name = state.key_form_name.trim().to_string();
            let name = if name.is_empty() {
                "id_ed25519_neoshell".to_string()
            } else {
                name
            };
            let comment = state.key_form_comment.trim().to_string();
            match crate::sshkeys::generate_ed25519(&name, &comment) {
                Ok(_) => {
                    state.key_form_name.clear();
                    state.key_form_comment.clear();
                    state.local_keys = crate::sshkeys::list_keys();
                    state.key_deploy_status = Some(i18n::t("keys.generated").to_string());
                }
                Err(e) => {
                    state.key_deploy_status = Some(format!("✗ {}", e));
                }
            }
            Task::none()
        }
        Message::KeyCopyPubkey(path) => {
            if let Some(k) = state.local_keys.iter().find(|k| k.path == path) {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text(&k.pubkey);
                }
                state.key_deploy_status = Some(i18n::t("keys.copied").to_string());
            }
            Task::none()
        }
        Message::KeyDeployStart(path) => {
            state.key_deploying = Some(path);
            state.key_deploy_status = None;
            Task::none()
        }
        Message::KeyDeployCancel => {
            state.key_deploying = None;
            Task::none()
        }
        Message::KeyDeployTo(path, conn_id) => {
            let pubkey = state
                .local_keys
                .iter()
                .find(|k| k.path == path)
                .map(|k| k.pubkey.clone());
            let Some(pubkey) = pubkey else {
                return Task::none();
            };
            state.key_deploying = None;
            state.key_deploy_status = Some(i18n::t("keys.deploying").to_string());
            let store = state.store.clone();
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || {
                        let config = store.get_connection(&conn_id)?;
                        crate::ssh::deploy_pubkey(&config, &pubkey)
                    })
                    .await
                    .map_err(|e| format!("Task: {}", e))?
                },
                Message::KeyDeployDone,
            )
        }
        Message::KeyDeployDone(result) => {
            state.key_deploy_status = Some(match result {
                Ok(host) => format!("{} {}", i18n::t("keys.deploy_ok"), host),
                Err(e) => format!("✗ {}", e),
            });
            Task::none()
        }

        // ---- v0.7.0: split panes ----------------------------------------------
        Message::SplitTab(vertical) => {
            let Some(idx) = state.active_tab else {
                return Task::none();
            };
            let Some(tab) = state.tabs.get(idx) else {
                return Task::none();
            };
            // One split per tab, none while one is still connecting; need a
            // live main session to duplicate.
            if tab.split.is_some() || tab.split_pending.is_some() || tab.session_id.is_empty() {
                return Task::none();
            }
            let tab_id = tab.id.clone();
            let conn_id = tab.connection_id.clone();
            // Known before the connect, like `ConnectTo`'s: closing the tab
            // withdraws the split's sign-in challenges too.
            let session_id = SshManager::new_session_id();
            if let Some(tab) = state.tabs.get_mut(idx) {
                tab.split_pending = Some(session_id.clone());
            }
            // Cmd+D is not typing elsewhere (see `ConnectTo`).
            state.last_keypress = None;
            let store = state.store.clone();
            let ssh = state.ssh_manager.clone();
            let failed_tab = tab_id.clone();
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || {
                        let config = store.get_connection(&conn_id)?;
                        let session_id = ssh.connect_config_with_id(&session_id, &config)?;
                        Ok((tab_id, vertical, session_id))
                    })
                    .await
                    .map_err(|e| format!("Task: {}", e))?
                },
                move |result: Result<(String, bool, String), String>| match result {
                    Ok((tab_id, vertical, session_id)) => {
                        Message::SplitConnected(tab_id, vertical, session_id)
                    }
                    Err(e) => Message::SplitFailed(failed_tab.clone(), e),
                },
            )
        }
        Message::SplitConnected(tab_id, vertical, session_id) => {
            // As in `SshConnected`: output held for this split goes next.
            if state.ssh_held.is_some() {
                state.ssh_manager.waker().notify_one();
            }
            if let Some(tab) = state.tabs.iter_mut().find(|t| t.id == tab_id) {
                // Only the split this tab is still waiting for.
                if tab.split.is_none() && tab.split_pending.as_deref() == Some(session_id.as_str()) {
                    tab.split_pending = None;
                    let terminal =
                        Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24)));
                    tab.split = Some(SplitPane {
                        session_id: session_id.clone(),
                        terminal,
                        vertical,
                        ratio: 0.5,
                        bounds: PaneBounds::default(),
                    });
                    tab.focus_split = true;
                    // The bottom panel follows the focused pane: it shows
                    // this session's files now.
                    state.current_dir.insert(session_id.clone(), "~".to_string());
                    return Task::done(Message::ChangeDir(session_id, "~".to_string()));
                }
            }
            // Tab vanished (or already split) while we were connecting —
            // don't leak the session.
            let ssh = state.ssh_manager.clone();
            Task::perform(
                async move {
                    let _ = ssh.disconnect(&session_id);
                },
                |_| Message::None,
            )
        }
        Message::SplitFailed(tab_id, e) => {
            log::error!("{}", e);
            let Some(tab) = state.tabs.iter_mut().find(|t| t.id == tab_id) else {
                // Closed while the split connected: nobody is waiting.
                return Task::none();
            };
            tab.split_pending = None;
            state.error_message = e;
            state.show_error_dialog = true;
            Task::none()
        }
        Message::SplitDividerPressed => {
            let start = state
                .active_tab
                .and_then(|i| state.tabs.get(i))
                .and_then(|t| t.split.as_ref())
                .map(|sp| {
                    let pos = if sp.vertical { state.cursor_x } else { state.cursor_y };
                    (pos, sp.ratio)
                });
            state.split_drag = start;
            Task::none()
        }
        Message::SplitFocusToggle => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get_mut(idx) {
                    if tab.split.is_some() {
                        tab.focus_split = !tab.focus_split;
                    }
                }
            }
            Task::none()
        }
        Message::CloseFocusedPane => {
            let Some(idx) = state.active_tab else {
                return Task::none();
            };
            let Some(tab) = state.tabs.get(idx) else {
                return Task::none();
            };
            if tab.split.is_none() {
                return Task::done(Message::TabClosed(idx));
            }
            let sid = tab.focused_session().to_string();
            // Taken out here and now, the survivor promoted as the Closed
            // handler would. No `SshEvent::Closed` comes for it: the
            // disconnect's stop flag ends the reader without a word, and a
            // dead pane left holding the focus turned every key into a
            // "Session not found" error. A Closed that does arrive finds
            // nothing left to do.
            if !remove_split_pane(&mut state.tabs, &sid) {
                return Task::none();
            }
            state.forget_session(&sid);
            // The selection was in the pane that is gone.
            state.selection_start = None;
            state.selection_end = None;
            state.selecting = false;
            // Its sign-in challenges go with it, as a closed tab's do.
            let (withdrawn, front) =
                take_challenges(&mut state.auth_queue, |c| c.session_id == sid);
            for challenge in withdrawn {
                challenge.cancel();
            }
            let auth = if front { state.begin_auth_prompt() } else { Task::none() };
            let ssh = state.ssh_manager.clone();
            let disconnect = Task::perform(
                async move {
                    let _ = ssh.disconnect(&sid);
                },
                |_| Message::None,
            );
            Task::batch([auth, disconnect])
        }

        Message::RzUploadDone(sid, bar, result) => {
            release_bar(&mut state.transfer_progress, &bar);
            if result.is_err() {
                report_transfer_error(state, result);
                return Task::none();
            }
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
                state.focus.focus(text_input::Id::new(TERM_SEARCH_INPUT_ID))
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
                // The name was scraped from terminal output — the remote host
                // controls it. Reduce it to a bare file name before it touches
                // the local filesystem; refuse rather than guess.
                let base = match safe_local_basename(&fname) {
                    Some(b) => b,
                    None => {
                        if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
                            // `{:?}` escapes what the server put in the name:
                            // it reaches the terminal as text, never as a
                            // control sequence.
                            let notice = i18n::tf(
                                "term.sz_refused",
                                &[("name", &format!("{:?}", fname))],
                            );
                            tab.terminal.lock().write(
                                format!("\r\n\x1b[31m{}\x1b[0m\r\n", notice).as_bytes(),
                            );
                        }
                        return Task::none();
                    }
                };

                let Some(progress) = state.claim_transfer_bar() else {
                    return Task::none();
                };
                let ssh = state.ssh_manager.clone();

                // Download directly to ~/Downloads
                let default_dir = dirs::download_dir()
                    .or_else(|| dirs::desktop_dir())
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_default());
                let local_path = default_dir.join(&base).to_string_lossy().to_string();

                if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
                    tab.terminal.lock().write(
                        format!("\r\n\x1b[32m[NeoShell] sz: {} → {}\x1b[0m\r\n", fname, local_path).as_bytes(),
                    );
                }

                let bar = progress.clone();
                Task::perform(
                    async move {
                        let result = tokio::task::spawn_blocking(move || {
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
                        })
                        .await
                        .unwrap_or_else(|e| Err(format!("{}", e)));
                        (bar, result)
                    },
                    |(bar, result)| Message::DownloadDone(bar, result),
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
            // An application reading the mouse (less, vim, htop) scrolls itself.
            if report_wheel(state, MouseButton::WheelUp) { return Task::none(); }
            if let Some(term) = state.focused_terminal() {
                term.lock().scroll_view_up(lines);
            }
            Task::none()
        }
        Message::TerminalScrollDown(lines) => {
            if state.any_overlay_open() { return Task::none(); }
            if report_wheel(state, MouseButton::WheelDown) { return Task::none(); }
            if let Some(term) = state.focused_terminal() {
                term.lock().scroll_view_down(lines);
            }
            Task::none()
        }
        Message::TerminalMouseDown(MouseButton::Left) => {
            // Passthrough guard: clicks inside an open overlay don't reach here
            // when they hit a widget; this guards the "click outside the modal
            // card but inside the page" case from triggering terminal actions.
            if state.any_overlay_open() { return Task::none(); }
            state.context_menu = None;
            state.remote_menu = None;
            // A click outside every widget takes focus off any text input.
            state.quick_cmd_focused = false;

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
            // The application asked for the mouse (vim `mouse=a`, htop, tmux):
            // the press is reported to it instead of starting a selection.
            // Shift keeps it local (see `mouse_report_target`).
            if let Some((session_id, term)) = state.mouse_report_target() {
                if let Some((col, row)) =
                    state.focused_pane_cell(state.cursor_x, state.cursor_y, false)
                {
                    let report = term.lock().encode_mouse(MouseButton::Left, col, row, true);
                    if let Some(bytes) = report {
                        send_mouse_report(&state.ssh_manager, &session_id, &bytes);
                        state.mouse_report = Some(MouseReport {
                            session_id,
                            button: MouseButton::Left,
                            cell: (col, row),
                        });
                        return Task::none();
                    }
                }
            }
            state.selecting = true;
            state.selection_start = None;
            state.selection_end = None;
            // Invalidate canvas cache so old selection is cleared
            if let Some(term) = state.focused_terminal() {
                let mut grid = term.lock();
                grid.generation = grid.generation.wrapping_add(1);
            }
            Task::none()
        }
        Message::TerminalMouseDown(button) => {
            // Right or middle. A right-click away from the open file menu
            // just closes it.
            if state.remote_menu.take().is_some() {
                return Task::none();
            }
            if state.any_overlay_open() {
                return Task::none();
            }
            let target = state.mouse_report_target();
            match secondary_click(button, target.is_some()) {
                SecondaryClick::Report => {
                    // Over the pane only, and one reported press at a time:
                    // `mouse_report` holds the one whose release is owed.
                    let cell = state.focused_pane_cell(state.cursor_x, state.cursor_y, false);
                    let free = state.mouse_report.is_none();
                    if let (Some((session_id, term)), Some((col, row)), true) = (target, cell, free)
                    {
                        if let Some(bytes) = term.lock().encode_mouse(button, col, row, true) {
                            send_mouse_report(&state.ssh_manager, &session_id, &bytes);
                            state.mouse_report = Some(MouseReport {
                                session_id,
                                button,
                                cell: (col, row),
                            });
                        }
                    }
                    Task::none()
                }
                SecondaryClick::Paste => Task::done(Message::PasteClipboard),
                SecondaryClick::Ignore => Task::none(),
            }
        }
        Message::TerminalMouseMove(x, y) => {
            state.cursor_x = x;
            state.cursor_y = y;
            // Handle splitter drag
            if state.dragging_splitter {
                let delta = state.drag_start_y - y;
                state.bottom_panel_height = (state.drag_start_height + delta).clamp(80.0, 600.0);
                return Task::none();
            }
            // Split-divider drag: move the ratio by the pointer's travel
            // along the split axis, relative to where the press landed.
            if let Some((start_pos, start_ratio)) = state.split_drag {
                let vertical = state
                    .active_tab
                    .and_then(|i| state.tabs.get(i))
                    .and_then(|t| t.split.as_ref())
                    .map(|sp| sp.vertical);
                if let Some(vertical) = vertical {
                    let extent = state.split_extent(vertical);
                    let pos = if vertical { x } else { y };
                    if let Some(sp) = state
                        .active_tab
                        .and_then(|i| state.tabs.get_mut(i))
                        .and_then(|t| t.split.as_mut())
                    {
                        if extent > 0.0 {
                            sp.ratio = (start_ratio + (pos - start_pos) / extent)
                                .clamp(SPLIT_MIN, SPLIT_MAX);
                        }
                    }
                }
                return Task::none();
            }
            // A reported press: its drag goes to the same application (DEC
            // 1002 / 1003), pinned to the pane's edge if the pointer leaves
            // it, and only when the cell actually changes.
            if let Some(report) = state.mouse_report.clone() {
                // The cell math measures from the focused pane; if focus moved
                // mid-drag there is nothing sensible to report.
                if state.focused_session_id().as_deref() == Some(report.session_id.as_str()) {
                    if let Some(cell) = state.focused_pane_cell(x, y, true) {
                        if cell != report.cell {
                            if let Some(r) = state.mouse_report.as_mut() {
                                r.cell = cell;
                            }
                            let bytes = state
                                .find_terminal_for_session(&report.session_id)
                                .and_then(|t| {
                                    t.lock().encode_mouse_motion(Some(report.button), cell.0, cell.1)
                                });
                            if let Some(bytes) = bytes {
                                send_mouse_report(&state.ssh_manager, &report.session_id, &bytes);
                            }
                        }
                    }
                }
                return Task::none();
            }
            // DEC 1003 also wants motion with no button held: over the pane
            // only, and again only when the cell changes.
            if !state.selecting && !state.any_overlay_open() {
                if let Some((session_id, term)) = state.mouse_report_target() {
                    let cell = state.focused_pane_cell(x, y, false);
                    if cell != state.mouse_motion_cell {
                        state.mouse_motion_cell = cell;
                        if let Some((col, row)) = cell {
                            let bytes = term.lock().encode_mouse_motion(None, col, row);
                            if let Some(bytes) = bytes {
                                send_mouse_report(&state.ssh_manager, &session_id, &bytes);
                            }
                        }
                    }
                }
            }
            if state.selecting {
                // Split-aware: measured from the focused pane (8b17f55).
                let (x_off, y_off) = state.focused_pane_origin();
                // Same font source as the canvas (see TerminalView construction),
                // otherwise the hit-test and the renderer disagree.
                if let Some(pos) =
                    pixel_to_grid_with(x, y, x_off, y_off, state.theme_cfg.terminal_font_size)
                {
                    if state.selection_start.is_none() {
                        state.selection_start = Some(pos);
                    }
                    state.selection_end = Some(pos);
                    // Invalidate canvas cache to update selection highlight
                    if let Some(term) = state.focused_terminal() {
                        let mut grid = term.lock();
                        grid.generation = grid.generation.wrapping_add(1);
                    }
                }
            }
            Task::none()
        }
        Message::TerminalMouseUp(button) => {
            let left = button == MouseButton::Left;
            if left {
                // Always reset splitter drag
                state.dragging_splitter = false;
                state.split_drag = None;
                state.selecting = false;
            }
            // The release of a reported press goes to the application that
            // saw the press, wherever the pointer is now.
            if let Some(report) = state.mouse_report.take_if(|r| r.button == button) {
                let cell = if state.focused_session_id().as_deref() == Some(report.session_id.as_str()) {
                    state
                        .focused_pane_cell(state.cursor_x, state.cursor_y, true)
                        .unwrap_or(report.cell)
                } else {
                    report.cell
                };
                let bytes = state
                    .find_terminal_for_session(&report.session_id)
                    .and_then(|t| t.lock().encode_mouse(report.button, cell.0, cell.1, false));
                if let Some(bytes) = bytes {
                    send_mouse_report(&state.ssh_manager, &report.session_id, &bytes);
                }
                return Task::none();
            }
            if left && state.selection_start.is_some() && state.selection_end.is_some() {
                return Task::done(Message::CopySelection);
            }
            Task::none()
        }
        Message::CopySelection => {
            if let (Some(start), Some(end)) = (state.selection_start, state.selection_end) {
                if let Some(term) = state.focused_terminal() {
                    let grid = term.lock();
                    let text = extract_selection(&grid, start, end);
                    if !text.is_empty() {
                        if let Ok(mut clipboard) = arboard::Clipboard::new() {
                            let _ = clipboard.set_text(&text);
                        }
                    }
                }
            }
            state.selection_start = None;
            state.selection_end = None;
            // Invalidate canvas cache to clear selection highlight
            if let Some(term) = state.focused_terminal() {
                let mut grid = term.lock();
                grid.generation = grid.generation.wrapping_add(1);
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
            let ports = tab == BottomTab::Ports;
            state.bottom_panel_tab = tab;
            state.quick_cmd_focused = false;
            if ports {
                return Task::done(Message::FetchPorts);
            }
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
                    let session_id = tab.focused_session().to_string();
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
                                let mut detail = parse_process_detail(pid, &output);
                                detail.session_id = session_id;
                                Ok(detail)
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
        Message::HideContextMenu => {
            state.context_menu = None;
            Task::none()
        }
        Message::PathInputSubmit => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let sid = tab.focused_session().to_string();
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
            clear_history(&mut state.cmd_history, &mut state.history_sync);
            // On disk at once, and over the old bytes: clearing is how a user
            // takes back a line they did not mean to keep. A cleartext
            // history.json still waiting to be imported goes too, or the next
            // unlock would bring its lines straight back.
            persist_history(state, true, true)
        }
        Message::QuickCmdInputChanged(v) => {
            state.quick_cmd_input = v;
            // Only a focused input produces this.
            state.quick_cmd_focused = true;
            Task::none()
        }
        Message::SetFontSize(size) => {
            state.font_size = size.clamp(8.0, 30.0);
            save_font_size(state.font_size);
            // Force terminal re-layout
            state.last_term_size = (0, 0);
            Task::none()
        }
        Message::WindowResized(w, h) => {
            state.window_width = w;
            state.window_height = h;
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
        Message::RefreshLocalFiles => {
            state.local_entries = list_local_dir(&state.local_path);
            Task::none()
        }
        Message::RefreshRemoteFiles => {
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let sid = tab.focused_session().to_string();
                    let path = state.current_dir.get(&sid).cloned().unwrap_or_else(|| "~".into());
                    return Task::done(Message::ChangeDir(sid, path));
                }
            }
            Task::none()
        }
        Message::UploadLocalFile => {
            // Upload selected local file to remote current dir
            if let Some(local_file) = state.selected_local_file.clone() {
                if let Some(idx) = state.active_tab {
                    if let Some(tab) = state.tabs.get(idx) {
                        let sid = tab.focused_session().to_string();
                        if state.transfer_refused_busy() {
                            return Task::none();
                        }
                        let remote_dir = state.browser_dir(&sid).unwrap_or_else(|| "~".into());
                        state.selected_local_file = None;
                        // The shared upload path: one bar, queued drops wait
                        // for it, and the listing refreshes when it ends.
                        let local = std::path::PathBuf::from(local_file);
                        return start_upload(state, sid, local, remote_dir);
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
            // One builder for opening and for ESC's "still as opened?" test,
            // so the two cannot drift apart.
            if let Some(id) = maybe_id {
                if let Some(p) = state.proxies.iter().find(|p| p.id == id) {
                    state.proxy_form = proxy_form_for(Some(p));
                    state.proxy_edit_id = Some(id);
                }
            } else {
                state.proxy_edit_id = None;
                state.proxy_form = proxy_form_for(None);
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
                .set_title(i18n::t("filedialog.select_key"))
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
            let port = match form_port(&state.proxy_form.port, default_port) {
                Ok(port) => port,
                Err(message) => {
                    state.show_notice("form.err.title", message);
                    return Task::none();
                }
            };
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
            // `try_*`, not the ()-returning shims: with the secret now in
            // the vault, a locked vault means the save did not happen, and
            // silently logging that loses the user's edit.
            let saved = if state.proxy_edit_id.is_some() {
                state.proxy_store.try_update(&proxy)
            } else {
                state.proxy_store.try_add(proxy)
            };
            if let Err(e) = saved {
                state.error_message = e;
                state.show_error_dialog = true;
                return Task::none();
            }
            state.proxies = state.proxy_store.load();
            state.show_proxy_form = false;
            state.proxy_edit_id = None;
            state.proxy_form = ProxyFormData::default();
            Task::none()
        }
        Message::DeleteProxy(id) => {
            if let Err(e) = state.proxy_store.try_delete(&id) {
                state.error_message = e;
                state.show_error_dialog = true;
                return Task::none();
            }
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
            // Same builder as ESC's "still as opened?" test.
            if let Some(id) = edit_id {
                if let Some(t) = state.tunnels.iter().find(|x| x.id == id) {
                    state.tunnel_form = tunnel_form_for(Some(t));
                }
            } else {
                state.tunnel_form = tunnel_form_for(None);
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
        Message::TunnelFormBrowseKey => {
            if let Some(path) = rfd::FileDialog::new()
                .set_title(i18n::t("filedialog.select_key"))
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
                    state.show_notice("form.err.title", i18n::t("tunnel.err.no_forwards").to_string());
                    return Task::none();
                }
                Err(e) => {
                    let message = i18n::tf("tunnel.err.forward_parse", &[("err", &e)]);
                    state.show_notice("form.err.title", message);
                    return Task::none();
                }
            };
            let port = match form_port(&state.tunnel_form.ssh_port, 22) {
                Ok(port) => port,
                Err(message) => {
                    state.show_notice("form.err.title", message);
                    return Task::none();
                }
            };
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
            if let Err(e) = state.tunnel_store.try_upsert(cfg) {
                state.error_message = e;
                state.show_error_dialog = true;
                return Task::none();
            }
            state.tunnels = state.tunnel_store.load();
            state.show_tunnel_form = false;
            state.tunnel_edit_id = None;
            state.tunnel_form = TunnelFormData::default();
            Task::none()
        }
        Message::DeleteTunnel(id) => {
            state.tunnel_manager.stop(&id);
            if let Err(e) = state.tunnel_store.try_delete(&id) {
                state.error_message = e;
                state.show_error_dialog = true;
                return Task::none();
            }
            state.tunnels = state.tunnel_store.load();
            Task::none()
        }
        Message::StartTunnel(id) => {
            // `get_for_connect`, so a locked vault says so instead of dialling
            // the jump host with an empty password.
            match state.tunnel_store.get_for_connect(&id) {
                Ok(cfg) => {
                    if let Err(e) = state.tunnel_manager.start(cfg) {
                        state.error_message = i18n::tf("tunnel.err.start", &[("err", &e)]);
                        state.show_error_dialog = true;
                    }
                }
                Err(e) => {
                    state.error_message = i18n::tf("tunnel.err.start", &[("err", &e)]);
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
                apply_theme(state);
            }
            Task::none()
        }
        Message::ThemeGChanged(g) => {
            if let Some(z) = state.theme_editing_zone {
                let mut v = z.get(&state.theme_cfg);
                v.g = g;
                z.set(&mut state.theme_cfg, v);
                apply_theme(state);
            }
            Task::none()
        }
        Message::ThemeBChanged(b) => {
            if let Some(z) = state.theme_editing_zone {
                let mut v = z.get(&state.theme_cfg);
                v.b = b;
                z.set(&mut state.theme_cfg, v);
                apply_theme(state);
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
                        apply_theme(state);
                    }
                }
            }
            Task::none()
        }
        Message::ThemeTerminalFontSize(s) => {
            state.theme_cfg.terminal_font_size = s.clamp(8.0, 28.0);
            state.font_size = state.theme_cfg.terminal_font_size;
            apply_theme(state);
            Task::none()
        }
        Message::ThemeUiFontSize(s) => {
            state.theme_cfg.ui_font_size = s.clamp(10.0, 18.0);
            apply_theme(state);
            Task::none()
        }
        Message::ThemeReset => {
            state.theme_cfg = crate::ui::theme_config::ThemeConfig::default();
            state.font_size = state.theme_cfg.terminal_font_size;
            state.theme_editing_zone = None;
            apply_theme(state);
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

        // ---- remote file operations (SFTP) ----------------------------------
        Message::RemoteMenuOpen(session_id, dir, entry) => {
            // ".." is navigation, not an entry that can be renamed or deleted.
            let entry = entry.filter(|e| e.name != ".." && e.name != ".");
            state.context_menu = None;
            state.remote_menu = Some(RemoteFileMenu {
                session_id,
                dir,
                entry,
                x: state.cursor_x,
                y: state.cursor_y,
            });
            Task::none()
        }
        Message::RemoteMenuClose => {
            state.remote_menu = None;
            Task::none()
        }
        Message::SftpNewFolder => {
            let Some(menu) = state.remote_menu.take() else {
                return Task::none();
            };
            state.sftp_input = Some(SftpInputDialog {
                session_id: menu.session_id,
                dir: menu.dir,
                kind: SftpInputKind::NewFolder,
                value: String::new(),
                error: None,
            });
            state.focus.focus(text_input::Id::new(SFTP_INPUT_ID))
        }
        Message::SftpRename => {
            let Some(RemoteFileMenu { session_id, dir, entry: Some(entry), .. }) =
                state.remote_menu.take()
            else {
                return Task::none();
            };
            state.sftp_input = Some(SftpInputDialog {
                session_id,
                dir,
                value: entry.name.clone(),
                kind: SftpInputKind::Rename {
                    confirmed: ConfirmedEntry::from(&entry),
                    kind: entry.kind(),
                    from: entry.name,
                },
                error: None,
            });
            Task::batch([
                state.focus.focus(text_input::Id::new(SFTP_INPUT_ID)),
                text_input::select_all(text_input::Id::new(SFTP_INPUT_ID)),
            ])
        }
        Message::SftpChmod => {
            let Some(RemoteFileMenu { session_id, dir, entry: Some(entry), .. }) =
                state.remote_menu.take()
            else {
                return Task::none();
            };
            let value = mode_from_permissions(&entry.permissions)
                .map(|m| format!("{:o}", m))
                .unwrap_or_default();
            state.sftp_input = Some(SftpInputDialog {
                session_id,
                dir,
                kind: SftpInputKind::Chmod {
                    confirmed: ConfirmedEntry::from(&entry),
                    kind: entry.kind(),
                    name: entry.name,
                },
                value,
                error: None,
            });
            Task::batch([
                state.focus.focus(text_input::Id::new(SFTP_INPUT_ID)),
                text_input::select_all(text_input::Id::new(SFTP_INPUT_ID)),
            ])
        }
        Message::SftpDelete => {
            let Some(RemoteFileMenu { session_id, dir, entry: Some(entry), .. }) =
                state.remote_menu.take()
            else {
                return Task::none();
            };
            // Destructive: held for the confirmation, which quotes the exact
            // name and says what it is — the kind the row showed, which is
            // also what the SSH layer checks the entry against.
            let path = join_remote_path(&dir, &entry.name);
            state.confirm_action = Some(ConfirmAction::SftpDelete {
                session_id,
                dir,
                path,
                confirmed: ConfirmedEntry::from(&entry),
                kind: entry.kind(),
                name: entry.name,
            });
            Task::none()
        }
        Message::SftpInputChanged(value) => {
            if let Some(dialog) = state.sftp_input.as_mut() {
                dialog.value = value;
                dialog.error = None;
            }
            Task::none()
        }
        Message::SftpInputCancel => {
            state.sftp_input = None;
            Task::none()
        }
        Message::SftpInputSubmit => {
            let Some(dialog) = state.sftp_input.clone() else {
                return Task::none();
            };
            let SftpInputDialog { session_id, dir, kind, value, .. } = dialog;
            let ssh = state.ssh_manager.clone();
            match kind {
                SftpInputKind::NewFolder => {
                    let Some(name) = valid_remote_name(&value) else {
                        if let Some(d) = state.sftp_input.as_mut() {
                            d.error = Some("sftp.err_name");
                        }
                        return Task::none();
                    };
                    state.sftp_input = None;
                    let path = join_remote_path(&dir, &name);
                    sftp_op_task(ssh, session_id, dir, move |ssh, sid| ssh.sftp_mkdir(sid, &path))
                }
                SftpInputKind::Rename { from, confirmed, .. } => {
                    let target = rename_target(&from, &value);
                    let Ok(target) = target else {
                        if let Some(d) = state.sftp_input.as_mut() {
                            d.error = Some("sftp.err_name");
                        }
                        return Task::none();
                    };
                    state.sftp_input = None;
                    // Submitted as it opened: nothing to rename.
                    let Some(name) = target else {
                        return Task::none();
                    };
                    let (src, dst) = (join_remote_path(&dir, &from), join_remote_path(&dir, &name));
                    sftp_op_task(ssh, session_id, dir, move |ssh, sid| {
                        ssh.sftp_rename_confirmed(sid, &src, &dst, confirmed)
                    })
                }
                SftpInputKind::Chmod { name, kind, confirmed } => {
                    let Some(mode) = parse_octal_mode(&value) else {
                        if let Some(d) = state.sftp_input.as_mut() {
                            d.error = Some("sftp.err_mode");
                        }
                        return Task::none();
                    };
                    state.sftp_input = None;
                    // Destructive too: confirmed with the exact name, its
                    // kind, the path and the mode.
                    let path = join_remote_path(&dir, &name);
                    state.confirm_action =
                        Some(ConfirmAction::SftpChmod { session_id, dir, path, name, kind, confirmed, mode });
                    Task::none()
                }
            }
        }
        Message::SftpOpDone(session_id, dir, result) => {
            // Set directly rather than through Message::Error, which would
            // also drop a transfer's progress bar and placeholder tabs. A
            // recursive delete that left names out still re-lists below.
            report_transfer_error(state, result);
            // Re-list whatever the browser shows for that session now.
            let path = state.current_dir.get(&session_id).cloned().unwrap_or(dir);
            Task::done(Message::ChangeDir(session_id, path))
        }
        Message::ConfirmActionCancel => {
            state.confirm_action = None;
            Task::none()
        }
        Message::ConfirmActionExecute => {
            let Some(action) = state.confirm_action.take() else {
                return Task::none();
            };
            let ssh = state.ssh_manager.clone();
            match action {
                // The row the user confirmed goes along: the SSH layer
                // refuses an entry that is no longer the kind shown, and a
                // row whose listing could not be verified; it addresses the
                // entry by the name the server sent, not the text shown. Only
                // a confirmed folder is deleted with what is inside it.
                ConfirmAction::SftpDelete { session_id, dir, path, confirmed, .. } => {
                    sftp_op_task(ssh, session_id, dir, move |ssh, sid| {
                        ssh.sftp_remove_confirmed(sid, &path, confirmed)
                    })
                }
                ConfirmAction::SftpChmod { session_id, dir, path, confirmed, mode, .. } => {
                    sftp_op_task(ssh, session_id, dir, move |ssh, sid| {
                        ssh.sftp_chmod_confirmed(sid, &path, mode, confirmed)
                    })
                }
                ConfirmAction::Kill { session_id, pid, signal, identity, .. } => Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            // Still the process the user confirmed? A pid that
                            // changed hands while the dialog was up would take
                            // the signal meant for another.
                            match read_proc_identity(&ssh, &session_id, pid)? {
                                Some(now) if same_process(&identity, &now) => {
                                    ssh.kill_process(&session_id, pid, signal)
                                }
                                Some(_) => Err(i18n::tf(
                                    "process.err.changed",
                                    &[("pid", &pid.to_string())],
                                )),
                                None => Err(i18n::tf("process.err.gone", &[("pid", &pid.to_string())])),
                            }
                        })
                        .await
                        .unwrap_or_else(|e| Err(format!("Task: {}", e)))
                    },
                    Message::KillProcessDone,
                ),
            }
        }

        // ---- recursive transfer / drag-and-drop -------------------------------
        Message::UploadDir => {
            let Some(session_id) = state
                .active_tab
                .and_then(|i| state.tabs.get(i))
                .map(|t| t.focused_session().to_string())
                .filter(|s| !s.is_empty())
            else {
                return Task::none();
            };
            if state.transfer_refused_busy() {
                return Task::none();
            }
            let dir = state.browser_dir(&session_id).unwrap_or_else(|| "~".to_string());
            Task::perform(
                async move {
                    let folder = rfd::AsyncFileDialog::new()
                        .set_title(i18n::t("filedialog.upload_dir"))
                        .set_directory(dirs::home_dir().unwrap_or_default())
                        .pick_folder()
                        .await
                        .map(|f| f.path().to_path_buf());
                    (session_id, dir, folder)
                },
                |(session_id, dir, folder)| Message::UploadPicked(session_id, dir, folder),
            )
        }
        Message::UploadPicked(session_id, dir, picked) => {
            let Some(local) = picked else {
                return Task::none();
            };
            // Another transfer may have started while the picker was open.
            if state.transfer_refused_busy() {
                return Task::none();
            }
            start_upload(state, session_id, local, dir)
        }
        Message::DownloadDir(session_id, remote) => {
            if state.transfer_refused_busy() {
                return Task::none();
            }
            Task::perform(
                async move {
                    let parent = rfd::AsyncFileDialog::new()
                        .set_title(i18n::t("filedialog.download_dir"))
                        .set_directory(default_download_dir())
                        .pick_folder()
                        .await
                        .map(|f| f.path().to_path_buf());
                    (session_id, remote, parent)
                },
                |(session_id, remote, parent)| {
                    Message::DownloadDirPicked(session_id, remote, parent)
                },
            )
        }
        Message::DownloadDirPicked(session_id, remote, parent) => {
            let Some(parent) = parent else {
                return Task::none();
            };
            let Some(progress) = state.claim_transfer_bar() else {
                return Task::none();
            };
            // The folder name comes from the remote listing: it must not get
            // to choose where on the local disk the tree lands.
            let name = safe_local_basename(&remote).unwrap_or_else(|| "download".to_string());
            let local = parent.join(name).to_string_lossy().to_string();
            let ssh = state.ssh_manager.clone();
            Task::perform(
                async move {
                    let bar = progress.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        ssh.download_dir_with_progress(&session_id, &remote, &local, progress)
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("Task: {}", e)));
                    (bar, result)
                },
                |(bar, result)| Message::DownloadDirDone(bar, result),
            )
        }
        Message::DownloadDirDone(bar, result) => {
            release_bar(&mut state.transfer_progress, &bar);
            report_transfer_error(state, result);
            Task::none()
        }
        Message::UploadFinished(session_id, bar, result) => {
            state.upload_job_running = false;
            release_bar(&mut state.transfer_progress, &bar);
            // A report of skipped entries is no failure: the drop carries on.
            if report_transfer_error(state, result) {
                // Stop the rest of a drop rather than pile errors up.
                state.drop_queue.clear();
            }
            let next = start_next_drop(state);
            // Show what arrived (a cancel can leave a partial tree) — but only
            // for a session the browser tracks; a split pane's has no listing.
            match state.current_dir.get(&session_id).cloned() {
                Some(path) => Task::batch([Task::done(Message::ChangeDir(session_id, path)), next]),
                None => next,
            }
        }
        Message::FileDropped(path) => {
            // Main screen, nothing modal in the way: a drop under the
            // connection form must not start an upload behind it.
            if state.screen != Screen::Main || state.any_overlay_open() {
                return Task::none();
            }
            let Some((session_id, remote_dir)) = state.drop_target() else {
                state.error_message = i18n::t("drop.no_target").to_string();
                state.show_error_dialog = true;
                return Task::none();
            };
            // Someone else's transfer holds the bar and would not start the
            // queue when it ends.
            if state.transfer_busy() && !state.upload_job_running {
                state.error_message = i18n::t("transfer.busy").to_string();
                state.show_error_dialog = true;
                return Task::none();
            }
            log::info!("drop: {} -> {}", path.display(), remote_dir);
            state.drop_queue.push_back(DropJob {
                session_id,
                local: path,
                remote_dir,
            });
            start_next_drop(state)
        }

        // ---- command history / quick-command autocomplete --------------------
        Message::FlushHistory => {
            // Paced: at most one write per HISTORY_FLUSH_INTERVAL. Lock, quit
            // and ClearHistory write at once, through their own paths.
            let now = std::time::Instant::now();
            if !history_flush_due(&state.history_sync, now) {
                return Task::none();
            }
            state.history_sync.flushed_at = Some(now);
            persist_history(state, false, false)
        }
        Message::HistoryWritten(result) => {
            if let Err(e) = result {
                log::warn!("command history not saved: {}", e);
                // The next paced flush tries again — unless the vault was
                // locked since, which wiped the records this write carried.
                if state.history_sync.loaded {
                    state.history_sync.dirty = true;
                }
            }
            Task::none()
        }
        Message::HistoryLoaded(seq, load) => {
            let Some(landed) =
                land_history_load(&mut state.cmd_history, &mut state.history_sync, seq, load)
            else {
                return Task::none();
            };
            // Said, not only logged: otherwise the user finds out when the
            // commands are gone.
            if let Some(key) = landed.warning {
                state.show_notice("history.warn.title", i18n::t(key).to_string());
            }
            if landed.import_legacy {
                persist_history(state, false, true)
            } else {
                Task::none()
            }
        }
        Message::QuickCmdAccept(cmd) => {
            state.quick_cmd_input = cmd;
            state.quick_cmd_focused = true;
            Task::batch([
                state.focus.focus(text_input::Id::new(QUICK_CMD_INPUT_ID)),
                text_input::move_cursor_to_end(text_input::Id::new(QUICK_CMD_INPUT_ID)),
            ])
        }

        // ---- keyboard-interactive auth ---------------------------------------
        Message::AuthAnswerChanged(i, mut value) => {
            // Keys in the modal's first moments were typed before anyone
            // could see it, for something else: they are no answer.
            if !auth_armed(state.auth_shown_at, std::time::Instant::now()) {
                value.zeroize();
                return Task::none();
            }
            if let Some(slot) = state.auth_answers.get_mut(i) {
                let mut old = std::mem::replace(slot, value);
                old.zeroize();
            }
            Task::none()
        }
        Message::AuthFocus(i) => {
            // Enter in an answer field moves on — not an Enter that arrived
            // with the modal.
            if !auth_armed(state.auth_shown_at, std::time::Instant::now()) {
                return Task::none();
            }
            state.focus.focus(auth_input_id(i))
        }
        Message::AuthSubmit => submit_auth_answers(state),
        Message::AuthEnter => {
            // Never an Enter typed before the modal appeared: that one ended
            // whatever the user was typing elsewhere, a sudo password say.
            if !auth_armed(state.auth_shown_at, std::time::Instant::now()) {
                return Task::none();
            }
            submit_auth_answers(state)
        }
        Message::AuthCancel => {
            // The user declining to answer: a cancel, which the SSH thread
            // tells apart from a modal retired unanswered.
            if let Some((challenge, _)) = state.auth_queue.pop_front() {
                challenge.cancel();
            }
            state.begin_auth_prompt()
        }

        // ---- process kill ------------------------------------------------------
        Message::KillProcessRequest(signal) => {
            let Some(detail) = &state.process_detail else {
                return Task::none();
            };
            if detail.pid <= 1 || detail.session_id.is_empty() {
                return Task::none();
            }
            // The confirmation names the process as /proc has it now — not as
            // the popup read it, maybe minutes ago, nor as `ss` named it: the
            // pid may have changed hands since.
            let (session_id, pid) = (detail.session_id.clone(), detail.pid);
            let ssh = state.ssh_manager.clone();
            Task::perform(
                async move {
                    let sid = session_id.clone();
                    let read = tokio::task::spawn_blocking(move || read_proc_identity(&ssh, &sid, pid))
                        .await
                        .unwrap_or_else(|e| Err(format!("Task: {}", e)));
                    (session_id, read)
                },
                move |(session_id, read)| Message::KillIdentityRead(session_id, pid, signal, read),
            )
        }
        Message::KillIdentityRead(session_id, pid, signal, read) => {
            // Only for the popup that asked, if it is still up.
            let asked = state
                .process_detail
                .as_ref()
                .is_some_and(|d| d.pid == pid && d.session_id == session_id);
            if !asked {
                return Task::none();
            }
            match read {
                Ok(Some(identity)) => {
                    state.confirm_action = Some(ConfirmAction::Kill {
                        session_id,
                        pid,
                        command: kill_command_label(&identity),
                        signal,
                        identity,
                    });
                }
                Ok(None) => {
                    state.error_message = i18n::tf("process.err.gone", &[("pid", &pid.to_string())]);
                    state.show_error_dialog = true;
                }
                Err(e) => {
                    state.error_message = e;
                    state.show_error_dialog = true;
                }
            }
            Task::none()
        }
        Message::KillProcessDone(result) => match result {
            Ok(()) => {
                // The process is gone or going; show the list without it.
                state.process_detail = None;
                let mut tasks = vec![Task::done(Message::FetchMonitorData)];
                if state.bottom_panel_tab == BottomTab::Ports {
                    tasks.push(Task::done(Message::FetchPorts));
                }
                Task::batch(tasks)
            }
            Err(e) => {
                // Verbatim: the remote's own "Operation not permitted".
                state.error_message = e;
                state.show_error_dialog = true;
                Task::none()
            }
        },

        // ---- listening ports ---------------------------------------------------
        Message::FetchPorts => {
            let Some(session_id) = state
                .active_tab
                .and_then(|i| state.tabs.get(i))
                .map(|t| t.focused_session().to_string())
                .filter(|s| !s.is_empty())
            else {
                return Task::none();
            };
            if !state.ports_inflight.start(&session_id) {
                return Task::none();
            }
            let ssh = state.ssh_manager.clone();
            Task::perform(
                async move {
                    let sid = session_id.clone();
                    let result = tokio::task::spawn_blocking(move || ssh.fetch_listening_ports(&sid))
                        .await
                        .unwrap_or_else(|e| Err(format!("Task: {}", e)));
                    (session_id, result)
                },
                |(session_id, result)| Message::PortsReceived(session_id, result),
            )
        }
        Message::PortsReceived(session_id, result) => {
            state.ports_inflight.finish(&session_id);
            // Fetches for different sessions now overlap: a late answer for
            // a tab the user has left must not replace the one on screen.
            if state
                .active_tab
                .and_then(|i| state.tabs.get(i))
                .map(|t| t.focused_session())
                != Some(session_id.as_str())
            {
                return Task::none();
            }
            state.ports_fetched_at = Some(std::time::Instant::now());
            state.ports_session = session_id;
            match result {
                Ok(mut ports) => {
                    // Sorted here, once per answer, not in the view.
                    sort_ports(&mut ports, state.ports_sort, state.ports_sort_desc);
                    state.ports = ports;
                    state.ports_error = None;
                }
                Err(e) => {
                    state.ports.clear();
                    state.ports_error = Some(e);
                }
            }
            Task::none()
        }
        Message::PortsSortBy(key) => {
            resort_ports(
                &mut state.ports,
                &mut state.ports_sort,
                &mut state.ports_sort_desc,
                key,
            );
            Task::none()
        }

        // ---- colour scheme presets ---------------------------------------------
        Message::ThemeApplyPreset(name) => {
            if let Some(preset) = theme_config::preset_by_name(&name) {
                state.theme_cfg = preset_keeping_fonts(preset, &state.theme_cfg);
                state.theme_editing_zone = None;
                // Saves, publishes to the shared styles, and re-palettes the
                // open terminals — the whole window is the live preview.
                apply_theme(state);
            }
            Task::none()
        }

        // ---- misc ------------------------------------------------------------
        Message::None => Task::none(),
        Message::Error(e) => {
            // No tab is touched: a connect reports its failure on its own tab
            // (`ConnectFailed`, `SplitFailed`). Taking every still-connecting
            // tab down over an unrelated error — a listing, a paste — lost
            // those connects, whose sessions then came up with no tab.
            log::error!("{}", e);
            state.error_message = e;
            state.show_error_dialog = true;
            // The progress bar is not touched: every transfer reports its own
            // end, and an unrelated failure — a refused connection, a wrong
            // password at the lock screen — must not strand one in flight
            // with no bar and no Cancel.
            Task::none()
        }
        Message::DismissErrorDialog => {
            state.show_error_dialog = false;
            state.error_message.clear();
            Task::none()
        }
        Message::CopyErrorText => {
            let copied = arboard::Clipboard::new()
                .and_then(|mut clipboard| clipboard.set_text(state.error_message.clone()));
            match copied {
                Ok(()) => state.error_copied = Some(fingerprint(&state.error_message)),
                Err(e) => log::warn!("copy error text to clipboard: {}", e),
            }
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
                        // Snap the raw byte offset forward to a char boundary
                        // before slicing — the log holds translated CJK, and
                        // both this slice and the unwrap_or(start) fallback
                        // below would otherwise land mid-character.
                        let mut start = c.len() - MAX;
                        while start < c.len() && !c.is_char_boundary(start) {
                            start += 1;
                        }
                        let aligned = c[start..].find('\n').map(|i| start + i + 1).unwrap_or(start);
                        let kb = ((c.len() - aligned) / 1024).to_string();
                        format!("{}\n{}", i18n::tf("log.truncated", &[("kb", &kb)]), &c[aligned..])
                    } else {
                        c
                    }
                }
                Err(e) => i18n::tf(
                    "log.err.read",
                    &[("path", &path.display().to_string()), ("err", &e.to_string())],
                ),
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
            // Here and now, after the writes already sent off: nothing waits
            // for a background task once the window is gone.
            if !state.history_file.wait_settled(HISTORY_SETTLE_WAIT) {
                log::warn!("command history: an earlier write is still running at quit");
            }
            if state.history_sync.dirty && state.history_sync.loaded {
                let saved = HistoryFile::snapshot(
                    &state.history_file,
                    &state.store,
                    &state.cmd_history,
                    false,
                    false,
                )
                .and_then(|job| job.run().map_err(|e| e.to_string()));
                if let Err(e) = saved {
                    log::warn!("command history not saved: {}", e);
                }
            }
            if state.groups_dirty {
                let saved = state
                    .groups_file
                    .snapshot(&state.store, &state.collapsed_groups, false)
                    .and_then(|job| state.groups_file.write(job).map_err(|e| e.to_string()));
                if let Err(e) = saved {
                    log::warn!("folded groups not saved: {}", e);
                }
            }
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
        // Output and sign-in challenges wake the drain themselves. On every
        // screen: sessions run on under the lock screen, and a reconnect can
        // ask for a code there. Waiting costs nothing while nothing arrives.
        Subscription::run_with_id("ssh-events", ssh_wakes(state.ssh_manager.waker())),
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

    if let Some(every) = poll_interval(
        state.screen == Screen::Main,
        !state.tabs.is_empty() || state.ssh_held.is_some(),
        !state.auth_queue.is_empty(),
        state.progress_moving(),
    ) {
        subs.push(time::every(every).map(|_| Message::PollSshEvents));
    }

    // Monitor refresh every 3 seconds when there is an active tab
    if state.screen == Screen::Main && state.active_tab.is_some() {
        subs.push(time::every(Duration::from_secs(3)).map(|_| Message::FetchMonitorData));
    }

    // Idle re-lock. 20s granularity is plenty for a timeout measured in
    // minutes, and it costs nothing when the feature is switched off.
    if state.screen == Screen::Main && state.lock_timeout_mins > 0 {
        subs.push(time::every(Duration::from_secs(20)).map(|_| Message::IdleCheck));
    }

    // When the tunnel panel is open, tick every 2s to refresh connection counts.
    if state.show_tunnel_manager {
        subs.push(time::every(Duration::from_secs(2)).map(|_| Message::TunnelStateTick));
    }

    // Command history reaches disk at most once a minute while new lines keep
    // coming, not on every Enter: each write fsyncs twice. The tick only asks
    // `history_flush_due`; lock and quit write at once.
    if state.screen == Screen::Main && state.history_sync.dirty {
        subs.push(time::every(HISTORY_FLUSH_TICK).map(|_| Message::FlushHistory));
    }

    // Capture ALL events. Terminal-targeted messages are filtered in update()
    // against state.any_overlay_open() so scroll / clicks / right-click-paste
    // can't pass through an open overlay to the terminal canvas.
    if state.screen == Screen::Main {
        subs.push(event::listen_with(|evt, status, _window| {
            match evt {
                iced::Event::Window(iced::window::Event::Resized(size)) => {
                    Some(Message::WindowResized(size.width, size.height))
                }
                iced::Event::Keyboard(keyboard::Event::KeyPressed {
                    key, modifiers, text, ..
                }) => {
                    // Keys reach this listener even when a focused text input
                    // consumed them; say so, so they are not typed twice.
                    Some(Message::KeyboardEvent(
                        key,
                        modifiers,
                        text.map(|s| s.to_string()),
                        matches!(status, event::Status::Captured),
                    ))
                }
                iced::Event::Keyboard(keyboard::Event::ModifiersChanged(modifiers)) => {
                    Some(Message::ModifiersChanged(modifiers))
                }
                // winit reports a drop for the whole window, with no position.
                iced::Event::Window(iced::window::Event::FileDropped(path)) => {
                    Some(Message::FileDropped(path))
                }
                // Only a press no widget claimed goes to the terminal: the
                // remote file browser's rows open their own menu with a
                // right-click. Right and middle go to an application that
                // asked for the mouse; otherwise a right-click pastes. Every
                // other press may still have moved the keyboard focus — onto
                // the text input it landed on, or off one.
                iced::Event::Mouse(mouse::Event::ButtonPressed(button)) => {
                    match (status, terminal_button(button)) {
                        (event::Status::Ignored, Some(button)) => {
                            Some(Message::TerminalMouseDown(button))
                        }
                        _ => Some(Message::FocusMayHaveMoved),
                    }
                }
                // Every release: a press reported to an application is owed
                // its release, wherever the pointer went.
                iced::Event::Mouse(mouse::Event::ButtonReleased(button)) => {
                    terminal_button(button).map(Message::TerminalMouseUp)
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

/// The user@host:port key `ImportAllSshConfigs` de-duplicates on; None for a
/// host entry with no usable address.
fn ssh_config_key(cfg: &crate::sshconfig::SshHostConfig) -> Option<String> {
    let host = if cfg.hostname.is_empty() { &cfg.alias } else { &cfg.hostname };
    (!host.is_empty()).then(|| format!("{}@{}:{}", cfg.user, host, cfg.port))
}

/// Cheap, stable (per process) fingerprint of a string.
fn fingerprint(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// A tab's title while its session reconnects: `base`, then the marker —
/// in the UI language, after " [", where `title_base` cuts it off again.
fn reconnecting_title(base: &str, attempt: u32) -> String {
    i18n::tf("tab.reconnecting", &[("title", base), ("n", &attempt.to_string())])
}

/// A tab title without its reconnect marker: "user@host:port".
fn title_base(title: &str) -> &str {
    title.split(" [").next().unwrap_or(title)
}

/// Whether a tab title carries a reconnect marker, in either language.
fn title_reconnecting(title: &str) -> bool {
    title_base(title).len() != title.len()
}

/// Host part of a tab title — "user@host:port", possibly followed by
/// " [Reconnecting...]".
fn host_from_title(title: &str) -> String {
    let base = title_base(title);
    let after_user = base.rsplit_once('@').map_or(base, |(_, h)| h);
    after_user.rsplit_once(':').map_or(after_user, |(h, _)| h).to_string()
}

/// Take the pane showing `session_id` out of a split tab: a split pane just
/// goes; a main pane hands the tab to its split, which becomes the main pane.
/// `false` when no split tab shows the session — its tab has no split, and
/// closes whole, or the pane was taken out already.
fn remove_split_pane(tabs: &mut [TerminalTab], session_id: &str) -> bool {
    if session_id.is_empty() {
        return false;
    }
    for tab in tabs.iter_mut() {
        if tab.split.as_ref().is_some_and(|s| s.session_id == session_id) {
            tab.split = None;
            tab.focus_split = false;
            return true;
        }
        if tab.session_id == session_id {
            let Some(sp) = tab.split.take() else {
                return false;
            };
            tab.session_id = sp.session_id;
            tab.terminal = sp.terminal;
            tab.focus_split = false;
            return true;
        }
    }
    false
}

/// The active tab once the tab at `removed` is gone and `len` are left: the
/// same tab as before when another one was removed, its neighbour when it
/// was the one.
fn active_after_removal(active: Option<usize>, removed: usize, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    active.map(|a| if a > removed { a - 1 } else { a.min(len - 1) })
}

#[cfg(test)]
mod tests;
