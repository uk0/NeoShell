use iced::widget::{
    button, canvas, column, container, horizontal_space, row, stack, text,
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

/// Reduce a remote-supplied name to a single, safe local file name.
///
/// `sz` filenames are scraped out of terminal output, i.e. out of bytes the
/// REMOTE host controls, and neither extractor rejects `/` or `..`. Path::join
/// honours `..` and lets an absolute name replace the base directory outright,
/// so an unsanitised name writes anywhere the user can write (~/.zshrc,
/// ~/.ssh/authorized_keys, ~/Library/LaunchAgents/...). Returns None when the
/// name cannot be reduced to something safe — the caller must then refuse.
fn safe_local_basename(name: &str) -> Option<String> {
    let base = std::path::Path::new(name).file_name()?.to_str()?;
    if base.is_empty() || base == "." || base == ".." {
        return None;
    }
    // `\` is not a path separator on unix, so Path::file_name() keeps it;
    // reject it explicitly so the same name is safe on every platform.
    if base
        .chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
    {
        return None;
    }
    Some(base.to_string())
}

/// True when the remote echoed `cmd` back onto the screen.
///
/// `cmd_buffer` is assembled from LOCAL keystrokes, with no idea whether the
/// remote tty is echoing. `sudo`, `su`, `mysql -p` and gpg all turn echo off at
/// their prompts, so without this gate the password is stored verbatim in
/// `cmd_history`, rendered in plaintext by the history panel, and one click on
/// ReplayCommand re-sends it to a shell.
///
/// Deliberately fails closed: when the terminal is gone or the echo has not
/// landed yet, the line is simply not recorded.
fn command_was_echoed(state: &NeoShell, session_id: &str, cmd: &str) -> bool {
    let term = match state.find_terminal_for_session(session_id) {
        Some(t) => t,
        None => return false,
    };
    let grid = term.lock();
    if grid.cells.is_empty() {
        return false;
    }
    let row_text = |y: usize| -> String {
        grid.cells
            .get(y)
            .map(|r| r.iter().filter(|c| !c.wide_cont).map(|c| c.c).collect())
            .unwrap_or_default()
    };
    let y = grid.cursor_y.min(grid.cells.len() - 1);

    // Second gate, for the case where the secret coincidentally matches text
    // left on screen: an explicit no-echo prompt is never a command line.
    let prompt = row_text(y).to_lowercase();
    if prompt.contains("password")
        || prompt.contains("passphrase")
        || prompt.contains("\u{5bc6}\u{7801}")
        || prompt.contains("\u{53e3}\u{4ee4}")
    {
        return false;
    }

    // Match a prefix rather than the whole line: with echo ON the head has long
    // since been echoed even on a slow link, while with echo OFF not a single
    // character reaches the grid. Join the two rows above the cursor so a
    // command that wrapped at the right margin still matches.
    let prefix: String = cmd.chars().take(6).collect();
    let start = y.saturating_sub(2);
    let visible: String = (start..=y).map(row_text).collect();
    visible.contains(&prefix)
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

/// Resource alert thresholds, persisted to alerts.json.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AlertConfig {
    pub enabled: bool,
    pub cpu_pct: f32,
    pub mem_pct: f32,
    pub disk_pct: f32,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self { enabled: true, cpu_pct: 90.0, mem_pct: 90.0, disk_pct: 90.0 }
    }
}

fn alerts_path() -> std::path::PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("neoshell");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("alerts.json")
}

fn load_alerts() -> AlertConfig {
    std::fs::read_to_string(alerts_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_alerts(cfg: &AlertConfig) {
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(alerts_path(), json);
    }
}

// ---- Sidebar groups: folded state and order --------------------------------

/// How long after the last fold or unfold the folded groups are saved: a run
/// of clicks costs one write, not one fsync each.
const GROUPS_SAVE_DELAY: Duration = Duration::from_millis(800);

/// Largest `collapsed_groups.enc` read back; anything bigger is not ours.
const SEALED_GROUPS_MAX_BYTES: u64 = 1024 * 1024;

/// The folded sidebar groups on disk. `collapsed_groups.enc` holds one
/// `EncryptedBlob`: the sorted JSON list of group names sealed under the
/// vault key, as `history.enc` holds the history — group names say what the
/// vault's connections are, so they are exactly as readable as the vault.
/// Builds before this wrote the list in the clear to `collapsed_groups.json`;
/// the first unlock imports that file, and the write that seals it scrubs and
/// deletes it.
///
/// Sealed on the UI thread, where the key is; written on a blocking thread,
/// in the order sealed: a snapshot that runs late is dropped rather than
/// landing over a newer one.
struct GroupsFile {
    sealed: std::path::PathBuf,
    legacy: std::path::PathBuf,
    next_seq: AtomicU64,
    /// Number of the newest snapshot on disk, held for the whole of a write.
    written: parking_lot::Mutex<u64>,
}

/// A sealed snapshot of the folded groups, on its way to disk.
struct GroupsWrite {
    seq: u64,
    blob: crate::storage::EncryptedBlob,
    /// Scrub and delete the cleartext `collapsed_groups.json` once this
    /// snapshot, or a newer one, is on disk.
    retire_legacy: bool,
}

impl GroupsFile {
    fn at(dir: &std::path::Path) -> Self {
        GroupsFile {
            sealed: dir.join("collapsed_groups.enc"),
            legacy: dir.join("collapsed_groups.json"),
            next_seq: AtomicU64::new(0),
            written: parking_lot::Mutex::new(0),
        }
    }

    fn in_data_dir() -> Self {
        Self::at(
            &dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("neoshell"),
        )
    }

    /// Seal `groups` for a later `write`. Fails while the vault is locked.
    fn snapshot(
        &self,
        store: &ConnectionStore,
        groups: &HashSet<String>,
        retire_legacy: bool,
    ) -> Result<GroupsWrite, String> {
        let mut list: Vec<&String> = groups.iter().collect();
        list.sort();
        let json = zeroize::Zeroizing::new(serde_json::to_vec(&list).map_err(|e| e.to_string())?);
        let blob = store.seal(&json)?;
        Ok(GroupsWrite {
            seq: self.next_seq.fetch_add(1, Ordering::Relaxed) + 1,
            blob,
            retire_legacy,
        })
    }

    /// Put `job` on disk — atomically, 0600 — unless a newer snapshot is
    /// there already. Blocking: it fsyncs.
    fn write(&self, job: GroupsWrite) -> std::io::Result<()> {
        let mut written = self.written.lock();
        if job.seq > *written {
            let bytes = serde_json::to_vec(&job.blob).map_err(std::io::Error::other)?;
            crate::storage::write_private(&self.sealed, &bytes)?;
            *written = job.seq;
        }
        if job.retire_legacy {
            retire_cleartext_groups(&self.legacy)?;
        }
        Ok(())
    }

    /// The folded groups of the vault just opened, with a cleartext
    /// `collapsed_groups.json` merged in; the flag says one was found, for
    /// the caller to seal at once and retire. A missing, damaged or foreign
    /// sealed file folds nothing — the next save replaces it — and nothing
    /// is read while the vault is locked.
    fn load(&self, store: &ConnectionStore) -> (HashSet<String>, bool) {
        if !store.is_unlocked() {
            return (HashSet::new(), false);
        }
        let mut groups = match self.read_sealed(store) {
            Ok(groups) => groups,
            Err(e) => {
                log::warn!("folded groups {} unreadable: {}", self.sealed.display(), e);
                HashSet::new()
            }
        };
        let legacy_found = std::fs::symlink_metadata(&self.legacy).is_ok();
        if legacy_found {
            let legacy = std::fs::read(&self.legacy)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Vec<String>>(&bytes).ok())
                .unwrap_or_default();
            groups.extend(legacy);
        }
        (groups, legacy_found)
    }

    fn read_sealed(&self, store: &ConnectionStore) -> Result<HashSet<String>, String> {
        match std::fs::metadata(&self.sealed) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
            Err(e) => return Err(e.to_string()),
            Ok(meta) if meta.len() > SEALED_GROUPS_MAX_BYTES => {
                return Err(format!("{} bytes", meta.len()));
            }
            Ok(_) => {}
        }
        let raw = std::fs::read(&self.sealed).map_err(|e| e.to_string())?;
        let blob: crate::storage::EncryptedBlob =
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let plain = store.open(&blob)?;
        let list: Vec<String> = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        Ok(list.into_iter().collect())
    }
}

/// Overwrite the cleartext `collapsed_groups.json` in place, then delete it.
/// Anything but a regular file is only unlinked, never written through.
fn retire_cleartext_groups(path: &std::path::Path) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_file() {
        crate::storage::write_private_scrubbing(path, b"")?;
    }
    std::fs::remove_file(path)?;
    log::info!("cleartext folded groups {} sealed and removed", path.display());
    Ok(())
}

/// Seal the folded groups now and write them off the UI thread; `Task::none`
/// while the vault is locked. `retire_legacy` then scrubs and deletes the
/// cleartext file.
fn persist_groups(state: &mut NeoShell, retire_legacy: bool) -> Task<Message> {
    match state
        .groups_file
        .snapshot(&state.store, &state.collapsed_groups, retire_legacy)
    {
        Ok(job) => {
            state.groups_dirty = false;
            let file = state.groups_file.clone();
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || file.write(job).map_err(|e| e.to_string()))
                        .await
                        .map_err(|e| format!("Task: {}", e))?
                },
                Message::GroupsWritten,
            )
        }
        Err(e) => {
            log::warn!("folded groups not sealed: {}", e);
            Task::none()
        }
    }
}

/// The folded groups changed: save them once no further change has come for
/// [`GROUPS_SAVE_DELAY`].
fn schedule_groups_save(state: &mut NeoShell) -> Task<Message> {
    state.groups_dirty = true;
    state.groups_gen += 1;
    let gen = state.groups_gen;
    Task::perform(tokio::time::sleep(GROUPS_SAVE_DELAY), move |_| {
        Message::SaveCollapsedGroups(gen)
    })
}

/// Read the folded groups of the vault just opened — on the UI thread: a
/// small file. A cleartext file found beside it is sealed and retired at
/// once.
fn unlock_groups(state: &mut NeoShell) -> Task<Message> {
    let (groups, legacy_found) = state.groups_file.load(&state.store);
    state.collapsed_groups = groups;
    state.groups_dirty = false;
    if legacy_found {
        persist_groups(state, true)
    } else {
        Task::none()
    }
}

/// Forget folded groups no connection is in any more — the last one was
/// deleted or moved to another group. True when anything was dropped.
fn prune_collapsed_groups(groups: &mut HashSet<String>, conns: &[ConnectionInfo]) -> bool {
    let before = groups.len();
    groups.retain(|g| conns.iter().any(|c| c.group == *g));
    groups.len() != before
}

/// One group of the sidebar list.
struct SidebarGroup<'a> {
    /// The connections' `group` as stored — "" is the ungrouped bucket. What
    /// `collapsed_groups` holds.
    key: String,
    conns: Vec<&'a ConnectionInfo>,
    /// Drawn folded: saved as collapsed, and no search running.
    collapsed: bool,
}

impl SidebarGroup<'_> {
    /// The header's name: the group's own, or "Ungrouped" in the UI language.
    fn label(&self) -> String {
        group_label(&self.key)
    }
}

/// How a stored group name reads in the sidebar and the palette.
fn group_label(key: &str) -> String {
    if key.is_empty() {
        i18n::t("sidebar.ungrouped").to_string()
    } else {
        key.to_string()
    }
}

/// The sidebar's groups for the search `query`, in display order. While a
/// search runs every group with a match is drawn open, whatever was saved —
/// search results are never hidden — and the saved state stays as it was.
fn sidebar_groups<'a>(
    conns: &'a [ConnectionInfo],
    query: &str,
    collapsed: &HashSet<String>,
) -> Vec<SidebarGroup<'a>> {
    let query = search_fold(query.trim());
    let searching = !query.is_empty();
    let mut groups: Vec<SidebarGroup<'a>> = Vec::new();
    for conn in conns.iter().filter(|c| !searching || connection_matches(c, &query)) {
        match groups.iter_mut().find(|g| g.key == conn.group) {
            Some(group) => group.conns.push(conn),
            None => groups.push(SidebarGroup {
                key: conn.group.clone(),
                conns: vec![conn],
                collapsed: false,
            }),
        }
    }
    groups.sort_by(|a, b| group_order(&a.key, &b.key));
    for group in &mut groups {
        group.collapsed = !searching && collapsed.contains(&group.key);
        group.conns.sort_by(|a, b| connection_order(a, b));
    }
    groups
}

/// Order of connections wherever they are listed — the sidebar, the connect
/// dialog, the palette: by group as the sidebar orders its groups, then by
/// name without regard to case, then by host. The vault is a map, so they
/// used to come back in a new order on every load. The exact name, host and
/// id settle ties, so the order never depends on how they were loaded.
fn connection_order(a: &ConnectionInfo, b: &ConnectionInfo) -> std::cmp::Ordering {
    // Without allocating: the sidebar sorts on every frame.
    let ignore_case = |x: &str, y: &str| {
        x.chars()
            .flat_map(char::to_lowercase)
            .cmp(y.chars().flat_map(char::to_lowercase))
    };
    group_order(&a.group, &b.group)
        .then_with(|| ignore_case(&a.name, &b.name))
        .then_with(|| ignore_case(&a.host, &b.host))
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.host.cmp(&b.host))
        .then_with(|| a.id.cmp(&b.id))
}

/// Group order: by name without regard to case — Chinese and English names
/// alike, by their text; no collation beyond that — and the ungrouped bucket
/// last. Names that differ only in case keep a fixed order.
fn group_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.is_empty()
        .cmp(&b.is_empty())
        .then_with(|| a.to_lowercase().cmp(&b.to_lowercase()))
        .then_with(|| a.cmp(b))
}

/// Text folded for search: lowercase, with the full-width Latin letters,
/// digits and punctuation a Chinese input method types in full-width mode
/// read as their ASCII selves, and the ideographic space as a space.
fn search_fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            '\u{3000}' => ' ',
            c => c,
        })
        .flat_map(char::to_lowercase)
        .collect()
}

/// Whether a connection matches a [`search_fold`]ed sidebar query: as a
/// substring of its name, host, user or group — the group as the sidebar
/// shows it, so the ungrouped bucket is found by its label ("Ungrouped" /
/// "未分组") too.
fn connection_matches(conn: &ConnectionInfo, folded_query: &str) -> bool {
    let group = group_label(&conn.group);
    [&conn.name, &conn.host, &conn.username, &group]
        .iter()
        .any(|field| search_fold(field).contains(folded_query))
}

/// One entry in the Cmd+K command palette.
struct PaletteItem {
    label: String,
    meta: String,
    /// Short i18n'd kind tag rendered as a chip: 连接 / 动作 / 片段.
    kind: &'static str,
    msg: Message,
    score: i32,
}

/// Case-insensitive subsequence fuzzy match. Returns None when `query`
/// is not a subsequence of `target`; higher score = better match
/// (prefix + consecutive-run bonuses, mild length penalty).
fn fuzzy_score(query: &str, target: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    // Folded as the sidebar search folds: full-width letters typed through
    // a Chinese input method match their ASCII selves.
    let q: Vec<char> = search_fold(query).chars().collect();
    let t: Vec<char> = search_fold(target).chars().collect();
    let mut qi = 0usize;
    let mut score = 0i32;
    let mut last_hit: Option<usize> = None;
    for (ti, &tc) in t.iter().enumerate() {
        if qi < q.len() && tc == q[qi] {
            score += 10;
            if ti == 0 {
                score += 8;
            }
            if let Some(lh) = last_hit {
                if ti == lh + 1 {
                    score += 6;
                }
            }
            last_hit = Some(ti);
            qi += 1;
        }
    }
    if qi == q.len() {
        Some(score - (t.len() as i32) / 4)
    } else {
        None
    }
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
/// Stable widget id for the Cmd+K palette input.
const PALETTE_INPUT_ID: &str = "palette_input";
/// Stable widget id for the tab-rename input.
const TAB_RENAME_INPUT_ID: &str = "tab_rename_input";

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

#[derive(Default, Clone, PartialEq)]
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

/// One submitted command line. Only lines that passed `command_was_echoed`
/// are ever built — that gate is what keeps a password typed at a no-echo
/// prompt out of the history panel and, now that it persists, out of
/// `history.enc` too.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CmdRecord {
    cmd: String,
    #[serde(default)]
    session_title: String,
    /// Host the line was typed on.
    #[serde(default)]
    host: String,
    /// Unix seconds. An `Instant` cannot outlive the process, which is why the
    /// history used to die with it.
    #[serde(default)]
    timestamp: u64,
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

/// Where a terminal canvas was last laid out, in window coordinates. The
/// canvas records it every time it draws, and the pointer hit-test reads it
/// back: whatever is actually on screen around the pane — the update banner,
/// the transfer bar, the other half of a split — is measured rather than
/// added up by hand from chrome heights that drift. Empty until the pane's
/// first frame.
#[derive(Clone, Default)]
struct PaneBounds(Arc<parking_lot::Mutex<Option<Rectangle>>>);

impl PaneBounds {
    fn record(&self, bounds: Rectangle) {
        *self.0.lock() = Some(bounds);
    }

    fn get(&self) -> Option<Rectangle> {
        *self.0.lock()
    }
}

/// Top-left of a pane's canvas: where it last drew, or `fallback` before its
/// first frame.
fn pane_origin(drawn: Option<Rectangle>, fallback: (f32, f32)) -> (f32, f32) {
    drawn.map_or(fallback, |b| (b.x, b.y))
}

/// Both canvases of a tab's split as last drawn, main pane first — only once
/// both have drawn: a main pane measured before the split existed still
/// spans the whole area.
fn drawn_split(tab: &TerminalTab) -> Option<(Rectangle, Rectangle)> {
    Some((tab.bounds.get()?, tab.split.as_ref()?.bounds.get()?))
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

#[derive(Default, Clone, PartialEq)]
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
pub(crate) struct ProcessDetailInfo {
    pid: u32,
    fields: Vec<(String, String)>,
    children: Vec<String>,      // child process lines
    threads: Vec<String>,       // thread IDs
    net_conns: Vec<String>,     // network connections (ss output)
    listen_ports: Vec<String>,  // listening ports
    open_fds: Vec<String>,      // file descriptors
    /// Session the details were read over. A kill from the popup goes to this
    /// host even if the user has switched tabs since.
    session_id: String,
}

/// Which process holds a pid right now, read from /proc when the kill
/// confirmation opens and again just before the signal goes. A pid names
/// whatever process holds it at that moment — the popup may be minutes old —
/// and the name `ss` / `netstat` printed is whatever the process chose to
/// call itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcIdentity {
    /// Field 22 of /proc/<pid>/stat, clock ticks after boot: a pid that has
    /// changed hands has a new one. This is what identifies the process.
    start_time: String,
    /// The name in the same stat line — all a kernel thread has to show.
    comm: String,
    /// /proc/<pid>/cmdline with its NULs as spaces: what the confirmation
    /// shows. The process may rewrite it, so it is not part of the identity.
    cmdline: String,
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
    x: f32,
    y: f32,
}

/// Right-click menu of the remote file browser.
#[derive(Debug, Clone)]
struct RemoteFileMenu {
    session_id: String,
    /// Directory the browser is showing: where "New folder" lands, and what
    /// `entry` is relative to.
    dir: String,
    /// The row that was clicked. `None` for the list background and for
    /// "..", which only offer "New folder".
    entry: Option<FileEntry>,
    x: f32,
    y: f32,
}

/// What the SFTP name / mode dialog is asking for. `kind` is what the row
/// showed ([`FileEntry::kind`]): the dialog states it, and the SSH layer
/// refuses the operation if the entry is no longer that.
#[derive(Debug, Clone, PartialEq)]
enum SftpInputKind {
    NewFolder,
    Rename { from: String, kind: EntryKind, confirmed: ConfirmedEntry },
    Chmod { name: String, kind: EntryKind, confirmed: ConfirmedEntry },
}

/// Small modal taking a folder name, a new name, or an octal mode.
#[derive(Debug, Clone)]
struct SftpInputDialog {
    session_id: String,
    dir: String,
    kind: SftpInputKind,
    value: String,
    /// i18n key of an inline validation message; the dialog stays open.
    error: Option<&'static str>,
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

/// A mouse press that went to the remote application. Its drag and its
/// release go to the same session, even if the pointer leaves the pane.
#[derive(Debug, Clone)]
struct MouseReport {
    session_id: String,
    button: MouseButton,
    /// Last cell reported, 1-based; motion is only sent when it changes.
    cell: (usize, usize),
}

/// A file or folder dropped on the window, waiting for the progress bar.
#[derive(Debug, Clone)]
struct DropJob {
    session_id: String,
    local: std::path::PathBuf,
    remote_dir: String,
}

/// Sessions with a fetch out on a blocking thread, one set per kind of fetch.
///
/// Monitor and ports fetches queue on a session's exec connection, which a
/// folder transfer holds for its whole length. Started on every tick
/// regardless, they piled up — a 30-minute transfer queued ~600 monitor
/// fetches, past tokio's 512 blocking threads, and from then on nothing that
/// needs one could start, new connections included. A session gets its next
/// fetch only once the last one is back; other sessions are not held up.
#[derive(Debug, Default)]
struct InFlight(HashSet<String>);

impl InFlight {
    /// Claim the fetch for `session_id`: false — skip this tick — while the
    /// previous one is still out, or when there is no session to ask.
    fn start(&mut self, session_id: &str) -> bool {
        !session_id.is_empty() && self.0.insert(session_id.to_string())
    }

    /// The fetch for `session_id` came back, answered or not.
    fn finish(&mut self, session_id: &str) {
        self.0.remove(session_id);
    }

    fn contains(&self, session_id: &str) -> bool {
        self.0.contains(session_id)
    }
}

/// Whether a monitor fetch failed because the SSH layer has parked the
/// session's exec connection: keyboard-interactive, where re-opening it is a
/// new challenge, so it waits for the user (`SshManager::resume_exec`). Told
/// by the SSH layer's own words for it.
fn exec_parked(error: &str) -> bool {
    error == i18n::t("exec.err.needs_reconnect")
}

/// A file listing for `session_id` failed. A parked exec connection is not an
/// error to put up each time a folder is asked for: the monitor and file
/// panels show why, with the one button that re-opens it — for a split
/// pane's session too, now that the panels follow the focused pane.
fn listing_failed(session_id: &str, error: String) -> Message {
    if exec_parked(&error) {
        Message::ExecParked(session_id.to_string())
    } else {
        Message::Error(error)
    }
}

/// A remote directory listing as the file browser shows it, with the
/// directory it was produced for. Every row action — open, download, edit,
/// rename, chmod, delete, the right-click menu — resolves the row's name
/// against `dir`, never against `current_dir`: that one names the next
/// directory as soon as it is asked for, before its listing arrives, and
/// even when it never does.
#[derive(Debug, Clone)]
struct Listing {
    /// The directory listed, as the SSH layer resolved it.
    dir: String,
    entries: Vec<FileEntry>,
    /// A later request that failed while this listing stayed on screen. The
    /// prompt's cwd sync does not ask for it again on every tick — which
    /// would put the same error up every 3 s.
    failed: Option<String>,
}

impl Listing {
    fn new(dir: String, entries: Vec<FileEntry>) -> Self {
        Listing { dir, entries, failed: None }
    }

    /// Remote path of the row called `name`.
    fn path_of(&self, name: &str) -> String {
        join_remote_path(&self.dir, name)
    }
}

/// Where the ".." row leads from the remote directory `dir`.
fn remote_parent(dir: &str) -> String {
    std::path::Path::new(dir)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string())
}

/// The listing of `requested` for `session_id` failed. The listing on screen
/// stays, and `current_dir` goes back to its directory — unless another one
/// has been asked for since — so a refresh, or the re-list after an
/// operation, lists what is shown; the failure is noted on the listing (see
/// [`cwd_sync_due`]).
fn note_listing_failed(
    current_dir: &mut HashMap<String, String>,
    listings: &mut HashMap<String, Listing>,
    session_id: &str,
    requested: &str,
) {
    let Some(listing) = listings.get_mut(session_id) else {
        return;
    };
    if current_dir.get(session_id).map(String::as_str) == Some(requested) {
        current_dir.insert(session_id.to_string(), listing.dir.clone());
        listing.failed = Some(requested.to_string());
    }
}

/// Whether the file browser should follow the shell to `cwd`, the directory
/// its prompt shows: when the prompt shows a different directory than the
/// one last followed, unless listing `cwd` has just failed.
fn cwd_sync_due(last_followed: Option<&str>, listing: Option<&Listing>, cwd: &str) -> bool {
    last_followed != Some(cwd) && listing.is_none_or(|l| l.failed.as_deref() != Some(cwd))
}

/// The prompt of `session_id` shows `cwd`: follow the shell there if it has
/// moved since the browser last followed it. True when a listing of `cwd`
/// should be asked for; `current_dir` then says `cwd`.
///
/// Compared with what the prompt showed last time, never with the directory
/// the browser is in. The listing resolves `~` to the login directory and
/// records that, so comparing the prompt's `~` with it never settled: the
/// browser re-listed on every monitor tick, and pulled the user back from
/// any folder they had opened by hand.
fn follow_prompt_cwd(
    prompt_cwd: &mut HashMap<String, String>,
    current_dir: &mut HashMap<String, String>,
    listings: &HashMap<String, Listing>,
    session_id: &str,
    cwd: &str,
) -> bool {
    let last = prompt_cwd.get(session_id).map(String::as_str);
    if !cwd_sync_due(last, listings.get(session_id), cwd) {
        return false;
    }
    prompt_cwd.insert(session_id.to_string(), cwd.to_string());
    current_dir.insert(session_id.to_string(), cwd.to_string());
    true
}

/// Sessions whose monitoring is parked (see [`exec_parked`]), with the
/// reconnect the monitor panel's one button sends for each.
#[derive(Debug, Default)]
struct ParkedMonitors(HashMap<String, ParkedMonitor>);

/// One parked session.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ParkedMonitor {
    /// The reconnect is out. The button stays off until it is back: one
    /// press, one challenge.
    resuming: bool,
    /// Why the last reconnect failed.
    error: Option<String>,
}

impl ParkedMonitors {
    /// A fetch found `session_id` parked. True the first time.
    fn park(&mut self, session_id: &str) -> bool {
        if self.0.contains_key(session_id) {
            return false;
        }
        let parked = ParkedMonitor::default();
        self.0.insert(session_id.to_string(), parked);
        true
    }

    /// A fetch came back with data, or the session is gone.
    fn unpark(&mut self, session_id: &str) {
        self.0.remove(session_id);
    }

    fn get(&self, session_id: &str) -> Option<&ParkedMonitor> {
        self.0.get(session_id)
    }

    /// "Reconnect monitoring" was pressed. True when the caller is to send
    /// the reconnect: the session is parked, and none is out already.
    fn begin_resume(&mut self, session_id: &str) -> bool {
        match self.0.get_mut(session_id) {
            Some(p) if !p.resuming => {
                p.resuming = true;
                p.error = None;
                true
            }
            _ => false,
        }
    }

    /// The reconnect came back. True when it re-opened a parked connection.
    fn finish_resume(&mut self, session_id: &str, result: Result<(), String>) -> bool {
        match result {
            Ok(()) => self.0.remove(session_id).is_some(),
            Err(e) => {
                if let Some(p) = self.0.get_mut(session_id) {
                    p.resuming = false;
                    p.error = Some(e);
                }
                false
            }
        }
    }
}

/// Column the listening-ports table is sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortSort {
    Proto,
    Addr,
    Port,
    Pid,
    Process,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BottomTab {
    Monitor,
    Files,
    QuickCmd,
    Ports,
}

#[derive(Default, Clone, PartialEq)]
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

// ---- Vault idle re-lock ---------------------------------------------------

/// Idle-timeout choices, in minutes. 0 = never re-lock.
const LOCK_TIMEOUT_STEPS: [u32; 7] = [0, 1, 5, 15, 30, 60, 120];

/// Default idle timeout when nothing is persisted yet.
const LOCK_TIMEOUT_DEFAULT: u32 = 15;

/// Snap an arbitrary minute count onto the nearest allowed step. Anything the
/// user could not have produced through the UI — a hand-edited config, a value
/// from a future build — lands on a real choice instead of being discarded.
fn clamp_lock_timeout(mins: u32) -> u32 {
    if LOCK_TIMEOUT_STEPS.contains(&mins) {
        return mins;
    }
    *LOCK_TIMEOUT_STEPS
        .iter()
        .min_by_key(|s| s.abs_diff(mins))
        .unwrap_or(&LOCK_TIMEOUT_DEFAULT)
}

/// Next value up or down the step list, saturating at both ends.
fn cycle_lock_timeout(current: u32, up: bool) -> u32 {
    let cur = clamp_lock_timeout(current);
    let idx = LOCK_TIMEOUT_STEPS.iter().position(|s| *s == cur).unwrap_or(0);
    let next = if up {
        (idx + 1).min(LOCK_TIMEOUT_STEPS.len() - 1)
    } else {
        idx.saturating_sub(1)
    };
    LOCK_TIMEOUT_STEPS[next]
}

/// Is the vault due to re-lock? `false` whenever the timeout is disabled, so
/// the caller never has to special-case 0.
fn idle_lock_due(timeout_mins: u32, idle: Duration) -> bool {
    if timeout_mins == 0 {
        return false;
    }
    idle >= Duration::from_secs(timeout_mins as u64 * 60)
}

/// Load the persisted idle timeout, in minutes.
fn load_lock_timeout() -> u32 {
    if let Some(d) = dirs::config_dir() {
        if let Ok(s) = std::fs::read_to_string(d.join("neoshell").join("locktimeout")) {
            if let Ok(v) = s.trim().parse::<u32>() {
                return clamp_lock_timeout(v);
            }
        }
    }
    LOCK_TIMEOUT_DEFAULT
}

fn save_lock_timeout(mins: u32) {
    if let Some(d) = dirs::config_dir() {
        let dir = d.join("neoshell");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("locktimeout"), mins.to_string());
    }
}

/// Human label for an idle-timeout value.
fn lock_timeout_label(mins: u32) -> String {
    if mins == 0 {
        i18n::t("settings.lock_never").to_string()
    } else {
        i18n::tf("settings.lock_minutes", &[("n", &mins.to_string())])
    }
}

/// Wipe every plaintext credential sitting in an open form.
///
/// Re-locking clears the DEK, but a half-filled connection / proxy / tunnel
/// form still holds the password the user typed or that `load()` decrypted.
/// Leaving it there would put the secret back on screen the moment the vault
/// is unlocked again, which is precisely what the lock is for. Zeroized, not
/// just cleared: `clear()` leaves the bytes in the buffer it keeps.
fn scrub_form_secrets(
    conn: &mut ConnectionFormData,
    proxy: &mut ProxyFormData,
    tunnel: &mut TunnelFormData,
) {
    conn.password.zeroize();
    conn.passphrase.zeroize();
    proxy.password.zeroize();
    proxy.passphrase.zeroize();
    tunnel.password.zeroize();
    tunnel.passphrase.zeroize();
}

/// Zero the credentials the proxy and tunnel lists hold decrypted, before the
/// lock drops the lists: a dropped `String` leaves its bytes on the heap.
fn scrub_list_secrets(
    proxies: &mut [crate::proxy::ProxyConfig],
    tunnels: &mut [crate::tunnel::TunnelConfig],
) {
    for p in proxies {
        p.password.zeroize();
        p.passphrase.zeroize();
    }
    for t in tunnels {
        t.password.zeroize();
        t.passphrase.zeroize();
    }
}

// ---- ESC and filled-in forms ------------------------------------------------
//
// ESC puts a form away only while it still reads exactly as it was opened.
// A half-filled connection, password included, used to be wiped by a habitual
// ESC; now typing is only ever thrown away by Cancel.

/// What the connection form is compared against to tell whether ESC may put
/// it away: `form` as just opened, minus any secret. Opening never fills the
/// password or passphrase (`ConnectionInfo` carries neither), so this is the
/// form itself — and should that ever change, the form merely reads as edited
/// and stays, rather than a second copy of a secret outliving the lock.
fn opened_connection_form(form: &ConnectionFormData) -> ConnectionFormData {
    ConnectionFormData {
        password: String::new(),
        passphrase: String::new(),
        ..form.clone()
    }
}

/// The proxy form as `ShowProxyForm` opens it: a saved proxy's fields, or
/// the defaults of a new one.
fn proxy_form_for(saved: Option<&crate::proxy::ProxyConfig>) -> ProxyFormData {
    let Some(p) = saved else {
        return ProxyFormData {
            proxy_type: "socks5h".into(),
            port: "1080".into(),
            ..Default::default()
        };
    };
    ProxyFormData {
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
    }
}

/// The tunnel form as `ShowTunnelForm` opens it: a saved tunnel's fields, or
/// the defaults of a new one.
fn tunnel_form_for(saved: Option<&crate::tunnel::TunnelConfig>) -> TunnelFormData {
    let Some(t) = saved else {
        return TunnelFormData {
            ssh_port: "22".into(),
            auth_type: "password".into(),
            ..Default::default()
        };
    };
    TunnelFormData {
        name: t.name.clone(),
        ssh_host: t.ssh_host.clone(),
        ssh_port: t.ssh_port.to_string(),
        username: t.username.clone(),
        auth_type: t.auth_type.clone(),
        password: t.password.clone().unwrap_or_default(),
        private_key: t.private_key.clone().unwrap_or_default(),
        passphrase: t.passphrase.clone().unwrap_or_default(),
        forwards_text: t.forwards.iter()
            // `spec()`, not a hand-rolled format: SaveTunnel re-parses this
            // text, and the 3-field form parses back as Local — silently
            // downgrading an "R:" or "D:" rule the user typed.
            .map(|f| f.spec())
            .collect::<Vec<_>>().join("\n"),
        auto_start: t.auto_start,
    }
}

/// Whether ESC may put the proxy form away: it still reads exactly as
/// `ShowProxyForm` opened it. When the proxy being edited is no longer in
/// `saved` that cannot be told, and the form is kept.
fn proxy_form_pristine(
    form: &ProxyFormData,
    edit_id: Option<&str>,
    saved: &[crate::proxy::ProxyConfig],
) -> bool {
    match edit_id {
        Some(id) => saved
            .iter()
            .find(|p| p.id == id)
            .is_some_and(|p| *form == proxy_form_for(Some(p))),
        None => *form == proxy_form_for(None),
    }
}

/// [`proxy_form_pristine`], for the tunnel form.
fn tunnel_form_pristine(
    form: &TunnelFormData,
    edit_id: Option<&str>,
    saved: &[crate::tunnel::TunnelConfig],
) -> bool {
    match edit_id {
        Some(id) => saved
            .iter()
            .find(|t| t.id == id)
            .is_some_and(|t| *form == tunnel_form_for(Some(t))),
        None => *form == tunnel_form_for(None),
    }
}

/// Whether ESC may put the snippet editor away: the name and body are what
/// `SnippetEdit` put there — the saved snippet's, or empty for a new one.
fn snippet_form_pristine(name: &str, body: &str, edit_id: Option<&str>, saved: &[Snippet]) -> bool {
    match edit_id {
        Some(id) => saved
            .iter()
            .any(|s| s.id == id && s.name == name && s.body == body),
        None => name.is_empty() && body.is_empty(),
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
        // this channel and block until the modal answers. Registered once.
        let (auth_tx, auth_rx) = mpsc::channel();
        crate::ssh::set_auth_prompter(auth_tx);

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

/// Rows the palette shows at most — its list does not scroll.
const PALETTE_MAX: usize = 12;

/// Display columns a palette row gives its label and its meta at the default
/// UI font size. The card's width is fixed, so both shrink as the font grows
/// (`cols_at_scale`), as the sidebar's do.
const PALETTE_LABEL_COLS: usize = 40;
const PALETTE_META_COLS: usize = 32;

/// A palette row's label and meta cut to its column budgets at UI `scale`,
/// each with whether it was cut.
fn palette_row_text(label: &str, meta: &str, scale: f32) -> ((String, bool), (String, bool)) {
    (
        clip_to_width(label, cols_at_scale(PALETTE_LABEL_COLS, scale)),
        clip_to_width(meta, cols_at_scale(PALETTE_META_COLS, scale)),
    )
}

/// Build the Cmd+K palette item list for `query`, sorted by fuzzy score.
/// Connections first-class, then actions, then snippets.
///
/// Every matching connection's own entry is kept: past [`PALETTE_MAX`] the
/// lowest-placed entry that is *not* a connection goes first, so neither an
/// action nor a snippet can push a connection out of reach. Only when nothing
/// but connections is left do the lowest-ranked of those go, as they always
/// did. The row actions (edit / test / clone / delete) are offered for the
/// single best match only, right under it — four per match used to fill the
/// list with actions and push the other connections off it.
fn build_palette_items(
    query: &str,
    connections: &[ConnectionInfo],
    snippets: &[Snippet],
    collapsed_groups: &HashSet<String>,
) -> Vec<PaletteItem> {
    let q = query.trim();
    let mut items: Vec<PaletteItem> = Vec::new();

    // Connections the palette ranks the same keep the sidebar's order.
    let mut ordered: Vec<&ConnectionInfo> = connections.iter().collect();
    ordered.sort_by(|a, b| connection_order(a, b));
    let rank: HashMap<&str, usize> =
        ordered.iter().enumerate().map(|(n, c)| (c.id.as_str(), n)).collect();

    for c in ordered {
        let label = c.name.clone();
        let meta = format!("{}@{}:{}", c.username, c.host, c.port);
        // The group as the sidebar shows it: "Ungrouped" finds those too.
        let hay = format!("{} {} {}", c.name, meta, group_label(&c.group));
        if let Some(s) = fuzzy_score(q, &hay) {
            items.push(PaletteItem {
                label,
                meta,
                kind: "palette.kind.conn",
                msg: Message::ConnectTo(c.id.clone()),
                score: s + 5, // connections get a small priority bump
            });
        }
    }

    let actions: &[(&str, Message)] = &[
        ("palette.act.new_conn",   Message::ShowForm(None)),
        ("palette.act.connect",    Message::ShowConnectDialog),
        ("palette.act.settings",   Message::ShowSettings),
        ("palette.act.broadcast",  Message::ShowBroadcastDialog),
        ("palette.act.snippets",   Message::ShowSnippetsPanel),
        ("palette.act.keys",       Message::ShowKeyManager),
        ("palette.act.tunnels",    Message::ShowTunnelManager),
        ("palette.act.proxies",    Message::ShowProxyManager),
        ("palette.act.history",    Message::ShowHistory),
        ("palette.act.logs",       Message::ShowLogViewer),
        ("palette.act.sync",       Message::ToggleSyncInput),
        ("palette.act.split_v",    Message::SplitTab(true)),
        ("palette.act.split_h",    Message::SplitTab(false)),
        ("palette.act.import_ssh", Message::ImportAllSshConfigs),
        ("sidebar.collapse_all",   Message::SetAllGroupsCollapsed(true)),
        ("sidebar.expand_all",     Message::SetAllGroupsCollapsed(false)),
    ];
    for (key, msg) in actions {
        let label = i18n::t(key).to_string();
        if let Some(s) = fuzzy_score(q, &label) {
            items.push(PaletteItem {
                label,
                meta: String::new(),
                kind: "palette.kind.action",
                msg: msg.clone(),
                score: s,
            });
        }
    }

    // The keyboard's way to fold one sidebar group (iced 0.13 buttons cannot
    // take focus): type its name. Only for a typed query, like row actions.
    if !q.is_empty() {
        let mut seen: HashSet<&str> = HashSet::new();
        for c in connections {
            if !seen.insert(c.group.as_str()) {
                continue;
            }
            let name = group_label(&c.group);
            if let Some(s) = fuzzy_score(q, &name) {
                let key = if collapsed_groups.contains(&c.group) {
                    "palette.act.expand_group"
                } else {
                    "palette.act.collapse_group"
                };
                items.push(PaletteItem {
                    label: i18n::tf(key, &[("name", &name)]),
                    meta: String::new(),
                    kind: "palette.kind.action",
                    msg: Message::ToggleGroupCollapsed(c.group.clone()),
                    score: s,
                });
            }
        }
    }

    for sn in snippets {
        let hay = format!("{} {}", sn.name, sn.body);
        if let Some(s) = fuzzy_score(q, &hay) {
            items.push(PaletteItem {
                label: sn.name.clone(),
                meta: sn.body.chars().take(40).collect(),
                kind: "palette.kind.snippet",
                msg: Message::SnippetSend(sn.id.clone()),
                score: s,
            });
        }
    }

    // Best score first; among equals, connections first in the sidebar's
    // order, then the rest by label.
    let conn_rank = |it: &PaletteItem| match &it.msg {
        Message::ConnectTo(id) => rank.get(id.as_str()).copied(),
        _ => None,
    };
    items.sort_by(|a, b| {
        b.score.cmp(&a.score).then_with(|| match (conn_rank(a), conn_rank(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.label.cmp(&b.label),
        })
    });

    // Keyboard route to the row actions the sidebar only shows on hover
    // (iced 0.13 buttons cannot take focus) — for the best match, and only
    // for a typed query, so the empty palette keeps its action list.
    let best = if q.is_empty() {
        None
    } else {
        items.iter().enumerate().find_map(|(at, it)| match &it.msg {
            Message::ConnectTo(id) => Some((at, id.clone())),
            _ => None,
        })
    };
    if let Some((at, id)) = best {
        let best = &items[at];
        let row_actions = [
            ("palette.act.edit_conn", Message::ShowForm(Some(id.clone()))),
            (
                "palette.act.test_conn",
                Message::TestConnectionInList(id.clone()),
            ),
            (
                "palette.act.clone_conn",
                Message::CloneConnection(id.clone()),
            ),
            ("palette.act.delete_conn", Message::DeleteConnection(id)),
        ]
        .map(|(key, msg)| PaletteItem {
            label: i18n::tf(key, &[("name", &best.label)]),
            meta: best.meta.clone(),
            kind: "palette.kind.action",
            msg,
            score: best.score - 5,
        });
        items.splice(at + 1..at + 1, row_actions);
    }

    let is_connection = |it: &PaletteItem| matches!(it.msg, Message::ConnectTo(_));
    while items.len() > PALETTE_MAX {
        match items.iter().rposition(|it| !is_connection(it)) {
            Some(i) => {
                items.remove(i);
            }
            None => items.truncate(PALETTE_MAX),
        }
    }
    items
}

// ---------------------------------------------------------------------------
// Application entry point
// ---------------------------------------------------------------------------

pub fn run() -> iced::Result {
    let initial_scale = load_ui_scale() as f64;

    // The app opens on the setup or the lock screen, which hold nothing but
    // master-password fields: no input method there, from the first frame.
    // Recorded before the window exists, which opens with this setting.
    iced_winit::ime::set_allowed(false);

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
// Input method: kept away from secrets
// ---------------------------------------------------------------------------

/// Stable ids of the text inputs that always take a secret — every
/// `.secure(true)` field. No input method may compose, show or upload what
/// is typed into them: it is off while one of them has the keyboard focus
/// (`ime_allowed`). The sign-in modal's answer fields are secret only when
/// their prompt is not echoed; they go by `auth_input_id`.
const SETUP_PW_INPUT_ID: &str = "setup_pw";
const SETUP_CONFIRM_INPUT_ID: &str = "setup_confirm";
const UNLOCK_PW_INPUT_ID: &str = "unlock_pw";
const CONN_PASSWORD_INPUT_ID: &str = "conn_password";
const CONN_PASSPHRASE_INPUT_ID: &str = "conn_passphrase";
const PROXY_PASSWORD_INPUT_ID: &str = "proxy_password";
const PROXY_PASSPHRASE_INPUT_ID: &str = "proxy_passphrase";
const TUNNEL_PASSWORD_INPUT_ID: &str = "tunnel_password";
const TUNNEL_PASSPHRASE_INPUT_ID: &str = "tunnel_passphrase";
const SECRET_INPUT_IDS: [&str; 9] = [
    SETUP_PW_INPUT_ID,
    SETUP_CONFIRM_INPUT_ID,
    UNLOCK_PW_INPUT_ID,
    CONN_PASSWORD_INPUT_ID,
    CONN_PASSPHRASE_INPUT_ID,
    PROXY_PASSWORD_INPUT_ID,
    PROXY_PASSPHRASE_INPUT_ID,
    TUNNEL_PASSWORD_INPUT_ID,
    TUNNEL_PASSPHRASE_INPUT_ID,
];

/// The text input holding the keyboard focus, as the input method sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FocusedField {
    /// No text input: keys go to the terminal.
    #[default]
    None,
    /// One of [`SECRET_INPUT_IDS`].
    Secret,
    /// The sign-in modal's answer field for prompt `n`.
    AuthAnswer(usize),
    /// Any other text input.
    Text,
}

impl FocusedField {
    /// What the input with widget id `id` is. A focused input without an id
    /// is never reported (`find_focused` skips it) — which is why every
    /// secret field carries one.
    fn of(id: Option<&iced::advanced::widget::Id>) -> Self {
        use iced::advanced::widget::Id;
        let Some(id) = id else {
            return FocusedField::None;
        };
        if SECRET_INPUT_IDS.iter().any(|secret| *id == Id::new(*secret)) {
            return FocusedField::Secret;
        }
        match (0..AUTH_MAX_FIELDS).find(|&n| *id == Id::from(auth_input_id(n))) {
            Some(n) => FocusedField::AuthAnswer(n),
            None => FocusedField::Text,
        }
    }
}

/// Whether the input method may be on. Never on the setup and lock screens,
/// which hold nothing but master-password fields; on the main screen unless
/// the focused field takes a secret. `auth_prompts` are the sign-in modal's
/// prompts with their echo flags: an answer the server echoes is no secret,
/// and an answer field with no prompt behind it any more counts as one.
fn ime_allowed(screen: &Screen, focused: FocusedField, auth_prompts: &[(String, bool)]) -> bool {
    if *screen != Screen::Main {
        return false;
    }
    match focused {
        FocusedField::None | FocusedField::Text => true,
        FocusedField::Secret => false,
        FocusedField::AuthAnswer(n) => auth_prompts.get(n).is_some_and(|(_, echo)| *echo),
    }
}

/// Fail closed while the focus is unknown. A click on an overlay that holds
/// a secret field ([`Overlay::HOLDS_SECRETS`]) may just have focused it, and
/// iced 0.13 says which field only once the widget-tree query answers — a
/// frame later. Until then the input method stays off, so no keystroke can
/// reach a password field through it. Anywhere else no secret field is on
/// screen, and a click leaves the input method alone: switching it off and on
/// drops the candidate window's anchor on X11/Wayland and an in-progress
/// composition on macOS.
fn focus_settled_or_no_secret_on_screen(answered: bool, secret_on_screen: bool) -> bool {
    answered || !secret_on_screen
}

/// Which text input has the keyboard focus, as the app last learned it:
/// iced 0.13 keeps the focus inside the widgets. The widget tree is asked
/// (`query`) after anything that can move it — a mouse press, Tab, Esc, a
/// modal or a screen coming or going. When the app moves the focus itself
/// (`focus`), the field counts at once, and the tree confirms it after.
#[derive(Debug, Default)]
struct FocusTracker {
    field: FocusedField,
    /// The focused input's id, as `field` was read from.
    id: Option<iced::advanced::widget::Id>,
    /// Queries and focus moves, numbered as they are issued.
    issued: u64,
    /// Answers to queries numbered up to here are stale: a later answer is
    /// in, or the app moved the focus after they were asked.
    settled: u64,
}

impl FocusTracker {
    /// Ask the widget tree which input has the focus. `collect` answers even
    /// when none has: leaving a field for the terminal is an answer too.
    fn query(&mut self) -> Task<Message> {
        use iced::advanced::widget::{operate, operation::focusable::find_focused};
        self.issued += 1;
        let seq = self.issued;
        operate(find_focused())
            .collect()
            .map(move |ids| Message::FocusFound(seq, ids.into_iter().next()))
    }

    /// Focus the text input `id`. It counts as focused from here on — a
    /// secret field closes the input method before a key can reach it — and
    /// the tree is asked once the focus has moved, in case `id` was not on
    /// screen to take it.
    fn focus(&mut self, id: text_input::Id) -> Task<Message> {
        self.id = Some(id.clone().into());
        self.field = FocusedField::of(self.id.as_ref());
        self.issued += 1;
        self.settled = self.issued;
        text_input::focus(id).chain(self.query())
    }

    /// Run `task` — one that moves the focus — then ask the tree.
    fn then_query(&mut self, task: Task<Message>) -> Task<Message> {
        task.chain(self.query())
    }

    /// Every question asked of the widget tree has been answered: `field`
    /// is what holds the focus now, not what held it before the last click.
    fn answered(&self) -> bool {
        self.settled == self.issued
    }

    /// The answer to query `seq`.
    fn found(&mut self, seq: u64, id: Option<iced::advanced::widget::Id>) {
        if seq <= self.settled {
            return;
        }
        self.settled = seq;
        self.field = FocusedField::of(id.as_ref());
        self.id = id;
    }

    /// `field`, for a sign-in modal showing `answers` answer fields: one past
    /// the `AUTH_MAX_FIELDS` that `FocusedField::of` looks through — a server
    /// may ask for more — is still an answer field, not any text input.
    fn field_for(&self, answers: usize) -> FocusedField {
        use iced::advanced::widget::Id;
        match (self.field, &self.id) {
            (FocusedField::Text, Some(id)) if answers > AUTH_MAX_FIELDS => (AUTH_MAX_FIELDS
                ..answers)
                .find(|&n| *id == Id::from(auth_input_id(n)))
                .map_or(FocusedField::Text, FocusedField::AuthAnswer),
            (field, _) => field,
        }
    }
}

/// Whether `message` may leave another text input — or none — holding the
/// keyboard focus: a mouse press (a click focuses the input under it and
/// takes the focus from every other one), Tab or Shift+Tab, and Esc (a
/// focused text input lets go on Esc).
fn moves_focus(message: &Message) -> bool {
    use keyboard::key::Named;
    matches!(
        message,
        Message::TerminalMouseDown(_)
            | Message::FocusMayHaveMoved
            // Hiding the bottom panel or the sidebar removes the path inputs
            // or the search box — and the focus with them.
            | Message::ToggleBottomPanel
            | Message::ToggleSidebar
            | Message::KeyboardEvent(keyboard::Key::Named(Named::Tab | Named::Escape), ..)
    )
}

/// The input method's anchor for a terminal whose canvas starts at `origin`
/// with the text cursor in `cell` (0-based column, row): the cell's top-left
/// in window (logical) coordinates, and the line height. The renderer's and
/// `pixel_to_grid_with`'s cell metrics, font-size clamp included.
fn ime_cursor_area(origin: (f32, f32), font_size: f32, cell: (usize, usize)) -> (f32, f32, f32) {
    let font_size = if font_size.is_finite() {
        font_size.clamp(8.0, 28.0)
    } else {
        14.0
    };
    let (cell_w, cell_h) = (font_size * 0.6, font_size * 1.2);
    (
        origin.0 + cell.0 as f32 * cell_w,
        origin.1 + cell.1 as f32 * cell_h,
        cell_h,
    )
}

/// Tell the runtime what the input method may do now: nothing on the vault
/// screens or in a secret field; and while the terminal has the keyboard,
/// open its candidate window at the text cursor — sent only when that moves.
fn sync_input_method(state: &mut NeoShell) {
    let prompts = state
        .auth_queue
        .front()
        .map_or(&[][..], |(challenge, _)| challenge.prompt.prompts.as_slice());
    let field = state.focus.field_for(prompts.len());
    let allowed = ime_allowed(&state.screen, field, prompts)
        && focus_settled_or_no_secret_on_screen(state.focus.answered(), state.secret_overlay_open());
    iced_winit::ime::set_allowed(allowed);
    // Not while a click's answer is out: the runtime anchored the window at
    // the click — on the field it focused, perhaps — and the terminal takes
    // it back only once it is known to hold the keys.
    let terminal_keys = allowed
        && field == FocusedField::None
        && state.focus.answered()
        && !state.any_overlay_open();
    let area = if terminal_keys {
        state.focused_terminal().map(|term| {
            let cell = {
                let grid = term.lock();
                (
                    grid.cursor_x.min(grid.cols.saturating_sub(1)),
                    grid.cursor_y.min(grid.rows.saturating_sub(1)),
                )
            };
            ime_cursor_area(
                state.focused_pane_origin(),
                state.theme_cfg.terminal_font_size,
                cell,
            )
        })
    } else {
        None
    };
    match area {
        Some(area) if state.ime_area != Some(area) => {
            iced_winit::ime::set_cursor_area(area.0, area.1, area.2);
            state.ime_area = Some(area);
        }
        Some(_) => {}
        // Whatever takes the keys now places the window itself (a click
        // anchors it where it lands); the terminal re-sends when it is back.
        None => state.ime_area = None,
    }
}

// ---------------------------------------------------------------------------
// Update
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

/// Move any credential still sitting in cleartext in `proxies.json` /
/// `tunnels.json` into the vault. One-shot and idempotent: both stores record
/// that they ran, and a failure leaves the file byte-identical so the next
/// unlock simply retries.
///
/// Must run with the vault OPEN — it is a no-op otherwise — and before
/// anything reads a credential back, which is why it is called synchronously
/// from the unlock arms rather than dispatched as a message.
fn migrate_store_secrets(state: &mut NeoShell) {
    let mut moved = false;
    match state.proxy_store.migrate_secrets() {
        Ok(changed) => moved |= changed,
        Err(e) => log::error!("proxy credential migration: {}", e),
    }
    match state.tunnel_store.migrate_secrets() {
        Ok(changed) => moved |= changed,
        Err(e) => log::error!("tunnel credential migration: {}", e),
    }
    // `state.proxies` / `state.tunnels` were first filled in `Default`, before
    // the vault could decrypt anything, and the edit forms prefill from them.
    // Reload unconditionally so a stale pre-unlock list can never be written
    // back over a real one.
    state.proxies = state.proxy_store.load();
    state.tunnels = state.tunnel_store.load();
    if moved {
        log::info!("credential migration complete");
    }
}

/// Re-lock the vault: wipe the DEK, drop any decrypted secret held in the UI,
/// and return to the lock screen. Returns the write that takes the command
/// history's unsaved records to disk.
///
/// Live SSH sessions are deliberately untouched. They run on their own
/// threads inside `SshManager`, their output is drained by `PollSshEvents`
/// (which is not gated on `Screen::Main`), and `state.tabs` is left intact —
/// so the terminals are still there, still connected, when the vault is
/// unlocked again.
fn lock_vault(state: &mut NeoShell) -> Task<Message> {
    // History first, while the key is still in memory: what the disk has not
    // seen yet is sealed, then every record is wiped. The write itself runs
    // on a blocking thread and carries only ciphertext.
    let flush = lock_history(
        &state.history_file,
        &state.store,
        &mut state.cmd_history,
        &mut state.history_sync,
    )
    .map_or_else(Task::none, spawn_history_write);
    // The folded groups too: a change not saved yet is sealed while the key
    // is here, and the names are forgotten until the next unlock reads them.
    let groups = if state.groups_dirty {
        persist_groups(state, false)
    } else {
        Task::none()
    };
    state.collapsed_groups.clear();
    state.groups_dirty = false;
    state.store.lock();
    scrub_form_secrets(
        &mut state.form,
        &mut state.proxy_form,
        &mut state.tunnel_form,
    );
    // The lists are re-read on unlock; holding decrypted copies across the
    // lock would defeat it.
    scrub_list_secrets(&mut state.proxies, &mut state.tunnels);
    state.proxies.clear();
    state.tunnels.clear();
    state.connections.clear();
    // Nothing below the lock screen is rendered, but an overlay left open
    // would spring back with the vault.
    state.show_form = false;
    state.show_proxy_form = false;
    state.show_proxy_manager = false;
    state.show_tunnel_form = false;
    state.show_tunnel_manager = false;
    state.show_settings = false;
    state.show_key_manager = false;
    state.show_palette = false;
    // A half-typed keyboard-interactive answer is a secret, and the SSH
    // threads behind the queue must not wait on a screen nobody can see:
    // scrub the answers and cancel every challenge (dropping one cancels it).
    scrub_answers(&mut state.auth_answers);
    state.auth_queue.clear();
    state.auth_focus_owed = false;
    state.auth_shown_at = None;
    // A pending destructive action does not survive the lock either.
    state.confirm_action = None;
    state.sftp_input = None;
    state.remote_menu = None;
    // The master password fields too, zeroized like the forms' secrets.
    state.password_input.zeroize();
    state.confirm_input.zeroize();
    state.error_message.clear();
    state.screen = Screen::Locked;
    Task::batch([flush, groups])
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
            // Keyboard-interactive challenges ride this tick rather than a
            // timer of their own; a new one comes back as a focus task.
            let auth = poll_auth_prompts(state);
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
        .size(22.0 * scale)
        .color(c_primary);

    let subtitle = text(i18n::t("setup.subtitle"))
        .size(12.5 * scale)
        .color(theme::TEXT_SECONDARY);

    let pw_input = input(&i18n::t("setup.password_placeholder"), &state.password_input)
        .on_input(Message::PasswordChanged)
        .secure(true)
        .padding(Padding::from([9, 12]))
        .size(14.0 * scale)
        .id(text_input::Id::new(SETUP_PW_INPUT_ID));

    let confirm_input = input(&i18n::t("setup.confirm_placeholder"), &state.confirm_input)
        .on_input(Message::ConfirmChanged)
        .on_submit(Message::CreateVault)
        .secure(true)
        .padding(Padding::from([9, 12]))
        .size(14.0 * scale)
        .id(text_input::Id::new(SETUP_CONFIRM_INPUT_ID));

    let create_btn = button(
        text(i18n::t("setup.create_vault")).size(13.0 * scale),
    )
    .on_press(Message::CreateVault)
    .padding(Padding::from([8, 22]))
    .style(accent_button_style);

    let error_text = if state.error_message.is_empty() {
        text("").size(1.0 * scale)
    } else {
        text(&state.error_message).color(c_danger).size(12.0 * scale)
    };

    let form = column![title, subtitle, pw_input, confirm_input, error_text, create_btn]
        .spacing(space::M)
        .align_x(alignment::Horizontal::Center)
        .width(320);

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
        .size(22.0 * scale)
        .color(c_primary);

    let subtitle = text(i18n::t("unlock.subtitle"))
        .size(12.5 * scale)
        .color(theme::TEXT_SECONDARY);

    let pw_input = input(&i18n::t("unlock.password_placeholder"), &state.password_input)
        .on_input(Message::PasswordChanged)
        .on_submit(Message::UnlockVault)
        .secure(true)
        .padding(Padding::from([9, 12]))
        .size(14.0 * scale)
        .id(text_input::Id::new(UNLOCK_PW_INPUT_ID));

    let unlock_btn = button(
        text(i18n::t("unlock.btn")).size(13.0 * scale),
    )
    .on_press(Message::UnlockVault)
    .padding(Padding::from([8, 22]))
    .style(accent_button_style);

    let error_text = if state.error_message.is_empty() {
        text("").size(1.0 * scale)
    } else {
        text(&state.error_message).color(c_danger).size(12.0 * scale)
    };

    let form = column![title, subtitle, pw_input, error_text, unlock_btn]
        .spacing(space::M)
        .align_x(alignment::Horizontal::Center)
        .width(320);

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

    let sidebar_width: f32 = if state.sidebar_collapsed { 0.0 } else { SIDEBAR_W };

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
        let chevron_tip = if state.bottom_panel_collapsed { "tip.panel_show" } else { "tip.panel_hide" };
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
                tip(chevron_btn, i18n::t(chevron_tip)),
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
        view_welcome(state)
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

    // If a context menu is open, wrap main_col with the menu overlay
    let main_layout: Element<'_, Message> =
        if state.context_menu.is_none() && state.remote_menu.is_none() {
            main_col.height(Fill).into()
        } else {
            let mut layers: Vec<Element<'_, Message>> = vec![main_col.height(Fill).into()];
            if let Some(ctx) = &state.context_menu {
                layers.push(view_context_menu(ctx));
            }
            if let Some(menu) = &state.remote_menu {
                layers.push(view_remote_menu(state, menu));
            }
            container(stack(layers)).width(Fill).height(Fill).into()
        };

    // At most one overlay, picked by the shared z-order (see `Overlay`) and
    // drawn on the shared scrim. ESC closes this same one.
    let overlay: Option<Element<'_, Message>> = state.topmost_overlay().map(|top| match top {
        Overlay::Palette => view_palette(state),
        Overlay::ConfirmDelete => view_confirm_delete(state),
        Overlay::AuthPrompt => view_auth_prompt(state),
        Overlay::ConfirmAction => view_confirm_action(state),
        Overlay::LogViewer => view_log_viewer(state),
        Overlay::ErrorDialog => view_error_dialog(state),
        Overlay::ProcessDetail => view_process_detail(state),
        Overlay::Editor => view_editor(state),
        Overlay::NetworkDetail => view_network_detail(state),
        Overlay::ConnectDialog => view_connect_dialog(state),
        Overlay::History => view_history_panel(state),
        Overlay::ProxyManager => view_proxy_manager(state),
        Overlay::TunnelManager => view_tunnel_manager(state),
        Overlay::TabRename => view_tab_rename(state),
        Overlay::SftpInput => view_sftp_input(state),
        Overlay::KeyManager => view_key_manager(state),
        Overlay::ShortcutsHelp => view_shortcuts_help(),
        Overlay::Broadcast => view_broadcast_dialog(state),
        Overlay::Snippets => view_snippets_panel(state),
        Overlay::About => view_about_dialog(state),
        Overlay::Settings => view_settings_menu(state),
        Overlay::ConnectionForm => view_connection_form_overlay(state),
    });

    let base = container(main_layout)
        .width(Fill)
        .height(Fill)
        .style(bg_primary_container);
    match overlay {
        Some(overlay) => stack![base, scrim(), overlay]
            .width(Fill)
            .height(Fill)
            .into(),
        None => base.into(),
    }
}

// ---- Delete confirmation ----------------------------------------------------

fn view_confirm_delete(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let name = state
        .confirm_delete
        .as_ref()
        .map(|(_, name)| name.as_str())
        .unwrap_or_default();
    let msg = i18n::tf("confirm.delete", &[("name", name)]);
    let card = modal_card(
        column![
            text(msg).color(state.c_primary()).size(14.0 * scale),
            vertical_space().height(12),
            row![
                button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
                    .on_press(Message::CancelDelete)
                    .padding(Padding::from([6, 16]))
                    .style(transparent_button_style),
                button(text(i18n::t("dialog.delete")).size(13.0 * scale))
                    .on_press(Message::ExecuteDelete)
                    .padding(Padding::from([6, 16]))
                    .style(filled_button_style(state.c_danger())),
            ]
            .spacing(12),
        ]
        .align_x(alignment::Horizontal::Center)
        .padding(24),
    );
    iced::widget::center(card).into()
}

// ---- Destructive-action confirmation (SFTP delete / chmod, kill) ------------

/// Same shape as the connection delete: the question, then exactly what it
/// will touch — the full remote path, or the process's command line — in a
/// block of its own, so nothing is confirmed on a truncated name.
fn view_confirm_action(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let Some(action) = &state.confirm_action else {
        return Space::new(0, 0).into();
    };
    // Which host, too: a tab switch can put a different one on screen.
    let session_id = match action {
        ConfirmAction::SftpDelete { session_id, .. }
        | ConfirmAction::SftpChmod { session_id, .. }
        | ConfirmAction::Kill { session_id, .. } => session_id,
    };
    let host = state.session_label(session_id);
    let (question, subject, marked) = confirm_action_text(action);
    let confirm_label = i18n::t(match action {
        ConfirmAction::SftpDelete { .. } => "tip.delete",
        ConfirmAction::SftpChmod { .. } => "sftp.apply",
        ConfirmAction::Kill { .. } => "process.send_signal",
    });
    let subject_block = container(
        text(subject)
            .font(Font::MONOSPACE)
            .color(theme::TEXT_SECONDARY)
            .size(12.0 * scale),
    )
    .padding(Padding::from([8, 10]))
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border { radius: 6.0.into(), width: 1.0, color: theme::BORDER },
        ..Default::default()
    });
    let host_line: Element<'_, Message> = if host.is_empty() {
        Space::new(0, 0).into()
    } else {
        text(i18n::tf("confirm.on_host", &[("host", &host)]))
            .font(Font::MONOSPACE)
            .color(theme::TEXT_MUTED)
            .size(11.0 * scale)
            .into()
    };
    // What the marks in the name stand for, when there are any.
    let marks_line: Element<'_, Message> = if marked {
        text(i18n::t("sftp.name_marks"))
            .color(theme::TEXT_MUTED)
            .size(11.0 * scale)
            .into()
    } else {
        Space::new(0, 0).into()
    };
    let card = modal_card(
        column![
            text(question).color(state.c_primary()).size(14.0 * scale),
            host_line,
            subject_block,
            marks_line,
            row![
                button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
                    .on_press(Message::ConfirmActionCancel)
                    .padding(Padding::from([6, 16]))
                    .style(transparent_button_style),
                horizontal_space(),
                button(text(confirm_label).size(13.0 * scale))
                    .on_press(Message::ConfirmActionExecute)
                    .padding(Padding::from([6, 16]))
                    .style(filled_button_style(state.c_danger())),
            ]
            .spacing(12)
            .align_y(alignment::Vertical::Center),
        ]
        .spacing(space::M)
        .padding(24)
        .width(480),
    );
    iced::widget::center(card).into()
}

/// What the confirmation of `action` says: the question, the block under it,
/// and whether those carry [`visible_name`] marks, which a line explains.
///
/// For an SFTP action the question quotes the name exactly and states what
/// the row showed it to be, with the full path under it — spaces at the ends
/// and anything invisible marked — so a decoy "project " cannot pass for
/// "project", nor a file for a folder. For a kill, the block is the command
/// line /proc gave as the confirmation opened.
fn confirm_action_text(action: &ConfirmAction) -> (String, String, bool) {
    match action {
        ConfirmAction::SftpDelete { path, name, kind, .. } => {
            let shown = visible_name(name);
            let subject = visible_path(path);
            let marked = shown != *name || subject != *path;
            let question = match kind {
                EntryKind::Dir => i18n::tf("sftp.confirm_delete_dir_named", &[("name", &shown)]),
                EntryKind::Symlink => {
                    i18n::tf("sftp.confirm_delete_link_named", &[("name", &shown)])
                }
                EntryKind::File | EntryKind::Other => i18n::tf(
                    "sftp.confirm_delete_named",
                    &[("kind", entry_kind_label(*kind)), ("name", &shown)],
                ),
            };
            (question, subject, marked)
        }
        ConfirmAction::SftpChmod { path, name, kind, mode, .. } => {
            let shown = visible_name(name);
            let subject = visible_path(path);
            let marked = shown != *name || subject != *path;
            let question = i18n::tf(
                "sftp.confirm_chmod_named",
                &[
                    ("kind", entry_kind_label(*kind)),
                    ("name", &shown),
                    ("mode", &format!("{:04o}", mode)),
                ],
            );
            (question, subject, marked)
        }
        ConfirmAction::Kill { pid, command, signal, .. } => (
            i18n::tf(
                "process.confirm_kill",
                &[("signal", &signal_name(*signal)), ("pid", &pid.to_string())],
            ),
            command.clone(),
            false,
        ),
    }
}

// ---- SFTP name / mode dialog -----------------------------------------------

fn view_sftp_input(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let Some(dialog) = &state.sftp_input else {
        return Space::new(0, 0).into();
    };
    let (title, hint) = match &dialog.kind {
        SftpInputKind::NewFolder => (
            i18n::tf("sftp.new_folder_title", &[("dir", &dialog.dir)]),
            i18n::t("sftp.name_hint"),
        ),
        SftpInputKind::Rename { from, kind, .. } => (
            i18n::tf(
                "sftp.rename_title_named",
                &[("kind", entry_kind_label(*kind)), ("name", &visible_name(from))],
            ),
            i18n::t("sftp.name_hint"),
        ),
        SftpInputKind::Chmod { name, kind, .. } => (
            i18n::tf(
                "sftp.chmod_title_named",
                &[("kind", entry_kind_label(*kind)), ("name", &visible_name(name))],
            ),
            i18n::t("sftp.mode_hint"),
        ),
    };
    let field = input("", &dialog.value)
        .id(text_input::Id::new(SFTP_INPUT_ID))
        .on_input(Message::SftpInputChanged)
        .on_submit(Message::SftpInputSubmit)
        .padding(Padding::from([8, 10]))
        .size(14.0 * scale);
    let mut content = column![
        text(title).size(15.0 * scale).color(state.c_primary()),
        text(hint).size(11.0 * scale).color(theme::TEXT_MUTED),
        field,
    ]
    .spacing(12)
    .width(400);
    // What the marks in the quoted name stand for, when there are any.
    let marked = match &dialog.kind {
        SftpInputKind::NewFolder => false,
        SftpInputKind::Rename { from: name, .. } | SftpInputKind::Chmod { name, .. } => {
            visible_name(name) != *name
        }
    };
    if marked {
        content = content.push(
            text(i18n::t("sftp.name_marks")).size(11.0 * scale).color(theme::TEXT_MUTED),
        );
    }
    if let Some(error) = dialog.error {
        content = content.push(text(i18n::t(error)).size(11.0 * scale).color(state.c_danger()));
    }
    content = content.push(
        row![
            button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
                .on_press(Message::SftpInputCancel)
                .padding(Padding::from([6, 16]))
                .style(transparent_button_style),
            horizontal_space(),
            button(text(i18n::t("sftp.ok")).size(12.0 * scale))
                .on_press(Message::SftpInputSubmit)
                .padding(Padding::from([6, 16]))
                .style(accent_button_style),
        ]
        .align_y(alignment::Vertical::Center),
    );
    iced::widget::center(modal_card(content).padding(20)).into()
}

// ---- Keyboard-interactive auth ---------------------------------------------

/// A keyboard-interactive challenge from an SSH server: its prompts, masked
/// where the server marked them non-echo. The SSH thread is blocked on the
/// answer, so every way out — Continue, Cancel, Esc, the vault lock —
/// resolves it.
fn view_auth_prompt(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let Some((challenge, _)) = state.auth_queue.front() else {
        return Space::new(0, 0).into();
    };
    // Apart from the labels, everything here was written by the server.
    let mut target = sanitize_remote_text(&challenge.target, 120);
    // The server may challenge a different user than the one we sent.
    let asked = sanitize_remote_text(&challenge.username, 64);
    if !asked.is_empty() && !target.starts_with(&format!("{}@", asked)) {
        target = format!("{} ({})", target, asked);
    }
    let mut head = column![
        text(i18n::t("auth.title")).size(16.0 * scale).color(state.c_primary()),
        text(format!("{} · {}", target, auth_purpose_label(&challenge.purpose)))
            .font(Font::MONOSPACE)
            .size(11.0 * scale)
            .color(theme::TEXT_SECONDARY),
        text(i18n::t("auth.from_server")).size(11.0 * scale).color(theme::TEXT_MUTED),
    ]
    .spacing(space::S);
    let instructions = sanitize_remote_text(&challenge.instructions, 600);
    if !instructions.is_empty() {
        head = head.push(text(instructions).size(12.0 * scale).color(theme::TEXT_SECONDARY));
    }

    let count = challenge.prompt.prompts.len();
    let mut fields = column![].spacing(space::M);
    for (i, (prompt, echo)) in challenge.prompt.prompts.iter().enumerate() {
        let value = state.auth_answers.get(i).map(String::as_str).unwrap_or("");
        // Enter moves to the next answer; on the last one it submits.
        let on_enter = if i + 1 < count { Message::AuthFocus(i + 1) } else { Message::AuthEnter };
        let field = input("", value)
            .id(auth_input_id(i))
            .on_input(move |v| Message::AuthAnswerChanged(i, v))
            .on_submit(on_enter)
            .secure(!*echo)
            .padding(8)
            .size(14.0 * scale);
        fields = fields.push(
            column![
                text(sanitize_remote_text(prompt, 200))
                    .size(12.0 * scale)
                    .color(theme::TEXT_SECONDARY),
                field,
            ]
            .spacing(4),
        );
    }

    let mut content = column![head, container(slim_scroll(fields)).max_height(320)]
        .spacing(space::M)
        .padding(24)
        .width(440);
    let waiting = state.auth_queue.len().saturating_sub(1);
    if waiting > 0 {
        content = content.push(
            text(i18n::tf("auth.queued", &[("count", &waiting.to_string())]))
                .size(10.0 * scale)
                .color(theme::TEXT_MUTED),
        );
    }
    content = content.push(
        row![
            button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
                .on_press(Message::AuthCancel)
                .padding(Padding::from([6, 16]))
                .style(transparent_button_style),
            horizontal_space(),
            button(text(i18n::t("auth.continue")).size(13.0 * scale))
                .on_press(Message::AuthSubmit)
                .padding(Padding::from([6, 16]))
                .style(accent_button_style),
        ]
        .align_y(alignment::Vertical::Center),
    );
    iced::widget::center(modal_card(content)).into()
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

    let title = text(format!("{} · {}", i18n::t("process.title"), detail.pid))
        .size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideProcessDetail)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    // Signals, each behind a confirmation naming the pid and command. Not
    // offered for pid 0/1, which kill_process refuses anyway.
    let kill_btns: Element<'_, Message> = if detail.pid > 1 && !detail.session_id.is_empty() {
        row![
            tip(
                button(text(i18n::t("process.sigterm")).color(c_danger).size(11.0 * scale))
                    .on_press(Message::KillProcessRequest(15))
                    .padding(Padding::from([3, 10]))
                    .style(outline_button_style),
                i18n::t("process.sigterm_tip"),
            ),
            tip(
                button(text(i18n::t("process.sigkill")).size(11.0 * scale))
                    .on_press(Message::KillProcessRequest(9))
                    .padding(Padding::from([3, 10]))
                    .style(filled_button_style(c_danger)),
                i18n::t("process.sigkill_tip"),
            ),
        ]
        .spacing(space::S)
        .into()
    } else {
        Space::new(0, 0).into()
    };

    let header = row![title, horizontal_space(), kill_btns, tip(close_btn, i18n::t("tip.close"))]
        .spacing(space::S)
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
                text(i18n::t("monitor.pid")).color(theme::TEXT_MUTED).size(9.0 * scale).width(60),
                text(i18n::t("monitor.proc_cpu")).color(theme::TEXT_MUTED).size(9.0 * scale).width(40),
                text(i18n::t("monitor.proc_mem")).color(theme::TEXT_MUTED).size(9.0 * scale).width(40),
                text(i18n::t("monitor.proc_cmd")).color(theme::TEXT_MUTED).size(9.0 * scale),
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
        slim_scroll(body_col).height(Fill),
    ]
    .spacing(space::S)
    .padding(16)
    .width(560);

    iced::widget::center(modal_card(content).height(500)).into()
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
        column![connect_item, edit_item, delete_item].spacing(space::XXS).width(140)
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

// ---- Context menu (right-click in the remote file browser) ------------------

/// "New folder" always; Rename, Permissions and Delete for a real row. Opened
/// at the pointer and kept inside the window — the browser sits low, so it
/// usually opens upward.
fn view_remote_menu<'a>(state: &'a NeoShell, menu: &RemoteFileMenu) -> Element<'a, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let item = |label: &str, color: Color, msg: Message| -> Element<'a, Message> {
        button(text(label.to_string()).color(color).size(12.0 * scale))
            .on_press(msg)
            .padding(Padding::from([6, 16]))
            .width(Fill)
            .style(sidebar_item_style)
            .into()
    };
    let mut items = column![item(i18n::t("sftp.new_folder"), c_primary, Message::SftpNewFolder)]
        .spacing(space::XXS)
        .width(180);
    let rows = if let Some(entry) = &menu.entry {
        items = items.push(item(i18n::t("sftp.rename"), c_primary, Message::SftpRename));
        // Over SFTP a symlink's permissions cannot be changed, only its
        // target's — which the SSH layer refuses — so it is not offered.
        let chmod = entry.kind() != EntryKind::Symlink;
        if chmod {
            items = items.push(item(i18n::t("sftp.permissions"), c_primary, Message::SftpChmod));
        }
        items = items.push(item(i18n::t("sftp.delete"), state.c_danger(), Message::SftpDelete));
        if chmod { 4.0 } else { 3.0 }
    } else {
        1.0
    };

    let card = container(items)
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

    // Estimated card size, only to keep it on screen.
    let (w, h) = (188.0, rows * (16.0 * scale + 14.0) + 10.0);
    let x = menu.x.min(state.window_width - w).max(0.0);
    let y = if menu.y + h > state.window_height {
        (menu.y - h).max(0.0)
    } else {
        menu.y
    };

    // Transparent full-window backdrop: a click anywhere else closes the menu.
    let backdrop = button(Space::new(Fill, Fill))
        .on_press(Message::RemoteMenuClose)
        .style(|_: &Theme, _| button::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.01).into()),
            ..Default::default()
        });

    stack([
        backdrop.width(Fill).height(Fill).into(),
        container(card)
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
            s.border = iced::Border { radius: 6.0.into(), ..Default::default() };
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
                s.border = iced::Border { radius: 6.0.into(), ..Default::default() };
            }
            s
        });

    let sidebar_tip = if state.sidebar_collapsed { "tip.sidebar_show" } else { "tip.sidebar_hide" };
    let sep = || -> Element<'_, Message> {
        container(Space::new(1, 16))
            .style(|_| container::Style { background: Some(theme::BORDER.into()), ..Default::default() })
            .into()
    };

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
    let btn_keys = button(text(i18n::t("btn.keys")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowKeyManager).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_settings = button(text(i18n::t("settings.title")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowSettings).padding(Padding::from([4, 10])).style(toolbar_style);

    // Clustered by how often they are reached for: every session / running
    // operations across hosts / one-off setup.
    let bar = row![
        tip(sidebar_btn, i18n::t(sidebar_tip)),
        sep(),
        btn_new,
        btn_history,
        btn_snippets,
        sep(),
        btn_broadcast,
        btn_tunnel,
        sep(),
        btn_proxy,
        btn_keys,
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
    let ports_active = state.bottom_panel_tab == BottomTab::Ports;

    let tab_monitor = button(
        text(i18n::t("monitor.system")).color(if mon_active { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::Monitor))
    .padding(Padding::from([4, 14]))
    .style(move |_theme: &Theme, status| segment_style(mon_active, status));

    let tab_files = button(
        text(i18n::t("bottom.files")).color(if files_active { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::Files))
    .padding(Padding::from([4, 14]))
    .style(move |_theme: &Theme, status| segment_style(files_active, status));

    let tab_cmd = button(
        text(i18n::t("bottom.cmd")).color(if cmd_active { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::QuickCmd))
    .padding(Padding::from([4, 14]))
    .style(move |_theme: &Theme, status| segment_style(cmd_active, status));

    let tab_ports = button(
        text(i18n::t("bottom.ports")).color(if ports_active { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::Ports))
    .padding(Padding::from([4, 14]))
    .style(move |_theme: &Theme, status| segment_style(ports_active, status));

    let tab_strip = container(
        row![tab_monitor, tab_ports, tab_files, tab_cmd].spacing(4).padding(Padding::from([3, 8]))
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
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
        BottomTab::Ports => view_ports_panel(state),
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
    // The focused pane's session, split panes included.
    let active_session = state.active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.focused_session());
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
    if let Some(parked) = state.monitor_parked.get(sid) {
        return view_monitor_parked(sid, parked, "monitor.parked", scale, c_primary, c_danger);
    }

    let stats = state.server_stats.get(sid);
    let processes = state.top_processes.get(sid);

    // ── Column 1: System info ──────────────────────────────────────
    let mut sys_col = column![
        text(i18n::t("monitor.system")).color(c_primary).size(11.0 * scale),
    ].spacing(2);
    let sys_size = 10.0 * scale;
    if let Some(s) = stats {
        sys_col = sys_col.push(sys_row_sized(&i18n::t("monitor.load"), &format!("{:.2} / {:.2} / {:.2}", s.load_1m, s.load_5m, s.load_15m), sys_size));
        let cores = i18n::tf("monitor.cpu_cores", &[("count", &s.cpu_cores.to_string())]);
        if s.cpu_per_core.is_empty() {
            // No /proc/stat (a non-Linux remote): the core count, as before.
            sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.cpu"), &cores, sys_size));
        } else {
            // Real utilisation from the /proc/stat delta — load average is a
            // queue length, not a percentage.
            sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.cpu"), &format!("{:.0}% · {}", s.cpu_percent, cores), sys_size));
            sys_col = sys_col.push(progress_bar_widget_with_color(s.cpu_percent, pb_color));
            if s.cpu_per_core.len() > 1 {
                sys_col = sys_col.push(per_core_bars(&s.cpu_per_core, scale, pb_color));
            }
        }
        sys_col = sys_col.push(sys_row_sized(&i18n::t("monitor.mem"), &format!("{} / {} MB ({:.0}%)", s.mem_used_mb, s.mem_total_mb, s.mem_percent), sys_size));
        sys_col = sys_col.push(progress_bar_widget_with_color(s.mem_percent, pb_color));
        // Zero on a host with no swap configured: nothing to show then.
        if s.swap_total_mb > 0 {
            sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.swap"), &format!("{} / {} MB ({:.0}%)", s.swap_used_mb, s.swap_total_mb, s.swap_percent), sys_size));
            sys_col = sys_col.push(progress_bar_widget_with_color(s.swap_percent, pb_color));
        }
        if s.disks.is_empty() {
            // No per-mount breakdown (df output unparsed): fall back to the
            // aggregate figures, as the old sidebar monitor did, instead of
            // showing no disk at all.
            sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.disk"), &format!("{:.1} / {:.1} GB ({:.0}%)", s.disk_used_gb, s.disk_total_gb, s.disk_percent), sys_size));
            sys_col = sys_col.push(progress_bar_widget_with_color(s.disk_percent, pb_color));
        } else {
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
    ].spacing(space::XXS);

    if let Some(s) = stats {
        let rx_rate = state.net_rx_rate.get(sid).copied().unwrap_or(0.0);
        let tx_rate = state.net_tx_rate.get(sid).copied().unwrap_or(0.0);
        // Byte columns are right-aligned in fixed widths so digits line up.
        let right = alignment::Horizontal::Right;
        net_col = net_col.push(
            row![
                text(i18n::t("net.speed")).color(theme::TEXT_MUTED).size(9.0 * scale).width(80),
                text(format!("D {}/s", format_bytes(rx_rate as u64))).color(c_success).size(9.0 * scale).width(80).align_x(right),
                text(format!("U {}/s", format_bytes(tx_rate as u64))).color(c_success).size(9.0 * scale).width(80).align_x(right),
            ].spacing(4)
        );

        net_col = net_col.push(
            row![
                text(i18n::t("net.interface")).color(theme::TEXT_MUTED).size(8.0 * scale).width(80),
                text(i18n::t("net.received")).color(theme::TEXT_MUTED).size(8.0 * scale).width(80).align_x(right),
                text(i18n::t("net.sent")).color(theme::TEXT_MUTED).size(8.0 * scale).width(80).align_x(right),
            ].spacing(4)
        );

        for (i, iface) in s.interfaces.iter().enumerate() {
            if iface.name == "lo" { continue; }
            let is_physical = iface.name.starts_with("eth") || iface.name.starts_with("en")
                || iface.name.starts_with("wl") || iface.name.starts_with("bond")
                || iface.name.starts_with("ib");
            let name_color = if is_physical { c_primary } else { theme::TEXT_MUTED };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };

            let iface_row = row![
                text(truncate_str(&iface.name, 10)).color(name_color).size(9.0 * scale).width(80),
                text(format_bytes(iface.rx_bytes)).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(80).align_x(right),
                text(format_bytes(iface.tx_bytes)).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(80).align_x(right),
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
                    text(format_bytes(s.net_rx_bytes)).color(c_accent).size(9.0 * scale).width(80).align_x(right),
                    text(format_bytes(s.net_tx_bytes)).color(c_accent).size(9.0 * scale).width(80).align_x(right),
                ].spacing(4)
            ).padding(Padding::from([2, 2]))
        );
    }

    // ── Column 3: Processes ────────────────────────────────────────
    // Numbers right-aligned under right-aligned headers; the command is
    // capped and never wraps, so one long argv cannot blow up a row.
    let num = alignment::Horizontal::Right;
    let mut proc_col = column![
        text(i18n::t("monitor.processes")).color(c_primary).size(11.0 * scale),
        row![
            text(i18n::t("monitor.pid")).color(theme::TEXT_MUTED).size(8.0 * scale).width(44).align_x(num),
            text(i18n::t("monitor.proc_cpu")).color(theme::TEXT_MUTED).size(8.0 * scale).width(36).align_x(num),
            text(i18n::t("monitor.proc_mem")).color(theme::TEXT_MUTED).size(8.0 * scale).width(36).align_x(num),
            text(i18n::t("monitor.proc_cmd")).color(theme::TEXT_MUTED).size(8.0 * scale),
        ].spacing(space::XS),
    ].spacing(space::XXS);

    if let Some(procs) = processes {
        let row_size = 9.0 * scale;
        for (i, p) in procs.iter().take(15).enumerate() {
            let color = if p.cpu > 50.0 { c_danger }
                       else if p.cpu > 20.0 { theme::WARNING }
                       else { theme::TEXT_SECONDARY };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
            let pid_val = p.pid;
            let prow = row![
                text(format!("{}", p.pid)).color(color).size(row_size).width(44).align_x(num),
                text(format!("{:.1}", p.cpu)).color(color).size(row_size).width(36).align_x(num),
                text(format!("{:.1}", p.mem)).color(color).size(row_size).width(36).align_x(num),
                text(truncate_str(&p.command, 48))
                    .color(color)
                    .size(row_size)
                    .wrapping(iced::widget::text::Wrapping::None),
            ].spacing(space::XS);
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

    let left_panel = slim_scroll(left_combined).height(Fill);
    let right_panel = slim_scroll(proc_col).height(Fill);

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

/// The monitor panel of a session whose monitoring is parked: why, and the
/// one button that re-opens it. Off while its reconnect is out, so one press
/// is one challenge.
fn view_monitor_parked<'a>(
    session_id: &str,
    parked: &'a ParkedMonitor,
    what: &'static str,
    scale: f32,
    c_primary: Color,
    c_danger: Color,
) -> Element<'a, Message> {
    let action: Element<'a, Message> = if parked.resuming {
        button(
            text(i18n::t("monitor.reconnecting"))
                .color(theme::TEXT_MUTED)
                .size(12.0 * scale),
        )
        .padding(Padding::from([6, 14]))
        .style(transparent_button_style)
        .into()
    } else {
        button(text(i18n::t("monitor.reconnect")).size(12.0 * scale))
            .on_press(Message::ResumeMonitoring(session_id.to_string()))
            .padding(Padding::from([6, 14]))
            .style(accent_button_style)
            .into()
    };
    let mut col = column![
        text(i18n::t(what))
            .color(c_primary)
            .size(12.0 * scale),
        action,
    ]
    .spacing(space::S);
    if let Some(e) = &parked.error {
        col = col.push(text(e.as_str()).color(c_danger).size(11.0 * scale));
    }
    container(col).padding(Padding::from([12, 12])).into()
}

/// Per-core utilisation as a grid of mini bars, eight to a row, each labelled
/// with its core number and percentage.
fn per_core_bars(cores: &[f64], scale: f32, user_color: Option<Color>) -> Element<'static, Message> {
    const PER_ROW: usize = 8;
    let mut grid = column![].spacing(space::XS);
    for (r, chunk) in cores.chunks(PER_ROW).enumerate() {
        let mut line = row![].spacing(space::XS);
        for (i, pct) in chunk.iter().enumerate() {
            let pct = if pct.is_finite() { pct.clamp(0.0, 100.0) } else { 0.0 };
            let color = user_color.unwrap_or_else(|| heat_color(pct));
            let filled = pct.round() as u16;
            let bar: Element<'static, Message> = if filled == 0 {
                Space::new(Fill, 3).into()
            } else {
                row![
                    container(Space::new(Fill, 3))
                        .width(Length::FillPortion(filled))
                        .style(move |_| container::Style {
                            background: Some(color.into()),
                            border: iced::Border { radius: 1.5.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    Space::new(Length::FillPortion((100 - filled.min(100)).max(1)), 3),
                ]
                .into()
            };
            line = line.push(
                column![
                    text(format!("{} {:.0}%", r * PER_ROW + i, pct))
                        .size(8.0 * scale)
                        .color(theme::TEXT_MUTED)
                        .wrapping(iced::widget::text::Wrapping::None),
                    container(bar).width(Fill).style(|_| container::Style {
                        background: Some(theme::BG_TERTIARY.into()),
                        ..Default::default()
                    }),
                ]
                .spacing(1)
                .width(Length::FillPortion(1)),
            );
        }
        // Pad a short last row so its cells keep the same width.
        for _ in chunk.len()..PER_ROW {
            line = line.push(Space::with_width(Length::FillPortion(1)));
        }
        grid = grid.push(line);
    }
    container(grid).padding(Padding::from([2, 10])).width(Fill).into()
}

/// Green / orange / red by load: a bar's colour when the theme sets none.
fn heat_color(pct: f64) -> Color {
    if pct > 90.0 {
        theme::DANGER
    } else if pct > 70.0 {
        theme::WARNING
    } else {
        theme::SUCCESS
    }
}

// ---- Listening ports (bottom tab) -------------------------------------------

/// `fetch_listening_ports` for the active session as a sortable table; a row
/// with a known owner opens the process-detail popup.
fn view_ports_panel(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let fs = 10.0 * scale;
    let num = alignment::Horizontal::Right;
    let left = alignment::Horizontal::Left;
    let sid = state
        .active_tab
        .and_then(|i| state.tabs.get(i))
        .map(|t| t.focused_session())
        .unwrap_or("");
    let current = !sid.is_empty() && state.ports_session == sid;

    let refresh = button(text(i18n::t("btn.refresh")).color(state.c_accent()).size(11.0 * scale))
        .on_press(Message::FetchPorts)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let count = if current { state.ports.len() } else { 0 };
    let header = row![
        text(i18n::t("ports.title")).color(c_primary).size(11.0 * scale),
        text(format!("({})", count)).color(theme::TEXT_MUTED).size(fs),
        horizontal_space(),
        text(i18n::t("ports.hint")).color(theme::TEXT_MUTED).size(9.0 * scale),
        tip(refresh, i18n::t("log.refresh")),
    ]
    .spacing(space::S)
    .align_y(alignment::Vertical::Center);

    let sort_head = |label: &str, key: PortSort, width: Length, align: alignment::Horizontal| {
        let active = state.ports_sort == key;
        let arrow = match (active, state.ports_sort_desc) {
            (false, _) => "",
            (true, false) => " ↑",
            (true, true) => " ↓",
        };
        button(
            text(format!("{}{}", i18n::t(label), arrow))
                .size(9.0 * scale)
                .color(if active { c_primary } else { theme::TEXT_MUTED })
                .width(Fill)
                .align_x(align),
        )
        .on_press(Message::PortsSortBy(key))
        .padding(Padding::from([1, 2]))
        .width(width)
        .style(transparent_button_style)
    };
    let columns = row![
        sort_head("ports.proto", PortSort::Proto, Length::Fixed(56.0), left),
        sort_head("ports.addr", PortSort::Addr, Length::FillPortion(2), left),
        sort_head("ports.port", PortSort::Port, Length::Fixed(64.0), num),
        sort_head("ports.pid", PortSort::Pid, Length::Fixed(64.0), num),
        sort_head("ports.process", PortSort::Process, Length::FillPortion(3), left),
    ]
    .spacing(space::XS)
    .padding(Padding::from([0, 4]));

    let mut list = column![].spacing(0);
    let notice = |key: &str| {
        container(text(i18n::t(key)).color(theme::TEXT_MUTED).size(11.0 * scale))
            .padding(Padding::from([10, 8]))
    };
    if !current {
        list = list.push(notice("ports.loading"));
    } else if let Some(e) = &state.ports_error {
        list = list.push(
            container(text(e.clone()).color(state.c_danger()).size(11.0 * scale))
                .padding(Padding::from([10, 8])),
        );
    } else if state.ports.is_empty() {
        let loading = state.ports_inflight.contains(sid);
        list = list.push(notice(if loading { "ports.loading" } else { "ports.empty" }));
    } else {
        // Already in table order: `PortsReceived` / `PortsSortBy` sort it.
        for (i, p) in state.ports.iter().enumerate() {
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
            let pid_text = p.pid.map_or_else(|| "—".to_string(), |pid| pid.to_string());
            let line = row![
                text(p.proto.clone()).size(fs).color(theme::TEXT_SECONDARY).width(Length::Fixed(56.0)),
                text(p.local_addr.clone())
                    .size(fs)
                    .color(theme::TEXT_SECONDARY)
                    .width(Length::FillPortion(2))
                    .wrapping(iced::widget::text::Wrapping::None),
                text(p.port.to_string())
                    .size(fs)
                    .color(c_primary)
                    .width(Length::Fixed(64.0))
                    .align_x(num),
                text(pid_text)
                    .size(fs)
                    .color(theme::TEXT_SECONDARY)
                    .width(Length::Fixed(64.0))
                    .align_x(num),
                text(truncate_str(&p.process, 40))
                    .size(fs)
                    .color(c_primary)
                    .width(Length::FillPortion(3))
                    .wrapping(iced::widget::text::Wrapping::None),
            ]
            .spacing(space::XS);
            let cell = container(line)
                .padding(Padding::from([2, 4]))
                .width(Fill)
                .style(move |_| container::Style {
                    background: Some(row_bg.into()),
                    ..Default::default()
                });
            // Without a pid (an unprivileged login cannot see other users'
            // sockets' owners) there is nothing to drill into.
            list = list.push(match p.pid {
                Some(pid) => Element::from(
                    button(cell)
                        .on_press(Message::InspectProcess(pid))
                        .padding(0)
                        .width(Fill)
                        .style(transparent_button_style),
                ),
                None => Element::from(cell),
            });
        }
    }

    column![header, columns, slim_scroll(list).height(Fill)]
        .spacing(space::XS)
        .padding(Padding::from([4, 8]))
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
    let cmd_input = input("Enter command...", &state.quick_cmd_input)
        .id(text_input::Id::new(QUICK_CMD_INPUT_ID))
        .on_input(Message::QuickCmdInputChanged)
        .on_submit(Message::SendQuickCmd)
        .padding(6)
        .size(12.0 * scale);

    let send_btn = button(
        text(i18n::t("btn.send")).size(11.0 * scale)
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

    let list: Element<'_, Message> = slim_scroll(col).height(Fill).into();
    let suggestions = state.quick_cmd_suggestions();
    let body: Element<'_, Message> = if suggestions.is_empty() {
        list
    } else {
        // Autocomplete dropdown, floating over the list under the input. The
        // top entry is what Tab / Down accept; any entry can be clicked.
        let mut drop = column![].spacing(0);
        for (i, suggestion) in suggestions.into_iter().enumerate() {
            let top = i == 0;
            drop = drop.push(
                button(
                    text(truncate_str(&suggestion, 120))
                        .font(Font::MONOSPACE)
                        .color(c_primary)
                        .size(11.0 * scale)
                        .wrapping(iced::widget::text::Wrapping::None),
                )
                .on_press(Message::QuickCmdAccept(suggestion))
                .padding(Padding::from([3, 8]))
                .width(Fill)
                .style(move |_theme: &Theme, status| button::Style {
                    background: Some(
                        if top || matches!(status, button::Status::Hovered) {
                            theme::BG_HOVER
                        } else {
                            theme::BG_SECONDARY
                        }
                        .into(),
                    ),
                    ..Default::default()
                }),
            );
        }
        drop = drop.push(
            container(text(i18n::t("quickcmd.accept_hint")).color(theme::TEXT_MUTED).size(9.5 * scale))
                .padding(Padding::from([2, 8])),
        );
        let card = container(drop)
            .width(Fill)
            .max_width(640)
            .style(|_| container::Style {
                background: Some(theme::BG_SECONDARY.into()),
                border: iced::Border { color: theme::BORDER_STRONG, width: 1.0, radius: 4.0.into() },
                shadow: iced::Shadow {
                    color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
                    offset: iced::Vector::new(0.0, 4.0),
                    blur_radius: 12.0,
                },
                ..Default::default()
            });
        stack![list, container(card).padding(Padding::from([0, 6]))].into()
    };

    column![input_bar, body].into()
}

// ---- Welcome screen (no active tab) ----------------------------------------

/// Shown while no tab is open: somewhere to start, not a dead end. One
/// primary action, the ~/.ssh/config importer when it has something to add,
/// and the shortcuts worth knowing before the first session.
fn view_welcome(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let subtitle = if state.connections.is_empty() {
        i18n::t("welcome.subtitle_empty")
    } else {
        i18n::t("welcome.subtitle")
    };

    let new_btn = button(text(i18n::t("palette.act.new_conn")).size(13.0 * scale))
        .on_press(Message::ShowForm(None))
        .padding(Padding::from([8, 18]))
        .style(accent_button_style);
    let mut actions = row![new_btn].spacing(space::M).align_y(alignment::Vertical::Center);
    let pending = state.ssh_config_pending();
    if pending > 0 {
        actions = actions.push(
            button(
                text(i18n::tf("welcome.import_ssh", &[("count", &pending.to_string())]))
                    .size(13.0 * scale),
            )
            .on_press(Message::ImportAllSshConfigs)
            .padding(Padding::from([8, 18]))
            .style(outline_button_style),
        );
    }

    let m = if cfg!(target_os = "macos") { "Cmd" } else { "Ctrl" };
    let shortcuts = [
        (format!("{}+T", m), "shortcuts.desc.connect"),
        (format!("{}+K", m), "shortcuts.desc.palette"),
        (format!("{}+/", m), "shortcuts.title"),
        (format!("{}+Shift+L", m), "shortcuts.desc.lock"),
    ];
    let mut keys = column![].spacing(space::S);
    for (accel, desc) in shortcuts {
        keys = keys.push(
            row![
                container(
                    text(accel)
                        .font(Font::MONOSPACE)
                        .color(theme::TEXT_SECONDARY)
                        .size(11.0 * scale),
                )
                .width(Length::Fixed(110.0 * scale))
                .align_x(alignment::Horizontal::Right),
                text(i18n::t(desc)).color(theme::TEXT_SECONDARY).size(12.0 * scale),
            ]
            .spacing(space::M)
            .align_y(alignment::Vertical::Center),
        );
    }

    let content = column![
        text(i18n::t("welcome.title")).size(36.0 * scale).color(state.c_primary()),
        text(subtitle).size(14.0 * scale).color(theme::TEXT_SECONDARY),
        vertical_space().height(space::S),
        actions,
        vertical_space().height(space::XL),
        keys,
    ]
    .spacing(space::M)
    .align_x(alignment::Horizontal::Center);

    iced::widget::center(content)
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
                    button(text(i18n::t("update.restart")).size(11.0 * scale))
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
            .style(move |_| container::Style {
                background: Some(tint(c_success, 0.12).into()),
                border: iced::Border {
                    color: c_success,
                    width: 1.0,
                    radius: 0.0.into(),
                },
                ..Default::default()
            })
            .into(),
        )
    } else if available && progress > 0.0 && progress < 1.0 {
        // Download in progress. The accent lives in the wash and the frame;
        // the text stays in the body colour (accent is below AA as text).
        Some(
            container(
                row![text(i18n::tf("update.downloading", &[("version", &version), ("percent", &format!("{:.0}", progress * 100.0))]))
                .color(c_primary)
                .size(12.0 * scale),]
                .padding(Padding::from([6, 16])),
            )
            .width(Fill)
            .style(move |_| container::Style {
                background: Some(tint(c_accent, 0.12).into()),
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
                        .color(c_primary)
                        .size(12.0 * scale),
                    horizontal_space(),
                    button(text(i18n::t("update.download_btn")).size(11.0 * scale))
                        .on_press(Message::DownloadUpdate)
                        .padding(Padding::from([4, 14]))
                        .style(accent_button_style),
                    tip(
                        button(text("x").color(theme::TEXT_MUTED).size(11.0 * scale))
                            .on_press(Message::DismissUpdate)
                            .padding(Padding::from([4, 6]))
                            .style(transparent_button_style),
                        i18n::t("err.dismiss"),
                    ),
                ]
                .align_y(alignment::Vertical::Center)
                .padding(Padding::from([6, 16])),
            )
            .width(Fill)
            .style(move |_| container::Style {
                background: Some(tint(c_accent, 0.12).into()),
                border: iced::Border {
                    color: c_accent,
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
            theme::BG_PRIMARY
        } else {
            Color::TRANSPARENT
        };
        let text_color = if is_active { c_primary } else { theme::TEXT_MUTED };

        // Alert badge wins over connection state — a red dot tells the
        // operator "this box tripped a threshold" at a glance.
        let alerting = !tab.session_id.is_empty()
            && (state.alerts_active.contains_key(&tab.session_id)
                || tab
                    .split
                    .as_ref()
                    .map(|s| state.alerts_active.contains_key(&s.session_id))
                    .unwrap_or(false));
        let status_dot = if alerting {
            text("● ").color(state.c_danger()).size(10.0 * scale)
        } else if tab.session_id.is_empty() || title_reconnecting(&tab.title) {
            text("● ").color(theme::WARNING).size(10.0 * scale)
        } else {
            text("● ").color(c_success).size(10.0 * scale)
        };

        // Split indicator: ⊞-ish marker rendered as "[2]" (glyph-safe).
        let split_tag: Element<'_, Message> = if tab.split.is_some() {
            text("[2]")
                .font(Font::MONOSPACE)
                .color(theme::TEXT_MUTED)
                .size(9.0 * scale)
                .into()
        } else {
            Space::new(0, 0).into()
        };

        // Titles are capped so ten tabs still fit — by display width, so a
        // Chinese name gets the room of a Latin one, not twice it; the full
        // name is a hover away.
        let full_title = tab.display_title();
        let (short_title, truncated) = clip_to_width(full_title, 20);
        let title_text = text(short_title)
            .color(text_color)
            .size(13.0 * scale)
            .wrapping(iced::widget::text::Wrapping::None);
        let label: Element<'_, Message> = if truncated {
            tip(title_text, full_title)
        } else {
            title_text.into()
        };
        let close_btn = button(text("x").color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::TabClosed(i))
            .padding(Padding::from([2, 6]))
            .style(transparent_button_style);

        let tab_content = row![status_dot, label, split_tag, tip(close_btn, i18n::t("tip.close_tab"))]
            .spacing(8)
            .align_y(alignment::Vertical::Center);

        // The active tab keeps its fill under the pointer; hover only
        // previews inactive ones.
        let tab_btn = button(tab_content)
            .on_press(Message::TabSelected(i))
            .padding(Padding::from([6, 14]))
            .style(move |_theme: &Theme, status| button::Style {
                background: Some(
                    if !is_active && matches!(status, button::Status::Hovered) {
                        theme::BG_HOVER
                    } else {
                        bg_color
                    }
                    .into(),
                ),
                text_color,
                ..Default::default()
            });

        tabs_row = tabs_row.push(tab_btn);
    }

    if state.tabs.is_empty() {
        tabs_row = tabs_row.push(
            container(text(i18n::t("tab.no_tabs")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([8, 14])),
        );
    }

    tabs_row = tabs_row.push(tip(
        button(text("+").color(theme::TEXT_MUTED).size(14.0 * scale))
            .on_press(Message::ShowConnectDialog)
            .padding(Padding::from([6, 10]))
            .style(transparent_button_style),
        i18n::t("palette.act.connect"),
    ));

    let history_count = state.cmd_history.len();
    let history_label = if history_count > 0 {
        format!("H:{}", history_count)
    } else {
        "H".to_string()
    };
    let history_btn = tip(
        button(text(history_label).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::ShowHistory)
            .padding(Padding::from([6, 10]))
            .style(transparent_button_style),
        i18n::t("palette.act.history"),
    );

    // Tabs scroll sideways once they outgrow the bar (wheel or trackpad),
    // so the close buttons never run off-screen; history stays pinned.
    let strip = iced::widget::scrollable(tabs_row)
        .direction(iced::widget::scrollable::Direction::Horizontal(
            iced::widget::scrollable::Scrollbar::new()
                .width(2)
                .scroller_width(2)
                .margin(0),
        ))
        .style(slim_scrollbar_style)
        .width(Fill);

    container(row![strip, history_btn].align_y(alignment::Vertical::Center))
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

    // Grouped, filtered and in display order (see `sidebar_groups`). While a
    // search runs every group with a match is open, and folding waits.
    let groups = sidebar_groups(&state.connections, &state.search_query, &state.collapsed_groups);
    let searching = !state.search_query.trim().is_empty();

    // One toggle folds or unfolds every group: "expand all" once all are
    // folded, "collapse all" otherwise.
    let fold_all: Element<'_, Message> = if searching || groups.is_empty() {
        Space::new(0, 0).into()
    } else {
        let all_folded = groups.iter().all(|g| g.collapsed);
        let (glyph, label) = if all_folded {
            ("\u{F103}", i18n::t("sidebar.expand_all"))
        } else {
            ("\u{F102}", i18n::t("sidebar.collapse_all"))
        };
        tip(
            button(text(glyph).font(NERD_ICON_FONT).color(theme::TEXT_MUTED).size(12.0 * scale))
                .on_press(Message::SetAllGroupsCollapsed(!all_folded))
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style),
            label,
        )
    };

    let header = row![
        text(i18n::t("sidebar.connections")).color(c_primary).size(15.0 * scale),
        horizontal_space(),
        fold_all,
        tip(
            button(text("+").color(c_accent).size(18.0 * scale))
                .on_press(Message::ShowForm(None))
                .padding(Padding::from([2, 8]))
                .style(transparent_button_style),
            i18n::t("palette.act.new_conn"),
        ),
    ]
    .align_y(alignment::Vertical::Center)
    .padding(Padding::from([8, 12]));

    let search = input(&i18n::t("sidebar.search"), &state.search_query)
        .id(text_input::Id::new(SIDEBAR_SEARCH_INPUT_ID))
        .on_input(Message::SearchChanged)
        .padding(8)
        .size(13.0 * scale);

    let search_container = container(search).padding(Padding::new(8.0).top(0.0));

    let mut list_col = column![].spacing(4);

    // The row of the connection the active tab belongs to counts as selected:
    // it keeps a tint and its actions stay visible.
    let active_conn = state
        .active_tab
        .and_then(|i| state.tabs.get(i))
        .map(|t| t.connection_id.as_str());
    let selected_bg = mix(theme::BG_SECONDARY, c_accent, 0.16);

    for group in &groups {
        // The whole header row is the click target: chevron, name, count.
        // Chevrons come from the embedded Symbols Nerd Font — the CJK font
        // has no arrow glyphs, and a system fallback is not there on every
        // install. Keyboard users fold a group from the palette (Cmd+K, type
        // its name): iced 0.13 buttons cannot take focus.
        let full_name = group.label();
        let (name, cut) = clip_to_width(&full_name, cols_at_scale(24, scale));
        let chevron = if group.collapsed { "\u{F054}" } else { "\u{F078}" };
        let header_row = row![
            text(chevron).font(NERD_ICON_FONT).color(theme::TEXT_MUTED).size(9.0 * scale),
            text(name)
                .color(theme::TEXT_MUTED)
                .size(11.0 * scale)
                .wrapping(iced::widget::text::Wrapping::None),
            text(format!("({})", group.conns.len())).color(theme::TEXT_MUTED).size(11.0 * scale),
        ]
        .spacing(6)
        .align_y(alignment::Vertical::Center);
        let header_btn = button(header_row)
            .padding(Padding::new(6.0).left(12.0).right(12.0))
            .width(Fill)
            .style(transparent_button_style);
        // Search results are never hidden: the header folds nothing then.
        let header_btn = if searching {
            header_btn
        } else {
            header_btn.on_press(Message::ToggleGroupCollapsed(group.key.clone()))
        };
        list_col = list_col.push(tip_if(header_btn, cut, &full_name));

        if group.collapsed {
            continue;
        }

        for &conn in &group.conns {
            let is_connected = state.is_connected(&conn.id);
            let dot_color = if is_connected { c_success } else { theme::TEXT_MUTED };
            let status_dot = text("\u{25CF} ").color(dot_color).size(10.0 * scale);
            // Names and user@host:port are cut to the column by display
            // width — a Chinese character is two columns — so the row never
            // wraps; the full text is in a tooltip.
            let (name, name_cut) = clip_to_width(&conn.name, cols_at_scale(24, scale));
            let name_label = tip_if(
                text(name)
                    .color(c_primary)
                    .size(13.0 * scale)
                    .wrapping(iced::widget::text::Wrapping::None),
                name_cut,
                &conn.name,
            );
            let host_full = format!("{}@{}:{}", conn.username, conn.host, conn.port);
            let (host_disp, host_cut) = clip_to_width(&host_full, cols_at_scale(22, scale));
            let host_label = tip_if(
                text(host_disp).color(theme::TEXT_MUTED).size(10.5 * scale),
                host_cut,
                &host_full,
            );

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

            let edit_btn = tip(
                button(text(i18n::t("btn.edit")).color(theme::TEXT_MUTED).size(10.0 * scale))
                    .on_press(Message::ShowForm(Some(conn_id_edit)))
                    .padding(Padding::from([3, 6]))
                    .style(transparent_button_style),
                i18n::t("dialog.edit"),
            );

            let test_btn = button(text(i18n::t("conn.test")).color(c_accent).size(10.0 * scale))
                .on_press(Message::TestConnectionInList(conn_id_test))
                .padding(Padding::from([3, 6]))
                .style(transparent_button_style);

            let clone_btn = button(text(i18n::t("conn.clone")).color(theme::TEXT_MUTED).size(10.0 * scale))
                .on_press(Message::CloneConnection(conn_id_clone))
                .padding(Padding::from([3, 6]))
                .style(transparent_button_style);

            let del_btn = button(text(i18n::t("dialog.delete")).color(c_danger).size(10.0 * scale))
                .on_press(Message::DeleteConnection(conn_id_del))
                .padding(Padding::from([3, 6]))
                .style(transparent_button_style);

            // Host line is indented to sit under the name (after the
            // status dot), not flush against the sidebar edge. The test
            // badge follows the name so the hover actions never cover it.
            let info_col = column![
                row![status_dot, name_label, proxy_tag, test_badge]
                    .spacing(4).align_y(alignment::Vertical::Center),
                row![Space::with_width(Length::Fixed(16.0 * scale)), host_label],
            ].spacing(space::XS);

            // Actions only on the hovered or selected row. They float over
            // the row's right end on the row's own fill, so revealing them
            // never reflows the name. Keyboard users reach the same four
            // actions from the palette (Cmd+K, type the name): iced 0.13
            // buttons are not focus targets.
            let hovered = state.hovered_conn.as_deref() == Some(conn.id.as_str());
            let selected = active_conn == Some(conn.id.as_str());
            let row_fill = if hovered {
                Some(theme::BG_HOVER)
            } else if selected {
                Some(selected_bg)
            } else {
                None
            };

            let main_btn = button(info_col)
                .on_press(Message::ConnectTo(conn_id))
                .padding(Padding::from([7, 10]))
                .width(Fill)
                .style(move |t: &Theme, status| {
                    let mut s = sidebar_item_style(t, status);
                    if let Some(fill) = row_fill {
                        s.background = Some(fill.into());
                    }
                    s
                });

            let mut layers: Vec<Element<'_, Message>> = vec![main_btn.into()];
            // Colour tag: a 3px rail down the row's left edge.
            if let Some(rail) = parse_hex_color(&conn.color) {
                layers.push(
                    container(Space::new(Length::Fixed(3.0), Fill))
                        .height(Fill)
                        .style(move |_| container::Style {
                            background: Some(rail.into()),
                            border: iced::Border { radius: 1.5.into(), ..Default::default() },
                            ..Default::default()
                        })
                        .into(),
                );
            }
            if let Some(fill) = row_fill {
                let actions = column![
                    row![test_btn, clone_btn].spacing(space::XS),
                    row![edit_btn, del_btn].spacing(space::XS),
                ]
                .spacing(space::XXS);
                layers.push(
                    container(
                        container(actions)
                            .padding(Padding::from([0, 4]))
                            .style(move |_| container::Style {
                                background: Some(fill.into()),
                                ..Default::default()
                            }),
                    )
                    .width(Fill)
                    .height(Fill)
                    .align_x(alignment::Horizontal::Right)
                    .align_y(alignment::Vertical::Center)
                    .padding(Padding::new(0.0).right(4.0))
                    .into(),
                );
            }

            list_col = list_col.push(
                iced::widget::mouse_area(iced::widget::Stack::with_children(layers).width(Fill))
                    .on_enter(Message::SidebarHover(conn.id.clone(), true))
                    .on_exit(Message::SidebarHover(conn.id.clone(), false)),
            );
        }
    }

    if groups.is_empty() {
        list_col = list_col.push(
            container(
                text(i18n::t("sidebar.no_results"))
                    .color(theme::TEXT_MUTED)
                    .size(13.0 * scale),
            )
            .padding(Padding::from([16, 12])),
        );
    }

    let sidebar_content = column![header, search_container, slim_scroll(list_col).height(Fill)]
        .height(Fill);

    container(sidebar_content)
        .width(SIDEBAR_W)
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

    let input = input(
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
    let (case_fill, case_label) = fill_and_label(c_accent);
    let case_btn = button(
        text("Aa")
            .size(11.0 * scale)
            .color(if case_active { case_label } else { c_primary }),
    )
    .on_press(Message::ToggleTerminalSearchCase)
    .padding(Padding::from([4, 6]))
    .style(move |_, _| button::Style {
        background: Some(if case_active {
            case_fill.into()
        } else {
            theme::BG_TERTIARY.into()
        }),
        text_color: if case_active { case_label } else { c_primary },
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
            tip(case_btn, i18n::t("tip.match_case")),
            nav_btn(i18n::t("search.close"), Message::TerminalSearchClose),
        ]
        .spacing(space::S)
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

fn sys_row_sized(label_str: &str, value_str: &str, size: f32) -> Element<'static, Message> {
    let l = label_str.to_string();
    let v = value_str.to_string();
    container(
        row![
            container(text(l).color(theme::TEXT_MUTED).size(size)).width(72),
            container(text(v).color(theme::TEXT_SECONDARY).size(size))
                .width(Fill).align_x(alignment::Horizontal::Right),
        ]
        .spacing(space::S)
        .align_y(alignment::Vertical::Center)
    )
    .padding(Padding::from([4, 10]))
    .width(Fill)
    .into()
}

fn progress_bar_widget_with_color(percent: f64, user_color: Option<Color>) -> Element<'static, Message> {
    let clamped = percent.max(0.0).min(100.0);
    // When the user set a custom progress color in the theme editor, use it.
    // Otherwise keep the heat-gauge (green/orange/red) behavior.
    let bar_color = user_color.unwrap_or_else(|| {
        if clamped > 90.0 { theme::DANGER }
        else if clamped > 70.0 { theme::WARNING }
        else { theme::SUCCESS }
    });

    // Proportional fill: the bar tracks its container's width (sidebar or
    // bottom panel) instead of a hardcoded 196 px that overflowed narrow
    // layouts and underfilled wide ones. 0% renders an empty track — no
    // leftover dot.
    let filled = clamped.round() as u16;
    let track: Element<'static, Message> = if filled == 0 {
        Space::new(Fill, 4).into()
    } else {
        let empty = (100u16 - filled.min(100)).max(1);
        row![
            container(Space::new(Fill, 4))
                .width(Length::FillPortion(filled))
                .style(move |_| container::Style {
                    background: Some(bar_color.into()),
                    border: iced::Border { radius: 2.0.into(), ..Default::default() },
                    ..Default::default()
                }),
            Space::new(Length::FillPortion(empty), 4),
        ]
        .into()
    };

    container(track)
        .padding(Padding::new(2.0).left(10.0).right(10.0).bottom(5.0))
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
            // Selection + Cmd+F highlights only paint on the focused pane.
            let make_view = |grid: &Arc<parking_lot::Mutex<TerminalGrid>>,
                             bounds: &PaneBounds,
                             session_id: &str,
                             focused: bool|
             -> TerminalView {
                TerminalView {
                    grid: grid.clone(),
                    bounds: bounds.clone(),
                    selection_start: if focused { state.selection_start } else { None },
                    selection_end: if focused { state.selection_end } else { None },
                    font_size: state.theme_cfg.terminal_font_size,
                    session_id: session_id.to_string(),
                    ssh_manager: state.ssh_manager.clone(),
                    terminal_bg: state.theme_cfg.terminal_bg.to_color(),
                    terminal_fg: state.theme_cfg.terminal_fg.to_color(),
                    search_matches: if focused {
                        state.term_search_matches.clone()
                    } else {
                        Vec::new()
                    },
                    search_current: if focused
                        && state.term_search_active
                        && !state.term_search_matches.is_empty()
                    {
                        Some(state.term_search_current)
                    } else {
                        None
                    },
                }
            };

            let canvas_el: Element<'_, Message> = if let Some(sp) = &tab.split {
                let main_focused = !tab.focus_split;
                let main_view =
                    make_view(&tab.terminal, &tab.bounds, &tab.session_id, main_focused);
                let split_view =
                    make_view(&sp.terminal, &sp.bounds, &sp.session_id, tab.focus_split);

                // Panes share the area by `sp.ratio`; FillPortion keeps the
                // divider's fixed width out of the split, exactly as
                // `split_extent` assumes for the hit-test.
                let main_share = (sp.ratio.clamp(SPLIT_MIN, SPLIT_MAX) * 1000.0).round() as u16;
                let pane_len = |share: u16| Length::FillPortion(share.max(1));
                let (main_len, split_len) = (pane_len(main_share), pane_len(1000 - main_share));

                // Focused pane gets an accent edge so you always know where
                // keystrokes land. Click anywhere in a pane to focus it
                // (handled via SplitFocusToggle on the unfocused half).
                let pane = |v: TerminalView, focused: bool, len: Length| -> Element<'_, Message> {
                    let el: Element<'_, Message> =
                        canvas(v).width(Fill).height(Fill).into();
                    let (w, h) = if sp.vertical { (len, Length::Fill) } else { (Length::Fill, len) };
                    let bordered = container(el).width(w).height(h).style(
                        move |_| container::Style {
                            border: iced::Border {
                                color: if focused { c_accent } else { theme::BORDER },
                                width: 1.0,
                                radius: 0.0.into(),
                            },
                            ..Default::default()
                        },
                    );
                    if focused {
                        bordered.into()
                    } else {
                        // Unfocused pane: clicking it moves focus there.
                        iced::widget::mouse_area(bordered)
                            .on_press(Message::SplitFocusToggle)
                            .into()
                    }
                };

                // Drag handle: wide enough to hit, BORDER_STRONG so it reads
                // as structure, accent while it is being dragged.
                let dragging = state.split_drag.is_some();
                let divider: Element<'_, Message> = iced::widget::mouse_area(
                    container(Space::new(
                        if sp.vertical { Length::Fixed(SPLIT_DIVIDER) } else { Fill },
                        if sp.vertical { Fill } else { Length::Fixed(SPLIT_DIVIDER) },
                    ))
                    .style(move |_| container::Style {
                        background: Some(if dragging { c_accent } else { theme::BORDER_STRONG }.into()),
                        ..Default::default()
                    }),
                )
                .on_press(Message::SplitDividerPressed)
                .interaction(if sp.vertical {
                    mouse::Interaction::ResizingHorizontally
                } else {
                    mouse::Interaction::ResizingVertically
                })
                .into();

                if sp.vertical {
                    row![
                        pane(main_view, main_focused, main_len),
                        divider,
                        pane(split_view, tab.focus_split, split_len),
                    ]
                    .width(Fill)
                    .height(Fill)
                    .into()
                } else {
                    column![
                        pane(main_view, main_focused, main_len),
                        divider,
                        pane(split_view, tab.focus_split, split_len),
                    ]
                    .width(Fill)
                    .height(Fill)
                    .into()
                }
            } else {
                let term_view = make_view(&tab.terminal, &tab.bounds, &tab.session_id, true);
                canvas(term_view).width(Fill).height(Fill).into()
            };

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
    let path_input = input("Local path...", &state.local_path)
        .id(text_input::Id::new(LOCAL_PATH_INPUT_ID))
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
            text(format!("{} {}", i18n::t("file.send_prefix"), fname)).size(10.0 * scale)
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
            row![path_input, tip(refresh_btn, i18n::t("log.refresh"))]
                .spacing(2)
                .align_y(alignment::Vertical::Center)
                .padding(Padding::from([2, 4])),
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
        file_col = file_col.push(tip(
            button(text("..").color(c_accent).size(10.0 * scale))
                .on_press(Message::LocalFileClicked(parent_path))
                .padding(Padding::from([2, 6]))
                .width(Fill)
                .style(sidebar_item_style),
            i18n::t("tip.parent_dir"),
        ));
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

    column![header, slim_scroll(file_col).height(Fill)]
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
    // The focused pane's session, split panes included.
    let active_session = state
        .active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.focused_session().to_string());

    let sid = match &active_session {
        Some(s) => s.clone(),
        None => return Space::new(Fill, 0).into(),
    };
    // Its exec connection — SFTP runs on it too — is parked: say so, with the
    // one button that re-opens it, as the monitor panel does.
    if let Some(parked) = state.monitor_parked.get(&sid) {
        return view_monitor_parked(&sid, parked, "files.parked", scale, c_primary, c_danger);
    }

    let current_path = state
        .current_dir
        .get(&sid)
        .map(|s| s.as_str())
        .unwrap_or("~");

    let listing = state.file_entries.get(&sid);

    // Header with editable path input and upload button
    let path_value = if state.path_input.is_empty() {
        current_path.to_string()
    } else {
        state.path_input.clone()
    };

    let path_input = input("/path/to/dir", &path_value)
        .id(text_input::Id::new(REMOTE_PATH_INPUT_ID))
        .on_input(Message::PathInputChanged)
        .on_submit(Message::PathInputSubmit)
        .padding(4)
        .size(12.0 * scale);

    let upload_btn = button(text(i18n::t("filebrowser.upload")).color(c_success).size(11.0 * scale))
        .on_press(Message::UploadFile)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    // A whole local folder, through the recursive transfer.
    let upload_dir_btn = tip(
        button(text(i18n::t("filebrowser.upload_dir")).color(c_success).size(11.0 * scale))
            .on_press(Message::UploadDir)
            .padding(Padding::from([4, 8]))
            .style(transparent_button_style),
        i18n::t("tip.upload_dir"),
    );

    let remote_refresh = button(text(i18n::t("btn.refresh")).color(c_accent).size(11.0 * scale))
        .on_press(Message::RefreshRemoteFiles)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let header = container(
        row![path_input, tip(remote_refresh, i18n::t("log.refresh")), upload_btn, upload_dir_btn]
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
    // Directory the right-click menu acts in: the listing's on screen.
    let menu_dir = state.browser_dir(&sid).unwrap_or_else(|| "~".to_string());

    if let Some(listing) = listing {
        let entries = &listing.entries;
        // Build unified file entries (including ".." parent)
        let mut all_entries: Vec<&FileEntry> = Vec::new();
        // Create a static parent entry
        let parent_entry = FileEntry {
            name: "..".to_string(),
            is_dir: true,
            ..FileEntry::default()
        };
        all_entries.push(&parent_entry);
        for e in entries.iter().filter(|e| e.name != "..") {
            all_entries.push(e);
        }

        for entry in &all_entries {
            // The letter says what the row is — the kind a rename, a chmod
            // or a delete from it is checked against.
            let (icon, name_color) = if entry.name == ".." {
                ("..", theme::ACCENT)
            } else {
                match entry.kind() {
                    EntryKind::Dir => ("D", theme::ACCENT),
                    EntryKind::File => ("F", theme::TEXT_PRIMARY),
                    EntryKind::Symlink => ("L", theme::TEXT_PRIMARY),
                    EntryKind::Other => ("?", theme::TEXT_PRIMARY),
                }
            };

            // The name exactly: spaces at its ends or in a run, and anything
            // invisible, are marked (`visible_name`). A long one loses its
            // middle, not its end, and shows whole in a tooltip.
            let shown_name = visible_name(&entry.name);
            let (display_name, name_cut) = if entry.name == ".." {
                ("..".to_string(), false)
            } else {
                let short = truncate_middle_to_width(&shown_name, 28);
                let cut = short != shown_name;
                (format!("{} {}", icon, short), cut)
            };

            let human_size = if entry.size.is_empty() { "".to_string() } else { humanize_file_size(&entry.size) };
            let date_str = if entry.modified.is_empty() { "".to_string() } else { entry.modified.clone() };

            // Build action buttons (fixed 50px column, always present for alignment)
            // Every path from the listing this row is on (see `Listing`).
            let actions: Element<'_, Message> = if !entry.is_dir && entry.name != ".." {
                let full_path = listing.path_of(&entry.name);

                let dl_btn = tip(
                    button(text(i18n::t("btn.download")).color(c_accent).size(10.0 * scale))
                        .on_press(Message::DownloadFile(sid.clone(), full_path.clone()))
                        .padding(Padding::from([1, 3]))
                        .style(transparent_button_style),
                    i18n::t("update.download_btn"),
                );

                if crate::ssh::is_editable_file(&entry.name) {
                    let edit_btn = tip(
                        button(text(i18n::t("btn.edit")).color(c_success).size(10.0 * scale))
                            .on_press(Message::OpenEditor(sid.clone(), full_path))
                            .padding(Padding::from([1, 3]))
                            .style(transparent_button_style),
                        i18n::t("dialog.edit"),
                    );
                    row![dl_btn, edit_btn].spacing(2).into()
                } else {
                    dl_btn
                }
            } else if entry.name != ".." {
                // A folder downloads whole, through the recursive transfer.
                let full_path = listing.path_of(&entry.name);
                tip(
                    button(text(i18n::t("btn.download")).color(c_accent).size(10.0 * scale))
                        .on_press(Message::DownloadDir(sid.clone(), full_path))
                        .padding(Padding::from([1, 3]))
                        .style(transparent_button_style),
                    i18n::t("tip.download_dir"),
                )
            } else {
                Space::new(0, 0).into()
            };

            // Unified columns: Name(left,fill) | Size(right,80) | Date(center,110) | Actions(right,50)
            let name_text = tip_if(
                text(display_name).color(name_color).size(11.0 * scale),
                name_cut,
                &shown_name,
            );
            let entry_row = row![
                container(name_text).width(Fill),
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
            let row_el: Element<'_, Message> = if entry.is_dir {
                let entry_clone = (*entry).clone();
                let sid_clone = sid.clone();
                let dir_btn = button(entry_row)
                    .on_press(Message::FileClicked(sid_clone, listing.dir.clone(), entry_clone))
                    .padding(Padding::from([2, 8]))
                    .width(Fill)
                    .style(sidebar_item_style);
                if entry.name == ".." {
                    tip(dir_btn, i18n::t("tip.parent_dir"))
                } else {
                    dir_btn.into()
                }
            } else {
                container(entry_row)
                    .padding(Padding::from([2, 8]))
                    .width(Fill)
                    .into()
            };
            // Right-click: rename / permissions / delete this row.
            let menu_entry = (entry.name != "..").then(|| (*entry).clone());
            file_col = file_col.push(
                iced::widget::mouse_area(row_el)
                    .on_right_press(Message::RemoteMenuOpen(sid.clone(), menu_dir.clone(), menu_entry)),
            );
        }
    } else {
        file_col = file_col.push(
            container(text(i18n::t("filebrowser.loading")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([8, 10])),
        );
    }

    // A right-click on the list outside any row still offers "New folder".
    let list = iced::widget::mouse_area(slim_scroll(file_col).height(Fill))
        .on_right_press(Message::RemoteMenuOpen(sid.clone(), menu_dir, None));

    column![header, list]
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
        tip(
            button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
                .on_press(Message::HideConnectDialog)
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style),
            i18n::t("tip.close"),
        ),
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

            // Cut by display width, a Chinese name included, with the full
            // text in a tooltip: the row keeps to one line.
            let (name, name_cut) = clip_to_width(&conn.name, 30);
            let host_full = format!("{}@{}:{}", conn.username, conn.host, conn.port);
            let (host, host_cut) = clip_to_width(&host_full, 40);
            let info_col = column![
                tip_if(text(name).color(c_primary).size(14.0 * scale), name_cut, &conn.name),
                tip_if(
                    text(host).color(theme::TEXT_MUTED).size(11.0 * scale),
                    host_cut,
                    &host_full,
                ),
            ].spacing(2);
            let (group, group_cut) = clip_to_width(&conn.group, 14);

            // Same live-session test as the sidebar: green only while a tab
            // actually holds a session to this host.
            let dot_color = if state.is_connected(&conn.id) { c_success } else { theme::TEXT_MUTED };
            let connect_btn = button(
                row![
                    text("\u{25CF} ").color(dot_color).size(10.0 * scale),
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
                tip_if(
                    text(group).color(theme::TEXT_MUTED).size(10.0 * scale),
                    group_cut,
                    &conn.group,
                ),
                edit_btn,
                del_btn,
            ]
            .align_y(alignment::Vertical::Center)
            .spacing(4)
            .padding(Padding::from([0, 4]));

            list_col = list_col.push(entry_row);
        }
    }

    // SSH config hosts — read into state on ConnectionsLoaded (which opening
    // this dialog triggers), not here: a view runs on every redraw.
    let ssh_configs = &state.ssh_config_hosts;
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

        for config in ssh_configs.iter().cloned() {
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

    let content = column![title, slim_scroll(list_col).height(300), hint]
        .spacing(12)
        .padding(24)
        .width(480);

    iced::widget::center(modal_card(content)).into()
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

    iced::widget::center(modal_card(content)).into()
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

    let save_btn = button(text(i18n::t("editor.save")).size(13.0 * scale))
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

    // Large modal: fills the window up to 1000×700.
    iced::widget::center(
        modal_card(content)
            .width(Fill)
            .height(Fill)
            .max_width(1000)
            .max_height(700),
    )
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

    let header = row![title, horizontal_space(), add_btn, tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(4);

    // Proxy form (inline)
    if state.show_proxy_form {
        let on_accent_label = on_accent(c_accent);
        let form_title = if state.proxy_edit_id.is_some() {
            i18n::t("proxy.edit")
        } else {
            i18n::t("proxy.add")
        };
        let name_input = input(i18n::t("proxy.name"), &state.proxy_form.name)
            .on_input(Message::ProxyFormNameChanged).padding(6).size(12.0 * scale);
        let host_input = input(i18n::t("proxy.host"), &state.proxy_form.host)
            .on_input(Message::ProxyFormHostChanged).padding(6).size(12.0 * scale);
        let port_input = input(i18n::t("proxy.port"), &state.proxy_form.port)
            .on_input(Message::ProxyFormPortChanged).padding(6).size(12.0 * scale).width(80);
        let user_input = input(i18n::t("proxy.username"), &state.proxy_form.username)
            .on_input(Message::ProxyFormUsernameChanged).padding(6).size(12.0 * scale);
        let pass_input = input(i18n::t("proxy.password"), &state.proxy_form.password)
            .on_input(Message::ProxyFormPasswordChanged).padding(6).size(12.0 * scale).secure(true)
            .id(text_input::Id::new(PROXY_PASSWORD_INPUT_ID));

        let type_socks = button(
            text("SOCKS5H").color(if state.proxy_form.proxy_type == "socks5h" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("socks5h".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "socks5h" { accent_button_style } else { transparent_button_style });
        let type_http = button(
            text("HTTP").color(if state.proxy_form.proxy_type == "http" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("http".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "http" { accent_button_style } else { transparent_button_style });
        let type_bastion = button(
            text(i18n::t("proxy.type.bastion")).color(if state.proxy_form.proxy_type == "bastion" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("bastion".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "bastion" { accent_button_style } else { transparent_button_style });

        let save_btn = button(text(i18n::t("proxy.save")).size(11.0 * scale))
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
        ].spacing(space::S).padding(10).width(Fill);

        if is_bastion {
            let auth_pwd_btn = button(
                text(i18n::t("proxy.bastion.auth_password"))
                    .color(if state.proxy_form.auth_type == "password" || state.proxy_form.auth_type.is_empty() { on_accent_label } else { theme::TEXT_MUTED })
                    .size(11.0 * scale)
            ).on_press(Message::ProxyFormAuthTypeChanged("password".into())).padding(Padding::from([4, 8]))
             .style(if state.proxy_form.auth_type == "password" || state.proxy_form.auth_type.is_empty() { accent_button_style } else { transparent_button_style });
            let auth_key_btn = button(
                text(i18n::t("proxy.bastion.auth_key"))
                    .color(if state.proxy_form.auth_type == "key" { on_accent_label } else { theme::TEXT_MUTED })
                    .size(11.0 * scale)
            ).on_press(Message::ProxyFormAuthTypeChanged("key".into())).padding(Padding::from([4, 8]))
             .style(if state.proxy_form.auth_type == "key" { accent_button_style } else { transparent_button_style });

            form_content = form_content.push(row![auth_pwd_btn, auth_key_btn].spacing(4));

            if state.proxy_form.auth_type == "key" {
                let key_input = input(i18n::t("proxy.bastion.key_path"), &state.proxy_form.private_key)
                    .on_input(Message::ProxyFormPrivateKeyChanged).padding(6).size(12.0 * scale);
                let browse_btn = button(text(i18n::t("proxy.bastion.browse")).color(c_accent).size(11.0 * scale))
                    .on_press(Message::ProxyFormBrowsePrivateKey).padding(Padding::from([4, 8]))
                    .style(transparent_button_style);
                let passphrase_input = input(i18n::t("proxy.bastion.passphrase"), &state.proxy_form.passphrase)
                    .on_input(Message::ProxyFormPassphraseChanged).padding(6).size(12.0 * scale).secure(true)
                    .id(text_input::Id::new(PROXY_PASSPHRASE_INPUT_ID));
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

    let content = column![header, slim_scroll(list_col).height(Fill)]
        .spacing(space::M).padding(16).width(420);

    let card = container(content).height(Fill).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        shadow: iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.4), offset: iced::Vector::new(-4.0, 0.0), blur_radius: 16.0 },
        ..Default::default()
    });

    // Drawer: pinned to the right edge, full height, over the shared scrim.
    let overlay = row![horizontal_space(), card];
    container(overlay).width(Fill).height(Fill).into()
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

    let header = row![title, horizontal_space(), clear_btn, tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);

    let filter_input = input(i18n::t("history.filter"), &state.history_filter)
        .on_input(Message::HistoryFilterChanged)
        .padding(8)
        .size(13.0 * scale);

    let filter_lower = state.history_filter.to_lowercase();

    // Build list (newest first), filtered
    let mut list_col = column![].spacing(2);
    let mut shown = 0;
    let now = unix_now();
    for record in state.cmd_history.iter().rev() {
        if !filter_lower.is_empty() && !record.cmd.to_lowercase().contains(&filter_lower) {
            continue;
        }
        if shown >= 100 { break; }
        shown += 1;

        let ago = format_ago(now.saturating_sub(record.timestamp));

        let cmd_text = text(truncate_str(&record.cmd, 50))
            .font(Font::MONOSPACE)
            .color(c_primary)
            .size(12.0 * scale);
        // A split pane's session has no title of its own; its host does.
        let origin = if record.session_title.is_empty() { &record.host } else { &record.session_title };
        // A tab title — cut by display width, whole in a tooltip.
        let (origin_text, origin_cut) = clip_to_width(origin, 18);
        let session_text = tip_if(
            text(origin_text).color(theme::TEXT_MUTED).size(10.0 * scale),
            origin_cut,
            origin,
        );
        let ago_text = text(ago).color(theme::TEXT_MUTED).size(10.0 * scale);

        let replay_btn = button(text(">").font(Font::MONOSPACE).color(c_success).size(12.0 * scale))
            .on_press(Message::ReplayCommand(record.cmd.clone()))
            .padding(Padding::from([2, 8]))
            .style(transparent_button_style);

        let entry_row = row![
            column![cmd_text, session_text].spacing(2).width(Fill),
            ago_text,
            tip(replay_btn, i18n::t("tip.replay")),
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
        slim_scroll(list_col).height(Fill),
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

    // Slide in from right, over the shared scrim.
    let overlay = row![horizontal_space(), card];

    container(overlay).width(Fill).height(Fill).into()
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

    let header = row![title, horizontal_space(), tip(close_btn, i18n::t("tip.close"))]
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
    let scale_row = row![
        scale_label,
        horizontal_space(),
        tip(scale_down, i18n::t("tip.decrease")),
        text(scale_pct).color(c_primary).size(13.0 * scale),
        tip(scale_up, i18n::t("tip.increase")),
    ]
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
    let font_row = row![
        font_label,
        horizontal_space(),
        tip(font_down, i18n::t("tip.decrease")),
        text(font_pct).color(c_primary).size(13.0 * scale),
        tip(font_up, i18n::t("tip.increase")),
    ]
        .spacing(4)
        .align_y(alignment::Vertical::Center);

    let lock_label = text(i18n::t("settings.lock_timeout")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let lock_value = lock_timeout_label(state.lock_timeout_mins);
    let lock_down = button(text("-").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetLockTimeout(cycle_lock_timeout(state.lock_timeout_mins, false)))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let lock_up = button(text("+").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetLockTimeout(cycle_lock_timeout(state.lock_timeout_mins, true)))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let lock_row = row![
        lock_label,
        horizontal_space(),
        tip(lock_down, i18n::t("tip.decrease")),
        text(lock_value).color(c_primary).size(13.0 * scale),
        tip(lock_up, i18n::t("tip.increase")),
    ]
        .spacing(4)
        .align_y(alignment::Vertical::Center);

    let lock_now_btn = button(
        row![
            text(i18n::t("settings.lock_now")).color(theme::TEXT_SECONDARY).size(13.0 * scale),
            horizontal_space(),
            text(if cfg!(target_os = "macos") { "Cmd+Shift+L" } else { "Ctrl+Shift+L" })
                .font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(11.0 * scale),
        ]
        .align_y(alignment::Vertical::Center)
    )
    .on_press(Message::LockNow)
    .padding(Padding::from([8, 0]))
    .width(Fill)
    .style(transparent_button_style);

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
        lock_row,
        lock_now_btn,
        divider,
        appearance,
        proxy_btn,
        about_btn,
    ]
    .spacing(12)
    .padding(20)
    .width(360);

    let card = modal_card(slim_scroll(menu_content).height(Fill)).max_height(620);

    // Position near bottom-right (above status bar)
    let overlay_content = column![
        vertical_space(),
        row![horizontal_space(), container(card).padding(Padding::from([0, 16]))],
    ];

    container(overlay_content).width(Fill).height(Fill).into()
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

    // Colour-scheme presets. The names are lookup keys and proper nouns, so
    // they render verbatim; each row previews the scheme's terminal colours,
    // and a click applies it to the whole window at once.
    let mut presets = column![text(i18n::t("theme.preset")).color(theme::TEXT_SECONDARY).size(12.0 * scale)]
        .spacing(space::XS);
    for name in theme_config::preset_names() {
        let Some(preset) = theme_config::preset_by_name(name) else { continue };
        let active = preset_keeping_fonts(preset.clone(), t) == *t;
        let (bg, fg) = (preset.terminal_bg.to_color(), preset.terminal_fg.to_color());
        let mut chips = row![text("$").font(Font::MONOSPACE).color(fg).size(10.0 * scale)]
            .spacing(3)
            .align_y(alignment::Vertical::Center);
        for slot in 1..=6 {
            let c = preset.ansi[slot].to_color();
            chips = chips.push(container(Space::new(7, 7)).style(move |_| container::Style {
                background: Some(c.into()),
                border: iced::Border { radius: 1.5.into(), ..Default::default() },
                ..Default::default()
            }));
        }
        let preview = container(chips)
            .padding(Padding::from([3, 6]))
            .style(move |_| container::Style {
                background: Some(bg.into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                ..Default::default()
            });
        presets = presets.push(
            button(
                row![
                    preview,
                    text(name).color(if active { c_primary } else { theme::TEXT_SECONDARY }).size(12.0 * scale),
                    horizontal_space(),
                    text(if active { "✓" } else { "" }).color(c_accent).size(12.0 * scale),
                ]
                .spacing(space::M)
                .align_y(alignment::Vertical::Center),
            )
            .on_press(Message::ThemeApplyPreset(name.to_string()))
            .padding(Padding::from([3, 6]))
            .width(Fill)
            .style(if active { sidebar_item_style } else { transparent_button_style }),
        );
    }

    let mut swatches = column![].spacing(space::S);
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
                .spacing(space::M)
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
            let hex_input = input("#RRGGBB", &current.to_hex())
                .on_input(Message::ThemeHexChanged)
                .padding(4).size(11.0 * scale).width(90);
            let preview = container(Space::new(Fill, 24))
                .style(move |_| container::Style {
                    background: Some(current.to_color().into()),
                    border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                    ..Default::default()
                });
            let editor = column![
                row![r_lbl, r_slider].spacing(space::S).align_y(alignment::Vertical::Center),
                row![g_lbl, g_slider].spacing(space::S).align_y(alignment::Vertical::Center),
                row![b_lbl, b_slider].spacing(space::S).align_y(alignment::Vertical::Center),
                row![hex_input, horizontal_space(), preview].spacing(8),
            ].spacing(space::S).padding(8).width(Fill);
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

    // ---- v0.7.0: resource threshold alerts -------------------------------
    let a = &state.alert_cfg;
    let alerts_title = text(i18n::t("alerts.title"))
        .color(c_primary)
        .size(13.0 * scale);
    let enabled = a.enabled;
    let alerts_toggle = button(
        text(if enabled { i18n::t("alerts.on") } else { i18n::t("alerts.off") })
            .size(11.0 * scale)
            .color(if enabled { Color::WHITE } else { theme::TEXT_SECONDARY }),
    )
    .on_press(Message::AlertEnabledToggled(!enabled))
    .padding(Padding::from([3, 10]))
    .style(move |_, _| button::Style {
        background: Some(if enabled {
            theme::DANGER.into()
        } else {
            theme::BG_TERTIARY.into()
        }),
        text_color: if enabled { Color::WHITE } else { theme::TEXT_SECONDARY },
        border: iced::Border {
            radius: 4.0.into(),
            width: 1.0,
            color: theme::BORDER,
        },
        ..Default::default()
    });

    let alert_row = |label: &'static str, val: f32, msg: fn(f32) -> Message| {
        column![
            row![
                text(i18n::t(label)).color(theme::TEXT_SECONDARY).size(12.0 * scale).width(Fill),
                text(format!("{:.0}%", val)).font(Font::MONOSPACE).color(c_primary).size(11.0 * scale).width(40),
            ]
            .align_y(alignment::Vertical::Center),
            slider(50.0..=100.0f32, val, msg).step(5.0f32),
        ]
        .spacing(2)
    };

    let alerts_block = column![
        row![alerts_title, horizontal_space(), alerts_toggle]
            .align_y(alignment::Vertical::Center),
        text(i18n::t("alerts.hint")).color(theme::TEXT_MUTED).size(10.0 * scale),
        alert_row("alerts.cpu", a.cpu_pct, Message::AlertCpuChanged),
        alert_row("alerts.mem", a.mem_pct, Message::AlertMemChanged),
        alert_row("alerts.disk", a.disk_pct, Message::AlertDiskChanged),
    ]
    .spacing(8);

    column![
        section_title,
        presets,
        swatches,
        term_size_row, term_slider,
        ui_size_row, ui_slider,
        row![horizontal_space(), reset_btn],
        hr_space(),
        alerts_block,
    ]
    .spacing(8)
    .into()
}

/// Thin horizontal rule used between Settings sections.
fn hr_space() -> Element<'static, Message> {
    container(Space::new(Fill, 1))
        .width(Fill)
        .style(|_| container::Style {
            background: Some(theme::BORDER.into()),
            ..Default::default()
        })
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

    iced::widget::center(modal_card(content)).into()
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
                ("2×Click".into(), "shortcuts.desc.rename_tab"),
            ],
        ),
        (
            "shortcuts.group.split",
            vec![
                (format!("{}+D", m_key), "shortcuts.desc.split_v"),
                (format!("{}+Shift+D", m_key), "shortcuts.desc.split_h"),
                (format!("{}+]", m_key), "shortcuts.desc.split_focus"),
                (format!("{}+Shift+W", m_key), "shortcuts.desc.split_close"),
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
                (i18n::t("shortcuts.key.drag").into(),        "shortcuts.desc.mouse_select"),
                (i18n::t("shortcuts.key.shift_drag").into(),  "shortcuts.desc.shift_select"),
                (i18n::t("shortcuts.key.right_click").into(), "shortcuts.desc.right_click"),
                (i18n::t("shortcuts.key.drop").into(),        "shortcuts.desc.drop_upload"),
                ("Ctrl+C".into(),     "shortcuts.desc.sigint"),
                (format!("{}+F", m_key), "shortcuts.desc.search"),
                ("Enter".into(), "shortcuts.desc.search_next"),
                ("Esc".into(), "shortcuts.desc.search_close"),
            ],
        ),
        (
            "shortcuts.group.panels",
            vec![
                (format!("{}+K", m_key), "shortcuts.desc.palette"),
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
                (format!("{}+Shift+L", m_key), "shortcuts.desc.lock"),
                (format!("{}+Shift+Q", m_key), "shortcuts.desc.quit"),
            ],
        ),
    ];

    let title = text(i18n::t("shortcuts.title").to_string())
        .size(22).color(theme::TEXT_PRIMARY);

    let mut rows_col = column![].spacing(space::L);
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

    iced::widget::center(modal_card(content)).into()
}

// ---- Error dialog ----------------------------------------------------------

fn view_error_dialog(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title_key = error_dialog_title(state.error_title, &state.error_message);
    let title = text(i18n::t(title_key)).size(16.0 * scale).color(c_danger);

    // Full error, wrapped; no truncation
    let msg = text(state.error_message.clone()).size(13.0 * scale).color(c_primary);

    let log_btn = button(text(i18n::t("err.view_log")).color(c_accent).size(12.0 * scale))
        .on_press(Message::ShowLogViewer)
        .padding(Padding::from([6, 14]))
        .style(transparent_button_style);

    let dismiss_btn = button(text(i18n::t("err.dismiss")).size(12.0 * scale))
        .on_press(Message::DismissErrorDialog)
        .padding(Padding::from([6, 18]))
        .style(accent_button_style);

    // Text widgets cannot be selected in iced, so copying is a button.
    let copied = state.error_copied == Some(fingerprint(&state.error_message));
    let copy_btn = button(
        text(i18n::t(if copied { "err.copied" } else { "err.copy" })).size(12.0 * scale),
    )
    .on_press(Message::CopyErrorText)
    .padding(Padding::from([6, 14]))
    .style(outline_button_style);

    let content = column![
        title,
        vertical_space().height(8),
        // Shrinks to a one-line error, scrolls past 260px.
        container(slim_scroll(container(msg).padding(8).width(Fill))).max_height(260),
        vertical_space().height(8),
        row![log_btn, horizontal_space(), copy_btn, dismiss_btn]
            .spacing(space::S)
            .align_y(alignment::Vertical::Center),
    ]
    .spacing(4)
    .padding(24)
    .width(540);

    let border = c_danger;
    iced::widget::center(modal_card(content).style(move |_| modal_card_style(border))).into()
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
        title, horizontal_space(), refresh_btn, open_folder_btn, tip(close_btn, i18n::t("tip.close")),
    ].spacing(space::S).align_y(alignment::Vertical::Center);

    // Render log content as monospace text, scrollable
    let body = text(state.log_viewer_content.clone())
        .font(Font::MONOSPACE)
        .color(theme::TEXT_SECONDARY)
        .size(11.0 * scale);

    let content = column![
        header,
        path_hint,
        vertical_space().height(8),
        slim_scroll(container(body).padding(10).width(Fill)).height(Fill),
    ]
    .spacing(4)
    .padding(20)
    .width(780)
    .height(520);

    iced::widget::center(modal_card(content)).into()
}

// ---- Broadcast dialog ------------------------------------------------------

// ---- v0.7.0: Cmd+K command palette ----------------------------------------

fn view_palette(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();

    let input = input(&i18n::t("palette.placeholder"), &state.palette_query)
        .id(text_input::Id::new(PALETTE_INPUT_ID))
        .on_input(Message::PaletteQueryChanged)
        .on_submit(Message::PaletteExecute)
        .padding(Padding::from([10, 14]))
        .size(15.0 * scale);

    // Selected row: AA-safe accent fill and the label colour that reads on it.
    let (sel_fill, sel_label) = fill_and_label(c_accent);
    let items = state.palette_items();
    let mut list = column![].spacing(2);
    if items.is_empty() {
        list = list.push(
            container(
                text(i18n::t("palette.empty"))
                    .color(theme::TEXT_MUTED)
                    .size(12.0 * scale),
            )
            .padding(Padding::from([10, 14])),
        );
    }
    for (i, item) in items.iter().enumerate() {
        let selected = i == state.palette_selected;
        let kind_chip = container(
            text(i18n::t(item.kind))
                .size(9.0 * scale)
                .color(if selected { sel_label } else { theme::TEXT_MUTED }),
        )
        .padding(Padding::from([2, 6]))
        .style(move |_| container::Style {
            background: Some(if selected {
                tint(sel_label, 0.18).into()
            } else {
                theme::BG_TERTIARY.into()
            }),
            border: iced::Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        });

        // Cut by display width — a Chinese name is twice as wide as its
        // character count — to budgets that follow the UI font size, with
        // the full text a hover away.
        let ((label_text, label_cut), (meta_text, meta_cut)) =
            palette_row_text(&item.label, &item.meta, scale);
        let label = tip_if(
            text(label_text)
                .size(13.0 * scale)
                .color(if selected { sel_label } else { c_primary })
                .wrapping(iced::widget::text::Wrapping::None),
            label_cut,
            &item.label,
        );
        let meta = tip_if(
            text(meta_text)
                .size(11.0 * scale)
                .color(if selected {
                    tint(sel_label, 0.85)
                } else {
                    theme::TEXT_MUTED
                })
                .wrapping(iced::widget::text::Wrapping::None),
            meta_cut,
            &item.meta,
        );

        let row_el = row![kind_chip, label, horizontal_space(), meta]
            .spacing(space::M)
            .align_y(alignment::Vertical::Center);

        list = list.push(
            button(row_el)
                .on_press(Message::PaletteExecuteIndex(i))
                .padding(Padding::from([8, 12]))
                .width(Fill)
                .style(move |_, _| button::Style {
                    background: Some(if selected {
                        sel_fill.into()
                    } else {
                        Color::TRANSPARENT.into()
                    }),
                    text_color: if selected { sel_label } else { c_primary },
                    border: iced::Border {
                        radius: 6.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
        );
    }

    let hint = text(i18n::t("palette.hint"))
        .size(10.0 * scale)
        .color(theme::TEXT_MUTED);

    let card = modal_card(column![input, list, hint].spacing(space::M).width(560)).padding(16);

    // Pin the card to the upper third — palettes feel wrong centered.
    container(
        column![Space::with_height(Length::Fixed(90.0)), card]
            .align_x(alignment::Horizontal::Center)
            .width(Fill),
    )
    .width(Fill)
    .height(Fill)
    .into()
}

// ---- v0.7.0: tab rename dialog ---------------------------------------------

fn view_tab_rename(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();

    let input = input(&i18n::t("tabrename.placeholder"), &state.tab_rename_input)
        .id(text_input::Id::new(TAB_RENAME_INPUT_ID))
        .on_input(Message::TabRenameInput)
        .on_submit(Message::TabRenameCommit)
        .padding(Padding::from([8, 10]))
        .size(14.0 * scale);

    let buttons = row![
        button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
            .on_press(Message::TabRenameCancel)
            .padding(Padding::from([6, 16]))
            .style(transparent_button_style),
        horizontal_space(),
        button(text(i18n::t("tabrename.save")).size(12.0 * scale))
            .on_press(Message::TabRenameCommit)
            .padding(Padding::from([6, 16]))
            .style(accent_button_style),
    ]
    .align_y(alignment::Vertical::Center);

    let card = modal_card(
        column![
            text(i18n::t("tabrename.title")).size(15.0 * scale).color(c_primary),
            text(i18n::t("tabrename.hint")).size(11.0 * scale).color(theme::TEXT_MUTED),
            input,
            buttons,
        ]
        .spacing(12)
        .width(380),
    )
    .padding(20);

    iced::widget::center(card).into()
}

// ---- v0.7.0: SSH key manager ------------------------------------------------

fn view_key_manager(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_success = state.c_success();
    let c_danger = state.c_danger();

    let title_bar = row![
        text(i18n::t("keys.title")).size(17.0 * scale).color(c_primary),
        horizontal_space(),
        tip(
            button(text("×").size(16.0 * scale).color(theme::TEXT_SECONDARY))
                .on_press(Message::HideKeyManager)
                .padding(Padding::from([2, 10]))
                .style(transparent_button_style),
            i18n::t("tip.close"),
        ),
    ]
    .align_y(alignment::Vertical::Center);

    // ---- key list ----
    let mut key_list = column![].spacing(8);
    if state.local_keys.is_empty() {
        key_list = key_list.push(
            text(i18n::t("keys.empty"))
                .color(theme::TEXT_MUTED)
                .size(12.0 * scale),
        );
    }
    for k in &state.local_keys {
        let path_copy = k.path.clone();
        let path_deploy = k.path.clone();
        let pubkey_short: String = {
            // type + first 16 … last 8 of base64 + comment
            let mut parts = k.pubkey.split_whitespace();
            let _ty = parts.next().unwrap_or("");
            let b64 = parts.next().unwrap_or("");
            // Char-based: `pubkey` is the raw line from ~/.ssh/*.pub, which is
            // never charset-validated, so a byte slice can split a multi-byte char.
            let b64_chars: Vec<char> = b64.chars().collect();
            if b64_chars.len() > 28 {
                let head: String = b64_chars[..16].iter().collect();
                let tail: String = b64_chars[b64_chars.len() - 8..].iter().collect();
                format!("{}…{}", head, tail)
            } else {
                b64.to_string()
            }
        };

        let mut card_col = column![
            row![
                text(k.name.clone()).size(13.0 * scale).color(c_primary),
                container(
                    text(k.key_type.clone()).size(9.0 * scale).color(c_accent)
                )
                .padding(Padding::from([1, 6]))
                .style(|_| container::Style {
                    background: Some(theme::BG_TERTIARY.into()),
                    border: iced::Border { radius: 4.0.into(), ..Default::default() },
                    ..Default::default()
                }),
                horizontal_space(),
                button(text(i18n::t("keys.copy")).size(10.0 * scale).color(c_accent))
                    .on_press(Message::KeyCopyPubkey(path_copy))
                    .padding(Padding::from([3, 8]))
                    .style(transparent_button_style),
                button(text(i18n::t("keys.deploy")).size(10.0 * scale).color(c_success))
                    .on_press(Message::KeyDeployStart(path_deploy))
                    .padding(Padding::from([3, 8]))
                    .style(transparent_button_style),
            ]
            .spacing(8)
            .align_y(alignment::Vertical::Center),
            text(format!("{}  {}", pubkey_short, k.comment))
                .size(10.0 * scale)
                .font(Font::MONOSPACE)
                .color(theme::TEXT_MUTED),
        ]
        .spacing(4);

        // Inline connection picker when this key is in deploy mode.
        if state.key_deploying.as_deref() == Some(k.path.as_str()) {
            let mut pick = column![
                text(i18n::t("keys.pick_target"))
                    .size(11.0 * scale)
                    .color(c_primary)
            ]
            .spacing(4);
            for c in &state.connections {
                let label = format!("{} — {}@{}:{}", c.name, c.username, c.host, c.port);
                pick = pick.push(
                    button(text(label).size(11.0 * scale).color(theme::TEXT_SECONDARY))
                        .on_press(Message::KeyDeployTo(k.path.clone(), c.id.clone()))
                        .padding(Padding::from([4, 10]))
                        .width(Fill)
                        .style(sidebar_item_style),
                );
            }
            pick = pick.push(
                button(text(i18n::t("form.cancel")).size(11.0 * scale).color(theme::TEXT_MUTED))
                    .on_press(Message::KeyDeployCancel)
                    .padding(Padding::from([4, 10]))
                    .style(transparent_button_style),
            );
            card_col = card_col.push(
                container(pick).padding(8).style(|_| container::Style {
                    background: Some(theme::BG_PRIMARY.into()),
                    border: iced::Border {
                        color: theme::BORDER,
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                }),
            );
        }

        key_list = key_list.push(
            container(card_col).padding(10).width(Fill).style(|_| container::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border {
                    color: theme::BORDER,
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..Default::default()
            }),
        );
    }

    // ---- generate form ----
    let gen_form = column![
        text(i18n::t("keys.gen_title")).size(13.0 * scale).color(c_primary),
        row![
            input(&i18n::t("keys.gen_name"), &state.key_form_name)
                .on_input(Message::KeyFormNameChanged)
                .padding(8)
                .size(12.0 * scale),
            input(&i18n::t("keys.gen_comment"), &state.key_form_comment)
                .on_input(Message::KeyFormCommentChanged)
                .padding(8)
                .size(12.0 * scale),
            button(text(i18n::t("keys.gen_btn")).size(12.0 * scale))
                .on_press(Message::KeyGenerate)
                .padding(Padding::from([8, 16]))
                .style(accent_button_style),
        ]
        .spacing(8)
        .align_y(alignment::Vertical::Center),
        text(i18n::t("keys.gen_hint")).size(10.0 * scale).color(theme::TEXT_MUTED),
    ]
    .spacing(space::S);

    // ---- status line ----
    let status: Element<'_, Message> = if let Some(s) = &state.key_deploy_status {
        let color = if s.starts_with('✗') { c_danger } else { c_success };
        text(s.clone()).size(11.0 * scale).color(color).into()
    } else {
        Space::new(0, 0).into()
    };

    let card = modal_card(
        column![
            title_bar,
            slim_scroll(key_list).height(Length::Fixed(300.0)),
            gen_form,
            status,
        ]
        .spacing(space::L)
        .width(620),
    )
    .padding(20)
    .max_height(560);

    iced::widget::center(card).into()
}

fn view_broadcast_dialog(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_success = state.c_success();

    let title = text(i18n::t("broadcast.title")).color(c_primary).size(16.0 * scale);
    let close_btn = button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideBroadcastDialog).padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);
    let hint = text(i18n::t("broadcast.hint")).color(theme::TEXT_MUTED).size(11.0 * scale);

    let cmd_input = input("echo hello", &state.broadcast_text)
        .on_input(Message::BroadcastTextChanged)
        .on_submit(Message::BroadcastSendNow)
        .padding(8).size(13.0 * scale).font(Font::MONOSPACE);

    let sessions_title = text(i18n::t("broadcast.sessions")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
    let mut sessions_col = column![].spacing(4);
    // Sessions = every main pane plus every split pane.
    let mut entries: Vec<(String, String)> = Vec::new();
    for tab in &state.tabs {
        if !tab.session_id.is_empty() {
            entries.push((tab.session_id.clone(), tab.display_title().to_string()));
        }
        if let Some(sp) = &tab.split {
            if !sp.session_id.is_empty() {
                entries.push((
                    sp.session_id.clone(),
                    i18n::tf("tab.split_suffix", &[("title", tab.display_title())]),
                ));
            }
        }
    }
    if entries.is_empty() {
        sessions_col = sessions_col.push(
            text(i18n::t("broadcast.empty")).color(theme::TEXT_MUTED).size(11.0 * scale)
        );
    } else {
        for (sid, title) in entries {
            let selected = state.broadcast_selected.contains(&sid);
            let marker = if selected { "●" } else { "○" };
            let marker_color = if selected { c_success } else { theme::TEXT_MUTED };
            let label = text(format!(" {}", title)).color(c_primary).size(12.0 * scale);
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
        text(format!("{} ({})", i18n::t("broadcast.send"), count)).size(12.0 * scale)
    )
    .on_press(Message::BroadcastSendNow)
    .padding(Padding::from([6, 16]))
    .style(accent_button_style);

    // Live sync toggle: while ON, every keystroke in the focused terminal
    // is mirrored to all ticked sessions in real time.
    let sync_on = state.sync_input_on;
    let sync_label = if sync_on {
        i18n::t("broadcast.sync_on")
    } else {
        i18n::t("broadcast.sync_off")
    };
    let sync_btn = button(
        text(sync_label)
            .size(12.0 * scale)
            .color(if sync_on { Color::WHITE } else { theme::TEXT_SECONDARY }),
    )
    .on_press(Message::ToggleSyncInput)
    .padding(Padding::from([6, 16]))
    .style(move |_, _| button::Style {
        background: Some(if sync_on {
            theme::DANGER.into()
        } else {
            theme::BG_TERTIARY.into()
        }),
        text_color: if sync_on { Color::WHITE } else { theme::TEXT_SECONDARY },
        border: iced::Border {
            radius: 6.0.into(),
            width: 1.0,
            color: theme::BORDER,
        },
        ..Default::default()
    });
    let sync_hint = text(i18n::t("broadcast.sync_hint"))
        .size(10.0 * scale)
        .color(theme::TEXT_MUTED);

    let body = column![header, hint, cmd_input, sessions_title, slim_scroll(sessions_col).height(220),
        sync_hint,
        row![sync_btn, horizontal_space(), send_btn].align_y(alignment::Vertical::Center)
    ].spacing(space::M).padding(20).width(520);

    iced::widget::center(modal_card(body)).into()
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
    let header = row![title, horizontal_space(), tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);

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
                tip(
                    button(text(i18n::t("btn.edit")).color(theme::TEXT_SECONDARY).size(10.0 * scale))
                        .on_press(Message::SnippetEdit(Some(id2)))
                        .padding(Padding::from([2, 6])).style(transparent_button_style),
                    i18n::t("dialog.edit"),
                ),
                tip(
                    button(text("×").color(c_danger).size(12.0 * scale))
                        .on_press(Message::SnippetDelete(id3))
                        .padding(Padding::from([2, 6])).style(transparent_button_style),
                    i18n::t("tip.delete"),
                ),
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
    let name_input = input(i18n::t("snippet.name_placeholder"), &state.snippet_form_name)
        .on_input(Message::SnippetFormNameChanged)
        .padding(6).size(12.0 * scale);
    let body_input = input(i18n::t("snippet.body_placeholder"), &state.snippet_form_body)
        .on_input(Message::SnippetFormBodyChanged)
        .padding(6).size(12.0 * scale).font(Font::MONOSPACE);
    let save_btn = button(text(i18n::t("snippet.save")).size(11.0 * scale))
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
        slim_scroll(list_col).height(280),
        container(Space::new(Fill, 1)).style(|_| container::Style {
            background: Some(theme::BORDER.into()), ..Default::default()
        }),
        form_title,
        name_input,
        body_input,
        row![horizontal_space(), cancel_btn, save_btn].spacing(8),
    ].spacing(space::M).padding(20).width(560);

    iced::widget::center(modal_card(body)).into()
}

// ---- Status bar ------------------------------------------------------------

fn view_status_bar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_accent = state.c_accent();
    let c_danger = state.c_danger();
    // One size for the whole bar, at the readable floor (was 9-10px).
    let fs = 10.5 * scale;

    let version = text(i18n::tf("status.version", &[("version", env!("CARGO_PKG_VERSION"))]))
        .color(theme::TEXT_MUTED).size(fs);

    let session_text = if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            text(&tab.title).color(theme::TEXT_SECONDARY).size(fs)
        } else {
            text("").size(fs)
        }
    } else {
        text(i18n::t("status.no_session")).color(theme::TEXT_MUTED).size(fs)
    };

    let counters = text(format!("{}T · {}H", state.tabs.len(), state.cmd_history.len()))
        .font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(fs);

    // SYNC badge — loud on purpose: typing while it's on reaches N boxes.
    let sync_badge: Element<'_, Message> = if state.sync_input_on {
        let n = state.broadcast_selected.len();
        button(
            text(i18n::tf("status.sync_badge", &[("n", &n.to_string())]))
                .font(Font::MONOSPACE)
                .color(Color::WHITE)
                .size(fs),
        )
        .on_press(Message::ToggleSyncInput)
        .padding(Padding::from([1, 6]))
        .style(|_, _| button::Style {
            background: Some(theme::DANGER.into()),
            text_color: Color::WHITE,
            border: iced::Border { radius: 3.0.into(), ..Default::default() },
            ..Default::default()
        })
        .into()
    } else {
        Space::new(0, 0).into()
    };

    // First active threshold alert (clicking opens nothing yet — it's a
    // status readout; the tab dot tells you which box).
    let alert_badge: Element<'_, Message> = if let Some((sid, breaches)) =
        state.alerts_active.iter().next()
    {
        let title = state
            .tabs
            .iter()
            .find_map(|t| {
                if t.session_id == *sid {
                    Some(t.display_title().to_string())
                } else if t.split.as_ref().map(|s| &s.session_id) == Some(sid) {
                    Some(i18n::tf("tab.split_suffix", &[("title", t.display_title())]))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| sid.chars().take(8).collect());
        // Keep the status bar from being elbowed out by a long user@host —
        // or a Chinese tab name, measured by display width.
        let (short, cut) = clip_to_width(&title, 18);
        let more = if state.alerts_active.len() > 1 {
            format!(" +{}", state.alerts_active.len() - 1)
        } else {
            String::new()
        };
        let badge = text(format!("⚠ {}: {}{}", short, breaches.join(" "), more))
            .color(c_danger)
            .size(fs);
        if cut {
            tip_at(badge, &title, iced::widget::tooltip::Position::Top)
        } else {
            badge.into()
        }
    } else {
        Space::new(0, 0).into()
    };

    let lang_label = if state.locale == "zh-CN" { "EN" } else { "CN" };
    let lang_btn = button(text(lang_label).font(Font::MONOSPACE).color(c_accent).size(fs))
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
    let shortcuts = text(shortcuts_str).color(theme::TEXT_MUTED).size(fs);

    let help_btn = button(text("?").font(Font::MONOSPACE).color(c_accent).size(fs))
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

    let log_btn = button(text(i18n::t("status.log")).color(c_accent).size(fs))
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

    let lock_btn = button(text(i18n::t("lock.now")).color(c_accent).size(fs))
        .on_press(Message::LockNow)
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

    let quit_btn = button(text(i18n::t("status.quit")).color(c_danger).size(fs))
        .on_press(Message::QuitApp)
        .padding(Padding::from([1, 6]))
        .style(move |_: &Theme, status| button::Style {
            background: matches!(status, button::Status::Hovered)
                .then(|| tint(c_danger, 0.15).into()),
            border: iced::Border { color: c_danger, width: 1.0, radius: 3.0.into() },
            ..Default::default()
        });

    // Quit sits alone past a hairline so it is never hit on the way to Lock.
    let quit_sep: Element<'_, Message> = container(Space::new(1, 14))
        .style(|_| container::Style { background: Some(theme::BORDER.into()), ..Default::default() })
        .into();
    let up = iced::widget::tooltip::Position::Top;

    // Active session leftmost — it is what the bar is for.
    let bar = row![
        session_text,
        sync_badge,
        alert_badge,
        horizontal_space(),
        shortcuts,
        counters,
        version,
        log_btn,
        tip_at(help_btn, i18n::t("shortcuts.title"), up),
        tip_at(lang_btn, i18n::t("settings.language"), up),
        lock_btn,
        quit_sep,
        quit_btn,
    ]
        .spacing(space::M)
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
    let header = row![title, horizontal_space(), add_btn, tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);
    let on_accent_label = on_accent(c_accent);

    let mut list_col = column![].spacing(4);

    // Inline form
    if state.show_tunnel_form {
        let form_title = if state.tunnel_edit_id.is_some() { i18n::t("tunnel.edit") } else { i18n::t("tunnel.add") };
        let name_in = input(i18n::t("tunnel.name"), &state.tunnel_form.name)
            .on_input(Message::TunnelFormNameChanged).padding(6).size(12.0 * scale);
        let host_in = input(i18n::t("tunnel.ssh_host"), &state.tunnel_form.ssh_host)
            .on_input(Message::TunnelFormHostChanged).padding(6).size(12.0 * scale);
        let port_in = input(i18n::t("tunnel.ssh_port"), &state.tunnel_form.ssh_port)
            .on_input(Message::TunnelFormPortChanged).padding(6).size(12.0 * scale).width(80);
        let user_in = input(i18n::t("tunnel.user"), &state.tunnel_form.username)
            .on_input(Message::TunnelFormUserChanged).padding(6).size(12.0 * scale);

        let auth_pwd_btn = button(text(i18n::t("proxy.bastion.auth_password"))
            .color(if state.tunnel_form.auth_type != "key" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale))
            .on_press(Message::TunnelFormAuthTypeChanged("password".into()))
            .padding(Padding::from([4, 8]))
            .style(if state.tunnel_form.auth_type != "key" { accent_button_style } else { transparent_button_style });
        let auth_key_btn = button(text(i18n::t("proxy.bastion.auth_key"))
            .color(if state.tunnel_form.auth_type == "key" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale))
            .on_press(Message::TunnelFormAuthTypeChanged("key".into()))
            .padding(Padding::from([4, 8]))
            .style(if state.tunnel_form.auth_type == "key" { accent_button_style } else { transparent_button_style });

        let secret: Element<'_, Message> = if state.tunnel_form.auth_type == "key" {
            let key_in = input(i18n::t("proxy.bastion.key_path"), &state.tunnel_form.private_key)
                .on_input(Message::TunnelFormKeyChanged).padding(6).size(12.0 * scale);
            let browse = button(text(i18n::t("proxy.bastion.browse")).color(c_accent).size(11.0 * scale))
                .on_press(Message::TunnelFormBrowseKey)
                .padding(Padding::from([4, 8])).style(transparent_button_style);
            let pass = input(i18n::t("proxy.bastion.passphrase"), &state.tunnel_form.passphrase)
                .on_input(Message::TunnelFormPassphraseChanged).padding(6).size(12.0 * scale).secure(true)
                .id(text_input::Id::new(TUNNEL_PASSPHRASE_INPUT_ID));
            column![row![key_in, browse].spacing(4), pass].spacing(space::S).into()
        } else {
            input(i18n::t("proxy.password"), &state.tunnel_form.password)
                .on_input(Message::TunnelFormPasswordChanged).padding(6).size(12.0 * scale).secure(true)
                .id(text_input::Id::new(TUNNEL_PASSWORD_INPUT_ID))
                .into()
        };

        let fwd_label = text(i18n::t("tunnel.forwards_label")).color(theme::TEXT_SECONDARY).size(11.0 * scale);
        let fwd_hint = text(i18n::t("tunnel.forwards_hint")).color(theme::TEXT_MUTED).size(10.0 * scale);
        let fwd_in = input("", &state.tunnel_form.forwards_text)
            .on_input(Message::TunnelFormForwardsChanged).padding(6).size(12.0 * scale);

        let save = button(text(i18n::t("proxy.save")).size(11.0 * scale))
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
        ].spacing(space::S).padding(10).width(Fill);

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
            .map(|f| f.spec())
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

    let content = column![header, slim_scroll(list_col).height(Fill)]
        .spacing(space::M).padding(16).width(480);

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

    let title = text(title_text).size(16.5 * scale).color(c_primary);
    let on_accent_label = on_accent(c_accent);

    let name_input = labeled_input(&i18n::t("form.name"), &state.form.name, Message::FormNameChanged);
    let host_input = labeled_input(&i18n::t("form.host"), &state.form.host, Message::FormHostChanged);
    let port_input = labeled_input(&i18n::t("form.port"), &state.form.port, Message::FormPortChanged);
    let user_input = labeled_input(
        &i18n::t("form.username"),
        &state.form.username,
        Message::FormUsernameChanged,
    );

    // One segment per `auth_type` the SSH layer accepts.
    let auth_choice = |value: &'static str, label: &'static str| {
        let on = state.form.auth_type == value;
        button(
            text(label)
                .color(if on { on_accent_label } else { theme::TEXT_MUTED })
                .size(13.0 * scale),
        )
        .on_press(Message::FormAuthTypeChanged(value.into()))
        .padding(Padding::from([6, 12]))
        .style(if on { accent_button_style } else { transparent_button_style })
    };
    let auth_row = row![
        auth_choice("password", i18n::t("form.password")),
        auth_choice("key", i18n::t("form.private_key")),
        auth_choice("interactive", i18n::t("form.auth_interactive")),
        auth_choice("agent", i18n::t("form.auth_agent")),
    ]
    .spacing(8);

    let auth_label = text(i18n::t("form.auth_type")).color(theme::TEXT_SECONDARY).size(12.0 * scale);

    // Placeholder hint for secret fields during edit (empty = keep existing)
    let is_editing = state.edit_id.is_some();
    let secret_placeholder = if is_editing { i18n::t("form.keep_existing") } else { "" };

    let auth_fields: Element<'_, Message> = if state.form.auth_type == "key" {
        let key_label = text(i18n::t("form.key_path")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let key_input = input(secret_placeholder, &state.form.private_key)
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
        let pass_input = input(secret_placeholder, &state.form.passphrase)
            .on_input(Message::FormPassphraseChanged)
            .secure(true)
            .id(text_input::Id::new(CONN_PASSPHRASE_INPUT_ID))
            .padding(8)
            .size(14.0 * scale);

        column![key_field, column![pass_label, pass_input].spacing(4)]
            .spacing(12)
            .into()
    } else if state.form.auth_type == "agent" {
        // Nothing to store: the keys stay in the agent.
        text(i18n::t("form.agent_hint")).color(theme::TEXT_MUTED).size(12.0 * scale).into()
    } else {
        let interactive = state.form.auth_type == "interactive";
        let pw_label = text(i18n::t(if interactive { "form.password_optional" } else { "form.password" }))
            .color(theme::TEXT_SECONDARY)
            .size(12.0 * scale);
        let pw_input = input(secret_placeholder, &state.form.password)
            .on_input(Message::FormPasswordChanged)
            .secure(true)
            .id(text_input::Id::new(CONN_PASSWORD_INPUT_ID))
            .padding(8)
            .size(14.0 * scale);
        let mut fields = column![pw_label, pw_input].spacing(4);
        if interactive {
            fields = fields.push(
                text(i18n::t("form.interactive_hint")).color(theme::TEXT_MUTED).size(11.0 * scale),
            );
        }
        fields.into()
    };

    let group_input: Element<'_, Message> = {
        let label_text = text(i18n::t("form.group")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let input = input("", &state.form.group)
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
                .color(if state.form.proxy_id.is_empty() { on_accent_label } else { theme::TEXT_MUTED })
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
            button(text(label).color(if is_sel { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale))
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
        // Char-based on purpose: translate_ssh_error appends a translated hint,
        // so error_message routinely mixes ASCII with CJK. A byte slice here
        // splits a multi-byte char and, under panic = "abort", kills the app.
        let short = truncate_str(&state.error_message, 57);
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
        button(text(i18n::t("form.save")).size(14.0 * scale))
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
        slim_scroll(form_content).height(Fill),
        test_row,
        error_row,
        buttons,
    ]
    .spacing(8)
    .width(440)
    .padding(24);

    iced::widget::center(modal_card(form).max_height(780)).into()
}

/// Helper: a labeled text input field.
fn labeled_input<'a>(
    label: &'a str,
    value: &'a str,
    on_change: impl Fn(String) -> Message + 'a,
) -> Element<'a, Message> {
    let label_text = text(label).color(theme::TEXT_SECONDARY).size(12);
    let input = input("", value).on_input(on_change).padding(8).size(14);
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
    /// The theme's terminal background and foreground: what a cell left at
    /// the grid's default colours paints in (see `cell_paint`).
    terminal_bg: Color,
    terminal_fg: Color,
    /// All Cmd+F matches in absolute-line coords; painted as yellow/orange
    /// rectangles on top of the cell background.
    search_matches: Vec<crate::terminal::SearchMatch>,
    /// Index into `search_matches` for the currently selected match; painted
    /// in a brighter color than the rest.
    search_current: Option<usize>,
    /// The pane's [`PaneBounds`]: `draw` records where it was laid out.
    bounds: PaneBounds,
}

/// Persistent state for the terminal canvas. Created once by iced and reused
/// across frames. The `cache` uses interior mutability so `clear()` / `draw()`
/// work through `&self`. `last_generation` is an `AtomicU64` so we can
/// compare-and-store without `&mut`.
struct TerminalViewState {
    cache: canvas::Cache,
    last_generation: AtomicU64,
    /// `theme_colors_key` of the colours the cached geometry was painted
    /// with. A theme edit changes them without touching the grid, so the
    /// generation alone would keep the old colours on screen until the next
    /// byte of output.
    last_colors: AtomicU64,
}

impl Default for TerminalViewState {
    fn default() -> Self {
        Self {
            cache: canvas::Cache::new(),
            last_generation: AtomicU64::new(0),
            last_colors: AtomicU64::new(0),
        }
    }
}

/// The terminal's theme colours as one comparable word.
fn theme_colors_key(bg: Color, fg: Color) -> u64 {
    let [r0, g0, b0, a0] = bg.into_rgba8();
    let [r1, g1, b1, a1] = fg.into_rgba8();
    u64::from_be_bytes([r0, g0, b0, a0, r1, g1, b1, a1])
}

/// A blank cell (space or NUL) on the default background, not inverted. It
/// paints nothing the canvas's terminal_bg fill has not already painted.
#[inline]
fn is_blank_cell(cell: &crate::terminal::Cell) -> bool {
    (cell.c == ' ' || cell.c == '\0')
        && crate::terminal::is_default_bg(cell.style.bg)
        && !cell.style.inverse
}

/// Check whether a row consists entirely of blank cells. Such rows need no
/// rendering at all.
#[inline]
fn is_row_empty(row: &[crate::terminal::Cell]) -> bool {
    row.iter().all(is_blank_cell)
}

/// What one cell paints: a background fill (`None` leaves the canvas's
/// terminal_bg showing) and the glyph colour.
///
/// The grid's `DEFAULT_FG` / `DEFAULT_BG` are sentinels meaning "the theme's
/// colour", never colours to paint as they are. Testing the background
/// against a chrome token (`theme::BG_PRIMARY`) instead put a #1A1B2E block
/// under every default-background glyph as soon as the chrome moved off that
/// value, whatever the terminal background was, and default text ignored the
/// theme's foreground altogether.
fn cell_paint(
    style: &crate::terminal::CellStyle,
    terminal_fg: Color,
    terminal_bg: Color,
) -> (Option<Color>, Color) {
    let fg = if crate::terminal::is_default_fg(style.fg) {
        terminal_fg
    } else {
        cell_color_to_iced(style.fg)
    };
    let bg = (!crate::terminal::is_default_bg(style.bg)).then(|| cell_color_to_iced(style.bg));
    if style.inverse {
        // Reverse video swaps the resolved colours: the cell is filled with
        // the foreground, and the glyph takes the background.
        (Some(fg), bg.unwrap_or(terminal_bg))
    } else {
        (bg, fg)
    }
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
        // Absolute layout bounds (iced's canvas passes `layout.bounds()`):
        // the pointer hit-test measures from here.
        self.bounds.record(bounds);
        let grid = self.grid.lock();
        let current_gen = grid.generation;

        // Invalidate the geometry cache when the terminal content changes.
        let last_gen = state.last_generation.load(Ordering::Relaxed);
        if current_gen != last_gen {
            state.cache.clear();
            state.last_generation.store(current_gen, Ordering::Relaxed);
        }
        // ...or when the theme's terminal colours do.
        let colors = theme_colors_key(self.terminal_bg, self.terminal_fg);
        if state.last_colors.swap(colors, Ordering::Relaxed) != colors {
            state.cache.clear();
        }

        // Resize terminal grid to fit canvas bounds.
        // cell_h was 1.5x font_size — too loose, top/htop output looked
        // double-spaced. 1.2x matches iTerm2/Windows Terminal defaults.
        // Defensive: theme.json is user-editable and ThemeConfig feeds this
        // directly. A 0.0 / NaN size makes cell_w 0.0, `bounds.width / 0.0` is
        // inf, and `as usize` saturates to usize::MAX — which resize() would
        // then try to allocate.
        let font_size: f32 = if self.font_size.is_finite() {
            self.font_size.clamp(8.0, 28.0)
        } else {
            14.0
        };
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
        let fg_color = self.terminal_fg;
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
                    if is_blank_cell(cell) {
                        // Flush any pending ASCII run before the gap
                        flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
                        x += char_cols;
                        continue;
                    }

                    let (bg, fg) = cell_paint(&cell.style, fg_color, bg_color);

                    // Draw background if non-default (cheap GPU op, always per-cell)
                    if let Some(bg) = bg {
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

    // Must match the renderer's cell metrics (TerminalView::draw) exactly, or a
    // click resolves to the wrong row — the drift grows towards the bottom of
    // the screen. Same defensive clamp as the renderer.
    let font_size = if font_size.is_finite() {
        font_size.clamp(8.0, 28.0)
    } else {
        14.0
    };
    let cell_w = font_size * 0.6;
    let cell_h = font_size * 1.2;

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
                            // pos + 2 (end of "->") is always a char boundary and
                            // always <= len; pos + 3 is neither when the target
                            // starts with a multi-byte char or the line ends here.
                            // trim() still drops the separating space.
                            open_fds.push(l[pos + 2..].trim().to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    ProcessDetailInfo {
        pid,
        fields,
        children,
        threads,
        net_conns,
        listen_ports,
        open_fds,
        session_id: String::new(),
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

/// `s` fitted to `cols` display columns — a CJK character takes two, see
/// `terminal::truncate_to_width` — and whether that cut anything. A cut label
/// carries its full text in a tooltip ([`tip_if`]).
fn clip_to_width(s: &str, cols: usize) -> (String, bool) {
    let short = crate::terminal::truncate_to_width(s, cols);
    let cut = short != s;
    (short, cut)
}

/// A column budget meant for the default UI font size, at `scale`: text in
/// the fixed-width sidebar grows with the font, the sidebar does not.
fn cols_at_scale(cols: usize, scale: f32) -> usize {
    ((cols as f32 / scale.max(0.5)).floor() as usize).max(6)
}

/// `s` cut to at most `max_cols` display columns by taking out its middle:
/// the head and the tail stay, joined by "…". For a file name that keeps the
/// extension, and any mark [`visible_name`] put at its end.
fn truncate_middle_to_width(s: &str, max_cols: usize) -> String {
    use crate::terminal::display_width;
    if display_width(s) <= max_cols {
        return s.to_string();
    }
    let Some(budget) = max_cols.checked_sub(1) else {
        return String::new();
    };
    let cols = |c: char| display_width(c.encode_utf8(&mut [0u8; 4]));
    let chars: Vec<char> = s.chars().collect();
    let tail_budget = budget / 2;
    let head_budget = budget - tail_budget;
    let (mut tail_start, mut used) = (chars.len(), 0);
    while tail_start > 0 && used + cols(chars[tail_start - 1]) <= tail_budget {
        used += cols(chars[tail_start - 1]);
        tail_start -= 1;
    }
    // A combining mark whose base was left out goes with it.
    while tail_start < chars.len() && cols(chars[tail_start]) == 0 {
        tail_start += 1;
    }
    let (mut head_end, mut used) = (0, 0);
    while head_end < tail_start && used + cols(chars[head_end]) <= head_budget {
        used += cols(chars[head_end]);
        head_end += 1;
    }
    let mut out: String = chars[..head_end].iter().collect();
    out.push('…');
    out.extend(&chars[tail_start..]);
    out
}

/// A remote name as the file browser and its confirmations show it: exactly,
/// with what would not show made visible. A space at either end, or next to
/// another space, reads "·" — a co-tenant's "project " beside a user's
/// "project" used to look the same — and any other whitespace, control or
/// invisible formatting character (zero-width, bidi override, BOM, soft
/// hyphen) is written as its `\u{…}` escape. A name holding none of these
/// comes back unchanged.
fn visible_name(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == ' ' {
            let edge = i == 0 || i + 1 == chars.len();
            let run = (i > 0 && chars[i - 1] == ' ') || chars.get(i + 1) == Some(&' ');
            out.push(if edge || run { '·' } else { ' ' });
        } else {
            push_visible(&mut out, c, i.checked_sub(1).map(|p| chars[p]));
        }
    }
    out
}

/// A remote path with each component shown as [`visible_name`] shows it.
fn visible_path(path: &str) -> String {
    path.split('/').map(visible_name).collect::<Vec<_>>().join("/")
}

/// `s` with every character that would not show written as its escape, as
/// [`visible_name`] does, but spaces left alone: for a command line.
fn visible_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev = None;
    for c in s.chars() {
        push_visible(&mut out, c, prev);
        prev = Some(c);
    }
    out
}

/// Push `c` onto `out`, or its `\u{…}` escape if it would not show. A
/// variation selector is kept after anything but ASCII — emoji use them — and
/// escaped after ASCII, where it changes nothing on screen.
fn push_visible(out: &mut String, c: char, prev: Option<char>) {
    let selector = matches!(c, '\u{FE00}'..='\u{FE0F}');
    let hidden = c.is_control()
        || (c.is_whitespace() && c != ' ')
        || (selector && prev.is_none_or(|p| p.is_ascii()))
        || matches!(
            c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}'
                | '\u{17B5}' | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}' | '\u{3164}' | '\u{FEFF}' | '\u{FFA0}'
        );
    if hidden {
        out.extend(c.escape_unicode());
    } else {
        out.push(c);
    }
}

/// "folder", "file", … for the confirmations that state what they touch.
fn entry_kind_label(kind: EntryKind) -> &'static str {
    i18n::t(match kind {
        EntryKind::File => "sftp.kind.file",
        EntryKind::Dir => "sftp.kind.dir",
        EntryKind::Symlink => "sftp.kind.symlink",
        EntryKind::Other => "sftp.kind.other",
    })
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


/// macOS-style slim scrollbar: no track, 4 px rounded thumb that
/// brightens on hover / drag.
fn slim_scrollbar_style(
    _theme: &Theme,
    status: iced::widget::scrollable::Status,
) -> iced::widget::scrollable::Style {
    use iced::widget::scrollable::{Rail, Scroller, Style};
    let engaged = matches!(
        status,
        iced::widget::scrollable::Status::Hovered { .. }
            | iced::widget::scrollable::Status::Dragged { .. }
    );
    let thumb = if engaged {
        Color::from_rgba(1.0, 1.0, 1.0, 0.35)
    } else {
        Color::from_rgba(1.0, 1.0, 1.0, 0.16)
    };
    let rail = Rail {
        background: None,
        border: iced::Border::default(),
        scroller: Scroller {
            color: thumb,
            border: iced::Border {
                radius: 99.0.into(),
                ..Default::default()
            },
        },
    };
    Style {
        container: container::Style::default(),
        vertical_rail: rail,
        horizontal_rail: rail,
        gap: None,
    }
}

/// Vertical scrollable with the slim scrollbar (4 px thumb, 2 px margin).
fn slim_scroll<'a>(
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::Scrollable<'a, Message> {
    iced::widget::scrollable(content)
        .direction(iced::widget::scrollable::Direction::Vertical(
            iced::widget::scrollable::Scrollbar::new()
                .width(4)
                .scroller_width(4)
                .margin(2),
        ))
        .style(slim_scrollbar_style)
}

/// Input field with rounded corners + accent focus ring (macOS-like).
/// Accent and text follow the live theme, like the other shared styles.
fn input_style(
    _theme: &Theme,
    status: iced::widget::text_input::Status,
) -> iced::widget::text_input::Style {
    let focused = matches!(status, iced::widget::text_input::Status::Focused);
    let live = theme_config::live();
    let accent = live.accent.to_color();
    iced::widget::text_input::Style {
        background: theme::BG_PRIMARY.into(),
        border: iced::Border {
            radius: 8.0.into(),
            width: 1.0,
            color: if focused { accent } else { theme::BORDER },
        },
        icon: theme::TEXT_MUTED,
        placeholder: theme::TEXT_MUTED,
        value: live.text_primary.to_color(),
        selection: tint(accent, 0.35),
    }
}

/// text_input constructor with the shared style pre-applied.
fn input<'a>(placeholder: &str, value: &str) -> iced::widget::TextInput<'a, Message> {
    iced::widget::text_input(placeholder, value).style(input_style)
}

/// `color` at `alpha` opacity — washes and hover fills derived from a theme
/// token, so they follow the user's palette instead of a baked-in RGB.
fn tint(color: Color, alpha: f32) -> Color {
    Color { a: alpha.clamp(0.0, 1.0), ..color }
}

/// Linear blend from `a` toward `b`. `t` is clamped, so unlike scaling the
/// channels the result can never leave the gamut.
fn mix(a: Color, b: Color, t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    Color {
        r: a.r + (b.r - a.r) * t,
        g: a.g + (b.g - a.g) * t,
        b: a.b + (b.b - a.b) * t,
        a: a.a + (b.a - a.a) * t,
    }
}

/// WCAG 2.1 relative luminance.
fn rel_luminance(c: Color) -> f32 {
    let lin = |v: f32| {
        if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b)
}

/// WCAG contrast ratio between two opaque colours; always >= 1.
fn contrast_ratio(a: Color, b: Color) -> f32 {
    let (la, lb) = (rel_luminance(a), rel_luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// How far toward white a filled button moves on hover.
const HOVER_LIFT: f32 = 0.10;

/// Fill and label colour for a solid button in `base`, chosen so the label
/// clears WCAG AA (4.5:1) on the resting fill *and* on the hover fill, for
/// whatever colour the user's theme puts there.
///
/// Mid and dark colours keep white text and are darkened only as far as that
/// needs: the shipped accent #6366F1 measures 3.62:1 under TEXT_PRIMARY and
/// 4.47:1 under white, so it moves 15% toward black. Light colours (Nord
/// frost, Gruvbox yellow, Dracula purple) would turn muddy long before white
/// reads on them, so they keep their own colour and take dark text instead.
fn fill_and_label(base: Color) -> (Color, Color) {
    const AA: f32 = 4.5;
    let base = Color { a: 1.0, ..base };
    let white_reads = |fill: Color| {
        contrast_ratio(Color::WHITE, fill) >= AA
            && contrast_ratio(Color::WHITE, mix(fill, Color::WHITE, HOVER_LIFT)) >= AA
    };
    let darkened = |step: u8| mix(base, Color::BLACK, f32::from(step) * 0.05);
    if let Some(fill) = (0..=6).map(darkened).find(|&f| white_reads(f)) {
        return (fill, Color::WHITE);
    }
    // Hover only lightens, which can only raise dark-on-fill contrast.
    if contrast_ratio(theme::BG_PRIMARY, base) >= AA {
        return (base, theme::BG_PRIMARY);
    }
    // Reads under neither label at its own lightness: keep darkening. Pure
    // black (step 20) passes, so the search always ends inside the range.
    let fill = (7..=20).map(darkened).find(|&f| white_reads(f)).unwrap_or(Color::BLACK);
    (fill, Color::WHITE)
}

/// Solid button in `base` with an AA-safe label (see [`fill_and_label`]).
/// Labels inside must not set their own colour — they inherit `text_color`.
fn filled_button_style(base: Color) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_theme, status| {
        let (fill, label) = fill_and_label(base);
        let background = match status {
            button::Status::Hovered => mix(fill, Color::WHITE, HOVER_LIFT),
            _ => fill,
        };
        button::Style {
            background: Some(background.into()),
            text_color: label,
            border: iced::Border {
                radius: 8.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

/// Primary button in the live accent.
fn accent_button_style(theme: &Theme, status: button::Status) -> button::Style {
    filled_button_style(theme_config::live().accent.to_color())(theme, status)
}

/// Label colour for text that sits on an accent fill but is coloured by the
/// caller — segmented toggles, the palette's selected row.
fn on_accent(accent: Color) -> Color {
    fill_and_label(accent).1
}

fn transparent_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Some(theme::BG_HOVER.into()),
        _ => None,
    };
    button::Style {
        background: bg,
        text_color: theme_config::live().text_primary.to_color(),
        border: iced::Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Secondary action next to a filled primary: hairline outline, no fill.
fn outline_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: matches!(status, button::Status::Hovered)
            .then(|| theme::BG_HOVER.into()),
        text_color: theme_config::live().text_primary.to_color(),
        border: iced::Border {
            color: theme::BORDER_STRONG,
            width: 1.0,
            radius: 8.0.into(),
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
        text_color: theme_config::live().text_primary.to_color(),
        border: iced::Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// One segment of a tab strip. The active segment keeps its fill whatever the
/// pointer does; hover only previews an inactive one, at half strength, so a
/// hovered tab can never be mistaken for the selected one.
fn segment_style(active: bool, status: button::Status) -> button::Style {
    let background = if active {
        Some(theme::BG_HOVER.into())
    } else if matches!(status, button::Status::Hovered) {
        Some(tint(theme::BG_HOVER, 0.5).into())
    } else {
        None
    };
    button::Style {
        background,
        border: iced::Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Hover label for a control whose face is a glyph ("x", "+", "<|", "R"...),
/// placed below it.
fn tip<'a>(el: impl Into<Element<'a, Message>>, label: &str) -> Element<'a, Message> {
    tip_at(el, label, iced::widget::tooltip::Position::Bottom)
}

/// `el` with `full` as its tooltip when its label was `cut` to fit (see
/// [`clip_to_width`]); as it is otherwise.
fn tip_if<'a>(el: impl Into<Element<'a, Message>>, cut: bool, full: &str) -> Element<'a, Message> {
    if cut {
        tip(el, full)
    } else {
        el.into()
    }
}

/// [`tip`] with an explicit side — the status bar's controls sit on the
/// window's bottom edge and need theirs above.
fn tip_at<'a>(
    el: impl Into<Element<'a, Message>>,
    label: &str,
    position: iced::widget::tooltip::Position,
) -> Element<'a, Message> {
    let live = theme_config::live();
    let scale = live.ui_font_size / 12.0;
    iced::widget::tooltip(
        el,
        text(label.to_string())
            .size(11.0 * scale)
            .color(live.text_primary.to_color()),
        position,
    )
    .gap(space::XS)
    .padding(6)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border {
            color: theme::BORDER_STRONG,
            width: 1.0,
            radius: 6.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
            offset: iced::Vector::new(0.0, 2.0),
            blur_radius: 8.0,
        },
        ..Default::default()
    })
    .into()
}

/// Dimmed full-window layer between the main layout and an overlay. It
/// swallows left clicks, so nothing behind an open dialog can be pressed
/// through it, and claims the pointer (`Idle`), so the stack neither scrolls
/// nor hover-highlights the widgets underneath.
fn scrim<'a>() -> Element<'a, Message> {
    iced::widget::mouse_area(container(Space::new(Fill, Fill)).style(|_| container::Style {
        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.5).into()),
        ..Default::default()
    }))
    .on_press(Message::None)
    .interaction(mouse::Interaction::Idle)
    .into()
}

/// The shared modal surface: raised panel, hairline border, soft shadow.
/// Returns the container so callers can still size or pad it.
fn modal_card<'a>(
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::Container<'a, Message> {
    container(content).style(|_| modal_card_style(theme::BORDER))
}

fn modal_card_style(border: Color) -> container::Style {
    container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border {
            color: border,
            width: 1.0,
            radius: 10.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    }
}

/// `"#rrggbb"` (the `#` optional, surrounding blanks ignored) to a colour.
/// Anything else — empty, short, non-hex — is None rather than a guess.
fn parse_hex_color(s: &str) -> Option<Color> {
    let hex = s.trim();
    let hex = hex.strip_prefix('#').unwrap_or(hex);
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(Color::from_rgb8((n >> 16) as u8, (n >> 8) as u8, n as u8))
}

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

/// The error dialog's title for `message`: the notice title bound to that
/// very message (`NeoShell::show_notice`), else the connection-error one.
fn error_dialog_title(title: Option<(u64, &'static str)>, message: &str) -> &'static str {
    match title {
        Some((bound, key)) if bound == fingerprint(message) => key,
        _ => "err.title",
    }
}

// ---------------------------------------------------------------------------
// v0.7.0 feature wiring helpers
// ---------------------------------------------------------------------------

/// Widget id of the quick-command input; autocomplete keeps focus in it.
const QUICK_CMD_INPUT_ID: &str = "quick_cmd_input";
/// Main-screen inputs outside any overlay. They carry ids so a focus query
/// reports them: `find_focused` skips an input without one, which read as
/// "the terminal has the keys" and moved the input method's candidate
/// window to the terminal cursor while the user typed here.
const SIDEBAR_SEARCH_INPUT_ID: &str = "sidebar_search";
const LOCAL_PATH_INPUT_ID: &str = "local_path";
const REMOTE_PATH_INPUT_ID: &str = "remote_path";
/// Widget id of the SFTP name / mode dialog's input.
const SFTP_INPUT_ID: &str = "sftp_input";
/// Suggestions the quick-command dropdown shows at most.
const QUICK_CMD_SUGGESTIONS: usize = 5;
/// Most command lines kept, in memory and in `history.enc`.
const HISTORY_MAX: usize = 500;
/// Paced history writes go out at most this often. Lock, quit and clearing
/// write at once; this spaces out the ones in between, each of which ends in
/// two fsyncs (F_FULLFSYNC on macOS).
const HISTORY_FLUSH_INTERVAL: Duration = Duration::from_secs(60);
/// How often a dirty history asks `history_flush_due`. The check is cheap.
const HISTORY_FLUSH_TICK: Duration = Duration::from_secs(5);
/// Longest quit waits for history writes already on their way to disk. It
/// waits on the UI thread, with the window about to close.
const HISTORY_SETTLE_WAIT: Duration = Duration::from_secs(5);
/// Longest the unlock-time load waits for them. It waits on a blocking
/// thread, never in `update`, so it can outwait a slow disk; a write still
/// out after this long is stuck, and the user is told that this session's
/// commands will not be saved.
const HISTORY_LOAD_SETTLE_WAIT: Duration = Duration::from_secs(60);
/// A sealed history file larger than this is not one NeoShell wrote.
const SEALED_HISTORY_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// How long a keyboard-interactive challenge stays answerable. The SSH thread
/// stops waiting after 180 s (`AUTH_PROMPT_TIMEOUT` in ssh/mod.rs); retiring
/// the modal a little earlier means nobody types an answer that no thread is
/// waiting for.
const AUTH_PROMPT_TTL: Duration = Duration::from_secs(170);
/// What the SFTP transfer loops return once the progress bar's Cancel has set
/// `finished` (ssh/mod.rs). A cancel is not a failure to report.
const TRANSFER_CANCELLED: &str = "Transfer cancelled";

/// The newest `HISTORY_MAX` records of a cleartext `history.json`, the file
/// builds before the sealed history wrote. Missing, oversized or corrupt reads
/// as empty: losing the history beats refusing to unlock.
fn load_history_from(path: &std::path::Path) -> Vec<CmdRecord> {
    const MAX_BYTES: u64 = 4 * 1024 * 1024;
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() <= MAX_BYTES => {}
        Ok(meta) => {
            log::warn!("{} is {} bytes; not loading it", path.display(), meta.len());
            return Vec::new();
        }
        Err(_) => return Vec::new(),
    }
    let parsed = std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str::<Vec<CmdRecord>>(&s).map_err(|e| e.to_string()));
    let mut list = match parsed {
        Ok(list) => list,
        Err(e) => {
            log::warn!("command history {} unreadable: {}", path.display(), e);
            return Vec::new();
        }
    };
    if list.len() > HISTORY_MAX {
        list.drain(..list.len() - HISTORY_MAX);
    }
    list
}

/// Whether, and when, `cmd_history` reaches `history_file`. It sits beside
/// the list rather than around it, so the list's readers stay as they are.
#[derive(Debug, Default)]
struct HistorySync {
    /// `cmd_history` holds records the sealed file does not have yet.
    dirty: bool,
    /// The unlock-time load has read the sealed file, found none, or set an
    /// unreadable one aside. Nothing is written without it — a session that
    /// never saw the file would write its short list over the real one — and
    /// it is always false while the vault is locked.
    loaded: bool,
    /// When the last paced write went out.
    flushed_at: Option<std::time::Instant>,
    /// The unlock-time load out on a blocking thread, if any. Only this one
    /// lands (`land_history_load`): a lock drops it, a later unlock replaces
    /// it.
    pending_load: Option<PendingLoad>,
    /// Numbers the unlock-time loads.
    load_seq: u64,
}

/// An unlock-time load on its way back to the UI thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingLoad {
    seq: u64,
    /// The history was cleared while the load ran: what it read predates the
    /// clear and must not come back.
    cleared: bool,
}

/// Is a paced history write due at `now`? At most one per
/// `HISTORY_FLUSH_INTERVAL`, and never before the unlock-time load.
fn history_flush_due(sync: &HistorySync, now: std::time::Instant) -> bool {
    sync.dirty
        && sync.loaded
        && sync
            .flushed_at
            .is_none_or(|t| now.saturating_duration_since(t) >= HISTORY_FLUSH_INTERVAL)
}

/// May a write go out at all? Not before the unlock-time load, which is what
/// keeps a session from writing its short list over records it never saw —
/// unless the write is a clear, which is meant to replace whatever is there.
fn history_write_allowed(sync: &HistorySync, scrub: bool) -> bool {
    sync.loaded || scrub
}

/// The command history on disk. `history.enc` holds one `EncryptedBlob`: the
/// JSON record list sealed under the vault DEK, so it is exactly as readable
/// as the vault. `history.json` is the cleartext file earlier builds wrote;
/// the first unlock imports it, and the write that seals its records scrubs
/// and deletes it.
///
/// Records are sealed on the UI thread, where the key is and where sealing a
/// few hundred lines costs next to nothing. The write, which fsyncs twice,
/// runs on a blocking thread and only ever holds ciphertext.
struct HistoryFile {
    sealed: std::path::PathBuf,
    legacy: std::path::PathBuf,
    /// Numbers snapshots in the order they are sealed.
    next_seq: AtomicU64,
    /// Number of the newest snapshot on disk. Held for the whole of a write:
    /// writes never overlap (`write_private` stages every writer in the same
    /// `<name>.tmp<pid>`), and a snapshot that runs late is dropped instead of
    /// landing over a newer one.
    written: parking_lot::Mutex<u64>,
    /// Snapshots sealed but not yet written or dropped.
    pending: parking_lot::Mutex<usize>,
    settled: parking_lot::Condvar,
    /// Counts vault locks. Bumped before the key goes (`lock_history`), so a
    /// load running off the UI thread can tell a sealed file it could not
    /// open for want of the key from a damaged one.
    locks: AtomicU64,
}

/// A sealed snapshot of the history, on its way to disk.
struct HistoryWrite {
    seq: u64,
    blob: crate::storage::EncryptedBlob,
    /// Overwrite the bytes being replaced as well (clearing).
    scrub: bool,
    /// Scrub and delete the cleartext `history.json` once this snapshot, or
    /// a newer one, is on disk.
    retire_legacy: bool,
    /// Counts the snapshot as pending until it is dropped, run or not.
    pending: PendingWrite,
}

struct PendingWrite(Arc<HistoryFile>);

impl Drop for PendingWrite {
    fn drop(&mut self) {
        let mut pending = self.0.pending.lock();
        *pending = pending.saturating_sub(1);
        self.0.settled.notify_all();
    }
}

impl HistoryWrite {
    /// Put the snapshot on disk. Blocking: two fsyncs.
    fn run(self) -> std::io::Result<()> {
        let file = self.pending.0.clone();
        file.write(self)
    }
}

/// What an unlock found on disk. It comes back from the blocking thread in a
/// `Message`, hence `Clone`; its `Debug` shows no command line.
#[derive(Clone, Default)]
pub(crate) struct HistoryLoad {
    records: Vec<CmdRecord>,
    /// Safe to write the sealed file this session; see `HistorySync::loaded`.
    writable: bool,
    /// Not writable because a write sent off before the unlock was still out
    /// after `HISTORY_LOAD_SETTLE_WAIT`.
    unsettled: bool,
    /// A cleartext `history.json` was merged in, for the first write to
    /// retire.
    legacy_found: bool,
}

impl std::fmt::Debug for HistoryLoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryLoad")
            .field("records", &self.records.len())
            .field("writable", &self.writable)
            .field("unsettled", &self.unsettled)
            .field("legacy_found", &self.legacy_found)
            .finish()
    }
}

impl HistoryFile {
    fn at(dir: &std::path::Path) -> Self {
        HistoryFile {
            sealed: dir.join("history.enc"),
            legacy: dir.join("history.json"),
            next_seq: AtomicU64::new(0),
            written: parking_lot::Mutex::new(0),
            pending: parking_lot::Mutex::new(0),
            settled: parking_lot::Condvar::new(),
            locks: AtomicU64::new(0),
        }
    }

    fn in_data_dir() -> Self {
        Self::at(
            &dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("neoshell"),
        )
    }

    /// Seal the newest `HISTORY_MAX` of `records` for a later `run`. Fails
    /// while the vault is locked.
    fn snapshot(
        file: &Arc<HistoryFile>,
        store: &ConnectionStore,
        records: &[CmdRecord],
        scrub: bool,
        retire_legacy: bool,
    ) -> Result<HistoryWrite, String> {
        let start = records.len().saturating_sub(HISTORY_MAX);
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(&records[start..]).map_err(|e| e.to_string())?,
        );
        let blob = store.seal(&json)?;
        *file.pending.lock() += 1;
        Ok(HistoryWrite {
            seq: file.next_seq.fetch_add(1, Ordering::Relaxed) + 1,
            blob,
            scrub,
            retire_legacy,
            pending: PendingWrite(file.clone()),
        })
    }

    fn write(&self, job: HistoryWrite) -> std::io::Result<()> {
        let mut written = self.written.lock();
        if job.seq > *written {
            let bytes = serde_json::to_vec(&job.blob).map_err(std::io::Error::other)?;
            if job.scrub {
                crate::storage::write_private_scrubbing(&self.sealed, &bytes)?;
            } else {
                crate::storage::write_private(&self.sealed, &bytes)?;
            }
            *written = job.seq;
        }
        // This snapshot or a newer one is on disk, and every snapshot sealed
        // after an import holds the imported records (or was cleared on
        // purpose): the cleartext copy has nothing left to give.
        if job.retire_legacy {
            retire_legacy_history(&self.legacy).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("sealed, but {} not removed: {}", self.legacy.display(), e),
                )
            })?;
        }
        Ok(())
    }

    /// Wait, at most `limit`, for every snapshot sealed so far to be written
    /// or dropped. `false` if some are still out.
    fn wait_settled(&self, limit: Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        let mut pending = self.pending.lock();
        while *pending > 0 {
            if self.settled.wait_until(&mut pending, deadline).timed_out() {
                return *pending == 0;
            }
        }
        true
    }

    /// The history of a vault that was just unlocked: the sealed records with
    /// a cleartext `history.json` merged in. Touches nothing while locked.
    /// Blocking — it waits out earlier writes first — so it runs off the UI
    /// thread (`unlock_history`).
    fn load(&self, store: &ConnectionStore) -> HistoryLoad {
        self.load_within(store, HISTORY_LOAD_SETTLE_WAIT)
    }

    /// `load`, waiting at most `settle` for the writes already sent off.
    fn load_within(&self, store: &ConnectionStore, settle: Duration) -> HistoryLoad {
        // Taken before the lock state is: a lock from here on shows as a
        // change.
        let locks = self.locks.load(Ordering::SeqCst);
        let mut load = HistoryLoad::default();
        // Locked is not unreadable: a file that cannot be opened for want of
        // the key must not be set aside as if it were damaged.
        if !store.is_unlocked() {
            return load;
        }
        // The lock sent its last records off on a blocking thread. Reading
        // before they land would load the older file, and this session's
        // next write would then drop them for good.
        let settled = self.wait_settled(settle);
        if !settled {
            log::warn!(
                "command history: an earlier write is still running; not saving this session"
            );
            load.unsettled = true;
        }
        let sealed = match self.read_sealed(store) {
            Ok(list) => {
                load.writable = settled;
                list
            }
            // The vault locked while this ran and took the key with it: no
            // sign of damage, and a load nobody wants any more.
            Err(_) if self.locks.load(Ordering::SeqCst) != locks => {
                return HistoryLoad::default();
            }
            Err(e) => {
                log::warn!(
                    "command history {} unreadable: {}",
                    self.sealed.display(),
                    e
                );
                load.writable = settled && self.set_aside();
                Vec::new()
            }
        };
        let legacy = if self.legacy.exists() {
            load.legacy_found = load.writable;
            load_history_from(&self.legacy)
        } else {
            Vec::new()
        };
        load.records = merge_history(sealed, legacy);
        load
    }

    fn read_sealed(&self, store: &ConnectionStore) -> Result<Vec<CmdRecord>, String> {
        match std::fs::metadata(&self.sealed) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.to_string()),
            Ok(meta) if meta.len() > SEALED_HISTORY_MAX_BYTES => {
                return Err(format!("{} bytes", meta.len()));
            }
            Ok(_) => {}
        }
        let raw = std::fs::read(&self.sealed).map_err(|e| e.to_string())?;
        let blob: crate::storage::EncryptedBlob =
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let plain = store.open(&blob)?;
        let mut list: Vec<CmdRecord> = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        if list.len() > HISTORY_MAX {
            list.drain(..list.len() - HISTORY_MAX);
        }
        Ok(list)
    }

    /// Move an unreadable sealed file out of the way rather than write over
    /// it: it may be the only copy — sealed by a vault this one replaced, or
    /// damaged in a way that can still be repaired. Never over an earlier one
    /// either, for the same reason. `true` once the path is free.
    fn set_aside(&self) -> bool {
        let free = (0..1000)
            .map(|n| match n {
                0 => self.sealed.with_extension("enc.unreadable"),
                n => self.sealed.with_extension(format!("enc.unreadable.{n}")),
            })
            .find(|p| std::fs::symlink_metadata(p).is_err());
        let Some(aside) = free else {
            log::error!(
                "no free name to set {} aside; command history will not be saved this session",
                self.sealed.display()
            );
            return false;
        };
        match std::fs::rename(&self.sealed, &aside) {
            Ok(()) => {
                log::warn!(
                    "unreadable command history set aside as {}",
                    aside.display()
                );
                true
            }
            Err(e) => {
                log::error!(
                    "could not set {} aside ({}); command history will not be saved this session",
                    self.sealed.display(),
                    e
                );
                false
            }
        }
    }
}

/// Sealed and imported records as one list: oldest first, the newest
/// `HISTORY_MAX` kept. An import that was cut short leaves the same records
/// in both files, so an imported record the sealed list already holds is
/// dropped.
fn merge_history(mut sealed: Vec<CmdRecord>, legacy: Vec<CmdRecord>) -> Vec<CmdRecord> {
    if !legacy.is_empty() {
        let known = sealed.len();
        for record in legacy {
            if !sealed[..known].contains(&record) {
                sealed.push(record);
            }
        }
        // Stable: records from the same second keep their order.
        sealed.sort_by_key(|r| r.timestamp);
    }
    if sealed.len() > HISTORY_MAX {
        sealed.drain(..sealed.len() - HISTORY_MAX);
    }
    sealed
}

/// Overwrite the cleartext `history.json` in place, then delete it. Anything
/// but a regular file is only unlinked, never written through.
fn retire_legacy_history(path: &std::path::Path) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_file() {
        crate::storage::write_private_scrubbing(path, b"")?;
    }
    std::fs::remove_file(path)?;
    log::info!(
        "cleartext command history {} imported and removed",
        path.display()
    );
    Ok(())
}

/// Overwrite every record's text, then drop them all.
fn wipe_history(records: &mut Vec<CmdRecord>) {
    for record in records.iter_mut() {
        record.cmd.zeroize();
        record.session_title.zeroize();
        record.host.zeroize();
    }
    records.clear();
}

/// The history half of `lock_vault`. Seals what the disk has not seen yet —
/// the key is still in memory at this point, and the write returned carries
/// only ciphertext — then wipes every record and bars writes until the next
/// unlock has loaded the file again.
fn lock_history(
    file: &Arc<HistoryFile>,
    store: &ConnectionStore,
    records: &mut Vec<CmdRecord>,
    sync: &mut HistorySync,
) -> Option<HistoryWrite> {
    // Before the key goes. A load still out is not wanted any more, and must
    // not take the file it can no longer open for a damaged one.
    file.locks.fetch_add(1, Ordering::SeqCst);
    sync.pending_load = None;
    let job = if sync.dirty && sync.loaded {
        HistoryFile::snapshot(file, store, records, false, false)
            .map_err(|e| log::warn!("command history not sealed before the lock: {}", e))
            .ok()
    } else {
        None
    };
    wipe_history(records);
    sync.dirty = false;
    sync.loaded = false;
    job
}

/// Run a history write on a blocking thread.
fn spawn_history_write(job: HistoryWrite) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || job.run().map_err(|e| e.to_string()))
                .await
                .map_err(|e| format!("Task: {}", e))?
        },
        Message::HistoryWritten,
    )
}

/// Seal `cmd_history` now and write it off the UI thread. `scrub` overwrites
/// the bytes being replaced; `retire_legacy` then scrubs and deletes the
/// cleartext `history.json`. See `history_write_allowed` for when nothing is
/// written.
fn persist_history(state: &mut NeoShell, scrub: bool, retire_legacy: bool) -> Task<Message> {
    if !history_write_allowed(&state.history_sync, scrub) {
        return Task::none();
    }
    match HistoryFile::snapshot(
        &state.history_file,
        &state.store,
        &state.cmd_history,
        scrub,
        retire_legacy,
    ) {
        Ok(job) => {
            state.history_sync.dirty = false;
            spawn_history_write(job)
        }
        Err(e) => {
            log::warn!("command history not sealed: {}", e);
            Task::none()
        }
    }
}

/// Load the sealed history for a vault that was just opened, on a blocking
/// thread: the load first waits out the writes still on their way to disk —
/// the lock's, above all — and `update` must not wait with it. It lands in
/// `Message::HistoryLoaded` (`land_history_load`).
fn unlock_history(state: &mut NeoShell) -> Task<Message> {
    let (seq, load) = start_history_load(
        &state.history_file,
        state.store.clone(),
        &mut state.history_sync,
    );
    Task::perform(
        async move {
            tokio::task::spawn_blocking(load).await.unwrap_or_else(|e| {
                log::warn!("command history not loaded: {}", e);
                HistoryLoad::default()
            })
        },
        move |load| Message::HistoryLoaded(seq, load),
    )
}

/// The UI-thread half of `unlock_history`: number the load and hand back the
/// work for a blocking thread. Waits for nothing.
fn start_history_load(
    file: &Arc<HistoryFile>,
    store: Arc<ConnectionStore>,
    sync: &mut HistorySync,
) -> (u64, impl FnOnce() -> HistoryLoad + Send + 'static) {
    sync.load_seq += 1;
    let seq = sync.load_seq;
    sync.pending_load = Some(PendingLoad {
        seq,
        cleared: false,
    });
    let file = file.clone();
    (seq, move || file.load(&store))
}

/// What landing an unlock-time load asks of `update`.
#[derive(Debug, PartialEq, Eq)]
struct LoadLanded {
    /// Seal and write at once: that write retires the cleartext
    /// `history.json` the load imported.
    import_legacy: bool,
    /// The i18n key of the warning the user has to see: nothing typed this
    /// session will be saved.
    warning: Option<&'static str>,
}

/// Land the unlock-time load numbered `seq`: the records on disk, then the
/// ones typed while it ran. `None`, and every record it read wiped, for a
/// load nobody wants any more: the vault locked since, or a later unlock
/// started another.
fn land_history_load(
    records: &mut Vec<CmdRecord>,
    sync: &mut HistorySync,
    seq: u64,
    mut load: HistoryLoad,
) -> Option<LoadLanded> {
    let Some(pending) = sync.pending_load.filter(|p| p.seq == seq) else {
        wipe_history(&mut load.records);
        return None;
    };
    sync.pending_load = None;
    if pending.cleared {
        // Read before the clear reached the disk.
        wipe_history(&mut load.records);
    }
    let typed = std::mem::take(records);
    // Typed while the load ran, so not on disk yet. (A second unlock without
    // a lock between reloads what the first may have written already: the
    // merge drops those twins.)
    sync.dirty = !typed.is_empty();
    *records = merge_history(load.records, typed);
    sync.loaded = load.writable;
    Some(LoadLanded {
        import_legacy: load.legacy_found && !pending.cleared,
        warning: (!load.writable).then_some(if load.unsettled {
            "history.warn.unsettled"
        } else {
            "history.warn.unreadable"
        }),
    })
}

/// The in-memory half of clearing the history. A load still out read the
/// history before the clear: it must not bring it back.
fn clear_history(records: &mut Vec<CmdRecord>, sync: &mut HistorySync) {
    wipe_history(records);
    sync.dirty = false;
    if let Some(pending) = sync.pending_load.as_mut() {
        pending.cleared = true;
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compact age for the history panel: 42s, 5m, 3h, 2d.
fn format_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
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

/// Completions for the quick-command input, best first: commands already run
/// (newest first), then snippet bodies. A plain prefix match — case matters
/// to a shell — that never offers the text exactly as typed, and never a
/// multi-line snippet, which a one-line input cannot hold.
fn quick_cmd_matches(input: &str, history: &[CmdRecord], snippets: &[Snippet]) -> Vec<String> {
    if input.trim().is_empty() {
        return Vec::new();
    }
    let history = history.iter().rev().map(|r| r.cmd.as_str());
    let snippets = snippets
        .iter()
        .map(|s| s.body.trim_end())
        .filter(|body| !body.contains('\n'));
    let mut out: Vec<String> = Vec::new();
    for candidate in history.chain(snippets) {
        if candidate.len() > input.len()
            && candidate.starts_with(input)
            && !out.iter().any(|o| o == candidate)
        {
            out.push(candidate.to_string());
            if out.len() == QUICK_CMD_SUGGESTIONS {
                break;
            }
        }
    }
    out
}

/// Tab or Down with no modifier: the keys that accept a suggestion.
fn is_autocomplete_key(key: &keyboard::Key, modifiers: &keyboard::Modifiers) -> bool {
    use keyboard::key::Named;
    let plain = !modifiers.shift() && !modifiers.control() && !modifiers.alt() && !modifiers.logo();
    plain && matches!(key, keyboard::Key::Named(Named::Tab | Named::ArrowDown))
}

/// Whether the quick-command input holds keyboard focus right now, asked of
/// the widget tree. iced keeps focus inside the widgets, and a text input
/// does not capture Tab or the arrows, so the key event alone cannot say.
fn quick_cmd_input_focused() -> Task<bool> {
    use iced::advanced::widget::{operate, operation::focusable::find_focused, Id};
    operate(find_focused())
        .collect()
        .map(|ids: Vec<Id>| ids.iter().any(|id| *id == Id::new(QUICK_CMD_INPUT_ID)))
}

/// Drain the challenges SSH threads parked for the modal. Runs on the
/// `PollSshEvents` tick, which is on every screen: a reconnect can ask at any
/// time. Returns the focus task for the front challenge's first field, once
/// the modal is on screen to take it (see `deliver_auth_focus`).
fn poll_auth_prompts(state: &mut NeoShell) -> Task<Message> {
    let was_empty = state.auth_queue.is_empty();
    if let Some(rx) = &state.auth_rx {
        while let Ok(challenge) = rx.try_recv() {
            log::info!(
                "keyboard-interactive challenge for {} ({})",
                challenge.target,
                challenge.purpose
            );
            state.auth_queue.push_back((challenge, std::time::Instant::now()));
        }
    }
    // A challenge from a session no tab or pane holds any more — a connect
    // still dialling when its tab closed, which closing could not withdraw
    // yet — is cancelled, never shown: nobody is there to answer it.
    let mut front_orphaned = false;
    if !state.auth_queue.is_empty() {
        let tabs = &state.tabs;
        let (orphans, front) = take_challenges(&mut state.auth_queue, |c| {
            challenge_orphaned(&c.session_id, tabs)
        });
        for challenge in orphans {
            log::info!("withdrawing the sign-in for {}: its tab is gone", challenge.target);
            challenge.cancel();
        }
        front_orphaned = front;
    }
    // Past its SSH thread's own timeout nobody is waiting for the answer any
    // more: retire the modal instead of taking one.
    let front_expired = state
        .auth_queue
        .front()
        .is_some_and(|(_, at)| at.elapsed() >= AUTH_PROMPT_TTL);
    state.auth_queue.retain(|(_, at)| at.elapsed() < AUTH_PROMPT_TTL);
    if front_expired || front_orphaned || (was_empty && !state.auth_queue.is_empty()) {
        return state.begin_auth_prompt();
    }
    // A challenge that arrived under the lock screen, the palette or the
    // delete confirmation takes the focus once the modal is uncovered.
    state.deliver_auth_focus()
}

/// Whether the keyboard-interactive modal is on screen: only `view_main`
/// draws it, and only while nothing sits above it in the z-order.
fn auth_modal_visible(screen: &Screen, topmost: Option<Overlay>) -> bool {
    *screen == Screen::Main && topmost == Some(Overlay::AuthPrompt)
}

/// Settle an owed focus: true exactly once, the first time the modal is
/// `visible`. Handing it over on every tick would pull the cursor back to the
/// first field while the user is typing in the second.
fn take_owed_focus(owed: &mut bool, visible: bool) -> bool {
    let now = *owed && visible;
    if now {
        *owed = false;
    }
    now
}

fn auth_input_id(i: usize) -> text_input::Id {
    text_input::Id::new(format!("auth_answer_{}", i))
}

/// Answer fields `release_auth_focus` looks at. A server may ask for more,
/// but none does usefully.
const AUTH_MAX_FIELDS: usize = 64;

/// Keys this recent when a sign-in modal comes up mean the user is typing
/// somewhere else: the modal does not take the keyboard then, not even for a
/// challenge the user asked for.
const AUTH_TYPING_WINDOW: Duration = Duration::from_millis(1500);

/// For this long after a sign-in modal comes up, its answer fields take no
/// keys and Enter submits nothing. Nobody reads a modal and starts answering
/// that fast: what arrives in the window was typed before it appeared.
const AUTH_ARM_DELAY: Duration = Duration::from_millis(300);

/// Whether a sign-in challenge may take the keyboard when its modal comes up:
/// only one the user's own click just asked for — the Test or Deploy button,
/// whose challenges carry no session, or a Connect, a split or a "Reconnect
/// monitoring" still waiting on this session (`user_started`). Anything else,
/// above all a dropped session reconnecting on its own, turns up while the
/// user is typing somewhere else, and taking the focus would hand the rest of
/// what they type — Enter included — to this server as the answer. That
/// modal shows, and waits for a click.
fn challenge_may_take_focus(purpose: &str, user_started: bool) -> bool {
    match purpose {
        "test" | "deploy" => true,
        "reconnect" => false,
        _ => user_started,
    }
}

/// Whether keys were still arriving at `now` (see [`AUTH_TYPING_WINDOW`]).
fn typing_recently(last_keypress: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    last_keypress.is_some_and(|at| now.saturating_duration_since(at) < AUTH_TYPING_WINDOW)
}

/// Track when the sign-in modal came on screen: set the first time it is
/// `visible`, cleared whenever it is not — covered, gone, or locked away.
fn note_auth_shown(
    shown_at: &mut Option<std::time::Instant>,
    visible: bool,
    now: std::time::Instant,
) {
    if !visible {
        *shown_at = None;
    } else if shown_at.is_none() {
        *shown_at = Some(now);
    }
}

/// Whether the modal's answer fields take keys yet: it has been on screen
/// for [`AUTH_ARM_DELAY`].
fn auth_armed(shown_at: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    shown_at.is_some_and(|at| now.saturating_duration_since(at) >= AUTH_ARM_DELAY)
}

/// Take the keyboard focus off the sign-in modal's answer fields — and off
/// nothing else: whatever the user was typing in keeps it.
fn release_auth_focus() -> Task<Message> {
    use iced::advanced::widget::{operate, operation, Id, Operation};
    struct Release;
    impl<T> Operation<T> for Release {
        fn container(
            &mut self,
            _id: Option<&Id>,
            _bounds: Rectangle,
            operate_on_children: &mut dyn FnMut(&mut dyn Operation<T>),
        ) {
            operate_on_children(self);
        }

        fn focusable(&mut self, state: &mut dyn operation::Focusable, id: Option<&Id>) {
            let answer = id.is_some_and(|id| {
                (0..AUTH_MAX_FIELDS).any(|i| *id == Id::from(auth_input_id(i)))
            });
            if answer {
                state.unfocus();
            }
        }
    }
    operate(Release)
}

/// Send what was typed to the challenge at the front, and move on to the next.
fn submit_auth_answers(state: &mut NeoShell) -> Task<Message> {
    if let Some((challenge, _)) = state.auth_queue.pop_front() {
        let mut answers = std::mem::take(&mut state.auth_answers);
        answers.resize(challenge.prompt.prompts.len(), String::new());
        // A thread that already timed out dropped its receiver;
        // there is nobody left to tell.
        let _ = challenge.reply.send(answers);
    }
    state.begin_auth_prompt()
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

/// Every session id a tab's sign-in challenges can carry: its session or,
/// while it connects, the id that connect runs under — and the same for its
/// split.
fn tab_auth_sessions(tab: &TerminalTab) -> Vec<String> {
    [
        Some(&tab.session_id),
        Some(&tab.pending_session_id),
        tab.split.as_ref().map(|sp| &sp.session_id),
        tab.split_pending.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter(|id| !id.is_empty())
    .cloned()
    .collect()
}

/// Whether a challenge from `session_id` has nobody to answer it: it names a
/// session, and no tab or pane holds it — as its session, or as the connect
/// or split still dialling under it (`tab_auth_sessions`). A test or a key
/// deployment carries no session and always has its modal.
fn challenge_orphaned(session_id: &str, tabs: &[TerminalTab]) -> bool {
    !session_id.is_empty()
        && !tabs
            .iter()
            .any(|tab| tab_auth_sessions(tab).iter().any(|s| s == session_id))
}

/// Take every challenge `pick` chooses out of the modal's queue, oldest
/// first. The flag says whether the one on screen — the front — was among
/// them.
fn take_challenges<T>(
    queue: &mut VecDeque<(T, std::time::Instant)>,
    mut pick: impl FnMut(&T) -> bool,
) -> (Vec<T>, bool) {
    let front = queue.front().is_some_and(|(challenge, _)| pick(challenge));
    let mut taken = Vec::new();
    let mut kept = VecDeque::with_capacity(queue.len());
    for (challenge, at) in queue.drain(..) {
        if pick(&challenge) {
            taken.push(challenge);
        } else {
            kept.push_back((challenge, at));
        }
    }
    *queue = kept;
    (taken, front)
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

/// Zero every answer before dropping it: they are passwords and OTP codes.
fn scrub_answers(answers: &mut Vec<String>) {
    for answer in answers.iter_mut() {
        answer.zeroize();
    }
    answers.clear();
}

/// Text a remote server supplied, made safe to lay out: control characters
/// other than newline dropped, capped at `max` characters so a hostile banner
/// cannot push the buttons off screen.
fn sanitize_remote_text(s: &str, max: usize) -> String {
    let clean: String = s.chars().filter(|c| *c == '\n' || !c.is_control()).collect();
    truncate_str(clean.trim(), max)
}

/// Which connection is asking, in words (see `AuthChallenge::purpose`).
fn auth_purpose_label(purpose: &str) -> String {
    let key = match purpose {
        "shell" => "auth.purpose.shell",
        "exec" => "auth.purpose.exec",
        "reconnect" => "auth.purpose.reconnect",
        "test" => "auth.purpose.test",
        "deploy" => "auth.purpose.deploy",
        other => return other.to_string(),
    };
    i18n::t(key).to_string()
}

/// A file or folder name exactly as the user typed it; `None` unless it is a
/// single path component. The server would resolve `a/b` or `..` somewhere
/// other than the folder on screen, so those are refused, not guessed at.
/// Not trimmed: the rename dialog opens on the name exactly, and "report "
/// submitted as it stands is that file's own name, not "report". A name of
/// nothing but spaces is refused.
fn valid_remote_name(input: &str) -> Option<String> {
    let name = input;
    if name.trim().is_empty() || name == "." || name == ".." {
        return None;
    }
    if name.chars().any(|c| c == '/' || c == '\0' || c.is_control()) {
        return None;
    }
    Some(name.to_string())
}

/// What the rename dialog's `value` asks of the row called `from`:
/// `Ok(None)` when the name is unchanged — a no-op, whatever the name holds —
/// `Ok(Some(name))` for a new name, `Err(())` for one that is not valid.
fn rename_target(from: &str, value: &str) -> Result<Option<String>, ()> {
    if value == from {
        return Ok(None);
    }
    valid_remote_name(value).map(Some).ok_or(())
}

/// `dir/name` for a remote POSIX path, without doubling the root's slash.
fn join_remote_path(dir: &str, name: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), name)
}

/// A port as typed into a form. The full-width digits a Chinese input method
/// types in full-width mode (U+FF10..U+FF19) read as ASCII ones, and ASCII
/// and ideographic spaces around it are ignored. `Ok(None)` for a blank
/// field, which takes the form's default; `Err(())` for anything that is not
/// a port from 1 to 65535 — reported, never defaulted.
fn parse_port(input: &str) -> Result<Option<u16>, ()> {
    let digits: String = input
        .trim_matches(|c: char| c.is_ascii_whitespace() || c == '\u{3000}')
        .chars()
        .map(|c| match c {
            '\u{FF10}'..='\u{FF19}' => char::from_u32(c as u32 - 0xFF10 + '0' as u32).unwrap_or(c),
            c => c,
        })
        .collect();
    if digits.is_empty() {
        return Ok(None);
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    match digits.parse::<u16>() {
        Ok(0) | Err(_) => Err(()),
        Ok(port) => Ok(Some(port)),
    }
}

/// [`parse_port`] for a form whose blank port means `default`; `Err` holds
/// the message to show.
fn form_port(input: &str, default: u16) -> Result<u16, String> {
    match parse_port(input) {
        Ok(port) => Ok(port.unwrap_or(default)),
        Err(()) => Err(i18n::tf("form.err.port", &[("port", input.trim())])),
    }
}

/// Permission bits the user typed ("755", "0644", "4755"); `None` for
/// anything but one to four octal digits.
fn parse_octal_mode(input: &str) -> Option<u32> {
    let s = input.trim();
    if s.is_empty() || s.len() > 4 || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    u32::from_str_radix(s, 8).ok()
}

/// Permission bits of an `ls -l` mode string ("drwxr-sr-x", "-rwsr-xr-T"),
/// set-id and sticky included, to prefill the chmod dialog. `None` when the
/// string does not look like one.
fn mode_from_permissions(perms: &str) -> Option<u32> {
    let p: Vec<char> = perms.chars().collect();
    if p.len() < 10 {
        return None;
    }
    let mut mode = 0u32;
    for (i, shift, special) in [(1usize, 6u32, 0o4000u32), (4, 3, 0o2000), (7, 0, 0o1000)] {
        match p[i] {
            'r' => mode |= 4 << shift,
            '-' => {}
            _ => return None,
        }
        match p[i + 1] {
            'w' => mode |= 2 << shift,
            '-' => {}
            _ => return None,
        }
        match p[i + 2] {
            'x' => mode |= 1 << shift,
            's' | 't' => mode |= (1 << shift) | special,
            'S' | 'T' => mode |= special,
            '-' => {}
            _ => return None,
        }
    }
    Some(mode)
}

/// Sort the listening-ports table; ties fall back to port, then protocol.
fn sort_ports(ports: &mut [crate::ssh::PortInfo], key: PortSort, desc: bool) {
    ports.sort_by(|a, b| {
        let primary = match key {
            PortSort::Proto => a.proto.cmp(&b.proto),
            PortSort::Addr => a.local_addr.cmp(&b.local_addr),
            PortSort::Port => a.port.cmp(&b.port),
            PortSort::Pid => a.pid.cmp(&b.pid),
            // Case-insensitive without allocating two strings per comparison.
            PortSort::Process => a
                .process
                .chars()
                .flat_map(char::to_lowercase)
                .cmp(b.process.chars().flat_map(char::to_lowercase)),
        };
        let ord = primary
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.proto.cmp(&b.proto));
        if desc {
            ord.reverse()
        } else {
            ord
        }
    });
}

/// A click on a column header: the same column flips direction, a new one
/// starts ascending — and the table is re-sorted now, in `update`, so the
/// view can draw `ports` as it stands.
fn resort_ports(
    ports: &mut [crate::ssh::PortInfo],
    sort: &mut PortSort,
    desc: &mut bool,
    key: PortSort,
) {
    if *sort == key {
        *desc = !*desc;
    } else {
        *sort = key;
        *desc = false;
    }
    sort_ports(ports, *sort, *desc);
}

/// `ProcIdentity` from /proc/<pid>/stat and /proc/<pid>/cmdline as `cat` and
/// `tr '\0' ' '` print them. `None` when there is no such process: nothing
/// was printed, or not a stat line.
fn parse_proc_identity(stat: &str, cmdline: &str) -> Option<ProcIdentity> {
    // "pid (comm) state ppid ...": comm may hold spaces and parentheses of
    // its own, so it runs to the LAST ')'.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close < open {
        return None;
    }
    // The fields after comm start at field 3 (state); starttime is field 22.
    let start_time = stat[close + 1..].split_whitespace().nth(22 - 3)?;
    if !start_time.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(ProcIdentity {
        start_time: start_time.to_string(),
        comm: stat[open + 1..close].to_string(),
        cmdline: cmdline.trim_end().to_string(),
    })
}

/// `ProcIdentity` from `ps -o lstart= -o args=` in the C locale, for a host
/// without /proc — a BSD or macOS one: the start time, five fields ("Mon Sep
/// 22 01:02:03 2026"), then the command line. `None` when `ps` printed no
/// such line: no such process.
fn parse_ps_identity(out: &str) -> Option<ProcIdentity> {
    let line = out.lines().find(|l| !l.trim().is_empty())?;
    let mut fields = Vec::with_capacity(5);
    let mut rest = line.trim_start();
    for _ in 0..5 {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        fields.push(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    let year_ok = !fields[4].is_empty() && fields[4].bytes().all(|b| b.is_ascii_digit());
    if !year_ok || !fields[3].contains(':') {
        return None;
    }
    let cmdline = rest.trim_end().to_string();
    Some(ProcIdentity {
        start_time: fields.join(" "),
        comm: cmdline.split_whitespace().next().unwrap_or("?").to_string(),
        cmdline,
    })
}

/// Read `pid`'s [`ProcIdentity`] over the session's exec connection: plain
/// reads of /proc — any shell runs them, fish included — with nothing in
/// them but the pid. A host without /proc answers through `ps` instead.
fn read_proc_identity(
    ssh: &SshManager,
    session_id: &str,
    pid: u32,
) -> Result<Option<ProcIdentity>, String> {
    let stat = ssh.exec_command(
        session_id,
        &format!("cat /proc/{}/stat 2>/dev/null || test -d /proc/self || echo NOPROC", pid),
    )?;
    if stat.trim() == "NOPROC" {
        let ps = ssh.exec_command(
            session_id,
            &format!("env LC_ALL=C ps -ww -o lstart= -o args= -p {} 2>/dev/null", pid),
        )?;
        return Ok(parse_ps_identity(&ps));
    }
    let cmdline = ssh.exec_command(
        session_id,
        &format!("tr '\\0' ' ' < /proc/{}/cmdline 2>/dev/null", pid),
    )?;
    Ok(parse_proc_identity(&stat, &cmdline))
}

/// Whether two reads of a pid found the same process: the same start time.
/// A process may rename itself or rewrite its command line (postgres
/// backends do, per query); only a new process gets a new start time.
fn same_process(confirmed: &ProcIdentity, now: &ProcIdentity) -> bool {
    confirmed.start_time == now.start_time
}

/// What the kill confirmation shows for a process: its command line as /proc
/// has it, with whatever would not show made visible, else "[comm]" — a
/// kernel thread has no command line — as `ps` shows it.
fn kill_command_label(identity: &ProcIdentity) -> String {
    let line = if identity.cmdline.trim().is_empty() {
        format!("[{}]", identity.comm)
    } else {
        identity.cmdline.clone()
    };
    truncate_str(&visible_text(&line), 600)
}

fn signal_name(signal: i32) -> String {
    match signal {
        1 => "SIGHUP".to_string(),
        2 => "SIGINT".to_string(),
        9 => "SIGKILL".to_string(),
        15 => "SIGTERM".to_string(),
        n => i18n::tf("process.signal_n", &[("n", &n.to_string())]),
    }
}

/// `preset` carrying `current`'s font sizes: a colour scheme changes colours
/// only. Also how the picker tells which preset is the active one.
fn preset_keeping_fonts(
    mut preset: theme_config::ThemeConfig,
    current: &theme_config::ThemeConfig,
) -> theme_config::ThemeConfig {
    preset.terminal_font_size = current.terminal_font_size;
    preset.ui_font_size = current.ui_font_size;
    preset
}

/// 1-based `(col, row)` of the cell under window point `(x, y)` in a grid of
/// `size` = (cols, rows) whose canvas starts at `origin`, with the renderer's
/// cell metrics. Outside the grid it is `None` — unless `clamp`, which pins
/// the point to the nearest edge cell, as xterm does for a drag or release
/// that wandered off the pane.
fn grid_cell_at(
    x: f32,
    y: f32,
    origin: (f32, f32),
    font_size: f32,
    size: (usize, usize),
    clamp: bool,
) -> Option<(usize, usize)> {
    let (cols, rows) = size;
    if cols == 0 || rows == 0 {
        return None;
    }
    let (x, y) = if clamp { (x.max(origin.0), y.max(origin.1)) } else { (x, y) };
    let (col, row) = pixel_to_grid_with(x, y, origin.0, origin.1, font_size)?;
    if clamp {
        Some((col.min(cols - 1) + 1, row.min(rows - 1) + 1))
    } else if col < cols && row < rows {
        Some((col + 1, row + 1))
    } else {
        None
    }
}

/// Whether window point `pos` lies in the second pane of a split whose area
/// starts at `origin` and whose first pane is `main_len` long along the
/// split axis. The divider counts half to each side.
fn in_second_pane(pos: (f32, f32), origin: (f32, f32), main_len: f32, vertical: bool) -> bool {
    let boundary = main_len + SPLIT_DIVIDER / 2.0;
    if vertical {
        pos.0 - origin.0 >= boundary
    } else {
        pos.1 - origin.1 >= boundary
    }
}

/// The terminal's name for a mouse button; `None` for the ones a terminal
/// never reports (back / forward / other).
fn terminal_button(button: mouse::Button) -> Option<MouseButton> {
    match button {
        mouse::Button::Left => Some(MouseButton::Left),
        mouse::Button::Middle => Some(MouseButton::Middle),
        mouse::Button::Right => Some(MouseButton::Right),
        _ => None,
    }
}

/// What a right or middle press on the terminal does.
#[derive(Debug, PartialEq, Eq)]
enum SecondaryClick {
    /// Report it to the application that asked for the mouse.
    Report,
    /// Paste the clipboard, as a right-click always has.
    Paste,
    Ignore,
}

/// An application that switched mouse reporting on (vim `mouse=a`, htop,
/// tmux, mc) gets the right and middle buttons as it gets the left one and
/// the wheel — a right-click that pasted into it instead was never what it
/// asked for. With reporting off, or Shift held (see `mouse_report_target`),
/// a right-click pastes as before and a middle click does nothing.
fn secondary_click(button: MouseButton, reporting: bool) -> SecondaryClick {
    if reporting {
        SecondaryClick::Report
    } else if button == MouseButton::Right {
        SecondaryClick::Paste
    } else {
        SecondaryClick::Ignore
    }
}

/// Queue a mouse report on the session. Synchronous on purpose: `send_data`
/// only enqueues and never blocks, and sending from here keeps a press, its
/// drag and its release in order — separate tasks may run in any order.
fn send_mouse_report(ssh: &SshManager, session_id: &str, bytes: &[u8]) {
    if let Err(e) = ssh.send_data(session_id, bytes) {
        log::debug!("mouse report to {} dropped: {}", session_id, e);
    }
}

/// Hand a wheel notch to an application that asked for the mouse. `false`
/// when nothing was reported and the caller should scroll the scrollback as
/// before — including while the user is scrolled back into history.
fn report_wheel(state: &NeoShell, button: MouseButton) -> bool {
    let Some((session_id, term)) = state.mouse_report_target() else {
        return false;
    };
    let Some((col, row)) = state.focused_pane_cell(state.cursor_x, state.cursor_y, false) else {
        return false;
    };
    let bytes = {
        let grid = term.lock();
        if grid.scroll_offset > 0 {
            return false;
        }
        grid.encode_mouse(button, col, row, true)
    };
    match bytes {
        Some(bytes) => {
            send_mouse_report(&state.ssh_manager, &session_id, &bytes);
            true
        }
        None => false,
    }
}

/// Run one mutating SFTP call off the UI thread; `SftpOpDone` then re-lists
/// the directory.
fn sftp_op_task<F>(ssh: Arc<SshManager>, session_id: String, dir: String, op: F) -> Task<Message>
where
    F: FnOnce(&SshManager, &str) -> Result<(), String> + Send + 'static,
{
    Task::perform(
        async move {
            let sid = session_id.clone();
            let result = tokio::task::spawn_blocking(move || op(&ssh, &sid))
                .await
                .unwrap_or_else(|e| Err(format!("Task: {}", e)));
            (session_id, dir, result)
        },
        |(session_id, dir, result)| Message::SftpOpDone(session_id, dir, result),
    )
}

// ---- the single progress bar ----------------------------------------------
//
// Every transfer shows on one bar, and its Cancel reaches whatever is on it.
// A transfer claims the bar only once its path is picked — a cancelled
// picker must not leave a bar behind that no transfer will ever finish — and
// only while no other transfer holds it. Its end takes the bar down only if
// it is still its own: after a Cancel another transfer may already hold it.

/// Whether the bar is taken: an upload job is running (a cancelled one keeps
/// it until its thread lets go), or a transfer on it has not finished.
fn bar_busy(bar: Option<&Arc<TransferProgress>>, upload_job_running: bool) -> bool {
    upload_job_running || bar.is_some_and(|p| !p.is_finished())
}

/// Put a fresh progress on the bar for a transfer about to start, and hand
/// it back — or `None`, leaving the bar alone, while it is [`bar_busy`].
fn claim_bar(
    bar: &mut Option<Arc<TransferProgress>>,
    upload_job_running: bool,
) -> Option<Arc<TransferProgress>> {
    if bar_busy(bar.as_ref(), upload_job_running) {
        return None;
    }
    let progress = Arc::new(TransferProgress::new());
    *bar = Some(progress.clone());
    Some(progress)
}

/// A transfer ended: take its progress off the bar, if the bar still shows
/// it. Anything else there belongs to a transfer that is still running.
fn release_bar(bar: &mut Option<Arc<TransferProgress>>, ended: &Arc<TransferProgress>) {
    if bar.as_ref().is_some_and(|p| Arc::ptr_eq(p, ended)) {
        *bar = None;
    }
}

/// How a transfer or an SFTP operation ended, as the user hears of it.
#[derive(Debug, PartialEq, Eq)]
enum OpEnd {
    /// Done, or cancelled from the progress bar: nothing to say.
    Quiet,
    /// Done, with entries left out (`is_skipped_report`): said, but as the
    /// completion it is, not as a failure.
    Skipped(String),
    Failed(String),
}

fn op_end(result: Result<(), String>) -> OpEnd {
    match result {
        Ok(()) => OpEnd::Quiet,
        Err(e) if e == TRANSFER_CANCELLED => OpEnd::Quiet,
        Err(e) if is_skipped_report(&e) => OpEnd::Skipped(e),
        Err(e) => OpEnd::Failed(e),
    }
}

/// Whether `message` is ssh/mod.rs's "N item(s) skipped" report: what a
/// recursive download or delete returns once everything else is done. Told
/// apart by its text, like `TRANSFER_CANCELLED`: the template in the current
/// language, with a number for `{count}`. Should the language change while
/// the operation runs, the report still goes up — as a failure.
fn is_skipped_report(message: &str) -> bool {
    let Some((head, tail)) = i18n::t("sftp.err.skipped_names").split_once("{count}") else {
        return false;
    };
    message
        .strip_prefix(head)
        .and_then(|rest| rest.strip_suffix(tail))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A transfer's or an SFTP operation's end, on the error dialog (see
/// [`OpEnd`]). True for a failure.
fn report_transfer_error(state: &mut NeoShell, result: Result<(), String>) -> bool {
    match op_end(result) {
        OpEnd::Quiet => false,
        OpEnd::Skipped(note) => {
            state.show_notice("notice.skipped_title", note);
            false
        }
        OpEnd::Failed(e) => {
            state.error_message = e;
            state.show_error_dialog = true;
            true
        }
    }
}

/// Start one upload — a file, or a whole folder through the recursive
/// variant — into `remote_dir`, on the single progress bar. Ends in
/// `UploadFinished`, which starts the next queued drop. Callers have made
/// sure the bar is free.
fn start_upload(
    state: &mut NeoShell,
    session_id: String,
    local: std::path::PathBuf,
    remote_dir: String,
) -> Task<Message> {
    let progress = Arc::new(TransferProgress::new());
    // A filesystem root has no name to give the remote copy. Its progress
    // never reaches the bar, so the end below takes nothing down.
    let Some(name) = local.file_name().map(|n| n.to_string_lossy().to_string()) else {
        let path = local.display().to_string();
        return Task::done(Message::UploadFinished(
            session_id,
            progress,
            Err(i18n::tf("transfer.bad_local", &[("path", &path)])),
        ));
    };
    let remote = join_remote_path(&remote_dir, &name);
    *progress.filename.lock() = name;
    state.transfer_progress = Some(progress.clone());
    state.upload_job_running = true;
    let ssh = state.ssh_manager.clone();
    let is_dir = local.is_dir();
    let local = local.to_string_lossy().to_string();
    Task::perform(
        async move {
            let sid = session_id.clone();
            let bar = progress.clone();
            let result = tokio::task::spawn_blocking(move || {
                if is_dir {
                    ssh.upload_dir_with_progress(&sid, &local, &remote, progress)
                } else {
                    ssh.upload_file_with_progress(&sid, &local, &remote, progress)
                }
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task: {}", e)));
            (session_id, bar, result)
        },
        |(session_id, bar, result)| Message::UploadFinished(session_id, bar, result),
    )
}

/// Start the next queued drop, unless a transfer already holds the bar (its
/// own `UploadFinished` will call back here).
fn start_next_drop(state: &mut NeoShell) -> Task<Message> {
    if state.transfer_busy() {
        return Task::none();
    }
    match state.drop_queue.pop_front() {
        Some(job) => start_upload(state, job.session_id, job.local, job.remote_dir),
        None => Task::none(),
    }
}

/// Where the download pickers open: Downloads, else Desktop, else home.
fn default_download_dir() -> std::path::PathBuf {
    dirs::download_dir()
        .or_else(dirs::desktop_dir)
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_local_basename_strips_remote_directory_components() {
        assert_eq!(
            safe_local_basename("report.tar.gz").as_deref(),
            Some("report.tar.gz")
        );
        assert_eq!(safe_local_basename("logs/app.log").as_deref(), Some("app.log"));
        // The two vectors: `..` traversal, and an absolute name that would
        // otherwise replace the download directory outright.
        assert_eq!(
            safe_local_basename("../../../../tmp/EVIL").as_deref(),
            Some("EVIL")
        );
        assert_eq!(
            safe_local_basename("/Users/victim/.zshrc").as_deref(),
            Some(".zshrc")
        );
        // Whatever comes back must never carry a separator on any platform.
        for name in ["..\\..\\evil.txt", "a/b/c", "/etc/passwd"] {
            if let Some(base) = safe_local_basename(name) {
                assert!(
                    !base.contains('/') && !base.contains('\\'),
                    "{name:?} produced {base:?}"
                );
            }
        }
    }

    #[test]
    fn safe_local_basename_rejects_degenerate_names() {
        for bad in ["", ".", "..", "/", "foo/..", "a\0b", "a\nb", "a\rb"] {
            assert_eq!(safe_local_basename(bad), None, "should reject {bad:?}");
        }
    }

    // ---- vault idle re-lock ------------------------------------------

    #[test]
    fn idle_lock_never_fires_when_disabled() {
        // 0 means "never", and must stay that way no matter how long the
        // session has been idle — this is the switch that keeps the feature
        // out of the way of users who do not want it.
        for secs in [0u64, 60, 3600, 86_400, 86_400 * 365] {
            assert!(
                !idle_lock_due(0, Duration::from_secs(secs)),
                "0 must never lock, idle={secs}s"
            );
        }
    }

    #[test]
    fn idle_lock_fires_at_the_timeout_not_before() {
        let t = 15;
        let deadline = Duration::from_secs(15 * 60);
        assert!(!idle_lock_due(t, Duration::ZERO));
        assert!(!idle_lock_due(t, deadline - Duration::from_secs(1)));
        // Inclusive: a tick that lands exactly on the deadline locks.
        assert!(idle_lock_due(t, deadline));
        assert!(idle_lock_due(t, deadline + Duration::from_secs(1)));
        // A one-minute timeout is the tightest the UI offers; the 20s poll
        // interval means it must still fire well inside two minutes.
        assert!(!idle_lock_due(1, Duration::from_secs(59)));
        assert!(idle_lock_due(1, Duration::from_secs(60)));
    }

    #[test]
    fn idle_lock_does_not_overflow_on_the_largest_timeout() {
        // `timeout_mins * 60` is the only arithmetic here; make sure the
        // widest step cannot wrap and turn "2 hours" into "immediately".
        let max = *LOCK_TIMEOUT_STEPS.last().unwrap();
        assert!(!idle_lock_due(max, Duration::from_secs(max as u64 * 60 - 1)));
        assert!(idle_lock_due(max, Duration::from_secs(max as u64 * 60)));
        // The widest value the type allows is ~8100 years of minutes; it has
        // to stay in range as u64 seconds rather than wrapping to a tiny
        // deadline. `state.lock_timeout_mins` is always clamped, so this is
        // defence against a future caller, not a reachable path today.
        assert!(!idle_lock_due(u32::MAX, Duration::from_secs(1)));
        assert!(!idle_lock_due(
            u32::MAX,
            Duration::from_secs(u32::MAX as u64 * 60 - 1)
        ));
        assert!(idle_lock_due(
            u32::MAX,
            Duration::from_secs(u32::MAX as u64 * 60)
        ));
    }

    #[test]
    fn clamp_lock_timeout_snaps_onto_a_real_step() {
        for step in LOCK_TIMEOUT_STEPS {
            assert_eq!(clamp_lock_timeout(step), step);
        }
        // A hand-edited or future-build value lands on a choice the UI can
        // actually display, rather than being silently dropped to 0 (= never).
        assert_eq!(clamp_lock_timeout(13), 15);
        assert_eq!(clamp_lock_timeout(45), 30);
        // A tie goes to the lower step — i.e. the shorter timeout, which is
        // the safe direction to round in.
        assert_eq!(clamp_lock_timeout(3), 1, "3 is 2 from both 1 and 5");
        assert_eq!(clamp_lock_timeout(10), 5, "10 is 5 from both 5 and 15");
        assert_eq!(clamp_lock_timeout(u32::MAX), 120);
        for weird in [2u32, 7, 44, 99, 1000, u32::MAX] {
            assert!(
                LOCK_TIMEOUT_STEPS.contains(&clamp_lock_timeout(weird)),
                "{weird} clamped off the step list"
            );
        }
    }

    #[test]
    fn cycle_lock_timeout_saturates_at_both_ends() {
        assert_eq!(cycle_lock_timeout(0, false), 0, "cannot go below Never");
        assert_eq!(cycle_lock_timeout(120, true), 120, "cannot go past the top");
        // Walking up from Never reaches the top and stops there.
        let mut v = 0;
        for _ in 0..LOCK_TIMEOUT_STEPS.len() * 2 {
            v = cycle_lock_timeout(v, true);
        }
        assert_eq!(v, 120);
        // And back down to Never.
        for _ in 0..LOCK_TIMEOUT_STEPS.len() * 2 {
            v = cycle_lock_timeout(v, false);
        }
        assert_eq!(v, 0);
        // Stepping from an off-list value still produces an on-list one.
        assert_eq!(cycle_lock_timeout(13, true), 30);
        assert_eq!(cycle_lock_timeout(13, false), 5);
    }

    #[test]
    fn locking_scrubs_plaintext_secrets_out_of_open_forms() {
        let mut conn = ConnectionFormData {
            name: "prod".into(),
            host: "10.0.0.1".into(),
            username: "root".into(),
            password: "hunter2".into(),
            passphrase: "keypass".into(),
            private_key: "/home/me/.ssh/id_ed25519".into(),
            ..Default::default()
        };
        let mut proxy = ProxyFormData {
            name: "bastion".into(),
            password: "proxypw".into(),
            passphrase: "proxypass".into(),
            private_key: "/home/me/.ssh/jump".into(),
            ..Default::default()
        };
        let mut tunnel = TunnelFormData {
            name: "db".into(),
            password: "tunnelpw".into(),
            passphrase: "tunnelpass".into(),
            private_key: "/home/me/.ssh/tunnel".into(),
            forwards_text: "5432:127.0.0.1:5432".into(),
            ..Default::default()
        };

        scrub_form_secrets(&mut conn, &mut proxy, &mut tunnel);

        for secret in [
            &conn.password, &conn.passphrase,
            &proxy.password, &proxy.passphrase,
            &tunnel.password, &tunnel.passphrase,
        ] {
            assert!(secret.is_empty(), "a secret survived the lock: {secret:?}");
        }
        // Non-secret fields are left alone so re-unlocking does not throw the
        // user's half-finished form away. A private-key *path* is not a
        // secret; the key material never enters these structs.
        assert_eq!(conn.host, "10.0.0.1");
        assert_eq!(conn.private_key, "/home/me/.ssh/id_ed25519");
        assert_eq!(proxy.name, "bastion");
        assert_eq!(proxy.private_key, "/home/me/.ssh/jump");
        assert_eq!(tunnel.forwards_text, "5432:127.0.0.1:5432");
        assert_eq!(tunnel.private_key, "/home/me/.ssh/tunnel");
    }

    #[test]
    fn lock_timeout_label_reads_as_a_setting() {
        i18n::set_locale("en");
        assert_eq!(lock_timeout_label(0), "Never");
        assert_eq!(lock_timeout_label(15), "15 min");
        // The {n} placeholder must actually be substituted, in both locales.
        i18n::set_locale("zh-CN");
        let zh = lock_timeout_label(30);
        assert!(!zh.contains("{n}"), "unsubstituted placeholder: {zh}");
        assert!(zh.contains("30"), "{zh}");
        i18n::set_locale("en");
    }

    /// The forward rules the edit form renders are re-parsed on save, so the
    /// text it produces has to survive the round trip. Rendering the three
    /// fields by hand silently turned an `R:`/`D:` rule into a local one.
    #[test]
    fn tunnel_form_renders_forwards_in_parseable_syntax() {
        use crate::tunnel::{ForwardKind, ForwardRule};
        let rules = vec![
            ForwardRule { local_port: 8080, remote_host: "10.0.0.5".into(), remote_port: 80, kind: ForwardKind::Local },
            ForwardRule { local_port: 3000, remote_host: "0.0.0.0".into(), remote_port: 8080, kind: ForwardKind::Remote },
            ForwardRule { local_port: 1080, remote_host: String::new(), remote_port: 0, kind: ForwardKind::Dynamic },
        ];
        // Exactly what `Message::ShowTunnelForm` puts in `forwards_text`.
        let text = rules.iter().map(|f| f.spec()).collect::<Vec<_>>().join("\n");
        let reparsed: Vec<ForwardRule> = text
            .lines()
            .map(|l| ForwardRule::parse(l.trim()).expect("must re-parse"))
            .collect();
        assert_eq!(reparsed, rules, "SaveTunnel would have rewritten the rules");
    }

    // ---- UI pass -----------------------------------------------------

    /// Every filled button must stay readable whatever colour the theme puts
    /// under it — every shipped preset's accent and danger, plus the corners
    /// of the colour space a user can dial in with the RGB sliders.
    #[test]
    fn filled_buttons_meet_wcag_aa_at_rest_and_on_hover() {
        let mut bases: Vec<(String, Color)> = crate::ui::theme_config::PRESETS
            .iter()
            .flat_map(|(name, cfg)| {
                [
                    (format!("{name} accent"), cfg.accent.to_color()),
                    (format!("{name} danger"), cfg.danger.to_color()),
                ]
            })
            .collect();
        for (name, c) in [
            ("white", Color::WHITE),
            ("black", Color::BLACK),
            ("red", Color::from_rgb8(255, 0, 0)),
            ("green", Color::from_rgb8(0, 255, 0)),
            ("blue", Color::from_rgb8(0, 0, 255)),
            ("yellow", Color::from_rgb8(255, 255, 0)),
            ("mid grey", Color::from_rgb8(119, 119, 119)),
            ("slate", Color::from_rgb8(100, 116, 139)),
        ] {
            bases.push((name.to_string(), c));
        }
        for (name, base) in bases {
            let (fill, label) = fill_and_label(base);
            let rest = contrast_ratio(label, fill);
            let hover = contrast_ratio(label, mix(fill, Color::WHITE, HOVER_LIFT));
            assert!(rest >= 4.5, "{name}: label on fill is {rest:.2}:1");
            assert!(hover >= 4.5, "{name}: label on hover fill is {hover:.2}:1");
        }
    }

    /// The shipped accent keeps white text and only darkens as far as AA
    /// needs — it must still read as the same indigo, not a new colour.
    #[test]
    fn shipped_accent_keeps_white_text_and_its_hue() {
        let accent = theme::ACCENT;
        assert!(
            contrast_ratio(theme::TEXT_PRIMARY, accent) < 4.5,
            "fixture: TEXT_PRIMARY on ACCENT was the failing pair"
        );
        let (fill, label) = fill_and_label(accent);
        assert_eq!(label, Color::WHITE);
        assert!(rel_luminance(fill) < rel_luminance(accent), "fill must be darker");
        for (f, a) in [(fill.r, accent.r), (fill.g, accent.g), (fill.b, accent.b)] {
            assert!(f >= a * 0.8, "darkened more than 20%: {fill:?} from {accent:?}");
        }
    }

    #[test]
    fn mix_and_tint_never_leave_the_gamut() {
        let c = mix(Color::from_rgb(0.9, 0.5, 0.1), Color::WHITE, 7.0);
        assert_eq!(c, Color::WHITE, "t is clamped to 1");
        let c = mix(theme::ACCENT, Color::BLACK, -3.0);
        assert_eq!(c, theme::ACCENT, "t is clamped to 0");
        assert_eq!(tint(theme::ACCENT, 1.7).a, 1.0);
        assert_eq!(tint(theme::ACCENT, -1.0).a, 0.0);
        assert!((contrast_ratio(Color::WHITE, Color::BLACK) - 21.0).abs() < 0.01);
    }

    /// `ConnectionConfig.color` is free text from the vault; only a real
    /// #rrggbb may draw a rail.
    #[test]
    fn connection_color_tag_parses_only_rrggbb() {
        assert_eq!(parse_hex_color("#ff8800"), Some(Color::from_rgb8(0xff, 0x88, 0x00)));
        assert_eq!(parse_hex_color("22C55E"), Some(Color::from_rgb8(0x22, 0xc5, 0x5e)));
        assert_eq!(parse_hex_color("  #0a0B0c "), Some(Color::from_rgb8(0x0a, 0x0b, 0x0c)));
        for bad in ["", "#", "#fff", "#ff88001", "#gg0000", "red", "#ff 880", "##ff8800", "+ff8800"] {
            assert_eq!(parse_hex_color(bad), None, "{bad:?} must not parse");
        }
    }

    /// One z-order drives both what view_main draws and what ESC closes; it
    /// must list every overlay exactly once and keep the placements its doc
    /// comment promises.
    #[test]
    fn overlay_z_order_is_complete_and_puts_alerts_on_top() {
        use Overlay::*;
        let mut seen = HashSet::new();
        for o in Overlay::Z_ORDER {
            assert!(seen.insert(o), "{o:?} listed twice");
        }
        // Exhaustive on purpose: a new variant fails to compile here until
        // it is added below — and then to Z_ORDER, or this test fails.
        let every = |o: Overlay| match o {
            Palette | ConfirmDelete | AuthPrompt | ConfirmAction | LogViewer | ErrorDialog
            | ProcessDetail | Editor | NetworkDetail | ConnectDialog | History | ProxyManager
            | TunnelManager | TabRename | SftpInput | KeyManager | ShortcutsHelp | Broadcast
            | Snippets | About | Settings | ConnectionForm => o,
        };
        for o in [
            Palette, ConfirmDelete, AuthPrompt, ConfirmAction, LogViewer, ErrorDialog,
            ProcessDetail, Editor, NetworkDetail, ConnectDialog, History, ProxyManager,
            TunnelManager, TabRename, SftpInput, KeyManager, ShortcutsHelp, Broadcast, Snippets,
            About, Settings, ConnectionForm,
        ] {
            assert!(seen.contains(&every(o)), "{o:?} missing from Z_ORDER");
        }

        let z = |o: Overlay| Overlay::Z_ORDER.iter().position(|&x| x == o).unwrap();
        assert_eq!(z(Palette), 0, "the palette is summoned over anything");
        // A failure raised inside a panel must show over that panel.
        for panel in [ProxyManager, TunnelManager, Editor, KeyManager, Settings, ConnectionForm, ConnectDialog] {
            assert!(z(ErrorDialog) < z(panel), "error dialog hidden under {panel:?}");
        }
        // "View log" in the error dialog opens the log viewer over it.
        assert!(z(LogViewer) < z(ErrorDialog));
        // An SSH thread is blocked on the auth prompt, and a test or a key
        // deploy raises it from inside a panel: it must clear all of them.
        for panel in [
            ErrorDialog, ProcessDetail, Editor, ConnectDialog, KeyManager, Settings,
            ConnectionForm, SftpInput,
        ] {
            assert!(z(AuthPrompt) < z(panel), "auth prompt hidden under {panel:?}");
        }
        // The kill confirmation is opened from the process popup.
        assert!(z(ConfirmAction) < z(ProcessDetail));
        // A failed SFTP call reports over the dialog that asked for it.
        assert!(z(ErrorDialog) < z(SftpInput));
    }

    // ---- feature wiring ------------------------------------------------

    fn record(cmd: &str, timestamp: u64) -> CmdRecord {
        CmdRecord {
            cmd: cmd.to_string(),
            session_title: "root@web:22".to_string(),
            host: "web".to_string(),
            timestamp,
        }
    }

    fn snippet(body: &str) -> Snippet {
        Snippet { id: body.to_string(), name: body.to_string(), body: body.to_string() }
    }

    #[test]
    fn quick_cmd_matches_newest_history_first_then_snippets() {
        let history = vec![
            record("git status", 1),
            record("git log --oneline", 2),
            record("ls -la", 3),
            record("git status", 4), // run again: counts as the newest
        ];
        let snippets = vec![snippet("git pull --rebase"), snippet("docker ps")];
        assert_eq!(
            quick_cmd_matches("git", &history, &snippets),
            vec!["git status", "git log --oneline", "git pull --rebase"],
            "newest first, de-duplicated, snippets after history"
        );
        // Case matters to a shell.
        assert!(quick_cmd_matches("GIT", &history, &snippets).is_empty());
    }

    #[test]
    fn quick_cmd_matches_caps_and_skips_what_it_cannot_offer() {
        let history: Vec<CmdRecord> = (0..20).map(|i| record(&format!("echo {}", i), i)).collect();
        let offered = quick_cmd_matches("echo", &history, &[]);
        assert_eq!(offered.len(), QUICK_CMD_SUGGESTIONS);
        assert_eq!(offered[0], "echo 19", "most recent first");
        // Nothing for an empty input, and never the text exactly as typed.
        assert!(quick_cmd_matches("", &history, &[]).is_empty());
        assert!(quick_cmd_matches("   ", &history, &[]).is_empty());
        assert!(quick_cmd_matches("echo 19", &history, &[]).is_empty());
        // A multi-line snippet cannot go into a one-line input.
        let multi = vec![snippet("cd /srv\nmake deploy"), snippet("cd /srv && make\n")];
        assert_eq!(quick_cmd_matches("cd", &[], &multi), vec!["cd /srv && make"]);
    }

    #[test]
    fn autocomplete_takes_only_plain_tab_and_down() {
        use keyboard::key::Named;
        let none = keyboard::Modifiers::default();
        assert!(is_autocomplete_key(&keyboard::Key::Named(Named::Tab), &none));
        assert!(is_autocomplete_key(&keyboard::Key::Named(Named::ArrowDown), &none));
        assert!(!is_autocomplete_key(&keyboard::Key::Named(Named::ArrowUp), &none));
        // Shift+Tab, Ctrl+Tab (tab switching) and Alt+Down stay with the terminal.
        for m in [keyboard::Modifiers::SHIFT, keyboard::Modifiers::CTRL, keyboard::Modifiers::ALT] {
            assert!(!is_autocomplete_key(&keyboard::Key::Named(Named::Tab), &m));
            assert!(!is_autocomplete_key(&keyboard::Key::Named(Named::ArrowDown), &m));
        }
    }

    /// `history.json` inside a directory of its own, so parallel tests never
    /// share one and each can remove its directory when done.
    fn scratch_history(test: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!("neoshell-app-test-{}-{}", std::process::id(), test))
            .join("history.json")
    }

    fn remove_scratch(path: &std::path::Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn history_loader_reads_missing_or_damaged_files_as_empty() {
        let path = scratch_history("damaged");
        remove_scratch(&path);
        assert!(load_history_from(&path).is_empty(), "missing file");
        crate::storage::write_private(&path, b"{ not json").expect("write");
        assert!(load_history_from(&path).is_empty());
        // A record written before a field existed still loads.
        crate::storage::write_private(&path, br#"[{"cmd":"uptime"}]"#).expect("write");
        let loaded = load_history_from(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].cmd, "uptime");
        assert_eq!(loaded[0].timestamp, 0);
        remove_scratch(&path);
    }

    /// One unlocked vault shared by the history tests, so Argon2id runs once.
    /// Its file is deleted at once: sealing only needs the key, which stays in
    /// memory.
    fn history_vault() -> &'static ConnectionStore {
        shared_history_vault()
    }

    /// `history_vault`, in the `Arc` the app holds its store in.
    fn shared_history_vault() -> &'static Arc<ConnectionStore> {
        static VAULT: std::sync::OnceLock<Arc<ConnectionStore>> = std::sync::OnceLock::new();
        VAULT.get_or_init(|| {
            let dir = std::env::temp_dir()
                .join(format!("neoshell-app-test-{}-vault", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("vault dir");
            let store = ConnectionStore::with_vault_path(dir.join("vault.json"));
            store.set_master_password("history tests").expect("vault");
            let _ = std::fs::remove_dir_all(&dir);
            Arc::new(store)
        })
    }

    /// A `HistoryFile` over a directory of its own, removed on drop.
    struct HistoryScratch(std::path::PathBuf);

    impl HistoryScratch {
        fn new(test: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "neoshell-app-test-{}-sealed-{}",
                std::process::id(),
                test
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            HistoryScratch(dir)
        }

        fn file(&self) -> Arc<HistoryFile> {
            Arc::new(HistoryFile::at(&self.0))
        }

        /// Every name in the directory, sorted.
        fn names(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.0)
                .expect("read dir")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for HistoryScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Seal `records` and write them, as a paced flush does.
    fn seal_to_disk(file: &Arc<HistoryFile>, records: &[CmdRecord]) {
        HistoryFile::snapshot(file, history_vault(), records, false, false)
            .expect("seal")
            .run()
            .expect("write");
    }

    #[test]
    fn sealed_history_is_private_opaque_and_keeps_the_newest_records() {
        let s = HistoryScratch::new("roundtrip");
        let file = s.file();
        let list: Vec<CmdRecord> = (0..HISTORY_MAX as u64 + 20)
            .map(|i| record(&format!("mysql -phunter{}", i), 1_700_000_000 + i))
            .collect();
        seal_to_disk(&file, &list);

        // Neither base64 nor compact JSON ever holds a space.
        let raw = std::fs::read_to_string(&file.sealed).expect("sealed file");
        assert!(
            !raw.contains("mysql -p"),
            "command lines must not reach disk in the clear"
        );
        assert!(serde_json::from_str::<crate::storage::EncryptedBlob>(&raw).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file.sealed)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "history.enc must be owner-only");
        }
        assert_eq!(s.names(), ["history.enc"], "no staging file left behind");

        let load = file.load(history_vault());
        assert!(load.writable && !load.legacy_found);
        let loaded = load.records;
        assert_eq!(loaded.len(), HISTORY_MAX, "capped on the way out");
        assert_eq!(
            loaded.first().map(|r| r.cmd.as_str()),
            Some("mysql -phunter20"),
            "oldest dropped"
        );
        let last = loaded.last().expect("non-empty");
        assert_eq!(last.cmd, format!("mysql -phunter{}", HISTORY_MAX + 19));
        assert_eq!(last.host, "web");
        assert_eq!(last.timestamp, 1_700_000_000 + HISTORY_MAX as u64 + 19);
    }

    #[test]
    fn a_locked_vault_neither_reads_nor_moves_any_history_file() {
        let s = HistoryScratch::new("locked");
        let file = s.file();
        seal_to_disk(&file, &[record("uptime", 1)]);
        let legacy = serde_json::to_vec(&[record("export TOKEN=abc", 2)]).expect("json");
        crate::storage::write_private(&file.legacy, &legacy).expect("legacy");
        let sealed = std::fs::read(&file.sealed).expect("sealed file");

        // Never unlocked: the key is not in memory.
        let locked = ConnectionStore::with_vault_path(s.0.join("vault.json"));
        let load = file.load(&locked);
        assert!(load.records.is_empty(), "nothing is read before the unlock");
        assert!(!load.writable && !load.legacy_found);
        assert!(HistoryFile::snapshot(&file, &locked, &[record("ls", 3)], false, false).is_err());

        // Locked is not damaged: both files are still there, untouched.
        assert_eq!(std::fs::read(&file.sealed).expect("sealed file"), sealed);
        assert_eq!(std::fs::read(&file.legacy).expect("legacy file"), legacy);
        assert_eq!(s.names(), ["history.enc", "history.json"]);
    }

    #[test]
    fn unreadable_sealed_history_is_set_aside_never_written_over() {
        let s = HistoryScratch::new("unreadable");
        let file = s.file();
        let aside = s.0.join("history.enc.unreadable");

        // Tampered: one byte of real ciphertext changed.
        seal_to_disk(&file, &[record("uptime", 1)]);
        let mut blob: crate::storage::EncryptedBlob =
            serde_json::from_slice(&std::fs::read(&file.sealed).expect("sealed")).expect("blob");
        let flipped = if blob.data.starts_with('A') { "B" } else { "A" };
        blob.data.replace_range(..1, flipped);
        let tampered = serde_json::to_vec(&blob).expect("json");
        crate::storage::write_private(&file.sealed, &tampered).expect("write");

        let load = file.load(history_vault());
        assert!(load.records.is_empty());
        assert!(load.writable, "the path is free once the old file is aside");
        assert_eq!(std::fs::read(&aside).expect("set aside"), tampered);
        assert!(!file.sealed.exists());

        // Malformed: a nonce of the wrong length, which must come back as an
        // error rather than a panic in the cipher. It goes beside the first
        // one, not over it.
        let junk = br#"{"nonce":"AAAA","data":"AAAA"}"#;
        crate::storage::write_private(&file.sealed, junk).expect("write");
        assert!(file.load(history_vault()).writable);
        assert_eq!(std::fs::read(&aside).expect("first one kept"), tampered);
        assert_eq!(
            std::fs::read(s.0.join("history.enc.unreadable.1")).expect("set aside"),
            junk
        );

        // The next write starts a fresh file beside them.
        seal_to_disk(&file, &[record("ls", 2)]);
        assert_eq!(file.load(history_vault()).records, vec![record("ls", 2)]);
        assert_eq!(
            s.names(),
            [
                "history.enc",
                "history.enc.unreadable",
                "history.enc.unreadable.1"
            ]
        );
    }

    #[test]
    fn cleartext_history_is_imported_once_then_scrubbed_away() {
        let s = HistoryScratch::new("legacy");
        let file = s.file();
        // What a build before the sealed history left behind.
        let old = [record("export TOKEN=abc", 100), record("uptime", 300)];
        crate::storage::write_private(&file.legacy, &serde_json::to_vec(&old).expect("json"))
            .expect("legacy");
        seal_to_disk(&file, &[record("ls", 200)]);

        let merged = vec![
            record("export TOKEN=abc", 100),
            record("ls", 200),
            record("uptime", 300),
        ];
        let load = file.load(history_vault());
        assert!(load.writable && load.legacy_found);
        assert_eq!(load.records, merged, "merged, oldest first");

        // The write `unlock_history` sends off.
        HistoryFile::snapshot(&file, history_vault(), &load.records, false, true)
            .expect("seal")
            .run()
            .expect("write");
        assert_eq!(s.names(), ["history.enc"], "the cleartext file is gone");
        let raw = std::fs::read_to_string(&file.sealed).expect("sealed");
        assert!(!raw.contains("TOKEN="));

        let again = file.load(history_vault());
        assert!(!again.legacy_found, "one-shot");
        assert_eq!(again.records, merged);
    }

    #[cfg(unix)]
    #[test]
    fn retiring_the_cleartext_file_never_writes_through_a_link() {
        let s = HistoryScratch::new("link");
        let file = s.file();
        let target = s.0.join("elsewhere.txt");
        std::fs::write(&target, b"not ours").expect("target");
        std::os::unix::fs::symlink(&target, &file.legacy).expect("symlink");
        retire_legacy_history(&file.legacy).expect("retire");
        assert!(
            std::fs::symlink_metadata(&file.legacy).is_err(),
            "the link is gone"
        );
        assert_eq!(std::fs::read(&target).expect("target"), b"not ours");
    }

    #[test]
    fn an_interrupted_import_does_not_duplicate_records() {
        let s = HistoryScratch::new("reimport");
        let file = s.file();
        let both = vec![record("ls", 100), record("uptime", 200)];
        // The sealed write landed; the cleartext file was never removed.
        seal_to_disk(&file, &both);
        crate::storage::write_private(&file.legacy, &serde_json::to_vec(&both).expect("json"))
            .expect("legacy");
        let load = file.load(history_vault());
        assert!(load.legacy_found);
        assert_eq!(load.records, both);
    }

    #[test]
    fn a_flush_that_runs_late_cannot_undo_a_clear() {
        let s = HistoryScratch::new("order");
        let file = s.file();
        let flush = HistoryFile::snapshot(
            &file,
            history_vault(),
            &[record("ls", 1), record("mysql -phunter2", 2)],
            false,
            false,
        )
        .expect("seal");
        let clear = HistoryFile::snapshot(&file, history_vault(), &[], true, true).expect("seal");
        // The blocking pool runs them in whatever order it likes.
        clear.run().expect("write");
        flush
            .run()
            .expect("a stale snapshot is dropped, not an error");
        assert!(file.load(history_vault()).records.is_empty());
    }

    #[test]
    fn the_unlock_time_load_waits_for_a_write_still_in_flight() {
        let s = HistoryScratch::new("settle");
        let file = s.file();
        let job = HistoryFile::snapshot(&file, history_vault(), &[record("ls", 1)], false, false)
            .expect("seal");
        assert!(
            !file.wait_settled(Duration::from_millis(20)),
            "the write is still out"
        );
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            job.run()
        });
        // Blocks until the write lands, then reads what it wrote.
        let load = file.load(history_vault());
        writer.join().expect("writer thread").expect("write");
        assert!(load.writable);
        assert_eq!(load.records, vec![record("ls", 1)]);

        // A snapshot dropped without running settles too.
        drop(HistoryFile::snapshot(&file, history_vault(), &[], false, false).expect("seal"));
        assert!(file.wait_settled(Duration::ZERO));
    }

    #[test]
    fn locking_wipes_the_history_and_seals_what_disk_has_not_seen() {
        let s = HistoryScratch::new("lock");
        let file = s.file();
        let typed = vec![record("ls", 1), record("mysql -phunter2", 2)];
        let mut records = typed.clone();
        let mut sync = HistorySync {
            dirty: true,
            loaded: true,
            flushed_at: None,
            ..HistorySync::default()
        };

        let job = lock_history(&file, history_vault(), &mut records, &mut sync);
        assert!(records.is_empty(), "no record survives the lock in memory");
        assert!(!sync.dirty && !sync.loaded);
        let much_later = std::time::Instant::now() + Duration::from_secs(3600);
        assert!(
            !history_flush_due(&sync, much_later),
            "nothing is written while locked"
        );
        // The unsaved records were sealed before the key went, not lost.
        job.expect("unsaved records are sealed")
            .run()
            .expect("write");
        assert_eq!(file.load(history_vault()).records, typed);

        // Nothing unsaved: nothing to write, and still wiped.
        let mut records = typed.clone();
        let mut sync = HistorySync {
            dirty: false,
            loaded: true,
            flushed_at: None,
            ..HistorySync::default()
        };
        assert!(lock_history(&file, history_vault(), &mut records, &mut sync).is_none());
        assert!(records.is_empty());

        // Never loaded: wiped, and never written over a file it did not see.
        let mut records = typed;
        let mut sync = HistorySync {
            dirty: true,
            loaded: false,
            flushed_at: None,
            ..HistorySync::default()
        };
        assert!(lock_history(&file, history_vault(), &mut records, &mut sync).is_none());
        assert!(records.is_empty());
    }

    #[test]
    fn only_a_clear_writes_before_the_file_was_loaded() {
        let unloaded = HistorySync::default();
        assert!(
            !history_write_allowed(&unloaded, false),
            "would write over unseen records"
        );
        assert!(
            history_write_allowed(&unloaded, true),
            "a clear replaces them on purpose"
        );
        let loaded = HistorySync {
            loaded: true,
            ..HistorySync::default()
        };
        assert!(history_write_allowed(&loaded, false));
        assert!(history_write_allowed(&loaded, true));
    }

    #[test]
    fn unlocking_hands_the_history_load_to_a_blocking_thread() {
        let s = HistoryScratch::new("offthread");
        let file = s.file();
        // The lock's write, still on its way to disk.
        let write = HistoryFile::snapshot(&file, history_vault(), &[record("ls", 1)], false, false)
            .expect("seal");
        let mut sync = HistorySync::default();
        let started = std::time::Instant::now();
        let (seq, load) = start_history_load(&file, shared_history_vault().clone(), &mut sync);
        // What `update` runs. It used to wait right here, for as long as
        // HISTORY_SETTLE_WAIT, with the window frozen.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the UI thread waited for the write"
        );
        assert_eq!(
            sync.pending_load,
            Some(PendingLoad {
                seq,
                cleared: false
            })
        );
        // The blocking thread waits instead, then reads what the write left.
        let loader = std::thread::spawn(load);
        std::thread::sleep(Duration::from_millis(100));
        assert!(!loader.is_finished(), "read before the write landed");
        write.run().expect("write");
        let load = loader.join().expect("loader thread");
        assert!(load.writable && !load.unsettled);
        assert_eq!(load.records, vec![record("ls", 1)]);
    }

    #[test]
    fn commands_typed_while_the_history_loads_are_kept_after_the_saved_ones() {
        let s = HistoryScratch::new("typed");
        let mut sync = HistorySync::default();
        let (seq, _) = start_history_load(&s.file(), shared_history_vault().clone(), &mut sync);
        // Typed after the unlock, before the load came back.
        let mut records = vec![record("uptime", 200)];
        sync.dirty = true;
        let saved = HistoryLoad {
            records: vec![record("ls", 100)],
            writable: true,
            ..HistoryLoad::default()
        };
        let landed = land_history_load(&mut records, &mut sync, seq, saved).expect("wanted");
        assert_eq!(
            landed,
            LoadLanded {
                import_legacy: false,
                warning: None
            }
        );
        assert_eq!(records, vec![record("ls", 100), record("uptime", 200)]);
        assert!(sync.loaded, "writes may go out now");
        assert!(sync.dirty, "the typed line is not on disk yet");
        assert_eq!(sync.pending_load, None);

        // Nothing typed meanwhile: nothing new to write, but an imported
        // cleartext file is sealed at once.
        let (seq, _) = start_history_load(&s.file(), shared_history_vault().clone(), &mut sync);
        let mut records = Vec::new();
        let saved = HistoryLoad {
            records: vec![record("ls", 100)],
            writable: true,
            legacy_found: true,
            ..HistoryLoad::default()
        };
        let landed = land_history_load(&mut records, &mut sync, seq, saved).expect("wanted");
        assert!(landed.import_legacy);
        assert!(!sync.dirty);
    }

    #[test]
    fn a_load_overtaken_by_a_lock_or_a_later_unlock_never_lands() {
        let s = HistoryScratch::new("stale");
        let file = s.file();
        let vault = shared_history_vault();
        let saved = || HistoryLoad {
            records: vec![record("mysql -phunter2", 1)],
            writable: true,
            ..HistoryLoad::default()
        };

        // Locked before the load came back.
        let mut sync = HistorySync::default();
        let (seq, _) = start_history_load(&file, vault.clone(), &mut sync);
        let mut records = vec![record("whoami", 5)];
        sync.dirty = true;
        let locks = file.locks.load(Ordering::SeqCst);
        assert!(
            lock_history(&file, vault, &mut records, &mut sync).is_none(),
            "never loaded: nothing is written"
        );
        assert_eq!(file.locks.load(Ordering::SeqCst), locks + 1);
        assert_eq!(
            land_history_load(&mut records, &mut sync, seq, saved()),
            None
        );
        assert!(records.is_empty(), "nothing comes back under the lock");
        assert!(!sync.loaded && !sync.dirty);

        // Two unlocks in a row: only the second load lands.
        let (first, _) = start_history_load(&file, vault.clone(), &mut sync);
        let (second, _) = start_history_load(&file, vault.clone(), &mut sync);
        assert_eq!(
            land_history_load(&mut records, &mut sync, first, saved()),
            None
        );
        assert!(land_history_load(&mut records, &mut sync, second, saved()).is_some());
        assert_eq!(records, vec![record("mysql -phunter2", 1)]);
        // Loading again what memory already holds does not double it.
        let (third, _) = start_history_load(&file, vault.clone(), &mut sync);
        assert!(land_history_load(&mut records, &mut sync, third, saved()).is_some());
        assert_eq!(records, vec![record("mysql -phunter2", 1)]);
    }

    #[test]
    fn a_clear_while_the_history_loads_is_not_undone_when_it_lands() {
        let s = HistoryScratch::new("clearload");
        let mut sync = HistorySync::default();
        let (seq, _) = start_history_load(&s.file(), shared_history_vault().clone(), &mut sync);
        let mut records = vec![record("ls", 10)];
        clear_history(&mut records, &mut sync);
        assert!(records.is_empty() && !sync.dirty);
        records.push(record("pwd", 20));
        sync.dirty = true;
        // Read before the clear reached the disk, a cleartext import with it.
        let stale = HistoryLoad {
            records: vec![record("mysql -phunter2", 1)],
            writable: true,
            legacy_found: true,
            ..HistoryLoad::default()
        };
        let landed = land_history_load(&mut records, &mut sync, seq, stale).expect("wanted");
        assert_eq!(records, vec![record("pwd", 20)]);
        assert!(!landed.import_legacy, "the clear's own write retires it");
        assert!(sync.loaded && sync.dirty);
    }

    #[test]
    fn history_that_cannot_be_saved_is_said_not_only_logged() {
        let s = HistoryScratch::new("stuck");
        let file = s.file();
        seal_to_disk(&file, &[record("ls", 1)]);
        // A write that does not land in time.
        let stuck = HistoryFile::snapshot(
            &file,
            history_vault(),
            &[record("ls", 1), record("pwd", 2)],
            false,
            false,
        )
        .expect("seal");
        let load = file.load_within(history_vault(), Duration::from_millis(20));
        assert!(!load.writable && load.unsettled);
        assert_eq!(
            load.records,
            vec![record("ls", 1)],
            "what is there still shows"
        );
        drop(stuck);

        let mut sync = HistorySync::default();
        let (seq, _) = start_history_load(&file, shared_history_vault().clone(), &mut sync);
        let landed = land_history_load(&mut Vec::new(), &mut sync, seq, load).expect("wanted");
        assert_eq!(landed.warning, Some("history.warn.unsettled"));
        assert!(!sync.loaded, "nothing is written over the file");

        // Unreadable, and not moved aside either.
        let (seq, _) = start_history_load(&file, shared_history_vault().clone(), &mut sync);
        let landed = land_history_load(&mut Vec::new(), &mut sync, seq, HistoryLoad::default());
        assert_eq!(
            landed.and_then(|l| l.warning),
            Some("history.warn.unreadable")
        );
        for key in [
            "history.warn.title",
            "history.warn.unsettled",
            "history.warn.unreadable",
        ] {
            assert_ne!(i18n::t(key), "???", "{key}");
        }
    }

    #[test]
    fn a_lock_while_the_history_loads_is_no_reason_to_set_the_file_aside() {
        let s = HistoryScratch::new("lockmid");
        let file = s.file();
        // A vault of its own: this test locks it.
        let vault = Arc::new(ConnectionStore::with_vault_path(s.0.join("vault.json")));
        vault
            .set_master_password("history lock test")
            .expect("vault");
        HistoryFile::snapshot(&file, &vault, &[record("ls", 1)], false, false)
            .expect("seal")
            .run()
            .expect("write");
        let sealed = std::fs::read(&file.sealed).expect("sealed file");
        // A write still out keeps the load waiting, past its check that the
        // vault is open...
        let flush =
            HistoryFile::snapshot(&file, &vault, &[record("ls", 1)], false, false).expect("seal");
        let mut sync = HistorySync::default();
        let (seq, load) = start_history_load(&file, vault.clone(), &mut sync);
        let loader = std::thread::spawn(load);
        std::thread::sleep(Duration::from_millis(100));
        // ...while the lock lands, and the key goes.
        let mut records = Vec::new();
        assert!(lock_history(&file, &vault, &mut records, &mut sync).is_none());
        vault.lock();
        drop(flush);
        let load = loader.join().expect("loader thread");
        assert!(!load.writable && load.records.is_empty());
        assert_eq!(
            std::fs::read(&file.sealed).expect("left in place"),
            sealed,
            "a file that only lacked the key was set aside as damaged"
        );
        assert!(!s.0.join("history.enc.unreadable").exists());
        assert_eq!(land_history_load(&mut records, &mut sync, seq, load), None);
    }

    #[test]
    fn a_notice_title_goes_with_its_own_message_only() {
        let note = i18n::tf("sftp.err.skipped_names", &[("count", "3")]);
        let bound = Some((fingerprint(&note), "notice.skipped_title"));
        assert_eq!(error_dialog_title(bound, &note), "notice.skipped_title");
        // An error put up afterwards, by any path, is titled as ever.
        assert_eq!(error_dialog_title(bound, "Connection refused"), "err.title");
        assert_eq!(error_dialog_title(None, &note), "err.title");
    }

    #[test]
    fn a_parked_session_gets_one_reconnect_per_press() {
        let parked = i18n::t("exec.err.needs_reconnect");
        assert!(exec_parked(parked));
        assert!(!exec_parked("Failed to open exec channel: timed out"));
        let mut m = ParkedMonitors::default();
        assert!(m.park("s1"), "the first failure parks it");
        assert!(!m.park("s1"), "the next ticks add nothing");
        assert!(m.begin_resume("s1"), "the press sends the reconnect");
        assert!(
            !m.begin_resume("s1"),
            "a second press while it is out sends nothing"
        );
        assert!(!m.park("s1"));
        assert_eq!(
            m.get("s1").map(|p| p.resuming),
            Some(true),
            "a tick failing meanwhile does not re-arm the button"
        );
        // Dismissed, or a wrong code: still parked, the button back, the
        // reason on the panel.
        assert!(!m.finish_resume("s1", Err("no answer".into())));
        assert_eq!(
            m.get("s1"),
            Some(&ParkedMonitor {
                resuming: false,
                error: Some("no answer".into())
            })
        );
        assert!(m.begin_resume("s1"));
        assert_eq!(m.get("s1").and_then(|p| p.error.clone()), None);
        assert!(m.finish_resume("s1", Ok(())), "re-opened");
        assert!(m.get("s1").is_none());
        assert!(!m.begin_resume("s1"), "nothing parked, nothing sent");
        // Data from a fetch, or the session going, clears it as well.
        m.park("s2");
        m.unpark("s2");
        assert!(m.get("s2").is_none());
        for key in [
            "monitor.parked",
            "monitor.reconnect",
            "monitor.reconnecting",
        ] {
            assert_ne!(i18n::t(key), "???", "{key}");
        }
    }

    #[test]
    fn a_skipped_items_report_is_a_completion_to_mention_not_a_failure() {
        let note = i18n::tf("sftp.err.skipped_names", &[("count", "3")]);
        assert_eq!(op_end(Err(note.clone())), OpEnd::Skipped(note));
        assert_eq!(op_end(Ok(())), OpEnd::Quiet);
        assert_eq!(op_end(Err(TRANSFER_CANCELLED.to_string())), OpEnd::Quiet);
        let failed = i18n::tf(
            "sftp.err.delete",
            &[("path", "/srv/a"), ("err", "permission denied")],
        );
        assert_eq!(op_end(Err(failed.clone())), OpEnd::Failed(failed));
        assert!(is_skipped_report(&i18n::tf(
            "sftp.err.skipped_names",
            &[("count", "12")]
        )));
        for other in [
            i18n::t("sftp.err.skipped_names").to_string(),
            i18n::tf("sftp.err.skipped_names", &[("count", "x")]),
            format!(
                "Failed to list '/srv': {}",
                i18n::tf("sftp.err.skipped_names", &[("count", "2")])
            ),
        ] {
            assert!(!is_skipped_report(&other), "{other}");
        }
        assert_ne!(i18n::t("notice.skipped_title"), "???");
    }

    #[test]
    fn paced_history_writes_go_out_at_most_once_a_minute() {
        assert_eq!(HISTORY_FLUSH_INTERVAL, Duration::from_secs(60));
        let t0 = std::time::Instant::now();
        let fresh = HistorySync {
            dirty: true,
            loaded: true,
            flushed_at: None,
            ..HistorySync::default()
        };
        assert!(
            history_flush_due(&fresh, t0),
            "the first write of a session goes at once"
        );

        let sync = HistorySync {
            flushed_at: Some(t0),
            ..fresh
        };
        // The old 3 s tick wrote at every one of these.
        for secs in [0, 3, 6, 30, 59] {
            assert!(
                !history_flush_due(&sync, t0 + Duration::from_secs(secs)),
                "{secs}s after a write"
            );
        }
        assert!(history_flush_due(&sync, t0 + Duration::from_secs(60)));
        assert!(history_flush_due(&sync, t0 + Duration::from_secs(61)));
        assert!(history_flush_due(&sync, t0 + Duration::from_secs(86_400)));
        if let Some(before) = t0.checked_sub(Duration::from_secs(1)) {
            assert!(
                !history_flush_due(&sync, before),
                "a clock read before the write"
            );
        }

        // Nothing new, or not loaded since the unlock: never.
        let later = t0 + Duration::from_secs(600);
        assert!(!history_flush_due(
            &HistorySync {
                dirty: false,
                ..sync
            },
            later
        ));
        assert!(!history_flush_due(
            &HistorySync {
                loaded: false,
                ..sync
            },
            later
        ));
    }

    // ---- terminal renderer colours -------------------------------------

    fn styled(
        fg: crate::terminal::Color,
        bg: crate::terminal::Color,
        inverse: bool,
    ) -> crate::terminal::CellStyle {
        crate::terminal::CellStyle {
            fg,
            bg,
            inverse,
            ..Default::default()
        }
    }

    #[test]
    fn default_cells_paint_the_theme_colours_and_no_background_block() {
        let plain = crate::terminal::CellStyle::default();
        for (name, preset) in theme_config::PRESETS {
            let (fg, bg) = (preset.terminal_fg.to_color(), preset.terminal_bg.to_color());
            // Before: a #1A1B2E fill under every glyph (it is not BG_PRIMARY
            // any more), and #E2E8F0 text whatever the theme said.
            assert_eq!(cell_paint(&plain, fg, bg), (None, fg), "{name}");
        }
    }

    #[test]
    fn reverse_video_swaps_the_resolved_theme_colours() {
        let light = theme_config::preset_by_name("Solarized Light").expect("preset");
        let (fg, bg) = (light.terminal_fg.to_color(), light.terminal_bg.to_color());
        let inverse = crate::terminal::CellStyle {
            inverse: true,
            ..Default::default()
        };
        assert_eq!(cell_paint(&inverse, fg, bg), (Some(fg), bg));
    }

    #[test]
    fn explicit_cell_colours_are_painted_as_set() {
        use crate::terminal::{Color as Rgb, DEFAULT_BG, DEFAULT_FG};
        let (red, blue) = (Rgb::rgb(205, 49, 49), Rgb::rgb(36, 114, 200));
        let (ired, iblue) = (cell_color_to_iced(red), cell_color_to_iced(blue));
        let (fg, bg) = (Color::from_rgb8(1, 2, 3), Color::from_rgb8(4, 5, 6));
        assert_eq!(
            cell_paint(&styled(red, blue, false), fg, bg),
            (Some(iblue), ired)
        );
        assert_eq!(
            cell_paint(&styled(red, blue, true), fg, bg),
            (Some(ired), iblue)
        );
        // One side explicit, one default: only the default side follows the theme.
        assert_eq!(
            cell_paint(&styled(red, DEFAULT_BG, false), fg, bg),
            (None, ired)
        );
        assert_eq!(
            cell_paint(&styled(DEFAULT_FG, blue, false), fg, bg),
            (Some(iblue), fg)
        );
        assert_eq!(
            cell_paint(&styled(red, DEFAULT_BG, true), fg, bg),
            (Some(ired), bg)
        );
        assert_eq!(
            cell_paint(&styled(DEFAULT_FG, blue, true), fg, bg),
            (Some(fg), iblue)
        );
    }

    #[test]
    fn a_terminal_colour_edit_changes_the_canvas_cache_key() {
        let (bg, fg) = (
            Color::from_rgb8(26, 27, 46),
            Color::from_rgb8(226, 232, 240),
        );
        assert_eq!(theme_colors_key(bg, fg), theme_colors_key(bg, fg));
        assert_ne!(
            theme_colors_key(bg, fg),
            theme_colors_key(Color::from_rgb8(26, 27, 47), fg)
        );
        assert_ne!(
            theme_colors_key(bg, fg),
            theme_colors_key(bg, Color::from_rgb8(226, 232, 241))
        );
        assert_ne!(
            theme_colors_key(bg, fg),
            theme_colors_key(fg, bg),
            "not symmetric"
        );
        // Never the fresh state's 0, so the first frame is always painted.
        assert_ne!(theme_colors_key(Color::BLACK, Color::BLACK), 0);
    }

    #[test]
    fn blank_cells_are_judged_by_the_default_background_sentinel() {
        use crate::terminal::{Cell, Color as Rgb};
        let blank = Cell::default();
        let nul = Cell {
            c: '\0',
            ..Cell::default()
        };
        assert!(is_blank_cell(&blank) && is_blank_cell(&nul));
        assert!(is_row_empty(&[blank.clone(), nul]));

        let mut coloured = Cell::default();
        coloured.style.bg = Rgb::rgb(1, 2, 3);
        let mut inverse = Cell::default();
        inverse.style.inverse = true;
        let glyph = Cell {
            c: 'x',
            ..Cell::default()
        };
        for cell in [&coloured, &inverse, &glyph] {
            assert!(!is_blank_cell(cell), "{cell:?}");
        }
        assert!(!is_row_empty(&[blank, glyph]));
    }

    #[test]
    fn format_ago_picks_the_largest_whole_unit() {
        assert_eq!(format_ago(0), "0s");
        assert_eq!(format_ago(59), "59s");
        assert_eq!(format_ago(60), "1m");
        assert_eq!(format_ago(3599), "59m");
        assert_eq!(format_ago(3600), "1h");
        assert_eq!(format_ago(86_399), "23h");
        assert_eq!(format_ago(86_400 * 3), "3d");
    }

    #[test]
    fn host_from_title_strips_user_port_and_status() {
        assert_eq!(host_from_title("root@10.0.0.7:22"), "10.0.0.7");
        assert_eq!(host_from_title("deploy@web.example.com:2222 [Reconnecting...1]"), "web.example.com");
        assert_eq!(host_from_title("me@::1:22"), "::1");
    }

    #[test]
    fn octal_modes_are_one_to_four_octal_digits() {
        assert_eq!(parse_octal_mode("755"), Some(0o755));
        assert_eq!(parse_octal_mode(" 0644 "), Some(0o644));
        assert_eq!(parse_octal_mode("4755"), Some(0o4755));
        assert_eq!(parse_octal_mode("7777"), Some(0o7777));
        for bad in ["", "8", "0o755", "75a", "-755", "17777", "rwxr-xr-x"] {
            assert_eq!(parse_octal_mode(bad), None, "{bad:?} must not parse");
        }
    }

    #[test]
    fn ls_mode_strings_prefill_the_chmod_dialog() {
        assert_eq!(mode_from_permissions("drwxr-xr-x"), Some(0o755));
        assert_eq!(mode_from_permissions("-rw-r--r--"), Some(0o644));
        assert_eq!(mode_from_permissions("-rwsr-xr-x"), Some(0o4755));
        assert_eq!(mode_from_permissions("drwxrwsr-x"), Some(0o2775));
        assert_eq!(mode_from_permissions("drwxrwxrwt"), Some(0o1777));
        assert_eq!(mode_from_permissions("-rwSr--r-T"), Some(0o5644));
        // ACL / SELinux markers after the ten mode characters are ignored.
        assert_eq!(mode_from_permissions("-rw-r-----+"), Some(0o640));
        assert_eq!(mode_from_permissions(""), None);
        assert_eq!(mode_from_permissions("total"), None);
        assert_eq!(mode_from_permissions("-rwxq-x---"), None);
    }

    #[test]
    fn remote_names_must_be_one_path_component() {
        // Exactly as typed: spaces at the ends are part of a name.
        assert_eq!(valid_remote_name("  logs  ").as_deref(), Some("  logs  "));
        assert_eq!(valid_remote_name("my file.txt").as_deref(), Some("my file.txt"));
        for bad in ["", "   ", ".", "..", "a/b", "/etc", "../x", "a\0b", "a\nb"] {
            assert_eq!(valid_remote_name(bad), None, "{bad:?} must be refused");
        }
        assert_eq!(join_remote_path("/var/www", "site"), "/var/www/site");
        assert_eq!(join_remote_path("/var/www/", "site"), "/var/www/site");
        assert_eq!(join_remote_path("/", "etc"), "/etc");
    }

    #[test]
    fn ports_sort_by_column_and_flip_direction() {
        use crate::ssh::PortInfo;
        let port = |proto: &str, addr: &str, port: u16, pid: Option<u32>, process: &str| PortInfo {
            proto: proto.into(),
            local_addr: addr.into(),
            port,
            pid,
            process: process.into(),
        };
        let mut ports = vec![
            port("tcp", "0.0.0.0", 443, Some(900), "nginx"),
            port("udp", "127.0.0.1", 53, None, ""),
            port("tcp", "127.0.0.1", 22, Some(12), "sshd"),
        ];
        sort_ports(&mut ports, PortSort::Port, false);
        assert_eq!(ports.iter().map(|p| p.port).collect::<Vec<_>>(), vec![22, 53, 443]);
        sort_ports(&mut ports, PortSort::Port, true);
        assert_eq!(ports.iter().map(|p| p.port).collect::<Vec<_>>(), vec![443, 53, 22]);
        // No pid (an unprivileged view) sorts before any known one.
        sort_ports(&mut ports, PortSort::Pid, false);
        assert_eq!(ports.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![None, Some(12), Some(900)]);
        sort_ports(&mut ports, PortSort::Process, false);
        assert_eq!(ports.iter().map(|p| p.process.as_str()).collect::<Vec<_>>(), vec!["", "nginx", "sshd"]);
    }

    /// Mouse reports carry 1-based cells: one off and a click lands on the
    /// wrong row. Pixel -> cell -> wire, through the terminal's own encoder.
    #[test]
    fn mouse_reports_use_one_based_cells_from_the_pane_origin() {
        let origin = (SIDEBAR_W, 30.0 + 34.0);
        let font = 13.0;
        let (cw, ch) = (font * 0.6, font * 1.2);
        // Inside the third column of the first row.
        let (x, y) = (origin.0 + cw * 2.0 + 1.0, origin.1 + 1.0);
        let cell = grid_cell_at(x, y, origin, font, (80, 24), false);
        assert_eq!(cell, Some((3, 1)));

        let mut grid = TerminalGrid::new(80, 24);
        grid.write(b"\x1b[?1000h\x1b[?1006h");
        assert_eq!(grid.mouse_mode(), MouseMode::Click);
        let (col, row) = cell.expect("inside");
        assert_eq!(
            grid.encode_mouse(MouseButton::Left, col, row, true).as_deref(),
            Some(&b"\x1b[<0;3;1M"[..])
        );

        // Past the last row / column: not reported, unless clamped (a drag
        // or release that left the pane).
        let below = origin.1 + ch * 30.0;
        assert_eq!(grid_cell_at(x, below, origin, font, (80, 24), false), None);
        assert_eq!(grid_cell_at(x, below, origin, font, (80, 24), true), Some((3, 24)));
        assert_eq!(grid_cell_at(0.0, 0.0, origin, font, (80, 24), false), None);
        assert_eq!(grid_cell_at(0.0, 0.0, origin, font, (80, 24), true), Some((1, 1)));
        assert_eq!(grid_cell_at(x, y, origin, font, (0, 0), true), None);
    }

    #[test]
    fn second_pane_starts_past_the_middle_of_the_divider() {
        let origin = (SIDEBAR_W, 64.0);
        // Side by side, main pane 400 px wide.
        assert!(!in_second_pane((SIDEBAR_W + 399.0, 300.0), origin, 400.0, true));
        assert!(!in_second_pane((SIDEBAR_W + 400.0 + SPLIT_DIVIDER / 2.0 - 0.5, 300.0), origin, 400.0, true));
        assert!(in_second_pane((SIDEBAR_W + 400.0 + SPLIT_DIVIDER, 300.0), origin, 400.0, true));
        // Stacked, main pane 200 px tall: only y matters.
        assert!(!in_second_pane((2000.0, 64.0 + 150.0), origin, 200.0, false));
        assert!(in_second_pane((0.0, 64.0 + 210.0), origin, 200.0, false));
    }

    #[test]
    fn remote_text_is_stripped_of_controls_and_capped() {
        assert_eq!(sanitize_remote_text("  Password:\x1b[31m  ", 50), "Password:[31m");
        assert_eq!(sanitize_remote_text("line one\nline two", 50), "line one\nline two");
        let long = "x".repeat(300);
        assert_eq!(sanitize_remote_text(&long, 10), format!("{}...", "x".repeat(10)));
    }

    #[test]
    fn scrubbed_answers_are_gone() {
        let mut answers = vec!["hunter2".to_string(), "123456".to_string()];
        scrub_answers(&mut answers);
        assert!(answers.is_empty());
    }

    #[test]
    fn a_colour_scheme_keeps_the_users_font_sizes() {
        use crate::ui::theme_config::{preset_by_name, preset_names, ThemeConfig};
        let mut mine = ThemeConfig::default();
        mine.terminal_font_size = 17.0;
        mine.ui_font_size = 14.0;
        for name in preset_names() {
            let preset = preset_by_name(name).expect("listed preset exists");
            let applied = preset_keeping_fonts(preset.clone(), &mine);
            assert_eq!(applied.terminal_font_size, 17.0, "{name}");
            assert_eq!(applied.ui_font_size, 14.0, "{name}");
            assert_eq!(applied.ansi, preset.ansi, "{name}: ANSI table comes from the preset");
            assert_eq!(applied.accent, preset.accent, "{name}");
        }
    }

    /// The welcome screen's "pending import" count and ImportAllSshConfigs
    /// must agree on what is already saved.
    #[test]
    fn ssh_config_key_mirrors_the_import_dedup() {
        use crate::sshconfig::SshHostConfig;
        let host = |alias: &str, hostname: &str| SshHostConfig {
            alias: alias.into(),
            hostname: hostname.into(),
            user: "deploy".into(),
            port: 2222,
            ..Default::default()
        };
        assert_eq!(ssh_config_key(&host("web", "10.0.0.7")).as_deref(), Some("deploy@10.0.0.7:2222"));
        // No HostName line: ssh(1) dials the alias itself.
        assert_eq!(ssh_config_key(&host("web", "")).as_deref(), Some("deploy@web:2222"));
        assert_eq!(ssh_config_key(&host("", "")), None);
    }

    #[test]
    fn truncate_str_counts_chars_not_bytes() {
        // Shape of a real error_message: ASCII plus a translated CJK hint.
        let s = "Authentication failed (username/password) — 用户名或密码不正确";
        assert!(s.len() > s.chars().count(), "fixture must be multi-byte");
        assert!(s.chars().count() > 48);
        // 48 lands inside the CJK run — the byte slice this replaced panicked
        // on exactly this offset.
        let out = truncate_str(s, 48);
        assert_eq!(out.chars().count(), 48 + 3);
        assert!(out.ends_with("..."));
        // No ellipsis when nothing was dropped.
        assert_eq!(truncate_str(s, s.chars().count()), s);
    }

    // ---- UI behaviour pass -------------------------------------------

    /// A challenge raised behind the lock screen (a session reconnecting) or
    /// under the palette must not take the keyboard: iced's focus operation
    /// unfocuses every other input, so the master password or the query
    /// stopped receiving keys and Enter no longer submitted. The focus waits
    /// for the modal to be on screen, and is then handed over exactly once.
    #[test]
    fn auth_focus_waits_until_the_modal_is_on_screen() {
        use Overlay::*;
        assert!(!auth_modal_visible(&Screen::Locked, Some(AuthPrompt)));
        assert!(!auth_modal_visible(&Screen::Setup, Some(AuthPrompt)));
        assert!(!auth_modal_visible(&Screen::Main, Some(Palette)));
        assert!(!auth_modal_visible(&Screen::Main, Some(ConfirmDelete)));
        assert!(!auth_modal_visible(&Screen::Main, None));
        assert!(auth_modal_visible(&Screen::Main, Some(AuthPrompt)));

        // Raised on the lock screen: owed, not handed over.
        let mut owed = true;
        let locked = auth_modal_visible(&Screen::Locked, Some(AuthPrompt));
        assert!(!take_owed_focus(&mut owed, locked));
        assert!(owed, "the focus is still owed once the vault is unlocked");
        // Unlocked, nothing above the modal: handed over — once.
        let shown = auth_modal_visible(&Screen::Main, Some(AuthPrompt));
        assert!(take_owed_focus(&mut owed, shown));
        assert!(
            !take_owed_focus(&mut owed, shown),
            "a focus on every poll tick would pull the cursor back to the first field"
        );
    }

    /// ESC used to reset these forms to empty — a half-typed connection, its
    /// password included. It now only puts away a form that still reads
    /// exactly as it was opened.
    #[test]
    fn esc_only_puts_away_a_form_nothing_was_typed_into() {
        use crate::proxy::{ProxyConfig, ProxyType};
        use crate::tunnel::{ForwardKind, ForwardRule, TunnelConfig};

        // Connection form, as `ShowForm(None)` opens it.
        let opened = ConnectionFormData {
            port: "22".into(),
            auth_type: "password".into(),
            ..Default::default()
        };
        let baseline = opened_connection_form(&opened);
        assert!(opened == baseline, "untouched: ESC closes it");
        let mut typed = opened.clone();
        typed.password = "hunter2".into();
        assert!(typed != baseline, "a typed password keeps the form open");
        let mut named = opened.clone();
        named.host = "10.0.0.7".into();
        assert!(named != baseline);
        // The baseline never holds a secret, whatever it is built from.
        let from_typed = opened_connection_form(&typed);
        assert!(from_typed.password.is_empty() && from_typed.passphrase.is_empty());

        // Proxy form: a new one, and a saved one opened with its secret.
        assert!(proxy_form_pristine(&proxy_form_for(None), None, &[]));
        let mut new_proxy = proxy_form_for(None);
        new_proxy.host = "10.0.0.9".into();
        assert!(!proxy_form_pristine(&new_proxy, None, &[]));
        let proxies = vec![ProxyConfig {
            id: "p1".into(),
            name: "jump".into(),
            proxy_type: ProxyType::SshBastion,
            host: "bastion.example".into(),
            port: 22,
            username: Some("ops".into()),
            password: Some("s3cret".into()),
            auth_type: Some("password".into()),
            private_key: None,
            passphrase: None,
        }];
        let editing = proxy_form_for(Some(&proxies[0]));
        assert!(proxy_form_pristine(&editing, Some("p1"), &proxies));
        let mut changed_pw = editing.clone();
        changed_pw.password.push('!');
        assert!(!proxy_form_pristine(&changed_pw, Some("p1"), &proxies));
        // The proxy was deleted underneath the form: it cannot be told, so
        // the form is kept.
        assert!(!proxy_form_pristine(&editing, Some("p1"), &[]));

        // Tunnel form.
        assert!(tunnel_form_pristine(&tunnel_form_for(None), None, &[]));
        let mut new_tunnel = tunnel_form_for(None);
        new_tunnel.passphrase = "keypass".into();
        assert!(!tunnel_form_pristine(&new_tunnel, None, &[]));
        let tunnels = vec![TunnelConfig {
            id: "t1".into(),
            name: "db".into(),
            ssh_host: "jump.example".into(),
            ssh_port: 22,
            username: "ops".into(),
            auth_type: "password".into(),
            password: Some("tunnelpw".into()),
            private_key: None,
            passphrase: None,
            forwards: vec![ForwardRule {
                local_port: 3000,
                remote_host: "0.0.0.0".into(),
                remote_port: 8080,
                kind: ForwardKind::Remote,
            }],
            auto_start: false,
        }];
        let editing = tunnel_form_for(Some(&tunnels[0]));
        assert!(tunnel_form_pristine(&editing, Some("t1"), &tunnels));
        let mut more_rules = editing.clone();
        more_rules.forwards_text.push_str("\n5432:127.0.0.1:5432");
        assert!(!tunnel_form_pristine(&more_rules, Some("t1"), &tunnels));

        // Snippet editor: the new-snippet fields, then a saved snippet.
        let snippets = vec![snippet("uptime")];
        assert!(snippet_form_pristine("", "", None, &snippets));
        assert!(!snippet_form_pristine("", "df -h", None, &snippets));
        assert!(snippet_form_pristine(
            "uptime",
            "uptime",
            Some("uptime"),
            &snippets
        ));
        assert!(!snippet_form_pristine(
            "uptime",
            "uptime -p",
            Some("uptime"),
            &snippets
        ));
    }

    /// One bar, one Cancel. Starting a transfer over one in flight replaced
    /// its progress — the folder transfer ran on with no bar and nothing could
    /// cancel it — and the late end of a cancelled transfer, or any unrelated
    /// error, took down whatever bar was showing.
    #[test]
    fn a_transfer_neither_takes_over_nor_takes_down_another_ones_bar() {
        let mut bar: Option<Arc<TransferProgress>> = None;
        let folder = claim_bar(&mut bar, false).expect("the bar is free");
        // An upload started meanwhile is refused; the folder transfer keeps
        // the bar, and with it its Cancel.
        assert!(claim_bar(&mut bar, false).is_none());
        assert!(bar.as_ref().is_some_and(|p| Arc::ptr_eq(p, &folder)));
        // A drop upload still winding down after its Cancel holds the bar
        // with nothing on it.
        let mut winding_down: Option<Arc<TransferProgress>> = None;
        assert!(bar_busy(winding_down.as_ref(), true));
        assert!(claim_bar(&mut winding_down, true).is_none());
        assert!(winding_down.is_none());

        // The folder transfer is cancelled (CancelTransfer) and another one
        // starts before the folder's thread has let go...
        folder.finished.store(true, Ordering::Relaxed);
        bar = None;
        let next = claim_bar(&mut bar, false).expect("free after a Cancel");
        // ...so the folder's late end must leave the new bar alone.
        release_bar(&mut bar, &folder);
        assert!(bar.as_ref().is_some_and(|p| Arc::ptr_eq(p, &next)));
        release_bar(&mut bar, &next);
        assert!(bar.is_none());

        // A transfer that finished, its end not yet processed, is no longer
        // in the way.
        let done = claim_bar(&mut bar, false).expect("free");
        done.finished.store(true, Ordering::Relaxed);
        assert!(claim_bar(&mut bar, false).is_some());
    }

    /// Four row actions for every matching connection, then a cut at twelve:
    /// with four or more matches the lower-ranked connections fell off the
    /// list and Cmd+K could no longer reach them.
    #[test]
    fn every_matching_connection_stays_reachable_from_the_palette() {
        // Each name is 24 characters longer than the last, which costs it 6
        // points of fuzzy score: the matches rank apart.
        let conns = |n: usize| -> Vec<ConnectionInfo> {
            (0..n)
                .map(|i| ConnectionInfo {
                    id: format!("c{i}"),
                    name: format!("web{}", "x".repeat(24 * i)),
                    host: "10.0.0.1".into(),
                    port: 22,
                    username: "root".into(),
                    auth_type: "password".into(),
                    group: String::new(),
                    color: String::new(),
                    proxy_id: None,
                })
                .collect()
        };
        let connect_ids = |items: &[PaletteItem]| -> Vec<String> {
            items
                .iter()
                .filter_map(|it| match &it.msg {
                    Message::ConnectTo(id) => Some(id.clone()),
                    _ => None,
                })
                .collect()
        };
        let row_action_of = |it: &PaletteItem| match &it.msg {
            Message::ShowForm(Some(id))
            | Message::TestConnectionInList(id)
            | Message::CloneConnection(id)
            | Message::DeleteConnection(id) => Some(id.clone()),
            _ => None,
        };

        let six = conns(6);
        let items = build_palette_items("web", &six, &[], &HashSet::new());
        assert!(items.len() <= PALETTE_MAX);
        assert_eq!(connect_ids(&items), ["c0", "c1", "c2", "c3", "c4", "c5"]);
        // Row actions for the best match only, right under it.
        let best = items
            .iter()
            .position(|it| matches!(&it.msg, Message::ConnectTo(id) if id == "c0"))
            .expect("best match listed");
        let actions: Vec<String> = items.iter().filter_map(row_action_of).collect();
        assert_eq!(actions, ["c0", "c0", "c0", "c0"]);
        assert!(items[best + 1..best + 5]
            .iter()
            .all(|it| row_action_of(it).as_deref() == Some("c0")));
        // No query, no row actions.
        assert!(build_palette_items("", &six, &[], &HashSet::new())
            .iter()
            .all(|it| row_action_of(it).is_none()));

        // More matches than rows: every row goes to a connection, best first.
        let items = build_palette_items("web", &conns(14), &[], &HashSet::new());
        assert_eq!(items.len(), PALETTE_MAX);
        assert_eq!(connect_ids(&items).len(), PALETTE_MAX);
        assert_eq!(connect_ids(&items)[0], "c0");
    }

    /// With the update banner showing, the canvas sits ~34 px below where
    /// the fixed chrome puts it: a click on row 10 in vim or htop was
    /// reported as row 12, and a selection started two rows off. The origin
    /// now comes from where the canvas drew.
    #[test]
    fn the_pointer_is_measured_from_where_the_pane_drew() {
        let font = 13.0;
        let row_h = font * 1.2;
        let fixed = (SIDEBAR_W, 30.0 + 34.0);
        let banner = 34.0;
        let drawn = Rectangle {
            x: SIDEBAR_W,
            y: banner + 30.0 + 34.0,
            width: 800.0,
            height: 480.0,
        };

        // The tab and its canvas share one cell: what `draw` records, the
        // hit-test reads.
        let main_bounds = PaneBounds::default();
        assert_eq!(
            pane_origin(main_bounds.get(), fixed),
            fixed,
            "before the first frame"
        );
        main_bounds.clone().record(drawn);
        let origin = pane_origin(main_bounds.get(), fixed);
        assert_eq!(origin, (drawn.x, drawn.y));
        // The middle of row 10, first column.
        let (x, y) = (drawn.x + 2.0, drawn.y + row_h * 9.5);
        assert_eq!(
            grid_cell_at(x, y, origin, font, (80, 24), false),
            Some((1, 10))
        );
        assert_eq!(
            grid_cell_at(x, y, fixed, font, (80, 24), false),
            Some((1, 12)),
            "what the fixed chrome made of the same click"
        );

        // A stacked split: the extent the divider drag shares out is the two
        // canvases as drawn — the transfer bar under them included — but only
        // once both have drawn.
        let tab = TerminalTab {
            id: "t".into(),
            session_id: "s".into(),
            connection_id: "c".into(),
            title: "root@web:22".into(),
            terminal: Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24))),
            custom_title: None,
            split: Some(SplitPane {
                session_id: "s2".into(),
                terminal: Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24))),
                vertical: false,
                ratio: 0.5,
                bounds: PaneBounds::default(),
            }),
            focus_split: true,
            bounds: main_bounds,
            pending_session_id: String::new(),
            split_pending: None,
        };
        assert!(
            drawn_split(&tab).is_none(),
            "until the second pane has drawn"
        );
        let second = Rectangle {
            y: drawn.y + drawn.height + SPLIT_DIVIDER,
            height: 300.0,
            ..drawn
        };
        if let Some(sp) = &tab.split {
            sp.bounds.record(second);
        }
        let (main, split) = drawn_split(&tab).expect("both drawn");
        assert_eq!(main.height + split.height, 780.0);
        assert_eq!(pane_origin(Some(split), fixed), (second.x, second.y));
    }

    /// The ports table was cloned and sorted inside the view on every redraw
    /// — every 50 ms tick. It is sorted when the data or the sort key
    /// changes; the view draws it as it stands.
    #[test]
    fn a_header_click_resorts_the_ports_table_in_place() {
        use crate::ssh::PortInfo;
        let port = |port: u16, process: &str| PortInfo {
            proto: "tcp".into(),
            local_addr: "0.0.0.0".into(),
            port,
            pid: None,
            process: process.into(),
        };
        let mut ports = vec![port(443, "nginx"), port(22, "SSHD"), port(53, "dnsmasq")];
        let processes =
            |ports: &[PortInfo]| ports.iter().map(|p| p.process.clone()).collect::<Vec<_>>();
        let (mut sort, mut desc) = (PortSort::Port, false);

        resort_ports(&mut ports, &mut sort, &mut desc, PortSort::Process);
        assert_eq!((sort, desc), (PortSort::Process, false));
        assert_eq!(
            processes(&ports),
            ["dnsmasq", "nginx", "SSHD"],
            "case-insensitive"
        );
        resort_ports(&mut ports, &mut sort, &mut desc, PortSort::Process);
        assert!(desc, "the same column flips direction");
        assert_eq!(processes(&ports), ["SSHD", "nginx", "dnsmasq"]);
        resort_ports(&mut ports, &mut sort, &mut desc, PortSort::Port);
        assert_eq!(
            (sort, desc),
            (PortSort::Port, false),
            "a new column starts ascending"
        );
        assert_eq!(
            ports.iter().map(|p| p.port).collect::<Vec<_>>(),
            [22, 53, 443]
        );
    }

    /// A monitor fetch was started every 3 s whatever happened to the last
    /// one. Behind a folder transfer holding the exec lock they queued up —
    /// ~600 in 30 minutes, past tokio's 512 blocking threads — and new
    /// connections could no longer start.
    #[test]
    fn a_session_has_one_fetch_out_at_a_time() {
        let mut inflight = InFlight::default();
        assert!(inflight.start("s1"));
        // A 30-minute transfer's worth of 3 s ticks adds nothing.
        for _ in 0..600 {
            assert!(!inflight.start("s1"));
        }
        assert!(inflight.contains("s1"));
        assert!(inflight.start("s2"), "another session is not held up");
        inflight.finish("s1");
        assert!(!inflight.contains("s1"));
        assert!(inflight.start("s1"), "the next tick fetches again");
        assert!(
            !inflight.start(""),
            "a tab with no session has nothing to fetch"
        );
    }

    /// A right-click pasted even into an application that had asked for the
    /// mouse, and the middle button was never reported at all
    /// (`MouseButton::Right` / `Middle` were never constructed).
    #[test]
    fn right_and_middle_clicks_reach_an_application_that_asked_for_the_mouse() {
        use iced::mouse::Button;
        assert_eq!(
            secondary_click(MouseButton::Right, true),
            SecondaryClick::Report
        );
        assert_eq!(
            secondary_click(MouseButton::Middle, true),
            SecondaryClick::Report
        );
        // Reporting off (or Shift held): right-click still pastes.
        assert_eq!(
            secondary_click(MouseButton::Right, false),
            SecondaryClick::Paste
        );
        assert_eq!(
            secondary_click(MouseButton::Middle, false),
            SecondaryClick::Ignore
        );

        assert_eq!(terminal_button(Button::Left), Some(MouseButton::Left));
        assert_eq!(terminal_button(Button::Middle), Some(MouseButton::Middle));
        assert_eq!(terminal_button(Button::Right), Some(MouseButton::Right));
        assert_eq!(terminal_button(Button::Back), None);

        // What the application receives, through the terminal's own encoder.
        let mut grid = TerminalGrid::new(80, 24);
        grid.write(b"\x1b[?1000h\x1b[?1006h");
        assert_eq!(
            grid.encode_mouse(MouseButton::Right, 3, 1, true).as_deref(),
            Some(&b"\x1b[<2;3;1M"[..])
        );
        assert_eq!(
            grid.encode_mouse(MouseButton::Right, 3, 1, false)
                .as_deref(),
            Some(&b"\x1b[<2;3;1m"[..])
        );
        assert_eq!(
            grid.encode_mouse(MouseButton::Middle, 3, 1, true)
                .as_deref(),
            Some(&b"\x1b[<1;3;1M"[..])
        );
    }

    // ---- exact names, fresh kill checks, withdrawn and unfocused sign-ins,
    // ---- folded groups, Chinese connection names -------------------------

    /// A co-tenant's 0-byte "project " beside the user's folder "project"
    /// read the same in the file list and the confirmation. What would not
    /// show is marked now; an ordinary name — a Chinese one included — is
    /// left alone.
    #[test]
    fn visible_name_marks_what_would_not_show() {
        assert_eq!(visible_name("project"), "project");
        assert_eq!(visible_name("project "), "project·");
        assert_eq!(visible_name(" project"), "·project");
        assert_eq!(visible_name("pro  ject"), "pro··ject");
        assert_eq!(visible_name("my file.txt"), "my file.txt", "one space inside is a space");
        assert_ne!(visible_name("project "), visible_name("project"));
        // Other whitespace, controls, invisible formatting: escaped.
        assert_eq!(visible_name("pro\u{200B}ject"), "pro\\u{200b}ject");
        assert_eq!(visible_name("a\tb"), "a\\u{9}b");
        assert_eq!(visible_name("a\u{A0}b"), "a\\u{a0}b");
        assert_eq!(visible_name("a\nb"), "a\\u{a}b");
        assert_eq!(visible_name("evil\u{202E}txt.exe"), "evil\\u{202e}txt.exe");
        // A variation selector after ASCII changes nothing on screen.
        assert_eq!(visible_name("project\u{FE0F}"), "project\\u{fe0f}");
        // Chinese names, the interpunct and emoji stay as they are.
        assert_eq!(visible_name("生产 服务器"), "生产 服务器");
        assert_eq!(visible_name("张三·李四"), "张三·李四");
        assert_eq!(visible_name("❤\u{FE0F}.txt"), "❤\u{FE0F}.txt");
        // Each component of a path.
        assert_eq!(visible_path("/srv/project /a"), "/srv/project·/a");
    }

    /// A long name loses its middle, so the mark at its end stays in view.
    #[test]
    fn long_names_keep_their_marked_end() {
        use crate::terminal::display_width;
        let decoy = visible_name("quarterly_report_for_the_board_2024 ");
        let short = truncate_middle_to_width(&decoy, 16);
        assert!(display_width(&short) <= 16, "{short}");
        assert!(short.starts_with("quarter") && short.ends_with('·'), "{short}");
        let cjk = truncate_middle_to_width("年度报告终稿版本确认后归档.docx", 16);
        assert!(display_width(&cjk) <= 16, "{cjk}");
        assert!(cjk.starts_with("年度") && cjk.ends_with(".docx") && cjk.contains('…'), "{cjk}");
        assert_eq!(truncate_middle_to_width("a.txt", 16), "a.txt");
    }

    /// The confirmation quotes the exact name and states what the row
    /// showed: a decoy file "project " reads differently from the folder
    /// "project" — and that kind is what the SSH layer is told.
    #[test]
    fn sftp_confirmations_quote_the_exact_name_and_state_its_kind() {
        let delete = |name: &str, kind: EntryKind| ConfirmAction::SftpDelete {
            session_id: "s".into(),
            dir: "/srv".into(),
            path: join_remote_path("/srv", name),
            name: name.into(),
            kind,
            confirmed: ConfirmedEntry::from(kind),
        };
        let (decoy_q, decoy_path, decoy_marked) =
            confirm_action_text(&delete("project ", EntryKind::File));
        let (real_q, real_path, real_marked) =
            confirm_action_text(&delete("project", EntryKind::Dir));
        assert!(decoy_q.contains("“project·”"), "{decoy_q}");
        assert!(real_q.contains("“project”"), "{real_q}");
        assert_ne!(decoy_q, real_q);
        assert_eq!(decoy_path, "/srv/project·");
        assert_eq!(real_path, "/srv/project");
        assert!(decoy_marked && !real_marked, "the marks are explained when there are some");
        // The kind is stated, in either language.
        assert!(["file", "文件"].iter().any(|k| decoy_q.contains(k)), "{decoy_q}");
        assert!(["folder", "文件夹"].iter().any(|k| real_q.contains(k)), "{real_q}");
        let chmod = ConfirmAction::SftpChmod {
            session_id: "s".into(),
            dir: "/srv".into(),
            path: "/srv/run.sh".into(),
            name: "run.sh".into(),
            kind: EntryKind::File,
            confirmed: ConfirmedEntry::from(EntryKind::File),
            mode: 0o755,
        };
        let (question, subject, _) = confirm_action_text(&chmod);
        assert!(question.contains("“run.sh”") && question.contains("0755"), "{question}");
        assert!(["file", "文件"].iter().any(|k| question.contains(k)), "{question}");
        assert_eq!(subject, "/srv/run.sh");
    }

    /// The kill confirmation shows the process /proc has under the pid as it
    /// opens — not a name `ss` parsed — and the signal goes only while that
    /// is still the process: same start time.
    #[test]
    fn a_kill_goes_only_to_the_process_confirmed() {
        let stat = |start: &str| {
            format!(
                "4242 (nginx: worker) S 1 4242 4242 0 -1 4194624 312 0 0 0 1 2 0 0 20 0 1 0 {} \
                 1000000 200 18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 3 0 0\n",
                start
            )
        };
        let first = parse_proc_identity(&stat("98765"), "nginx: worker process ").expect("a process");
        assert_eq!(first.comm, "nginx: worker");
        assert_eq!(kill_command_label(&first), "nginx: worker process");
        // It retitled itself: the same process.
        let retitled =
            parse_proc_identity(&stat("98765"), "nginx: worker process is shutting down").unwrap();
        assert!(same_process(&first, &retitled));
        // The pid changed hands: another start time, no signal.
        let reused = parse_proc_identity(&stat("123456"), "nginx: worker process").unwrap();
        assert!(!same_process(&first, &reused));
        // Gone: nothing printed.
        assert_eq!(parse_proc_identity("", ""), None);
        // A name with parentheses and spaces of its own cannot shift the fields.
        let tricky = parse_proc_identity(
            "77 (a) 1 2 (b) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5555 0 0\n",
            "",
        )
        .unwrap();
        assert_eq!(tricky.comm, "a) 1 2 (b");
        assert_eq!(tricky.start_time, "5555");
        // No command line — a kernel thread — shows as `ps` shows it.
        let kthread =
            parse_proc_identity("2 (kthreadd) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 7 0 0\n", "")
                .unwrap();
        assert_eq!(kill_command_label(&kthread), "[kthreadd]");
        // What would not show, shows.
        let hidden = parse_proc_identity(&stat("1"), "sleep 100\u{202E}fdsa").unwrap();
        assert_eq!(kill_command_label(&hidden), "sleep 100\\u{202e}fdsa");

        // A host without /proc answers through `ps`: the same check, by the
        // start time it prints.
        let ps = parse_ps_identity("Mon Sep 22 01:02:03 2026 /usr/sbin/nginx -g daemon off;\n")
            .expect("a process");
        assert_eq!(ps.start_time, "Mon Sep 22 01:02:03 2026");
        assert_eq!(kill_command_label(&ps), "/usr/sbin/nginx -g daemon off;");
        let padded = parse_ps_identity("Tue Sep  2 01:02:03 2026 sleep 100").unwrap();
        assert_eq!(padded.start_time, "Tue Sep 2 01:02:03 2026");
        let later = parse_ps_identity("Tue Sep  2 01:07:44 2026 sleep 100").unwrap();
        assert!(!same_process(&padded, &later), "the pid changed hands");
        assert_eq!(parse_ps_identity(""), None, "gone");
        assert_eq!(parse_ps_identity("ps: illegal option -- w\n"), None);
    }

    fn test_tab(session_id: &str, pending: &str) -> TerminalTab {
        TerminalTab {
            id: "t".into(),
            session_id: session_id.into(),
            connection_id: "c".into(),
            title: String::new(),
            terminal: Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24))),
            custom_title: None,
            split: None,
            focus_split: false,
            bounds: PaneBounds::default(),
            pending_session_id: pending.into(),
            split_pending: None,
        }
    }

    fn test_split(session_id: &str) -> SplitPane {
        SplitPane {
            session_id: session_id.into(),
            terminal: Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24))),
            vertical: true,
            ratio: 0.5,
            bounds: PaneBounds::default(),
        }
    }

    /// Closing a tab withdraws every sign-in it is waiting on — its connect,
    /// under the id picked before the connect; its split's; a reconnect of
    /// either — and no other tab's.
    #[test]
    fn closing_a_tab_withdraws_its_own_sign_in_challenges() {
        let mut tab = test_tab("", "sid-new");
        assert_eq!(tab_auth_sessions(&tab), ["sid-new"], "still connecting");
        tab.session_id = "sid-new".into();
        tab.pending_session_id.clear();
        tab.split_pending = Some("sid-split".into());
        assert_eq!(tab_auth_sessions(&tab), ["sid-new", "sid-split"]);
        tab.split_pending = None;
        tab.split = Some(test_split("sid-2"));
        assert_eq!(tab_auth_sessions(&tab), ["sid-new", "sid-2"]);

        let now = std::time::Instant::now();
        let mut queue: VecDeque<(&str, std::time::Instant)> =
            ["sid-2", "other", "sid-new", "other-2"].into_iter().map(|s| (s, now)).collect();
        let asking = tab_auth_sessions(&tab);
        let pick = |s: &&str| asking.iter().any(|a| a.as_str() == *s);
        let (taken, front) = take_challenges(&mut queue, pick);
        assert_eq!(taken, ["sid-2", "sid-new"]);
        assert!(front, "the one on screen was the tab's: the modal moves on");
        let left: Vec<&str> = queue.iter().map(|(s, _)| *s).collect();
        assert_eq!(left, ["other", "other-2"], "the rest stay, in order");
        let (taken, front) = take_challenges(&mut queue, pick);
        assert!(taken.is_empty() && !front);
        assert_eq!(queue.len(), 2);
    }

    /// A connect failing in the background takes its own tab away and
    /// nothing else — every still-connecting tab used to go with it — and the
    /// tab the user is on stays the active one.
    #[test]
    fn a_failed_connect_leaves_the_active_tab_where_it_was() {
        assert_eq!(active_after_removal(Some(2), 0, 2), Some(1), "[x, A, B] on B");
        assert_eq!(active_after_removal(Some(2), 0, 3), Some(1), "[x, A, B, C] on B, not C");
        assert_eq!(active_after_removal(Some(0), 1, 2), Some(0), "[A, x, B] on A");
        assert_eq!(active_after_removal(Some(1), 1, 2), Some(1), "on the failed one");
        assert_eq!(active_after_removal(Some(2), 2, 2), Some(1));
        assert_eq!(active_after_removal(Some(0), 0, 0), None);
        assert_eq!(active_after_removal(None, 0, 3), None);
    }

    /// A parked exec connection turns a folder listing into the panels'
    /// "Reconnect monitoring" rather than an error dialog per listing — for
    /// the focused pane's session, which the panels now show, a split's
    /// included.
    #[test]
    fn a_parked_listing_offers_the_reconnect_for_the_focused_pane() {
        let parked = i18n::t("exec.err.needs_reconnect").to_string();
        assert!(matches!(listing_failed("sid-2", parked), Message::ExecParked(s) if s == "sid-2"));
        assert!(matches!(
            listing_failed("sid-2", "Permission denied".into()),
            Message::Error(e) if e == "Permission denied"
        ));
        let mut tab = test_tab("sid-1", "");
        tab.split = Some(test_split("sid-2"));
        assert_eq!(tab.focused_session(), "sid-1");
        tab.focus_split = true;
        assert_eq!(tab.focused_session(), "sid-2", "the panels follow the focused pane");
    }

    /// A sign-in challenge takes the keyboard only when the user's own click
    /// asked for it; one arriving on its own — another tab reconnecting —
    /// shows its modal and waits for a click.
    #[test]
    fn only_a_challenge_the_user_asked_for_takes_the_keyboard() {
        assert!(!challenge_may_take_focus("reconnect", false));
        assert!(!challenge_may_take_focus("reconnect", true), "never the user's click");
        assert!(challenge_may_take_focus("shell", true), "Connect");
        assert!(challenge_may_take_focus("exec", true), "Reconnect monitoring");
        assert!(!challenge_may_take_focus("shell", false));
        assert!(!challenge_may_take_focus("exec", false));
        assert!(challenge_may_take_focus("test", false));
        assert!(challenge_may_take_focus("deploy", false));
        // Not even then while keys are still arriving from somewhere else.
        let t0 = std::time::Instant::now();
        assert!(typing_recently(Some(t0), t0 + Duration::from_millis(200)));
        assert!(!typing_recently(Some(t0), t0 + AUTH_TYPING_WINDOW));
        assert!(!typing_recently(None, t0));
    }

    /// Keys — Enter above all — arriving in the modal's first moments were
    /// typed before it appeared: the rest of a sudo password and its Enter,
    /// say. They are not submitted as this server's answer.
    #[test]
    fn keys_typed_before_the_modal_appeared_are_no_answer() {
        let t0 = std::time::Instant::now();
        let mut shown = None;
        assert!(!auth_armed(shown, t0), "not on screen");
        note_auth_shown(&mut shown, true, t0);
        assert_eq!(shown, Some(t0));
        note_auth_shown(&mut shown, true, t0 + Duration::from_millis(40));
        assert_eq!(shown, Some(t0), "staying up does not restart it");
        assert!(!auth_armed(shown, t0 + Duration::from_millis(50)), "one poll tick in");
        assert!(!auth_armed(shown, t0 + AUTH_ARM_DELAY - Duration::from_millis(1)));
        assert!(auth_armed(shown, t0 + AUTH_ARM_DELAY));
        // Covered — by the palette, say — and uncovered: the wait starts over.
        note_auth_shown(&mut shown, false, t0 + Duration::from_secs(1));
        assert_eq!(shown, None);
        assert!(!auth_armed(shown, t0 + Duration::from_secs(2)));
        let t1 = t0 + Duration::from_secs(3);
        note_auth_shown(&mut shown, true, t1);
        assert!(!auth_armed(shown, t1 + Duration::from_millis(100)));
        assert!(auth_armed(shown, t1 + AUTH_ARM_DELAY));
    }

    /// `clear()` left the password's bytes in the buffer the string keeps;
    /// the lock zeroes them — and the decrypted proxy and tunnel lists'.
    #[test]
    fn locking_zeroes_the_secrets_it_scrubs() {
        let mut conn = ConnectionFormData { password: "hunter2".into(), ..Default::default() };
        let mut proxy = ProxyFormData { passphrase: "proxypass".into(), ..Default::default() };
        let mut tunnel = TunnelFormData { password: "tunnelpw".into(), ..Default::default() };
        let buffers = [
            (conn.password.as_ptr(), conn.password.len()),
            (proxy.passphrase.as_ptr(), proxy.passphrase.len()),
            (tunnel.password.as_ptr(), tunnel.password.len()),
        ];
        scrub_form_secrets(&mut conn, &mut proxy, &mut tunnel);
        assert_eq!(conn.password.as_ptr(), buffers[0].0, "the same buffer, kept");
        for (ptr, len) in buffers {
            // SAFETY: each empty string above still owns this allocation, and
            // every byte read was written when the string was made.
            let left = unsafe { std::slice::from_raw_parts(ptr, len) };
            assert!(left.iter().all(|b| *b == 0), "plaintext left behind: {left:?}");
        }

        let mut proxies = vec![crate::proxy::ProxyConfig {
            id: "p1".into(),
            name: "jump".into(),
            proxy_type: crate::proxy::ProxyType::SshBastion,
            host: "bastion.example".into(),
            port: 22,
            username: Some("ops".into()),
            password: Some("s3cret".into()),
            auth_type: Some("password".into()),
            private_key: None,
            passphrase: Some("keypass".into()),
        }];
        let mut tunnels = vec![crate::tunnel::TunnelConfig {
            id: "t1".into(),
            name: "db".into(),
            ssh_host: "jump.example".into(),
            ssh_port: 22,
            username: "ops".into(),
            auth_type: "password".into(),
            password: Some("tunnelpw".into()),
            private_key: None,
            passphrase: Some("tunnelpass".into()),
            forwards: Vec::new(),
            auto_start: false,
        }];
        scrub_list_secrets(&mut proxies, &mut tunnels);
        assert_eq!((&proxies[0].password, &proxies[0].passphrase), (&None, &None));
        assert_eq!((&tunnels[0].password, &tunnels[0].passphrase), (&None, &None));
        assert_eq!(proxies[0].host, "bastion.example", "only the secrets go");
    }

    fn sidebar_conn(id: &str, name: &str, group: &str) -> ConnectionInfo {
        ConnectionInfo {
            id: id.into(),
            name: name.into(),
            host: "10.0.0.1".into(),
            port: 22,
            username: "root".into(),
            auth_type: "password".into(),
            group: group.into(),
            color: String::new(),
            proxy_id: None,
        }
    }

    fn groups_of(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// A `GroupsFile` over a scratch directory of its own; remove the
    /// returned path's directory with `remove_scratch` when done.
    fn scratch_groups(test: &str) -> (std::path::PathBuf, GroupsFile) {
        let path = scratch_history(test);
        remove_scratch(&path);
        let dir = path.parent().expect("scratch dir").to_path_buf();
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let file = GroupsFile::at(&dir);
        (path, file)
    }

    /// The folded groups outlive a restart — Chinese names included — sealed
    /// with the vault: the file names no group, and nothing is read or sealed
    /// while the vault is locked. Written atomically and owner-only, in the
    /// order sealed; a damaged file folds nothing.
    #[test]
    fn folded_groups_survive_a_restart() {
        let (path, file) = scratch_groups("groups");
        let vault = history_vault();
        assert_eq!(file.load(vault), (HashSet::new(), false), "nothing saved: all open");
        let saved = groups_of(&["生产环境", "开发 / 测试", "", "Web"]);
        file.write(file.snapshot(vault, &saved, false).expect("seal")).expect("write");
        assert_eq!(file.load(vault), (saved.clone(), false));
        let raw = String::from_utf8_lossy(&std::fs::read(&file.sealed).expect("read")).into_owned();
        for name in ["生产环境", "开发", "Web"] {
            assert!(!raw.contains(name), "{name} on disk in the clear: {raw}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file.sealed).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Locked: nothing is read, nothing sealed.
        let locked = ConnectionStore::with_vault_path(file.sealed.with_file_name("locked.json"));
        assert_eq!(file.load(&locked), (HashSet::new(), false));
        assert!(file.snapshot(&locked, &saved, false).is_err());
        // A snapshot that runs late never lands over a newer one.
        let older = file.snapshot(vault, &groups_of(&["old"]), false).expect("seal");
        let newer = file.snapshot(vault, &groups_of(&["new"]), false).expect("seal");
        file.write(newer).expect("write");
        file.write(older).expect("write");
        assert_eq!(file.load(vault).0, groups_of(&["new"]));
        // A damaged file folds nothing rather than failing.
        crate::storage::write_private(&file.sealed, b"{ not json").expect("write");
        assert_eq!(file.load(vault), (HashSet::new(), false));
        remove_scratch(&path);
    }

    /// Builds before this wrote the folded groups in the clear, and read them
    /// before the vault was open. The first unlock imports that file; the
    /// write that seals the import overwrites it and deletes it.
    #[test]
    fn cleartext_folded_groups_are_imported_then_scrubbed() {
        let (path, file) = scratch_groups("groups-legacy");
        let vault = history_vault();
        crate::storage::write_private(&file.legacy, "[\"生产环境\",\"\"]".as_bytes())
            .expect("legacy file");
        // Not before the unlock.
        let locked = ConnectionStore::with_vault_path(file.sealed.with_file_name("locked.json"));
        assert_eq!(file.load(&locked), (HashSet::new(), false));
        let (groups, legacy_found) = file.load(vault);
        assert!(legacy_found);
        assert_eq!(groups, groups_of(&["生产环境", ""]));
        file.write(file.snapshot(vault, &groups, true).expect("seal")).expect("write");
        assert!(std::fs::symlink_metadata(&file.legacy).is_err(), "the cleartext file is gone");
        assert_eq!(file.load(vault), (groups, false), "and what it held is sealed");
        remove_scratch(&path);
    }

    /// A group whose last connection is deleted or moved away drops out of
    /// the saved set.
    #[test]
    fn a_group_left_empty_is_forgotten() {
        let conns = vec![sidebar_conn("a", "db", "生产环境"), sidebar_conn("b", "web", "")];
        let mut folded = groups_of(&["生产环境", "", "已删除"]);
        assert!(prune_collapsed_groups(&mut folded, &conns));
        assert_eq!(folded, groups_of(&["生产环境", ""]));
        assert!(!prune_collapsed_groups(&mut folded, &conns), "nothing more to drop");
        let moved = vec![sidebar_conn("a", "db", "测试"), sidebar_conn("b", "web", "")];
        assert!(prune_collapsed_groups(&mut folded, &moved));
        assert_eq!(folded, groups_of(&[""]));
    }

    /// Searching opens every group with a match, a folded one included,
    /// without touching what was saved; with the search cleared it is
    /// folded again.
    #[test]
    fn search_opens_a_folded_group_holding_a_chinese_match() {
        let conns = vec![
            sidebar_conn("1", "订单数据库主节点", "生产环境"),
            sidebar_conn("2", "web-01", "生产环境"),
            sidebar_conn("3", "构建机", "开发"),
        ];
        let folded = groups_of(&["生产环境"]);
        let groups = sidebar_groups(&conns, "数据库", &folded);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].key, "生产环境");
        assert!(!groups[0].collapsed, "a search result is never hidden");
        let ids: Vec<&str> = groups[0].conns.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["1"]);
        assert_eq!(folded, groups_of(&["生产环境"]), "the saved state is as it was");
        let all = sidebar_groups(&conns, "", &folded);
        assert!(all.iter().find(|g| g.key == "生产环境").expect("listed").collapsed);
        assert!(!all.iter().find(|g| g.key == "开发").expect("listed").collapsed);
        assert!(sidebar_groups(&conns, "  ", &folded).iter().any(|g| g.collapsed), "blank is no search");
    }

    /// Mixed Chinese and English groups: by name without regard to case, in
    /// a fixed order, and the ungrouped bucket last.
    #[test]
    fn groups_sort_by_name_with_ungrouped_last() {
        let conns = vec![
            sidebar_conn("1", "a", ""),
            sidebar_conn("2", "b", "生产"),
            sidebar_conn("3", "c", "web"),
            sidebar_conn("4", "d", "开发"),
            sidebar_conn("5", "e", "Api"),
            sidebar_conn("6", "f", "WEB"),
        ];
        let order: Vec<String> =
            sidebar_groups(&conns, "", &HashSet::new()).into_iter().map(|g| g.key).collect();
        assert_eq!(order, ["Api", "WEB", "web", "开发", "生产", ""]);
    }

    /// Search works on Chinese names: substrings match, Latin case is
    /// ignored, and the full-width letters a Chinese input method types match
    /// their ASCII selves — in the sidebar and the palette alike.
    #[test]
    fn search_matches_chinese_names_and_full_width_letters() {
        let conn = sidebar_conn("1", "生产Web服务器", "华东区");
        for q in ["生产", "web服务", "WEB", "ｗｅｂ", "服务器", "华东", "10.0.0.1"] {
            assert!(connection_matches(&conn, &search_fold(q)), "{q}");
        }
        for q in ["测试", "生 产", "webs"] {
            assert!(!connection_matches(&conn, &search_fold(q)), "{q}");
        }
        assert_eq!(search_fold("ＡＢＣ　１２"), "abc 12");
        assert!(fuzzy_score("服务器", "生产Web服务器").is_some());
        assert!(fuzzy_score("ＷＥＢ", "生产Web服务器").is_some());
        assert!(fuzzy_score("测试", "生产Web服务器").is_none());
    }

    /// Folding from the keyboard: the palette offers each group by name, and
    /// collapse all / expand all.
    #[test]
    fn the_palette_folds_groups() {
        let conns = vec![sidebar_conn("1", "db", "生产环境"), sidebar_conn("2", "web", "")];
        let toggle_of = |items: &[PaletteItem]| {
            items
                .iter()
                .find(|it| matches!(&it.msg, Message::ToggleGroupCollapsed(g) if g == "生产环境"))
                .map(|it| it.label.clone())
        };
        let open = toggle_of(&build_palette_items("生产", &conns, &[], &HashSet::new()))
            .expect("offered while open");
        let folded = toggle_of(&build_palette_items("生产", &conns, &[], &groups_of(&["生产环境"])))
            .expect("offered while folded");
        assert!(open.contains("生产环境") && folded.contains("生产环境"));
        assert_ne!(open, folded, "collapse, then expand");
        let blank = build_palette_items("", &conns, &[], &HashSet::new());
        assert!(!blank.iter().any(|it| matches!(it.msg, Message::ToggleGroupCollapsed(_))));
        let all = build_palette_items(i18n::t("sidebar.collapse_all"), &conns, &[], &HashSet::new());
        assert!(all.iter().any(|it| matches!(it.msg, Message::SetAllGroupsCollapsed(true))));
    }

    /// A Chinese name is cut by the columns it takes, not by its character
    /// count: it fits the budget a Latin one does, and the cut shows.
    #[test]
    fn chinese_names_are_cut_to_the_display_width_budget() {
        use crate::terminal::display_width;
        let name = "华东区生产环境订单数据库主节点";
        assert!(name.chars().count() <= 16 && display_width(name) > 20, "the old count let it by");
        let (short, cut) = clip_to_width(name, 20);
        assert!(cut);
        assert!(display_width(&short) <= 20, "{short}");
        assert!(short.starts_with("华东区") && short.ends_with('…'), "{short}");
        let (same, cut) = clip_to_width("root@10.0.0.1:22", 20);
        assert!(!cut);
        assert_eq!(same, "root@10.0.0.1:22");
        // The fixed-width sidebar's budget shrinks as the UI font grows.
        assert_eq!(cols_at_scale(24, 1.0), 24);
        assert!(cols_at_scale(24, 1.5) < 24);
        assert!(cols_at_scale(24, 10.0) >= 6);
    }

    /// Every string this pass added resolves — in either language, which the
    /// tables' parity guarantees.
    #[test]
    fn strings_added_for_this_pass_resolve() {
        for key in [
            "sftp.kind.file", "sftp.kind.dir", "sftp.kind.symlink", "sftp.kind.other",
            "sftp.confirm_delete_named", "sftp.confirm_delete_dir_named",
            "sftp.confirm_delete_link_named", "sftp.confirm_chmod_named",
            "sftp.rename_title_named", "sftp.chmod_title_named", "sftp.name_marks",
            "process.err.gone", "process.err.changed", "process.signal_n", "files.parked",
            "tunnel.err.start", "shortcuts.key.drag", "shortcuts.key.shift_drag",
            "shortcuts.key.right_click", "shortcuts.key.drop", "tab.split_suffix",
            "sidebar.collapse_all", "sidebar.expand_all", "palette.act.collapse_group",
            "palette.act.expand_group",
        ] {
            assert_ne!(i18n::t(key), "???", "{key}");
        }
    }

    // ---- round 5: input method, ports, listings, panes, groups ----------

    /// The input method is off wherever a secret is typed: on the vault
    /// screens whatever has the focus, in every secret field, and in a
    /// sign-in answer the server does not echo.
    #[test]
    fn the_input_method_stays_away_from_secrets() {
        use FocusedField::{AuthAnswer, None as Terminal, Secret, Text};
        let otp = [("Verification code:".to_string(), false)];
        let user = [("Username:".to_string(), true)];
        for screen in [Screen::Setup, Screen::Locked] {
            for focused in [Terminal, Text, Secret, AuthAnswer(0)] {
                assert!(!ime_allowed(&screen, focused, &user), "{screen:?} {focused:?}");
            }
        }
        assert!(ime_allowed(&Screen::Main, Terminal, &[]), "the terminal takes Chinese");
        assert!(ime_allowed(&Screen::Main, Text, &[]), "so do names and searches");
        assert!(!ime_allowed(&Screen::Main, Secret, &[]));
        assert!(!ime_allowed(&Screen::Main, AuthAnswer(0), &otp), "a masked answer");
        assert!(ime_allowed(&Screen::Main, AuthAnswer(0), &user), "an echoed one");
        assert!(!ime_allowed(&Screen::Main, AuthAnswer(1), &user), "no prompt behind it");
    }

    /// Every secret field is told apart by its id — the setup and unlock
    /// passwords, the connection, proxy and tunnel secrets — and so is each
    /// sign-in answer, by its prompt's number.
    #[test]
    fn every_secret_field_is_known_by_its_id() {
        use iced::advanced::widget::Id;
        assert_eq!(SECRET_INPUT_IDS.len(), 9);
        for secret in SECRET_INPUT_IDS {
            let id = Id::from(text_input::Id::new(secret));
            assert_eq!(FocusedField::of(Some(&id)), FocusedField::Secret, "{secret}");
        }
        let unique: HashSet<&str> = SECRET_INPUT_IDS.into_iter().collect();
        assert_eq!(unique.len(), SECRET_INPUT_IDS.len());
        let answer = Id::from(auth_input_id(3));
        assert_eq!(FocusedField::of(Some(&answer)), FocusedField::AuthAnswer(3));
        for other in [PALETTE_INPUT_ID, QUICK_CMD_INPUT_ID, SFTP_INPUT_ID, TERM_SEARCH_INPUT_ID] {
            assert_eq!(FocusedField::of(Some(&Id::new(other))), FocusedField::Text, "{other}");
        }
        assert_eq!(FocusedField::of(None), FocusedField::None);
    }

    /// A focus the app gives counts at once; an answer from the widget tree
    /// asked before that, or older than one already in, is stale.
    #[test]
    fn stale_focus_answers_are_ignored() {
        use iced::advanced::widget::Id;
        let mut focus = FocusTracker::default();
        let _ = focus.query(); // 1: asked before the app focused a field
        let _ = focus.focus(auth_input_id(0)); // 2, and its own query: 3
        assert_eq!(focus.field, FocusedField::AuthAnswer(0), "known before any answer");
        focus.found(1, None);
        assert_eq!(focus.field, FocusedField::AuthAnswer(0), "asked before the focus moved");
        focus.found(3, Some(Id::from(auth_input_id(0))));
        assert_eq!(focus.field, FocusedField::AuthAnswer(0));
        let _ = focus.query(); // 4
        let _ = focus.query(); // 5
        focus.found(5, None);
        assert_eq!(focus.field, FocusedField::None, "back in the terminal");
        focus.found(4, Some(Id::new(UNLOCK_PW_INPUT_ID)));
        assert_eq!(focus.field, FocusedField::None, "older than the answer in");
        assert!(focus.answered());
        let _ = focus.query();
        assert!(!focus.answered(), "a click's answer is out");
        focus.found(6, None);
        assert!(focus.answered());
        // An answer field past AUTH_MAX_FIELDS is one all the same, while a
        // challenge that long is on screen.
        let far = AUTH_MAX_FIELDS + 5;
        let _ = focus.query();
        focus.found(7, Some(Id::from(auth_input_id(far))));
        assert_eq!(focus.field_for(far + 1), FocusedField::AuthAnswer(far));
        assert_eq!(focus.field_for(1), FocusedField::Text, "no such field on screen");
        let _ = focus.query();
        focus.found(8, Some(Id::new(PALETTE_INPUT_ID)));
        assert_eq!(focus.field_for(far + 1), FocusedField::Text);
    }

    /// A press anywhere, Tab and Esc may move the focus; other keys and the
    /// poll tick do not.
    #[test]
    fn presses_tab_and_esc_may_move_the_focus() {
        use keyboard::key::Named;
        let key = |named| {
            let none = keyboard::Modifiers::default();
            Message::KeyboardEvent(keyboard::Key::Named(named), none, None, false)
        };
        assert!(moves_focus(&Message::TerminalMouseDown(MouseButton::Left)));
        assert!(moves_focus(&Message::FocusMayHaveMoved));
        assert!(moves_focus(&key(Named::Tab)));
        assert!(moves_focus(&key(Named::Escape)));
        assert!(!moves_focus(&key(Named::Enter)));
        assert!(!moves_focus(&Message::PollSshEvents));
    }

    /// The candidate window is anchored on the text cursor's cell, measured
    /// from the pane origin selection and mouse reporting use: the point
    /// maps back to the same cell.
    #[test]
    fn the_candidate_window_sits_on_the_text_cursor() {
        let origin = (240.0, 64.0);
        let (x, y, h) = ime_cursor_area(origin, 13.0, (10, 2));
        assert!((x - (240.0 + 10.0 * 13.0 * 0.6)).abs() < 1e-3, "{x}");
        assert!((y - (64.0 + 2.0 * 13.0 * 1.2)).abs() < 1e-3, "{y}");
        assert!((h - 13.0 * 1.2).abs() < 1e-3, "{h}");
        let cell = grid_cell_at(x + 1.0, y + 1.0, origin, 13.0, (80, 24), false);
        assert_eq!(cell, Some((11, 3)), "1-based: the cursor's own cell");
        // The renderer's clamp: a silly font size lays out as 28.
        let clamped = ime_cursor_area((0.0, 0.0), 28.0, (1, 1));
        assert_eq!(ime_cursor_area((0.0, 0.0), 99.0, (1, 1)), clamped);
    }

    /// Full-width digits typed through an input method are the port they
    /// read as; anything that is no port is refused, never turned into 22.
    #[test]
    fn full_width_ports_are_read_and_bad_ports_refused() {
        assert_eq!(parse_port("２２２２"), Ok(Some(2222)));
        assert_eq!(parse_port("\u{3000}８０８０ "), Ok(Some(8080)));
        assert_eq!(parse_port(" 22 "), Ok(Some(22)));
        assert_eq!(parse_port("65535"), Ok(Some(65535)));
        assert_eq!(parse_port(""), Ok(None));
        assert_eq!(parse_port("\u{3000} "), Ok(None));
        for bad in ["0", "０", "65536", "22a", "+22", "-1", "2 2", "二十二", "２２.５"] {
            assert_eq!(parse_port(bad), Err(()), "{bad:?}");
        }
        assert_eq!(form_port("２２２２", 22), Ok(2222));
        assert_eq!(form_port("", 1080), Ok(1080), "a blank field takes the default");
        let err = form_port("２２２x", 22).expect_err("refused");
        assert!(err.contains("２２２x"), "names what was typed: {err}");
    }

    #[test]
    fn the_input_method_waits_for_the_focus_answer_only_where_a_secret_can_be() {
        // A form is open and a click's answer is out: off until it arrives.
        assert!(!focus_settled_or_no_secret_on_screen(false, true));
        // Answered: the focused field decides (see ime_allowed).
        assert!(focus_settled_or_no_secret_on_screen(true, true));
        // No overlay, no secret field on screen: a click never flips it.
        assert!(focus_settled_or_no_secret_on_screen(false, false));
    }

    #[test]
    fn only_the_overlays_with_a_secret_field_wait_for_the_focus_answer() {
        assert_eq!(
            Overlay::HOLDS_SECRETS,
            [Overlay::ConnectionForm, Overlay::ProxyManager, Overlay::TunnelManager, Overlay::AuthPrompt]
        );
        for overlay in [Overlay::Palette, Overlay::SftpInput, Overlay::TabRename, Overlay::Settings] {
            assert!(!Overlay::HOLDS_SECRETS.contains(&overlay), "{overlay:?}");
        }
    }

    #[test]
    fn hiding_a_panel_asks_where_the_focus_went() {
        assert!(moves_focus(&Message::ToggleBottomPanel));
        assert!(moves_focus(&Message::ToggleSidebar));
    }

    #[test]
    fn main_screen_inputs_are_reported_as_text_not_as_the_terminal() {
        use iced::advanced::widget::Id;
        for id in [SIDEBAR_SEARCH_INPUT_ID, LOCAL_PATH_INPUT_ID, REMOTE_PATH_INPUT_ID] {
            assert_eq!(FocusedField::of(Some(&Id::new(id))), FocusedField::Text, "{id}");
            assert!(!SECRET_INPUT_IDS.contains(&id), "{id}");
        }
    }

    /// Regression: a prompt showing `~` made the browser re-list on every
    /// monitor tick. The listing resolves `~` to the login directory and
    /// records that; comparing it with the prompt's `~` never settled.
    #[test]
    fn a_home_prompt_is_followed_once_not_on_every_tick() {
        let mut prompt = HashMap::new();
        let mut current = HashMap::new();
        let mut listings = HashMap::new();
        // Tick 1: the prompt shows ~ and the browser follows it.
        assert!(follow_prompt_cwd(&mut prompt, &mut current, &listings, "s", "~"));
        assert_eq!(current["s"], "~");
        // The listing arrives, resolved, and records the real directory.
        current.insert("s".to_string(), "/home/alice".to_string());
        listings.insert("s".to_string(), Listing::new("/home/alice".into(), Vec::new()));
        // The old rule compared the prompt with that directory: always due.
        assert!(cwd_sync_due(current.get("s").map(String::as_str), listings.get("s"), "~"));
        // Tick 2 and later: the prompt still shows ~ — nothing to do.
        for _ in 0..3 {
            assert!(!follow_prompt_cwd(&mut prompt, &mut current, &listings, "s", "~"));
        }
        // The user opens /var/log by hand; the idle shell does not pull the
        // browser back.
        current.insert("s".to_string(), "/var/log".to_string());
        assert!(!follow_prompt_cwd(&mut prompt, &mut current, &listings, "s", "~"));
        assert_eq!(current["s"], "/var/log");
        // The shell moves: the browser follows.
        assert!(follow_prompt_cwd(&mut prompt, &mut current, &listings, "s", "/etc"));
        assert_eq!(current["s"], "/etc");
    }

    /// Scenario: the browser shows /home/u/app; the shell cds to /etc and the
    /// sync asks for it, so `current_dir` already says /etc. A row still on
    /// screen resolves against /home/u/app — and a failed listing puts
    /// `current_dir` back, without the sync asking again every tick.
    #[test]
    fn row_actions_resolve_against_the_listing_on_screen() {
        let row = |name: &str| FileEntry { name: name.into(), ..FileEntry::default() };
        let mut listings = HashMap::new();
        listings.insert("s".to_string(), Listing::new("/home/u/app".into(), vec![row("config.yml")]));
        let mut current = HashMap::new();
        current.insert("s".to_string(), "/etc".to_string());
        let shown = &listings["s"];
        assert_eq!(shown.path_of("config.yml"), "/home/u/app/config.yml");
        assert_eq!(remote_parent(&shown.dir), "/home/u");
        assert_eq!(remote_parent("/"), "/");
        assert_eq!(Listing::new("/".into(), Vec::new()).path_of("etc"), "/etc");

        // The listing of /etc fails: back to what is shown.
        note_listing_failed(&mut current, &mut listings, "s", "/etc");
        assert_eq!(current["s"], "/home/u/app");
        assert_eq!(listings["s"].failed.as_deref(), Some("/etc"));
        assert!(!cwd_sync_due(Some("/home/u/app"), listings.get("s"), "/etc"), "not asked again");
        assert!(cwd_sync_due(Some("/home/u/app"), listings.get("s"), "/var"), "a new cwd is");
        assert!(!cwd_sync_due(Some("/var"), None, "/var"));
        assert!(cwd_sync_due(None, None, "~"));

        // A failure for a directory no longer asked for changes nothing.
        current.insert("s".to_string(), "/srv".to_string());
        note_listing_failed(&mut current, &mut listings, "s", "/etc");
        assert_eq!(current["s"], "/srv");
        // Nor for a session with nothing on screen.
        note_listing_failed(&mut current, &mut listings, "other", "/etc");
        assert!(!current.contains_key("other"));
    }

    /// Closing the focused pane of a split takes it out at once: a split
    /// pane just goes; the main pane hands the tab to the split. A `Closed`
    /// arriving after finds nothing more to do.
    #[test]
    fn closing_a_pane_promotes_the_survivor_once() {
        let mut tabs = vec![test_tab("main", "")];
        tabs[0].split = Some(test_split("split"));
        tabs[0].focus_split = true;
        let split_grid = tabs[0].split.as_ref().expect("split").terminal.clone();
        assert!(remove_split_pane(&mut tabs, "main"));
        assert_eq!(tabs[0].session_id, "split", "promoted");
        assert!(Arc::ptr_eq(&tabs[0].terminal, &split_grid), "with its own screen");
        assert!(tabs[0].split.is_none() && !tabs[0].focus_split);
        assert!(!remove_split_pane(&mut tabs, "main"), "a late Closed: nothing to do");
        assert_eq!(tabs.len(), 1);

        tabs[0].split = Some(test_split("second"));
        assert!(remove_split_pane(&mut tabs, "second"));
        assert_eq!(tabs[0].session_id, "split");
        assert!(tabs[0].split.is_none());
        assert!(!remove_split_pane(&mut tabs, "split"), "no split: the tab closes whole");
        assert!(!remove_split_pane(&mut tabs, ""));
    }

    /// Rename keeps the name exactly: "report " submitted as it opened is a
    /// no-op, not a rename to "report".
    #[test]
    fn an_unchanged_rename_is_a_no_op() {
        assert_eq!(rename_target("report ", "report "), Ok(None));
        assert_eq!(rename_target("report ", "report"), Ok(Some("report".into())));
        assert_eq!(rename_target("a", " b "), Ok(Some(" b ".into())));
        assert_eq!(rename_target("a\u{7}b", "a\u{7}b"), Ok(None), "even a name it could not type");
        assert_eq!(rename_target("a", "a/b"), Err(()));
        assert_eq!(rename_target("a", "   "), Err(()));
    }

    /// A challenge from a session no tab or pane holds any more — a connect
    /// still dialling when its tab closed — has nobody to answer it.
    #[test]
    fn a_challenge_whose_tab_is_gone_is_withdrawn() {
        let mut tabs = vec![test_tab("", "dialling")];
        tabs.push(test_tab("live", ""));
        tabs[1].split = Some(test_split("pane"));
        tabs[1].split_pending = Some("pane-dialling".into());
        for held in ["dialling", "live", "pane", "pane-dialling"] {
            assert!(!challenge_orphaned(held, &tabs), "{held}");
        }
        assert!(!challenge_orphaned("", &tabs), "a test or a deploy has its modal");
        tabs.remove(0);
        assert!(challenge_orphaned("dialling", &tabs), "its tab closed while it dialled");
        assert!(challenge_orphaned("gone", &[]));
    }

    /// Connections sort by group, then by name without regard to case, then
    /// by host — in the sidebar, and in the empty palette alike, whatever
    /// order the vault handed them over in.
    #[test]
    fn connections_keep_one_order_everywhere() {
        let mut b = sidebar_conn("3", "db", "生产");
        b.host = "10.0.0.9".into();
        let conns = vec![
            sidebar_conn("1", "web", "生产"),
            b,
            sidebar_conn("2", "DB", "生产"),
            sidebar_conn("4", "api", ""),
            sidebar_conn("5", "Build", "开发"),
        ];
        let groups = sidebar_groups(&conns, "", &HashSet::new());
        let ids: Vec<Vec<&str>> =
            groups.iter().map(|g| g.conns.iter().map(|c| c.id.as_str()).collect()).collect();
        assert_eq!(ids, [vec!["5"], vec!["2", "3", "1"], vec!["4"]]);
        let flat: Vec<&str> = ids.concat();

        let mut reversed = conns.clone();
        reversed.reverse();
        let mut sorted = reversed.clone();
        sorted.sort_by(connection_order);
        assert_eq!(sorted.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), flat);

        let palette: Vec<String> = build_palette_items("", &reversed, &[], &HashSet::new())
            .into_iter()
            .filter_map(|it| match it.msg {
                Message::ConnectTo(id) => Some(id),
                _ => None,
            })
            .collect();
        assert_eq!(palette, flat, "the empty palette lists them as the sidebar does");
    }

    /// The ungrouped bucket is found by the label it is shown under.
    #[test]
    fn the_ungrouped_bucket_is_found_by_its_label() {
        let loose = sidebar_conn("1", "db", "");
        let grouped = sidebar_conn("2", "db", "生产");
        // Whichever language is on: another test may switch it.
        let hit = |c: &ConnectionInfo, q: &str| connection_matches(c, &search_fold(q));
        assert!(hit(&loose, "Ungrouped") || hit(&loose, "未分组"));
        assert!(hit(&loose, "ungroup") || hit(&loose, "未分"));
        assert!(!hit(&grouped, "Ungrouped") && !hit(&grouped, "未分组"));
    }

    /// The palette's column budgets follow the UI font, like the sidebar's.
    #[test]
    fn palette_budgets_shrink_as_the_ui_font_grows() {
        let label = "x".repeat(PALETTE_LABEL_COLS);
        let meta = "y".repeat(PALETTE_META_COLS);
        let ((_, label_cut), (_, meta_cut)) = palette_row_text(&label, &meta, 1.0);
        assert!(!label_cut && !meta_cut, "they fit at the default size");
        let ((short, label_cut), (_, meta_cut)) = palette_row_text(&label, &meta, 1.5);
        assert!(label_cut && meta_cut, "not at 1.5×");
        assert!(crate::terminal::display_width(&short) <= cols_at_scale(PALETTE_LABEL_COLS, 1.5));
    }

    /// The reconnect marker is in the UI language, and the title still
    /// parses: its base, its host, and whether it is reconnecting.
    #[test]
    fn the_reconnect_marker_is_translated_and_still_parsed() {
        let base = "deploy@web.example.com:2222";
        let title = reconnecting_title(base, 3);
        assert!(title.starts_with(&format!("{base} [")), "{title}");
        assert!(title.contains('3'), "{title}");
        assert_eq!(title_base(&title), base);
        assert!(title_reconnecting(&title));
        assert!(!title_reconnecting(base));
        assert_eq!(host_from_title(&title), "web.example.com");
    }

    /// Every string round 5 added resolves, in either language.
    #[test]
    fn strings_added_in_round_5_resolve() {
        for key in [
            "form.err.title", "form.err.port", "conn.copy_name", "tab.reconnecting",
            "tunnel.err.no_forwards", "tunnel.err.forward_parse", "log.truncated",
            "log.err.read", "filedialog.select_key", "term.sz_refused", "status.sync_badge",
        ] {
            assert_ne!(i18n::t(key), "???", "{key}");
        }
        assert!(i18n::tf("conn.copy_name", &[("name", "db")]).contains("db"));
    }
}
