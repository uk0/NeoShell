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
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::ssh::{FileEntry, ProcessInfo, ServerStats, SshEvent, SshManager, TransferProgress};
use crate::storage::{ConnectionConfig, ConnectionInfo, ConnectionStore};
use crate::terminal::TerminalGrid;
use crate::ui::theme;

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
    KeyboardEvent(keyboard::Key, keyboard::Modifiers),

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
        .default_font(Font::MONOSPACE)
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
            // Prevent duplicate: already connected — switch to tab
            if let Some(idx) = state.tabs.iter().position(|t| t.connection_id == id) {
                state.active_tab = Some(idx);
                return Task::none();
            }
            // Prevent duplicate: already connecting (async in flight)
            if state.connecting_ids.contains(&id) {
                return Task::none();
            }
            state.connecting_ids.insert(id.clone());
            let store = state.store.clone();
            let ssh = state.ssh_manager.clone();
            let tab_id = uuid::Uuid::new_v4().to_string();
            Task::perform(
                async move {
                    let config = store.get_connection(&id)?;
                    let session_id = ssh.connect_config(&config)?;
                    let title = format!("{}@{}:{}", config.username, config.host, config.port);
                    Ok((tab_id, session_id, title, id))
                },
                |result: Result<(String, String, String, String), String>| match result {
                    Ok((tab_id, session_id, title, conn_id)) => {
                        Message::SshConnected(tab_id, session_id, title, conn_id)
                    }
                    Err(e) => Message::Error(e),
                },
            )
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
            let terminal = Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24)));
            let sid_for_fetch = session_id.clone();
            state.tabs.push(TerminalTab {
                id: tab_id,
                session_id,
                connection_id,
                title,
                terminal,
            });
            state.active_tab = Some(state.tabs.len() - 1);
            state.current_dir.insert(sid_for_fetch.clone(), "~".to_string());
            // Trigger initial file listing
            Task::done(Message::ChangeDir(sid_for_fetch, "~".to_string()))
        }
        Message::SshData(session_id, data) => {
            if let Some(tab) = state.tabs.iter().find(|t| t.session_id == session_id) {
                let mut grid = tab.terminal.lock();
                grid.write(&data);
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
            if let Some(rx) = &state.ssh_event_rx {
                while let Ok(event) = rx.try_recv() {
                    match event {
                        SshEvent::Data { session_id, data } => {
                            if let Some(tab) =
                                state.tabs.iter().find(|t| t.session_id == session_id)
                            {
                                let mut grid = tab.terminal.lock();
                                grid.write(&data);
                            }
                        }
                        SshEvent::Closed { session_id } => {
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
                                // Restore original title
                                let base = tab.title.split(" [").next().unwrap_or(&tab.title).to_string();
                                tab.title = base;
                            }
                        }
                    }
                }
            }
            Task::none()
        }

        // ---- keyboard -------------------------------------------------------
        Message::KeyboardEvent(key, modifiers) => {
            if state.screen != Screen::Main {
                return Task::none();
            }
            // Don't forward keys to terminal while editor is open
            if state.editor_file_path.is_some() {
                return Task::none();
            }
            if let Some(idx) = state.active_tab {
                if let Some(tab) = state.tabs.get(idx) {
                    let session_id = tab.session_id.clone();
                    if let Some(data) = key_to_terminal_bytes(&key, &modifiers) {
                        return Task::done(Message::TerminalInput(session_id, data));
                    }
                }
            }
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
                            let stats = ssh.fetch_server_stats(&sid)?;
                            let procs = ssh.fetch_top_processes(&sid, 15)?;
                            Ok((sid, stats, procs))
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
            state.server_stats.insert(sid.clone(), stats);
            state.top_processes.insert(sid, procs);
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
                async move { ssh.list_files(&sid_for_async, &path_async) },
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
                        let file = rfd::AsyncFileDialog::new()
                            .set_title("Select file to upload")
                            .pick_file()
                            .await;

                        if let Some(file) = file {
                            let local_path = file.path().to_string_lossy().to_string();
                            let file_name = file.file_name();
                            let remote_path = format!("{}/{}", current.trim_end_matches('/'), file_name);

                            ssh.upload_file_with_progress(&sid, &local_path, &remote_path, progress)?;
                            Ok(sid)
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
                    let save_path = rfd::AsyncFileDialog::new()
                        .set_title("Save file as")
                        .set_file_name(&filename)
                        .save_file()
                        .await;

                    if let Some(save_path) = save_path {
                        let local_path = save_path.path().to_string_lossy().to_string();
                        ssh.download_file_with_progress(&sid, &remote_path, &local_path, progress)?;
                        Ok(format!("Downloaded to {}", local_path))
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

        // ---- misc ------------------------------------------------------------
        Message::Tick => Task::none(),
        Message::None => Task::none(),
        Message::Error(e) => {
            state.error_message = e;
            state.transfer_progress = None;
            state.connecting_ids.clear();
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
    // terminal tab. We use event::listen_with so we can capture key events
    // even when the canvas does not have focus.
    if state.screen == Screen::Main && state.active_tab.is_some() {
        subs.push(event::listen_with(handle_event));
    }

    Subscription::batch(subs)
}

/// Global event handler forwarded from event::listen_with.
/// Only forward key presses that were not captured by a widget (e.g. text_input).
fn handle_event(
    evt: iced::Event,
    status: event::Status,
    _window: iced::window::Id,
) -> Option<Message> {
    match evt {
        iced::Event::Keyboard(keyboard::Event::KeyPressed {
            ref key,
            modifiers,
            ..
        }) => {
            // Always forward special keys (ESC, arrows, F-keys, etc.)
            // even if a widget "captured" them — the terminal needs these.
            let is_special = matches!(
                key,
                keyboard::Key::Named(
                    keyboard::key::Named::Escape
                    | keyboard::key::Named::ArrowUp
                    | keyboard::key::Named::ArrowDown
                    | keyboard::key::Named::ArrowLeft
                    | keyboard::key::Named::ArrowRight
                    | keyboard::key::Named::Home
                    | keyboard::key::Named::End
                    | keyboard::key::Named::PageUp
                    | keyboard::key::Named::PageDown
                    | keyboard::key::Named::Insert
                    | keyboard::key::Named::Delete
                    | keyboard::key::Named::F1
                    | keyboard::key::Named::F2
                    | keyboard::key::Named::F3
                    | keyboard::key::Named::F4
                    | keyboard::key::Named::F5
                    | keyboard::key::Named::F6
                    | keyboard::key::Named::F7
                    | keyboard::key::Named::F8
                    | keyboard::key::Named::F9
                    | keyboard::key::Named::F10
                    | keyboard::key::Named::F11
                    | keyboard::key::Named::F12
                )
            );

            // For normal characters: only forward if not captured by a widget
            if !is_special && status == event::Status::Captured {
                return None;
            }

            Some(Message::KeyboardEvent(key.clone(), modifiers))
        }
        _ => None,
    }
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
        .size(16);

    let confirm_input = text_input("Confirm password", &state.confirm_input)
        .on_input(Message::ConfirmChanged)
        .secure(true)
        .padding(10)
        .size(16);

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
            container(sidebar).width(220).height(Fill),
            right_panel,
        ]
        .height(Fill)
        .into()
    } else {
        // Not connected: connection list sidebar + welcome
        let sidebar = view_sidebar(state);
        let welcome = view_welcome();
        row![
            container(sidebar).width(220).height(Fill),
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

        let label = text(&tab.title).color(text_color).size(13);
        let close_btn = button(text("x").color(theme::TEXT_MUTED).size(11))
            .on_press(Message::TabClosed(i))
            .padding(Padding::from([2, 6]))
            .style(transparent_button_style);

        let tab_content = row![label, close_btn]
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

    // Fill remaining space with empty bar
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
        .width(220)
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
                .on_press(Message::ShowForm(None))
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
        // Load
        col = col.push(stat_row("*", &format!(
            "Load: {:.2} / {:.2} / {:.2}", stats.load_1m, stats.load_5m, stats.load_15m
        )));
        col = col.push(stat_row("#", &format!("CPU: {} cores", stats.cpu_cores)));

        // Memory
        col = col.push(stat_row(">", &format!(
            "Mem: {} / {} MB ({:.0}%)", stats.mem_used_mb, stats.mem_total_mb, stats.mem_percent
        )));
        col = col.push(progress_bar_widget(stats.mem_percent));

        // Disks (all mount points)
        if stats.disks.is_empty() {
            col = col.push(stat_row(">", &format!(
                "Disk: {:.1} / {:.1} GB ({:.0}%)", stats.disk_used_gb, stats.disk_total_gb, stats.disk_percent
            )));
            col = col.push(progress_bar_widget(stats.disk_percent));
        } else {
            for d in &stats.disks {
                let label = format!(
                    "{} {}/{}({:.0}%)",
                    truncate_str(&d.mount_point, 10),
                    d.used, d.total, d.percent,
                );
                col = col.push(stat_row(">", &label));
                col = col.push(progress_bar_widget(d.percent));
            }
        }

        // Uptime
        if !stats.uptime.is_empty() {
            col = col.push(stat_row("~", &stats.uptime));
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
        let hdr = format!("{:>6} {:>5} {:>5}  {}", "PID", "CPU%", "MEM%", "CMD");
        let mut proc_col = column![
            container(text(hdr).color(theme::TEXT_MUTED).size(9).font(Font::MONOSPACE))
                .padding(Padding::from([4, 8])),
            sidebar_divider(),
        ].spacing(0);

        for (i, p) in procs.iter().take(15).enumerate() {
            let bar_len = ((p.cpu / 100.0) * 8.0).ceil() as usize;
            let bar: String = "\u{2588}".repeat(bar_len.min(8));
            let pad: String = "\u{2591}".repeat(8_usize.saturating_sub(bar_len));

            let line = format!(
                "{:>6} {:>5.1} {:>5.1}  {}",
                p.pid, p.cpu, p.mem, truncate_str(&p.command, 12)
            );

            let color = if p.cpu > 50.0 { theme::DANGER }
                       else if p.cpu > 20.0 { theme::WARNING }
                       else { theme::TEXT_SECONDARY };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };

            proc_col = proc_col.push(
                container(
                    row![
                        text(line).color(color).size(9).font(Font::MONOSPACE),
                        horizontal_space(),
                        text(format!("{}{}", bar, pad)).color(color).size(7).font(Font::MONOSPACE),
                    ].align_y(alignment::Vertical::Center)
                )
                .padding(Padding::from([2, 8]))
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

        // Show physical interfaces
        for iface in &physical {
            let iface_clone = (*iface).clone();
            let label = format!(
                "{}: \u{2193}{} \u{2191}{}",
                truncate_str(&iface.name, 8),
                format_bytes(iface.rx_bytes),
                format_bytes(iface.tx_bytes),
            );
            col = col.push(
                button(
                    text(label).color(theme::ACCENT).size(10).font(Font::MONOSPACE)
                )
                .on_press(Message::ShowNetworkDetail(iface_clone))
                .padding(Padding::from([3, 10]))
                .width(Fill)
                .style(sidebar_item_style)
            );
        }

        // Show virtual count as summary if many
        if !virtual_ifs.is_empty() {
            let virt_rx: u64 = virtual_ifs.iter().map(|i| i.rx_bytes).sum();
            let virt_tx: u64 = virtual_ifs.iter().map(|i| i.tx_bytes).sum();
            let label = format!(
                "virtual({}): \u{2193}{} \u{2191}{}",
                virtual_ifs.len(),
                format_bytes(virt_rx),
                format_bytes(virt_tx),
            );
            col = col.push(
                container(
                    text(label).color(theme::TEXT_MUTED).size(10).font(Font::MONOSPACE)
                ).padding(Padding::from([3, 10]))
            );
        }

        // Total
        col = col.push(
            container(
                text(format!(
                    "Total: \u{2193}{} \u{2191}{}",
                    format_bytes(stats.net_rx_bytes),
                    format_bytes(stats.net_tx_bytes),
                ))
                .color(theme::TEXT_SECONDARY)
                .size(10)
                .font(Font::MONOSPACE)
            )
            .padding(Padding::from([3, 10]))
        );
    }

    // Wrap everything in a scrollable
    let sidebar_content = scrollable(col).height(Fill);

    container(sidebar_content)
        .width(220)
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

    let label = if total > 0 {
        format!("{} -- {} / {} ({:.0}%)", filename, format_bytes(transferred), format_bytes(total), pct)
    } else {
        format!("{} -- preparing...", filename)
    };

    let bar_width_fraction = (pct / 100.0).min(1.0).max(0.0);
    let filled = (bar_width_fraction * 1000.0) as u16;
    let empty = 1000_u16.saturating_sub(filled);

    let progress_text = text(label).color(theme::TEXT_PRIMARY).size(11);

    // Progress bar using FillPortion: filled portion + empty portion in a row
    let bar_inner = row![
        container(Space::new(Length::FillPortion(filled.max(1)), 4))
            .style(|_| container::Style {
                background: Some(theme::ACCENT.into()),
                border: iced::Border { radius: 2.0.into(), ..Default::default() },
                ..Default::default()
            }),
        container(Space::new(Length::FillPortion(empty.max(1)), 4))
            .style(|_| container::Style {
                background: Some(Color::TRANSPARENT.into()),
                ..Default::default()
            }),
    ].width(Fill);

    let bar_bg = container(bar_inner)
        .width(Fill)
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border { radius: 2.0.into(), ..Default::default() },
            ..Default::default()
        });

    container(
        column![progress_text, bar_bg].spacing(4).padding(Padding::from([6, 10]))
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
        .size(12)
        .font(Font::MONOSPACE);

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
        // Always add a parent directory entry first
        let parent_sid = sid.clone();
        let parent_entry = FileEntry {
            name: "..".to_string(),
            is_dir: true,
            size: String::new(),
            permissions: String::new(),
            modified: "(parent)".to_string(),
            owner: String::new(),
        };
        let parent_btn = button(
            text("  ..  (parent)")
                .color(theme::ACCENT)
                .size(11)
                .font(Font::MONOSPACE),
        )
        .on_press(Message::FileClicked(parent_sid, parent_entry))
        .padding(Padding::from([3, 10]))
        .width(Fill)
        .style(sidebar_item_style);
        file_col = file_col.push(parent_btn);

        for entry in entries.iter().filter(|e| e.name != "..") {
            let icon = if entry.is_dir { "D" } else { "F" };
            let name_color = if entry.is_dir {
                theme::ACCENT
            } else {
                theme::TEXT_PRIMARY
            };

            let name_text = text(format!("{} {}", icon, truncate_str(&entry.name, 20)))
                .color(name_color)
                .size(11)
                .font(Font::MONOSPACE);
            let size_text = text(&entry.size)
                .color(theme::TEXT_MUTED)
                .size(10)
                .font(Font::MONOSPACE);
            let date_text = text(&entry.modified)
                .color(theme::TEXT_MUTED)
                .size(10)
                .font(Font::MONOSPACE);

            let mut entry_row = row![name_text]
                .spacing(6)
                .align_y(alignment::Vertical::Center);
            entry_row = entry_row.push(horizontal_space());
            entry_row = entry_row.push(size_text);
            entry_row = entry_row.push(date_text);

            // Action buttons for files (not directories)
            if !entry.is_dir {
                let current = state.current_dir.get(&sid).cloned().unwrap_or("~".to_string());
                let full_path = format!("{}/{}", current.trim_end_matches('/'), entry.name);

                // Download button
                let dl_btn = button(text("v").color(theme::ACCENT).size(11))
                    .on_press(Message::DownloadFile(sid.clone(), full_path.clone()))
                    .padding(Padding::from([2, 4]))
                    .style(transparent_button_style);
                entry_row = entry_row.push(dl_btn);

                // Edit button (only for editable files)
                if crate::ssh::is_editable_file(&entry.name) {
                    let edit_btn = button(text("E").color(theme::SUCCESS).size(11))
                        .on_press(Message::OpenEditor(sid.clone(), full_path))
                        .padding(Padding::from([2, 4]))
                        .style(transparent_button_style);
                    entry_row = entry_row.push(edit_btn);
                }
            }

            // Wrap in a button for click-to-navigate (directories)
            if entry.is_dir {
                let entry_clone = entry.clone();
                let sid_clone = sid.clone();
                let nav_btn = button(entry_row)
                    .on_press(Message::FileClicked(sid_clone, entry_clone))
                    .padding(Padding::from([3, 10]))
                    .width(Fill)
                    .style(sidebar_item_style);
                file_col = file_col.push(nav_btn);
            } else {
                // Non-directory files: just show the row with action buttons
                file_col = file_col.push(
                    container(entry_row).padding(Padding::from([3, 10])).width(Fill),
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
        .font(Font::MONOSPACE)
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
        column![
            labeled_input(
                "Private Key Path",
                &state.form.private_key,
                Message::FormPrivateKeyChanged
            ),
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

    let group_input = labeled_input(
        "Group (optional)",
        &state.form.group,
        Message::FormGroupChanged,
    );

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
}

impl<Message> canvas::Program<Message> for TerminalView {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let grid = self.grid.lock();
        let font_size: f32 = 14.0;
        let cell_w = font_size * 0.6;
        let cell_h = font_size * 1.5;

        let mut frame = canvas::Frame::new(renderer, bounds.size());

        // Background fill
        frame.fill_rectangle(Point::ORIGIN, bounds.size(), theme::BG_PRIMARY);

        // Draw cells with wide character support.
        // Wide (CJK) chars span 2 columns; their right half is marked wide_cont.
        for y in 0..grid.rows {
            let mut x = 0;
            while x < grid.cols {
                let cell = &grid.cells[y][x];

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
                    x += char_cols;
                    continue;
                }

                let is_inv = cell.style.inverse;
                let bg = cell_color_to_iced(if is_inv { cell.style.fg } else { cell.style.bg });
                let fg = cell_color_to_iced(if is_inv { cell.style.bg } else { cell.style.fg });

                // Draw background if non-default
                if bg != theme::BG_PRIMARY {
                    frame.fill_rectangle(
                        Point::new(x as f32 * cell_w, y as f32 * cell_h),
                        Size::new(char_cols as f32 * cell_w, cell_h),
                        bg,
                    );
                }

                // Draw character
                if cell.c != ' ' && cell.c != '\0' {
                    frame.fill_text(canvas::Text {
                        content: cell.c.to_string(),
                        position: Point::new(x as f32 * cell_w, y as f32 * cell_h),
                        color: fg,
                        size: Pixels(font_size),
                        font: Font::MONOSPACE,
                        ..canvas::Text::default()
                    });
                }

                x += char_cols;
            }
        }

        // Cursor
        if grid.cursor_visible && grid.cursor_y < grid.rows && grid.cursor_x < grid.cols {
            frame.fill_rectangle(
                Point::new(
                    grid.cursor_x as f32 * cell_w,
                    grid.cursor_y as f32 * cell_h,
                ),
                Size::new(2.0, cell_h),
                theme::ACCENT,
            );
        }

        vec![frame.into_geometry()]
    }
}

/// Convert our terminal color (r, g, b fields) to an iced Color.
fn cell_color_to_iced(c: crate::terminal::Color) -> Color {
    Color::from_rgb(c.r as f32 / 255.0, c.g as f32 / 255.0, c.b as f32 / 255.0)
}

// ---------------------------------------------------------------------------
// Keyboard -> terminal byte conversion
// ---------------------------------------------------------------------------

fn key_to_terminal_bytes(key: &keyboard::Key, modifiers: &keyboard::Modifiers) -> Option<String> {
    use keyboard::key::Named;
    use keyboard::Key;

    match key {
        Key::Character(c) => {
            let s = c.as_str();
            if modifiers.control() && s.len() == 1 {
                // Ctrl+letter -> send control character (0x01..0x1A)
                let ch = s.chars().next()?;
                if ch.is_ascii_alphabetic() {
                    let ctrl_byte = (ch.to_ascii_uppercase() as u8) - b'A' + 1;
                    return Some(String::from(ctrl_byte as char));
                }
            }
            Some(s.to_string())
        }
        Key::Named(named) => {
            let seq = match named {
                Named::Enter => "\r",
                Named::Backspace => "\x7f",
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
                Named::F1 => "\x1bOP",
                Named::F2 => "\x1bOQ",
                Named::F3 => "\x1bOR",
                Named::F4 => "\x1bOS",
                Named::F5 => "\x1b[15~",
                Named::F6 => "\x1b[17~",
                Named::F7 => "\x1b[18~",
                Named::F8 => "\x1b[19~",
                Named::F9 => "\x1b[20~",
                Named::F10 => "\x1b[21~",
                Named::F11 => "\x1b[23~",
                Named::F12 => "\x1b[24~",
                Named::Space => " ",
                _ => return None,
            };
            Some(seq.to_string())
        }
        _ => None,
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

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
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
