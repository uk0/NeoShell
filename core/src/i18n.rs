use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;

static LOCALE: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

static EN: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("app.title", "NeoShell");
    // Setup
    m.insert("setup.title", "Welcome to NeoShell");
    m.insert("setup.subtitle", "Create a master password to protect your connections");
    m.insert("setup.password_placeholder", "Master password");
    m.insert("setup.confirm_placeholder", "Confirm password");
    m.insert("setup.create_vault", "Create Vault");
    m.insert("setup.err_too_short", "Password must be at least 4 characters");
    m.insert("setup.err_mismatch", "Passwords do not match");
    // Unlock
    m.insert("unlock.title", "NeoShell");
    m.insert("unlock.subtitle", "Enter master password to unlock");
    m.insert("unlock.password_placeholder", "Master password");
    m.insert("unlock.btn", "Unlock");
    m.insert("unlock.err_invalid", "Invalid password");
    // Welcome
    m.insert("welcome.title", "NeoShell");
    m.insert("welcome.subtitle", "Select a connection from the sidebar to begin");
    // Update
    m.insert("update.restart", "Restart Now");
    m.insert("update.later", "Later");
    m.insert("update.download_btn", "Download");
    // Tab
    m.insert("tab.no_tabs", "No open tabs");
    // Sidebar
    m.insert("sidebar.connections", "Connections");
    m.insert("sidebar.search", "Search...");
    m.insert("sidebar.ungrouped", "Ungrouped");
    m.insert("sidebar.no_results", "No connections found");
    // Dialog
    m.insert("dialog.connect_title", "Connect to Server");
    m.insert("dialog.new_btn", "+ New");
    m.insert("dialog.no_saved", "No saved connections");
    m.insert("dialog.edit", "Edit");
    m.insert("dialog.delete", "Del");
    m.insert("dialog.ssh_config", "From ~/.ssh/config");
    m.insert("dialog.ssh_config_label", "ssh config");
    m.insert("dialog.keyboard_hint", "Cmd+T open | Cmd+1-9 switch tabs | Ctrl+Tab next | Cmd+W close");
    // Monitor
    m.insert("monitor.system", "System");
    m.insert("monitor.load", "Load");
    m.insert("monitor.cpu", "CPU");
    m.insert("monitor.mem", "Mem");
    m.insert("monitor.disk", "Disk");
    m.insert("monitor.uptime", "Up");
    m.insert("monitor.connecting", "Connecting...");
    m.insert("monitor.processes", "Top Processes");
    m.insert("monitor.pid", "PID");
    m.insert("monitor.proc_cpu", "CPU");
    m.insert("monitor.proc_mem", "MEM");
    m.insert("monitor.proc_cmd", "CMD");
    m.insert("monitor.loading", "Loading...");
    m.insert("monitor.network", "Network");
    m.insert("monitor.total", "Total");
    // Net detail
    m.insert("netdetail.close", "Close");
    m.insert("netdetail.interface", "Interface");
    m.insert("netdetail.rx", "Received (Rx)");
    m.insert("netdetail.tx", "Transmitted (Tx)");
    m.insert("netdetail.total_traffic", "Total Traffic");
    m.insert("netdetail.type", "Type");
    m.insert("netdetail.ethernet", "Ethernet");
    m.insert("netdetail.wireless", "Wireless");
    m.insert("netdetail.docker", "Docker Bridge");
    m.insert("netdetail.veth", "Virtual Ethernet (Container)");
    m.insert("netdetail.bond", "Bond");
    m.insert("netdetail.vpn", "VPN Tunnel");
    m.insert("netdetail.loopback", "Loopback");
    m.insert("netdetail.other", "Other");
    // Form
    m.insert("form.edit_title", "Edit Connection");
    m.insert("form.new_title", "New Connection");
    m.insert("form.name", "Name");
    m.insert("form.host", "Host");
    m.insert("form.port", "Port");
    m.insert("form.username", "Username");
    m.insert("form.auth_type", "Auth Type");
    m.insert("form.password", "Password");
    m.insert("form.private_key", "Private Key");
    m.insert("form.key_path", "Private Key Path");
    m.insert("form.browse", "Browse...");
    m.insert("form.passphrase", "Passphrase (optional)");
    m.insert("form.group", "Group (optional)");
    m.insert("form.cancel", "Cancel");
    m.insert("form.save", "Save");
    m.insert("form.test", "Test");
    m.insert("form.testing", "Testing...");
    m.insert("form.test_ok", "OK");
    m.insert("form.test_fail", "Failed");
    m.insert("form.keep_existing", "(unchanged — leave empty to keep)");
    m.insert("conn.clone", "Clone");
    m.insert("conn.test", "Test");
    m.insert("shortcuts.title", "Keyboard Shortcuts");
    m.insert("shortcuts.close", "Close");
    m.insert("shortcuts.group.tabs",     "Tabs");
    m.insert("shortcuts.group.split",    "Split panes");
    m.insert("shortcuts.group.terminal", "Terminal");
    m.insert("shortcuts.group.panels",   "Panels");
    m.insert("shortcuts.group.other",    "Other");
    m.insert("shortcuts.desc.rename_tab",   "Double-click a tab to rename it");
    m.insert("shortcuts.desc.palette",      "Command palette (connections / actions / snippets)");
    m.insert("shortcuts.desc.split_v",      "Split tab side-by-side (same host, new shell)");
    m.insert("shortcuts.desc.split_h",      "Split tab top/bottom");
    m.insert("shortcuts.desc.split_focus",  "Switch focus between panes (or click a pane)");
    m.insert("shortcuts.desc.split_close",  "Close the focused pane");
    m.insert("shortcuts.desc.connect",         "Open connection dialog");
    m.insert("shortcuts.desc.close_tab",       "Close active tab");
    m.insert("shortcuts.desc.switch_tab",      "Switch to tab N");
    m.insert("shortcuts.desc.next_tab",        "Next tab");
    m.insert("shortcuts.desc.prev_tab",        "Previous tab");
    m.insert("shortcuts.desc.paste",           "Paste clipboard into terminal");
    m.insert("shortcuts.desc.copy",            "Copy selection to clipboard");
    m.insert("shortcuts.desc.right_click",     "Paste clipboard (right-click in session)");
    m.insert("shortcuts.desc.mouse_select",    "Drag-select with left button — auto-copies to clipboard on release");
    m.insert("shortcuts.desc.sigint",          "Send SIGINT to the running command (interrupt)");
    m.insert("shortcuts.desc.search",          "Find in terminal scrollback");
    m.insert("shortcuts.desc.search_next",     "Next search match");
    m.insert("shortcuts.desc.search_close",    "Close search bar");
    m.insert("shortcuts.desc.history",         "Toggle command history panel");
    m.insert("shortcuts.desc.help",            "Toggle this help panel");
    m.insert("shortcuts.desc.bottom_toggle",   "Collapse / expand bottom panel");
    m.insert("shortcuts.desc.editor_save",     "Save file (when editor open)");
    m.insert("shortcuts.desc.close_dialog",    "Close any open dialog");
    m.insert("shortcuts.desc.quit",            "Quit application (× only minimizes)");
    m.insert("err.title", "Connection Error");
    m.insert("err.view_log", "View Log");
    m.insert("err.dismiss", "Dismiss");
    m.insert("log.title", "Log Viewer");
    m.insert("log.refresh", "Refresh");
    m.insert("log.open_folder", "Open Folder");
    m.insert("status.log", "LOG");
    m.insert("status.quit", "QUIT");
    m.insert("tunnel.title", "Tunnels");
    m.insert("tunnel.add", "+ Add Tunnel");
    m.insert("tunnel.edit", "Edit Tunnel");
    m.insert("tunnel.name", "Name");
    m.insert("tunnel.ssh_host", "SSH Host");
    m.insert("tunnel.ssh_port", "Port");
    m.insert("tunnel.user", "Username");
    m.insert("tunnel.forwards_label", "Port Forwards");
    m.insert("tunnel.forwards_hint", "One per line: LOCAL:REMOTE_HOST:REMOTE_PORT (e.g. 8080:10.0.0.5:80)");
    m.insert("tunnel.empty", "No tunnels configured");
    m.insert("tunnel.start", "Start");
    m.insert("tunnel.stop", "Stop");
    m.insert("tunnel.running", "Running");
    m.insert("tunnel.stopped", "Stopped");
    m.insert("tunnel.starting", "Starting...");
    m.insert("theme.title", "Appearance");
    m.insert("theme.zone.text_primary", "Primary text");
    m.insert("theme.zone.accent", "Accent (buttons / links)");
    m.insert("theme.zone.terminal_fg", "Terminal foreground");
    m.insert("theme.zone.terminal_bg", "Terminal background");
    m.insert("theme.zone.success", "Success / running");
    m.insert("theme.zone.danger", "Danger / stopped");
    m.insert("theme.zone.progress_bar", "Progress bar (monitor)");
    m.insert("theme.terminal_font_size", "Terminal font size");
    m.insert("theme.ui_font_size", "UI font size");
    m.insert("theme.reset", "Reset to defaults");
    m.insert("dialog.ssh_config_import_all", "Import all ({count})");
    m.insert("broadcast.title", "Broadcast command");
    m.insert("broadcast.hint", "Command will be sent to every ticked session (appends \\n)");
    m.insert("broadcast.sessions", "Active sessions");
    m.insert("broadcast.send", "Send to ticked");
    m.insert("broadcast.empty", "No active sessions to broadcast to");
    m.insert("snippet.title", "Snippets");
    m.insert("snippet.new", "New snippet");
    m.insert("snippet.name_placeholder", "Name (e.g. 'docker ps')");
    m.insert("snippet.body_placeholder", "Command or script body");
    m.insert("snippet.save", "Save");
    m.insert("snippet.send", "Send to active tab");
    m.insert("snippet.empty", "No snippets yet — create one below");
    m.insert("btn.broadcast", "Broadcast");
    m.insert("btn.snippets", "Snippets");
    m.insert("search.placeholder", "Search terminal (Cmd+F)");
    m.insert("search.no_matches", "0/0");
    m.insert("search.prev", "Prev");
    m.insert("search.next", "Next");
    m.insert("search.close", "Close");
    // v0.7.0 — command palette
    m.insert("palette.placeholder", "Type to search connections, actions, snippets…");
    m.insert("palette.empty", "No matches");
    m.insert("palette.hint", "↑↓ navigate · Enter run · Esc close");
    m.insert("palette.kind.conn", "CONN");
    m.insert("palette.kind.action", "ACT");
    m.insert("palette.kind.snippet", "SNIP");
    m.insert("palette.act.new_conn", "New connection");
    m.insert("palette.act.connect", "Open connect dialog");
    m.insert("palette.act.settings", "Open settings");
    m.insert("palette.act.broadcast", "Broadcast command");
    m.insert("palette.act.snippets", "Open snippets");
    m.insert("palette.act.keys", "SSH key manager");
    m.insert("palette.act.tunnels", "Tunnel manager");
    m.insert("palette.act.proxies", "Proxy manager");
    m.insert("palette.act.history", "Command history");
    m.insert("palette.act.logs", "Log viewer");
    m.insert("palette.act.sync", "Toggle live sync input");
    m.insert("palette.act.split_v", "Split pane (vertical)");
    m.insert("palette.act.split_h", "Split pane (horizontal)");
    m.insert("palette.act.import_ssh", "Import all from ~/.ssh/config");
    // v0.7.0 — tab rename
    m.insert("tabrename.title", "Rename tab");
    m.insert("tabrename.hint", "Empty name restores the automatic user@host title");
    m.insert("tabrename.placeholder", "Tab name");
    m.insert("tabrename.save", "Save");
    // v0.7.0 — sync input
    m.insert("broadcast.sync_on", "LIVE SYNC: ON");
    m.insert("broadcast.sync_off", "Live sync: off");
    m.insert("broadcast.sync_hint", "Live sync mirrors every keystroke in the focused terminal to all ticked sessions — including Enter and Ctrl+C. Use with care.");
    // v0.7.0 — threshold alerts
    m.insert("alerts.title", "Resource alerts");
    m.insert("alerts.hint", "Red dot on the tab + status-bar warning when a session crosses a threshold (checked every 3 s)");
    m.insert("alerts.on", "ON");
    m.insert("alerts.off", "OFF");
    m.insert("alerts.cpu", "CPU load threshold");
    m.insert("alerts.mem", "Memory threshold");
    m.insert("alerts.disk", "Disk threshold");
    // v0.7.0 — SSH key manager
    m.insert("btn.keys", "Keys");
    m.insert("keys.title", "SSH key manager");
    m.insert("keys.empty", "No keys found in ~/.ssh");
    m.insert("keys.copy", "Copy pubkey");
    m.insert("keys.deploy", "Deploy to…");
    m.insert("keys.pick_target", "Deploy to which connection?");
    m.insert("keys.gen_title", "Generate new key (ed25519)");
    m.insert("keys.gen_name", "File name (e.g. id_ed25519_work)");
    m.insert("keys.gen_comment", "Comment (e.g. ops@laptop)");
    m.insert("keys.gen_btn", "Generate");
    m.insert("keys.gen_hint", "Written to ~/.ssh/<name> + .pub (0600). Never overwrites existing files.");
    m.insert("keys.generated", "Key generated");
    m.insert("keys.copied", "Public key copied to clipboard");
    m.insert("keys.deploying", "Deploying…");
    m.insert("keys.deploy_ok", "Deployed to");
    // SSH error hints
    m.insert("ssh.err.auth", "wrong username/password or key — check credentials or server sshd permissions");
    m.insert("ssh.err.refused", "target port closed — confirm SSH service is running on the right port (usually 22)");
    m.insert("ssh.err.timeout", "no response — check network connectivity, IP/domain, or whether a proxy/bastion is required");
    m.insert("ssh.err.no_route", "route unreachable — host may be offline or firewall is blocking inbound");
    m.insert("ssh.err.host_key", "host key changed — server may have been reinstalled, or this could be a MitM attack");
    m.insert("ssh.err.dns", "DNS resolve failed — check spelling or use an IP instead of a domain");
    m.insert("ssh.err.kex", "no common KEX algorithm — server disabled modern KEX, ask admin to enable broader algorithms");
    m.insert("ssh.err.denied", "permission denied — check username, key permissions (chmod 600), or authorized_keys");
    m.insert("ssh.err.key_missing", "private key file not found — choose a valid key path");
    m.insert("ssh.err.key_format", "invalid private key format — must be OpenSSH/PEM, PuTTY .ppk needs conversion");
    m.insert("ssh.err.reset", "connection closed by peer — likely idle timeout or server-side disconnect");
    // File browser
    m.insert("filebrowser.upload", "^ Upload");
    m.insert("filebrowser.loading", "Loading files...");
    // File dialog
    m.insert("filedialog.upload", "Select file to upload");
    m.insert("filedialog.save", "Save file as");
    m.insert("filedialog.select_key", "Select Private Key");
    m.insert("filedialog.rz_upload", "rz: Select file to upload");
    // Editor
    m.insert("editor.save", "Save");
    m.insert("editor.close", "Close");
    // Status
    m.insert("status.no_session", "No active session");
    m.insert("status.version", "NeoShell v{version}");
    // Transfer
    m.insert("transfer.cancel", "Cancel");
    m.insert("transfer.preparing", "{name} — preparing...");
    // Update (with params)
    m.insert("update.ready", "NeoShell {version} ready");
    m.insert("update.available", "Update available: v{version}");
    m.insert("update.downloading", "Downloading v{version}... {percent}%");
    // Monitor (with params)
    m.insert("monitor.cpu_cores", "{count} cores");
    m.insert("monitor.virtual_count", "virtual({count})");
    m.insert("monitor.speed", "Speed: ↓{down}/s ↑{up}/s");
    // Net detail (with params)
    m.insert("netdetail.title", "Interface: {name}");
    // File browser (with params)
    m.insert("filebrowser.dir", "[DIR] {path}");
    // Settings menu
    m.insert("settings.title", "Settings");
    m.insert("settings.language", "Language");
    m.insert("settings.scale", "UI Scale");
    m.insert("settings.about", "About NeoShell");
    m.insert("settings.sidebar", "Toggle Sidebar");
    m.insert("settings.close", "Close");
    // About
    m.insert("about.title", "About NeoShell");
    m.insert("about.version", "Version {version}");
    m.insert("about.desc", "A cross-platform SSH terminal manager built with Rust.");
    m.insert("about.tech", "Rust • iced • wgpu • AES-256-GCM • Argon2id");
    m.insert("about.copyright", "© 2026 NeoShell — All Rights Reserved");
    m.insert("about.close", "Close");
    // History
    m.insert("history.title", "Command History");
    m.insert("history.filter", "Filter commands...");
    m.insert("history.empty", "No commands yet");
    m.insert("history.clear", "Clear");
    // Proxy
    m.insert("proxy.title", "Proxy Manager");
    m.insert("proxy.add", "+ Add Proxy");
    m.insert("proxy.name", "Name");
    m.insert("proxy.type", "Type");
    m.insert("proxy.host", "Host");
    m.insert("proxy.port", "Port");
    m.insert("proxy.username", "Username");
    m.insert("proxy.password", "Password");
    m.insert("proxy.save", "Save");
    m.insert("proxy.cancel", "Cancel");
    m.insert("proxy.test", "Test");
    m.insert("proxy.delete", "Del");
    m.insert("proxy.edit", "Edit");
    m.insert("proxy.empty", "No proxies configured");
    m.insert("proxy.ok", "OK");
    m.insert("proxy.fail", "Fail");
    m.insert("proxy.testing", "...");
    m.insert("proxy.none", "Direct (no proxy)");
    m.insert("proxy.select", "Proxy");
    m.insert("proxy.type.bastion", "SSH Bastion");
    m.insert("proxy.bastion.auth_password", "Password");
    m.insert("proxy.bastion.auth_key", "Private Key");
    m.insert("proxy.bastion.key_path", "Private key path");
    m.insert("proxy.bastion.browse", "Browse");
    m.insert("proxy.bastion.passphrase", "Key passphrase (optional)");
    // UI elements
    m.insert("btn.close", "x");
    m.insert("btn.refresh", "R");
    m.insert("btn.send", "Send");
    m.insert("btn.edit", "E");
    m.insert("btn.download", "v");
    m.insert("bottom.files", "Files");
    m.insert("bottom.cmd", "Cmd");
    m.insert("process.title", "Process Info");
    m.insert("process.child", "Child Processes");
    m.insert("process.listen", "Listening Ports");
    m.insert("process.net", "Network Connections");
    m.insert("process.fds", "Open Files");
    m.insert("process.threads", "Threads");
    m.insert("net.speed", "Speed");
    m.insert("net.interface", "Interface");
    m.insert("net.received", "Received");
    m.insert("net.sent", "Sent");
    m.insert("file.name", "Name");
    m.insert("file.size", "Size");
    m.insert("file.modified", "Modified");
    m.insert("file.send_prefix", "Send:");
    m.insert("settings.font_size", "Font Size");
    m.insert("status.shortcuts", "{mod}+H:History  {mod}+T:Connect");
    m.insert("welcome.select", "Select a connection from the sidebar to begin");
    m.insert("confirm.delete", "Delete \"{name}\"?");
    m.insert("vault.locked_secret", "Vault is locked — unlock it to use this credential.");
    m.insert("vault.no_credential", "No stored credential — unlock the vault, or re-enter it in the settings.");
    m.insert("lock.now", "LOCK");
    m.insert("settings.lock_now", "Lock now");
    m.insert("settings.lock_timeout", "Auto-lock");
    m.insert("settings.lock_never", "Never");
    m.insert("settings.lock_minutes", "{n} min");
    m.insert("shortcuts.desc.lock", "Lock the vault now (sessions stay connected)");
    // UI pass: tooltips on glyph-only controls, welcome screen, error copy,
    // palette route to the sidebar row actions.
    m.insert("tip.sidebar_hide", "Hide sidebar");
    m.insert("tip.sidebar_show", "Show sidebar");
    m.insert("tip.panel_hide", "Hide bottom panel");
    m.insert("tip.panel_show", "Show bottom panel");
    m.insert("tip.close", "Close");
    m.insert("tip.close_tab", "Close tab");
    m.insert("tip.parent_dir", "Parent folder");
    m.insert("tip.replay", "Run again");
    m.insert("tip.decrease", "Decrease");
    m.insert("tip.increase", "Increase");
    m.insert("tip.delete", "Delete");
    m.insert("tip.match_case", "Match case");
    m.insert("welcome.subtitle_empty", "Add a server to get started");
    m.insert("welcome.import_ssh", "Import from ~/.ssh/config ({count})");
    m.insert("err.copy", "Copy");
    m.insert("err.copied", "Copied");
    m.insert("palette.act.edit_conn", "Edit: {name}");
    m.insert("palette.act.test_conn", "Test: {name}");
    m.insert("palette.act.clone_conn", "Clone: {name}");
    m.insert("palette.act.delete_conn", "Delete: {name}");
    // Feature wiring: SFTP file operations, folder transfer, drag-and-drop,
    // keyboard-interactive auth, process kill, listening ports, presets.
    m.insert("sftp.new_folder", "New folder");
    m.insert("sftp.rename", "Rename");
    m.insert("sftp.permissions", "Permissions");
    m.insert("sftp.delete", "Delete");
    m.insert("sftp.new_folder_title", "New folder in {dir}");
    m.insert("sftp.rename_title", "Rename \"{name}\"");
    m.insert("sftp.chmod_title", "Permissions of \"{name}\"");
    m.insert("sftp.name_hint", "A single name, without \"/\"");
    m.insert("sftp.mode_hint", "Octal, e.g. 755 or 0644");
    m.insert("sftp.err_name", "Enter a single file name: not empty, no \"/\", not \".\" or \"..\"");
    m.insert("sftp.err_mode", "Enter 1-4 octal digits (0-7), e.g. 755");
    m.insert("sftp.ok", "OK");
    m.insert("sftp.apply", "Apply");
    m.insert("sftp.confirm_delete", "Delete this file? This cannot be undone.");
    m.insert("sftp.confirm_delete_dir", "Delete this folder and everything inside it? This cannot be undone.");
    m.insert("sftp.confirm_chmod", "Change permissions to {mode}?");
    m.insert("filebrowser.upload_dir", "^ Folder");
    m.insert("filedialog.upload_dir", "Select folder to upload");
    m.insert("filedialog.download_dir", "Choose where to save the folder");
    m.insert("tip.upload_dir", "Upload a folder");
    m.insert("tip.download_dir", "Download folder");
    m.insert("transfer.busy", "A transfer is already running — wait for it, or cancel it first.");
    m.insert("drop.no_target", "Nowhere to upload to: open a session and let the Files tab load a remote folder first.");
    m.insert("quickcmd.accept_hint", "Tab / ↓ to accept · click to pick");
    m.insert("auth.title", "Server authentication");
    m.insert("auth.from_server", "Asked by the server; your answers go only to it. NeoShell never asks for the master password here.");
    m.insert("auth.continue", "Continue");
    m.insert("auth.queued", "{count} more waiting");
    m.insert("auth.purpose.shell", "terminal session");
    m.insert("auth.purpose.exec", "monitor / file transfer connection");
    m.insert("auth.purpose.reconnect", "reconnect");
    m.insert("auth.purpose.test", "connection test");
    m.insert("auth.purpose.deploy", "key deployment");
    m.insert("form.auth_interactive", "Interactive");
    m.insert("form.auth_agent", "Agent");
    m.insert("form.password_optional", "Password (optional)");
    m.insert("form.interactive_hint", "For PAM / one-time-code logins. The server's questions appear in a dialog; a saved password answers a plain password prompt.");
    m.insert("form.agent_hint", "Uses the keys loaded in your ssh-agent (SSH_AUTH_SOCK). Nothing is stored.");
    m.insert("process.sigterm", "SIGTERM");
    m.insert("process.sigkill", "SIGKILL");
    m.insert("process.sigterm_tip", "Ask the process to exit");
    m.insert("process.sigkill_tip", "Force-kill the process");
    m.insert("process.confirm_kill", "Send {signal} to PID {pid}?");
    m.insert("process.send_signal", "Send");
    m.insert("bottom.ports", "Ports");
    m.insert("ports.title", "Listening ports");
    m.insert("ports.hint", "Click a row to inspect its process");
    m.insert("ports.proto", "Proto");
    m.insert("ports.addr", "Address");
    m.insert("ports.port", "Port");
    m.insert("ports.pid", "PID");
    m.insert("ports.process", "Process");
    m.insert("ports.loading", "Loading...");
    m.insert("ports.empty", "No listening sockets found (ss / netstat may be missing on this host)");
    m.insert("monitor.swap", "Swap");
    m.insert("theme.preset", "Color scheme");
    m.insert("shortcuts.desc.shift_select", "Select text even while a program (vim, htop, tmux) reads the mouse");
    m.insert("shortcuts.desc.drop_upload", "Drop files or folders on the window to upload them to the remote folder");
    m.insert("confirm.on_host", "on {host}");
    m.insert("transfer.bad_local", "Cannot upload \"{path}\": it has no name to give the remote copy.");
    // ssh/mod.rs: SFTP / kill / agent + interactive auth errors
    m.insert("sftp.err.path_empty", "remote path is empty");
    m.insert("sftp.err.path_control", "remote path contains a control character");
    m.insert("sftp.err.path_relative", "remote path must be absolute: {path}");
    m.insert("sftp.err.path_root", "refusing to operate on the filesystem root '/'");
    m.insert("sftp.err.path_dotdot", "remote path must not contain '..': {path}");
    m.insert("sftp.err.not_dir", "'{path}' exists and is not a directory");
    m.insert("sftp.err.mkdir", "Failed to create remote directory '{path}': {err}");
    m.insert("sftp.err.rename", "Failed to rename '{from}' to '{to}': {err}");
    m.insert("sftp.err.bad_mode", "invalid permission bits: {mode}");
    m.insert("sftp.err.chmod", "Failed to chmod '{path}' to {mode}: {err}");
    m.insert("sftp.err.too_deep", "refusing to recurse past {max} levels at '{path}'");
    m.insert("sftp.err.stat", "Failed to stat '{path}': {err}");
    m.insert("sftp.err.list", "Failed to list '{path}': {err}");
    m.insert("sftp.err.bad_entry", "the server listed an entry under '{path}' whose name cannot be deleted exactly as listed — nothing was deleted");
    m.insert("sftp.err.unaddressable", "'{path}' cannot be addressed exactly from this system: its SFTP library would send '\\' as '/' — nothing was deleted");
    m.insert("sftp.err.delete", "Failed to delete '{path}': {err}");
    m.insert("sftp.err.rmdir", "Failed to remove directory '{path}': {err}");
    m.insert("process.err.kill_exit", "kill -{signal} {pid} failed (exit {status})");
    m.insert("process.err.kill", "kill -{signal} {pid} failed: {detail}");
    m.insert("auth.err.no_handler", "the server asked an interactive question but no prompt handler is registered");
    m.insert("auth.err.handler_gone", "the prompt handler is gone");
    m.insert("auth.err.no_answer", "no answer to the server's challenge: {err}");
    m.insert("auth.err.agent_unavailable", "ssh-agent unavailable: {err}");
    m.insert("auth.err.agent_connect", "could not connect to ssh-agent: {err} (is SSH_AUTH_SOCK set?)");
    m.insert("auth.err.agent_list", "could not list ssh-agent identities: {err}");
    m.insert("auth.err.agent_read", "could not read ssh-agent identities: {err}");
    m.insert("auth.err.agent_empty", "ssh-agent holds no identities (run `ssh-add` first)");
    m.insert("auth.err.agent_rejected", "no ssh-agent identity was accepted ({count} tried, last: {last})");
    // ssh/mod.rs + proxy.rs: exec-connection rebuild gate, proxy credentials
    m.insert("exec.err.needs_reconnect", "Monitoring and file access for this session are paused: the connection behind them dropped, and re-opening it would mean another sign-in challenge. Reconnect the session to resume.");
    m.insert("exec.err.rebuilding", "The connection behind monitoring and file access is being re-established — try again in a moment.");
    m.insert("exec.err.cooldown", "The connection behind monitoring and file access could not be re-established; the next attempt is in {secs}s.");
    m.insert("proxy.err.missing", "Proxy '{id}' is configured for this connection but no longer exists. Refusing to connect directly — re-create the proxy or clear it from the connection.");
    m.insert("proxy.err.vault_locked", "Vault is locked — unlock it to reconnect through proxy '{name}'.");
    m.insert("proxy.err.no_password", "Proxy '{name}' has a username but no password — unlock the vault, or re-enter the password in the proxy settings.");
    // ssh/mod.rs: reconnect cancel, skipped names, local folder errors
    m.insert("ssh.err.reconnect_cancelled", "Reconnect cancelled: the sign-in challenge was dismissed.");
    m.insert("sftp.err.skipped_names", "{count} item(s) skipped: names not representable on this system.");
    m.insert("transfer.err.not_dir", "'{path}' is not a directory");
    m.insert("transfer.err.local_empty", "The local directory path is empty.");
    m.insert("transfer.err.local_mkdir", "Failed to create local directory '{path}': {err}");
    m.insert("transfer.err.local_read_dir", "Failed to read local directory '{path}': {err}");
    // app.rs: unlock-time history warning, parked monitoring, skipped items
    m.insert("history.warn.title", "Command history not saved");
    m.insert("history.warn.unsettled", "The previous write of the command history has not finished, so the commands you run in this session will not be saved. They stay in the history panel until the vault locks or NeoShell quits.");
    m.insert("history.warn.unreadable", "The command history file could not be read, nor moved aside to start a new one, so the commands you run in this session will not be saved. See the log for details.");
    m.insert("monitor.parked", "Monitoring paused — this server requires a verification code");
    m.insert("monitor.reconnect", "Reconnect monitoring");
    m.insert("monitor.reconnecting", "Reconnecting...");
    m.insert("notice.skipped_title", "Finished — some items were skipped");
    // ssh/mod.rs: type-checked SFTP ops, backslash paths, exec sign-in, session ids
    m.insert("sftp.err.changed", "'{path}' has changed since it was listed — refresh and try again. Nothing was changed.");
    m.insert("sftp.err.chmod_symlink", "'{path}' is a symbolic link: over SFTP its permissions cannot be changed without changing the file it points to instead. Nothing was changed.");
    m.insert("sftp.err.path_backslash", "remote path must not contain a backslash: {path}");
    m.insert("auth.err.exec_interactive", "Keyboard-interactive sign-in failed for the monitoring / file transfer connection: {err}");
    m.insert("auth.err.exec_agent", "SSH agent sign-in failed for the monitoring / file transfer connection: {err}");
    m.insert("ssh.err.bad_session_id", "Session id '{id}' is invalid or already in use.");
    // tunnel.rs: forward-rule parse errors, tunnel store and runtime failures
    m.insert("tunnel.err.bad_socks_port", "bad SOCKS5 listen port '{port}': {err}");
    m.insert("tunnel.err.socks_port_zero", "SOCKS5 listen port must not be 0");
    m.insert("tunnel.err.bad_remote", "invalid remote: {remote}");
    m.insert("tunnel.err.bad_remote_port", "bad remote port '{port}': {err}");
    m.insert("tunnel.err.bad_local_port", "bad local port '{port}': {err}");
    m.insert("tunnel.err.bad_rule", "expected 'LOCAL:REMOTE_HOST:REMOTE_PORT', 'REMOTE:PORT->LOCAL:PORT', 'R:LOCAL:REMOTE_HOST:REMOTE_PORT' or 'D:LOCAL', got '{rule}'");
    m.insert("tunnel.err.missing_host", "missing remote host in '{rule}'");
    m.insert("tunnel.err.not_found", "Tunnel '{id}' not found");
    m.insert("tunnel.err.vault_not_retained", "vault did not retain the credential for tunnel '{id}' — leaving {path} as it is");
    m.insert("tunnel.err.bind", "bind {addr}: {err}");
    m.insert("tunnel.err.remote_listen", "remote listen on {bind}:{port}: {err} (the server may need GatewayPorts for a non-loopback bind)");
    m.insert("tunnel.err.remote_accept", "remote accept on port {port}: {err}");
    // app.rs: type-stated SFTP confirmations, fresh kill check, groups, i18n pass
    m.insert("sftp.kind.file", "file");
    m.insert("sftp.kind.dir", "folder");
    m.insert("sftp.kind.symlink", "symbolic link");
    m.insert("sftp.kind.other", "special file");
    m.insert("sftp.confirm_delete_named", "Delete the {kind} “{name}”? This cannot be undone.");
    m.insert("sftp.confirm_delete_dir_named", "Delete the folder “{name}” and everything inside it? This cannot be undone.");
    m.insert("sftp.confirm_delete_link_named", "Delete the symbolic link “{name}”? Only the link is removed; what it points to is left alone.");
    m.insert("sftp.confirm_chmod_named", "Change the permissions of the {kind} “{name}” to {mode}?");
    m.insert("sftp.rename_title_named", "Rename the {kind} “{name}”");
    m.insert("sftp.chmod_title_named", "Permissions of the {kind} “{name}”");
    m.insert("sftp.name_marks", "In the name, · stands for a space at its start or end or next to another space, and \\u{…} for a character that would not show.");
    m.insert("process.err.gone", "Process {pid} is no longer running. No signal was sent.");
    m.insert("process.err.changed", "PID {pid} now belongs to a different process than the one you confirmed. No signal was sent.");
    m.insert("process.signal_n", "signal {n}");
    m.insert("files.parked", "File browsing paused — this server requires a verification code");
    m.insert("tunnel.err.start", "Could not start the tunnel: {err}");
    m.insert("shortcuts.key.drag", "Drag");
    m.insert("shortcuts.key.shift_drag", "Shift+Drag");
    m.insert("shortcuts.key.right_click", "Right-click");
    m.insert("shortcuts.key.drop", "Drop");
    m.insert("tab.split_suffix", "{title} (split)");
    m.insert("sidebar.collapse_all", "Collapse all groups");
    m.insert("sidebar.expand_all", "Expand all groups");
    m.insert("palette.act.collapse_group", "Collapse group “{name}”");
    m.insert("palette.act.expand_group", "Expand group “{name}”");
    m.insert("sftp.err.unverified", "'{path}' was not changed: this server offers no SFTP, so the folder was listed from the shell and its entries cannot be changed safely from the file browser.");
    m.insert("sftp.err.not_utf8", "'{path}' cannot be addressed exactly from this system: its name on the server is not valid UTF-8, or could not be read exactly. Nothing was changed.");
    m.insert("sftp.err.start", "Could not start SFTP: {err}");
    // app.rs: form validation, copied connection, reconnect marker, log viewer
    m.insert("form.err.title", "Check the form");
    m.insert("form.err.port", "“{port}” is not a port. Enter a number from 1 to 65535.");
    m.insert("conn.copy_name", "{name} (Copy)");
    m.insert("tab.reconnecting", "{title} [Reconnecting... {n}]");
    m.insert("tunnel.err.no_forwards", "At least one forward rule is required.");
    m.insert("tunnel.err.forward_parse", "Forward rule not understood: {err}");
    m.insert("log.truncated", "…(showing the last {kb} KB)…");
    m.insert("log.err.read", "Cannot read the log file {path}: {err}");
    m.insert("term.sz_refused", "[NeoShell] sz: refusing unsafe remote filename {name}");
    m.insert("status.sync_badge", "SYNC {n}");
    m
});

static ZH: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("app.title", "NeoShell");
    m.insert("setup.title", "欢迎使用 NeoShell");
    m.insert("setup.subtitle", "创建主密码以保护您的连接配置");
    m.insert("setup.password_placeholder", "主密码");
    m.insert("setup.confirm_placeholder", "确认密码");
    m.insert("setup.create_vault", "创建保险库");
    m.insert("setup.err_too_short", "密码长度不能少于 4 个字符");
    m.insert("setup.err_mismatch", "两次输入的密码不一致");
    m.insert("unlock.title", "NeoShell");
    m.insert("unlock.subtitle", "输入主密码以解锁");
    m.insert("unlock.password_placeholder", "主密码");
    m.insert("unlock.btn", "解锁");
    m.insert("unlock.err_invalid", "密码错误");
    m.insert("welcome.title", "NeoShell");
    m.insert("welcome.subtitle", "从左侧选择一个连接以开始");
    m.insert("update.restart", "立即重启");
    m.insert("update.later", "稍后");
    m.insert("update.download_btn", "下载");
    m.insert("tab.no_tabs", "暂无打开的标签");
    m.insert("sidebar.connections", "连接列表");
    m.insert("sidebar.search", "搜索...");
    m.insert("sidebar.ungrouped", "未分组");
    m.insert("sidebar.no_results", "未找到匹配的连接");
    m.insert("dialog.connect_title", "连接到服务器");
    m.insert("dialog.new_btn", "+ 新建");
    m.insert("dialog.no_saved", "暂无保存的连接");
    m.insert("dialog.edit", "编辑");
    m.insert("dialog.delete", "删除");
    m.insert("dialog.ssh_config", "来自 ~/.ssh/config");
    m.insert("dialog.ssh_config_label", "SSH 配置");
    m.insert("dialog.keyboard_hint", "Cmd+T 新建 | Cmd+1-9 切换标签 | Ctrl+Tab 下一个 | Cmd+W 关闭");
    m.insert("monitor.system", "系统信息");
    m.insert("monitor.load", "负载");
    m.insert("monitor.cpu", "CPU");
    m.insert("monitor.mem", "内存");
    m.insert("monitor.disk", "磁盘");
    m.insert("monitor.uptime", "运行");
    m.insert("monitor.connecting", "连接中...");
    m.insert("monitor.processes", "Top 进程");
    m.insert("monitor.pid", "PID");
    m.insert("monitor.proc_cpu", "CPU");
    m.insert("monitor.proc_mem", "MEM");
    m.insert("monitor.proc_cmd", "命令");
    m.insert("monitor.loading", "加载中...");
    m.insert("monitor.network", "网络");
    m.insert("monitor.total", "合计");
    m.insert("netdetail.close", "关闭");
    m.insert("netdetail.interface", "接口");
    m.insert("netdetail.rx", "接收 (Rx)");
    m.insert("netdetail.tx", "发送 (Tx)");
    m.insert("netdetail.total_traffic", "总流量");
    m.insert("netdetail.type", "类型");
    m.insert("netdetail.ethernet", "以太网");
    m.insert("netdetail.wireless", "无线网络");
    m.insert("netdetail.docker", "Docker 网桥");
    m.insert("netdetail.veth", "虚拟以太网 (容器)");
    m.insert("netdetail.bond", "绑定");
    m.insert("netdetail.vpn", "VPN 隧道");
    m.insert("netdetail.loopback", "回环");
    m.insert("netdetail.other", "其他");
    m.insert("form.edit_title", "编辑连接");
    m.insert("form.new_title", "新建连接");
    m.insert("form.name", "名称");
    m.insert("form.host", "主机");
    m.insert("form.port", "端口");
    m.insert("form.username", "用户名");
    m.insert("form.auth_type", "认证方式");
    m.insert("form.password", "密码");
    m.insert("form.private_key", "私钥");
    m.insert("form.key_path", "私钥路径");
    m.insert("form.browse", "浏览...");
    m.insert("form.passphrase", "密钥口令 (可选)");
    m.insert("form.group", "分组 (可选)");
    m.insert("form.cancel", "取消");
    m.insert("form.save", "保存");
    m.insert("form.test", "测试连接");
    m.insert("form.testing", "测试中...");
    m.insert("form.test_ok", "连接成功");
    m.insert("form.test_fail", "连接失败");
    m.insert("form.keep_existing", "(未修改 — 留空保留原值)");
    m.insert("conn.clone", "复制");
    m.insert("conn.test", "测试");
    m.insert("shortcuts.title", "键盘快捷键");
    m.insert("shortcuts.close", "关闭");
    m.insert("shortcuts.group.tabs",     "标签页");
    m.insert("shortcuts.group.split",    "分屏");
    m.insert("shortcuts.group.terminal", "终端");
    m.insert("shortcuts.group.panels",   "面板");
    m.insert("shortcuts.group.other",    "其他");
    m.insert("shortcuts.desc.rename_tab",   "双击标签页可重命名");
    m.insert("shortcuts.desc.palette",      "命令面板（连接 / 动作 / 片段）");
    m.insert("shortcuts.desc.split_v",      "左右分屏（同主机新 shell）");
    m.insert("shortcuts.desc.split_h",      "上下分屏");
    m.insert("shortcuts.desc.split_focus",  "切换 pane 焦点（或直接点击 pane）");
    m.insert("shortcuts.desc.split_close",  "关闭当前焦点 pane");
    m.insert("shortcuts.desc.connect",         "打开连接对话框");
    m.insert("shortcuts.desc.close_tab",       "关闭当前标签页");
    m.insert("shortcuts.desc.switch_tab",      "切换到第 N 个标签页");
    m.insert("shortcuts.desc.next_tab",        "下一个标签页");
    m.insert("shortcuts.desc.prev_tab",        "上一个标签页");
    m.insert("shortcuts.desc.paste",           "粘贴剪贴板到终端");
    m.insert("shortcuts.desc.copy",            "复制选中文本到剪贴板");
    m.insert("shortcuts.desc.right_click",     "右键粘贴剪贴板（在 session 内）");
    m.insert("shortcuts.desc.mouse_select",    "左键拖动选中文本 — 释放鼠标自动复制到剪贴板");
    m.insert("shortcuts.desc.sigint",          "中断当前正在运行的命令（发 SIGINT）");
    m.insert("shortcuts.desc.search",          "在终端 scrollback 中搜索");
    m.insert("shortcuts.desc.search_next",     "跳到下一个匹配");
    m.insert("shortcuts.desc.search_close",    "关闭搜索栏");
    m.insert("shortcuts.desc.history",         "显示/隐藏命令历史面板");
    m.insert("shortcuts.desc.help",            "显示/隐藏本帮助面板");
    m.insert("shortcuts.desc.bottom_toggle",   "折叠/展开底部面板");
    m.insert("shortcuts.desc.editor_save",     "保存文件（编辑器打开时）");
    m.insert("shortcuts.desc.close_dialog",    "关闭任意打开的对话框");
    m.insert("shortcuts.desc.quit",            "退出应用（× 仅最小化）");
    m.insert("err.title", "连接错误");
    m.insert("err.view_log", "查看日志");
    m.insert("err.dismiss", "关闭");
    m.insert("log.title", "日志查看器");
    m.insert("log.refresh", "刷新");
    m.insert("log.open_folder", "打开目录");
    m.insert("status.log", "日志");
    m.insert("status.quit", "退出");
    m.insert("tunnel.title", "隧道管理");
    m.insert("tunnel.add", "+ 新增隧道");
    m.insert("tunnel.edit", "编辑隧道");
    m.insert("tunnel.name", "名称");
    m.insert("tunnel.ssh_host", "SSH 主机");
    m.insert("tunnel.ssh_port", "端口");
    m.insert("tunnel.user", "用户名");
    m.insert("tunnel.forwards_label", "端口转发规则");
    m.insert("tunnel.forwards_hint", "每行一条：本地端口:远端主机:远端端口 (例 8080:10.0.0.5:80)");
    m.insert("tunnel.empty", "暂无隧道配置");
    m.insert("tunnel.start", "启动");
    m.insert("tunnel.stop", "停止");
    m.insert("tunnel.running", "运行中");
    m.insert("tunnel.stopped", "已停止");
    m.insert("tunnel.starting", "启动中...");
    m.insert("theme.title", "外观");
    m.insert("theme.zone.text_primary", "主要文本");
    m.insert("theme.zone.accent", "强调色 (按钮/链接)");
    m.insert("theme.zone.terminal_fg", "终端前景色");
    m.insert("theme.zone.terminal_bg", "终端背景色");
    m.insert("theme.zone.success", "成功 / 运行中");
    m.insert("theme.zone.danger", "危险 / 停止");
    m.insert("theme.zone.progress_bar", "进度条 (监控区)");
    m.insert("theme.terminal_font_size", "终端字号");
    m.insert("theme.ui_font_size", "UI 字号");
    m.insert("theme.reset", "恢复默认");
    m.insert("dialog.ssh_config_import_all", "全部导入 ({count})");
    m.insert("broadcast.title", "广播命令");
    m.insert("broadcast.hint", "命令将发送到所有勾选的 session（自动补 \\n）");
    m.insert("broadcast.sessions", "活跃会话");
    m.insert("broadcast.send", "发送到已勾选");
    m.insert("broadcast.empty", "没有活跃会话可广播");
    m.insert("snippet.title", "命令片段");
    m.insert("snippet.new", "新建片段");
    m.insert("snippet.name_placeholder", "名称（如 'docker ps'）");
    m.insert("snippet.body_placeholder", "命令 / 脚本内容");
    m.insert("snippet.save", "保存");
    m.insert("snippet.send", "发送到当前 tab");
    m.insert("snippet.empty", "暂无片段 — 在下方新建");
    m.insert("btn.broadcast", "广播");
    m.insert("btn.snippets", "片段");
    m.insert("search.placeholder", "搜索终端 (Cmd+F)");
    m.insert("search.no_matches", "0/0");
    m.insert("search.prev", "上一个");
    m.insert("search.next", "下一个");
    m.insert("search.close", "关闭");
    // v0.7.0 — 命令面板
    m.insert("palette.placeholder", "输入以搜索连接、动作、片段…");
    m.insert("palette.empty", "无匹配结果");
    m.insert("palette.hint", "↑↓ 选择 · Enter 执行 · Esc 关闭");
    m.insert("palette.kind.conn", "连接");
    m.insert("palette.kind.action", "动作");
    m.insert("palette.kind.snippet", "片段");
    m.insert("palette.act.new_conn", "新建连接");
    m.insert("palette.act.connect", "打开连接对话框");
    m.insert("palette.act.settings", "打开设置");
    m.insert("palette.act.broadcast", "广播命令");
    m.insert("palette.act.snippets", "打开命令片段");
    m.insert("palette.act.keys", "SSH 密钥管理");
    m.insert("palette.act.tunnels", "隧道管理");
    m.insert("palette.act.proxies", "代理管理");
    m.insert("palette.act.history", "命令历史");
    m.insert("palette.act.logs", "日志查看器");
    m.insert("palette.act.sync", "切换实时同步输入");
    m.insert("palette.act.split_v", "分屏（左右）");
    m.insert("palette.act.split_h", "分屏（上下）");
    m.insert("palette.act.import_ssh", "一键导入 ~/.ssh/config");
    // v0.7.0 — 标签重命名
    m.insert("tabrename.title", "重命名标签页");
    m.insert("tabrename.hint", "留空则恢复自动 user@host 标题");
    m.insert("tabrename.placeholder", "标签名称");
    m.insert("tabrename.save", "保存");
    // v0.7.0 — 同步输入
    m.insert("broadcast.sync_on", "实时同步：开");
    m.insert("broadcast.sync_off", "实时同步：关");
    m.insert("broadcast.sync_hint", "实时同步会把当前终端的每一次按键（包括 Enter 和 Ctrl+C）镜像到所有勾选的 session，谨慎使用。");
    // v0.7.0 — 阈值告警
    m.insert("alerts.title", "资源告警");
    m.insert("alerts.hint", "session 超过阈值时标签页显示红点 + 状态栏警告（每 3 秒检查）");
    m.insert("alerts.on", "开");
    m.insert("alerts.off", "关");
    m.insert("alerts.cpu", "CPU 负载阈值");
    m.insert("alerts.mem", "内存阈值");
    m.insert("alerts.disk", "磁盘阈值");
    // v0.7.0 — SSH 密钥管理
    m.insert("btn.keys", "密钥");
    m.insert("keys.title", "SSH 密钥管理");
    m.insert("keys.empty", "~/.ssh 下没有找到密钥");
    m.insert("keys.copy", "复制公钥");
    m.insert("keys.deploy", "部署到…");
    m.insert("keys.pick_target", "部署到哪个连接？");
    m.insert("keys.gen_title", "生成新密钥（ed25519）");
    m.insert("keys.gen_name", "文件名（如 id_ed25519_work）");
    m.insert("keys.gen_comment", "注释（如 ops@laptop）");
    m.insert("keys.gen_btn", "生成");
    m.insert("keys.gen_hint", "写入 ~/.ssh/<名称> + .pub（0600），不会覆盖已有文件。");
    m.insert("keys.generated", "密钥已生成");
    m.insert("keys.copied", "公钥已复制到剪贴板");
    m.insert("keys.deploying", "部署中…");
    m.insert("keys.deploy_ok", "已部署到");
    // SSH 错误提示
    m.insert("ssh.err.auth", "用户名或密码/密钥不正确 — 请检查账号凭据，或确认服务器 sshd 是否允许此用户登录");
    m.insert("ssh.err.refused", "目标端口未开放 — 确认 SSH 服务已启动且端口号正确 (通常是 22)");
    m.insert("ssh.err.timeout", "网络不通或主机无响应 — 检查 IP/域名、网络连通性，或是否需要走代理/堡垒机");
    m.insert("ssh.err.no_route", "路由不可达 — 主机可能关机，或防火墙阻挡了入站连接");
    m.insert("ssh.err.host_key", "主机密钥变化 — 可能是服务器重装，也可能遭遇中间人攻击，请向管理员确认");
    m.insert("ssh.err.dns", "域名解析失败 — 检查域名拼写或改用 IP 地址");
    m.insert("ssh.err.kex", "无公共密钥交换算法 — 服务器禁用了现代 KEX，请联系管理员开启兼容算法");
    m.insert("ssh.err.denied", "认证被拒 — 检查用户名、密钥权限 (chmod 600)、或 authorized_keys 配置");
    m.insert("ssh.err.key_missing", "私钥文件不存在 — 请重新选择正确的私钥文件路径");
    m.insert("ssh.err.key_format", "私钥格式无效 — 确认是 OpenSSH/PEM 格式，PuTTY .ppk 需要先转换");
    m.insert("ssh.err.reset", "连接被对端关闭 — 可能是空闲超时或服务器主动断开");
    m.insert("filebrowser.upload", "^ 上传");
    m.insert("filebrowser.loading", "正在加载文件...");
    m.insert("filedialog.upload", "选择要上传的文件");
    m.insert("filedialog.save", "另存为");
    m.insert("filedialog.select_key", "选择私钥文件");
    m.insert("filedialog.rz_upload", "rz: 选择要上传的文件");
    m.insert("editor.save", "保存");
    m.insert("editor.close", "关闭");
    m.insert("status.no_session", "无活动会话");
    m.insert("status.version", "NeoShell v{version}");
    m.insert("transfer.cancel", "取消");
    m.insert("transfer.preparing", "{name} — 准备中...");
    m.insert("update.ready", "NeoShell {version} 已就绪");
    m.insert("update.available", "有新版本可用: v{version}");
    m.insert("update.downloading", "正在下载 v{version}... {percent}%");
    m.insert("monitor.cpu_cores", "{count} 核");
    m.insert("monitor.virtual_count", "虚拟({count})");
    m.insert("monitor.speed", "速率: ↓{down}/s ↑{up}/s");
    m.insert("netdetail.title", "接口: {name}");
    m.insert("filebrowser.dir", "[目录] {path}");
    // 设置菜单
    m.insert("settings.title", "设置");
    m.insert("settings.language", "语言");
    m.insert("settings.scale", "界面缩放");
    m.insert("settings.about", "关于 NeoShell");
    m.insert("settings.sidebar", "切换侧边栏");
    m.insert("settings.close", "关闭");
    // 关于
    m.insert("about.title", "关于 NeoShell");
    m.insert("about.version", "版本 {version}");
    m.insert("about.desc", "基于 Rust 构建的跨平台 SSH 终端管理工具。");
    m.insert("about.tech", "Rust • iced • wgpu • AES-256-GCM • Argon2id");
    m.insert("about.copyright", "© 2026 NeoShell — 保留所有权利");
    m.insert("about.close", "关闭");
    // 历史
    m.insert("history.title", "命令历史");
    m.insert("history.filter", "搜索命令...");
    m.insert("history.empty", "暂无命令记录");
    m.insert("history.clear", "清空");
    // 代理
    m.insert("proxy.title", "代理管理");
    m.insert("proxy.add", "+ 添加代理");
    m.insert("proxy.name", "名称");
    m.insert("proxy.type", "类型");
    m.insert("proxy.host", "主机");
    m.insert("proxy.port", "端口");
    m.insert("proxy.username", "用户名");
    m.insert("proxy.password", "密码");
    m.insert("proxy.save", "保存");
    m.insert("proxy.cancel", "取消");
    m.insert("proxy.test", "测试");
    m.insert("proxy.delete", "删除");
    m.insert("proxy.edit", "编辑");
    m.insert("proxy.empty", "暂无代理配置");
    m.insert("proxy.ok", "可用");
    m.insert("proxy.fail", "不可用");
    m.insert("proxy.testing", "...");
    m.insert("proxy.none", "直连 (无代理)");
    m.insert("proxy.select", "代理");
    m.insert("proxy.type.bastion", "SSH 堡垒机");
    m.insert("proxy.bastion.auth_password", "密码认证");
    m.insert("proxy.bastion.auth_key", "密钥认证");
    m.insert("proxy.bastion.key_path", "私钥文件路径");
    m.insert("proxy.bastion.browse", "浏览");
    m.insert("proxy.bastion.passphrase", "密钥口令 (可选)");
    // 界面元素
    m.insert("btn.close", "关闭");
    m.insert("btn.refresh", "刷新");
    m.insert("btn.send", "发送");
    m.insert("btn.edit", "编辑");
    m.insert("btn.download", "下载");
    m.insert("bottom.files", "文件");
    m.insert("bottom.cmd", "命令");
    m.insert("process.title", "进程信息");
    m.insert("process.child", "子进程");
    m.insert("process.listen", "监听端口");
    m.insert("process.net", "网络连接");
    m.insert("process.fds", "打开文件");
    m.insert("process.threads", "线程");
    m.insert("net.speed", "速率");
    m.insert("net.interface", "接口");
    m.insert("net.received", "接收");
    m.insert("net.sent", "发送");
    m.insert("file.name", "名称");
    m.insert("file.size", "大小");
    m.insert("file.modified", "修改时间");
    m.insert("file.send_prefix", "发送:");
    m.insert("settings.font_size", "字体大小");
    m.insert("status.shortcuts", "{mod}+H:历史  {mod}+T:连接");
    m.insert("welcome.select", "从左侧选择一个连接以开始");
    m.insert("confirm.delete", "确认删除 \"{name}\"?");
    m.insert("vault.locked_secret", "保险库已锁定 — 解锁后才能使用该凭据。");
    m.insert("vault.no_credential", "没有可用凭据 — 请解锁保险库，或在设置中重新填写。");
    m.insert("lock.now", "锁定");
    m.insert("settings.lock_now", "立即锁定");
    m.insert("settings.lock_timeout", "自动锁定");
    m.insert("settings.lock_never", "从不");
    m.insert("settings.lock_minutes", "{n} 分钟");
    m.insert("shortcuts.desc.lock", "立即锁定保险库（会话保持连接）");
    // 界面整理：纯图标控件的提示、欢迎页、复制错误信息、命令面板中的连接操作
    m.insert("tip.sidebar_hide", "隐藏侧边栏");
    m.insert("tip.sidebar_show", "显示侧边栏");
    m.insert("tip.panel_hide", "收起底部面板");
    m.insert("tip.panel_show", "展开底部面板");
    m.insert("tip.close", "关闭");
    m.insert("tip.close_tab", "关闭标签页");
    m.insert("tip.parent_dir", "上级目录");
    m.insert("tip.replay", "再次执行");
    m.insert("tip.decrease", "减小");
    m.insert("tip.increase", "增大");
    m.insert("tip.delete", "删除");
    m.insert("tip.match_case", "区分大小写");
    m.insert("welcome.subtitle_empty", "添加一台服务器即可开始");
    m.insert("welcome.import_ssh", "从 ~/.ssh/config 导入（{count}）");
    m.insert("err.copy", "复制");
    m.insert("err.copied", "已复制");
    m.insert("palette.act.edit_conn", "编辑：{name}");
    m.insert("palette.act.test_conn", "测试：{name}");
    m.insert("palette.act.clone_conn", "复制：{name}");
    m.insert("palette.act.delete_conn", "删除：{name}");
    // 功能接入：SFTP 文件操作、文件夹传输、拖放上传、键盘交互认证、结束进程、监听端口、配色方案
    m.insert("sftp.new_folder", "新建文件夹");
    m.insert("sftp.rename", "重命名");
    m.insert("sftp.permissions", "权限");
    m.insert("sftp.delete", "删除");
    m.insert("sftp.new_folder_title", "在 {dir} 中新建文件夹");
    m.insert("sftp.rename_title", "重命名“{name}”");
    m.insert("sftp.chmod_title", "“{name}”的权限");
    m.insert("sftp.name_hint", "单个名称，不能包含“/”");
    m.insert("sftp.mode_hint", "八进制，例如 755 或 0644");
    m.insert("sftp.err_name", "请输入单个文件名：不能为空、不能包含“/”，也不能是“.”或“..”");
    m.insert("sftp.err_mode", "请输入 1-4 位八进制数字（0-7），例如 755");
    m.insert("sftp.ok", "确定");
    m.insert("sftp.apply", "应用");
    m.insert("sftp.confirm_delete", "删除此文件？此操作无法撤销。");
    m.insert("sftp.confirm_delete_dir", "删除此文件夹及其中的全部内容？此操作无法撤销。");
    m.insert("sftp.confirm_chmod", "将权限修改为 {mode}？");
    m.insert("filebrowser.upload_dir", "^ 文件夹");
    m.insert("filedialog.upload_dir", "选择要上传的文件夹");
    m.insert("filedialog.download_dir", "选择文件夹的保存位置");
    m.insert("tip.upload_dir", "上传文件夹");
    m.insert("tip.download_dir", "下载文件夹");
    m.insert("transfer.busy", "已有传输正在进行——请等待完成，或先取消。");
    m.insert("drop.no_target", "没有可上传的位置：请先打开会话，并等待“文件”页加载出远程目录。");
    m.insert("quickcmd.accept_hint", "Tab / ↓ 采用 · 点击选择");
    m.insert("auth.title", "服务器身份验证");
    m.insert("auth.from_server", "这是服务器的提问，答案只会发送给该服务器。NeoShell 不会在这里索要主密码。");
    m.insert("auth.continue", "继续");
    m.insert("auth.queued", "还有 {count} 个等待回答");
    m.insert("auth.purpose.shell", "终端会话");
    m.insert("auth.purpose.exec", "监控 / 文件传输连接");
    m.insert("auth.purpose.reconnect", "重新连接");
    m.insert("auth.purpose.test", "连接测试");
    m.insert("auth.purpose.deploy", "部署公钥");
    m.insert("form.auth_interactive", "交互式");
    m.insert("form.auth_agent", "ssh-agent");
    m.insert("form.password_optional", "密码（可选）");
    m.insert("form.interactive_hint", "用于 PAM / 一次性验证码登录。服务器的提问会在对话框中显示；已保存的密码会自动回答普通的密码提示。");
    m.insert("form.agent_hint", "使用 ssh-agent（SSH_AUTH_SOCK）中已加载的密钥，不保存任何凭据。");
    m.insert("process.sigterm", "SIGTERM 终止");
    m.insert("process.sigkill", "SIGKILL 强杀");
    m.insert("process.sigterm_tip", "请求进程退出");
    m.insert("process.sigkill_tip", "强制结束进程");
    m.insert("process.confirm_kill", "向 PID {pid} 发送 {signal}？");
    m.insert("process.send_signal", "发送");
    m.insert("bottom.ports", "端口");
    m.insert("ports.title", "监听端口");
    m.insert("ports.hint", "点击一行查看对应进程");
    m.insert("ports.proto", "协议");
    m.insert("ports.addr", "地址");
    m.insert("ports.port", "端口");
    m.insert("ports.pid", "PID");
    m.insert("ports.process", "进程");
    m.insert("ports.loading", "加载中...");
    m.insert("ports.empty", "未发现监听端口（该主机可能没有 ss / netstat）");
    m.insert("monitor.swap", "交换");
    m.insert("theme.preset", "配色方案");
    m.insert("shortcuts.desc.shift_select", "即使程序（vim、htop、tmux）占用鼠标，也能选择文本");
    m.insert("shortcuts.desc.drop_upload", "把文件或文件夹拖到窗口上，即可上传到远程目录");
    m.insert("confirm.on_host", "主机：{host}");
    m.insert("transfer.bad_local", "无法上传“{path}”：它没有可用于远程副本的名称。");
    // ssh/mod.rs: SFTP / kill / agent + interactive auth errors
    m.insert("sftp.err.path_empty", "远程路径为空");
    m.insert("sftp.err.path_control", "远程路径包含控制字符");
    m.insert("sftp.err.path_relative", "远程路径必须是绝对路径：{path}");
    m.insert("sftp.err.path_root", "拒绝对文件系统根目录“/”执行此操作");
    m.insert("sftp.err.path_dotdot", "远程路径不能包含“..”：{path}");
    m.insert("sftp.err.not_dir", "“{path}”已存在，但不是目录");
    m.insert("sftp.err.mkdir", "创建远程目录“{path}”失败：{err}");
    m.insert("sftp.err.rename", "将“{from}”重命名为“{to}”失败：{err}");
    m.insert("sftp.err.bad_mode", "无效的权限位：{mode}");
    m.insert("sftp.err.chmod", "将“{path}”的权限修改为 {mode} 失败：{err}");
    m.insert("sftp.err.too_deep", "“{path}”处的目录层级超过 {max} 层，已停止");
    m.insert("sftp.err.stat", "读取“{path}”的属性失败：{err}");
    m.insert("sftp.err.list", "列出“{path}”的内容失败：{err}");
    m.insert("sftp.err.bad_entry", "服务器在“{path}”下列出的某个条目名称无法按原样删除——未删除任何内容");
    m.insert("sftp.err.unaddressable", "无法从本系统精确定位“{path}”：此处的 SFTP 库会把“\\”当作“/”发送——未删除任何内容");
    m.insert("sftp.err.delete", "删除“{path}”失败：{err}");
    m.insert("sftp.err.rmdir", "删除目录“{path}”失败：{err}");
    m.insert("process.err.kill_exit", "kill -{signal} {pid} 失败（退出码 {status}）");
    m.insert("process.err.kill", "kill -{signal} {pid} 失败：{detail}");
    m.insert("auth.err.no_handler", "服务器发起了交互式提问，但没有注册提示处理程序");
    m.insert("auth.err.handler_gone", "提示处理程序已不可用");
    m.insert("auth.err.no_answer", "未回答服务器的验证提问：{err}");
    m.insert("auth.err.agent_unavailable", "ssh-agent 不可用：{err}");
    m.insert("auth.err.agent_connect", "无法连接 ssh-agent：{err}（是否已设置 SSH_AUTH_SOCK？）");
    m.insert("auth.err.agent_list", "无法列出 ssh-agent 中的身份：{err}");
    m.insert("auth.err.agent_read", "无法读取 ssh-agent 中的身份：{err}");
    m.insert("auth.err.agent_empty", "ssh-agent 中没有任何身份（请先运行 `ssh-add`）");
    m.insert("auth.err.agent_rejected", "服务器未接受任何 ssh-agent 身份（已尝试 {count} 个，最后一个：{last}）");
    // ssh/mod.rs + proxy.rs: exec-connection rebuild gate, proxy credentials
    m.insert("exec.err.needs_reconnect", "该会话的监控与文件访问已暂停：其后台连接已断开，重新建立需要再次完成登录验证。请重新连接该会话以恢复。");
    m.insert("exec.err.rebuilding", "正在重新建立监控与文件访问所用的连接，请稍后重试。");
    m.insert("exec.err.cooldown", "无法重新建立监控与文件访问所用的连接，将在 {secs} 秒后再次尝试。");
    m.insert("proxy.err.missing", "此连接配置的代理“{id}”已不存在。为避免绕过代理，已拒绝直接连接 — 请重新创建该代理，或在连接设置中清除它。");
    m.insert("proxy.err.vault_locked", "保险库已锁定 — 解锁后才能通过代理“{name}”重新连接。");
    m.insert("proxy.err.no_password", "代理“{name}”设置了用户名但没有密码 — 请解锁保险库，或在代理设置中重新填写密码。");
    // ssh/mod.rs: reconnect cancel, skipped names, local folder errors
    m.insert("ssh.err.reconnect_cancelled", "已取消重新连接：登录验证已被关闭。");
    m.insert("sftp.err.skipped_names", "已跳过 {count} 个项目：其名称无法在本系统上表示。");
    m.insert("transfer.err.not_dir", "“{path}”不是目录");
    m.insert("transfer.err.local_empty", "本地目录路径为空。");
    m.insert("transfer.err.local_mkdir", "创建本地目录“{path}”失败：{err}");
    m.insert("transfer.err.local_read_dir", "读取本地目录“{path}”失败：{err}");
    // app.rs: unlock-time history warning, parked monitoring, skipped items
    m.insert("history.warn.title", "命令历史未保存");
    m.insert("history.warn.unsettled", "上一次命令历史写入尚未完成，本次会话中运行的命令将不会被保存。在保险库锁定或 NeoShell 退出之前，它们仍会显示在历史面板中。");
    m.insert("history.warn.unreadable", "无法读取命令历史文件，也无法将其移到一旁以新建文件，本次会话中运行的命令将不会被保存。详情请查看日志。");
    m.insert("monitor.parked", "监控已暂停——此服务器需要验证码");
    m.insert("monitor.reconnect", "重新连接监控");
    m.insert("monitor.reconnecting", "正在重新连接...");
    m.insert("notice.skipped_title", "已完成——部分项目已跳过");
    // ssh/mod.rs: type-checked SFTP ops, backslash paths, exec sign-in, session ids
    m.insert("sftp.err.changed", "“{path}”在列出后已发生变化——请刷新后重试。未做任何修改。");
    m.insert("sftp.err.chmod_symlink", "“{path}”是符号链接：通过 SFTP 修改它的权限，实际会改到它所指向的文件上。未做任何修改。");
    m.insert("sftp.err.path_backslash", "远程路径不能包含反斜杠：{path}");
    m.insert("auth.err.exec_interactive", "监控 / 文件传输连接的键盘交互式登录失败：{err}");
    m.insert("auth.err.exec_agent", "监控 / 文件传输连接的 SSH agent 登录失败：{err}");
    m.insert("ssh.err.bad_session_id", "会话 ID“{id}”无效或已被占用。");
    // tunnel.rs: forward-rule parse errors, tunnel store and runtime failures
    m.insert("tunnel.err.bad_socks_port", "SOCKS5 监听端口“{port}”无效：{err}");
    m.insert("tunnel.err.socks_port_zero", "SOCKS5 监听端口不能为 0");
    m.insert("tunnel.err.bad_remote", "远端地址无效：{remote}");
    m.insert("tunnel.err.bad_remote_port", "远端端口“{port}”无效：{err}");
    m.insert("tunnel.err.bad_local_port", "本地端口“{port}”无效：{err}");
    m.insert("tunnel.err.bad_rule", "无法识别转发规则“{rule}”，应为 LOCAL:REMOTE_HOST:REMOTE_PORT、REMOTE:PORT->LOCAL:PORT、R:LOCAL:REMOTE_HOST:REMOTE_PORT 或 D:LOCAL");
    m.insert("tunnel.err.missing_host", "转发规则“{rule}”缺少远端主机");
    m.insert("tunnel.err.not_found", "未找到隧道“{id}”");
    m.insert("tunnel.err.vault_not_retained", "保险库未能保存隧道“{id}”的凭据——{path} 保持原样");
    m.insert("tunnel.err.bind", "无法监听本地地址 {addr}：{err}");
    m.insert("tunnel.err.remote_listen", "无法在 SSH 主机上监听 {bind}:{port}：{err}（绑定非回环地址时，服务器可能需要开启 GatewayPorts）");
    m.insert("tunnel.err.remote_accept", "SSH 主机端口 {port} 接受连接失败：{err}");
    // app.rs: type-stated SFTP confirmations, fresh kill check, groups, i18n pass
    m.insert("sftp.kind.file", "文件");
    m.insert("sftp.kind.dir", "文件夹");
    m.insert("sftp.kind.symlink", "符号链接");
    m.insert("sftp.kind.other", "特殊文件");
    m.insert("sftp.confirm_delete_named", "删除{kind}“{name}”？此操作无法撤销。");
    m.insert("sftp.confirm_delete_dir_named", "删除文件夹“{name}”及其中的全部内容？此操作无法撤销。");
    m.insert("sftp.confirm_delete_link_named", "删除符号链接“{name}”？只删除链接本身，它指向的内容保持不变。");
    m.insert("sftp.confirm_chmod_named", "将{kind}“{name}”的权限修改为 {mode}？");
    m.insert("sftp.rename_title_named", "重命名{kind}“{name}”");
    m.insert("sftp.chmod_title_named", "{kind}“{name}”的权限");
    m.insert("sftp.name_marks", "名称中的 · 表示位于开头、结尾或与其他空格相连的空格，\\u{…} 表示原本不可见的字符。");
    m.insert("process.err.gone", "进程 {pid} 已不在运行，未发送任何信号。");
    m.insert("process.err.changed", "PID {pid} 现在对应的已不是您确认的那个进程，未发送任何信号。");
    m.insert("process.signal_n", "信号 {n}");
    m.insert("files.parked", "文件浏览已暂停——此服务器需要验证码");
    m.insert("tunnel.err.start", "无法启动隧道：{err}");
    m.insert("shortcuts.key.drag", "拖动");
    m.insert("shortcuts.key.shift_drag", "Shift+拖动");
    m.insert("shortcuts.key.right_click", "右键单击");
    m.insert("shortcuts.key.drop", "拖放");
    m.insert("tab.split_suffix", "{title}（分屏）");
    m.insert("sidebar.collapse_all", "折叠全部分组");
    m.insert("sidebar.expand_all", "展开全部分组");
    m.insert("palette.act.collapse_group", "折叠分组“{name}”");
    m.insert("palette.act.expand_group", "展开分组“{name}”");
    m.insert("sftp.err.unverified", "未修改“{path}”：该服务器不提供 SFTP，目录内容是通过 shell 列出的，无法在文件浏览器中安全地修改其中的条目。");
    m.insert("sftp.err.not_utf8", "无法从本系统精确定位“{path}”：它在服务器上的名称不是有效的 UTF-8，或无法被准确读取。未做任何修改。");
    m.insert("sftp.err.start", "无法启动 SFTP：{err}");
    // app.rs: form validation, copied connection, reconnect marker, log viewer
    m.insert("form.err.title", "请检查表单");
    m.insert("form.err.port", "“{port}”不是有效的端口，请输入 1 到 65535 之间的数字。");
    m.insert("conn.copy_name", "{name}（副本）");
    m.insert("tab.reconnecting", "{title} [正在重连… {n}]");
    m.insert("tunnel.err.no_forwards", "至少需要一条转发规则。");
    m.insert("tunnel.err.forward_parse", "无法识别的转发规则：{err}");
    m.insert("log.truncated", "…（仅显示最后 {kb} KB）…");
    m.insert("log.err.read", "无法读取日志文件 {path}：{err}");
    m.insert("term.sz_refused", "[NeoShell] sz：已拒绝不安全的远程文件名 {name}");
    m.insert("status.sync_badge", "同步 {n}");
    m
});

/// Get a translated string. Returns &'static str.
pub fn t(key: &str) -> &'static str {
    let locale = LOCALE.read();
    let map = if locale.starts_with("zh") { &*ZH } else { &*EN };
    match map.get(key).copied() {
        Some(v) => v,
        None => EN.get(key).copied().unwrap_or("???"),
    }
}

/// Format a translated string with named parameters.
/// Usage: `tf("update.ready", &[("version", "1.0")])`
///
/// One pass over the template: each `{name}` that names a parameter becomes
/// its value, once, and a value is never scanned again. Replacing the
/// parameters one after another substituted into the values already put in —
/// a remote file named "{mode}" turned into the mode in the chmod error. A
/// `{…}` that names no parameter stays as written.
pub fn tf(key: &str, params: &[(&str, &str)]) -> String {
    fill(t(key), params)
}

/// [`tf`] on a template already looked up.
fn fill(template: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let value = after.find('}').and_then(|close| {
            let name = &after[..close];
            params
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (close, *v))
        });
        match value {
            Some((close, v)) => {
                out.push_str(v);
                rest = &after[close + 1..];
            }
            // Not a parameter: the brace is text, and the scan goes on
            // right after it — "{{mode}}" is "{" and then "{mode}".
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn current_locale() -> String {
    LOCALE.read().clone()
}

pub fn set_locale(locale: &str) {
    *LOCALE.write() = locale.to_string();
}

#[cfg(test)]
mod tf_tests {
    use super::{fill, tf};

    /// `sftp.err.chmod`, as both tables have it.
    const CHMOD: [&str; 2] = [
        "Failed to chmod '{path}' to {mode}: {err}",
        "将“{path}”的权限修改为 {mode} 失败：{err}",
    ];

    #[test]
    fn a_value_is_put_in_as_it_is_and_never_scanned_again() {
        // A remote file named "{mode}": the sequential replace turned it into
        // "/srv/755" in the chmod error.
        let params = [("path", "/srv/{mode}"), ("mode", "755"), ("err", "denied")];
        assert_eq!(
            fill(CHMOD[0], &params),
            "Failed to chmod '/srv/{mode}' to 755: denied"
        );
        // A value holding every placeholder name, given for every parameter.
        let every = "{path}{mode}{err}{}{unknown}";
        let params = [("path", every), ("mode", every), ("err", every)];
        assert_eq!(
            fill(CHMOD[0], &params),
            format!("Failed to chmod '{0}' to {0}: {0}", every)
        );
    }

    #[test]
    fn tf_fills_a_real_template_in_one_pass() {
        // Either language: another test in this binary may flip the locale.
        let got = tf(
            "sftp.err.chmod",
            &[("path", "/srv/{mode}"), ("mode", "755"), ("err", "{path}")],
        );
        let want = [
            "Failed to chmod '/srv/{mode}' to 755: {path}",
            "将“/srv/{mode}”的权限修改为 755 失败：{path}",
        ];
        assert!(want.contains(&got.as_str()), "{}", got);
    }

    #[test]
    fn braces_that_name_no_parameter_stay_as_written() {
        assert_eq!(fill("{a} {b} {} {", &[("a", "1")]), "1 {b} {} {");
        assert_eq!(fill("{{a}}", &[("a", "1")]), "{1}");
        assert_eq!(fill("{a}{a}", &[("a", "x")]), "xx");
        assert_eq!(fill("no parameters", &[]), "no parameters");
        assert_eq!(fill("中{a}文", &[("a", "“x”")]), "中“x”文");
        // The first of two parameters with the same name, as before.
        assert_eq!(fill("{a}", &[("a", "1"), ("a", "2")]), "1");
    }
}
