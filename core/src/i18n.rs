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
pub fn tf(key: &str, params: &[(&str, &str)]) -> String {
    let mut s = t(key).to_string();
    for (name, value) in params {
        s = s.replace(&format!("{{{}}}", name), value);
    }
    s
}

pub fn current_locale() -> String {
    LOCALE.read().clone()
}

pub fn set_locale(locale: &str) {
    *LOCALE.write() = locale.to_string();
}
