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
