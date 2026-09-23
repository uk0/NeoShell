import type { Dict } from "./en";

export const zh: Dict = {
  "nav.features": "功能",
  "nav.stack": "技术栈",
  "nav.security": "安全",
  "nav.changelog": "更新日志",
  "nav.download": "下载",
  "nav.github": "GitHub",

  "hero.badge": "v0.7.0 · 纯 Rust · 原生 GPU",
  "hero.title_a": "你真正",
  "hero.title_b": "想用的",
  "hero.title_c": "那款终端。",
  "hero.lede":
    "NeoShell 是一款完全用 Rust 打造的原生 SSH 工作台。加密凭据库、实时监控、多标签终端、SFTP —— 全部集成在一个 6MB 的单文件可执行程序中。无 Electron、无 JavaScript 运行时。",
  "hero.cta.primary": "下载 v0.7.0",
  "hero.cta.secondary": "探索功能",
  "hero.cta.source": "查看源码 →",
  "hero.stat.binary": "程序体积",
  "hero.stat.start": "冷启动",
  "hero.stat.mem": "空闲内存",
  "hero.stat.platforms": "支持平台",

  "features.eyebrow": "核心能力",
  "features.title": "工作需要的，一个不少。不需要的，一个不多。",
  "features.lede":
    "一套完整的 SSH 工作台，永远不会要求你先安装 JVM、Electron 运行时，或是用掉 800MB 本不该被占的内存。",
  "features.terminal.title": "多标签终端",
  "features.terminal.body":
    "完整的 VTE 仿真器，支持 256 色、真彩色、CJK，1 万行滚动缓冲。Cmd+1-9 切换标签，Cmd+F 实时搜索高亮。",
  "features.vault.title": "加密凭据库",
  "features.vault.body":
    "AES-256-GCM + Argon2id 双层信封加密。密码永远不会以明文形式落盘。",
  "features.ssh.title": "永久 SSH",
  "features.ssh.body":
    "基于 tmux 的自动重连机制。断网、VPN 切换、合盖休眠——你的会话每一次都稳稳活着。",
  "features.monitor.title": "实时监控",
  "features.monitor.body":
    "每 3 秒刷新 CPU、内存、所有磁盘分区、每张网卡流量、Top 15 进程。",
  "features.sftp.title": "SFTP 文件管理",
  "features.sftp.body":
    "浏览远程文件，支持带进度条与断点续传的上传下载。可直接在应用内编辑远程配置文件。",
  "features.cross.title": "跨平台",
  "features.cross.body":
    "原生支持 macOS（ARM64 + Intel）、Windows 7–11、Linux，体验统一，不走任何 Web 运行时。",

  "stack.eyebrow": "技术内核",
  "stack.title": "100% Rust。零 JavaScript。",
  "stack.lede":
    "没有 Electron，没有 WebView，基于 wgpu 的硬件加速渲染。",
  "stack.item.iced": "iced 0.13",
  "stack.item.iced_d": "基于 wgpu 的 GPU 加速原生 GUI",
  "stack.item.ssh2": "libssh2 + OpenSSL",
  "stack.item.ssh2_d": "全平台 vendor，完整 KEX / 算法支持",
  "stack.item.vte": "VTE",
  "stack.item.vte_d": "完整 xterm 解析器 + 自绘 canvas 渲染",
  "stack.item.crypto": "AES-256-GCM",
  "stack.item.crypto_d": "+ Argon2id KDF，抗 GPU 暴力破解",
  "stack.item.tokio": "Tokio",
  "stack.item.tokio_d": "异步运行时，50 ms SSH 轮询循环",

  "security.eyebrow": "信任模型",
  "security.title": "你的凭据，只在你的设备上，没有别处。",
  "security.lede":
    "双层信封加密架构。任何数据离开设备前，都已加密。",
  "security.item.1": "主密码从不存储——仅使用派生出的 KEK",
  "security.item.2": "每个连接都用独立的随机 Nonce 加密",
  "security.item.3": "没有正确密码，Vault 文件形同随机噪声",
  "security.item.4": "独立的 SSH exec 通道——与终端零锁竞争",
  "security.item.5": "私钥加密保存，仅在内存中解密使用",
  "security.item.6": "开源 @ GitHub —— 可审计加密实现、可 fork、可贡献。",

  "dl.eyebrow": "立即开始",
  "dl.title": "下载 NeoShell",
  "dl.lede": "v0.7.0 —— 单文件可执行，无需安装依赖。",
  "dl.macos": "macOS",
  "dl.macos_arm": "Apple Silicon（ARM64）",
  "dl.macos_intel": "Intel（x86_64）",
  "dl.windows": "Windows 10 / 11",
  "dl.win7": "Windows 7",
  "dl.linux": "Linux",
  "dl.primary": "下载",
  "dl.alt": "替代",
  "dl.note": "由 NEO 打造 — firsh.me",
  "dl.update_note": "已安装用户？App 会在 1 小时内自动升级。",

  "cl.eyebrow": "发布日志",
  "cl.title": "v0.7.0 里有什么",
  "cl.date": "2026-09-23",
  "cl.latest": "最新",
  "cl.category.added": "新增",
  "cl.category.changed": "优化",
  "cl.category.fixed": "修复",
  "cl.added.1":
    "输入法全面可用 —— 连接名、分组、搜索框和终端里都能直接用拼音等输入法打中文；密码框会自动关闭输入法。",
  "cl.added.2":
    "SFTP 文件操作 —— 右键新建文件夹、重命名、删除、改权限；整个文件夹上传和下载；把文件拖进窗口直接上传。",
  "cl.added.3":
    "端口转发新增远程转发（-R）和动态 SOCKS5 转发（-D），与本地转发并列。",
  "cl.added.4":
    "支持双因素登录（keyboard-interactive 验证码）和 SSH agent 认证。",
  "cl.added.5":
    "命令面板（Cmd/Ctrl+K）、分屏、SSH 密钥管理器，以及多会话同步输入。",
  "cl.added.6":
    "监控面板新增监听端口、结束进程、每核 CPU 和 swap；8 套配色方案；连接分组可折叠。",
  "cl.changed.1":
    "SSH 主机密钥会对照 ~/.ssh/known_hosts 校验：首次连接自动记录，密钥变化则拒绝连接。",
  "cl.changed.2":
    "代理和隧道的密码在首次解锁时迁入加密保险库；闲置 15 分钟后保险库自动上锁。",
  "cl.changed.3":
    "更新包带签名，安装前先校验。",
  "cl.changed.4":
    "空闲时更省电 —— 终端有输出才刷新界面，不再每秒轮询 20 次。",
  "cl.changed.5":
    "所有界面文字对比度达到 WCAG AA；图标按钮加上提示；欢迎页可以直接新建或导入连接。",
  "cl.fixed.1":
    "修复错误信息中英文混排时程序闪退。",
  "cl.fixed.2":
    "修复 Windows 上打开含 GBK 编码文件名的 SFTP 目录时程序退出。",
  "cl.fixed.3":
    "更新失败时回滚到上一个版本，不再导致程序无法启动。",

  "contact.eyebrow": "保持联系",
  "contact.title": "加入社区",
  "contact.lede":
    "Bug 反馈、补丁、功能请求 —— 每一条都会落到我们的收件箱。",
  "contact.discord": "Discord 服务器",
  "contact.github": "到 GitHub 提 issue",
  "contact.wechat": "微信公众号",
  "contact.wechat_hint": "微信扫码关注公众号，第一时间收到版本更新。",
  "contact.qq": "QQ 群",
  "contact.qr_hint": "微信或 QQ 扫码，加入中文交流群。",

  "footer.meta": "© 2026 NeoShell · 用 Rust ♥ 构建 · 开源 @ GitHub",
  "footer.version": "当前版本",
};
