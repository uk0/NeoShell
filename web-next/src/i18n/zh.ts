import type { Dict } from "./en";

export const zh: Dict = {
  "nav.features": "功能",
  "nav.stack": "技术栈",
  "nav.security": "安全",
  "nav.changelog": "更新日志",
  "nav.download": "下载",
  "nav.github": "GitHub",

  "hero.badge": "v0.6.26 · 纯 Rust · 原生 GPU",
  "hero.title_a": "你真正",
  "hero.title_b": "想用的",
  "hero.title_c": "那款终端。",
  "hero.lede":
    "NeoShell 是一款完全用 Rust 打造的原生 SSH 工作台。加密凭据库、实时监控、多标签终端、SFTP —— 全部集成在一个 6MB 的单文件可执行程序中。无 Electron、无 JavaScript 运行时。",
  "hero.cta.primary": "下载 v0.6.26",
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
  "dl.lede": "v0.6.26 —— 单文件可执行，无需安装依赖。",
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
  "cl.title": "v0.6.26 里有什么",
  "cl.date": "2026-04-25",
  "cl.latest": "最新",
  "cl.category.added": "新增",
  "cl.category.changed": "优化",
  "cl.category.fixed": "修复",
  "cl.added.1":
    "Cmd+F 终端搜索 —— 浮动搜索栏实时扫 scrollback + 当前 grid，黄/橙色高亮、3/12 计数、大小写 toggle、Enter/↑/↓ 导航。",
  "cl.added.2":
    "一键批量导入 ~/.ssh/config —— 所有 Host 条目入连接列表，按 user@host:port 去重。",
  "cl.added.3":
    "命令广播 —— 一次输入，下发到任意多个活跃 session。完美适配 apt update、日志 tail 等场景。",
  "cl.added.4":
    "命令片段库 —— 命名片段持久化到 snippets.json，点击即发送。",
  "cl.added.5":
    "Settings → Appearance —— 7 个颜色 zone 调色盘、字号滑条、实时预览、自动存 theme.json。",
  "cl.added.6":
    "底部面板可折叠 —— Splitter 中央 chevron 按钮 + 新快捷键 Cmd+J / Ctrl+J（VSCode/iTerm2 约定）。",
  "cl.changed.1":
    "主题系统全面 rollout：29 个 view 函数、206 处字号、~280 处颜色。实时生效无需重启。",
  "cl.changed.2":
    "工具栏按钮支持点开/点关切换，不用再找 × 按钮。",
  "cl.changed.3":
    "快捷键帮助面板大改：平台自适应（macOS 显示 ⌘，其他 Ctrl）、中英文 i18n、按领域分组。",
  "cl.fixed.1":
    "Overlay 滚动穿透 & 点击穿透 —— 打开任意 overlay 时，下面的终端不再响应滚轮或点击。",

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
