export const en = {
  "nav.features": "Features",
  "nav.stack": "Stack",
  "nav.security": "Security",
  "nav.changelog": "Changelog",
  "nav.download": "Download",
  "nav.github": "GitHub",

  "hero.badge": "v0.7.0 · Pure Rust · Native GPU",
  "hero.title_a": "The terminal",
  "hero.title_b": "you actually",
  "hero.title_c": "want to use.",
  "hero.lede":
    "NeoShell is a native SSH workstation built entirely in Rust. Encrypted vault, real-time monitoring, multi-tab terminals, SFTP — all in a single 6 MB binary. No Electron. No JavaScript runtime.",
  "hero.cta.primary": "Download v0.7.0",
  "hero.cta.secondary": "Explore features",
  "hero.cta.source": "Source on GitHub →",
  "hero.stat.binary": "Binary size",
  "hero.stat.start": "Cold start",
  "hero.stat.mem": "Memory idle",
  "hero.stat.platforms": "Platforms",

  "features.eyebrow": "What's inside",
  "features.title": "Everything the work needs. Nothing it doesn't.",
  "features.lede":
    "A full SSH workstation that never asks you to install a JVM, an Electron runtime, or 800 MB of RAM you didn't plan to give it.",
  "features.terminal.title": "Multi-tab terminal",
  "features.terminal.body":
    "Full VTE emulator with 256-color, truecolor, CJK. 10 000 lines of scrollback. Cmd+1-9 switching. Cmd+F search with live highlight.",
  "features.vault.title": "Encrypted vault",
  "features.vault.body":
    "AES-256-GCM + Argon2id. Two-layer envelope encryption. Passwords never touch disk in cleartext.",
  "features.ssh.title": "Eternal SSH",
  "features.ssh.body":
    "Auto-reconnect with tmux persistence. Wi-Fi drops, VPN resets, laptop sleep — your session survives every one of them.",
  "features.monitor.title": "Live monitoring",
  "features.monitor.body":
    "CPU, memory, every disk partition, per-interface network, top 15 processes. Refreshed every 3 seconds.",
  "features.sftp.title": "SFTP browser",
  "features.sftp.body":
    "Navigate remote files, upload/download with progress bars and resume. Quick-edit configs in-app.",
  "features.cross.title": "Cross-platform",
  "features.cross.body":
    "macOS (ARM64 + Intel), Windows 7–11, Linux. Same native experience. Never a web runtime.",

  "stack.eyebrow": "Under the hood",
  "stack.title": "100% Rust. Zero JavaScript.",
  "stack.lede":
    "No Electron. No WebView. Hardware-accelerated rendering via wgpu.",
  "stack.item.iced": "iced 0.13",
  "stack.item.iced_d": "GPU-accelerated native GUI via wgpu",
  "stack.item.ssh2": "libssh2 + OpenSSL",
  "stack.item.ssh2_d": "Vendored on every platform for full KEX/algo support",
  "stack.item.vte": "VTE",
  "stack.item.vte_d": "Full xterm parser, custom canvas renderer",
  "stack.item.crypto": "AES-256-GCM",
  "stack.item.crypto_d": "+ Argon2id KDF — memory-hard, GPU-resistant",
  "stack.item.tokio": "Tokio",
  "stack.item.tokio_d": "Async runtime, 50 ms SSH poll loop",

  "security.eyebrow": "Trust model",
  "security.title": "Your credentials. Your machine. Nothing else.",
  "security.lede":
    "Two-layer envelope encryption. Nothing leaves your device in cleartext.",
  "security.item.1": "Master password never stored — only the derived KEK is used",
  "security.item.2": "Each connection encrypted with a unique random nonce",
  "security.item.3": "Vault is binary noise without the correct password",
  "security.item.4": "Dedicated exec SSH session — zero lock contention with terminal",
  "security.item.5": "Private keys encrypted at rest, decrypted only in memory",
  "security.item.6":
    "Open source on GitHub. Audit the crypto, fork, contribute.",

  "dl.eyebrow": "Get started",
  "dl.title": "Download NeoShell",
  "dl.lede": "v0.7.0 — single binary, no installer dependencies.",
  "dl.macos": "macOS",
  "dl.macos_arm": "Apple Silicon (ARM64)",
  "dl.macos_intel": "Intel (x86_64)",
  "dl.windows": "Windows 10 / 11",
  "dl.win7": "Windows 7",
  "dl.linux": "Linux",
  "dl.primary": "Download",
  "dl.alt": "Alt",
  "dl.note": "Crafted by NEO — firsh.me",
  "dl.update_note": "Already installed? App auto-updates within 1 hour.",

  "cl.eyebrow": "Release log",
  "cl.title": "What shipped in v0.7.0",
  "cl.date": "2026-09-23",
  "cl.latest": "Latest",
  "cl.category.added": "Added",
  "cl.category.changed": "Changed",
  "cl.category.fixed": "Fixed",
  "cl.added.1":
    "Chinese input methods work everywhere — type into connection names, groups, search and the terminal itself. Password fields switch the input method off.",
  "cl.added.2":
    "SFTP file operations — new folder, rename, delete and permissions from the right-click menu, whole-folder upload and download, and drag-and-drop upload.",
  "cl.added.3":
    "Remote (-R) and dynamic SOCKS5 (-D) port forwarding, alongside local forwards.",
  "cl.added.4":
    "Two-factor sign-in (keyboard-interactive codes) and SSH agent authentication.",
  "cl.added.5":
    "Command palette (Cmd/Ctrl+K), split panes, an SSH key manager, and synchronized input across sessions.",
  "cl.added.6":
    "Monitoring adds listening ports, process kill, per-core CPU and swap; eight colour schemes; collapsible connection groups.",
  "cl.changed.1":
    "SSH host keys are checked against ~/.ssh/known_hosts. A new host is remembered on first connect; a changed key is refused.",
  "cl.changed.2":
    "Proxy and tunnel passwords move into the encrypted vault on first unlock, and the vault locks itself after 15 minutes idle.",
  "cl.changed.3":
    "Updates are signed and verified before they are installed.",
  "cl.changed.4":
    "Lower idle CPU — terminal output wakes the window instead of polling 20 times a second.",
  "cl.changed.5":
    "Readable contrast on every surface, tooltips on icon buttons, and a welcome screen that can create or import connections.",
  "cl.fixed.1":
    "No more crash when an error message mixes Chinese and English.",
  "cl.fixed.2":
    "Windows no longer quits on SFTP folders that contain GBK file names.",
  "cl.fixed.3":
    "A failed update rolls back to the previous version instead of leaving the app unable to start.",

  "contact.eyebrow": "Stay in touch",
  "contact.title": "Join the community",
  "contact.lede":
    "Bug reports, patches, feature requests — every one of them lands in our inbox.",
  "contact.discord": "Discord server",
  "contact.github": "Open a GitHub issue",
  "contact.wechat": "WeChat MP",
  "contact.wechat_hint": "Scan with WeChat to follow the official account for release notes.",
  "contact.qq": "QQ group",
  "contact.qr_hint": "Scan with WeChat or QQ to join the Chinese-speaking group.",

  "footer.meta": "© 2026 NeoShell · Built with Rust ♥ · Open source on GitHub",
  "footer.version": "Current release",
} as const;

export type Dict = Record<keyof typeof en, string>;
