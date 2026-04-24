export const en = {
  "nav.features": "Features",
  "nav.stack": "Stack",
  "nav.security": "Security",
  "nav.changelog": "Changelog",
  "nav.download": "Download",
  "nav.github": "GitHub",

  "hero.badge": "v0.6.26 · Pure Rust · Native GPU",
  "hero.title_a": "The terminal",
  "hero.title_b": "you actually",
  "hero.title_c": "want to use.",
  "hero.lede":
    "NeoShell is a native SSH workstation built entirely in Rust. Encrypted vault, real-time monitoring, multi-tab terminals, SFTP — all in a single 6 MB binary. No Electron. No JavaScript runtime.",
  "hero.cta.primary": "Download v0.6.26",
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
  "dl.lede": "v0.6.26 — single binary, no installer dependencies.",
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
  "cl.title": "What shipped in v0.6.26",
  "cl.date": "2026-04-25",
  "cl.latest": "Latest",
  "cl.category.added": "Added",
  "cl.category.changed": "Changed",
  "cl.category.fixed": "Fixed",
  "cl.added.1":
    "Cmd+F terminal search — floating bar scans scrollback + grid in real time. Yellow/orange hit highlights, 3/12 counter, case toggle, Enter/↑/↓ navigation.",
  "cl.added.2":
    "Bulk import from ~/.ssh/config — one click adds every Host entry, deduped by user@host:port.",
  "cl.added.3":
    "Command broadcast — type once, send to any subset of active sessions. Perfect for fleet-wide apt update / log tail.",
  "cl.added.4":
    "Command snippet library — named snippets persisted to snippets.json; click to send.",
  "cl.added.5":
    "Settings → Appearance — 7 color-zone palettes, font-size sliders, live preview, auto-saved theme.json.",
  "cl.added.6":
    "Collapsible bottom panel — chevron button on the splitter + new Cmd+J / Ctrl+J shortcut (VSCode/iTerm2 convention).",
  "cl.changed.1":
    "Theme system rolled out across 29 view functions, 206 font-size call sites, ~280 color refs. Live, no restart.",
  "cl.changed.2":
    "Toolbar buttons now toggle open/close on click — no more hunting for the × button.",
  "cl.changed.3":
    "Shortcuts help panel rebuilt — platform-aware (⌘ on macOS, Ctrl elsewhere), EN+ZH i18n, grouped by domain.",
  "cl.fixed.1":
    "Overlay scroll-through & click-through — terminal below stops reacting while any overlay is open.",

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
