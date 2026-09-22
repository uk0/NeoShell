# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

NeoShell — cross-platform SSH/server management tool (FinalShell alternative). Pure Rust, native GUI. Targets macOS, Windows, Linux.

## Tech Stack

- **GUI**: iced 0.13 (wgpu GPU-accelerated, native Rust)
- **Terminal**: VTE parser + custom canvas renderer
- **SSH**: Rust `ssh2` crate (libssh2 binding)
- **Encryption**: AES-256-GCM + Argon2id key derivation
- **Async**: tokio
- **State**: parking_lot RwLock/Mutex

## Build Commands

**Critical**: `/opt/bin/cc` is broken. All cargo commands require:
```bash
RUSTFLAGS="-C linker=/usr/bin/cc" CC=/usr/bin/cc CXX=/usr/bin/c++
```

```bash
cargo check           # Type check
cargo build           # Debug build
cargo run             # Run app
cargo test            # Run the workspace unit tests
cargo clippy          # Lint
cargo build --release # Release build
```

`cmake` required (`brew install cmake`): libssh2 and OpenSSL are vendored and
built from source — do NOT install a system libssh2.

## Architecture

Cargo workspace with thin launcher + dynamic core library:

```
Cargo.toml              # Workspace root
launcher/
  src/main.rs           # Thin binary: dlopen core, restart loop, update swap
core/
  build.rs              # Windows resource compilation
  src/
    lib.rs              # Exports neoshell_run() + neoshell_version() via C ABI
    app/                # iced Application, split by concern (was one ~19.6k-line app.rs)
      mod.rs            #   NeoShell state, Message, run/update/subscription, handle_message
      view/             #   every view_* function, grouped by area (sidebar, panels, forms, overlays, …)
      terminal_view.rs  #   the terminal Canvas program, key/mouse encoding
      files.rs          #   file browser listing, remote paths, transfers, ZMODEM
      history.rs  groups.rs  settings.rs  focus.rs  auth.rs  events.rs
      palette.rs  forms.rs  monitor.rs  style.rs
      tests.rs          #   the app's unit tests
    crypto/mod.rs       # AES-256-GCM encryption, Argon2id key derivation
    storage/mod.rs      # Encrypted connection vault (vault.json)
    ssh/mod.rs          # SSH session manager (ssh2 + background threads); SFTP transfers
    terminal/mod.rs     # VTE terminal emulator (grid + parser)
    proxy.rs            # SOCKS5/HTTP proxy + SSH bastion (jump host) chains — proxies.json holds the non-secret fields; passwords/passphrases live in the vault
    tunnel.rs           # Port forwarding (-L / -R / -D SOCKS5) — tunnels.json holds the non-secret fields; secrets live in the vault
    sshkeys.rs          # ed25519 keypair generation (OpenSSH format) for the key manager
    sshconfig.rs        # ~/.ssh/config parser
    i18n.rs             # en/zh string tables, kept in sync
    ui/
      mod.rs            # UI module re-exports
      theme.rs          # Color constants
      theme_config.rs   # theme.json load/save (font sizes, colors)
    updater.rs          # Background update checker/downloader (signature-verified)
```

Build produces: `neoshell` (launcher binary) + `libneoshell_core.dylib` (cdylib with all logic).

Two things a newcomer needs up front:
- **`core/src/app/` holds the entire UI state machine.** `mod.rs` has the `NeoShell`
  struct, every `Message` variant and `handle_message` (still ~4k lines: one
  match over every message). Everything else is in a module per concern; each
  child module starts with `use super::*;`, so items move between them freely.
  A child that uses `column!` must `use iced::widget::column;` explicitly —
  through the glob it is ambiguous with std's `column!`.
- **The update channel requires a signing key.** Published core libraries carry a
  detached ed25519 signature; the launcher and `updater.rs` verify it against
  `NEOSHELL_UPDATE_PUBKEY`, compiled in at build time. A build without that
  variable refuses to install any update. Generate the pair with
  `scripts/gen-update-key.sh`, sign with `scripts/sign-update.sh`.
- **Two dependencies are vendored and patched** under `vendor/`, wired in through
  `[patch.crates-io]` and listed as workspace members so their patch tests run in
  CI. Read each `PATCHES.md` before touching them; do not reformat them.
  - `vendor/ssh2` (0.9.5): on Windows, SFTP names that are not UTF-8 (GBK) aborted
    the process. Its `.gitattributes` keeps upstream's CRLF files byte-identical.
  - `vendor/iced_winit` (0.13.0): input method (IME) support, so Chinese can be
    typed at all, plus `iced_winit::ime`, which `app/focus.rs` uses to turn the IME off
    while a password field has focus. Drop both once iced is upgraded to a release
    with input method support.

### Data Flow
1. User interacts with iced GUI → generates `Message`
2. `update()` handles messages, dispatches `Task::perform` for async ops
3. SSH data arrives via `mpsc::Receiver<SshEvent>`, polled at 50ms intervals
4. Terminal grid updated with VTE parser, rendered on iced Canvas

### Key Patterns
- App uses iced functional API: `iced::application(title, update, view)`
- State machine: Setup → Locked → Main screen
- SSH sessions run on std::thread (ssh2 is blocking), communicate via channels
- Terminal: `TerminalGrid` implements `vte::Perform` for escape sequence handling
- Encrypted vault at the platform config dir (`dirs` crate): macOS `~/Library/Application Support/neoshell/`, Linux `~/.config/neoshell/`, Windows `%APPDATA%\neoshell\` — `vault.json`
- Two-layer encryption: master password → KEK (Argon2id) → DEK → connection data

### Keyboard Handling
- `event::listen_with` captures keyboard events when terminal is active
- `key_to_terminal_bytes()` converts iced key events to terminal escape sequences
- Keys NOT captured by widgets (text_input) are forwarded to active SSH session
- IME commits arrive as one `KeyPressed` per character with `Key::Unidentified`
  and empty modifiers (see `vendor/iced_winit/PATCHES.md`)
- Every `.secure(true)` text input needs a widget id listed in `SECRET_INPUT_IDS`,
  or the input method stays on while it has focus

## Core Features

1. SSH terminal with multi-tab sessions (implemented)
2. Connection manager with AES-256-GCM encrypted storage (implemented)
3. Master password vault with Argon2id key derivation (implemented)
4. VTE terminal emulator with 256-color + truecolor support (implemented)
5. SFTP file browser/transfer (implemented — `ssh/mod.rs` upload_file_with_progress / download_file_with_progress)
6. Server monitoring (implemented — `app/view/panels.rs` view_monitor_panel, 3s poll via FetchMonitorData)
7. Port forwarding (-L, -R, -D SOCKS5), proxy/bastion chains, SSH key manager, command palette, broadcast + sync input (implemented)
8. Chinese input (IME) in every text field and the terminal; collapsible, persisted connection groups (implemented)

## Release & CI

- `.github/workflows/ci.yml` runs on push to `main` and every PR: rustfmt and clippy
  (report-only for now — see the ratchet plan in that file) plus the full test suite
- `.github/workflows/release.yml` runs on `v*` tags only, and builds/publishes every
  platform artifact
- `dev` branch is local-only, never push to remote
- Two-artifact output: launcher binary + core dylib, no web runtime dependencies
- Updater checks https://neoshell.wwwneo.com/updates/update.json for new core library versions
- `scripts/publish-update.sh` signs and uploads the release. It needs
  `NEOSHELL_DEPLOY_HOST` set (no default — the host is deliberately not in the repo)
- Security policy and private reporting: `SECURITY.md`
