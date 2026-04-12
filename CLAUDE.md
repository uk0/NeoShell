# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

NeoShell — cross-platform SSH/server management tool (FinalShell alternative). Targets macOS, Windows, Linux.

## Tech Stack

- **Frontend**: React 19 + TypeScript 5.8 + Vite 7 + TailwindCSS v4
- **Backend**: Rust / Tauri v2
- **Terminal emulation**: xterm.js v6 (addons: fit, web-links, webgl)
- **SSH**: Rust `ssh2` crate (libssh2 binding)
- **State management**: Zustand v5
- **Routing**: react-router-dom v7 (hash router for Tauri)
- **Package manager**: pnpm

## Build Commands

**Critical**: `/opt/bin/cc` is a broken linker on this machine. All Rust/Cargo commands require:
```bash
export RUSTFLAGS="-C linker=/usr/bin/cc" CC=/usr/bin/cc CXX=/usr/bin/c++
```

```bash
# Frontend only (fast, no Rust compilation)
pnpm dev              # Vite dev server on :1420
pnpm build            # tsc + vite build → dist/

# Full Tauri (needs linker env vars above)
pnpm tauri dev        # Dev mode with hot reload + Rust backend
pnpm tauri build      # Production build → src-tauri/target/release/bundle/

# Rust only (from src-tauri/)
cargo check           # Type check Rust code
cargo test            # Run Rust tests
cargo clippy          # Lint Rust code
```

`libssh2` must be installed for the ssh2 crate: `brew install libssh2` (macOS).

## Architecture

```
src/                    # React frontend
  main.tsx              # Entry point, mounts React app
  App.tsx               # Root component
src-tauri/              # Rust backend
  src/lib.rs            # Tauri command handlers, plugin registration
  Cargo.toml            # Rust dependencies
  tauri.conf.json       # App config (window, bundle, security)
  capabilities/         # Tauri v2 permission capabilities
```

### Data Flow
1. Frontend calls Rust functions via `invoke()` from `@tauri-apps/api/core`
2. Rust handlers are registered with `tauri::generate_handler![]` in `lib.rs`
3. SSH sessions managed entirely in Rust — frontend never touches raw sockets
4. Terminal I/O: Rust SSH → Tauri events → xterm.js renders

### Key Patterns
- Tauri commands are `#[tauri::command]` annotated functions in `src-tauri/src/`
- Frontend state stores in Zustand — each domain (connections, terminals, settings) gets its own store
- App identifier: `com.firshme.neoshell`

## Core Features (Planned)

1. SSH terminal with multi-tab sessions
2. SFTP file browser/transfer
3. Server monitoring (CPU, memory, disk, network)
4. Connection manager with encrypted credential storage
5. Port forwarding / tunneling
6. Local terminal support

## Release & CI

- Tag-based releases trigger CI/CD builds (not main branch pushes)
- `dev` branch is local-only, never push to remote
- Cross-platform builds: macOS (.dmg/.app), Windows (.msi/.exe), Linux (.deb/.AppImage)
