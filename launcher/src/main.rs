#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use libloading::{Library, Symbol};
use std::path::PathBuf;

fn main() {
    loop {
        let lib_path = find_core_lib();

        // Apply pending update if exists
        apply_pending_update(&lib_path);

        // Load core library
        let lib = match unsafe { Library::new(&lib_path) } {
            Ok(lib) => lib,
            Err(e) => {
                eprintln!("Failed to load core library {:?}: {}", lib_path, e);
                // Try rollback
                let bak = lib_path_with_ext(&lib_path, "bak");
                if bak.exists() {
                    eprintln!("Rolling back to backup...");
                    let _ = std::fs::rename(&bak, &lib_path);
                    continue;
                }
                std::process::exit(1);
            }
        };

        // Call run()
        let exit_code = unsafe {
            let run: Symbol<extern "C" fn() -> i32> =
                lib.get(b"neoshell_run").expect("Missing neoshell_run symbol");
            run()
        };

        // Unload library before potential swap
        drop(lib);

        match exit_code {
            42 => {
                // Restart requested (update applied)
                eprintln!("Restarting for update...");
                continue;
            }
            code => {
                std::process::exit(code);
            }
        }
    }
}

/// Find the core library path.
/// Looks next to the launcher executable.
fn find_core_lib() -> PathBuf {
    let exe = std::env::current_exe().expect("Cannot get exe path");
    let dir = exe.parent().expect("Cannot get exe dir");

    #[cfg(target_os = "macos")]
    let name = "libneoshell_core.dylib";
    #[cfg(target_os = "windows")]
    let name = "neoshell_core.dll";
    #[cfg(target_os = "linux")]
    let name = "libneoshell_core.so";

    // Check next to executable first, then ../lib/ (AppImage layout)
    let candidate = dir.join(name);
    if candidate.exists() {
        return candidate;
    }
    let lib_dir = dir.join("../lib").join(name);
    if lib_dir.exists() {
        return lib_dir;
    }
    candidate
}

/// Check for pending update and apply it.
fn apply_pending_update(lib_path: &PathBuf) {
    let update_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neoshell")
        .join("updates");

    let staged = update_dir.join(lib_path.file_name().unwrap());

    if staged.exists() {
        eprintln!("Found staged update, applying...");
        let bak = lib_path_with_ext(lib_path, "bak");

        // Backup current
        if lib_path.exists() {
            let _ = std::fs::rename(lib_path, &bak);
        }

        // Move staged -> current
        match std::fs::rename(&staged, lib_path) {
            Ok(()) => {
                eprintln!("Update applied successfully");
            }
            Err(e) => {
                eprintln!("Failed to apply update: {}. Rolling back.", e);
                let _ = std::fs::rename(&bak, lib_path);
            }
        }
    }

    // Clean old backup if exists and library loads fine
    let bak = lib_path_with_ext(lib_path, "bak");
    if bak.exists() && lib_path.exists() {
        let _ = std::fs::remove_file(&bak);
    }
}

fn lib_path_with_ext(path: &PathBuf, ext: &str) -> PathBuf {
    let mut p = path.clone();
    let name = p.file_stem().unwrap().to_string_lossy().to_string();
    p.set_file_name(format!("{}.{}", name, ext));
    p
}
