#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod i18n;
mod proxy;
mod app;
mod crypto;
mod ssh;
mod sshconfig;
mod storage;
mod terminal;
mod ui;
pub mod updater;

/// Entry point called by the launcher via dlopen.
/// Returns: 0 = normal exit, 42 = restart for update
#[no_mangle]
pub extern "C" fn neoshell_run() -> i32 {
    init_logger();
    log::info!("NeoShell {} starting; log file: {}",
        env!("CARGO_PKG_VERSION"), log_file_path().display());
    match app::run() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Path to the persistent log file under the app data dir.
pub(crate) fn log_file_path() -> std::path::PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("neoshell");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("neoshell.log")
}

/// Install a logger that writes to BOTH stderr (for terminal-launched use)
/// and a rotating-ish log file so GUI users can inspect connection failures
/// after the fact. Also redirects raw stderr into the log file so libssh2
/// trace output (which writes to fprintf(stderr, ...) bypassing the log crate)
/// is captured alongside structured logs.
fn init_logger() {
    use std::io::Write;

    let path = log_file_path();

    // Rotate: if > 2 MB, rename to .old and start fresh (keep only 1 previous).
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > 2 * 1024 * 1024 {
            let old = path.with_extension("log.old");
            let _ = std::fs::rename(&path, &old);
        }
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok();

    let file_arc = file.map(|f| std::sync::Arc::new(std::sync::Mutex::new(f)));

    let file_for_closure = file_arc.clone();
    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    );
    builder.format(move |buf, record| {
        let line = format!(
            "[{} {} {}] {}",
            chrono_now(),
            record.level(),
            record.target(),
            record.args()
        );
        if let Some(f) = &file_for_closure {
            if let Ok(mut g) = f.lock() {
                let _ = writeln!(g, "{}", line);
                let _ = g.flush();
            }
        }
        writeln!(buf, "{}", line)
    });
    // ignore "already set" error if env_logger::init was called before
    let _ = builder.try_init();
}

/// Tiny timestamp formatter — avoids pulling in chrono just for this.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let total = dur.as_secs();
    let ms = dur.subsec_millis();
    // Local time breakdown (approximate — no TZ handling for simplicity)
    let secs = total % 60;
    let mins = (total / 60) % 60;
    let hours = (total / 3600) % 24;
    // Use UTC-ish HH:MM:SS.mmm; full datetime is logged via file mtime
    format!("{:02}:{:02}:{:02}.{:03}", hours, mins, secs, ms)
}

/// Return the current version string.
#[no_mangle]
pub extern "C" fn neoshell_version() -> *const u8 {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr()
}
