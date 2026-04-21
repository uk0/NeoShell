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
    // Verify libssh2 has modern algorithm support — log loudly if it doesn't.
    // (CI tests catch this too, but a user-facing log line makes a bad build obvious.)
    match ssh::verify_required_algorithms() {
        Ok(()) => log::info!("libssh2 algorithm self-check: OK"),
        Err(e) => log::error!("libssh2 algorithm self-check FAILED: {}", e),
    }
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

/// Install a logger that writes to both stderr and a persistent log file.
/// The file handle is reopened on every write so that if the user deletes
/// the log file while the app is running, the next log line recreates it
/// instead of writing into a ghost inode (POSIX unlink semantics).
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

    // Serialize writes so two threads don't interleave characters mid-line.
    let write_lock = std::sync::Arc::new(std::sync::Mutex::new(()));
    let write_lock_for_closure = write_lock.clone();
    let path_for_closure = path.clone();

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
        // Open-append-close on every line so `rm neoshell.log` during runtime
        // is handled correctly — next write recreates the file.
        if let Ok(_g) = write_lock_for_closure.lock() {
            // Ensure parent dir exists (log dir might be removed alongside the file).
            if let Some(parent) = path_for_closure.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path_for_closure)
            {
                let _ = writeln!(f, "{}", line);
                let _ = f.flush();
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

#[cfg(test)]
mod logger_tests {
    use std::io::Write;

    /// Verify that log output recreates the file if it was deleted mid-run.
    /// (Can't call init_logger directly because env_logger::Builder is global;
    /// instead this tests the open-append-close write helper logic.)
    #[test]
    fn log_file_recreates_after_deletion() {
        let tmp = std::env::temp_dir().join(format!("neoshell_test_{}.log", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let write = |line: &str| {
            if let Some(parent) = tmp.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp)
                .expect("open log");
            writeln!(f, "{}", line).unwrap();
        };

        write("line 1");
        write("line 2");
        assert!(tmp.exists(), "file should exist after writes");

        // Simulate user deleting the log file mid-run
        std::fs::remove_file(&tmp).expect("remove");
        assert!(!tmp.exists(), "file should be gone");

        // Next write must recreate it
        write("line 3");
        assert!(tmp.exists(), "file should be recreated on next write");
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert_eq!(content.trim(), "line 3", "only post-delete content should remain");

        let _ = std::fs::remove_file(&tmp);
    }
}
