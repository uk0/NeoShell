#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod i18n;
mod proxy;
mod app;
mod crypto;
mod ssh;
mod sshconfig;
mod sshkeys;
mod storage;
mod terminal;
mod tunnel;
mod ui;
pub mod updater;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Entry point called by the launcher via dlopen.
/// Returns: 0 = normal exit, 42 = restart for update
#[no_mangle]
pub extern "C" fn neoshell_run() -> i32 {
    // First, so that even a panic while the logger starts is recorded.
    // Release builds are panic = "abort": the process dies where it panics,
    // and the hook is the only code that still runs. Nothing catches the
    // panic, on purpose. Under abort a catch_unwind would be dead code, and
    // switching to unwind would carry panics through the platform event
    // loop's foreign (AppKit, Win32) frames, which is not sound.
    install_panic_hook();
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
pub(crate) fn log_file_path() -> PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neoshell");
    // Owner-only like every other NeoShell directory. The logger starts
    // before anything else, so this is usually where the directory is made.
    let _ = storage::create_dir_private(&dir);
    dir.join("neoshell.log")
}

/// Rotate the log once it passes this size, keeping one previous file.
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

/// Every this many lines the logger checks that its open handle is still the
/// file at the log path, and that the file is under `MAX_LOG_BYTES`...
const CHECK_EVERY_LINES: u32 = 64;

/// ...and on the first line after this long without a check, so that a quiet
/// session also notices a deleted log on its next line.
const CHECK_EVERY: Duration = Duration::from_secs(1);

/// The log file every record is appended to, besides stderr.
static LOG_FILE: Mutex<Option<LogFile>> = Mutex::new(None);

/// Install a logger that writes to both stderr and a persistent log file.
///
/// The file stays open between lines. Deleting or moving `neoshell.log` while
/// the app runs still works: a periodic check notices that the path no longer
/// names the open file and opens it again, which recreates it.
fn init_logger() {
    let path = log_file_path();

    // Earlier builds created the log with the default umask, 0644 in practice.
    // The live file is narrowed when it is opened; this covers the rotated
    // copy next to it.
    storage::tighten_permissions(&rotated_log_path(&path));

    // Opening runs the first check, which also rotates a log that an earlier
    // session left over the limit.
    let log = LogFile::open(path);
    *LOG_FILE.lock().unwrap_or_else(PoisonError::into_inner) = Some(log);

    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    );
    builder.format(|buf, record| {
        let line = format!(
            "[{} {} {}] {}\n",
            chrono_now(),
            record.level(),
            record.target(),
            record.args()
        );
        append_line(&LOG_FILE, line.as_bytes());
        buf.write_all(line.as_bytes())
    });
    // ignore "already set" error if env_logger::init was called before
    let _ = builder.try_init();
}

/// Append one finished line to the log file held in `log`, if there is one.
fn append_line(log: &Mutex<Option<LogFile>>, line: &[u8]) {
    // Debug builds unwind, so a panic while this lock is held poisons it. The
    // LogFile inside is still sound; keep logging rather than go quiet.
    let mut guard = log.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(log) = guard.as_mut() {
        log.append(line);
    }
}

/// The open log file, plus what the logger needs to notice that it has been
/// deleted, replaced, or has outgrown `MAX_LOG_BYTES`.
struct LogFile {
    path: PathBuf,
    /// `None` while the file cannot be opened; the next check tries again.
    file: Option<File>,
    lines_since_check: u32,
    last_check: Instant,
}

impl LogFile {
    /// Open the log at `path`: create it, or rotate it first if it is already
    /// over the limit.
    fn open(path: PathBuf) -> Self {
        let mut log = LogFile {
            path,
            file: None,
            lines_since_check: 0,
            last_check: Instant::now(),
        };
        log.check();
        log
    }

    /// Append one finished line. Errors are dropped: a logger has nowhere to
    /// report its own, and the line still reaches stderr.
    ///
    /// The whole line goes out in one write with no buffer in between, so an
    /// abort straight after a log call has nothing left in memory to lose.
    fn append(&mut self, line: &[u8]) {
        self.lines_since_check = self.lines_since_check.saturating_add(1);
        if check_due(self.lines_since_check, self.last_check.elapsed()) {
            self.check();
        }
        let Some(file) = self.file.as_mut() else {
            return;
        };
        // A failed write is a reason to look now rather than at the next
        // scheduled check. If that replaced the handle, the line goes there.
        if file.write_all(line).is_err() && self.check() != LogAction::Keep {
            if let Some(file) = self.file.as_mut() {
                let _ = file.write_all(line);
            }
        }
    }

    /// Compare the open handle with the file at the log path, then reopen or
    /// rotate as `log_file_action` decides. Returns what it did.
    fn check(&mut self) -> LogAction {
        self.lines_since_check = 0;
        self.last_check = Instant::now();
        let held = self.file.as_ref().and_then(|f| f.metadata().ok());
        let at_path = std::fs::metadata(&self.path).ok();
        let action = log_file_action(
            held.as_ref().map(FileStamp::of),
            at_path.as_ref().map(FileStamp::of),
        );
        match action {
            LogAction::Keep => {}
            LogAction::Reopen => self.reopen(),
            LogAction::Rotate => {
                // Closed first, so the rename never depends on how an open
                // handle shares the file (it matters on Windows).
                self.file = None;
                let _ = std::fs::rename(&self.path, rotated_log_path(&self.path));
                self.reopen();
            }
        }
        action
    }

    fn reopen(&mut self) {
        // Close before opening again: on Windows a deleted file can keep its
        // name reserved until the last handle to it is closed.
        self.file = None;
        self.file = open_log_file(&self.path).ok();
    }
}

/// Enough of a file's metadata to tell whether two handles or paths lead to
/// the same file, and how big it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    /// (device, inode) on unix. `None` elsewhere: stable std exposes no file
    /// identity on Windows, so the length stands in for it there.
    id: Option<(u64, u64)>,
    len: u64,
}

impl FileStamp {
    fn of(meta: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        let id = {
            use std::os::unix::fs::MetadataExt;
            Some((meta.dev(), meta.ino()))
        };
        #[cfg(not(unix))]
        let id = None;
        FileStamp { id, len: meta.len() }
    }

    fn same_file(&self, other: &FileStamp) -> bool {
        match (self.id, other.id) {
            (Some(a), Some(b)) => a == b,
            // A file recreated at the path, by another instance rotating the
            // log say, is all but certain to differ in length from ours.
            _ => self.len == other.len,
        }
    }
}

/// What `LogFile::check` does with its handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogAction {
    /// The handle is the file at the path, and that file is under the limit.
    Keep,
    /// Open the path again: nothing is there (deleted or moved away, and
    /// opening recreates it), a different file is, or no handle is open.
    Reopen,
    /// The file at the path is over the limit: move it to `.old` and start
    /// a new one.
    Rotate,
}

/// Decide what to do about the log handle, from the file it holds (`held`,
/// `None` when no handle is open) and the file the log path names now
/// (`at_path`, `None` when nothing is there).
fn log_file_action(held: Option<FileStamp>, at_path: Option<FileStamp>) -> LogAction {
    let Some(at_path) = at_path else {
        return LogAction::Reopen;
    };
    if needs_rotation(at_path.len) {
        return LogAction::Rotate;
    }
    match held {
        Some(held) if held.same_file(&at_path) => LogAction::Keep,
        _ => LogAction::Reopen,
    }
}

/// Whether a log of `len` bytes is due for rotation.
fn needs_rotation(len: u64) -> bool {
    len > MAX_LOG_BYTES
}

/// Whether `LogFile::append` should check the file before this line.
fn check_due(lines_since_check: u32, since_last_check: Duration) -> bool {
    lines_since_check >= CHECK_EVERY_LINES || since_last_check >= CHECK_EVERY
}

/// `neoshell.log.old`: the one previous log that rotation keeps.
fn rotated_log_path(path: &Path) -> PathBuf {
    path.with_extension("log.old")
}

/// Open the log for appending, creating it and its directory owner-only.
///
/// The log names the hosts and users connected to, so it gets the same 0600
/// file and 0700 directory as the vault beside it. A log created before that
/// rule, or by the launcher, is narrowed through the handle.
/// `storage::tighten_permissions` would do the same by path, but it reports
/// failure through the logger, and this runs inside the logger.
fn open_log_file(path: &Path) -> std::io::Result<File> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        storage::create_dir_private(dir)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = file.metadata() {
            let mode = meta.permissions().mode();
            if mode & 0o177 != 0 {
                let _ = file.set_permissions(std::fs::Permissions::from_mode(mode & 0o7600));
            }
        }
    }
    Ok(file)
}

/// Tiny timestamp formatter — avoids pulling in chrono just for this.
/// Always UTC, and says so with the trailing Z: std has no time zone support
/// to work out local time with.
fn chrono_now() -> String {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_utc(since_epoch)
}

/// ISO-8601 in UTC to the millisecond, e.g. `2026-09-22T13:53:31.123Z`.
fn format_utc(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs();
    let (year, month, day) = civil_from_days(secs / 86_400);
    let secs_of_day = secs % 86_400;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        secs_of_day / 3_600,
        secs_of_day / 60 % 60,
        secs_of_day % 60,
        since_epoch.subsec_millis()
    )
}

/// (year, month, day) of the proleptic Gregorian date `days` after 1970-01-01.
///
/// Howard Hinnant's `civil_from_days`
/// (<https://howardhinnant.github.io/date_algorithms.html#civil_from_days>),
/// kept to unsigned arithmetic: a clock read after 1970 never needs the
/// negative half.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    // Count from 0000-03-01 instead, so that every year ends on its leap day
    // and every 400-year era (146097 days) starts at the same point.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // year of era, [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of the March-based year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month counted from March, [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    // January and February close the March-based year, so they belong to the
    // next civil one.
    let year = era * 400 + yoe + u64::from(month <= 2);
    (year, month, day)
}

/// Write every panic to the log before the default hook reports it.
///
/// Installed once per loaded copy of this library. The launcher calls
/// `neoshell_run` again after an update restart, and where the OS kept the
/// library mapped, a second install would chain this hook onto itself and log
/// every panic twice.
fn install_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            log_panic(info);
            default_hook(info);
        }));
    });
}

/// Append a report of the panic to the log file.
///
/// A panic inside a panic hook aborts on the spot, so nothing here may panic:
/// no unwrap, and every error is dropped. It takes no lock either. The
/// panicking thread may be inside a log call and already hold the logger's
/// lock, so the report goes out through a handle of its own, as a single
/// appending write like each of the logger's lines.
fn log_panic(info: &std::panic::PanicHookInfo<'_>) {
    let location: &dyn std::fmt::Display = match info.location() {
        Some(location) => location,
        None => &"<unknown location>",
    };
    let thread = std::thread::current();
    let report = panic_report(
        &chrono_now(),
        thread.name(),
        location,
        panic_message(info.payload()),
        &std::backtrace::Backtrace::force_capture(),
    );
    write_panic_report(&log_file_path(), &report);
}

/// Append `report` to the log at `path`. A log that cannot be written is
/// skipped: stderr still gets the default hook's report.
fn write_panic_report(path: &Path, report: &str) {
    if let Ok(mut file) = open_log_file(path) {
        let _ = file.write_all(report.as_bytes());
    }
}

/// The message in a panic payload: the `&str` or `String` that `panic!`
/// produces, or the placeholder std's own hook prints for anything else.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        "Box<dyn Any>"
    }
}

/// The text `log_panic` appends: a line shaped like every other log line,
/// then the message and the backtrace.
fn panic_report(
    timestamp: &str,
    thread: Option<&str>,
    location: &dyn std::fmt::Display,
    message: &str,
    backtrace: &dyn std::fmt::Display,
) -> String {
    use std::fmt::Write as _;
    // write! into a String fails only when a Display impl reports an error.
    // format! would turn that into a panic, which inside the hook aborts
    // before anything is written, so the error is ignored instead.
    let mut trace = String::new();
    let _ = write!(trace, "{}", backtrace);
    let mut report = String::new();
    let _ = write!(
        report,
        "[{} ERROR panic] thread '{}' panicked at {}:\n{}\nstack backtrace:\n{}\n",
        timestamp,
        thread.unwrap_or("<unnamed>"),
        location,
        message,
        trace.trim_end()
    );
    report
}

/// Return the current version string.
#[no_mangle]
pub extern "C" fn neoshell_version() -> *const u8 {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr()
}

#[cfg(test)]
mod logger_tests {
    use super::*;

    /// A fresh, empty directory for one test's log files.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("neoshell_log_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn utc(secs: u64, millis: u64) -> String {
        format_utc(Duration::from_millis(secs * 1_000 + millis))
    }

    #[test]
    fn timestamps_are_iso_8601_utc_with_the_date() {
        assert_eq!(utc(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(utc(951_782_400, 0), "2000-02-29T00:00:00.000Z");
        assert_eq!(utc(1_790_085_211, 123), "2026-09-22T13:53:31.123Z");
    }

    #[test]
    fn timestamps_cross_leap_days_correctly() {
        // 2000 is a leap year: divisible by 400.
        assert_eq!(utc(951_782_399, 999), "2000-02-28T23:59:59.999Z");
        assert_eq!(utc(951_868_800, 0), "2000-03-01T00:00:00.000Z");
        // So is 2024, which the leap day also makes 366 days long.
        assert_eq!(utc(1_709_164_799, 999), "2024-02-28T23:59:59.999Z");
        assert_eq!(utc(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
        assert_eq!(utc(1_735_689_599, 0), "2024-12-31T23:59:59.000Z");
        assert_eq!(utc(1_735_689_600, 0), "2025-01-01T00:00:00.000Z");
        // 2100 is not: divisible by 100 but not by 400.
        assert_eq!(utc(4_107_542_399, 0), "2100-02-28T23:59:59.000Z");
        assert_eq!(utc(4_107_542_400, 0), "2100-03-01T00:00:00.000Z");
    }

    #[test]
    fn civil_dates_agree_with_a_day_by_day_calendar_walk() {
        // Step through the calendar one day at a time with the plain
        // month-length rules, from 1970 to past 2400, and compare every day.
        fn is_leap(y: u64) -> bool {
            (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
        }
        let (mut y, mut m, mut d): (u64, u64, u64) = (1970, 1, 1);
        for days in 0..160_000u64 {
            assert_eq!(civil_from_days(days), (y, m, d), "day {}", days);
            let month_len = match m {
                2 if is_leap(y) => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            d += 1;
            if d > month_len {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
        assert!(y > 2400, "the walk should pass 2400, stopped in {}", y);
    }

    fn stamp(ino: u64, len: u64) -> Option<FileStamp> {
        Some(FileStamp { id: Some((1, ino)), len })
    }

    #[test]
    fn the_log_is_reopened_once_the_path_stops_naming_the_open_file() {
        // Deleted or moved away: opening the path recreates the file.
        assert_eq!(log_file_action(stamp(7, 10), None), LogAction::Reopen);
        // Replaced by a different file, e.g. another instance rotated it.
        assert_eq!(log_file_action(stamp(7, 10), stamp(8, 10)), LogAction::Reopen);
        // No handle, because an earlier open failed: try again.
        assert_eq!(log_file_action(None, stamp(8, 10)), LogAction::Reopen);
        assert_eq!(log_file_action(None, None), LogAction::Reopen);
        // Still the same file, and a growing one at that: nothing to do.
        assert_eq!(log_file_action(stamp(7, 10), stamp(7, 10)), LogAction::Keep);
        assert_eq!(log_file_action(stamp(7, 10), stamp(7, 90)), LogAction::Keep);
    }

    #[test]
    fn without_a_file_identity_the_length_decides() {
        let no_id = |len| Some(FileStamp { id: None, len });
        assert_eq!(log_file_action(no_id(10), no_id(10)), LogAction::Keep);
        assert_eq!(log_file_action(no_id(10), no_id(3)), LogAction::Reopen);
        assert_eq!(log_file_action(no_id(10), None), LogAction::Reopen);
    }

    #[test]
    fn rotation_starts_just_past_the_size_limit() {
        assert!(!needs_rotation(MAX_LOG_BYTES));
        assert!(needs_rotation(MAX_LOG_BYTES + 1));
        let at_limit = stamp(7, MAX_LOG_BYTES);
        let over = stamp(7, MAX_LOG_BYTES + 1);
        assert_eq!(log_file_action(at_limit, at_limit), LogAction::Keep);
        assert_eq!(log_file_action(over, over), LogAction::Rotate);
        // At startup nothing is open yet; an oversized leftover still rotates.
        assert_eq!(log_file_action(None, over), LogAction::Rotate);
    }

    #[test]
    fn checks_run_every_n_lines_or_after_a_quiet_spell() {
        assert!(!check_due(1, Duration::ZERO));
        assert!(!check_due(CHECK_EVERY_LINES - 1, CHECK_EVERY - Duration::from_millis(1)));
        assert!(check_due(CHECK_EVERY_LINES, Duration::ZERO));
        assert!(check_due(1, CHECK_EVERY));
    }

    #[test]
    fn a_log_moved_away_is_recreated_by_the_next_check() {
        let dir = scratch("moved");
        let path = dir.join("neoshell.log");
        let mut log = LogFile::open(path.clone());
        log.append(b"before\n");
        // What renaming it by hand, or a move to the Recycle Bin, does.
        let moved = dir.join("moved.log");
        std::fs::rename(&path, &moved).expect("move the log away");
        // The line count or the clock would trigger this within a second.
        assert_eq!(log.check(), LogAction::Reopen);
        log.append(b"after\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        assert_eq!(std::fs::read_to_string(&moved).unwrap(), "before\n");
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unix only: there an unlinked name is gone at once. On Windows a file
    /// deleted while open can linger as delete-pending, which std then reports
    /// from a stale directory entry; the move-away test above covers the same
    /// reopen on every platform.
    #[cfg(unix)]
    #[test]
    fn a_deleted_log_is_recreated_by_the_next_check() {
        let dir = scratch("deleted");
        let path = dir.join("neoshell.log");
        let mut log = LogFile::open(path.clone());
        log.append(b"line 1\n");
        std::fs::remove_file(&path).expect("delete the log");
        assert_eq!(log.check(), LogAction::Reopen);
        log.append(b"line 2\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "line 2\n");
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_oversized_log_is_rotated_to_old_at_startup_and_mid_session() {
        let dir = scratch("rotate");
        let path = dir.join("neoshell.log");
        let old = dir.join("neoshell.log.old");
        std::fs::create_dir_all(&dir).unwrap();
        let too_big = vec![b'x'; MAX_LOG_BYTES as usize + 1];

        // Startup: an earlier session left the log over the limit.
        std::fs::write(&path, &too_big).unwrap();
        let mut log = LogFile::open(path.clone());
        log.append(b"fresh\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh\n");
        assert_eq!(std::fs::metadata(&old).unwrap().len(), too_big.len() as u64);

        // Mid-session: the log grows past the limit and the next check
        // rotates it, replacing the previous .old.
        log.append(&too_big);
        assert_eq!(log.check(), LogAction::Rotate);
        log.append(b"after\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        assert_eq!(std::fs::metadata(&old).unwrap().len(), 6 + too_big.len() as u64);

        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_log_and_its_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = scratch("private");
        let path = dir.join("sub").join("neoshell.log");

        drop(open_log_file(&path).expect("create the log"));
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);

        // A log that an older build left world-readable is narrowed, and
        // appended to rather than truncated.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&path, "kept\n").unwrap();
        let mut file = open_log_file(&path).expect("reopen the log");
        file.write_all(b"added\n").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "kept\nadded\n");

        drop(file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn logging_carries_on_after_the_lock_is_poisoned() {
        let dir = scratch("poisoned");
        let path = dir.join("neoshell.log");
        let log = Mutex::new(Some(LogFile::open(path.clone())));
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _held = log.lock();
                    panic!("poison the logger's lock");
                })
                .join();
        });
        assert!(log.is_poisoned());

        append_line(&log, b"still logging\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "still logging\n");

        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_panic_report_carries_thread_location_message_and_backtrace() {
        let report = panic_report(
            "2026-09-22T13:53:31.123Z",
            Some("main"),
            &"core/src/app.rs:10:5",
            "index out of bounds",
            &"   0: neoshell_core::app::update\n   1: main\n",
        );
        let expected = concat!(
            "[2026-09-22T13:53:31.123Z ERROR panic] thread 'main' panicked at core/src/app.rs:10:5:\n",
            "index out of bounds\n",
            "stack backtrace:\n",
            "   0: neoshell_core::app::update\n",
            "   1: main\n",
        );
        assert_eq!(report, expected);

        let unnamed = panic_report("t", None, &"f.rs:1:1", "m", &"   0: f\n");
        assert!(unnamed.contains("thread '<unnamed>' panicked at f.rs:1:1:\nm\n"), "{}", unnamed);
    }

    #[test]
    fn panic_messages_are_read_from_str_and_string_payloads() {
        let literal: &(dyn std::any::Any + Send) = &"boom";
        let formatted: &(dyn std::any::Any + Send) = &String::from("boom 42");
        let other: &(dyn std::any::Any + Send) = &42_i32;
        assert_eq!(panic_message(literal), "boom");
        assert_eq!(panic_message(formatted), "boom 42");
        assert_eq!(panic_message(other), "Box<dyn Any>");
    }

    #[test]
    fn an_unwritable_log_is_skipped_without_panicking() {
        let dir = scratch("unwritable");
        std::fs::create_dir_all(&dir).unwrap();
        // The log's directory would have to go where a file already is.
        let blocker = dir.join("not-a-dir");
        std::fs::write(&blocker, "").unwrap();
        let path = blocker.join("neoshell.log");

        write_panic_report(&path, "report\n");
        let mut log = LogFile::open(path.clone());
        log.append(b"line\n");
        assert_eq!(log.check(), LogAction::Reopen);
        log.append(b"line\n");
        assert!(!path.exists());

        // Once the log can be written, reports are appended one after another.
        let good = dir.join("neoshell.log");
        write_panic_report(&good, "first\n");
        write_panic_report(&good, "second\n");
        assert_eq!(std::fs::read_to_string(&good).unwrap(), "first\nsecond\n");

        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
