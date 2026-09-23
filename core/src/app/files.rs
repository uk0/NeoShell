use super::*;

/// ZMODEM cancel sequence: 5x CAN + 5x BS.
pub(crate) const ZMODEM_CANCEL: &[u8] = &[0x18, 0x18, 0x18, 0x18, 0x18, 0x08, 0x08, 0x08, 0x08, 0x08];

/// Detect ZMODEM from `rz` command.
pub(crate) fn detect_zmodem_rz(data: &[u8]) -> bool {
    data.windows(6).any(|w| w.starts_with(b"**\x18B0"))
        || data.windows(4).any(|w| w == b"**B0")
        || data.windows(22).any(|w| w.starts_with(b"rz waiting to receive"))
}

/// Extract CWD from the shell prompt in the terminal grid.
/// Matches common prompt patterns like:
///   user@host:/path$    user@host:~$    (env) user@host:/path$
pub(crate) fn extract_cwd_from_prompt(grid: &TerminalGrid) -> Option<String> {
    // Scan bottom-up for a line with a prompt pattern
    for y in (0..grid.rows).rev() {
        let line: String = grid.cells[y].iter()
            .filter(|c| !c.wide_cont)
            .map(|c| c.c)
            .collect();
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        // Match pattern: ...@...:PATH$ or ...@...:PATH#
        // Find the last occurrence of @...:/path$ pattern
        if let Some(at_pos) = trimmed.rfind('@') {
            let after_at = &trimmed[at_pos + 1..];
            if let Some(colon_pos) = after_at.find(':') {
                let after_colon = &after_at[colon_pos + 1..];
                // Extract path: everything until $ or # or end
                let path: String = after_colon
                    .chars()
                    .take_while(|&c| c != '$' && c != '#')
                    .collect();
                let path = path.trim().to_string();
                if !path.is_empty() {
                    // Expand ~ to actual home if needed
                    return Some(path);
                }
            }
        }
        // Only check the last non-empty line with prompt
        break;
    }
    None
}

/// Extract "sz filename" from the terminal grid (shell echo already rendered).
/// Scans recent lines bottom-up for "sz " pattern.
pub(crate) fn extract_sz_from_grid(grid: &TerminalGrid) -> Option<String> {
    for y in (0..grid.rows).rev() {
        let line: String = grid.cells[y].iter()
            .filter(|c| !c.wide_cont)
            .map(|c| c.c)
            .collect();
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        // Stop if we hit ZMODEM garbage or NeoShell messages
        if trimmed.starts_with("**") || trimmed.contains("[NeoShell]") { continue; }

        if let Some(pos) = trimmed.rfind("sz ") {
            let after = trimmed[pos + 3..].trim();
            // Take filename (everything before ZMODEM or control chars)
            let fname: String = after
                .chars()
                .take_while(|&c| c != '*' && c != '\r' && c != '\n' && c.is_ascii_graphic() || c == ' ' || c > '\x7f')
                .collect();
            let fname = fname.trim().to_string();
            if !fname.is_empty() && fname.len() > 1 {
                return Some(fname);
            }
        }
        // Only check the last few non-empty lines
        break;
    }
    None
}

/// Extract filename from "sz filename" echo in SSH data stream.
/// Handles: "sz file.txt\r\n", "$ sz  my file.tar\r\n", ANSI escape codes stripped.
pub(crate) fn extract_sz_filename(data: &str) -> Option<String> {
    // Strip ANSI escape codes for cleaner matching
    let clean: String = data.chars().filter(|&c| c != '\x1b').collect();

    // Find "sz " in the text (could be "$ sz file" or just "sz file")
    for line in clean.lines() {
        let trimmed = line.trim();
        // Match "sz filename" at end of line or after shell prompt
        if let Some(pos) = trimmed.rfind("sz ") {
            let after_sz = trimmed[pos + 3..].trim();
            // Take everything until ZMODEM garbage or end
            let fname = after_sz
                .split(|c: char| c == '*' || c == '\r' || c == '\n')
                .next()
                .unwrap_or("")
                .trim();
            if !fname.is_empty() && fname.len() > 1 {
                return Some(fname.to_string());
            }
        }
    }
    None
}

/// Reduce a remote-supplied name to a single, safe local file name.
///
/// `sz` filenames are scraped out of terminal output, i.e. out of bytes the
/// REMOTE host controls, and neither extractor rejects `/` or `..`. Path::join
/// honours `..` and lets an absolute name replace the base directory outright,
/// so an unsanitised name writes anywhere the user can write (~/.zshrc,
/// ~/.ssh/authorized_keys, ~/Library/LaunchAgents/...). Returns None when the
/// name cannot be reduced to something safe — the caller must then refuse.
pub(crate) fn safe_local_basename(name: &str) -> Option<String> {
    let base = std::path::Path::new(name).file_name()?.to_str()?;
    if base.is_empty() || base == "." || base == ".." {
        return None;
    }
    // `\` is not a path separator on unix, so Path::file_name() keeps it;
    // reject it explicitly so the same name is safe on every platform.
    if base
        .chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
    {
        return None;
    }
    Some(base.to_string())
}

#[derive(Debug, Clone)]
pub(crate) struct LocalFileEntry {
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    pub(crate) size: u64,
    pub(crate) path: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ContextMenu {
    pub(crate) conn_id: String,
    pub(crate) x: f32,
    pub(crate) y: f32,
}

/// Right-click menu of the remote file browser.
#[derive(Debug, Clone)]
pub(crate) struct RemoteFileMenu {
    pub(crate) session_id: String,
    /// Directory the browser is showing: where "New folder" lands, and what
    /// `entry` is relative to.
    pub(crate) dir: String,
    /// The row that was clicked. `None` for the list background and for
    /// "..", which only offer "New folder".
    pub(crate) entry: Option<FileEntry>,
    pub(crate) x: f32,
    pub(crate) y: f32,
}

/// What the SFTP name / mode dialog is asking for. `kind` is what the row
/// showed ([`FileEntry::kind`]): the dialog states it, and the SSH layer
/// refuses the operation if the entry is no longer that.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SftpInputKind {
    NewFolder,
    Rename { from: String, kind: EntryKind, confirmed: ConfirmedEntry },
    Chmod { name: String, kind: EntryKind, confirmed: ConfirmedEntry },
}

/// Small modal taking a folder name, a new name, or an octal mode.
#[derive(Debug, Clone)]
pub(crate) struct SftpInputDialog {
    pub(crate) session_id: String,
    pub(crate) dir: String,
    pub(crate) kind: SftpInputKind,
    pub(crate) value: String,
    /// i18n key of an inline validation message; the dialog stays open.
    pub(crate) error: Option<&'static str>,
}

/// A file or folder dropped on the window, waiting for the progress bar.
#[derive(Debug, Clone)]
pub(crate) struct DropJob {
    pub(crate) session_id: String,
    pub(crate) local: std::path::PathBuf,
    pub(crate) remote_dir: String,
}

/// Sessions with a fetch out on a blocking thread, one set per kind of fetch.
///
/// Monitor and ports fetches queue on a session's exec connection, which a
/// folder transfer holds for its whole length. Started on every tick
/// regardless, they piled up — a 30-minute transfer queued ~600 monitor
/// fetches, past tokio's 512 blocking threads, and from then on nothing that
/// needs one could start, new connections included. A session gets its next
/// fetch only once the last one is back; other sessions are not held up.
#[derive(Debug, Default)]
pub(crate) struct InFlight(HashSet<String>);

impl InFlight {
    /// Claim the fetch for `session_id`: false — skip this tick — while the
    /// previous one is still out, or when there is no session to ask.
    pub(crate) fn start(&mut self, session_id: &str) -> bool {
        !session_id.is_empty() && self.0.insert(session_id.to_string())
    }

    /// The fetch for `session_id` came back, answered or not.
    pub(crate) fn finish(&mut self, session_id: &str) {
        self.0.remove(session_id);
    }

    pub(crate) fn contains(&self, session_id: &str) -> bool {
        self.0.contains(session_id)
    }
}

/// Whether a monitor fetch failed because the SSH layer has parked the
/// session's exec connection: keyboard-interactive, where re-opening it is a
/// new challenge, so it waits for the user (`SshManager::resume_exec`). Told
/// by the SSH layer's own words for it.
pub(crate) fn exec_parked(error: &str) -> bool {
    error == i18n::t("exec.err.needs_reconnect")
}

/// A file listing for `session_id` failed. A parked exec connection is not an
/// error to put up each time a folder is asked for: the monitor and file
/// panels show why, with the one button that re-opens it — for a split
/// pane's session too, now that the panels follow the focused pane.
pub(crate) fn listing_failed(session_id: &str, error: String) -> Message {
    if exec_parked(&error) {
        Message::ExecParked(session_id.to_string())
    } else {
        Message::Error(error)
    }
}

/// A remote directory listing as the file browser shows it, with the
/// directory it was produced for. Every row action — open, download, edit,
/// rename, chmod, delete, the right-click menu — resolves the row's name
/// against `dir`, never against `current_dir`: that one names the next
/// directory as soon as it is asked for, before its listing arrives, and
/// even when it never does.
#[derive(Debug, Clone)]
pub(crate) struct Listing {
    /// The directory listed, as the SSH layer resolved it.
    pub(crate) dir: String,
    pub(crate) entries: Vec<FileEntry>,
    /// A later request that failed while this listing stayed on screen. The
    /// prompt's cwd sync does not ask for it again on every tick — which
    /// would put the same error up every 3 s.
    pub(crate) failed: Option<String>,
}

impl Listing {
    pub(crate) fn new(dir: String, entries: Vec<FileEntry>) -> Self {
        Listing { dir, entries, failed: None }
    }

    /// Remote path of the row called `name`.
    pub(crate) fn path_of(&self, name: &str) -> String {
        join_remote_path(&self.dir, name)
    }
}

/// Where the ".." row leads from the remote directory `dir`.
pub(crate) fn remote_parent(dir: &str) -> String {
    std::path::Path::new(dir)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string())
}

/// The listing of `requested` for `session_id` failed. The listing on screen
/// stays, and `current_dir` goes back to its directory — unless another one
/// has been asked for since — so a refresh, or the re-list after an
/// operation, lists what is shown; the failure is noted on the listing (see
/// [`cwd_sync_due`]).
pub(crate) fn note_listing_failed(
    current_dir: &mut HashMap<String, String>,
    listings: &mut HashMap<String, Listing>,
    session_id: &str,
    requested: &str,
) {
    let Some(listing) = listings.get_mut(session_id) else {
        return;
    };
    if current_dir.get(session_id).map(String::as_str) == Some(requested) {
        current_dir.insert(session_id.to_string(), listing.dir.clone());
        listing.failed = Some(requested.to_string());
    }
}

/// Whether the file browser should follow the shell to `cwd`, the directory
/// its prompt shows: when the prompt shows a different directory than the
/// one last followed, unless listing `cwd` has just failed.
pub(crate) fn cwd_sync_due(last_followed: Option<&str>, listing: Option<&Listing>, cwd: &str) -> bool {
    last_followed != Some(cwd) && listing.is_none_or(|l| l.failed.as_deref() != Some(cwd))
}

/// The prompt of `session_id` shows `cwd`: follow the shell there if it has
/// moved since the browser last followed it. True when a listing of `cwd`
/// should be asked for; `current_dir` then says `cwd`.
///
/// Compared with what the prompt showed last time, never with the directory
/// the browser is in. The listing resolves `~` to the login directory and
/// records that, so comparing the prompt's `~` with it never settled: the
/// browser re-listed on every monitor tick, and pulled the user back from
/// any folder they had opened by hand.
pub(crate) fn follow_prompt_cwd(
    prompt_cwd: &mut HashMap<String, String>,
    current_dir: &mut HashMap<String, String>,
    listings: &HashMap<String, Listing>,
    session_id: &str,
    cwd: &str,
) -> bool {
    let last = prompt_cwd.get(session_id).map(String::as_str);
    if !cwd_sync_due(last, listings.get(session_id), cwd) {
        return false;
    }
    prompt_cwd.insert(session_id.to_string(), cwd.to_string());
    current_dir.insert(session_id.to_string(), cwd.to_string());
    true
}

/// List local directory entries.
pub(crate) fn list_local_dir(path: &str) -> Vec<LocalFileEntry> {
    let mut entries = Vec::new();
    let dir = std::path::Path::new(path);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            entries.push(LocalFileEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                is_dir,
                size,
                path: entry.path().to_string_lossy().to_string(),
            });
        }
    }
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    entries
}

/// What the SFTP transfer loops return once the progress bar's Cancel has set
/// `finished` (ssh/mod.rs). A cancel is not a failure to report.
pub(crate) const TRANSFER_CANCELLED: &str = "Transfer cancelled";

/// A file or folder name exactly as the user typed it; `None` unless it is a
/// single path component. The server would resolve `a/b` or `..` somewhere
/// other than the folder on screen, so those are refused, not guessed at.
/// Not trimmed: the rename dialog opens on the name exactly, and "report "
/// submitted as it stands is that file's own name, not "report". A name of
/// nothing but spaces is refused.
pub(crate) fn valid_remote_name(input: &str) -> Option<String> {
    let name = input;
    if name.trim().is_empty() || name == "." || name == ".." {
        return None;
    }
    if name.chars().any(|c| c == '/' || c == '\0' || c.is_control()) {
        return None;
    }
    Some(name.to_string())
}

/// What the rename dialog's `value` asks of the row called `from`:
/// `Ok(None)` when the name is unchanged — a no-op, whatever the name holds —
/// `Ok(Some(name))` for a new name, `Err(())` for one that is not valid.
pub(crate) fn rename_target(from: &str, value: &str) -> Result<Option<String>, ()> {
    if value == from {
        return Ok(None);
    }
    valid_remote_name(value).map(Some).ok_or(())
}

/// `dir/name` for a remote POSIX path, without doubling the root's slash.
pub(crate) fn join_remote_path(dir: &str, name: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), name)
}

/// Permission bits the user typed ("755", "0644", "4755"); `None` for
/// anything but one to four octal digits.
pub(crate) fn parse_octal_mode(input: &str) -> Option<u32> {
    let s = input.trim();
    if s.is_empty() || s.len() > 4 || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    u32::from_str_radix(s, 8).ok()
}

/// Permission bits of an `ls -l` mode string ("drwxr-sr-x", "-rwsr-xr-T"),
/// set-id and sticky included, to prefill the chmod dialog. `None` when the
/// string does not look like one.
pub(crate) fn mode_from_permissions(perms: &str) -> Option<u32> {
    let p: Vec<char> = perms.chars().collect();
    if p.len() < 10 {
        return None;
    }
    let mut mode = 0u32;
    for (i, shift, special) in [(1usize, 6u32, 0o4000u32), (4, 3, 0o2000), (7, 0, 0o1000)] {
        match p[i] {
            'r' => mode |= 4 << shift,
            '-' => {}
            _ => return None,
        }
        match p[i + 1] {
            'w' => mode |= 2 << shift,
            '-' => {}
            _ => return None,
        }
        match p[i + 2] {
            'x' => mode |= 1 << shift,
            's' | 't' => mode |= (1 << shift) | special,
            'S' | 'T' => mode |= special,
            '-' => {}
            _ => return None,
        }
    }
    Some(mode)
}

/// Run one mutating SFTP call off the UI thread; `SftpOpDone` then re-lists
/// the directory.
pub(crate) fn sftp_op_task<F>(ssh: Arc<SshManager>, session_id: String, dir: String, op: F) -> Task<Message>
where
    F: FnOnce(&SshManager, &str) -> Result<(), String> + Send + 'static,
{
    Task::perform(
        async move {
            let sid = session_id.clone();
            let result = tokio::task::spawn_blocking(move || op(&ssh, &sid))
                .await
                .unwrap_or_else(|e| Err(format!("Task: {}", e)));
            (session_id, dir, result)
        },
        |(session_id, dir, result)| Message::SftpOpDone(session_id, dir, result),
    )
}

// ---- the single progress bar ----------------------------------------------
//
// Every transfer shows on one bar, and its Cancel reaches whatever is on it.
// A transfer claims the bar only once its path is picked — a cancelled
// picker must not leave a bar behind that no transfer will ever finish — and
// only while no other transfer holds it. Its end takes the bar down only if
// it is still its own: after a Cancel another transfer may already hold it.

/// Whether the bar is taken: an upload job is running (a cancelled one keeps
/// it until its thread lets go), or a transfer on it has not finished.
pub(crate) fn bar_busy(bar: Option<&Arc<TransferProgress>>, upload_job_running: bool) -> bool {
    upload_job_running || bar.is_some_and(|p| !p.is_finished())
}

/// Put a fresh progress on the bar for a transfer about to start, and hand
/// it back — or `None`, leaving the bar alone, while it is [`bar_busy`].
pub(crate) fn claim_bar(
    bar: &mut Option<Arc<TransferProgress>>,
    upload_job_running: bool,
) -> Option<Arc<TransferProgress>> {
    if bar_busy(bar.as_ref(), upload_job_running) {
        return None;
    }
    let progress = Arc::new(TransferProgress::new());
    *bar = Some(progress.clone());
    Some(progress)
}

/// A transfer ended: take its progress off the bar, if the bar still shows
/// it. Anything else there belongs to a transfer that is still running.
pub(crate) fn release_bar(bar: &mut Option<Arc<TransferProgress>>, ended: &Arc<TransferProgress>) {
    if bar.as_ref().is_some_and(|p| Arc::ptr_eq(p, ended)) {
        *bar = None;
    }
}

/// How a transfer or an SFTP operation ended, as the user hears of it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OpEnd {
    /// Done, or cancelled from the progress bar: nothing to say.
    Quiet,
    /// Done, with entries left out (`is_skipped_report`): said, but as the
    /// completion it is, not as a failure.
    Skipped(String),
    Failed(String),
}

pub(crate) fn op_end(result: Result<(), String>) -> OpEnd {
    match result {
        Ok(()) => OpEnd::Quiet,
        Err(e) if e == TRANSFER_CANCELLED => OpEnd::Quiet,
        Err(e) if is_skipped_report(&e) => OpEnd::Skipped(e),
        Err(e) => OpEnd::Failed(e),
    }
}

/// Whether `message` is ssh/mod.rs's "N item(s) skipped" report: what a
/// recursive download or delete returns once everything else is done. Told
/// apart by its text, like `TRANSFER_CANCELLED`: the template in the current
/// language, with a number for `{count}`. Should the language change while
/// the operation runs, the report still goes up — as a failure.
pub(crate) fn is_skipped_report(message: &str) -> bool {
    let Some((head, tail)) = i18n::t("sftp.err.skipped_names").split_once("{count}") else {
        return false;
    };
    message
        .strip_prefix(head)
        .and_then(|rest| rest.strip_suffix(tail))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A transfer's or an SFTP operation's end, on the error dialog (see
/// [`OpEnd`]). True for a failure.
pub(crate) fn report_transfer_error(state: &mut NeoShell, result: Result<(), String>) -> bool {
    match op_end(result) {
        OpEnd::Quiet => false,
        OpEnd::Skipped(note) => {
            state.show_notice("notice.skipped_title", note);
            false
        }
        OpEnd::Failed(e) => {
            state.error_message = e;
            state.show_error_dialog = true;
            true
        }
    }
}

/// Start one upload — a file, or a whole folder through the recursive
/// variant — into `remote_dir`, on the single progress bar. Ends in
/// `UploadFinished`, which starts the next queued drop. Callers have made
/// sure the bar is free.
pub(crate) fn start_upload(
    state: &mut NeoShell,
    session_id: String,
    local: std::path::PathBuf,
    remote_dir: String,
) -> Task<Message> {
    let progress = Arc::new(TransferProgress::new());
    // A filesystem root has no name to give the remote copy. Its progress
    // never reaches the bar, so the end below takes nothing down.
    let Some(name) = local.file_name().map(|n| n.to_string_lossy().to_string()) else {
        let path = local.display().to_string();
        return Task::done(Message::UploadFinished(
            session_id,
            progress,
            Err(i18n::tf("transfer.bad_local", &[("path", &path)])),
        ));
    };
    let remote = join_remote_path(&remote_dir, &name);
    *progress.filename.lock() = name;
    state.transfer_progress = Some(progress.clone());
    state.upload_job_running = true;
    let ssh = state.ssh_manager.clone();
    let is_dir = local.is_dir();
    let local = local.to_string_lossy().to_string();
    Task::perform(
        async move {
            let sid = session_id.clone();
            let bar = progress.clone();
            let result = tokio::task::spawn_blocking(move || {
                if is_dir {
                    ssh.upload_dir_with_progress(&sid, &local, &remote, progress)
                } else {
                    ssh.upload_file_with_progress(&sid, &local, &remote, progress)
                }
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task: {}", e)));
            (session_id, bar, result)
        },
        |(session_id, bar, result)| Message::UploadFinished(session_id, bar, result),
    )
}

/// Start the next queued drop, unless a transfer already holds the bar (its
/// own `UploadFinished` will call back here).
pub(crate) fn start_next_drop(state: &mut NeoShell) -> Task<Message> {
    if state.transfer_busy() {
        return Task::none();
    }
    match state.drop_queue.pop_front() {
        Some(job) => start_upload(state, job.session_id, job.local, job.remote_dir),
        None => Task::none(),
    }
}

/// Where the download pickers open: Downloads, else Desktop, else home.
pub(crate) fn default_download_dir() -> std::path::PathBuf {
    dirs::download_dir()
        .or_else(dirs::desktop_dir)
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default())
}

// ---- Message handlers moved out of handle_message ----

/// `Message::ChangeDir`, moved out of `handle_message`.
pub(crate) fn on_change_dir(state: &mut NeoShell, sid: String, path: String) -> Task<Message> {
    let ssh = state.ssh_manager.clone();
    let sid_for_state = sid.clone();
    let sid_for_async = sid.clone();
    let path_async = path.clone();
    state.current_dir.insert(sid_for_state, path.clone());
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || ssh.list_files(&sid_for_async, &path_async))
                .await.map_err(|e| format!("{}", e))?
        },
        move |result: Result<(String, Vec<FileEntry>), String>| match result {
            Ok((real_path, entries)) => Message::FilesReceived(sid.clone(), real_path, entries),
            Err(e) => Message::ListingFailed(sid.clone(), path.clone(), e),
        },
    )
}

/// `Message::UploadFile`, moved out of `handle_message`.
pub(crate) fn on_upload_file(state: &mut NeoShell) -> Task<Message> {
    let Some(sid) = state
        .active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.focused_session().to_string())
        .filter(|s| !s.is_empty())
    else {
        return Task::none();
    };
    // Before the picker, not after the user has chosen a file.
    if state.transfer_refused_busy() {
        return Task::none();
    }
    let dir = state.browser_dir(&sid).unwrap_or_else(|| "~".to_string());
    // The bar is claimed in `UploadPicked`, once there is a file to
    // send: a cancelled picker leaves nothing behind.
    Task::perform(
        async move {
            let file = rfd::AsyncFileDialog::new()
                .set_title(i18n::t("filedialog.upload"))
                .set_directory(default_download_dir())
                .pick_file()
                .await
                .map(|f| f.path().to_path_buf());
            (sid, dir, file)
        },
        |(sid, dir, file)| Message::UploadPicked(sid, dir, file),
    )
}

/// `Message::DownloadFile`, moved out of `handle_message`.
pub(crate) fn on_download_file(state: &mut NeoShell, sid: String, remote_path: String) -> Task<Message> {
    if state.transfer_refused_busy() {
        return Task::none();
    }
    // Only prefills the save dialog (the user still picks the path),
    // but the name comes from the remote listing — sanitise it anyway.
    let filename = safe_local_basename(&remote_path).unwrap_or_else(|| "file".to_string());
    Task::perform(
        async move {
            let local = rfd::AsyncFileDialog::new()
                .set_title(i18n::t("filedialog.save"))
                .set_file_name(&filename)
                .set_directory(default_download_dir())
                .save_file()
                .await
                .map(|f| f.path().to_path_buf());
            (sid, remote_path, local)
        },
        |(sid, remote_path, local)| Message::DownloadPicked(sid, remote_path, local),
    )
}

/// `Message::DownloadPicked`, moved out of `handle_message`.
pub(crate) fn on_download_picked(state: &mut NeoShell, sid: String, remote_path: String, local: Option<std::path::PathBuf>) -> Task<Message> {
    let Some(local) = local.filter(|p| !p.as_os_str().is_empty()) else {
        return Task::none();
    };
    // Another transfer may have started while the dialog was open.
    let Some(progress) = state.claim_transfer_bar() else {
        return Task::none();
    };
    let ssh = state.ssh_manager.clone();
    let local = local.to_string_lossy().to_string();
    Task::perform(
        async move {
            let bar = progress.clone();
            let result = tokio::task::spawn_blocking(move || {
                ssh.download_file_with_progress(&sid, &remote_path, &local, progress)
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task: {}", e)));
            (bar, result)
        },
        |(bar, result)| Message::DownloadDone(bar, result),
    )
}

/// `Message::SaveEditor`, moved out of `handle_message`.
pub(crate) fn on_save_editor(state: &mut NeoShell) -> Task<Message> {
    if let (Some(sid), Some(path)) = (state.editor_session_id.clone(), state.editor_file_path.clone()) {
        let ssh = state.ssh_manager.clone();
        let content = state.editor_content.text();
        Task::perform(
            async move {
                ssh.write_file_content(&sid, &path, &content)?;
                Ok(())
            },
            |result: Result<(), String>| match result {
                Ok(()) => Message::EditorSaved,
                Err(e) => Message::Error(e),
            },
        )
    } else {
        Task::none()
    }
}

/// `Message::RzDetected`, moved out of `handle_message`.
pub(crate) fn on_rz_detected(state: &mut NeoShell, sid: String) -> Task<Message> {
    if state.transfer_refused_busy() {
        return Task::none();
    }
    let current_dir = state.current_dir.get(&sid).cloned()
        .unwrap_or_else(|| "~".to_string());
    // The bar is claimed in `RzPicked`, once a file is chosen.
    Task::perform(
        async move {
            let file = rfd::AsyncFileDialog::new()
                .set_title(i18n::t("filedialog.rz_upload"))
                .set_directory(default_download_dir())
                .pick_file()
                .await
                .map(|f| f.path().to_path_buf());
            (sid, current_dir, file)
        },
        |(sid, dir, file)| Message::RzPicked(sid, dir, file),
    )
}

/// `Message::RzPicked`, moved out of `handle_message`.
pub(crate) fn on_rz_picked(state: &mut NeoShell, sid: String, dir: String, file: Option<std::path::PathBuf>) -> Task<Message> {
    let Some((local, name)) = file.and_then(|f| {
        let name = f.file_name()?.to_string_lossy().to_string();
        Some((f, name))
    }) else {
        return Task::none();
    };
    let Some(progress) = state.claim_transfer_bar() else {
        return Task::none();
    };
    let remote_path = join_remote_path(&dir, &name);
    let local_path = local.to_string_lossy().to_string();
    let ssh = state.ssh_manager.clone();
    Task::perform(
        async move {
            let sid2 = sid.clone();
            let bar = progress.clone();
            let result = tokio::task::spawn_blocking(move || {
                ssh.upload_file_with_progress(&sid2, &local_path, &remote_path, progress)
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task: {}", e)));
            (sid, bar, result)
        },
        |(sid, bar, result)| Message::RzUploadDone(sid, bar, result),
    )
}

/// `Message::SzDetected`, moved out of `handle_message`.
pub(crate) fn on_sz_detected(state: &mut NeoShell, sid: String) -> Task<Message> {
    // Prevent duplicate: skip if already downloading
    if state.transfer_progress.is_some() {
        return Task::none();
    }

    let filename = state.sz_filename.remove(&sid);
    let current_dir = state.current_dir.get(&sid).cloned().unwrap_or("~".to_string());

    if let Some(fname) = filename {
        // The name was scraped from terminal output — the remote host
        // controls it. Reduce it to a bare file name before it touches
        // the local filesystem; refuse rather than guess.
        let base = match safe_local_basename(&fname) {
            Some(b) => b,
            None => {
                if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
                    // `{:?}` escapes what the server put in the name:
                    // it reaches the terminal as text, never as a
                    // control sequence.
                    let notice = i18n::tf(
                        "term.sz_refused",
                        &[("name", &format!("{:?}", fname))],
                    );
                    tab.terminal.lock().write(
                        format!("\r\n\x1b[31m{}\x1b[0m\r\n", notice).as_bytes(),
                    );
                }
                return Task::none();
            }
        };

        let Some(progress) = state.claim_transfer_bar() else {
            return Task::none();
        };
        let ssh = state.ssh_manager.clone();

        // Download directly to ~/Downloads
        let default_dir = dirs::download_dir()
            .or_else(|| dirs::desktop_dir())
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default());
        let local_path = default_dir.join(&base).to_string_lossy().to_string();

        if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
            tab.terminal.lock().write(
                format!("\r\n\x1b[32m[NeoShell] sz: {} → {}\x1b[0m\r\n", fname, local_path).as_bytes(),
            );
        }

        let bar = progress.clone();
        Task::perform(
            async move {
                let result = tokio::task::spawn_blocking(move || {
                    // Resolve absolute path on remote (shell CWD may differ from file browser)
                    let remote_path = if fname.starts_with('/') {
                        fname.clone()
                    } else {
                        let pwd = ssh.exec_command(&sid, "pwd")
                            .unwrap_or_else(|_| "~".to_string());
                        let cwd = pwd.trim();
                        format!("{}/{}", cwd.trim_end_matches('/'), fname)
                    };

                    ssh.download_file_with_progress(&sid, &remote_path, &local_path, progress)
                })
                .await
                .unwrap_or_else(|e| Err(format!("{}", e)));
                (bar, result)
            },
            |(bar, result)| Message::DownloadDone(bar, result),
        )
    } else {
        // No filename captured — refresh file browser
        if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
            tab.terminal.lock().write(
                b"\r\n\x1b[33m[NeoShell] sz: no filename captured. Use file browser to download.\x1b[0m\r\n",
            );
        }
        Task::done(Message::ChangeDir(sid, current_dir))
    }
}

/// `Message::UploadLocalFile`, moved out of `handle_message`.
pub(crate) fn on_upload_local_file(state: &mut NeoShell) -> Task<Message> {
    // Upload selected local file to remote current dir
    if let Some(local_file) = state.selected_local_file.clone() {
        if let Some(idx) = state.active_tab {
            if let Some(tab) = state.tabs.get(idx) {
                let sid = tab.focused_session().to_string();
                if state.transfer_refused_busy() {
                    return Task::none();
                }
                let remote_dir = state.browser_dir(&sid).unwrap_or_else(|| "~".into());
                state.selected_local_file = None;
                // The shared upload path: one bar, queued drops wait
                // for it, and the listing refreshes when it ends.
                let local = std::path::PathBuf::from(local_file);
                return start_upload(state, sid, local, remote_dir);
            }
        }
    }
    Task::none()
}

/// `Message::SftpRename`, moved out of `handle_message`.
pub(crate) fn on_sftp_rename(state: &mut NeoShell) -> Task<Message> {
    let Some(RemoteFileMenu { session_id, dir, entry: Some(entry), .. }) =
        state.remote_menu.take()
    else {
        return Task::none();
    };
    state.sftp_input = Some(SftpInputDialog {
        session_id,
        dir,
        value: entry.name.clone(),
        kind: SftpInputKind::Rename {
            confirmed: ConfirmedEntry::from(&entry),
            kind: entry.kind(),
            from: entry.name,
        },
        error: None,
    });
    Task::batch([
        state.focus.focus(text_input::Id::new(SFTP_INPUT_ID)),
        text_input::select_all(text_input::Id::new(SFTP_INPUT_ID)),
    ])
}

/// `Message::SftpChmod`, moved out of `handle_message`.
pub(crate) fn on_sftp_chmod(state: &mut NeoShell) -> Task<Message> {
    let Some(RemoteFileMenu { session_id, dir, entry: Some(entry), .. }) =
        state.remote_menu.take()
    else {
        return Task::none();
    };
    let value = mode_from_permissions(&entry.permissions)
        .map(|m| format!("{:o}", m))
        .unwrap_or_default();
    state.sftp_input = Some(SftpInputDialog {
        session_id,
        dir,
        kind: SftpInputKind::Chmod {
            confirmed: ConfirmedEntry::from(&entry),
            kind: entry.kind(),
            name: entry.name,
        },
        value,
        error: None,
    });
    Task::batch([
        state.focus.focus(text_input::Id::new(SFTP_INPUT_ID)),
        text_input::select_all(text_input::Id::new(SFTP_INPUT_ID)),
    ])
}

/// `Message::SftpDelete`, moved out of `handle_message`.
pub(crate) fn on_sftp_delete(state: &mut NeoShell) -> Task<Message> {
    let Some(RemoteFileMenu { session_id, dir, entry: Some(entry), .. }) =
        state.remote_menu.take()
    else {
        return Task::none();
    };
    // Destructive: held for the confirmation, which quotes the exact
    // name and says what it is — the kind the row showed, which is
    // also what the SSH layer checks the entry against.
    let path = join_remote_path(&dir, &entry.name);
    state.confirm_action = Some(ConfirmAction::SftpDelete {
        session_id,
        dir,
        path,
        confirmed: ConfirmedEntry::from(&entry),
        kind: entry.kind(),
        name: entry.name,
    });
    Task::none()
}

/// `Message::SftpInputSubmit`, moved out of `handle_message`.
pub(crate) fn on_sftp_input_submit(state: &mut NeoShell) -> Task<Message> {
    let Some(dialog) = state.sftp_input.clone() else {
        return Task::none();
    };
    let SftpInputDialog { session_id, dir, kind, value, .. } = dialog;
    let ssh = state.ssh_manager.clone();
    match kind {
        SftpInputKind::NewFolder => {
            let Some(name) = valid_remote_name(&value) else {
                if let Some(d) = state.sftp_input.as_mut() {
                    d.error = Some("sftp.err_name");
                }
                return Task::none();
            };
            state.sftp_input = None;
            let path = join_remote_path(&dir, &name);
            sftp_op_task(ssh, session_id, dir, move |ssh, sid| ssh.sftp_mkdir(sid, &path))
        }
        SftpInputKind::Rename { from, confirmed, .. } => {
            let target = rename_target(&from, &value);
            let Ok(target) = target else {
                if let Some(d) = state.sftp_input.as_mut() {
                    d.error = Some("sftp.err_name");
                }
                return Task::none();
            };
            state.sftp_input = None;
            // Submitted as it opened: nothing to rename.
            let Some(name) = target else {
                return Task::none();
            };
            let (src, dst) = (join_remote_path(&dir, &from), join_remote_path(&dir, &name));
            sftp_op_task(ssh, session_id, dir, move |ssh, sid| {
                ssh.sftp_rename_confirmed(sid, &src, &dst, confirmed)
            })
        }
        SftpInputKind::Chmod { name, kind, confirmed } => {
            let Some(mode) = parse_octal_mode(&value) else {
                if let Some(d) = state.sftp_input.as_mut() {
                    d.error = Some("sftp.err_mode");
                }
                return Task::none();
            };
            state.sftp_input = None;
            // Destructive too: confirmed with the exact name, its
            // kind, the path and the mode.
            let path = join_remote_path(&dir, &name);
            state.confirm_action =
                Some(ConfirmAction::SftpChmod { session_id, dir, path, name, kind, confirmed, mode });
            Task::none()
        }
    }
}

/// `Message::UploadDir`, moved out of `handle_message`.
pub(crate) fn on_upload_dir(state: &mut NeoShell) -> Task<Message> {
    let Some(session_id) = state
        .active_tab
        .and_then(|i| state.tabs.get(i))
        .map(|t| t.focused_session().to_string())
        .filter(|s| !s.is_empty())
    else {
        return Task::none();
    };
    if state.transfer_refused_busy() {
        return Task::none();
    }
    let dir = state.browser_dir(&session_id).unwrap_or_else(|| "~".to_string());
    Task::perform(
        async move {
            let folder = rfd::AsyncFileDialog::new()
                .set_title(i18n::t("filedialog.upload_dir"))
                .set_directory(dirs::home_dir().unwrap_or_default())
                .pick_folder()
                .await
                .map(|f| f.path().to_path_buf());
            (session_id, dir, folder)
        },
        |(session_id, dir, folder)| Message::UploadPicked(session_id, dir, folder),
    )
}

/// `Message::DownloadDir`, moved out of `handle_message`.
pub(crate) fn on_download_dir(state: &mut NeoShell, session_id: String, remote: String) -> Task<Message> {
    if state.transfer_refused_busy() {
        return Task::none();
    }
    Task::perform(
        async move {
            let parent = rfd::AsyncFileDialog::new()
                .set_title(i18n::t("filedialog.download_dir"))
                .set_directory(default_download_dir())
                .pick_folder()
                .await
                .map(|f| f.path().to_path_buf());
            (session_id, remote, parent)
        },
        |(session_id, remote, parent)| {
            Message::DownloadDirPicked(session_id, remote, parent)
        },
    )
}

/// `Message::DownloadDirPicked`, moved out of `handle_message`.
pub(crate) fn on_download_dir_picked(state: &mut NeoShell, session_id: String, remote: String, parent: Option<std::path::PathBuf>) -> Task<Message> {
    let Some(parent) = parent else {
        return Task::none();
    };
    let Some(progress) = state.claim_transfer_bar() else {
        return Task::none();
    };
    // The folder name comes from the remote listing: it must not get
    // to choose where on the local disk the tree lands.
    let name = safe_local_basename(&remote).unwrap_or_else(|| "download".to_string());
    let local = parent.join(name).to_string_lossy().to_string();
    let ssh = state.ssh_manager.clone();
    Task::perform(
        async move {
            let bar = progress.clone();
            let result = tokio::task::spawn_blocking(move || {
                ssh.download_dir_with_progress(&session_id, &remote, &local, progress)
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task: {}", e)));
            (bar, result)
        },
        |(bar, result)| Message::DownloadDirDone(bar, result),
    )
}

/// `Message::FileDropped`, moved out of `handle_message`.
pub(crate) fn on_file_dropped(state: &mut NeoShell, path: std::path::PathBuf) -> Task<Message> {
    // Main screen, nothing modal in the way: a drop under the
    // connection form must not start an upload behind it.
    if state.screen != Screen::Main || state.any_overlay_open() {
        return Task::none();
    }
    let Some((session_id, remote_dir)) = state.drop_target() else {
        state.error_message = i18n::t("drop.no_target").to_string();
        state.show_error_dialog = true;
        return Task::none();
    };
    // Someone else's transfer holds the bar and would not start the
    // queue when it ends.
    if state.transfer_busy() && !state.upload_job_running {
        state.error_message = i18n::t("transfer.busy").to_string();
        state.show_error_dialog = true;
        return Task::none();
    }
    log::info!("drop: {} -> {}", path.display(), remote_dir);
    state.drop_queue.push_back(DropJob {
        session_id,
        local: path,
        remote_dir,
    });
    start_next_drop(state)
}

/// `Message::FileClicked`, moved out of `handle_message`.
pub(crate) fn on_file_clicked(sid: String, dir: String, entry: FileEntry) -> Task<Message> {
    // `dir` is the listing the row was on, which the view handed over
    // with it — not `current_dir`, which may name another directory
    // by now.
    if entry.is_dir || entry.name == ".." {
        let new_path = if entry.name == ".." {
            remote_parent(&dir)
        } else {
            join_remote_path(&dir, &entry.name)
        };
        return Task::done(Message::ChangeDir(sid, new_path));
    }
    Task::none()
}

/// `Message::OpenEditor`, moved out of `handle_message`.
pub(crate) fn on_open_editor(state: &mut NeoShell, sid: String, path: String) -> Task<Message> {
    let ssh = state.ssh_manager.clone();
    let sid2 = sid.clone();
    let path2 = path.clone();
    Task::perform(
        async move {
            let content = ssh.read_file_content(&sid2, &path2)?;
            Ok((sid2, path2, content))
        },
        |result: Result<(String, String, String), String>| match result {
            Ok((sid, path, content)) => Message::EditorContentLoaded(sid, path, content),
            Err(e) => Message::Error(e),
        },
    )
}

/// `Message::EditorAction`, moved out of `handle_message`.
pub(crate) fn on_editor_action(state: &mut NeoShell, action: text_editor::Action) -> Task<Message> {
    let is_edit = action.is_edit();
    state.editor_content.perform(action);
    if is_edit {
        state.editor_dirty = true;
    }
    Task::none()
}

/// `Message::RzUploadDone`, moved out of `handle_message`.
pub(crate) fn on_rz_upload_done(state: &mut NeoShell, sid: String, bar: Arc<TransferProgress>, result: Result<(), String>) -> Task<Message> {
    release_bar(&mut state.transfer_progress, &bar);
    if result.is_err() {
        report_transfer_error(state, result);
        return Task::none();
    }
    if let Some(tab) = state.tabs.iter().find(|t| t.session_id == sid) {
        tab.terminal.lock().write(
            b"\r\n\x1b[32m[NeoShell] Upload complete.\x1b[0m\r\n",
        );
    }
    let path = state.current_dir.get(&sid).cloned()
        .unwrap_or_else(|| "~".to_string());
    Task::done(Message::ChangeDir(sid, path))
}

/// `Message::PathInputSubmit`, moved out of `handle_message`.
pub(crate) fn on_path_input_submit(state: &mut NeoShell) -> Task<Message> {
    if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            let sid = tab.focused_session().to_string();
            let path = state.path_input.clone();
            if !path.is_empty() {
                return Task::done(Message::ChangeDir(sid, path));
            }
        }
    }
    Task::none()
}

/// `Message::LocalFileClicked`, moved out of `handle_message`.
pub(crate) fn on_local_file_clicked(state: &mut NeoShell, path: String) -> Task<Message> {
    let p = std::path::Path::new(&path);
    if p.is_dir() {
        state.local_path = path;
        state.local_entries = list_local_dir(&state.local_path);
        state.selected_local_file = None;
    } else {
        state.selected_local_file = Some(path);
    }
    Task::none()
}

/// `Message::RemoteMenuOpen`, moved out of `handle_message`.
pub(crate) fn on_remote_menu_open(state: &mut NeoShell, session_id: String, dir: String, entry: Option<FileEntry>) -> Task<Message> {
    // ".." is navigation, not an entry that can be renamed or deleted.
    let entry = entry.filter(|e| e.name != ".." && e.name != ".");
    state.context_menu = None;
    state.remote_menu = Some(RemoteFileMenu {
        session_id,
        dir,
        entry,
        x: state.cursor_x,
        y: state.cursor_y,
    });
    Task::none()
}

/// `Message::SftpNewFolder`, moved out of `handle_message`.
pub(crate) fn on_sftp_new_folder(state: &mut NeoShell) -> Task<Message> {
    let Some(menu) = state.remote_menu.take() else {
        return Task::none();
    };
    state.sftp_input = Some(SftpInputDialog {
        session_id: menu.session_id,
        dir: menu.dir,
        kind: SftpInputKind::NewFolder,
        value: String::new(),
        error: None,
    });
    state.focus.focus(text_input::Id::new(SFTP_INPUT_ID))
}

/// `Message::SftpOpDone`, moved out of `handle_message`.
pub(crate) fn on_sftp_op_done(state: &mut NeoShell, session_id: String, dir: String, result: Result<(), String>) -> Task<Message> {
    // Set directly rather than through Message::Error, which would
    // also drop a transfer's progress bar and placeholder tabs. A
    // recursive delete that left names out still re-lists below.
    report_transfer_error(state, result);
    // Re-list whatever the browser shows for that session now.
    let path = state.current_dir.get(&session_id).cloned().unwrap_or(dir);
    Task::done(Message::ChangeDir(session_id, path))
}

/// `Message::UploadPicked`, moved out of `handle_message`.
pub(crate) fn on_upload_picked(state: &mut NeoShell, session_id: String, dir: String, picked: Option<std::path::PathBuf>) -> Task<Message> {
    let Some(local) = picked else {
        return Task::none();
    };
    // Another transfer may have started while the picker was open.
    if state.transfer_refused_busy() {
        return Task::none();
    }
    start_upload(state, session_id, local, dir)
}

/// `Message::UploadFinished`, moved out of `handle_message`.
pub(crate) fn on_upload_finished(state: &mut NeoShell, session_id: String, bar: Arc<TransferProgress>, result: Result<(), String>) -> Task<Message> {
    state.upload_job_running = false;
    release_bar(&mut state.transfer_progress, &bar);
    // A report of skipped entries is no failure: the drop carries on.
    if report_transfer_error(state, result) {
        // Stop the rest of a drop rather than pile errors up.
        state.drop_queue.clear();
    }
    let next = start_next_drop(state);
    // Show what arrived (a cancel can leave a partial tree) — but only
    // for a session the browser tracks; a split pane's has no listing.
    match state.current_dir.get(&session_id).cloned() {
        Some(path) => Task::batch([Task::done(Message::ChangeDir(session_id, path)), next]),
        None => next,
    }
}
