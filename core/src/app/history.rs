use super::*;

/// True when the remote echoed `cmd` back onto the screen.
///
/// `cmd_buffer` is assembled from LOCAL keystrokes, with no idea whether the
/// remote tty is echoing. `sudo`, `su`, `mysql -p` and gpg all turn echo off at
/// their prompts, so without this gate the password is stored verbatim in
/// `cmd_history`, rendered in plaintext by the history panel, and one click on
/// ReplayCommand re-sends it to a shell.
///
/// Deliberately fails closed: when the terminal is gone or the echo has not
/// landed yet, the line is simply not recorded.
pub(crate) fn command_was_echoed(state: &NeoShell, session_id: &str, cmd: &str) -> bool {
    let term = match state.find_terminal_for_session(session_id) {
        Some(t) => t,
        None => return false,
    };
    let grid = term.lock();
    if grid.cells.is_empty() {
        return false;
    }
    let row_text = |y: usize| -> String {
        grid.cells
            .get(y)
            .map(|r| r.iter().filter(|c| !c.wide_cont).map(|c| c.c).collect())
            .unwrap_or_default()
    };
    let y = grid.cursor_y.min(grid.cells.len() - 1);

    // Second gate, for the case where the secret coincidentally matches text
    // left on screen: an explicit no-echo prompt is never a command line.
    let prompt = row_text(y).to_lowercase();
    if prompt.contains("password")
        || prompt.contains("passphrase")
        || prompt.contains("\u{5bc6}\u{7801}")
        || prompt.contains("\u{53e3}\u{4ee4}")
    {
        return false;
    }

    // Match a prefix rather than the whole line: with echo ON the head has long
    // since been echoed even on a slow link, while with echo OFF not a single
    // character reaches the grid. Join the two rows above the cursor so a
    // command that wrapped at the right margin still matches.
    let prefix: String = cmd.chars().take(6).collect();
    let start = y.saturating_sub(2);
    let visible: String = (start..=y).map(row_text).collect();
    visible.contains(&prefix)
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// One submitted command line. Only lines that passed `command_was_echoed`
/// are ever built — that gate is what keeps a password typed at a no-echo
/// prompt out of the history panel and, now that it persists, out of
/// `history.enc` too.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CmdRecord {
    pub(crate) cmd: String,
    #[serde(default)]
    pub(crate) session_title: String,
    /// Host the line was typed on.
    #[serde(default)]
    pub(crate) host: String,
    /// Unix seconds. An `Instant` cannot outlive the process, which is why the
    /// history used to die with it.
    #[serde(default)]
    pub(crate) timestamp: u64,
}

/// Suggestions the quick-command dropdown shows at most.
pub(crate) const QUICK_CMD_SUGGESTIONS: usize = 5;
/// Most command lines kept, in memory and in `history.enc`.
pub(crate) const HISTORY_MAX: usize = 500;
/// Paced history writes go out at most this often. Lock, quit and clearing
/// write at once; this spaces out the ones in between, each of which ends in
/// two fsyncs (F_FULLFSYNC on macOS).
pub(crate) const HISTORY_FLUSH_INTERVAL: Duration = Duration::from_secs(60);
/// How often a dirty history asks `history_flush_due`. The check is cheap.
pub(crate) const HISTORY_FLUSH_TICK: Duration = Duration::from_secs(5);
/// Longest quit waits for history writes already on their way to disk. It
/// waits on the UI thread, with the window about to close.
pub(crate) const HISTORY_SETTLE_WAIT: Duration = Duration::from_secs(5);
/// Longest the unlock-time load waits for them. It waits on a blocking
/// thread, never in `update`, so it can outwait a slow disk; a write still
/// out after this long is stuck, and the user is told that this session's
/// commands will not be saved.
pub(crate) const HISTORY_LOAD_SETTLE_WAIT: Duration = Duration::from_secs(60);
/// A sealed history file larger than this is not one NeoShell wrote.
pub(crate) const SEALED_HISTORY_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// The newest `HISTORY_MAX` records of a cleartext `history.json`, the file
/// builds before the sealed history wrote. Missing, oversized or corrupt reads
/// as empty: losing the history beats refusing to unlock.
pub(crate) fn load_history_from(path: &std::path::Path) -> Vec<CmdRecord> {
    const MAX_BYTES: u64 = 4 * 1024 * 1024;
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() <= MAX_BYTES => {}
        Ok(meta) => {
            log::warn!("{} is {} bytes; not loading it", path.display(), meta.len());
            return Vec::new();
        }
        Err(_) => return Vec::new(),
    }
    let parsed = std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str::<Vec<CmdRecord>>(&s).map_err(|e| e.to_string()));
    let mut list = match parsed {
        Ok(list) => list,
        Err(e) => {
            log::warn!("command history {} unreadable: {}", path.display(), e);
            return Vec::new();
        }
    };
    if list.len() > HISTORY_MAX {
        list.drain(..list.len() - HISTORY_MAX);
    }
    list
}

/// Whether, and when, `cmd_history` reaches `history_file`. It sits beside
/// the list rather than around it, so the list's readers stay as they are.
#[derive(Debug, Default)]
pub(crate) struct HistorySync {
    /// `cmd_history` holds records the sealed file does not have yet.
    pub(crate) dirty: bool,
    /// The unlock-time load has read the sealed file, found none, or set an
    /// unreadable one aside. Nothing is written without it — a session that
    /// never saw the file would write its short list over the real one — and
    /// it is always false while the vault is locked.
    pub(crate) loaded: bool,
    /// When the last paced write went out.
    pub(crate) flushed_at: Option<std::time::Instant>,
    /// The unlock-time load out on a blocking thread, if any. Only this one
    /// lands (`land_history_load`): a lock drops it, a later unlock replaces
    /// it.
    pub(crate) pending_load: Option<PendingLoad>,
    /// Numbers the unlock-time loads.
    pub(crate) load_seq: u64,
}

/// An unlock-time load on its way back to the UI thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingLoad {
    pub(crate) seq: u64,
    /// The history was cleared while the load ran: what it read predates the
    /// clear and must not come back.
    pub(crate) cleared: bool,
}

/// Is a paced history write due at `now`? At most one per
/// `HISTORY_FLUSH_INTERVAL`, and never before the unlock-time load.
pub(crate) fn history_flush_due(sync: &HistorySync, now: std::time::Instant) -> bool {
    sync.dirty
        && sync.loaded
        && sync
            .flushed_at
            .is_none_or(|t| now.saturating_duration_since(t) >= HISTORY_FLUSH_INTERVAL)
}

/// May a write go out at all? Not before the unlock-time load, which is what
/// keeps a session from writing its short list over records it never saw —
/// unless the write is a clear, which is meant to replace whatever is there.
pub(crate) fn history_write_allowed(sync: &HistorySync, scrub: bool) -> bool {
    sync.loaded || scrub
}

/// The command history on disk. `history.enc` holds one `EncryptedBlob`: the
/// JSON record list sealed under the vault DEK, so it is exactly as readable
/// as the vault. `history.json` is the cleartext file earlier builds wrote;
/// the first unlock imports it, and the write that seals its records scrubs
/// and deletes it.
///
/// Records are sealed on the UI thread, where the key is and where sealing a
/// few hundred lines costs next to nothing. The write, which fsyncs twice,
/// runs on a blocking thread and only ever holds ciphertext.
pub(crate) struct HistoryFile {
    pub(crate) sealed: std::path::PathBuf,
    pub(crate) legacy: std::path::PathBuf,
    /// Numbers snapshots in the order they are sealed.
    pub(crate) next_seq: AtomicU64,
    /// Number of the newest snapshot on disk. Held for the whole of a write:
    /// writes never overlap (`write_private` stages every writer in the same
    /// `<name>.tmp<pid>`), and a snapshot that runs late is dropped instead of
    /// landing over a newer one.
    pub(crate) written: parking_lot::Mutex<u64>,
    /// Snapshots sealed but not yet written or dropped.
    pub(crate) pending: parking_lot::Mutex<usize>,
    pub(crate) settled: parking_lot::Condvar,
    /// Counts vault locks. Bumped before the key goes (`lock_history`), so a
    /// load running off the UI thread can tell a sealed file it could not
    /// open for want of the key from a damaged one.
    pub(crate) locks: AtomicU64,
}

/// A sealed snapshot of the history, on its way to disk.
pub(crate) struct HistoryWrite {
    pub(crate) seq: u64,
    pub(crate) blob: crate::storage::EncryptedBlob,
    /// Overwrite the bytes being replaced as well (clearing).
    pub(crate) scrub: bool,
    /// Scrub and delete the cleartext `history.json` once this snapshot, or
    /// a newer one, is on disk.
    pub(crate) retire_legacy: bool,
    /// Counts the snapshot as pending until it is dropped, run or not.
    pub(crate) pending: PendingWrite,
}

pub(crate) struct PendingWrite(Arc<HistoryFile>);

impl Drop for PendingWrite {
    fn drop(&mut self) {
        let mut pending = self.0.pending.lock();
        *pending = pending.saturating_sub(1);
        self.0.settled.notify_all();
    }
}

impl HistoryWrite {
    /// Put the snapshot on disk. Blocking: two fsyncs.
    pub(crate) fn run(self) -> std::io::Result<()> {
        let file = self.pending.0.clone();
        file.write(self)
    }
}

/// What an unlock found on disk. It comes back from the blocking thread in a
/// `Message`, hence `Clone`; its `Debug` shows no command line.
#[derive(Clone, Default)]
pub(crate) struct HistoryLoad {
    pub(crate) records: Vec<CmdRecord>,
    /// Safe to write the sealed file this session; see `HistorySync::loaded`.
    pub(crate) writable: bool,
    /// Not writable because a write sent off before the unlock was still out
    /// after `HISTORY_LOAD_SETTLE_WAIT`.
    pub(crate) unsettled: bool,
    /// A cleartext `history.json` was merged in, for the first write to
    /// retire.
    pub(crate) legacy_found: bool,
}

impl std::fmt::Debug for HistoryLoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryLoad")
            .field("records", &self.records.len())
            .field("writable", &self.writable)
            .field("unsettled", &self.unsettled)
            .field("legacy_found", &self.legacy_found)
            .finish()
    }
}

impl HistoryFile {
    pub(crate) fn at(dir: &std::path::Path) -> Self {
        HistoryFile {
            sealed: dir.join("history.enc"),
            legacy: dir.join("history.json"),
            next_seq: AtomicU64::new(0),
            written: parking_lot::Mutex::new(0),
            pending: parking_lot::Mutex::new(0),
            settled: parking_lot::Condvar::new(),
            locks: AtomicU64::new(0),
        }
    }

    pub(crate) fn in_data_dir() -> Self {
        Self::at(
            &dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("neoshell"),
        )
    }

    /// Seal the newest `HISTORY_MAX` of `records` for a later `run`. Fails
    /// while the vault is locked.
    pub(crate) fn snapshot(
        file: &Arc<HistoryFile>,
        store: &ConnectionStore,
        records: &[CmdRecord],
        scrub: bool,
        retire_legacy: bool,
    ) -> Result<HistoryWrite, String> {
        let start = records.len().saturating_sub(HISTORY_MAX);
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(&records[start..]).map_err(|e| e.to_string())?,
        );
        let blob = store.seal(&json)?;
        *file.pending.lock() += 1;
        Ok(HistoryWrite {
            seq: file.next_seq.fetch_add(1, Ordering::Relaxed) + 1,
            blob,
            scrub,
            retire_legacy,
            pending: PendingWrite(file.clone()),
        })
    }

    pub(crate) fn write(&self, job: HistoryWrite) -> std::io::Result<()> {
        let mut written = self.written.lock();
        if job.seq > *written {
            let bytes = serde_json::to_vec(&job.blob).map_err(std::io::Error::other)?;
            if job.scrub {
                crate::storage::write_private_scrubbing(&self.sealed, &bytes)?;
            } else {
                crate::storage::write_private(&self.sealed, &bytes)?;
            }
            *written = job.seq;
        }
        // This snapshot or a newer one is on disk, and every snapshot sealed
        // after an import holds the imported records (or was cleared on
        // purpose): the cleartext copy has nothing left to give.
        if job.retire_legacy {
            retire_legacy_history(&self.legacy).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("sealed, but {} not removed: {}", self.legacy.display(), e),
                )
            })?;
        }
        Ok(())
    }

    /// Wait, at most `limit`, for every snapshot sealed so far to be written
    /// or dropped. `false` if some are still out.
    pub(crate) fn wait_settled(&self, limit: Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        let mut pending = self.pending.lock();
        while *pending > 0 {
            if self.settled.wait_until(&mut pending, deadline).timed_out() {
                return *pending == 0;
            }
        }
        true
    }

    /// The history of a vault that was just unlocked: the sealed records with
    /// a cleartext `history.json` merged in. Touches nothing while locked.
    /// Blocking — it waits out earlier writes first — so it runs off the UI
    /// thread (`unlock_history`).
    pub(crate) fn load(&self, store: &ConnectionStore) -> HistoryLoad {
        self.load_within(store, HISTORY_LOAD_SETTLE_WAIT)
    }

    /// `load`, waiting at most `settle` for the writes already sent off.
    pub(crate) fn load_within(&self, store: &ConnectionStore, settle: Duration) -> HistoryLoad {
        // Taken before the lock state is: a lock from here on shows as a
        // change.
        let locks = self.locks.load(Ordering::SeqCst);
        let mut load = HistoryLoad::default();
        // Locked is not unreadable: a file that cannot be opened for want of
        // the key must not be set aside as if it were damaged.
        if !store.is_unlocked() {
            return load;
        }
        // The lock sent its last records off on a blocking thread. Reading
        // before they land would load the older file, and this session's
        // next write would then drop them for good.
        let settled = self.wait_settled(settle);
        if !settled {
            log::warn!(
                "command history: an earlier write is still running; not saving this session"
            );
            load.unsettled = true;
        }
        let sealed = match self.read_sealed(store) {
            Ok(list) => {
                load.writable = settled;
                list
            }
            // The vault locked while this ran and took the key with it: no
            // sign of damage, and a load nobody wants any more.
            Err(_) if self.locks.load(Ordering::SeqCst) != locks => {
                return HistoryLoad::default();
            }
            Err(e) => {
                log::warn!(
                    "command history {} unreadable: {}",
                    self.sealed.display(),
                    e
                );
                load.writable = settled && self.set_aside();
                Vec::new()
            }
        };
        let legacy = if self.legacy.exists() {
            load.legacy_found = load.writable;
            load_history_from(&self.legacy)
        } else {
            Vec::new()
        };
        load.records = merge_history(sealed, legacy);
        load
    }

    pub(crate) fn read_sealed(&self, store: &ConnectionStore) -> Result<Vec<CmdRecord>, String> {
        match std::fs::metadata(&self.sealed) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.to_string()),
            Ok(meta) if meta.len() > SEALED_HISTORY_MAX_BYTES => {
                return Err(format!("{} bytes", meta.len()));
            }
            Ok(_) => {}
        }
        let raw = std::fs::read(&self.sealed).map_err(|e| e.to_string())?;
        let blob: crate::storage::EncryptedBlob =
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let plain = store.open(&blob)?;
        let mut list: Vec<CmdRecord> = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        if list.len() > HISTORY_MAX {
            list.drain(..list.len() - HISTORY_MAX);
        }
        Ok(list)
    }

    /// Move an unreadable sealed file out of the way rather than write over
    /// it: it may be the only copy — sealed by a vault this one replaced, or
    /// damaged in a way that can still be repaired. Never over an earlier one
    /// either, for the same reason. `true` once the path is free.
    pub(crate) fn set_aside(&self) -> bool {
        let free = (0..1000)
            .map(|n| match n {
                0 => self.sealed.with_extension("enc.unreadable"),
                n => self.sealed.with_extension(format!("enc.unreadable.{n}")),
            })
            .find(|p| std::fs::symlink_metadata(p).is_err());
        let Some(aside) = free else {
            log::error!(
                "no free name to set {} aside; command history will not be saved this session",
                self.sealed.display()
            );
            return false;
        };
        match std::fs::rename(&self.sealed, &aside) {
            Ok(()) => {
                log::warn!(
                    "unreadable command history set aside as {}",
                    aside.display()
                );
                true
            }
            Err(e) => {
                log::error!(
                    "could not set {} aside ({}); command history will not be saved this session",
                    self.sealed.display(),
                    e
                );
                false
            }
        }
    }
}

/// Sealed and imported records as one list: oldest first, the newest
/// `HISTORY_MAX` kept. An import that was cut short leaves the same records
/// in both files, so an imported record the sealed list already holds is
/// dropped.
pub(crate) fn merge_history(mut sealed: Vec<CmdRecord>, legacy: Vec<CmdRecord>) -> Vec<CmdRecord> {
    if !legacy.is_empty() {
        let known = sealed.len();
        for record in legacy {
            if !sealed[..known].contains(&record) {
                sealed.push(record);
            }
        }
        // Stable: records from the same second keep their order.
        sealed.sort_by_key(|r| r.timestamp);
    }
    if sealed.len() > HISTORY_MAX {
        sealed.drain(..sealed.len() - HISTORY_MAX);
    }
    sealed
}

/// Overwrite the cleartext `history.json` in place, then delete it. Anything
/// but a regular file is only unlinked, never written through.
pub(crate) fn retire_legacy_history(path: &std::path::Path) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_file() {
        crate::storage::write_private_scrubbing(path, b"")?;
    }
    std::fs::remove_file(path)?;
    log::info!(
        "cleartext command history {} imported and removed",
        path.display()
    );
    Ok(())
}

/// Overwrite every record's text, then drop them all.
pub(crate) fn wipe_history(records: &mut Vec<CmdRecord>) {
    for record in records.iter_mut() {
        record.cmd.zeroize();
        record.session_title.zeroize();
        record.host.zeroize();
    }
    records.clear();
}

/// The history half of `lock_vault`. Seals what the disk has not seen yet —
/// the key is still in memory at this point, and the write returned carries
/// only ciphertext — then wipes every record and bars writes until the next
/// unlock has loaded the file again.
pub(crate) fn lock_history(
    file: &Arc<HistoryFile>,
    store: &ConnectionStore,
    records: &mut Vec<CmdRecord>,
    sync: &mut HistorySync,
) -> Option<HistoryWrite> {
    // Before the key goes. A load still out is not wanted any more, and must
    // not take the file it can no longer open for a damaged one.
    file.locks.fetch_add(1, Ordering::SeqCst);
    sync.pending_load = None;
    let job = if sync.dirty && sync.loaded {
        HistoryFile::snapshot(file, store, records, false, false)
            .map_err(|e| log::warn!("command history not sealed before the lock: {}", e))
            .ok()
    } else {
        None
    };
    wipe_history(records);
    sync.dirty = false;
    sync.loaded = false;
    job
}

/// Run a history write on a blocking thread.
pub(crate) fn spawn_history_write(job: HistoryWrite) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || job.run().map_err(|e| e.to_string()))
                .await
                .map_err(|e| format!("Task: {}", e))?
        },
        Message::HistoryWritten,
    )
}

/// Seal `cmd_history` now and write it off the UI thread. `scrub` overwrites
/// the bytes being replaced; `retire_legacy` then scrubs and deletes the
/// cleartext `history.json`. See `history_write_allowed` for when nothing is
/// written.
pub(crate) fn persist_history(state: &mut NeoShell, scrub: bool, retire_legacy: bool) -> Task<Message> {
    if !history_write_allowed(&state.history_sync, scrub) {
        return Task::none();
    }
    match HistoryFile::snapshot(
        &state.history_file,
        &state.store,
        &state.cmd_history,
        scrub,
        retire_legacy,
    ) {
        Ok(job) => {
            state.history_sync.dirty = false;
            spawn_history_write(job)
        }
        Err(e) => {
            log::warn!("command history not sealed: {}", e);
            Task::none()
        }
    }
}

/// Load the sealed history for a vault that was just opened, on a blocking
/// thread: the load first waits out the writes still on their way to disk —
/// the lock's, above all — and `update` must not wait with it. It lands in
/// `Message::HistoryLoaded` (`land_history_load`).
pub(crate) fn unlock_history(state: &mut NeoShell) -> Task<Message> {
    let (seq, load) = start_history_load(
        &state.history_file,
        state.store.clone(),
        &mut state.history_sync,
    );
    Task::perform(
        async move {
            tokio::task::spawn_blocking(load).await.unwrap_or_else(|e| {
                log::warn!("command history not loaded: {}", e);
                HistoryLoad::default()
            })
        },
        move |load| Message::HistoryLoaded(seq, load),
    )
}

/// The UI-thread half of `unlock_history`: number the load and hand back the
/// work for a blocking thread. Waits for nothing.
pub(crate) fn start_history_load(
    file: &Arc<HistoryFile>,
    store: Arc<ConnectionStore>,
    sync: &mut HistorySync,
) -> (u64, impl FnOnce() -> HistoryLoad + Send + 'static) {
    sync.load_seq += 1;
    let seq = sync.load_seq;
    sync.pending_load = Some(PendingLoad {
        seq,
        cleared: false,
    });
    let file = file.clone();
    (seq, move || file.load(&store))
}

/// What landing an unlock-time load asks of `update`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LoadLanded {
    /// Seal and write at once: that write retires the cleartext
    /// `history.json` the load imported.
    pub(crate) import_legacy: bool,
    /// The i18n key of the warning the user has to see: nothing typed this
    /// session will be saved.
    pub(crate) warning: Option<&'static str>,
}

/// Land the unlock-time load numbered `seq`: the records on disk, then the
/// ones typed while it ran. `None`, and every record it read wiped, for a
/// load nobody wants any more: the vault locked since, or a later unlock
/// started another.
pub(crate) fn land_history_load(
    records: &mut Vec<CmdRecord>,
    sync: &mut HistorySync,
    seq: u64,
    mut load: HistoryLoad,
) -> Option<LoadLanded> {
    let Some(pending) = sync.pending_load.filter(|p| p.seq == seq) else {
        wipe_history(&mut load.records);
        return None;
    };
    sync.pending_load = None;
    if pending.cleared {
        // Read before the clear reached the disk.
        wipe_history(&mut load.records);
    }
    let typed = std::mem::take(records);
    // Typed while the load ran, so not on disk yet. (A second unlock without
    // a lock between reloads what the first may have written already: the
    // merge drops those twins.)
    sync.dirty = !typed.is_empty();
    *records = merge_history(load.records, typed);
    sync.loaded = load.writable;
    Some(LoadLanded {
        import_legacy: load.legacy_found && !pending.cleared,
        warning: (!load.writable).then_some(if load.unsettled {
            "history.warn.unsettled"
        } else {
            "history.warn.unreadable"
        }),
    })
}

/// The in-memory half of clearing the history. A load still out read the
/// history before the clear: it must not bring it back.
pub(crate) fn clear_history(records: &mut Vec<CmdRecord>, sync: &mut HistorySync) {
    wipe_history(records);
    sync.dirty = false;
    if let Some(pending) = sync.pending_load.as_mut() {
        pending.cleared = true;
    }
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compact age for the history panel: 42s, 5m, 3h, 2d.
pub(crate) fn format_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// Completions for the quick-command input, best first: commands already run
/// (newest first), then snippet bodies. A plain prefix match — case matters
/// to a shell — that never offers the text exactly as typed, and never a
/// multi-line snippet, which a one-line input cannot hold.
pub(crate) fn quick_cmd_matches(input: &str, history: &[CmdRecord], snippets: &[Snippet]) -> Vec<String> {
    if input.trim().is_empty() {
        return Vec::new();
    }
    let history = history.iter().rev().map(|r| r.cmd.as_str());
    let snippets = snippets
        .iter()
        .map(|s| s.body.trim_end())
        .filter(|body| !body.contains('\n'));
    let mut out: Vec<String> = Vec::new();
    for candidate in history.chain(snippets) {
        if candidate.len() > input.len()
            && candidate.starts_with(input)
            && !out.iter().any(|o| o == candidate)
        {
            out.push(candidate.to_string());
            if out.len() == QUICK_CMD_SUGGESTIONS {
                break;
            }
        }
    }
    out
}

/// Tab or Down with no modifier: the keys that accept a suggestion.
pub(crate) fn is_autocomplete_key(key: &keyboard::Key, modifiers: &keyboard::Modifiers) -> bool {
    use keyboard::key::Named;
    let plain = !modifiers.shift() && !modifiers.control() && !modifiers.alt() && !modifiers.logo();
    plain && matches!(key, keyboard::Key::Named(Named::Tab | Named::ArrowDown))
}

/// Whether the quick-command input holds keyboard focus right now, asked of
/// the widget tree. iced keeps focus inside the widgets, and a text input
/// does not capture Tab or the arrows, so the key event alone cannot say.
pub(crate) fn quick_cmd_input_focused() -> Task<bool> {
    use iced::advanced::widget::{operate, operation::focusable::find_focused, Id};
    operate(find_focused())
        .collect()
        .map(|ids: Vec<Id>| ids.iter().any(|id| *id == Id::new(QUICK_CMD_INPUT_ID)))
}
