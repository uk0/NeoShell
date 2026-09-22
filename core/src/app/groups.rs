use super::*;

/// How long after the last fold or unfold the folded groups are saved: a run
/// of clicks costs one write, not one fsync each.
pub(crate) const GROUPS_SAVE_DELAY: Duration = Duration::from_millis(800);

/// Largest `collapsed_groups.enc` read back; anything bigger is not ours.
pub(crate) const SEALED_GROUPS_MAX_BYTES: u64 = 1024 * 1024;

/// The folded sidebar groups on disk. `collapsed_groups.enc` holds one
/// `EncryptedBlob`: the sorted JSON list of group names sealed under the
/// vault key, as `history.enc` holds the history — group names say what the
/// vault's connections are, so they are exactly as readable as the vault.
/// Builds before this wrote the list in the clear to `collapsed_groups.json`;
/// the first unlock imports that file, and the write that seals it scrubs and
/// deletes it.
///
/// Sealed on the UI thread, where the key is; written on a blocking thread,
/// in the order sealed: a snapshot that runs late is dropped rather than
/// landing over a newer one.
pub(crate) struct GroupsFile {
    pub(crate) sealed: std::path::PathBuf,
    pub(crate) legacy: std::path::PathBuf,
    pub(crate) next_seq: AtomicU64,
    /// Number of the newest snapshot on disk, held for the whole of a write.
    pub(crate) written: parking_lot::Mutex<u64>,
}

/// A sealed snapshot of the folded groups, on its way to disk.
pub(crate) struct GroupsWrite {
    pub(crate) seq: u64,
    pub(crate) blob: crate::storage::EncryptedBlob,
    /// Scrub and delete the cleartext `collapsed_groups.json` once this
    /// snapshot, or a newer one, is on disk.
    pub(crate) retire_legacy: bool,
}

impl GroupsFile {
    pub(crate) fn at(dir: &std::path::Path) -> Self {
        GroupsFile {
            sealed: dir.join("collapsed_groups.enc"),
            legacy: dir.join("collapsed_groups.json"),
            next_seq: AtomicU64::new(0),
            written: parking_lot::Mutex::new(0),
        }
    }

    pub(crate) fn in_data_dir() -> Self {
        Self::at(
            &dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("neoshell"),
        )
    }

    /// Seal `groups` for a later `write`. Fails while the vault is locked.
    pub(crate) fn snapshot(
        &self,
        store: &ConnectionStore,
        groups: &HashSet<String>,
        retire_legacy: bool,
    ) -> Result<GroupsWrite, String> {
        let mut list: Vec<&String> = groups.iter().collect();
        list.sort();
        let json = zeroize::Zeroizing::new(serde_json::to_vec(&list).map_err(|e| e.to_string())?);
        let blob = store.seal(&json)?;
        Ok(GroupsWrite {
            seq: self.next_seq.fetch_add(1, Ordering::Relaxed) + 1,
            blob,
            retire_legacy,
        })
    }

    /// Put `job` on disk — atomically, 0600 — unless a newer snapshot is
    /// there already. Blocking: it fsyncs.
    pub(crate) fn write(&self, job: GroupsWrite) -> std::io::Result<()> {
        let mut written = self.written.lock();
        if job.seq > *written {
            let bytes = serde_json::to_vec(&job.blob).map_err(std::io::Error::other)?;
            crate::storage::write_private(&self.sealed, &bytes)?;
            *written = job.seq;
        }
        if job.retire_legacy {
            retire_cleartext_groups(&self.legacy)?;
        }
        Ok(())
    }

    /// The folded groups of the vault just opened, with a cleartext
    /// `collapsed_groups.json` merged in; the flag says one was found, for
    /// the caller to seal at once and retire. A missing, damaged or foreign
    /// sealed file folds nothing — the next save replaces it — and nothing
    /// is read while the vault is locked.
    pub(crate) fn load(&self, store: &ConnectionStore) -> (HashSet<String>, bool) {
        if !store.is_unlocked() {
            return (HashSet::new(), false);
        }
        let mut groups = match self.read_sealed(store) {
            Ok(groups) => groups,
            Err(e) => {
                log::warn!("folded groups {} unreadable: {}", self.sealed.display(), e);
                HashSet::new()
            }
        };
        let legacy_found = std::fs::symlink_metadata(&self.legacy).is_ok();
        if legacy_found {
            let legacy = std::fs::read(&self.legacy)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Vec<String>>(&bytes).ok())
                .unwrap_or_default();
            groups.extend(legacy);
        }
        (groups, legacy_found)
    }

    pub(crate) fn read_sealed(&self, store: &ConnectionStore) -> Result<HashSet<String>, String> {
        match std::fs::metadata(&self.sealed) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
            Err(e) => return Err(e.to_string()),
            Ok(meta) if meta.len() > SEALED_GROUPS_MAX_BYTES => {
                return Err(format!("{} bytes", meta.len()));
            }
            Ok(_) => {}
        }
        let raw = std::fs::read(&self.sealed).map_err(|e| e.to_string())?;
        let blob: crate::storage::EncryptedBlob =
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let plain = store.open(&blob)?;
        let list: Vec<String> = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        Ok(list.into_iter().collect())
    }
}

/// Overwrite the cleartext `collapsed_groups.json` in place, then delete it.
/// Anything but a regular file is only unlinked, never written through.
pub(crate) fn retire_cleartext_groups(path: &std::path::Path) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_file() {
        crate::storage::write_private_scrubbing(path, b"")?;
    }
    std::fs::remove_file(path)?;
    log::info!("cleartext folded groups {} sealed and removed", path.display());
    Ok(())
}

/// Seal the folded groups now and write them off the UI thread; `Task::none`
/// while the vault is locked. `retire_legacy` then scrubs and deletes the
/// cleartext file.
pub(crate) fn persist_groups(state: &mut NeoShell, retire_legacy: bool) -> Task<Message> {
    match state
        .groups_file
        .snapshot(&state.store, &state.collapsed_groups, retire_legacy)
    {
        Ok(job) => {
            state.groups_dirty = false;
            let file = state.groups_file.clone();
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || file.write(job).map_err(|e| e.to_string()))
                        .await
                        .map_err(|e| format!("Task: {}", e))?
                },
                Message::GroupsWritten,
            )
        }
        Err(e) => {
            log::warn!("folded groups not sealed: {}", e);
            Task::none()
        }
    }
}

/// The folded groups changed: save them once no further change has come for
/// [`GROUPS_SAVE_DELAY`].
pub(crate) fn schedule_groups_save(state: &mut NeoShell) -> Task<Message> {
    state.groups_dirty = true;
    state.groups_gen += 1;
    let gen = state.groups_gen;
    Task::perform(tokio::time::sleep(GROUPS_SAVE_DELAY), move |_| {
        Message::SaveCollapsedGroups(gen)
    })
}

/// Read the folded groups of the vault just opened — on the UI thread: a
/// small file. A cleartext file found beside it is sealed and retired at
/// once.
pub(crate) fn unlock_groups(state: &mut NeoShell) -> Task<Message> {
    let (groups, legacy_found) = state.groups_file.load(&state.store);
    state.collapsed_groups = groups;
    state.groups_dirty = false;
    if legacy_found {
        persist_groups(state, true)
    } else {
        Task::none()
    }
}

/// Forget folded groups no connection is in any more — the last one was
/// deleted or moved to another group. True when anything was dropped.
pub(crate) fn prune_collapsed_groups(groups: &mut HashSet<String>, conns: &[ConnectionInfo]) -> bool {
    let before = groups.len();
    groups.retain(|g| conns.iter().any(|c| c.group == *g));
    groups.len() != before
}

/// One group of the sidebar list.
pub(crate) struct SidebarGroup<'a> {
    /// The connections' `group` as stored — "" is the ungrouped bucket. What
    /// `collapsed_groups` holds.
    pub(crate) key: String,
    pub(crate) conns: Vec<&'a ConnectionInfo>,
    /// Drawn folded: saved as collapsed, and no search running.
    pub(crate) collapsed: bool,
}

impl SidebarGroup<'_> {
    /// The header's name: the group's own, or "Ungrouped" in the UI language.
    pub(crate) fn label(&self) -> String {
        group_label(&self.key)
    }
}

/// How a stored group name reads in the sidebar and the palette.
pub(crate) fn group_label(key: &str) -> String {
    if key.is_empty() {
        i18n::t("sidebar.ungrouped").to_string()
    } else {
        key.to_string()
    }
}

/// The sidebar's groups for the search `query`, in display order. While a
/// search runs every group with a match is drawn open, whatever was saved —
/// search results are never hidden — and the saved state stays as it was.
pub(crate) fn sidebar_groups<'a>(
    conns: &'a [ConnectionInfo],
    query: &str,
    collapsed: &HashSet<String>,
) -> Vec<SidebarGroup<'a>> {
    let query = search_fold(query.trim());
    let searching = !query.is_empty();
    let mut groups: Vec<SidebarGroup<'a>> = Vec::new();
    for conn in conns.iter().filter(|c| !searching || connection_matches(c, &query)) {
        match groups.iter_mut().find(|g| g.key == conn.group) {
            Some(group) => group.conns.push(conn),
            None => groups.push(SidebarGroup {
                key: conn.group.clone(),
                conns: vec![conn],
                collapsed: false,
            }),
        }
    }
    groups.sort_by(|a, b| group_order(&a.key, &b.key));
    for group in &mut groups {
        group.collapsed = !searching && collapsed.contains(&group.key);
        group.conns.sort_by(|a, b| connection_order(a, b));
    }
    groups
}

/// Order of connections wherever they are listed — the sidebar, the connect
/// dialog, the palette: by group as the sidebar orders its groups, then by
/// name without regard to case, then by host. The vault is a map, so they
/// used to come back in a new order on every load. The exact name, host and
/// id settle ties, so the order never depends on how they were loaded.
pub(crate) fn connection_order(a: &ConnectionInfo, b: &ConnectionInfo) -> std::cmp::Ordering {
    // Without allocating: the sidebar sorts on every frame.
    let ignore_case = |x: &str, y: &str| {
        x.chars()
            .flat_map(char::to_lowercase)
            .cmp(y.chars().flat_map(char::to_lowercase))
    };
    group_order(&a.group, &b.group)
        .then_with(|| ignore_case(&a.name, &b.name))
        .then_with(|| ignore_case(&a.host, &b.host))
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.host.cmp(&b.host))
        .then_with(|| a.id.cmp(&b.id))
}

/// Group order: by name without regard to case — Chinese and English names
/// alike, by their text; no collation beyond that — and the ungrouped bucket
/// last. Names that differ only in case keep a fixed order.
pub(crate) fn group_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.is_empty()
        .cmp(&b.is_empty())
        .then_with(|| a.to_lowercase().cmp(&b.to_lowercase()))
        .then_with(|| a.cmp(b))
}

/// Text folded for search: lowercase, with the full-width Latin letters,
/// digits and punctuation a Chinese input method types in full-width mode
/// read as their ASCII selves, and the ideographic space as a space.
pub(crate) fn search_fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            '\u{3000}' => ' ',
            c => c,
        })
        .flat_map(char::to_lowercase)
        .collect()
}

/// Whether a connection matches a [`search_fold`]ed sidebar query: as a
/// substring of its name, host, user or group — the group as the sidebar
/// shows it, so the ungrouped bucket is found by its label ("Ungrouped" /
/// "未分组") too.
pub(crate) fn connection_matches(conn: &ConnectionInfo, folded_query: &str) -> bool {
    let group = group_label(&conn.group);
    [&conn.name, &conn.host, &conn.username, &group]
        .iter()
        .any(|field| search_fold(field).contains(folded_query))
}
