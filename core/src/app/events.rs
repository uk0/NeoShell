use super::*;

/// Least time between two drains the SSH side wakes: about a frame at 60 Hz.
/// Output that keeps trickling in would otherwise run update() and view()
/// back to back, far more often than the screen can show them. A quiet
/// session's next output still drains at once.
pub(crate) const WAKE_MIN_GAP: Duration = Duration::from_millis(16);

/// When a wake that came at `now` may drain: at once, unless the last
/// wake-driven drain began less than [`WAKE_MIN_GAP`] before.
pub(crate) fn wake_drain_at(last: Option<std::time::Instant>, now: std::time::Instant) -> std::time::Instant {
    match last {
        Some(last) => (last + WAKE_MIN_GAP).max(now),
        None => now,
    }
}

/// A `PollSshEvents` each time the SSH side wakes the UI (see
/// `crate::ssh::UiSender`), paced by [`wake_drain_at`].
///
/// No wake is lost between a drain and the next await: `notify_one` leaves a
/// permit when nothing is waiting, and the next `notified()` takes it at
/// once. Wakes that come while a drain is pending fold into that one permit,
/// so a burst of output costs one extra drain at most.
pub(crate) fn ssh_wakes(wake: Arc<tokio::sync::Notify>) -> impl iced::futures::Stream<Item = Message> {
    iced::futures::stream::unfold((wake, None), |(wake, last)| async move {
        wake.notified().await;
        let now = std::time::Instant::now();
        let at = wake_drain_at(last, now);
        if at > now {
            tokio::time::sleep(at - now).await;
        }
        Some((Message::PollSshEvents, (wake, Some(at))))
    })
}

/// A timer drain, beside the wakes, while something on screen moves with no
/// message of its own: a transfer's or the update download's progress bar,
/// read from counters other threads move, or a waiting sign-in challenge,
/// whose modal takes the focus and arms its fields on a drain
/// (`deliver_auth_focus`). The rate the always-on poll used to run at.
pub(crate) const LIVE_POLL: Duration = Duration::from_millis(50);
/// The slow timer under the wakes wherever output or a challenge can
/// arrive, so that a missed wake could never strand either. It also retires
/// unanswered challenges, and keeps what other threads change without a
/// message (a tunnel count, an update found) from going stale on screen.
pub(crate) const SAFETY_POLL: Duration = Duration::from_secs(1);

/// How often `PollSshEvents` also runs on a timer, if at all. The wakes do
/// the work (see [`ssh_wakes`]); nothing is left to poll for on the setup
/// screen, or on the lock screen with no session and no challenge.
pub(crate) fn poll_interval(
    on_main: bool,
    sessions: bool,
    challenge_waiting: bool,
    progress_moving: bool,
) -> Option<Duration> {
    if on_main && (challenge_waiting || progress_moving) {
        Some(LIVE_POLL)
    } else if on_main || sessions || challenge_waiting {
        Some(SAFETY_POLL)
    } else {
        None
    }
}

/// Most terminal output one `PollSshEvents` feeds to the grids. A flooding
/// remote (`cat` of a large file) queues output faster than the grids take
/// it, and draining all of it in one update froze the window until the
/// backlog was through. What a drain leaves stays queued, in order.
pub(crate) const SSH_DRAIN_BYTES: usize = 256 * 1024;
/// Most events one drain takes, whatever they carry: output trickling in a
/// few bytes per read stalls the UI in bulk as surely as large reads do.
pub(crate) const SSH_DRAIN_EVENTS: usize = 1024;

/// What one `PollSshEvents` drain may still take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DrainBudget {
    pub(crate) bytes: usize,
    pub(crate) events: usize,
}

impl DrainBudget {
    pub(crate) fn new(bytes: usize, events: usize) -> Self {
        DrainBudget { bytes, events }
    }

    /// Whether another event may be taken. Asked before one is taken: an
    /// event once off the channel is handled whole, never put back.
    pub(crate) fn has_room(&self) -> bool {
        self.bytes > 0 && self.events > 0
    }

    /// Count one event carrying `bytes` of output. The event that crosses
    /// the line is still handled whole: a drain may overshoot its byte
    /// budget by one event, and never splits one.
    pub(crate) fn charge(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_sub(bytes);
        self.events = self.events.saturating_sub(1);
    }
}

/// The next event off `rx` while `budget` has room, charged to it. What is
/// not taken stays on the channel, in order, for the next drain.
pub(crate) fn take_within<T>(
    rx: &mpsc::Receiver<T>,
    budget: &mut DrainBudget,
    size: impl Fn(&T) -> usize,
) -> Option<T> {
    if !budget.has_room() {
        return None;
    }
    let event = rx.try_recv().ok()?;
    budget.charge(size(&event));
    Some(event)
}

/// What an event weighs against a drain's byte budget: the output it carries.
pub(crate) fn ssh_event_bytes(event: &SshEvent) -> usize {
    match event {
        SshEvent::Data { data, .. } => data.len(),
        _ => 0,
    }
}

/// The session an event is about.
pub(crate) fn ssh_event_session(event: &SshEvent) -> &str {
    match event {
        SshEvent::Data { session_id, .. }
        | SshEvent::Closed { session_id }
        | SshEvent::Error { session_id, .. }
        | SshEvent::Reconnecting { session_id, .. }
        | SshEvent::Reconnected { session_id } => session_id,
    }
}

/// Whether `session_id` is a connect or a split still in flight: a tab holds
/// its id, but no pane shows the session yet.
pub(crate) fn session_connecting(tabs: &[TerminalTab], session_id: &str) -> bool {
    !session_id.is_empty()
        && tabs.iter().any(|t| {
            t.pending_session_id == session_id || t.split_pending.as_deref() == Some(session_id)
        })
}

/// The next event for a `PollSshEvents` drain, in arrival order.
///
/// An event held back earlier comes first. `None` ends the drain: the
/// channel is empty, `budget` is spent, or the event now due belongs to a
/// session still connecting ([`session_connecting`]). That event is kept in
/// `held`, ahead of everything still queued, until `SshConnected` or
/// `SplitConnected` gives the session a pane; the handler would find none and
/// drop it. A server that prints the moment its shell starts can send output
/// before the connect has returned. The 50 ms timer this drain used to run
/// on lost that output only when it fired in the gap; a drain that the
/// output itself wakes would lose it nearly every time.
pub(crate) fn next_ssh_event(
    held: &mut Option<SshEvent>,
    rx: &mpsc::Receiver<SshEvent>,
    budget: &mut DrainBudget,
    tabs: &[TerminalTab],
) -> Option<SshEvent> {
    let event = match held.take() {
        Some(event) => event,
        None => take_within(rx, budget, ssh_event_bytes)?,
    };
    if session_connecting(tabs, ssh_event_session(&event)) {
        *held = Some(event);
        return None;
    }
    Some(event)
}

// ---- Message handlers moved out of handle_message ----

/// `Message::SshConnected`, moved out of `handle_message`.
pub(crate) fn on_ssh_connected(state: &mut NeoShell, tab_id: String, session_id: String, title: String, connection_id: String) -> Task<Message> {
    // Output held back until this connect landed (see
    // `next_ssh_event`) is drained in a later update: after the
    // screen clear below, or dropped if the tab is gone.
    if state.ssh_held.is_some() {
        state.ssh_manager.waker().notify_one();
    }
    // Update existing placeholder tab (created in ConnectTo)
    let Some(tab) = state.tabs.iter_mut().find(|t| t.id == tab_id) else {
        // Closed while it connected — `TabClosed` already gave the
        // connection back. Nothing would ever show or close this
        // session: close it now.
        let ssh = state.ssh_manager.clone();
        return Task::perform(
            async move {
                let _ = ssh.disconnect(&session_id);
            },
            |_| Message::None,
        );
    };
    let sid_for_fetch = session_id.clone();
    tab.session_id = session_id;
    tab.pending_session_id.clear();
    tab.connection_id = connection_id.clone();
    tab.title = title;
    // Clear the "Connecting..." message
    tab.terminal.lock().write(b"\x1b[2J\x1b[H"); // Clear screen + home
    state.connecting_ids.remove(&connection_id);
    state.show_connect_dialog = false;

    state.current_dir.insert(sid_for_fetch.clone(), "~".to_string());
    Task::done(Message::ChangeDir(sid_for_fetch, "~".to_string()))
}

/// `Message::PollSshEvents`, moved out of `handle_message`.
pub(crate) fn on_poll_ssh_events(state: &mut NeoShell) -> Task<Message> {
    // Keyboard-interactive challenges ride this drain rather than a
    // timer of their own; a new one comes back as a focus task.
    let auth = poll_auth_prompts(state);
    let mut rz_sessions: Vec<String> = Vec::new();
    let mut sz_sessions: Vec<String> = Vec::new();

    let mut budget = DrainBudget::new(SSH_DRAIN_BYTES, SSH_DRAIN_EVENTS);
    if let Some(rx) = &state.ssh_event_rx {
        while let Some(event) =
            next_ssh_event(&mut state.ssh_held, rx, &mut budget, &state.tabs)
        {
            match event {
                SshEvent::Data { session_id, data } => {
                    // Skip ZMODEM residual binary data for 2s after detection
                    if let Some(detected_at) = state.zmodem_active.get(&session_id) {
                        if detected_at.elapsed() < Duration::from_secs(2) {
                            continue;
                        } else {
                            state.zmodem_active.remove(&session_id);
                        }
                    }

                    // Detect ZMODEM (both rz and sz send **B0 pattern)
                    if data.len() >= 4 && detect_zmodem_rz(&data) {
                        let _ = state.ssh_manager.send_data(&session_id, ZMODEM_CANCEL);
                        state.zmodem_active.insert(session_id.clone(), std::time::Instant::now());

                        // Extract sz filename from:
                        // 1. Terminal grid (shell echo already rendered)
                        // 2. Current data packet echo
                        // 3. Keyboard buffer fallback
                        let sz_from_grid = state.tabs.iter()
                            .find(|t| t.session_id == session_id)
                            .and_then(|tab| {
                                let grid = tab.terminal.lock();
                                extract_sz_from_grid(&grid)
                            });

                        let data_str = String::from_utf8_lossy(&data);
                        let sz_fname = sz_from_grid
                            .or_else(|| extract_sz_filename(&data_str))
                            .or_else(|| state.sz_filename.remove(&session_id));

                        if let Some(fname) = sz_fname {
                            if let Some(tab) = state.tabs.iter().find(|t| t.session_id == session_id) {
                                tab.terminal.lock().write(
                                    format!("\r\n\x1b[36m[NeoShell] sz: downloading {} via SFTP...\x1b[0m\r\n", fname).as_bytes(),
                                );
                            }
                            state.sz_filename.insert(session_id.clone(), fname);
                            sz_sessions.push(session_id.clone());
                        } else if data_str.contains("rz waiting") {
                            if let Some(tab) = state.tabs.iter().find(|t| t.session_id == session_id) {
                                tab.terminal.lock().write(
                                    b"\r\n\x1b[36m[NeoShell] rz detected - opening file picker...\x1b[0m\r\n",
                                );
                            }
                            rz_sessions.push(session_id.clone());
                        } else {
                            // Default: rz upload
                            if let Some(tab) = state.tabs.iter().find(|t| t.session_id == session_id) {
                                tab.terminal.lock().write(
                                    b"\r\n\x1b[36m[NeoShell] rz detected - opening file picker...\x1b[0m\r\n",
                                );
                            }
                            rz_sessions.push(session_id.clone());
                        }
                        continue;
                    }

                    // Normal data — write to terminal
                    // Split-aware lookup: data may belong to a main
                    // pane or a split pane.
                    if let Some(term) =
                        state.find_terminal_for_session(&session_id).cloned()
                    {
                        let mut grid = term.lock();
                        grid.write(&data);
                        grid.scroll_offset = 0; // Auto-scroll to bottom on new data
                    }
                }
                SshEvent::Closed { session_id } => {
                    // What `forget_session` drops; spelled out here,
                    // where the event receiver holds `state`.
                    state.zmodem_active.remove(&session_id);
                    state.broadcast_selected.remove(&session_id);
                    state.alerts_active.remove(&session_id);
                    state.server_stats.remove(&session_id);
                    state.top_processes.remove(&session_id);
                    state.monitor_parked.unpark(&session_id);
                    state.file_entries.remove(&session_id);
                    state.current_dir.remove(&session_id);
                    state.prompt_cwd.remove(&session_id);

                    // Split pane closed → drop just that pane; main
                    // pane closed with a live split → promote the
                    // split to main. Only a tab with no split left
                    // is removed outright.
                    let handled = remove_split_pane(&mut state.tabs, &session_id);
                    if !handled {
                        if let Some(idx) = state
                            .tabs
                            .iter()
                            .position(|t| t.session_id == session_id)
                        {
                            state.tabs.remove(idx);
                            if state.tabs.is_empty() {
                                state.active_tab = None;
                            } else {
                                state.active_tab =
                                    Some(idx.min(state.tabs.len() - 1));
                            }
                        }
                    }
                }
                SshEvent::Error { session_id, error } => {
                    log::error!("SSH error for {}: {}", session_id, error);
                }
                SshEvent::Reconnecting { session_id, attempt } => {
                    if let Some(tab) =
                        state.tabs.iter_mut().find(|t| t.session_id == session_id)
                    {
                        tab.title = reconnecting_title(title_base(&tab.title), attempt);
                    }
                }
                SshEvent::Reconnected { session_id } => {
                    if let Some(tab) =
                        state.tabs.iter_mut().find(|t| t.session_id == session_id)
                    {
                        tab.title = title_base(&tab.title).to_string();
                    }
                }
            }
        }
    }
    // Out of budget with output perhaps still queued: the rest comes
    // in a fresh update, so the window redraws and takes input in
    // between instead of freezing until a flood is through. A message
    // rather than a wake, so the wakes' frame pacing (`ssh_wakes`)
    // does not throttle a backlog. Not while output is held for a
    // connect: `SshConnected` wakes the drain for that.
    let auth = if !budget.has_room() && state.ssh_held.is_none() {
        Task::batch([auth, Task::done(Message::PollSshEvents)])
    } else {
        auth
    };

    // Dispatch ZMODEM messages (only one Task can be returned per update)
    if let Some(sid) = rz_sessions.into_iter().next() {
        return Task::batch([auth, Task::done(Message::RzDetected(sid))]);
    }
    if let Some(sid) = sz_sessions.into_iter().next() {
        return Task::batch([auth, Task::done(Message::SzDetected(sid))]);
    }

    // Check if terminal grid was resized and notify remote PTY
    if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            if !tab.session_id.is_empty() {
                let grid = tab.terminal.lock();
                let cur = (grid.cols, grid.rows);
                if cur != state.last_term_size && cur.0 > 0 && cur.1 > 0 {
                    state.last_term_size = cur;
                    let session_id = tab.session_id.clone();
                    let ssh = state.ssh_manager.clone();
                    let cols = cur.0 as u32;
                    let rows = cur.1 as u32;
                    drop(grid);
                    let resize = Task::perform(
                        async move {
                            tokio::task::spawn_blocking(move || {
                                ssh.resize(&session_id, cols, rows)
                            }).await.ok();
                            ()
                        },
                        |_| Message::None,
                    );
                    return Task::batch([auth, resize]);
                }
            }
        }
    }

    auth
}
