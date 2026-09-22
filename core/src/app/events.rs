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
