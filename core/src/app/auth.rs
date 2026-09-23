use super::*;

/// How long a keyboard-interactive challenge stays answerable. The SSH thread
/// stops waiting after 180 s (`AUTH_PROMPT_TIMEOUT` in ssh/mod.rs); retiring
/// the modal a little earlier means nobody types an answer that no thread is
/// waiting for.
pub(crate) const AUTH_PROMPT_TTL: Duration = Duration::from_secs(170);
/// Drain the challenges SSH threads parked for the modal. Runs on every
/// `PollSshEvents`, which a challenge's arrival wakes on every screen: a
/// reconnect can ask at any time. Returns the focus task for the front
/// challenge's first field, once the modal is on screen to take it (see
/// `deliver_auth_focus`).
pub(crate) fn poll_auth_prompts(state: &mut NeoShell) -> Task<Message> {
    let was_empty = state.auth_queue.is_empty();
    if let Some(rx) = &state.auth_rx {
        while let Ok(challenge) = rx.try_recv() {
            log::info!(
                "keyboard-interactive challenge for {} ({})",
                challenge.target,
                challenge.purpose
            );
            state.auth_queue.push_back((challenge, std::time::Instant::now()));
        }
    }
    // A challenge from a session no tab or pane holds any more — a connect
    // still dialling when its tab closed, which closing could not withdraw
    // yet — is cancelled, never shown: nobody is there to answer it.
    let mut front_orphaned = false;
    if !state.auth_queue.is_empty() {
        let tabs = &state.tabs;
        let (orphans, front) = take_challenges(&mut state.auth_queue, |c| {
            challenge_orphaned(&c.session_id, tabs)
        });
        for challenge in orphans {
            log::info!("withdrawing the sign-in for {}: its tab is gone", challenge.target);
            challenge.cancel();
        }
        front_orphaned = front;
    }
    // Past its SSH thread's own timeout nobody is waiting for the answer any
    // more: retire the modal instead of taking one.
    let front_expired = state
        .auth_queue
        .front()
        .is_some_and(|(_, at)| at.elapsed() >= AUTH_PROMPT_TTL);
    state.auth_queue.retain(|(_, at)| at.elapsed() < AUTH_PROMPT_TTL);
    if front_expired || front_orphaned || (was_empty && !state.auth_queue.is_empty()) {
        return state.begin_auth_prompt();
    }
    // A challenge that arrived under the lock screen, the palette or the
    // delete confirmation takes the focus once the modal is uncovered.
    state.deliver_auth_focus()
}

/// Whether the keyboard-interactive modal is on screen: only `view_main`
/// draws it, and only while nothing sits above it in the z-order.
pub(crate) fn auth_modal_visible(screen: &Screen, topmost: Option<Overlay>) -> bool {
    *screen == Screen::Main && topmost == Some(Overlay::AuthPrompt)
}

/// Settle an owed focus: true exactly once, the first time the modal is
/// `visible`. Handing it over on every tick would pull the cursor back to the
/// first field while the user is typing in the second.
pub(crate) fn take_owed_focus(owed: &mut bool, visible: bool) -> bool {
    let now = *owed && visible;
    if now {
        *owed = false;
    }
    now
}

pub(crate) fn auth_input_id(i: usize) -> text_input::Id {
    text_input::Id::new(format!("auth_answer_{}", i))
}

/// Answer fields `release_auth_focus` looks at. A server may ask for more,
/// but none does usefully.
pub(crate) const AUTH_MAX_FIELDS: usize = 64;

/// Keys this recent when a sign-in modal comes up mean the user is typing
/// somewhere else: the modal does not take the keyboard then, not even for a
/// challenge the user asked for.
pub(crate) const AUTH_TYPING_WINDOW: Duration = Duration::from_millis(1500);

/// For this long after a sign-in modal comes up, its answer fields take no
/// keys and Enter submits nothing. Nobody reads a modal and starts answering
/// that fast: what arrives in the window was typed before it appeared.
pub(crate) const AUTH_ARM_DELAY: Duration = Duration::from_millis(300);

/// Whether a sign-in challenge may take the keyboard when its modal comes up:
/// only one the user's own click just asked for — the Test or Deploy button,
/// whose challenges carry no session, or a Connect, a split or a "Reconnect
/// monitoring" still waiting on this session (`user_started`). Anything else,
/// above all a dropped session reconnecting on its own, turns up while the
/// user is typing somewhere else, and taking the focus would hand the rest of
/// what they type — Enter included — to this server as the answer. That
/// modal shows, and waits for a click.
pub(crate) fn challenge_may_take_focus(purpose: &str, user_started: bool) -> bool {
    match purpose {
        "test" | "deploy" => true,
        "reconnect" => false,
        _ => user_started,
    }
}

/// Whether keys were still arriving at `now` (see [`AUTH_TYPING_WINDOW`]).
pub(crate) fn typing_recently(last_keypress: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    last_keypress.is_some_and(|at| now.saturating_duration_since(at) < AUTH_TYPING_WINDOW)
}

/// Track when the sign-in modal came on screen: set the first time it is
/// `visible`, cleared whenever it is not — covered, gone, or locked away.
pub(crate) fn note_auth_shown(
    shown_at: &mut Option<std::time::Instant>,
    visible: bool,
    now: std::time::Instant,
) {
    if !visible {
        *shown_at = None;
    } else if shown_at.is_none() {
        *shown_at = Some(now);
    }
}

/// Whether the modal's answer fields take keys yet: it has been on screen
/// for [`AUTH_ARM_DELAY`].
pub(crate) fn auth_armed(shown_at: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    shown_at.is_some_and(|at| now.saturating_duration_since(at) >= AUTH_ARM_DELAY)
}

/// Take the keyboard focus off the sign-in modal's answer fields — and off
/// nothing else: whatever the user was typing in keeps it.
pub(crate) fn release_auth_focus() -> Task<Message> {
    use iced::advanced::widget::{operate, operation, Id, Operation};
    struct Release;
    impl<T> Operation<T> for Release {
        fn container(
            &mut self,
            _id: Option<&Id>,
            _bounds: Rectangle,
            operate_on_children: &mut dyn FnMut(&mut dyn Operation<T>),
        ) {
            operate_on_children(self);
        }

        fn focusable(&mut self, state: &mut dyn operation::Focusable, id: Option<&Id>) {
            let answer = id.is_some_and(|id| {
                (0..AUTH_MAX_FIELDS).any(|i| *id == Id::from(auth_input_id(i)))
            });
            if answer {
                state.unfocus();
            }
        }
    }
    operate(Release)
}

/// Send what was typed to the challenge at the front, and move on to the next.
pub(crate) fn submit_auth_answers(state: &mut NeoShell) -> Task<Message> {
    if let Some((challenge, _)) = state.auth_queue.pop_front() {
        let mut answers = std::mem::take(&mut state.auth_answers);
        answers.resize(challenge.prompt.prompts.len(), String::new());
        // A thread that already timed out dropped its receiver;
        // there is nobody left to tell.
        let _ = challenge.reply.send(answers);
    }
    state.begin_auth_prompt()
}

/// Every session id a tab's sign-in challenges can carry: its session or,
/// while it connects, the id that connect runs under — and the same for its
/// split.
pub(crate) fn tab_auth_sessions(tab: &TerminalTab) -> Vec<String> {
    [
        Some(&tab.session_id),
        Some(&tab.pending_session_id),
        tab.split.as_ref().map(|sp| &sp.session_id),
        tab.split_pending.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter(|id| !id.is_empty())
    .cloned()
    .collect()
}

/// Whether a challenge from `session_id` has nobody to answer it: it names a
/// session, and no tab or pane holds it — as its session, or as the connect
/// or split still dialling under it (`tab_auth_sessions`). A test or a key
/// deployment carries no session and always has its modal.
pub(crate) fn challenge_orphaned(session_id: &str, tabs: &[TerminalTab]) -> bool {
    !session_id.is_empty()
        && !tabs
            .iter()
            .any(|tab| tab_auth_sessions(tab).iter().any(|s| s == session_id))
}

/// Take every challenge `pick` chooses out of the modal's queue, oldest
/// first. The flag says whether the one on screen — the front — was among
/// them.
pub(crate) fn take_challenges<T>(
    queue: &mut VecDeque<(T, std::time::Instant)>,
    mut pick: impl FnMut(&T) -> bool,
) -> (Vec<T>, bool) {
    let front = queue.front().is_some_and(|(challenge, _)| pick(challenge));
    let mut taken = Vec::new();
    let mut kept = VecDeque::with_capacity(queue.len());
    for (challenge, at) in queue.drain(..) {
        if pick(&challenge) {
            taken.push(challenge);
        } else {
            kept.push_back((challenge, at));
        }
    }
    *queue = kept;
    (taken, front)
}

/// Zero every answer before dropping it: they are passwords and OTP codes.
pub(crate) fn scrub_answers(answers: &mut Vec<String>) {
    for answer in answers.iter_mut() {
        answer.zeroize();
    }
    answers.clear();
}

/// Text a remote server supplied, made safe to lay out: control characters
/// other than newline dropped, capped at `max` characters so a hostile banner
/// cannot push the buttons off screen.
pub(crate) fn sanitize_remote_text(s: &str, max: usize) -> String {
    let clean: String = s.chars().filter(|c| *c == '\n' || !c.is_control()).collect();
    truncate_str(clean.trim(), max)
}

/// Which connection is asking, in words (see `AuthChallenge::purpose`).
pub(crate) fn auth_purpose_label(purpose: &str) -> String {
    let key = match purpose {
        "shell" => "auth.purpose.shell",
        "exec" => "auth.purpose.exec",
        "reconnect" => "auth.purpose.reconnect",
        "test" => "auth.purpose.test",
        "deploy" => "auth.purpose.deploy",
        other => return other.to_string(),
    };
    i18n::t(key).to_string()
}

// ---- Message handlers moved out of handle_message ----

/// `Message::AuthAnswerChanged`, moved out of `handle_message`.
pub(crate) fn on_auth_answer_changed(state: &mut NeoShell, i: usize, mut value: String) -> Task<Message> {
    // Keys in the modal's first moments were typed before anyone
    // could see it, for something else: they are no answer.
    if !auth_armed(state.auth_shown_at, std::time::Instant::now()) {
        value.zeroize();
        return Task::none();
    }
    if let Some(slot) = state.auth_answers.get_mut(i) {
        let mut old = std::mem::replace(slot, value);
        old.zeroize();
    }
    Task::none()
}

/// `Message::AuthFocus`, moved out of `handle_message`.
pub(crate) fn on_auth_focus(state: &mut NeoShell, i: usize) -> Task<Message> {
    // Enter in an answer field moves on — not an Enter that arrived
    // with the modal.
    if !auth_armed(state.auth_shown_at, std::time::Instant::now()) {
        return Task::none();
    }
    state.focus.focus(auth_input_id(i))
}

/// `Message::AuthEnter`, moved out of `handle_message`.
pub(crate) fn on_auth_enter(state: &mut NeoShell) -> Task<Message> {
    // Never an Enter typed before the modal appeared: that one ended
    // whatever the user was typing elsewhere, a sudo password say.
    if !auth_armed(state.auth_shown_at, std::time::Instant::now()) {
        return Task::none();
    }
    submit_auth_answers(state)
}

/// `Message::AuthCancel`, moved out of `handle_message`.
pub(crate) fn on_auth_cancel(state: &mut NeoShell) -> Task<Message> {
    // The user declining to answer: a cancel, which the SSH thread
    // tells apart from a modal retired unanswered.
    if let Some((challenge, _)) = state.auth_queue.pop_front() {
        challenge.cancel();
    }
    state.begin_auth_prompt()
}
