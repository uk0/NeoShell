use super::*;

/// Stable widget id for the Cmd+F search input so we can focus it on open.
pub(crate) const TERM_SEARCH_INPUT_ID: &str = "term_search";
/// Stable widget id for the Cmd+K palette input.
pub(crate) const PALETTE_INPUT_ID: &str = "palette_input";
/// Stable widget id for the tab-rename input.
pub(crate) const TAB_RENAME_INPUT_ID: &str = "tab_rename_input";

/// Stable ids of the text inputs that always take a secret — every
/// `.secure(true)` field. No input method may compose, show or upload what
/// is typed into them: it is off while one of them has the keyboard focus
/// (`ime_allowed`). The sign-in modal's answer fields are secret only when
/// their prompt is not echoed; they go by `auth_input_id`.
pub(crate) const SETUP_PW_INPUT_ID: &str = "setup_pw";
pub(crate) const SETUP_CONFIRM_INPUT_ID: &str = "setup_confirm";
pub(crate) const UNLOCK_PW_INPUT_ID: &str = "unlock_pw";
pub(crate) const CONN_PASSWORD_INPUT_ID: &str = "conn_password";
pub(crate) const CONN_PASSPHRASE_INPUT_ID: &str = "conn_passphrase";
pub(crate) const PROXY_PASSWORD_INPUT_ID: &str = "proxy_password";
pub(crate) const PROXY_PASSPHRASE_INPUT_ID: &str = "proxy_passphrase";
pub(crate) const TUNNEL_PASSWORD_INPUT_ID: &str = "tunnel_password";
pub(crate) const TUNNEL_PASSPHRASE_INPUT_ID: &str = "tunnel_passphrase";
pub(crate) const SECRET_INPUT_IDS: [&str; 9] = [
    SETUP_PW_INPUT_ID,
    SETUP_CONFIRM_INPUT_ID,
    UNLOCK_PW_INPUT_ID,
    CONN_PASSWORD_INPUT_ID,
    CONN_PASSPHRASE_INPUT_ID,
    PROXY_PASSWORD_INPUT_ID,
    PROXY_PASSPHRASE_INPUT_ID,
    TUNNEL_PASSWORD_INPUT_ID,
    TUNNEL_PASSPHRASE_INPUT_ID,
];

/// The text input holding the keyboard focus, as the input method sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum FocusedField {
    /// No text input: keys go to the terminal.
    #[default]
    None,
    /// One of [`SECRET_INPUT_IDS`].
    Secret,
    /// The sign-in modal's answer field for prompt `n`.
    AuthAnswer(usize),
    /// Any other text input.
    Text,
}

impl FocusedField {
    /// What the input with widget id `id` is. A focused input without an id
    /// is never reported (`find_focused` skips it) — which is why every
    /// secret field carries one.
    pub(crate) fn of(id: Option<&iced::advanced::widget::Id>) -> Self {
        use iced::advanced::widget::Id;
        let Some(id) = id else {
            return FocusedField::None;
        };
        if SECRET_INPUT_IDS.iter().any(|secret| *id == Id::new(*secret)) {
            return FocusedField::Secret;
        }
        match (0..AUTH_MAX_FIELDS).find(|&n| *id == Id::from(auth_input_id(n))) {
            Some(n) => FocusedField::AuthAnswer(n),
            None => FocusedField::Text,
        }
    }
}

/// Whether the input method may be on. Never on the setup and lock screens,
/// which hold nothing but master-password fields; on the main screen unless
/// the focused field takes a secret. `auth_prompts` are the sign-in modal's
/// prompts with their echo flags: an answer the server echoes is no secret,
/// and an answer field with no prompt behind it any more counts as one.
pub(crate) fn ime_allowed(screen: &Screen, focused: FocusedField, auth_prompts: &[(String, bool)]) -> bool {
    if *screen != Screen::Main {
        return false;
    }
    match focused {
        FocusedField::None | FocusedField::Text => true,
        FocusedField::Secret => false,
        FocusedField::AuthAnswer(n) => auth_prompts.get(n).is_some_and(|(_, echo)| *echo),
    }
}

/// Fail closed while the focus is unknown. A click on an overlay that holds
/// a secret field ([`Overlay::HOLDS_SECRETS`]) may just have focused it, and
/// iced 0.13 says which field only once the widget-tree query answers — a
/// frame later. Until then the input method stays off, so no keystroke can
/// reach a password field through it. Anywhere else no secret field is on
/// screen, and a click leaves the input method alone: switching it off and on
/// drops the candidate window's anchor on X11/Wayland and an in-progress
/// composition on macOS.
pub(crate) fn focus_settled_or_no_secret_on_screen(answered: bool, secret_on_screen: bool) -> bool {
    answered || !secret_on_screen
}

/// Which text input has the keyboard focus, as the app last learned it:
/// iced 0.13 keeps the focus inside the widgets. The widget tree is asked
/// (`query`) after anything that can move it — a mouse press, Tab, Esc, a
/// modal or a screen coming or going. When the app moves the focus itself
/// (`focus`), the field counts at once, and the tree confirms it after.
#[derive(Debug, Default)]
pub(crate) struct FocusTracker {
    pub(crate) field: FocusedField,
    /// The focused input's id, as `field` was read from.
    pub(crate) id: Option<iced::advanced::widget::Id>,
    /// Queries and focus moves, numbered as they are issued.
    pub(crate) issued: u64,
    /// Answers to queries numbered up to here are stale: a later answer is
    /// in, or the app moved the focus after they were asked.
    pub(crate) settled: u64,
}

impl FocusTracker {
    /// Ask the widget tree which input has the focus. `collect` answers even
    /// when none has: leaving a field for the terminal is an answer too.
    pub(crate) fn query(&mut self) -> Task<Message> {
        use iced::advanced::widget::{operate, operation::focusable::find_focused};
        self.issued += 1;
        let seq = self.issued;
        operate(find_focused())
            .collect()
            .map(move |ids| Message::FocusFound(seq, ids.into_iter().next()))
    }

    /// Focus the text input `id`. It counts as focused from here on — a
    /// secret field closes the input method before a key can reach it — and
    /// the tree is asked once the focus has moved, in case `id` was not on
    /// screen to take it.
    pub(crate) fn focus(&mut self, id: text_input::Id) -> Task<Message> {
        self.id = Some(id.clone().into());
        self.field = FocusedField::of(self.id.as_ref());
        self.issued += 1;
        self.settled = self.issued;
        text_input::focus(id).chain(self.query())
    }

    /// Run `task` — one that moves the focus — then ask the tree.
    pub(crate) fn then_query(&mut self, task: Task<Message>) -> Task<Message> {
        task.chain(self.query())
    }

    /// Every question asked of the widget tree has been answered: `field`
    /// is what holds the focus now, not what held it before the last click.
    pub(crate) fn answered(&self) -> bool {
        self.settled == self.issued
    }

    /// The answer to query `seq`.
    pub(crate) fn found(&mut self, seq: u64, id: Option<iced::advanced::widget::Id>) {
        if seq <= self.settled {
            return;
        }
        self.settled = seq;
        self.field = FocusedField::of(id.as_ref());
        self.id = id;
    }

    /// `field`, for a sign-in modal showing `answers` answer fields: one past
    /// the `AUTH_MAX_FIELDS` that `FocusedField::of` looks through — a server
    /// may ask for more — is still an answer field, not any text input.
    pub(crate) fn field_for(&self, answers: usize) -> FocusedField {
        use iced::advanced::widget::Id;
        match (self.field, &self.id) {
            (FocusedField::Text, Some(id)) if answers > AUTH_MAX_FIELDS => (AUTH_MAX_FIELDS
                ..answers)
                .find(|&n| *id == Id::from(auth_input_id(n)))
                .map_or(FocusedField::Text, FocusedField::AuthAnswer),
            (field, _) => field,
        }
    }
}

/// Whether `message` may leave another text input — or none — holding the
/// keyboard focus: a mouse press (a click focuses the input under it and
/// takes the focus from every other one), Tab or Shift+Tab, and Esc (a
/// focused text input lets go on Esc).
pub(crate) fn moves_focus(message: &Message) -> bool {
    use keyboard::key::Named;
    matches!(
        message,
        Message::TerminalMouseDown(_)
            | Message::FocusMayHaveMoved
            // Hiding the bottom panel or the sidebar removes the path inputs
            // or the search box — and the focus with them.
            | Message::ToggleBottomPanel
            | Message::ToggleSidebar
            | Message::KeyboardEvent(keyboard::Key::Named(Named::Tab | Named::Escape), ..)
    )
}

/// The input method's anchor for a terminal whose canvas starts at `origin`
/// with the text cursor in `cell` (0-based column, row): the cell's top-left
/// in window (logical) coordinates, and the line height. The renderer's and
/// `pixel_to_grid_with`'s cell metrics, font-size clamp included.
pub(crate) fn ime_cursor_area(origin: (f32, f32), font_size: f32, cell: (usize, usize)) -> (f32, f32, f32) {
    let font_size = if font_size.is_finite() {
        font_size.clamp(8.0, 28.0)
    } else {
        14.0
    };
    let (cell_w, cell_h) = (font_size * 0.6, font_size * 1.2);
    (
        origin.0 + cell.0 as f32 * cell_w,
        origin.1 + cell.1 as f32 * cell_h,
        cell_h,
    )
}

/// Tell the runtime what the input method may do now: nothing on the vault
/// screens or in a secret field; and while the terminal has the keyboard,
/// open its candidate window at the text cursor — sent only when that moves.
pub(crate) fn sync_input_method(state: &mut NeoShell) {
    let prompts = state
        .auth_queue
        .front()
        .map_or(&[][..], |(challenge, _)| challenge.prompt.prompts.as_slice());
    let field = state.focus.field_for(prompts.len());
    let allowed = ime_allowed(&state.screen, field, prompts)
        && focus_settled_or_no_secret_on_screen(state.focus.answered(), state.secret_overlay_open());
    iced_winit::ime::set_allowed(allowed);
    // Not while a click's answer is out: the runtime anchored the window at
    // the click — on the field it focused, perhaps — and the terminal takes
    // it back only once it is known to hold the keys.
    let terminal_keys = allowed
        && field == FocusedField::None
        && state.focus.answered()
        && !state.any_overlay_open();
    let area = if terminal_keys {
        state.focused_terminal().map(|term| {
            let cell = {
                let grid = term.lock();
                (
                    grid.cursor_x.min(grid.cols.saturating_sub(1)),
                    grid.cursor_y.min(grid.rows.saturating_sub(1)),
                )
            };
            ime_cursor_area(
                state.focused_pane_origin(),
                state.theme_cfg.terminal_font_size,
                cell,
            )
        })
    } else {
        None
    };
    match area {
        Some(area) if state.ime_area != Some(area) => {
            iced_winit::ime::set_cursor_area(area.0, area.1, area.2);
            state.ime_area = Some(area);
        }
        Some(_) => {}
        // Whatever takes the keys now places the window itself (a click
        // anchors it where it lands); the terminal re-sends when it is back.
        None => state.ime_area = None,
    }
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

/// Widget id of the quick-command input; autocomplete keeps focus in it.
pub(crate) const QUICK_CMD_INPUT_ID: &str = "quick_cmd_input";
/// Main-screen inputs outside any overlay. They carry ids so a focus query
/// reports them: `find_focused` skips an input without one, which read as
/// "the terminal has the keys" and moved the input method's candidate
/// window to the terminal cursor while the user typed here.
pub(crate) const SIDEBAR_SEARCH_INPUT_ID: &str = "sidebar_search";
pub(crate) const LOCAL_PATH_INPUT_ID: &str = "local_path";
pub(crate) const REMOTE_PATH_INPUT_ID: &str = "remote_path";
/// Widget id of the SFTP name / mode dialog's input.
pub(crate) const SFTP_INPUT_ID: &str = "sftp_input";
