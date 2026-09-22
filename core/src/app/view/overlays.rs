use super::*;
// Explicit: through the glob above, `column` is ambiguous with std's `column!`.
use iced::widget::column;

pub(crate) fn view_confirm_delete(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let name = state
        .confirm_delete
        .as_ref()
        .map(|(_, name)| name.as_str())
        .unwrap_or_default();
    let msg = i18n::tf("confirm.delete", &[("name", name)]);
    let card = modal_card(
        column![
            text(msg).color(state.c_primary()).size(14.0 * scale),
            vertical_space().height(12),
            row![
                button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
                    .on_press(Message::CancelDelete)
                    .padding(Padding::from([6, 16]))
                    .style(transparent_button_style),
                button(text(i18n::t("dialog.delete")).size(13.0 * scale))
                    .on_press(Message::ExecuteDelete)
                    .padding(Padding::from([6, 16]))
                    .style(filled_button_style(state.c_danger())),
            ]
            .spacing(12),
        ]
        .align_x(alignment::Horizontal::Center)
        .padding(24),
    );
    iced::widget::center(card).into()
}

// ---- Destructive-action confirmation (SFTP delete / chmod, kill) ------------

/// Same shape as the connection delete: the question, then exactly what it
/// will touch — the full remote path, or the process's command line — in a
/// block of its own, so nothing is confirmed on a truncated name.
pub(crate) fn view_confirm_action(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let Some(action) = &state.confirm_action else {
        return Space::new(0, 0).into();
    };
    // Which host, too: a tab switch can put a different one on screen.
    let session_id = match action {
        ConfirmAction::SftpDelete { session_id, .. }
        | ConfirmAction::SftpChmod { session_id, .. }
        | ConfirmAction::Kill { session_id, .. } => session_id,
    };
    let host = state.session_label(session_id);
    let (question, subject, marked) = confirm_action_text(action);
    let confirm_label = i18n::t(match action {
        ConfirmAction::SftpDelete { .. } => "tip.delete",
        ConfirmAction::SftpChmod { .. } => "sftp.apply",
        ConfirmAction::Kill { .. } => "process.send_signal",
    });
    let subject_block = container(
        text(subject)
            .font(Font::MONOSPACE)
            .color(theme::TEXT_SECONDARY)
            .size(12.0 * scale),
    )
    .padding(Padding::from([8, 10]))
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border { radius: 6.0.into(), width: 1.0, color: theme::BORDER },
        ..Default::default()
    });
    let host_line: Element<'_, Message> = if host.is_empty() {
        Space::new(0, 0).into()
    } else {
        text(i18n::tf("confirm.on_host", &[("host", &host)]))
            .font(Font::MONOSPACE)
            .color(theme::TEXT_MUTED)
            .size(11.0 * scale)
            .into()
    };
    // What the marks in the name stand for, when there are any.
    let marks_line: Element<'_, Message> = if marked {
        text(i18n::t("sftp.name_marks"))
            .color(theme::TEXT_MUTED)
            .size(11.0 * scale)
            .into()
    } else {
        Space::new(0, 0).into()
    };
    let card = modal_card(
        column![
            text(question).color(state.c_primary()).size(14.0 * scale),
            host_line,
            subject_block,
            marks_line,
            row![
                button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
                    .on_press(Message::ConfirmActionCancel)
                    .padding(Padding::from([6, 16]))
                    .style(transparent_button_style),
                horizontal_space(),
                button(text(confirm_label).size(13.0 * scale))
                    .on_press(Message::ConfirmActionExecute)
                    .padding(Padding::from([6, 16]))
                    .style(filled_button_style(state.c_danger())),
            ]
            .spacing(12)
            .align_y(alignment::Vertical::Center),
        ]
        .spacing(space::M)
        .padding(24)
        .width(480),
    );
    iced::widget::center(card).into()
}

/// What the confirmation of `action` says: the question, the block under it,
/// and whether those carry [`visible_name`] marks, which a line explains.
///
/// For an SFTP action the question quotes the name exactly and states what
/// the row showed it to be, with the full path under it — spaces at the ends
/// and anything invisible marked — so a decoy "project " cannot pass for
/// "project", nor a file for a folder. For a kill, the block is the command
/// line /proc gave as the confirmation opened.
pub(crate) fn confirm_action_text(action: &ConfirmAction) -> (String, String, bool) {
    match action {
        ConfirmAction::SftpDelete { path, name, kind, .. } => {
            let shown = visible_name(name);
            let subject = visible_path(path);
            let marked = shown != *name || subject != *path;
            let question = match kind {
                EntryKind::Dir => i18n::tf("sftp.confirm_delete_dir_named", &[("name", &shown)]),
                EntryKind::Symlink => {
                    i18n::tf("sftp.confirm_delete_link_named", &[("name", &shown)])
                }
                EntryKind::File | EntryKind::Other => i18n::tf(
                    "sftp.confirm_delete_named",
                    &[("kind", entry_kind_label(*kind)), ("name", &shown)],
                ),
            };
            (question, subject, marked)
        }
        ConfirmAction::SftpChmod { path, name, kind, mode, .. } => {
            let shown = visible_name(name);
            let subject = visible_path(path);
            let marked = shown != *name || subject != *path;
            let question = i18n::tf(
                "sftp.confirm_chmod_named",
                &[
                    ("kind", entry_kind_label(*kind)),
                    ("name", &shown),
                    ("mode", &format!("{:04o}", mode)),
                ],
            );
            (question, subject, marked)
        }
        ConfirmAction::Kill { pid, command, signal, .. } => (
            i18n::tf(
                "process.confirm_kill",
                &[("signal", &signal_name(*signal)), ("pid", &pid.to_string())],
            ),
            command.clone(),
            false,
        ),
    }
}

// ---- SFTP name / mode dialog -----------------------------------------------

pub(crate) fn view_sftp_input(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let Some(dialog) = &state.sftp_input else {
        return Space::new(0, 0).into();
    };
    let (title, hint) = match &dialog.kind {
        SftpInputKind::NewFolder => (
            i18n::tf("sftp.new_folder_title", &[("dir", &dialog.dir)]),
            i18n::t("sftp.name_hint"),
        ),
        SftpInputKind::Rename { from, kind, .. } => (
            i18n::tf(
                "sftp.rename_title_named",
                &[("kind", entry_kind_label(*kind)), ("name", &visible_name(from))],
            ),
            i18n::t("sftp.name_hint"),
        ),
        SftpInputKind::Chmod { name, kind, .. } => (
            i18n::tf(
                "sftp.chmod_title_named",
                &[("kind", entry_kind_label(*kind)), ("name", &visible_name(name))],
            ),
            i18n::t("sftp.mode_hint"),
        ),
    };
    let field = input("", &dialog.value)
        .id(text_input::Id::new(SFTP_INPUT_ID))
        .on_input(Message::SftpInputChanged)
        .on_submit(Message::SftpInputSubmit)
        .padding(Padding::from([8, 10]))
        .size(14.0 * scale);
    let mut content = column![
        text(title).size(15.0 * scale).color(state.c_primary()),
        text(hint).size(11.0 * scale).color(theme::TEXT_MUTED),
        field,
    ]
    .spacing(12)
    .width(400);
    // What the marks in the quoted name stand for, when there are any.
    let marked = match &dialog.kind {
        SftpInputKind::NewFolder => false,
        SftpInputKind::Rename { from: name, .. } | SftpInputKind::Chmod { name, .. } => {
            visible_name(name) != *name
        }
    };
    if marked {
        content = content.push(
            text(i18n::t("sftp.name_marks")).size(11.0 * scale).color(theme::TEXT_MUTED),
        );
    }
    if let Some(error) = dialog.error {
        content = content.push(text(i18n::t(error)).size(11.0 * scale).color(state.c_danger()));
    }
    content = content.push(
        row![
            button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
                .on_press(Message::SftpInputCancel)
                .padding(Padding::from([6, 16]))
                .style(transparent_button_style),
            horizontal_space(),
            button(text(i18n::t("sftp.ok")).size(12.0 * scale))
                .on_press(Message::SftpInputSubmit)
                .padding(Padding::from([6, 16]))
                .style(accent_button_style),
        ]
        .align_y(alignment::Vertical::Center),
    );
    iced::widget::center(modal_card(content).padding(20)).into()
}

// ---- Keyboard-interactive auth ---------------------------------------------

/// A keyboard-interactive challenge from an SSH server: its prompts, masked
/// where the server marked them non-echo. The SSH thread is blocked on the
/// answer, so every way out — Continue, Cancel, Esc, the vault lock —
/// resolves it.
pub(crate) fn view_auth_prompt(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let Some((challenge, _)) = state.auth_queue.front() else {
        return Space::new(0, 0).into();
    };
    // Apart from the labels, everything here was written by the server.
    let mut target = sanitize_remote_text(&challenge.target, 120);
    // The server may challenge a different user than the one we sent.
    let asked = sanitize_remote_text(&challenge.username, 64);
    if !asked.is_empty() && !target.starts_with(&format!("{}@", asked)) {
        target = format!("{} ({})", target, asked);
    }
    let mut head = column![
        text(i18n::t("auth.title")).size(16.0 * scale).color(state.c_primary()),
        text(format!("{} · {}", target, auth_purpose_label(&challenge.purpose)))
            .font(Font::MONOSPACE)
            .size(11.0 * scale)
            .color(theme::TEXT_SECONDARY),
        text(i18n::t("auth.from_server")).size(11.0 * scale).color(theme::TEXT_MUTED),
    ]
    .spacing(space::S);
    let instructions = sanitize_remote_text(&challenge.instructions, 600);
    if !instructions.is_empty() {
        head = head.push(text(instructions).size(12.0 * scale).color(theme::TEXT_SECONDARY));
    }

    let count = challenge.prompt.prompts.len();
    let mut fields = column![].spacing(space::M);
    for (i, (prompt, echo)) in challenge.prompt.prompts.iter().enumerate() {
        let value = state.auth_answers.get(i).map(String::as_str).unwrap_or("");
        // Enter moves to the next answer; on the last one it submits.
        let on_enter = if i + 1 < count { Message::AuthFocus(i + 1) } else { Message::AuthEnter };
        let field = input("", value)
            .id(auth_input_id(i))
            .on_input(move |v| Message::AuthAnswerChanged(i, v))
            .on_submit(on_enter)
            .secure(!*echo)
            .padding(8)
            .size(14.0 * scale);
        fields = fields.push(
            column![
                text(sanitize_remote_text(prompt, 200))
                    .size(12.0 * scale)
                    .color(theme::TEXT_SECONDARY),
                field,
            ]
            .spacing(4),
        );
    }

    let mut content = column![head, container(slim_scroll(fields)).max_height(320)]
        .spacing(space::M)
        .padding(24)
        .width(440);
    let waiting = state.auth_queue.len().saturating_sub(1);
    if waiting > 0 {
        content = content.push(
            text(i18n::tf("auth.queued", &[("count", &waiting.to_string())]))
                .size(10.0 * scale)
                .color(theme::TEXT_MUTED),
        );
    }
    content = content.push(
        row![
            button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
                .on_press(Message::AuthCancel)
                .padding(Padding::from([6, 16]))
                .style(transparent_button_style),
            horizontal_space(),
            button(text(i18n::t("auth.continue")).size(13.0 * scale))
                .on_press(Message::AuthSubmit)
                .padding(Padding::from([6, 16]))
                .style(accent_button_style),
        ]
        .align_y(alignment::Vertical::Center),
    );
    iced::widget::center(modal_card(content)).into()
}

// ---- Welcome screen (no active tab) --------------------------------------

// ---- Process detail popup ---------------------------------------------------

pub(crate) fn view_context_menu(ctx: &ContextMenu) -> Element<'static, Message> {
    let conn_id = ctx.conn_id.clone();
    let conn_id2 = ctx.conn_id.clone();
    let conn_id3 = ctx.conn_id.clone();

    let connect_item = button(
        text(i18n::t("dialog.connect_title").to_string()).color(theme::TEXT_PRIMARY).size(12)
    )
    .on_press(Message::ConnectTo(conn_id))
    .padding(Padding::from([6, 16]))
    .width(Fill)
    .style(sidebar_item_style);

    let edit_item = button(
        text(i18n::t("dialog.edit").to_string()).color(theme::TEXT_PRIMARY).size(12)
    )
    .on_press(Message::ShowForm(Some(conn_id2)))
    .padding(Padding::from([6, 16]))
    .width(Fill)
    .style(sidebar_item_style);

    let delete_item = button(
        text(i18n::t("dialog.delete").to_string()).color(theme::DANGER).size(12)
    )
    .on_press(Message::DeleteConnection(conn_id3))
    .padding(Padding::from([6, 16]))
    .width(Fill)
    .style(sidebar_item_style);

    let menu_card = container(
        column![connect_item, edit_item, delete_item].spacing(space::XXS).width(140)
    )
    .style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 6.0.into() },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(2.0, 2.0),
            blur_radius: 10.0,
        },
        ..Default::default()
    })
    .padding(4);

    // Position the menu at the click coordinates using padding trick
    let x = ctx.x.max(0.0);
    let y = ctx.y.max(0.0);

    // Transparent full-screen backdrop that closes menu on click
    let backdrop = button(Space::new(Fill, Fill))
        .on_press(Message::HideContextMenu)
        .style(|_: &Theme, _| button::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.01).into()),
            ..Default::default()
        });

    stack([
        backdrop.width(Fill).height(Fill).into(),
        container(menu_card)
            .padding(Padding::new(0.0).top(y).left(x))
            .width(Fill)
            .height(Fill)
            .into(),
    ])
    .into()
}

// ---- Context menu (right-click in the remote file browser) ------------------

/// "New folder" always; Rename, Permissions and Delete for a real row. Opened
/// at the pointer and kept inside the window — the browser sits low, so it
/// usually opens upward.
pub(crate) fn view_remote_menu<'a>(state: &'a NeoShell, menu: &RemoteFileMenu) -> Element<'a, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let item = |label: &str, color: Color, msg: Message| -> Element<'a, Message> {
        button(text(label.to_string()).color(color).size(12.0 * scale))
            .on_press(msg)
            .padding(Padding::from([6, 16]))
            .width(Fill)
            .style(sidebar_item_style)
            .into()
    };
    let mut items = column![item(i18n::t("sftp.new_folder"), c_primary, Message::SftpNewFolder)]
        .spacing(space::XXS)
        .width(180);
    let rows = if let Some(entry) = &menu.entry {
        items = items.push(item(i18n::t("sftp.rename"), c_primary, Message::SftpRename));
        // Over SFTP a symlink's permissions cannot be changed, only its
        // target's — which the SSH layer refuses — so it is not offered.
        let chmod = entry.kind() != EntryKind::Symlink;
        if chmod {
            items = items.push(item(i18n::t("sftp.permissions"), c_primary, Message::SftpChmod));
        }
        items = items.push(item(i18n::t("sftp.delete"), state.c_danger(), Message::SftpDelete));
        if chmod { 4.0 } else { 3.0 }
    } else {
        1.0
    };

    let card = container(items)
        .style(|_| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border { color: theme::BORDER, width: 1.0, radius: 6.0.into() },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
                offset: iced::Vector::new(2.0, 2.0),
                blur_radius: 10.0,
            },
            ..Default::default()
        })
        .padding(4);

    // Estimated card size, only to keep it on screen.
    let (w, h) = (188.0, rows * (16.0 * scale + 14.0) + 10.0);
    let x = menu.x.min(state.window_width - w).max(0.0);
    let y = if menu.y + h > state.window_height {
        (menu.y - h).max(0.0)
    } else {
        menu.y
    };

    // Transparent full-window backdrop: a click anywhere else closes the menu.
    let backdrop = button(Space::new(Fill, Fill))
        .on_press(Message::RemoteMenuClose)
        .style(|_: &Theme, _| button::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.01).into()),
            ..Default::default()
        });

    stack([
        backdrop.width(Fill).height(Fill).into(),
        container(card)
            .padding(Padding::new(0.0).top(y).left(x))
            .width(Fill)
            .height(Fill)
            .into(),
    ])
    .into()
}

// ---- Toolbar (top action bar) -----------------------------------------------

pub(crate) fn view_editor(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let file_name = state.editor_file_path.as_deref().unwrap_or("untitled");

    let title_text = if state.editor_dirty {
        format!("* {} (modified)", file_name)
    } else {
        format!("  {}", file_name)
    };

    let title = text(title_text).color(c_primary).size(14.0 * scale);

    let save_btn = button(text(i18n::t("editor.save")).size(13.0 * scale))
        .on_press(Message::SaveEditor)
        .padding(Padding::from([6, 16]))
        .style(accent_button_style);

    let close_btn = button(text(i18n::t("editor.close")).color(theme::TEXT_SECONDARY).size(13.0 * scale))
        .on_press(Message::CloseEditor)
        .padding(Padding::from([6, 16]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), save_btn, close_btn]
        .spacing(8)
        .align_y(alignment::Vertical::Center)
        .padding(Padding::from([8, 12]));

    let header_bar = container(header)
        .width(Fill)
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        });

    let editor = text_editor(&state.editor_content)
        .on_action(Message::EditorAction)

        .size(13.0 * scale)
        .height(Fill);

    let content = column![header_bar, editor].height(Fill);

    // Large modal: fills the window up to 1000×700.
    iced::widget::center(
        modal_card(content)
            .width(Fill)
            .height(Fill)
            .max_width(1000)
            .max_height(700),
    )
    .into()
}

// ---- Status bar ----------------------------------------------------------

// ---- Proxy manager ----------------------------------------------------------

pub(crate) fn view_history_panel(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("history.title")).size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideHistory)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let clear_btn = button(text(i18n::t("history.clear")).color(c_danger).size(11.0 * scale))
        .on_press(Message::ClearHistory)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), clear_btn, tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);

    let filter_input = input(i18n::t("history.filter"), &state.history_filter)
        .on_input(Message::HistoryFilterChanged)
        .padding(8)
        .size(13.0 * scale);

    let filter_lower = state.history_filter.to_lowercase();

    // Build list (newest first), filtered
    let mut list_col = column![].spacing(2);
    let mut shown = 0;
    let now = unix_now();
    for record in state.cmd_history.iter().rev() {
        if !filter_lower.is_empty() && !record.cmd.to_lowercase().contains(&filter_lower) {
            continue;
        }
        if shown >= 100 { break; }
        shown += 1;

        let ago = format_ago(now.saturating_sub(record.timestamp));

        let cmd_text = text(truncate_str(&record.cmd, 50))
            .font(Font::MONOSPACE)
            .color(c_primary)
            .size(12.0 * scale);
        // A split pane's session has no title of its own; its host does.
        let origin = if record.session_title.is_empty() { &record.host } else { &record.session_title };
        // A tab title — cut by display width, whole in a tooltip.
        let (origin_text, origin_cut) = clip_to_width(origin, 18);
        let session_text = tip_if(
            text(origin_text).color(theme::TEXT_MUTED).size(10.0 * scale),
            origin_cut,
            origin,
        );
        let ago_text = text(ago).color(theme::TEXT_MUTED).size(10.0 * scale);

        let replay_btn = button(text(">").font(Font::MONOSPACE).color(c_success).size(12.0 * scale))
            .on_press(Message::ReplayCommand(record.cmd.clone()))
            .padding(Padding::from([2, 8]))
            .style(transparent_button_style);

        let entry_row = row![
            column![cmd_text, session_text].spacing(2).width(Fill),
            ago_text,
            tip(replay_btn, i18n::t("tip.replay")),
        ]
        .spacing(8)
        .align_y(alignment::Vertical::Center);

        let i = shown;
        let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
        list_col = list_col.push(
            button(entry_row)
                .on_press(Message::ReplayCommand(record.cmd.clone()))
                .padding(Padding::from([6, 10]))
                .width(Fill)
                .style(move |_theme: &Theme, status| {
                    let mut s = button::Style::default();
                    s.background = Some(row_bg.into());
                    if let button::Status::Hovered = status {
                        s.background = Some(theme::BG_HOVER.into());
                    }
                    s
                }),
        );
    }

    if shown == 0 {
        list_col = list_col.push(
            container(text(i18n::t("history.empty")).color(theme::TEXT_MUTED).size(13.0 * scale))
                .padding(Padding::from([20, 12])),
        );
    }

    let content = column![
        header,
        filter_input,
        slim_scroll(list_col).height(Fill),
    ]
    .spacing(8)
    .padding(16)
    .width(500)
    .height(Fill);

    let card = container(content)
        .height(Fill)
        .style(|_| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.4),
                offset: iced::Vector::new(-4.0, 0.0),
                blur_radius: 16.0,
            },
            ..Default::default()
        });

    // Slide in from right, over the shared scrim.
    let overlay = row![horizontal_space(), card];

    container(overlay).width(Fill).height(Fill).into()
}

// ---- Settings menu (dropdown-style overlay) --------------------------------

pub(crate) fn view_about_dialog(_state: &NeoShell) -> Element<'static, Message> {
    // About dialog returns 'static; use static theme consts rather than state lookups.
    let title = text(i18n::t("about.title").to_string()).size(22).color(theme::TEXT_PRIMARY);
    let version_str = i18n::tf("about.version", &[("version", env!("CARGO_PKG_VERSION"))]);
    let version = text(version_str).size(14).color(theme::ACCENT);
    let desc = text(i18n::t("about.desc").to_string()).size(13).color(theme::TEXT_SECONDARY);
    let tech = text(i18n::t("about.tech").to_string()).size(11).color(theme::TEXT_MUTED);
    let copyright = text(i18n::t("about.copyright").to_string()).size(11).color(theme::TEXT_MUTED);

    let close_btn = button(
        text(i18n::t("about.close").to_string()).color(theme::TEXT_SECONDARY).size(13)
    )
    .on_press(Message::HideAbout)
    .padding(Padding::from([6, 20]))
    .style(transparent_button_style);

    let content = column![
        text("NeoShell").font(Font::MONOSPACE).size(32).color(theme::ACCENT),
        title,
        version,
        vertical_space().height(8),
        desc,
        vertical_space().height(4),
        tech,
        vertical_space().height(12),
        copyright,
        vertical_space().height(8),
        close_btn,
    ]
    .spacing(4)
    .align_x(alignment::Horizontal::Center)
    .padding(32)
    .width(360);

    iced::widget::center(modal_card(content)).into()
}

// ---- Keyboard shortcuts help ----------------------------------------------

pub(crate) fn view_shortcuts_help() -> Element<'static, Message> {
    // Platform-specific modifier key label. On macOS the command key is the
    // primary modifier, on Windows/Linux it's Ctrl. Same binding code — the
    // `modifiers.command()` check in update() maps to whichever is native.
    #[cfg(target_os = "macos")]
    let m_key = "⌘";
    #[cfg(not(target_os = "macos"))]
    let m_key = "Ctrl";

    // Groups of shortcuts. Each entry is (accelerator-label, i18n-desc-key).
    // The accelerator column is rendered in a monospace pill so Cmd/Ctrl
    // columns stay aligned regardless of translation width.
    let groups: &[(&'static str, Vec<(String, &'static str)>)] = &[
        (
            "shortcuts.group.tabs",
            vec![
                (format!("{}+T", m_key), "shortcuts.desc.connect"),
                (format!("{}+W", m_key), "shortcuts.desc.close_tab"),
                (format!("{}+1…9", m_key), "shortcuts.desc.switch_tab"),
                ("Ctrl+Tab".into(), "shortcuts.desc.next_tab"),
                ("Ctrl+Shift+Tab".into(), "shortcuts.desc.prev_tab"),
                ("2×Click".into(), "shortcuts.desc.rename_tab"),
            ],
        ),
        (
            "shortcuts.group.split",
            vec![
                (format!("{}+D", m_key), "shortcuts.desc.split_v"),
                (format!("{}+Shift+D", m_key), "shortcuts.desc.split_h"),
                (format!("{}+]", m_key), "shortcuts.desc.split_focus"),
                (format!("{}+Shift+W", m_key), "shortcuts.desc.split_close"),
            ],
        ),
        (
            "shortcuts.group.terminal",
            vec![
                // Platform-aware copy/paste accelerators. Win/Linux uses
                // Ctrl+Shift+C/V so plain Ctrl+C still sends SIGINT.
                (
                    if cfg!(target_os = "macos") { format!("{}+V", m_key) } else { "Ctrl+Shift+V".into() },
                    "shortcuts.desc.paste",
                ),
                (
                    if cfg!(target_os = "macos") { format!("{}+C", m_key) } else { "Ctrl+Shift+C".into() },
                    "shortcuts.desc.copy",
                ),
                (i18n::t("shortcuts.key.drag").into(),        "shortcuts.desc.mouse_select"),
                (i18n::t("shortcuts.key.shift_drag").into(),  "shortcuts.desc.shift_select"),
                (i18n::t("shortcuts.key.right_click").into(), "shortcuts.desc.right_click"),
                (i18n::t("shortcuts.key.drop").into(),        "shortcuts.desc.drop_upload"),
                ("Ctrl+C".into(),     "shortcuts.desc.sigint"),
                (format!("{}+F", m_key), "shortcuts.desc.search"),
                ("Enter".into(), "shortcuts.desc.search_next"),
                ("Esc".into(), "shortcuts.desc.search_close"),
            ],
        ),
        (
            "shortcuts.group.panels",
            vec![
                (format!("{}+K", m_key), "shortcuts.desc.palette"),
                (format!("{}+J", m_key), "shortcuts.desc.bottom_toggle"),
                (format!("{}+H", m_key), "shortcuts.desc.history"),
                (format!("{}+/", m_key), "shortcuts.desc.help"),
                ("F1".into(), "shortcuts.desc.help"),
            ],
        ),
        (
            "shortcuts.group.other",
            vec![
                (format!("{}+S", m_key), "shortcuts.desc.editor_save"),
                ("Esc".into(), "shortcuts.desc.close_dialog"),
                (format!("{}+Shift+L", m_key), "shortcuts.desc.lock"),
                (format!("{}+Shift+Q", m_key), "shortcuts.desc.quit"),
            ],
        ),
    ];

    let title = text(i18n::t("shortcuts.title").to_string())
        .size(22).color(theme::TEXT_PRIMARY);

    let mut rows_col = column![].spacing(space::L);
    for (group_key, entries) in groups {
        rows_col = rows_col.push(
            text(i18n::t(group_key).to_string())
                .color(theme::TEXT_MUTED)
                .size(11)
        );
        let mut group_col = column![].spacing(4);
        for (accel, desc_key) in entries {
            group_col = group_col.push(
                row![
                    container(
                        text(accel.clone())
                            .font(Font::MONOSPACE)
                            .color(theme::ACCENT)
                            .size(12)
                    )
                    .padding(Padding::from([2, 8]))
                    .style(|_| container::Style {
                        background: Some(theme::BG_TERTIARY.into()),
                        border: iced::Border {
                            radius: 4.0.into(),
                            width: 1.0,
                            color: theme::BORDER,
                        },
                        ..Default::default()
                    })
                    .width(Length::Fixed(150.0)),
                    text(i18n::t(desc_key).to_string())
                        .color(theme::TEXT_SECONDARY)
                        .size(12),
                ]
                .spacing(12)
                .align_y(alignment::Vertical::Center),
            );
        }
        rows_col = rows_col.push(group_col);
    }

    let close_btn = button(
        text(i18n::t("shortcuts.close").to_string()).color(theme::TEXT_SECONDARY).size(13)
    )
    .on_press(Message::ToggleShortcutsHelp)
    .padding(Padding::from([6, 20]))
    .style(transparent_button_style);

    let content = column![
        title,
        vertical_space().height(14),
        rows_col,
        vertical_space().height(18),
        close_btn,
    ]
    .align_x(alignment::Horizontal::Center)
    .padding(28)
    .width(500);

    iced::widget::center(modal_card(content)).into()
}

// ---- Error dialog ----------------------------------------------------------

pub(crate) fn view_error_dialog(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title_key = error_dialog_title(state.error_title, &state.error_message);
    let title = text(i18n::t(title_key)).size(16.0 * scale).color(c_danger);

    // Full error, wrapped; no truncation
    let msg = text(state.error_message.clone()).size(13.0 * scale).color(c_primary);

    let log_btn = button(text(i18n::t("err.view_log")).color(c_accent).size(12.0 * scale))
        .on_press(Message::ShowLogViewer)
        .padding(Padding::from([6, 14]))
        .style(transparent_button_style);

    let dismiss_btn = button(text(i18n::t("err.dismiss")).size(12.0 * scale))
        .on_press(Message::DismissErrorDialog)
        .padding(Padding::from([6, 18]))
        .style(accent_button_style);

    // Text widgets cannot be selected in iced, so copying is a button.
    let copied = state.error_copied == Some(fingerprint(&state.error_message));
    let copy_btn = button(
        text(i18n::t(if copied { "err.copied" } else { "err.copy" })).size(12.0 * scale),
    )
    .on_press(Message::CopyErrorText)
    .padding(Padding::from([6, 14]))
    .style(outline_button_style);

    let content = column![
        title,
        vertical_space().height(8),
        // Shrinks to a one-line error, scrolls past 260px.
        container(slim_scroll(container(msg).padding(8).width(Fill))).max_height(260),
        vertical_space().height(8),
        row![log_btn, horizontal_space(), copy_btn, dismiss_btn]
            .spacing(space::S)
            .align_y(alignment::Vertical::Center),
    ]
    .spacing(4)
    .padding(24)
    .width(540);

    let border = c_danger;
    iced::widget::center(modal_card(content).style(move |_| modal_card_style(border))).into()
}

// ---- Log viewer ------------------------------------------------------------

pub(crate) fn view_log_viewer(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("log.title")).size(18.0 * scale).color(c_primary);
    let path_hint = {
        let p = crate::log_file_path();
        text(format!("{}", p.display())).color(theme::TEXT_MUTED).size(10.0 * scale)
    };

    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(13.0 * scale))
        .on_press(Message::HideLogViewer)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let refresh_btn = button(text(i18n::t("log.refresh")).color(c_accent).size(11.0 * scale))
        .on_press(Message::RefreshLogViewer)
        .padding(Padding::from([4, 10]))
        .style(transparent_button_style);

    let open_folder_btn = button(text(i18n::t("log.open_folder")).color(c_accent).size(11.0 * scale))
        .on_press(Message::OpenLogFolder)
        .padding(Padding::from([4, 10]))
        .style(transparent_button_style);

    let header = row![
        title, horizontal_space(), refresh_btn, open_folder_btn, tip(close_btn, i18n::t("tip.close")),
    ].spacing(space::S).align_y(alignment::Vertical::Center);

    // Render log content as monospace text, scrollable
    let body = text(state.log_viewer_content.clone())
        .font(Font::MONOSPACE)
        .color(theme::TEXT_SECONDARY)
        .size(11.0 * scale);

    let content = column![
        header,
        path_hint,
        vertical_space().height(8),
        slim_scroll(container(body).padding(10).width(Fill)).height(Fill),
    ]
    .spacing(4)
    .padding(20)
    .width(780)
    .height(520);

    iced::widget::center(modal_card(content)).into()
}

// ---- Broadcast dialog ------------------------------------------------------

// ---- v0.7.0: Cmd+K command palette ----------------------------------------

pub(crate) fn view_palette(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();

    let input = input(&i18n::t("palette.placeholder"), &state.palette_query)
        .id(text_input::Id::new(PALETTE_INPUT_ID))
        .on_input(Message::PaletteQueryChanged)
        .on_submit(Message::PaletteExecute)
        .padding(Padding::from([10, 14]))
        .size(15.0 * scale);

    // Selected row: AA-safe accent fill and the label colour that reads on it.
    let (sel_fill, sel_label) = fill_and_label(c_accent);
    let items = state.palette_items();
    let mut list = column![].spacing(2);
    if items.is_empty() {
        list = list.push(
            container(
                text(i18n::t("palette.empty"))
                    .color(theme::TEXT_MUTED)
                    .size(12.0 * scale),
            )
            .padding(Padding::from([10, 14])),
        );
    }
    for (i, item) in items.iter().enumerate() {
        let selected = i == state.palette_selected;
        let kind_chip = container(
            text(i18n::t(item.kind))
                .size(9.0 * scale)
                .color(if selected { sel_label } else { theme::TEXT_MUTED }),
        )
        .padding(Padding::from([2, 6]))
        .style(move |_| container::Style {
            background: Some(if selected {
                tint(sel_label, 0.18).into()
            } else {
                theme::BG_TERTIARY.into()
            }),
            border: iced::Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        });

        // Cut by display width — a Chinese name is twice as wide as its
        // character count — to budgets that follow the UI font size, with
        // the full text a hover away.
        let ((label_text, label_cut), (meta_text, meta_cut)) =
            palette_row_text(&item.label, &item.meta, scale);
        let label = tip_if(
            text(label_text)
                .size(13.0 * scale)
                .color(if selected { sel_label } else { c_primary })
                .wrapping(iced::widget::text::Wrapping::None),
            label_cut,
            &item.label,
        );
        let meta = tip_if(
            text(meta_text)
                .size(11.0 * scale)
                .color(if selected {
                    tint(sel_label, 0.85)
                } else {
                    theme::TEXT_MUTED
                })
                .wrapping(iced::widget::text::Wrapping::None),
            meta_cut,
            &item.meta,
        );

        let row_el = row![kind_chip, label, horizontal_space(), meta]
            .spacing(space::M)
            .align_y(alignment::Vertical::Center);

        list = list.push(
            button(row_el)
                .on_press(Message::PaletteExecuteIndex(i))
                .padding(Padding::from([8, 12]))
                .width(Fill)
                .style(move |_, _| button::Style {
                    background: Some(if selected {
                        sel_fill.into()
                    } else {
                        Color::TRANSPARENT.into()
                    }),
                    text_color: if selected { sel_label } else { c_primary },
                    border: iced::Border {
                        radius: 6.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
        );
    }

    let hint = text(i18n::t("palette.hint"))
        .size(10.0 * scale)
        .color(theme::TEXT_MUTED);

    let card = modal_card(column![input, list, hint].spacing(space::M).width(560)).padding(16);

    // Pin the card to the upper third — palettes feel wrong centered.
    container(
        column![Space::with_height(Length::Fixed(90.0)), card]
            .align_x(alignment::Horizontal::Center)
            .width(Fill),
    )
    .width(Fill)
    .height(Fill)
    .into()
}

// ---- v0.7.0: tab rename dialog ---------------------------------------------

pub(crate) fn view_tab_rename(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();

    let input = input(&i18n::t("tabrename.placeholder"), &state.tab_rename_input)
        .id(text_input::Id::new(TAB_RENAME_INPUT_ID))
        .on_input(Message::TabRenameInput)
        .on_submit(Message::TabRenameCommit)
        .padding(Padding::from([8, 10]))
        .size(14.0 * scale);

    let buttons = row![
        button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
            .on_press(Message::TabRenameCancel)
            .padding(Padding::from([6, 16]))
            .style(transparent_button_style),
        horizontal_space(),
        button(text(i18n::t("tabrename.save")).size(12.0 * scale))
            .on_press(Message::TabRenameCommit)
            .padding(Padding::from([6, 16]))
            .style(accent_button_style),
    ]
    .align_y(alignment::Vertical::Center);

    let card = modal_card(
        column![
            text(i18n::t("tabrename.title")).size(15.0 * scale).color(c_primary),
            text(i18n::t("tabrename.hint")).size(11.0 * scale).color(theme::TEXT_MUTED),
            input,
            buttons,
        ]
        .spacing(12)
        .width(380),
    )
    .padding(20);

    iced::widget::center(card).into()
}

// ---- v0.7.0: SSH key manager ------------------------------------------------

pub(crate) fn view_broadcast_dialog(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_success = state.c_success();

    let title = text(i18n::t("broadcast.title")).color(c_primary).size(16.0 * scale);
    let close_btn = button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideBroadcastDialog).padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);
    let hint = text(i18n::t("broadcast.hint")).color(theme::TEXT_MUTED).size(11.0 * scale);

    let cmd_input = input("echo hello", &state.broadcast_text)
        .on_input(Message::BroadcastTextChanged)
        .on_submit(Message::BroadcastSendNow)
        .padding(8).size(13.0 * scale).font(Font::MONOSPACE);

    let sessions_title = text(i18n::t("broadcast.sessions")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
    let mut sessions_col = column![].spacing(4);
    // Sessions = every main pane plus every split pane.
    let mut entries: Vec<(String, String)> = Vec::new();
    for tab in &state.tabs {
        if !tab.session_id.is_empty() {
            entries.push((tab.session_id.clone(), tab.display_title().to_string()));
        }
        if let Some(sp) = &tab.split {
            if !sp.session_id.is_empty() {
                entries.push((
                    sp.session_id.clone(),
                    i18n::tf("tab.split_suffix", &[("title", tab.display_title())]),
                ));
            }
        }
    }
    if entries.is_empty() {
        sessions_col = sessions_col.push(
            text(i18n::t("broadcast.empty")).color(theme::TEXT_MUTED).size(11.0 * scale)
        );
    } else {
        for (sid, title) in entries {
            let selected = state.broadcast_selected.contains(&sid);
            let marker = if selected { "●" } else { "○" };
            let marker_color = if selected { c_success } else { theme::TEXT_MUTED };
            let label = text(format!(" {}", title)).color(c_primary).size(12.0 * scale);
            let row_btn = button(
                row![text(marker).color(marker_color).size(12.0 * scale), label]
                    .align_y(alignment::Vertical::Center)
            )
            .on_press(Message::BroadcastToggleSession(sid))
            .padding(Padding::from([4, 8]))
            .width(Fill)
            .style(sidebar_item_style);
            sessions_col = sessions_col.push(row_btn);
        }
    }

    let count = state.broadcast_selected.len();
    let send_btn = button(
        text(format!("{} ({})", i18n::t("broadcast.send"), count)).size(12.0 * scale)
    )
    .on_press(Message::BroadcastSendNow)
    .padding(Padding::from([6, 16]))
    .style(accent_button_style);

    // Live sync toggle: while ON, every keystroke in the focused terminal
    // is mirrored to all ticked sessions in real time.
    let sync_on = state.sync_input_on;
    let sync_label = if sync_on {
        i18n::t("broadcast.sync_on")
    } else {
        i18n::t("broadcast.sync_off")
    };
    let sync_btn = button(
        text(sync_label)
            .size(12.0 * scale)
            .color(if sync_on { Color::WHITE } else { theme::TEXT_SECONDARY }),
    )
    .on_press(Message::ToggleSyncInput)
    .padding(Padding::from([6, 16]))
    .style(move |_, _| button::Style {
        background: Some(if sync_on {
            theme::DANGER.into()
        } else {
            theme::BG_TERTIARY.into()
        }),
        text_color: if sync_on { Color::WHITE } else { theme::TEXT_SECONDARY },
        border: iced::Border {
            radius: 6.0.into(),
            width: 1.0,
            color: theme::BORDER,
        },
        ..Default::default()
    });
    let sync_hint = text(i18n::t("broadcast.sync_hint"))
        .size(10.0 * scale)
        .color(theme::TEXT_MUTED);

    let body = column![header, hint, cmd_input, sessions_title, slim_scroll(sessions_col).height(220),
        sync_hint,
        row![sync_btn, horizontal_space(), send_btn].align_y(alignment::Vertical::Center)
    ].spacing(space::M).padding(20).width(520);

    iced::widget::center(modal_card(body)).into()
}

// ---- Snippets panel --------------------------------------------------------

pub(crate) fn view_snippets_panel(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_danger = state.c_danger();

    let title = text(i18n::t("snippet.title")).color(c_primary).size(16.0 * scale);
    let close_btn = button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideSnippetsPanel).padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let header = row![title, horizontal_space(), tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(4);
    if state.snippets.is_empty() {
        list_col = list_col.push(text(i18n::t("snippet.empty")).color(theme::TEXT_MUTED).size(12.0 * scale));
    } else {
        for sn in &state.snippets {
            let id = sn.id.clone();
            let id2 = sn.id.clone();
            let id3 = sn.id.clone();
            let snip_row = row![
                column![
                    text(sn.name.clone()).color(c_primary).size(13.0 * scale),
                    text(sn.body.lines().next().unwrap_or("").to_string())
                        .font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale),
                ].spacing(2).width(Fill),
                button(text(i18n::t("snippet.send")).color(c_accent).size(10.0 * scale))
                    .on_press(Message::SnippetSend(id))
                    .padding(Padding::from([2, 6])).style(transparent_button_style),
                tip(
                    button(text(i18n::t("btn.edit")).color(theme::TEXT_SECONDARY).size(10.0 * scale))
                        .on_press(Message::SnippetEdit(Some(id2)))
                        .padding(Padding::from([2, 6])).style(transparent_button_style),
                    i18n::t("dialog.edit"),
                ),
                tip(
                    button(text("×").color(c_danger).size(12.0 * scale))
                        .on_press(Message::SnippetDelete(id3))
                        .padding(Padding::from([2, 6])).style(transparent_button_style),
                    i18n::t("tip.delete"),
                ),
            ].spacing(4).align_y(alignment::Vertical::Center);
            list_col = list_col.push(
                container(snip_row).padding(Padding::from([6, 10])).width(Fill)
                    .style(|_| container::Style {
                        background: Some(theme::BG_TERTIARY.into()),
                        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                        ..Default::default()
                    })
            );
        }
    }

    let form_title_key = if state.snippet_edit_id.is_some() { "btn.edit" } else { "snippet.new" };
    let form_title = text(i18n::t(form_title_key)).color(theme::TEXT_SECONDARY).size(12.0 * scale);
    let name_input = input(i18n::t("snippet.name_placeholder"), &state.snippet_form_name)
        .on_input(Message::SnippetFormNameChanged)
        .padding(6).size(12.0 * scale);
    let body_input = input(i18n::t("snippet.body_placeholder"), &state.snippet_form_body)
        .on_input(Message::SnippetFormBodyChanged)
        .padding(6).size(12.0 * scale).font(Font::MONOSPACE);
    let save_btn = button(text(i18n::t("snippet.save")).size(11.0 * scale))
        .on_press(Message::SnippetSave).padding(Padding::from([4, 12])).style(accent_button_style);
    let cancel_btn: Element<'_, Message> = if state.snippet_edit_id.is_some() {
        button(text(i18n::t("form.cancel")).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::SnippetEdit(None)).padding(Padding::from([4, 8]))
            .style(transparent_button_style).into()
    } else {
        Space::new(0, 0).into()
    };

    let body = column![
        header,
        slim_scroll(list_col).height(280),
        container(Space::new(Fill, 1)).style(|_| container::Style {
            background: Some(theme::BORDER.into()), ..Default::default()
        }),
        form_title,
        name_input,
        body_input,
        row![horizontal_space(), cancel_btn, save_btn].spacing(8),
    ].spacing(space::M).padding(20).width(560);

    iced::widget::center(modal_card(body)).into()
}

// ---- Status bar ------------------------------------------------------------

/// The error dialog's title for `message`: the notice title bound to that
/// very message (`NeoShell::show_notice`), else the connection-error one.
pub(crate) fn error_dialog_title(title: Option<(u64, &'static str)>, message: &str) -> &'static str {
    match title {
        Some((bound, key)) if bound == fingerprint(message) => key,
        _ => "err.title",
    }
}

// ---------------------------------------------------------------------------
// v0.7.0 feature wiring helpers
// ---------------------------------------------------------------------------
