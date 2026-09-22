//! The top-level views; the rest are split by area below.

use super::*;
// Explicit: through the glob above, `column` is ambiguous with std's `column!`.
use iced::widget::column;

mod files;
mod forms;
mod overlays;
mod panels;
mod sidebar;
mod terminal;
pub(crate) use files::*;
pub(crate) use forms::*;
pub(crate) use overlays::*;
pub(crate) use panels::*;
pub(crate) use sidebar::*;
pub(crate) use terminal::*;

pub(crate) fn view(state: &NeoShell) -> Element<'_, Message> {
    match &state.screen {
        Screen::Setup => view_setup(state),
        Screen::Locked => view_unlock(state),
        Screen::Main => view_main(state),
    }
}

// ---- Setup screen --------------------------------------------------------

pub(crate) fn view_setup(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("setup.title"))
        .size(22.0 * scale)
        .color(c_primary);

    let subtitle = text(i18n::t("setup.subtitle"))
        .size(12.5 * scale)
        .color(theme::TEXT_SECONDARY);

    let pw_input = input(&i18n::t("setup.password_placeholder"), &state.password_input)
        .on_input(Message::PasswordChanged)
        .secure(true)
        .padding(Padding::from([9, 12]))
        .size(14.0 * scale)
        .id(text_input::Id::new(SETUP_PW_INPUT_ID));

    let confirm_input = input(&i18n::t("setup.confirm_placeholder"), &state.confirm_input)
        .on_input(Message::ConfirmChanged)
        .on_submit(Message::CreateVault)
        .secure(true)
        .padding(Padding::from([9, 12]))
        .size(14.0 * scale)
        .id(text_input::Id::new(SETUP_CONFIRM_INPUT_ID));

    let create_btn = button(
        text(i18n::t("setup.create_vault")).size(13.0 * scale),
    )
    .on_press(Message::CreateVault)
    .padding(Padding::from([8, 22]))
    .style(accent_button_style);

    let error_text = if state.error_message.is_empty() {
        text("").size(1.0 * scale)
    } else {
        text(&state.error_message).color(c_danger).size(12.0 * scale)
    };

    let form = column![title, subtitle, pw_input, confirm_input, error_text, create_btn]
        .spacing(space::M)
        .align_x(alignment::Horizontal::Center)
        .width(320);

    container(form)
        .center_x(Fill)
        .center_y(Fill)
        .width(Fill)
        .height(Fill)
        .style(bg_primary_container)
        .into()
}

// ---- Unlock screen -------------------------------------------------------

pub(crate) fn view_unlock(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("unlock.title"))
        .size(22.0 * scale)
        .color(c_primary);

    let subtitle = text(i18n::t("unlock.subtitle"))
        .size(12.5 * scale)
        .color(theme::TEXT_SECONDARY);

    let pw_input = input(&i18n::t("unlock.password_placeholder"), &state.password_input)
        .on_input(Message::PasswordChanged)
        .on_submit(Message::UnlockVault)
        .secure(true)
        .padding(Padding::from([9, 12]))
        .size(14.0 * scale)
        .id(text_input::Id::new(UNLOCK_PW_INPUT_ID));

    let unlock_btn = button(
        text(i18n::t("unlock.btn")).size(13.0 * scale),
    )
    .on_press(Message::UnlockVault)
    .padding(Padding::from([8, 22]))
    .style(accent_button_style);

    let error_text = if state.error_message.is_empty() {
        text("").size(1.0 * scale)
    } else {
        text(&state.error_message).color(c_danger).size(12.0 * scale)
    };

    let form = column![title, subtitle, pw_input, error_text, unlock_btn]
        .spacing(space::M)
        .align_x(alignment::Horizontal::Center)
        .width(320);

    container(form)
        .center_x(Fill)
        .center_y(Fill)
        .width(Fill)
        .height(Fill)
        .style(bg_primary_container)
        .into()
}

// ---- Main screen (FinalShell-inspired layout) -----------------------------
//
//  ┌──────────────────────────────────────────────────────┐
//  │  Toolbar  [+New] [Proxy] [History] [Settings]        │
//  ├──────────────────────────────────────────────────────┤
//  │  Tab bar  [tab1] [tab2] [+]                          │
//  ├────────────┬─────────────────────────────────────────┤
//  │ Connections│           Terminal                       │
//  │ (left 220) │       (center, Fill)                    │
//  │            ├─────────────────────────────────────────┤
//  │  search    │ [Monitor|Files|Cmd]  bottom panel 220px │
//  │  list...   │  (tabbed panel with content)            │
//  ├────────────┴─────────────────────────────────────────┤
//  │  Status bar                                          │
//  └──────────────────────────────────────────────────────┘

pub(crate) fn view_main(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let toolbar = view_toolbar(state);
    let tab_bar = view_tab_bar(state);
    let status_bar = view_status_bar(state);

    let sidebar_width: f32 = if state.sidebar_collapsed { 0.0 } else { SIDEBAR_W };

    // ── Left: connection list (always visible) ──────────────────────
    let left_panel: Element<'_, Message> = if state.sidebar_collapsed {
        Space::new(0, 0).into()
    } else {
        container(view_sidebar(state))
            .width(sidebar_width)
            .height(Fill)
            .into()
    };

    // ── Right side ──────────────────────────────────────────────────
    let right_content: Element<'_, Message> = if state.active_tab.is_some() {
        // Terminal (upper) + bottom panel (lower)
        let terminal = view_terminal_area(state);

        // Transfer progress bar (if active)
        let mut terminal_col = column![
            container(terminal).height(Fill),
        ];
        if let Some(progress) = &state.transfer_progress {
            if !progress.is_finished() {
                terminal_col = terminal_col.push(view_transfer_progress(progress));
            }
        }

        // Drag splitter handle with centered collapse/expand chevron button.
        // Drag still works on either side of the chevron (button captures its
        // own click, everything else on the splitter bar hits TerminalMouseDown
        // via the Ignored-status path).
        let drag_color = if state.dragging_splitter { theme::ACCENT } else { theme::BORDER };
        let chevron_label = if state.bottom_panel_collapsed { "∧" } else { "∨" };
        let chevron_tip = if state.bottom_panel_collapsed { "tip.panel_show" } else { "tip.panel_hide" };
        let chevron_btn = button(
            text(chevron_label)
                .size(11.0 * scale)
                .color(theme::TEXT_SECONDARY),
        )
        .on_press(Message::ToggleBottomPanel)
        .padding(Padding::from([0, 14]))
        .style(|_, _| button::Style {
            background: Some(theme::BG_TERTIARY.into()),
            text_color: theme::TEXT_SECONDARY,
            border: iced::Border {
                radius: 4.0.into(),
                width: 1.0,
                color: theme::BORDER,
            },
            ..Default::default()
        });
        let splitter: Element<'_, Message> = container(
            row![
                Space::with_width(Fill),
                tip(chevron_btn, i18n::t(chevron_tip)),
                Space::with_width(Fill),
            ]
            .align_y(alignment::Vertical::Center),
        )
        .width(Fill)
        .height(Length::Fixed(14.0))
        .style(move |_| container::Style {
            background: Some(drag_color.into()),
            ..Default::default()
        })
        .into();

        if state.bottom_panel_collapsed {
            column![
                terminal_col.height(Fill),
                splitter,
            ]
            .height(Fill)
            .into()
        } else {
            // Bottom panel with tabs: Monitor | Files | QuickCmd
            let bottom_panel = view_bottom_panel(state);
            column![
                terminal_col.height(Fill),
                splitter,
                container(bottom_panel).height(state.bottom_panel_height),
            ]
            .height(Fill)
            .into()
        }
    } else {
        // No active tab → welcome screen
        view_welcome(state)
    };

    // ── Compose main body ────────────────────────────────────────────
    let body: Element<'_, Message> = row![
        left_panel,
        container(right_content).width(Fill).height(Fill),
    ]
    .height(Fill)
    .into();

    let mut main_col = column![];
    // Update notification bar
    if let Some(update_bar) = view_update_bar(state) {
        main_col = main_col.push(update_bar);
    }
    main_col = main_col.push(toolbar);
    main_col = main_col.push(tab_bar);
    main_col = main_col.push(body);
    main_col = main_col.push(status_bar);

    // If a context menu is open, wrap main_col with the menu overlay
    let main_layout: Element<'_, Message> =
        if state.context_menu.is_none() && state.remote_menu.is_none() {
            main_col.height(Fill).into()
        } else {
            let mut layers: Vec<Element<'_, Message>> = vec![main_col.height(Fill).into()];
            if let Some(ctx) = &state.context_menu {
                layers.push(view_context_menu(ctx));
            }
            if let Some(menu) = &state.remote_menu {
                layers.push(view_remote_menu(state, menu));
            }
            container(stack(layers)).width(Fill).height(Fill).into()
        };

    // At most one overlay, picked by the shared z-order (see `Overlay`) and
    // drawn on the shared scrim. ESC closes this same one.
    let overlay: Option<Element<'_, Message>> = state.topmost_overlay().map(|top| match top {
        Overlay::Palette => view_palette(state),
        Overlay::ConfirmDelete => view_confirm_delete(state),
        Overlay::AuthPrompt => view_auth_prompt(state),
        Overlay::ConfirmAction => view_confirm_action(state),
        Overlay::LogViewer => view_log_viewer(state),
        Overlay::ErrorDialog => view_error_dialog(state),
        Overlay::ProcessDetail => view_process_detail(state),
        Overlay::Editor => view_editor(state),
        Overlay::NetworkDetail => view_network_detail(state),
        Overlay::ConnectDialog => view_connect_dialog(state),
        Overlay::History => view_history_panel(state),
        Overlay::ProxyManager => view_proxy_manager(state),
        Overlay::TunnelManager => view_tunnel_manager(state),
        Overlay::TabRename => view_tab_rename(state),
        Overlay::SftpInput => view_sftp_input(state),
        Overlay::KeyManager => view_key_manager(state),
        Overlay::ShortcutsHelp => view_shortcuts_help(),
        Overlay::Broadcast => view_broadcast_dialog(state),
        Overlay::Snippets => view_snippets_panel(state),
        Overlay::About => view_about_dialog(state),
        Overlay::Settings => view_settings_menu(state),
        Overlay::ConnectionForm => view_connection_form_overlay(state),
    });

    let base = container(main_layout)
        .width(Fill)
        .height(Fill)
        .style(bg_primary_container);
    match overlay {
        Some(overlay) => stack![base, scrim(), overlay]
            .width(Fill)
            .height(Fill)
            .into(),
        None => base.into(),
    }
}

// ---- Delete confirmation ----------------------------------------------------

/// Shown while no tab is open: somewhere to start, not a dead end. One
/// primary action, the ~/.ssh/config importer when it has something to add,
/// and the shortcuts worth knowing before the first session.
pub(crate) fn view_welcome(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let subtitle = if state.connections.is_empty() {
        i18n::t("welcome.subtitle_empty")
    } else {
        i18n::t("welcome.subtitle")
    };

    let new_btn = button(text(i18n::t("palette.act.new_conn")).size(13.0 * scale))
        .on_press(Message::ShowForm(None))
        .padding(Padding::from([8, 18]))
        .style(accent_button_style);
    let mut actions = row![new_btn].spacing(space::M).align_y(alignment::Vertical::Center);
    let pending = state.ssh_config_pending();
    if pending > 0 {
        actions = actions.push(
            button(
                text(i18n::tf("welcome.import_ssh", &[("count", &pending.to_string())]))
                    .size(13.0 * scale),
            )
            .on_press(Message::ImportAllSshConfigs)
            .padding(Padding::from([8, 18]))
            .style(outline_button_style),
        );
    }

    let m = if cfg!(target_os = "macos") { "Cmd" } else { "Ctrl" };
    let shortcuts = [
        (format!("{}+T", m), "shortcuts.desc.connect"),
        (format!("{}+K", m), "shortcuts.desc.palette"),
        (format!("{}+/", m), "shortcuts.title"),
        (format!("{}+Shift+L", m), "shortcuts.desc.lock"),
    ];
    let mut keys = column![].spacing(space::S);
    for (accel, desc) in shortcuts {
        keys = keys.push(
            row![
                container(
                    text(accel)
                        .font(Font::MONOSPACE)
                        .color(theme::TEXT_SECONDARY)
                        .size(11.0 * scale),
                )
                .width(Length::Fixed(110.0 * scale))
                .align_x(alignment::Horizontal::Right),
                text(i18n::t(desc)).color(theme::TEXT_SECONDARY).size(12.0 * scale),
            ]
            .spacing(space::M)
            .align_y(alignment::Vertical::Center),
        );
    }

    let content = column![
        text(i18n::t("welcome.title")).size(36.0 * scale).color(state.c_primary()),
        text(subtitle).size(14.0 * scale).color(theme::TEXT_SECONDARY),
        vertical_space().height(space::S),
        actions,
        vertical_space().height(space::XL),
        keys,
    ]
    .spacing(space::M)
    .align_x(alignment::Horizontal::Center);

    iced::widget::center(content)
        .style(|_theme| container::Style {
            background: Some(theme::BG_PRIMARY.into()),
            ..Default::default()
        })
        .into()
}

// ---- Update notification bar ---------------------------------------------

pub(crate) fn view_update_bar(state: &NeoShell) -> Option<Element<'_, Message>> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let (available, ready, version, progress) = {
        let s = state.updater.state.lock();
        (s.available, s.ready, s.version.clone(), s.download_progress)
    };

    if ready {
        // Update downloaded and ready to install
        Some(
            container(
                row![
                    text(i18n::tf("update.ready", &[("version", &version)]))
                        .color(c_success)
                        .size(12.0 * scale),
                    horizontal_space(),
                    button(text(i18n::t("update.restart")).size(11.0 * scale))
                        .on_press(Message::RestartForUpdate)
                        .padding(Padding::from([4, 14]))
                        .style(accent_button_style),
                    button(text(i18n::t("update.later")).color(theme::TEXT_MUTED).size(11.0 * scale))
                        .on_press(Message::DismissUpdate)
                        .padding(Padding::from([4, 8]))
                        .style(transparent_button_style),
                ]
                .align_y(alignment::Vertical::Center)
                .padding(Padding::from([6, 16])),
            )
            .width(Fill)
            .style(move |_| container::Style {
                background: Some(tint(c_success, 0.12).into()),
                border: iced::Border {
                    color: c_success,
                    width: 1.0,
                    radius: 0.0.into(),
                },
                ..Default::default()
            })
            .into(),
        )
    } else if available && progress > 0.0 && progress < 1.0 {
        // Download in progress. The accent lives in the wash and the frame;
        // the text stays in the body colour (accent is below AA as text).
        Some(
            container(
                row![text(i18n::tf("update.downloading", &[("version", &version), ("percent", &format!("{:.0}", progress * 100.0))]))
                .color(c_primary)
                .size(12.0 * scale),]
                .padding(Padding::from([6, 16])),
            )
            .width(Fill)
            .style(move |_| container::Style {
                background: Some(tint(c_accent, 0.12).into()),
                ..Default::default()
            })
            .into(),
        )
    } else if available {
        // Update available, not yet downloading
        Some(
            container(
                row![
                    text(i18n::tf("update.available", &[("version", &version)]))
                        .color(c_primary)
                        .size(12.0 * scale),
                    horizontal_space(),
                    button(text(i18n::t("update.download_btn")).size(11.0 * scale))
                        .on_press(Message::DownloadUpdate)
                        .padding(Padding::from([4, 14]))
                        .style(accent_button_style),
                    tip(
                        button(text("x").color(theme::TEXT_MUTED).size(11.0 * scale))
                            .on_press(Message::DismissUpdate)
                            .padding(Padding::from([4, 6]))
                            .style(transparent_button_style),
                        i18n::t("err.dismiss"),
                    ),
                ]
                .align_y(alignment::Vertical::Center)
                .padding(Padding::from([6, 16])),
            )
            .width(Fill)
            .style(move |_| container::Style {
                background: Some(tint(c_accent, 0.12).into()),
                border: iced::Border {
                    color: c_accent,
                    width: 1.0,
                    radius: 0.0.into(),
                },
                ..Default::default()
            })
            .into(),
        )
    } else {
        None
    }
}

// ---- Tab bar -------------------------------------------------------------
