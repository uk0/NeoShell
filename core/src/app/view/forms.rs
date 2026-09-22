use super::*;
// Explicit: through the glob above, `column` is ambiguous with std's `column!`.
use iced::widget::column;

pub(crate) fn view_connect_dialog(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = row![
        text(i18n::t("dialog.connect_title")).color(c_primary).size(18.0 * scale),
        horizontal_space(),
        button(text(i18n::t("dialog.new_btn")).color(c_accent).size(13.0 * scale))
            .on_press(Message::ShowForm(None))
            .padding(Padding::from([4, 12]))
            .style(transparent_button_style),
        tip(
            button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
                .on_press(Message::HideConnectDialog)
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style),
            i18n::t("tip.close"),
        ),
    ]
    .align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(2);

    if state.connections.is_empty() {
        list_col = list_col.push(
            container(text(i18n::t("dialog.no_saved")).color(theme::TEXT_MUTED).size(13.0 * scale))
                .padding(Padding::from([16, 12])),
        );
    } else {
        for conn in &state.connections {
            let conn_id = conn.id.clone();
            let conn_id_edit = conn.id.clone();
            let conn_id_del = conn.id.clone();

            // Cut by display width, a Chinese name included, with the full
            // text in a tooltip: the row keeps to one line.
            let (name, name_cut) = clip_to_width(&conn.name, 30);
            let host_full = format!("{}@{}:{}", conn.username, conn.host, conn.port);
            let (host, host_cut) = clip_to_width(&host_full, 40);
            let info_col = column![
                tip_if(text(name).color(c_primary).size(14.0 * scale), name_cut, &conn.name),
                tip_if(
                    text(host).color(theme::TEXT_MUTED).size(11.0 * scale),
                    host_cut,
                    &host_full,
                ),
            ].spacing(2);
            let (group, group_cut) = clip_to_width(&conn.group, 14);

            // Same live-session test as the sidebar: green only while a tab
            // actually holds a session to this host.
            let dot_color = if state.is_connected(&conn.id) { c_success } else { theme::TEXT_MUTED };
            let connect_btn = button(
                row![
                    text("\u{25CF} ").color(dot_color).size(10.0 * scale),
                    info_col,
                ].spacing(8).align_y(alignment::Vertical::Center)
            )
            .on_press(Message::ConnectTo(conn_id))
            .padding(Padding::from([8, 8]))
            .style(sidebar_item_style);

            let edit_btn = button(text(i18n::t("dialog.edit")).color(c_accent).size(11.0 * scale))
                .on_press(Message::ShowForm(Some(conn_id_edit)))
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style);

            let del_btn = button(text(i18n::t("dialog.delete")).color(c_danger).size(11.0 * scale))
                .on_press(Message::DeleteConnection(conn_id_del))
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style);

            let entry_row = row![
                connect_btn,
                horizontal_space(),
                tip_if(
                    text(group).color(theme::TEXT_MUTED).size(10.0 * scale),
                    group_cut,
                    &conn.group,
                ),
                edit_btn,
                del_btn,
            ]
            .align_y(alignment::Vertical::Center)
            .spacing(4)
            .padding(Padding::from([0, 4]));

            list_col = list_col.push(entry_row);
        }
    }

    // SSH config hosts — read into state on ConnectionsLoaded (which opening
    // this dialog triggers), not here: a view runs on every redraw.
    let ssh_configs = &state.ssh_config_hosts;
    if !ssh_configs.is_empty() {
        let import_all_btn = button(
            text(i18n::tf("dialog.ssh_config_import_all", &[("count", &ssh_configs.len().to_string())]))
                .color(c_accent).size(10.0 * scale)
        )
        .on_press(Message::ImportAllSshConfigs)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

        list_col = list_col.push(
            container(
                row![
                    text(i18n::t("dialog.ssh_config"))
                        .color(theme::TEXT_MUTED)
                        .size(11.0 * scale),
                    horizontal_space(),
                    import_all_btn,
                ].align_y(alignment::Vertical::Center)
            )
            .padding(Padding::from([8, 12])),
        );

        for config in ssh_configs.iter().cloned() {
            let display_host = if config.hostname.is_empty() {
                config.alias.clone()
            } else {
                config.hostname.clone()
            };
            let alias_text = config.alias.clone();
            let user_display = if config.user.is_empty() {
                "?".to_string()
            } else {
                config.user.clone()
            };
            let detail = format!("{}@{}:{}", user_display, display_host, config.port);

            let config_row = row![
                text("\u{25CB} ").color(c_accent).size(10.0 * scale),
                column![
                    text(alias_text).color(theme::TEXT_SECONDARY).size(13.0 * scale),
                    text(detail).color(theme::TEXT_MUTED).size(11.0 * scale),
                ]
                .spacing(2),
                horizontal_space(),
                text(i18n::t("dialog.ssh_config_label")).color(theme::TEXT_MUTED).size(9.0 * scale),
            ]
            .align_y(alignment::Vertical::Center)
            .spacing(8);

            list_col = list_col.push(
                button(config_row)
                    .on_press(Message::ImportSshConfig(config))
                    .padding(Padding::from([6, 12]))
                    .width(Fill)
                    .style(sidebar_item_style),
            );
        }
    }

    let hint = text(i18n::t("dialog.keyboard_hint"))
        .color(theme::TEXT_MUTED)
        .size(10.0 * scale);

    let content = column![title, slim_scroll(list_col).height(300), hint]
        .spacing(12)
        .padding(24)
        .width(480);

    iced::widget::center(modal_card(content)).into()
}

pub(crate) fn view_proxy_manager(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("proxy.title")).size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideProxyManager)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let add_btn = button(text(i18n::t("proxy.add")).color(c_accent).size(11.0 * scale))
        .on_press(Message::ShowProxyForm(None))
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), add_btn, tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);

    let mut list_col = column![].spacing(4);

    // Proxy form (inline)
    if state.show_proxy_form {
        let on_accent_label = on_accent(c_accent);
        let form_title = if state.proxy_edit_id.is_some() {
            i18n::t("proxy.edit")
        } else {
            i18n::t("proxy.add")
        };
        let name_input = input(i18n::t("proxy.name"), &state.proxy_form.name)
            .on_input(Message::ProxyFormNameChanged).padding(6).size(12.0 * scale);
        let host_input = input(i18n::t("proxy.host"), &state.proxy_form.host)
            .on_input(Message::ProxyFormHostChanged).padding(6).size(12.0 * scale);
        let port_input = input(i18n::t("proxy.port"), &state.proxy_form.port)
            .on_input(Message::ProxyFormPortChanged).padding(6).size(12.0 * scale).width(80);
        let user_input = input(i18n::t("proxy.username"), &state.proxy_form.username)
            .on_input(Message::ProxyFormUsernameChanged).padding(6).size(12.0 * scale);
        let pass_input = input(i18n::t("proxy.password"), &state.proxy_form.password)
            .on_input(Message::ProxyFormPasswordChanged).padding(6).size(12.0 * scale).secure(true)
            .id(text_input::Id::new(PROXY_PASSWORD_INPUT_ID));

        let type_socks = button(
            text("SOCKS5H").color(if state.proxy_form.proxy_type == "socks5h" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("socks5h".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "socks5h" { accent_button_style } else { transparent_button_style });
        let type_http = button(
            text("HTTP").color(if state.proxy_form.proxy_type == "http" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("http".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "http" { accent_button_style } else { transparent_button_style });
        let type_bastion = button(
            text(i18n::t("proxy.type.bastion")).color(if state.proxy_form.proxy_type == "bastion" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale)
        ).on_press(Message::ProxyFormTypeChanged("bastion".into())).padding(Padding::from([4, 8]))
         .style(if state.proxy_form.proxy_type == "bastion" { accent_button_style } else { transparent_button_style });

        let save_btn = button(text(i18n::t("proxy.save")).size(11.0 * scale))
            .on_press(Message::SaveProxy).padding(Padding::from([4, 12])).style(accent_button_style);
        let cancel_btn = button(text(i18n::t("proxy.cancel")).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::HideProxyForm).padding(Padding::from([4, 8])).style(transparent_button_style);

        let is_bastion = state.proxy_form.proxy_type == "bastion";
        let mut form_content = column![
            text(form_title).color(c_primary).size(13.0 * scale),
            name_input,
            row![type_socks, type_http, type_bastion].spacing(4),
            row![host_input, port_input].spacing(4),
            user_input,
        ].spacing(space::S).padding(10).width(Fill);

        if is_bastion {
            let auth_pwd_btn = button(
                text(i18n::t("proxy.bastion.auth_password"))
                    .color(if state.proxy_form.auth_type == "password" || state.proxy_form.auth_type.is_empty() { on_accent_label } else { theme::TEXT_MUTED })
                    .size(11.0 * scale)
            ).on_press(Message::ProxyFormAuthTypeChanged("password".into())).padding(Padding::from([4, 8]))
             .style(if state.proxy_form.auth_type == "password" || state.proxy_form.auth_type.is_empty() { accent_button_style } else { transparent_button_style });
            let auth_key_btn = button(
                text(i18n::t("proxy.bastion.auth_key"))
                    .color(if state.proxy_form.auth_type == "key" { on_accent_label } else { theme::TEXT_MUTED })
                    .size(11.0 * scale)
            ).on_press(Message::ProxyFormAuthTypeChanged("key".into())).padding(Padding::from([4, 8]))
             .style(if state.proxy_form.auth_type == "key" { accent_button_style } else { transparent_button_style });

            form_content = form_content.push(row![auth_pwd_btn, auth_key_btn].spacing(4));

            if state.proxy_form.auth_type == "key" {
                let key_input = input(i18n::t("proxy.bastion.key_path"), &state.proxy_form.private_key)
                    .on_input(Message::ProxyFormPrivateKeyChanged).padding(6).size(12.0 * scale);
                let browse_btn = button(text(i18n::t("proxy.bastion.browse")).color(c_accent).size(11.0 * scale))
                    .on_press(Message::ProxyFormBrowsePrivateKey).padding(Padding::from([4, 8]))
                    .style(transparent_button_style);
                let passphrase_input = input(i18n::t("proxy.bastion.passphrase"), &state.proxy_form.passphrase)
                    .on_input(Message::ProxyFormPassphraseChanged).padding(6).size(12.0 * scale).secure(true)
                    .id(text_input::Id::new(PROXY_PASSPHRASE_INPUT_ID));
                form_content = form_content
                    .push(row![key_input, browse_btn].spacing(4))
                    .push(passphrase_input);
            } else {
                form_content = form_content.push(pass_input);
            }
        } else {
            form_content = form_content.push(pass_input);
        }

        form_content = form_content.push(row![cancel_btn, save_btn].spacing(8));

        list_col = list_col.push(
            container(form_content).style(|_| container::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                ..Default::default()
            })
        );
    }

    // Proxy list
    if state.proxies.is_empty() && state.proxy_edit_id.is_none() {
        list_col = list_col.push(
            container(text(i18n::t("proxy.empty")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([16, 8])),
        );
    }
    for proxy in &state.proxies {
        let pid = proxy.id.clone();
        let pid2 = proxy.id.clone();
        let pid3 = proxy.id.clone();

        let type_label = format!("{}", proxy.proxy_type);
        let addr = format!("{}:{}", proxy.host, proxy.port);

        let test_status: Element<'_, Message> = if let Some(result) = state.proxy_test_results.get(&proxy.id) {
            if result.reachable {
                text(format!("{} {}ms", i18n::t("proxy.ok"), result.latency_ms))
                    .color(c_success).size(10.0 * scale).into()
            } else {
                text(format!("{} {}", i18n::t("proxy.fail"), result.error.as_deref().unwrap_or("")))
                    .color(c_danger).size(10.0 * scale).into()
            }
        } else {
            text("").size(1.0 * scale).into()
        };

        let test_btn = button(text(i18n::t("proxy.test")).color(c_accent).size(10.0 * scale))
            .on_press(Message::TestProxy(pid.clone())).padding(Padding::from([2, 6])).style(transparent_button_style);
        let edit_btn = button(text(i18n::t("proxy.edit")).color(theme::TEXT_SECONDARY).size(10.0 * scale))
            .on_press(Message::ShowProxyForm(Some(pid2))).padding(Padding::from([2, 6])).style(transparent_button_style);
        let del_btn = button(text(i18n::t("proxy.delete")).color(c_danger).size(10.0 * scale))
            .on_press(Message::DeleteProxy(pid3)).padding(Padding::from([2, 6])).style(transparent_button_style);

        let entry = row![
            column![
                text(&proxy.name).color(c_primary).size(12.0 * scale),
                row![text(type_label).color(theme::TEXT_MUTED).size(10.0 * scale), text(addr).color(theme::TEXT_MUTED).size(10.0 * scale)].spacing(8),
            ].spacing(2).width(Fill),
            test_status,
            test_btn,
            edit_btn,
            del_btn,
        ].spacing(4).align_y(alignment::Vertical::Center);

        list_col = list_col.push(
            container(entry).padding(Padding::from([6, 10])).width(Fill)
                .style(|_| container::Style {
                    background: Some(theme::BG_TERTIARY.into()),
                    border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                    ..Default::default()
                })
        );
    }

    let content = column![header, slim_scroll(list_col).height(Fill)]
        .spacing(space::M).padding(16).width(420);

    let card = container(content).height(Fill).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        shadow: iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.4), offset: iced::Vector::new(-4.0, 0.0), blur_radius: 16.0 },
        ..Default::default()
    });

    // Drawer: pinned to the right edge, full height, over the shared scrim.
    let overlay = row![horizontal_space(), card];
    container(overlay).width(Fill).height(Fill).into()
}

// ---- Command history panel --------------------------------------------------

pub(crate) fn view_settings_menu(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();

    let title = text(i18n::t("settings.title")).size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideSettings)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);

    let lang_label = text(i18n::t("settings.language")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let lang_value = if state.locale == "zh-CN" { "中文" } else { "English" };
    let lang_btn = button(
        text(lang_value).color(c_accent).size(13.0 * scale)
    )
    .on_press(Message::ToggleLanguage)
    .padding(Padding::from([4, 12]))
    .style(transparent_button_style);
    let lang_row = row![lang_label, horizontal_space(), lang_btn]
        .align_y(alignment::Vertical::Center);

    let scale_label = text(i18n::t("settings.scale")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let scale_pct = format!("{:.0}%", state.ui_scale * 100.0);
    let scale_down = button(text("-").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetUiScale((state.ui_scale - 0.1).max(0.5)))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let scale_up = button(text("+").color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetUiScale((state.ui_scale + 0.1).min(3.0)))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let scale_row = row![
        scale_label,
        horizontal_space(),
        tip(scale_down, i18n::t("tip.decrease")),
        text(scale_pct).color(c_primary).size(13.0 * scale),
        tip(scale_up, i18n::t("tip.increase")),
    ]
        .spacing(4)
        .align_y(alignment::Vertical::Center);

    let sidebar_label = text(i18n::t("settings.sidebar")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let sidebar_icon = if state.sidebar_collapsed { "OFF" } else { "ON" };
    let sidebar_btn = button(text(sidebar_icon).color(c_accent).size(14.0 * scale))
        .on_press(Message::ToggleSidebar)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let sidebar_row = row![sidebar_label, horizontal_space(), sidebar_btn]
        .align_y(alignment::Vertical::Center);

    let font_label = text(i18n::t("settings.font_size")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let font_pct = format!("{:.0}px", state.font_size);
    let font_down = button(text("-").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetFontSize(state.font_size - 1.0))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let font_up = button(text("+").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetFontSize(state.font_size + 1.0))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let font_row = row![
        font_label,
        horizontal_space(),
        tip(font_down, i18n::t("tip.decrease")),
        text(font_pct).color(c_primary).size(13.0 * scale),
        tip(font_up, i18n::t("tip.increase")),
    ]
        .spacing(4)
        .align_y(alignment::Vertical::Center);

    let lock_label = text(i18n::t("settings.lock_timeout")).color(theme::TEXT_SECONDARY).size(13.0 * scale);
    let lock_value = lock_timeout_label(state.lock_timeout_mins);
    let lock_down = button(text("-").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetLockTimeout(cycle_lock_timeout(state.lock_timeout_mins, false)))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let lock_up = button(text("+").font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(14.0 * scale))
        .on_press(Message::SetLockTimeout(cycle_lock_timeout(state.lock_timeout_mins, true)))
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let lock_row = row![
        lock_label,
        horizontal_space(),
        tip(lock_down, i18n::t("tip.decrease")),
        text(lock_value).color(c_primary).size(13.0 * scale),
        tip(lock_up, i18n::t("tip.increase")),
    ]
        .spacing(4)
        .align_y(alignment::Vertical::Center);

    let lock_now_btn = button(
        row![
            text(i18n::t("settings.lock_now")).color(theme::TEXT_SECONDARY).size(13.0 * scale),
            horizontal_space(),
            text(if cfg!(target_os = "macos") { "Cmd+Shift+L" } else { "Ctrl+Shift+L" })
                .font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(11.0 * scale),
        ]
        .align_y(alignment::Vertical::Center)
    )
    .on_press(Message::LockNow)
    .padding(Padding::from([8, 0]))
    .width(Fill)
    .style(transparent_button_style);

    // Divider
    let divider: Element<'_, Message> = container(Space::new(Fill, 1))
        .width(Fill)
        .style(|_| container::Style {
            background: Some(theme::BORDER.into()),
            ..Default::default()
        })
        .into();

    let proxy_btn = button(
        row![
            text(i18n::t("proxy.title")).color(theme::TEXT_SECONDARY).size(13.0 * scale),
            horizontal_space(),
            text(">").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(12.0 * scale),
        ]
        .align_y(alignment::Vertical::Center)
    )
    .on_press(Message::ShowProxyManager)
    .padding(Padding::from([8, 0]))
    .width(Fill)
    .style(transparent_button_style);

    let about_btn = button(
        row![
            text(i18n::t("settings.about")).color(theme::TEXT_SECONDARY).size(13.0 * scale),
            horizontal_space(),
            text(">").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(12.0 * scale),
        ]
        .align_y(alignment::Vertical::Center)
    )
    .on_press(Message::ShowAbout)
    .padding(Padding::from([8, 0]))
    .width(Fill)
    .style(transparent_button_style);

    // --- Appearance section: color zones + font sizes + picker --------------
    let appearance = view_theme_editor(state);

    let menu_content = column![
        header,
        lang_row,
        font_row,
        scale_row,
        sidebar_row,
        lock_row,
        lock_now_btn,
        divider,
        appearance,
        proxy_btn,
        about_btn,
    ]
    .spacing(12)
    .padding(20)
    .width(360);

    let card = modal_card(slim_scroll(menu_content).height(Fill)).max_height(620);

    // Position near bottom-right (above status bar)
    let overlay_content = column![
        vertical_space(),
        row![horizontal_space(), container(card).padding(Padding::from([0, 16]))],
    ];

    container(overlay_content).width(Fill).height(Fill).into()
}

// ---- Theme editor (colors + per-zone font sizes) --------------------------

pub(crate) fn view_theme_editor(state: &NeoShell) -> Element<'_, Message> {
    use crate::ui::theme_config::ThemeZone;
    use iced::widget::slider;

    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_danger = state.c_danger();
    let t = &state.theme_cfg;

    let section_title = text(i18n::t("theme.title"))
        .color(c_primary).size(13.0 * scale);

    // Colour-scheme presets. The names are lookup keys and proper nouns, so
    // they render verbatim; each row previews the scheme's terminal colours,
    // and a click applies it to the whole window at once.
    let mut presets = column![text(i18n::t("theme.preset")).color(theme::TEXT_SECONDARY).size(12.0 * scale)]
        .spacing(space::XS);
    for name in theme_config::preset_names() {
        let Some(preset) = theme_config::preset_by_name(name) else { continue };
        let active = preset_keeping_fonts(preset.clone(), t) == *t;
        let (bg, fg) = (preset.terminal_bg.to_color(), preset.terminal_fg.to_color());
        let mut chips = row![text("$").font(Font::MONOSPACE).color(fg).size(10.0 * scale)]
            .spacing(3)
            .align_y(alignment::Vertical::Center);
        for slot in 1..=6 {
            let c = preset.ansi[slot].to_color();
            chips = chips.push(container(Space::new(7, 7)).style(move |_| container::Style {
                background: Some(c.into()),
                border: iced::Border { radius: 1.5.into(), ..Default::default() },
                ..Default::default()
            }));
        }
        let preview = container(chips)
            .padding(Padding::from([3, 6]))
            .style(move |_| container::Style {
                background: Some(bg.into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                ..Default::default()
            });
        presets = presets.push(
            button(
                row![
                    preview,
                    text(name).color(if active { c_primary } else { theme::TEXT_SECONDARY }).size(12.0 * scale),
                    horizontal_space(),
                    text(if active { "✓" } else { "" }).color(c_accent).size(12.0 * scale),
                ]
                .spacing(space::M)
                .align_y(alignment::Vertical::Center),
            )
            .on_press(Message::ThemeApplyPreset(name.to_string()))
            .padding(Padding::from([3, 6]))
            .width(Fill)
            .style(if active { sidebar_item_style } else { transparent_button_style }),
        );
    }

    let mut swatches = column![].spacing(space::S);
    for zone in ThemeZone::ALL {
        let rgb = zone.get(t);
        let selected = state.theme_editing_zone == Some(zone);
        let swatch = container(Space::new(24, 20))
            .style(move |_| container::Style {
                background: Some(rgb.to_color().into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                ..Default::default()
            });
        let label_color = if selected { c_accent } else { theme::TEXT_SECONDARY };
        let label = text(i18n::t(zone.label_key())).color(label_color).size(12.0 * scale);
        let hex = text(rgb.to_hex()).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale);

        let press_msg = if selected {
            Message::ThemeCloseZone
        } else {
            Message::ThemeSelectZone(zone)
        };
        let row_el = button(
            row![swatch, label, horizontal_space(), hex]
                .spacing(space::M)
                .align_y(alignment::Vertical::Center)
        )
        .on_press(press_msg)
        .padding(Padding::from([4, 6]))
        .width(Fill)
        .style(if selected { sidebar_item_style } else { transparent_button_style });
        swatches = swatches.push(row_el);

        if selected {
            let current = rgb;
            let r_slider = slider(0..=255u8, current.r, Message::ThemeRChanged).step(1u8);
            let g_slider = slider(0..=255u8, current.g, Message::ThemeGChanged).step(1u8);
            let b_slider = slider(0..=255u8, current.b, Message::ThemeBChanged).step(1u8);
            let r_lbl = text(format!("R {:>3}", current.r)).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale).width(50);
            let g_lbl = text(format!("G {:>3}", current.g)).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale).width(50);
            let b_lbl = text(format!("B {:>3}", current.b)).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(10.0 * scale).width(50);
            let hex_input = input("#RRGGBB", &current.to_hex())
                .on_input(Message::ThemeHexChanged)
                .padding(4).size(11.0 * scale).width(90);
            let preview = container(Space::new(Fill, 24))
                .style(move |_| container::Style {
                    background: Some(current.to_color().into()),
                    border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                    ..Default::default()
                });
            let editor = column![
                row![r_lbl, r_slider].spacing(space::S).align_y(alignment::Vertical::Center),
                row![g_lbl, g_slider].spacing(space::S).align_y(alignment::Vertical::Center),
                row![b_lbl, b_slider].spacing(space::S).align_y(alignment::Vertical::Center),
                row![hex_input, horizontal_space(), preview].spacing(8),
            ].spacing(space::S).padding(8).width(Fill);
            let editor_container = container(editor).style(|_| container::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 6.0.into() },
                ..Default::default()
            });
            swatches = swatches.push(editor_container);
        }
    }

    let term_size = t.terminal_font_size;
    let ui_size = t.ui_font_size;
    let term_size_row = row![
        text(i18n::t("theme.terminal_font_size")).color(theme::TEXT_SECONDARY).size(12.0 * scale).width(Fill),
        text(format!("{:.0}px", term_size)).font(Font::MONOSPACE).color(c_primary).size(11.0 * scale).width(40),
    ].align_y(alignment::Vertical::Center);
    let term_slider = slider(8.0..=28.0f32, term_size, Message::ThemeTerminalFontSize).step(1.0f32);

    let ui_size_row = row![
        text(i18n::t("theme.ui_font_size")).color(theme::TEXT_SECONDARY).size(12.0 * scale).width(Fill),
        text(format!("{:.0}px", ui_size)).font(Font::MONOSPACE).color(c_primary).size(11.0 * scale).width(40),
    ].align_y(alignment::Vertical::Center);
    let ui_slider = slider(10.0..=18.0f32, ui_size, Message::ThemeUiFontSize).step(1.0f32);

    let reset_btn = button(text(i18n::t("theme.reset")).color(c_danger).size(11.0 * scale))
        .on_press(Message::ThemeReset)
        .padding(Padding::from([4, 10]))
        .style(transparent_button_style);

    // ---- v0.7.0: resource threshold alerts -------------------------------
    let a = &state.alert_cfg;
    let alerts_title = text(i18n::t("alerts.title"))
        .color(c_primary)
        .size(13.0 * scale);
    let enabled = a.enabled;
    let alerts_toggle = button(
        text(if enabled { i18n::t("alerts.on") } else { i18n::t("alerts.off") })
            .size(11.0 * scale)
            .color(if enabled { Color::WHITE } else { theme::TEXT_SECONDARY }),
    )
    .on_press(Message::AlertEnabledToggled(!enabled))
    .padding(Padding::from([3, 10]))
    .style(move |_, _| button::Style {
        background: Some(if enabled {
            theme::DANGER.into()
        } else {
            theme::BG_TERTIARY.into()
        }),
        text_color: if enabled { Color::WHITE } else { theme::TEXT_SECONDARY },
        border: iced::Border {
            radius: 4.0.into(),
            width: 1.0,
            color: theme::BORDER,
        },
        ..Default::default()
    });

    let alert_row = |label: &'static str, val: f32, msg: fn(f32) -> Message| {
        column![
            row![
                text(i18n::t(label)).color(theme::TEXT_SECONDARY).size(12.0 * scale).width(Fill),
                text(format!("{:.0}%", val)).font(Font::MONOSPACE).color(c_primary).size(11.0 * scale).width(40),
            ]
            .align_y(alignment::Vertical::Center),
            slider(50.0..=100.0f32, val, msg).step(5.0f32),
        ]
        .spacing(2)
    };

    let alerts_block = column![
        row![alerts_title, horizontal_space(), alerts_toggle]
            .align_y(alignment::Vertical::Center),
        text(i18n::t("alerts.hint")).color(theme::TEXT_MUTED).size(10.0 * scale),
        alert_row("alerts.cpu", a.cpu_pct, Message::AlertCpuChanged),
        alert_row("alerts.mem", a.mem_pct, Message::AlertMemChanged),
        alert_row("alerts.disk", a.disk_pct, Message::AlertDiskChanged),
    ]
    .spacing(8);

    column![
        section_title,
        presets,
        swatches,
        term_size_row, term_slider,
        ui_size_row, ui_slider,
        row![horizontal_space(), reset_btn],
        hr_space(),
        alerts_block,
    ]
    .spacing(8)
    .into()
}

pub(crate) fn view_key_manager(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_success = state.c_success();
    let c_danger = state.c_danger();

    let title_bar = row![
        text(i18n::t("keys.title")).size(17.0 * scale).color(c_primary),
        horizontal_space(),
        tip(
            button(text("×").size(16.0 * scale).color(theme::TEXT_SECONDARY))
                .on_press(Message::HideKeyManager)
                .padding(Padding::from([2, 10]))
                .style(transparent_button_style),
            i18n::t("tip.close"),
        ),
    ]
    .align_y(alignment::Vertical::Center);

    // ---- key list ----
    let mut key_list = column![].spacing(8);
    if state.local_keys.is_empty() {
        key_list = key_list.push(
            text(i18n::t("keys.empty"))
                .color(theme::TEXT_MUTED)
                .size(12.0 * scale),
        );
    }
    for k in &state.local_keys {
        let path_copy = k.path.clone();
        let path_deploy = k.path.clone();
        let pubkey_short: String = {
            // type + first 16 … last 8 of base64 + comment
            let mut parts = k.pubkey.split_whitespace();
            let _ty = parts.next().unwrap_or("");
            let b64 = parts.next().unwrap_or("");
            // Char-based: `pubkey` is the raw line from ~/.ssh/*.pub, which is
            // never charset-validated, so a byte slice can split a multi-byte char.
            let b64_chars: Vec<char> = b64.chars().collect();
            if b64_chars.len() > 28 {
                let head: String = b64_chars[..16].iter().collect();
                let tail: String = b64_chars[b64_chars.len() - 8..].iter().collect();
                format!("{}…{}", head, tail)
            } else {
                b64.to_string()
            }
        };

        let mut card_col = column![
            row![
                text(k.name.clone()).size(13.0 * scale).color(c_primary),
                container(
                    text(k.key_type.clone()).size(9.0 * scale).color(c_accent)
                )
                .padding(Padding::from([1, 6]))
                .style(|_| container::Style {
                    background: Some(theme::BG_TERTIARY.into()),
                    border: iced::Border { radius: 4.0.into(), ..Default::default() },
                    ..Default::default()
                }),
                horizontal_space(),
                button(text(i18n::t("keys.copy")).size(10.0 * scale).color(c_accent))
                    .on_press(Message::KeyCopyPubkey(path_copy))
                    .padding(Padding::from([3, 8]))
                    .style(transparent_button_style),
                button(text(i18n::t("keys.deploy")).size(10.0 * scale).color(c_success))
                    .on_press(Message::KeyDeployStart(path_deploy))
                    .padding(Padding::from([3, 8]))
                    .style(transparent_button_style),
            ]
            .spacing(8)
            .align_y(alignment::Vertical::Center),
            text(format!("{}  {}", pubkey_short, k.comment))
                .size(10.0 * scale)
                .font(Font::MONOSPACE)
                .color(theme::TEXT_MUTED),
        ]
        .spacing(4);

        // Inline connection picker when this key is in deploy mode.
        if state.key_deploying.as_deref() == Some(k.path.as_str()) {
            let mut pick = column![
                text(i18n::t("keys.pick_target"))
                    .size(11.0 * scale)
                    .color(c_primary)
            ]
            .spacing(4);
            for c in &state.connections {
                let label = format!("{} — {}@{}:{}", c.name, c.username, c.host, c.port);
                pick = pick.push(
                    button(text(label).size(11.0 * scale).color(theme::TEXT_SECONDARY))
                        .on_press(Message::KeyDeployTo(k.path.clone(), c.id.clone()))
                        .padding(Padding::from([4, 10]))
                        .width(Fill)
                        .style(sidebar_item_style),
                );
            }
            pick = pick.push(
                button(text(i18n::t("form.cancel")).size(11.0 * scale).color(theme::TEXT_MUTED))
                    .on_press(Message::KeyDeployCancel)
                    .padding(Padding::from([4, 10]))
                    .style(transparent_button_style),
            );
            card_col = card_col.push(
                container(pick).padding(8).style(|_| container::Style {
                    background: Some(theme::BG_PRIMARY.into()),
                    border: iced::Border {
                        color: theme::BORDER,
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                }),
            );
        }

        key_list = key_list.push(
            container(card_col).padding(10).width(Fill).style(|_| container::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border {
                    color: theme::BORDER,
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..Default::default()
            }),
        );
    }

    // ---- generate form ----
    let gen_form = column![
        text(i18n::t("keys.gen_title")).size(13.0 * scale).color(c_primary),
        row![
            input(&i18n::t("keys.gen_name"), &state.key_form_name)
                .on_input(Message::KeyFormNameChanged)
                .padding(8)
                .size(12.0 * scale),
            input(&i18n::t("keys.gen_comment"), &state.key_form_comment)
                .on_input(Message::KeyFormCommentChanged)
                .padding(8)
                .size(12.0 * scale),
            button(text(i18n::t("keys.gen_btn")).size(12.0 * scale))
                .on_press(Message::KeyGenerate)
                .padding(Padding::from([8, 16]))
                .style(accent_button_style),
        ]
        .spacing(8)
        .align_y(alignment::Vertical::Center),
        text(i18n::t("keys.gen_hint")).size(10.0 * scale).color(theme::TEXT_MUTED),
    ]
    .spacing(space::S);

    // ---- status line ----
    let status: Element<'_, Message> = if let Some(s) = &state.key_deploy_status {
        let color = if s.starts_with('✗') { c_danger } else { c_success };
        text(s.clone()).size(11.0 * scale).color(color).into()
    } else {
        Space::new(0, 0).into()
    };

    let card = modal_card(
        column![
            title_bar,
            slim_scroll(key_list).height(Length::Fixed(300.0)),
            gen_form,
            status,
        ]
        .spacing(space::L)
        .width(620),
    )
    .padding(20)
    .max_height(560);

    iced::widget::center(card).into()
}

pub(crate) fn view_tunnel_manager(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title = text(i18n::t("tunnel.title")).size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideTunnelManager)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let add_btn = button(text(i18n::t("tunnel.add")).color(c_accent).size(11.0 * scale))
        .on_press(Message::ShowTunnelForm(None))
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);
    let header = row![title, horizontal_space(), add_btn, tip(close_btn, i18n::t("tip.close"))]
        .align_y(alignment::Vertical::Center);
    let on_accent_label = on_accent(c_accent);

    let mut list_col = column![].spacing(4);

    // Inline form
    if state.show_tunnel_form {
        let form_title = if state.tunnel_edit_id.is_some() { i18n::t("tunnel.edit") } else { i18n::t("tunnel.add") };
        let name_in = input(i18n::t("tunnel.name"), &state.tunnel_form.name)
            .on_input(Message::TunnelFormNameChanged).padding(6).size(12.0 * scale);
        let host_in = input(i18n::t("tunnel.ssh_host"), &state.tunnel_form.ssh_host)
            .on_input(Message::TunnelFormHostChanged).padding(6).size(12.0 * scale);
        let port_in = input(i18n::t("tunnel.ssh_port"), &state.tunnel_form.ssh_port)
            .on_input(Message::TunnelFormPortChanged).padding(6).size(12.0 * scale).width(80);
        let user_in = input(i18n::t("tunnel.user"), &state.tunnel_form.username)
            .on_input(Message::TunnelFormUserChanged).padding(6).size(12.0 * scale);

        let auth_pwd_btn = button(text(i18n::t("proxy.bastion.auth_password"))
            .color(if state.tunnel_form.auth_type != "key" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale))
            .on_press(Message::TunnelFormAuthTypeChanged("password".into()))
            .padding(Padding::from([4, 8]))
            .style(if state.tunnel_form.auth_type != "key" { accent_button_style } else { transparent_button_style });
        let auth_key_btn = button(text(i18n::t("proxy.bastion.auth_key"))
            .color(if state.tunnel_form.auth_type == "key" { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale))
            .on_press(Message::TunnelFormAuthTypeChanged("key".into()))
            .padding(Padding::from([4, 8]))
            .style(if state.tunnel_form.auth_type == "key" { accent_button_style } else { transparent_button_style });

        let secret: Element<'_, Message> = if state.tunnel_form.auth_type == "key" {
            let key_in = input(i18n::t("proxy.bastion.key_path"), &state.tunnel_form.private_key)
                .on_input(Message::TunnelFormKeyChanged).padding(6).size(12.0 * scale);
            let browse = button(text(i18n::t("proxy.bastion.browse")).color(c_accent).size(11.0 * scale))
                .on_press(Message::TunnelFormBrowseKey)
                .padding(Padding::from([4, 8])).style(transparent_button_style);
            let pass = input(i18n::t("proxy.bastion.passphrase"), &state.tunnel_form.passphrase)
                .on_input(Message::TunnelFormPassphraseChanged).padding(6).size(12.0 * scale).secure(true)
                .id(text_input::Id::new(TUNNEL_PASSPHRASE_INPUT_ID));
            column![row![key_in, browse].spacing(4), pass].spacing(space::S).into()
        } else {
            input(i18n::t("proxy.password"), &state.tunnel_form.password)
                .on_input(Message::TunnelFormPasswordChanged).padding(6).size(12.0 * scale).secure(true)
                .id(text_input::Id::new(TUNNEL_PASSWORD_INPUT_ID))
                .into()
        };

        let fwd_label = text(i18n::t("tunnel.forwards_label")).color(theme::TEXT_SECONDARY).size(11.0 * scale);
        let fwd_hint = text(i18n::t("tunnel.forwards_hint")).color(theme::TEXT_MUTED).size(10.0 * scale);
        let fwd_in = input("", &state.tunnel_form.forwards_text)
            .on_input(Message::TunnelFormForwardsChanged).padding(6).size(12.0 * scale);

        let save = button(text(i18n::t("proxy.save")).size(11.0 * scale))
            .on_press(Message::SaveTunnel).padding(Padding::from([4, 12])).style(accent_button_style);
        let cancel = button(text(i18n::t("proxy.cancel")).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::HideTunnelForm).padding(Padding::from([4, 8])).style(transparent_button_style);

        let form_col = column![
            text(form_title).color(c_primary).size(13.0 * scale),
            name_in,
            row![host_in, port_in].spacing(4),
            user_in,
            row![auth_pwd_btn, auth_key_btn].spacing(4),
            secret,
            fwd_label,
            fwd_hint,
            fwd_in,
            row![cancel, save].spacing(8),
        ].spacing(space::S).padding(10).width(Fill);

        list_col = list_col.push(
            container(form_col).style(|_| container::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                ..Default::default()
            })
        );
    }

    if state.tunnels.is_empty() && !state.show_tunnel_form {
        list_col = list_col.push(
            container(text(i18n::t("tunnel.empty")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([16, 8])),
        );
    }

    let states = state.tunnel_manager.states();
    for t in &state.tunnels {
        let id = t.id.clone();
        let tid1 = id.clone();
        let tid2 = id.clone();
        let tid3 = id.clone();
        let st = states.get(&id).cloned().unwrap_or(crate::tunnel::TunnelState::Stopped);

        let (status_text, status_color) = match &st {
            crate::tunnel::TunnelState::Stopped => (i18n::t("tunnel.stopped").to_string(), theme::TEXT_MUTED),
            crate::tunnel::TunnelState::Starting => (i18n::t("tunnel.starting").to_string(), theme::WARNING),
            crate::tunnel::TunnelState::Running { connections, .. } =>
                (format!("{} ({})", i18n::t("tunnel.running"), connections), theme::SUCCESS),
            crate::tunnel::TunnelState::Failed(e) => (format!("ERR: {}", e), theme::DANGER),
        };

        let running = st.is_running();
        let run_btn: Element<'_, Message> = if running {
            button(text(i18n::t("tunnel.stop")).color(c_danger).size(10.0 * scale))
                .on_press(Message::StopTunnel(tid1))
                .padding(Padding::from([2, 6])).style(transparent_button_style).into()
        } else {
            button(text(i18n::t("tunnel.start")).color(c_success).size(10.0 * scale))
                .on_press(Message::StartTunnel(tid1))
                .padding(Padding::from([2, 6])).style(transparent_button_style).into()
        };
        let edit = button(text(i18n::t("proxy.edit")).color(theme::TEXT_SECONDARY).size(10.0 * scale))
            .on_press(Message::ShowTunnelForm(Some(tid2)))
            .padding(Padding::from([2, 6])).style(transparent_button_style);
        let del = button(text(i18n::t("proxy.delete")).color(c_danger).size(10.0 * scale))
            .on_press(Message::DeleteTunnel(tid3))
            .padding(Padding::from([2, 6])).style(transparent_button_style);

        let forwards_summary = t.forwards.iter()
            .map(|f| f.spec())
            .collect::<Vec<_>>().join(", ");

        let entry = row![
            column![
                text(&t.name).color(c_primary).size(12.0 * scale),
                text(format!("{}@{}:{}", t.username, t.ssh_host, t.ssh_port)).color(theme::TEXT_MUTED).size(10.0 * scale),
                text(forwards_summary).color(theme::TEXT_MUTED).size(10.0 * scale),
                text(status_text).color(status_color).size(10.0 * scale),
            ].spacing(2).width(Fill),
            run_btn, edit, del,
        ].spacing(4).align_y(alignment::Vertical::Center);

        list_col = list_col.push(
            container(entry).padding(Padding::from([6, 10])).width(Fill)
                .style(|_| container::Style {
                    background: Some(theme::BG_TERTIARY.into()),
                    border: iced::Border { color: theme::BORDER, width: 1.0, radius: 4.0.into() },
                    ..Default::default()
                })
        );
    }

    let content = column![header, slim_scroll(list_col).height(Fill)]
        .spacing(space::M).padding(16).width(480);

    let card = container(content).height(Fill).style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        shadow: iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.4), offset: iced::Vector::new(-4.0, 0.0), blur_radius: 16.0 },
        ..Default::default()
    });
    let overlay = row![horizontal_space(), card];
    container(overlay).width(Fill).height(Fill).into()
}

// ---- Connection form (modal overlay) -------------------------------------

pub(crate) fn view_connection_form_overlay(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let title_text = if state.edit_id.is_some() {
        i18n::t("form.edit_title")
    } else {
        i18n::t("form.new_title")
    };

    let title = text(title_text).size(16.5 * scale).color(c_primary);
    let on_accent_label = on_accent(c_accent);

    let name_input = labeled_input(&i18n::t("form.name"), &state.form.name, Message::FormNameChanged);
    let host_input = labeled_input(&i18n::t("form.host"), &state.form.host, Message::FormHostChanged);
    let port_input = labeled_input(&i18n::t("form.port"), &state.form.port, Message::FormPortChanged);
    let user_input = labeled_input(
        &i18n::t("form.username"),
        &state.form.username,
        Message::FormUsernameChanged,
    );

    // One segment per `auth_type` the SSH layer accepts.
    let auth_choice = |value: &'static str, label: &'static str| {
        let on = state.form.auth_type == value;
        button(
            text(label)
                .color(if on { on_accent_label } else { theme::TEXT_MUTED })
                .size(13.0 * scale),
        )
        .on_press(Message::FormAuthTypeChanged(value.into()))
        .padding(Padding::from([6, 12]))
        .style(if on { accent_button_style } else { transparent_button_style })
    };
    let auth_row = row![
        auth_choice("password", i18n::t("form.password")),
        auth_choice("key", i18n::t("form.private_key")),
        auth_choice("interactive", i18n::t("form.auth_interactive")),
        auth_choice("agent", i18n::t("form.auth_agent")),
    ]
    .spacing(8);

    let auth_label = text(i18n::t("form.auth_type")).color(theme::TEXT_SECONDARY).size(12.0 * scale);

    // Placeholder hint for secret fields during edit (empty = keep existing)
    let is_editing = state.edit_id.is_some();
    let secret_placeholder = if is_editing { i18n::t("form.keep_existing") } else { "" };

    let auth_fields: Element<'_, Message> = if state.form.auth_type == "key" {
        let key_label = text(i18n::t("form.key_path")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let key_input = input(secret_placeholder, &state.form.private_key)
            .on_input(Message::FormPrivateKeyChanged)
            .padding(8)
            .size(14.0 * scale);
        let browse_btn = button(text(i18n::t("form.browse")).color(c_accent).size(12.0 * scale))
            .on_press(Message::BrowseKeyFile)
            .padding(Padding::from([6, 12]))
            .style(transparent_button_style);
        let key_field: Element<'_, Message> = column![
            key_label,
            row![key_input, browse_btn]
                .spacing(8)
                .align_y(alignment::Vertical::Center),
        ]
        .spacing(4)
        .into();

        let pass_label = text(i18n::t("form.passphrase")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let pass_input = input(secret_placeholder, &state.form.passphrase)
            .on_input(Message::FormPassphraseChanged)
            .secure(true)
            .id(text_input::Id::new(CONN_PASSPHRASE_INPUT_ID))
            .padding(8)
            .size(14.0 * scale);

        column![key_field, column![pass_label, pass_input].spacing(4)]
            .spacing(12)
            .into()
    } else if state.form.auth_type == "agent" {
        // Nothing to store: the keys stay in the agent.
        text(i18n::t("form.agent_hint")).color(theme::TEXT_MUTED).size(12.0 * scale).into()
    } else {
        let interactive = state.form.auth_type == "interactive";
        let pw_label = text(i18n::t(if interactive { "form.password_optional" } else { "form.password" }))
            .color(theme::TEXT_SECONDARY)
            .size(12.0 * scale);
        let pw_input = input(secret_placeholder, &state.form.password)
            .on_input(Message::FormPasswordChanged)
            .secure(true)
            .id(text_input::Id::new(CONN_PASSWORD_INPUT_ID))
            .padding(8)
            .size(14.0 * scale);
        let mut fields = column![pw_label, pw_input].spacing(4);
        if interactive {
            fields = fields.push(
                text(i18n::t("form.interactive_hint")).color(theme::TEXT_MUTED).size(11.0 * scale),
            );
        }
        fields.into()
    };

    let group_input: Element<'_, Message> = {
        let label_text = text(i18n::t("form.group")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
        let input = input("", &state.form.group)
            .on_input(Message::FormGroupChanged)
            .on_submit(Message::SaveForm)
            .padding(8)
            .size(14.0 * scale);
        column![label_text, input].spacing(4).into()
    };

    // Proxy selection
    let proxy_label = text(i18n::t("proxy.select")).color(theme::TEXT_SECONDARY).size(12.0 * scale);
    let mut proxy_row = row![
        button(
            text(i18n::t("proxy.none"))
                .color(if state.form.proxy_id.is_empty() { on_accent_label } else { theme::TEXT_MUTED })
                .size(11.0 * scale)
        )
        .on_press(Message::FormProxyChanged(String::new()))
        .padding(Padding::from([4, 8]))
        .style(if state.form.proxy_id.is_empty() { accent_button_style } else { transparent_button_style }),
    ].spacing(4);
    for p in &state.proxies {
        let is_sel = state.form.proxy_id == p.id;
        let label = format!("{} ({})", p.name, p.proxy_type);
        let pid = p.id.clone();
        proxy_row = proxy_row.push(
            button(text(label).color(if is_sel { on_accent_label } else { theme::TEXT_MUTED }).size(11.0 * scale))
                .on_press(Message::FormProxyChanged(pid))
                .padding(Padding::from([4, 8]))
                .style(if is_sel { accent_button_style } else { transparent_button_style }),
        );
    }
    let proxy_input: Element<'_, Message> = column![proxy_label, proxy_row].spacing(4).into();

    // Error: show truncated, single-line
    let error_row: Element<'_, Message> = if state.error_message.is_empty() {
        Space::new(0, 0).into()
    } else {
        // Char-based on purpose: translate_ssh_error appends a translated hint,
        // so error_message routinely mixes ASCII with CJK. A byte slice here
        // splits a multi-byte char and, under panic = "abort", kills the app.
        let short = truncate_str(&state.error_message, 57);
        text(short).color(c_danger).size(11.0 * scale).into()
    };

    // Test result row
    let test_row: Element<'_, Message> = if state.form_testing {
        text(i18n::t("form.testing")).color(c_accent).size(12.0 * scale).into()
    } else if let Some(r) = &state.form_test_result {
        if r.ok {
            text(format!("{} {} ms", i18n::t("form.test_ok"), r.latency_ms))
                .color(c_success).size(12.0 * scale).into()
        } else {
            let msg = r.error.clone().unwrap_or_else(|| "unknown".into());
            column![
                text(format!("{} [{}]", i18n::t("form.test_fail"), r.stage))
                    .color(c_danger).size(12.0 * scale),
                text(msg).color(theme::TEXT_MUTED).size(11.0 * scale),
            ].spacing(2).into()
        }
    } else { Space::new(0, 0).into() };

    let test_btn: Element<'_, Message> = if state.form_testing {
        button(text(i18n::t("form.testing")).color(theme::TEXT_MUTED).size(14.0 * scale))
            .padding(Padding::from([8, 16]))
            .style(transparent_button_style).into()
    } else {
        button(text(i18n::t("form.test")).color(c_accent).size(14.0 * scale))
            .on_press(Message::TestFormConnection)
            .padding(Padding::from([8, 16]))
            .style(transparent_button_style).into()
    };

    let buttons = row![
        button(text(i18n::t("form.cancel")).color(theme::TEXT_SECONDARY).size(14.0 * scale))
            .on_press(Message::HideForm)
            .padding(Padding::from([8, 20]))
            .style(transparent_button_style),
        horizontal_space(),
        test_btn,
        button(text(i18n::t("form.save")).size(14.0 * scale))
            .on_press(Message::SaveForm)
            .padding(Padding::from([8, 20]))
            .style(accent_button_style),
    ]
    .spacing(12)
    .align_y(alignment::Vertical::Center);

    let form_content = column![
        title,
        name_input,
        host_input,
        port_input,
        user_input,
        auth_label,
        auth_row,
        auth_fields,
        group_input,
        proxy_input,
    ]
    .spacing(12);

    // Scrollable form + fixed bottom (test result + error + buttons)
    let form = column![
        slim_scroll(form_content).height(Fill),
        test_row,
        error_row,
        buttons,
    ]
    .spacing(8)
    .width(440)
    .padding(24);

    iced::widget::center(modal_card(form).max_height(780)).into()
}
