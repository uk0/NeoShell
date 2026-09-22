use super::*;
// Explicit: through the glob above, `column` is ambiguous with std's `column!`.
use iced::widget::column;

pub(crate) fn view_tab_bar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_success = state.c_success();

    let mut tabs_row = row![].spacing(0);

    for (i, tab) in state.tabs.iter().enumerate() {
        let is_active = state.active_tab == Some(i);
        let bg_color = if is_active {
            theme::BG_PRIMARY
        } else {
            Color::TRANSPARENT
        };
        let text_color = if is_active { c_primary } else { theme::TEXT_MUTED };

        // Alert badge wins over connection state — a red dot tells the
        // operator "this box tripped a threshold" at a glance.
        let alerting = !tab.session_id.is_empty()
            && (state.alerts_active.contains_key(&tab.session_id)
                || tab
                    .split
                    .as_ref()
                    .map(|s| state.alerts_active.contains_key(&s.session_id))
                    .unwrap_or(false));
        let status_dot = if alerting {
            text("● ").color(state.c_danger()).size(10.0 * scale)
        } else if tab.session_id.is_empty() || title_reconnecting(&tab.title) {
            text("● ").color(theme::WARNING).size(10.0 * scale)
        } else {
            text("● ").color(c_success).size(10.0 * scale)
        };

        // Split indicator: ⊞-ish marker rendered as "[2]" (glyph-safe).
        let split_tag: Element<'_, Message> = if tab.split.is_some() {
            text("[2]")
                .font(Font::MONOSPACE)
                .color(theme::TEXT_MUTED)
                .size(9.0 * scale)
                .into()
        } else {
            Space::new(0, 0).into()
        };

        // Titles are capped so ten tabs still fit — by display width, so a
        // Chinese name gets the room of a Latin one, not twice it; the full
        // name is a hover away.
        let full_title = tab.display_title();
        let (short_title, truncated) = clip_to_width(full_title, 20);
        let title_text = text(short_title)
            .color(text_color)
            .size(13.0 * scale)
            .wrapping(iced::widget::text::Wrapping::None);
        let label: Element<'_, Message> = if truncated {
            tip(title_text, full_title)
        } else {
            title_text.into()
        };
        let close_btn = button(text("x").color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::TabClosed(i))
            .padding(Padding::from([2, 6]))
            .style(transparent_button_style);

        let tab_content = row![status_dot, label, split_tag, tip(close_btn, i18n::t("tip.close_tab"))]
            .spacing(8)
            .align_y(alignment::Vertical::Center);

        // The active tab keeps its fill under the pointer; hover only
        // previews inactive ones.
        let tab_btn = button(tab_content)
            .on_press(Message::TabSelected(i))
            .padding(Padding::from([6, 14]))
            .style(move |_theme: &Theme, status| button::Style {
                background: Some(
                    if !is_active && matches!(status, button::Status::Hovered) {
                        theme::BG_HOVER
                    } else {
                        bg_color
                    }
                    .into(),
                ),
                text_color,
                ..Default::default()
            });

        tabs_row = tabs_row.push(tab_btn);
    }

    if state.tabs.is_empty() {
        tabs_row = tabs_row.push(
            container(text(i18n::t("tab.no_tabs")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([8, 14])),
        );
    }

    tabs_row = tabs_row.push(tip(
        button(text("+").color(theme::TEXT_MUTED).size(14.0 * scale))
            .on_press(Message::ShowConnectDialog)
            .padding(Padding::from([6, 10]))
            .style(transparent_button_style),
        i18n::t("palette.act.connect"),
    ));

    let history_count = state.cmd_history.len();
    let history_label = if history_count > 0 {
        format!("H:{}", history_count)
    } else {
        "H".to_string()
    };
    let history_btn = tip(
        button(text(history_label).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(11.0 * scale))
            .on_press(Message::ShowHistory)
            .padding(Padding::from([6, 10]))
            .style(transparent_button_style),
        i18n::t("palette.act.history"),
    );

    // Tabs scroll sideways once they outgrow the bar (wheel or trackpad),
    // so the close buttons never run off-screen; history stays pinned.
    let strip = iced::widget::scrollable(tabs_row)
        .direction(iced::widget::scrollable::Direction::Horizontal(
            iced::widget::scrollable::Scrollbar::new()
                .width(2)
                .scroller_width(2)
                .margin(0),
        ))
        .style(slim_scrollbar_style)
        .width(Fill);

    container(row![strip, history_btn].align_y(alignment::Vertical::Center))
        .width(Fill)
        .height(34)
        .style(|_theme| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            ..Default::default()
        })
        .into()
}

// ---- Sidebar (connection list, shown when no active tab) -----------------

pub(crate) fn view_sidebar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();
    let c_success = state.c_success();
    let c_danger = state.c_danger();

    // Grouped, filtered and in display order (see `sidebar_groups`). While a
    // search runs every group with a match is open, and folding waits.
    let groups = sidebar_groups(&state.connections, &state.search_query, &state.collapsed_groups);
    let searching = !state.search_query.trim().is_empty();

    // One toggle folds or unfolds every group: "expand all" once all are
    // folded, "collapse all" otherwise.
    let fold_all: Element<'_, Message> = if searching || groups.is_empty() {
        Space::new(0, 0).into()
    } else {
        let all_folded = groups.iter().all(|g| g.collapsed);
        let (glyph, label) = if all_folded {
            ("\u{F103}", i18n::t("sidebar.expand_all"))
        } else {
            ("\u{F102}", i18n::t("sidebar.collapse_all"))
        };
        tip(
            button(text(glyph).font(NERD_ICON_FONT).color(theme::TEXT_MUTED).size(12.0 * scale))
                .on_press(Message::SetAllGroupsCollapsed(!all_folded))
                .padding(Padding::from([4, 8]))
                .style(transparent_button_style),
            label,
        )
    };

    let header = row![
        text(i18n::t("sidebar.connections")).color(c_primary).size(15.0 * scale),
        horizontal_space(),
        fold_all,
        tip(
            button(text("+").color(c_accent).size(18.0 * scale))
                .on_press(Message::ShowForm(None))
                .padding(Padding::from([2, 8]))
                .style(transparent_button_style),
            i18n::t("palette.act.new_conn"),
        ),
    ]
    .align_y(alignment::Vertical::Center)
    .padding(Padding::from([8, 12]));

    let search = input(&i18n::t("sidebar.search"), &state.search_query)
        .id(text_input::Id::new(SIDEBAR_SEARCH_INPUT_ID))
        .on_input(Message::SearchChanged)
        .padding(8)
        .size(13.0 * scale);

    let search_container = container(search).padding(Padding::new(8.0).top(0.0));

    let mut list_col = column![].spacing(4);

    // The row of the connection the active tab belongs to counts as selected:
    // it keeps a tint and its actions stay visible.
    let active_conn = state
        .active_tab
        .and_then(|i| state.tabs.get(i))
        .map(|t| t.connection_id.as_str());
    let selected_bg = mix(theme::BG_SECONDARY, c_accent, 0.16);

    for group in &groups {
        // The whole header row is the click target: chevron, name, count.
        // Chevrons come from the embedded Symbols Nerd Font — the CJK font
        // has no arrow glyphs, and a system fallback is not there on every
        // install. Keyboard users fold a group from the palette (Cmd+K, type
        // its name): iced 0.13 buttons cannot take focus.
        let full_name = group.label();
        let (name, cut) = clip_to_width(&full_name, cols_at_scale(24, scale));
        let chevron = if group.collapsed { "\u{F054}" } else { "\u{F078}" };
        let header_row = row![
            text(chevron).font(NERD_ICON_FONT).color(theme::TEXT_MUTED).size(9.0 * scale),
            text(name)
                .color(theme::TEXT_MUTED)
                .size(11.0 * scale)
                .wrapping(iced::widget::text::Wrapping::None),
            text(format!("({})", group.conns.len())).color(theme::TEXT_MUTED).size(11.0 * scale),
        ]
        .spacing(6)
        .align_y(alignment::Vertical::Center);
        let header_btn = button(header_row)
            .padding(Padding::new(6.0).left(12.0).right(12.0))
            .width(Fill)
            .style(transparent_button_style);
        // Search results are never hidden: the header folds nothing then.
        let header_btn = if searching {
            header_btn
        } else {
            header_btn.on_press(Message::ToggleGroupCollapsed(group.key.clone()))
        };
        list_col = list_col.push(tip_if(header_btn, cut, &full_name));

        if group.collapsed {
            continue;
        }

        for &conn in &group.conns {
            let is_connected = state.is_connected(&conn.id);
            let dot_color = if is_connected { c_success } else { theme::TEXT_MUTED };
            let status_dot = text("\u{25CF} ").color(dot_color).size(10.0 * scale);
            // Names and user@host:port are cut to the column by display
            // width — a Chinese character is two columns — so the row never
            // wraps; the full text is in a tooltip.
            let (name, name_cut) = clip_to_width(&conn.name, cols_at_scale(24, scale));
            let name_label = tip_if(
                text(name)
                    .color(c_primary)
                    .size(13.0 * scale)
                    .wrapping(iced::widget::text::Wrapping::None),
                name_cut,
                &conn.name,
            );
            let host_full = format!("{}@{}:{}", conn.username, conn.host, conn.port);
            let (host_disp, host_cut) = clip_to_width(&host_full, cols_at_scale(22, scale));
            let host_label = tip_if(
                text(host_disp).color(theme::TEXT_MUTED).size(10.5 * scale),
                host_cut,
                &host_full,
            );

            let proxy_tag: Element<'_, Message> = if conn.proxy_id.is_some() {
                text("P").font(Font::MONOSPACE).color(theme::WARNING).size(9.0 * scale).into()
            } else {
                Space::new(0, 0).into()
            };

            let conn_id = conn.id.clone();
            let conn_id_edit = conn.id.clone();
            let conn_id_del = conn.id.clone();
            let conn_id_test = conn.id.clone();
            let conn_id_clone = conn.id.clone();

            let test_badge: Element<'_, Message> = if let Some(r) = state.conn_test_results.get(&conn.id) {
                if r.ok {
                    text(format!("{} ms", r.latency_ms)).color(c_success).size(9.0 * scale).into()
                } else {
                    text("!").color(c_danger).size(9.0 * scale).into()
                }
            } else { Space::new(0, 0).into() };

            let edit_btn = tip(
                button(text(i18n::t("btn.edit")).color(theme::TEXT_MUTED).size(10.0 * scale))
                    .on_press(Message::ShowForm(Some(conn_id_edit)))
                    .padding(Padding::from([3, 6]))
                    .style(transparent_button_style),
                i18n::t("dialog.edit"),
            );

            let test_btn = button(text(i18n::t("conn.test")).color(c_accent).size(10.0 * scale))
                .on_press(Message::TestConnectionInList(conn_id_test))
                .padding(Padding::from([3, 6]))
                .style(transparent_button_style);

            let clone_btn = button(text(i18n::t("conn.clone")).color(theme::TEXT_MUTED).size(10.0 * scale))
                .on_press(Message::CloneConnection(conn_id_clone))
                .padding(Padding::from([3, 6]))
                .style(transparent_button_style);

            let del_btn = button(text(i18n::t("dialog.delete")).color(c_danger).size(10.0 * scale))
                .on_press(Message::DeleteConnection(conn_id_del))
                .padding(Padding::from([3, 6]))
                .style(transparent_button_style);

            // Host line is indented to sit under the name (after the
            // status dot), not flush against the sidebar edge. The test
            // badge follows the name so the hover actions never cover it.
            let info_col = column![
                row![status_dot, name_label, proxy_tag, test_badge]
                    .spacing(4).align_y(alignment::Vertical::Center),
                row![Space::with_width(Length::Fixed(16.0 * scale)), host_label],
            ].spacing(space::XS);

            // Actions only on the hovered or selected row. They float over
            // the row's right end on the row's own fill, so revealing them
            // never reflows the name. Keyboard users reach the same four
            // actions from the palette (Cmd+K, type the name): iced 0.13
            // buttons are not focus targets.
            let hovered = state.hovered_conn.as_deref() == Some(conn.id.as_str());
            let selected = active_conn == Some(conn.id.as_str());
            let row_fill = if hovered {
                Some(theme::BG_HOVER)
            } else if selected {
                Some(selected_bg)
            } else {
                None
            };

            let main_btn = button(info_col)
                .on_press(Message::ConnectTo(conn_id))
                .padding(Padding::from([7, 10]))
                .width(Fill)
                .style(move |t: &Theme, status| {
                    let mut s = sidebar_item_style(t, status);
                    if let Some(fill) = row_fill {
                        s.background = Some(fill.into());
                    }
                    s
                });

            let mut layers: Vec<Element<'_, Message>> = vec![main_btn.into()];
            // Colour tag: a 3px rail down the row's left edge.
            if let Some(rail) = parse_hex_color(&conn.color) {
                layers.push(
                    container(Space::new(Length::Fixed(3.0), Fill))
                        .height(Fill)
                        .style(move |_| container::Style {
                            background: Some(rail.into()),
                            border: iced::Border { radius: 1.5.into(), ..Default::default() },
                            ..Default::default()
                        })
                        .into(),
                );
            }
            if let Some(fill) = row_fill {
                let actions = column![
                    row![test_btn, clone_btn].spacing(space::XS),
                    row![edit_btn, del_btn].spacing(space::XS),
                ]
                .spacing(space::XXS);
                layers.push(
                    container(
                        container(actions)
                            .padding(Padding::from([0, 4]))
                            .style(move |_| container::Style {
                                background: Some(fill.into()),
                                ..Default::default()
                            }),
                    )
                    .width(Fill)
                    .height(Fill)
                    .align_x(alignment::Horizontal::Right)
                    .align_y(alignment::Vertical::Center)
                    .padding(Padding::new(0.0).right(4.0))
                    .into(),
                );
            }

            list_col = list_col.push(
                iced::widget::mouse_area(iced::widget::Stack::with_children(layers).width(Fill))
                    .on_enter(Message::SidebarHover(conn.id.clone(), true))
                    .on_exit(Message::SidebarHover(conn.id.clone(), false)),
            );
        }
    }

    if groups.is_empty() {
        list_col = list_col.push(
            container(
                text(i18n::t("sidebar.no_results"))
                    .color(theme::TEXT_MUTED)
                    .size(13.0 * scale),
            )
            .padding(Padding::from([16, 12])),
        );
    }

    let sidebar_content = column![header, search_container, slim_scroll(list_col).height(Fill)]
        .height(Fill);

    container(sidebar_content)
        .width(SIDEBAR_W)
        .height(Fill)
        .style(|_theme| container::Style {
            background: Some(theme::BG_SECONDARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}
