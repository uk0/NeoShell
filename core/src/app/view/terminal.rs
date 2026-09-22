use super::*;
// Explicit: through the glob above, `column` is ambiguous with std's `column!`.
use iced::widget::column;

/// Overlay search bar that floats in the upper-right corner of the terminal.
/// Rendered on top of the terminal canvas via `stack![]`. Uses `pick_next`
/// wiring: typing into the input fires `TerminalSearchChanged`, pressing Enter
/// fires `TerminalSearchNext`. ↑ / ↓ / Aa / × are explicit buttons.
pub(crate) fn view_terminal_search_bar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let c_accent = state.c_accent();

    let count_label = if state.term_search_query.is_empty() {
        String::new()
    } else if state.term_search_matches.is_empty() {
        i18n::t("search.no_matches").to_string()
    } else {
        format!(
            "{}/{}",
            state.term_search_current + 1,
            state.term_search_matches.len()
        )
    };

    let input = input(
        &i18n::t("search.placeholder"),
        &state.term_search_query,
    )
    .id(text_input::Id::new(TERM_SEARCH_INPUT_ID))
    .on_input(Message::TerminalSearchChanged)
    .on_submit(Message::TerminalSearchNext)
    .padding(Padding::from([4, 8]))
    .size(12.0 * scale)
    .width(Length::Fixed(200.0 * scale));

    let case_active = !state.term_search_case_insensitive;
    let (case_fill, case_label) = fill_and_label(c_accent);
    let case_btn = button(
        text("Aa")
            .size(11.0 * scale)
            .color(if case_active { case_label } else { c_primary }),
    )
    .on_press(Message::ToggleTerminalSearchCase)
    .padding(Padding::from([4, 6]))
    .style(move |_, _| button::Style {
        background: Some(if case_active {
            case_fill.into()
        } else {
            theme::BG_TERTIARY.into()
        }),
        text_color: if case_active { case_label } else { c_primary },
        border: iced::Border {
            radius: 4.0.into(),
            width: 1.0,
            color: theme::BORDER,
        },
        ..Default::default()
    });

    let nav_btn = |label: &'static str, msg: Message| {
        button(text(label).size(12.0 * scale).color(c_primary))
            .on_press(msg)
            .padding(Padding::from([4, 8]))
            .style(|_, _| button::Style {
                background: Some(theme::BG_TERTIARY.into()),
                border: iced::Border {
                    radius: 4.0.into(),
                    width: 1.0,
                    color: theme::BORDER,
                },
                ..Default::default()
            })
    };

    let bar = container(
        row![
            input,
            text(count_label)
                .size(11.0 * scale)
                .color(theme::TEXT_MUTED)
                .width(Length::Fixed(56.0 * scale)),
            nav_btn(i18n::t("search.prev"), Message::TerminalSearchPrev),
            nav_btn(i18n::t("search.next"), Message::TerminalSearchNext),
            tip(case_btn, i18n::t("tip.match_case")),
            nav_btn(i18n::t("search.close"), Message::TerminalSearchClose),
        ]
        .spacing(space::S)
        .align_y(alignment::Vertical::Center),
    )
    .padding(Padding::from([8, 10]))
    .style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border {
            radius: 8.0.into(),
            width: 1.0,
            color: theme::BORDER,
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 12.0,
        },
        ..Default::default()
    });

    // Push the bar to the top-right using a column + row with Fill spacers.
    column![
        row![Space::with_width(Fill), bar, Space::with_width(Length::Fixed(12.0))]
            .align_y(alignment::Vertical::Center),
        Space::with_height(Fill),
    ]
    .padding(Padding::from([8, 0]))
    .into()
}

pub(crate) fn view_terminal_area(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            // Selection + Cmd+F highlights only paint on the focused pane.
            let make_view = |grid: &Arc<parking_lot::Mutex<TerminalGrid>>,
                             bounds: &PaneBounds,
                             session_id: &str,
                             focused: bool|
             -> TerminalView {
                TerminalView {
                    grid: grid.clone(),
                    bounds: bounds.clone(),
                    selection_start: if focused { state.selection_start } else { None },
                    selection_end: if focused { state.selection_end } else { None },
                    font_size: state.theme_cfg.terminal_font_size,
                    session_id: session_id.to_string(),
                    ssh_manager: state.ssh_manager.clone(),
                    terminal_bg: state.theme_cfg.terminal_bg.to_color(),
                    terminal_fg: state.theme_cfg.terminal_fg.to_color(),
                    search_matches: if focused {
                        state.term_search_matches.clone()
                    } else {
                        Vec::new()
                    },
                    search_current: if focused
                        && state.term_search_active
                        && !state.term_search_matches.is_empty()
                    {
                        Some(state.term_search_current)
                    } else {
                        None
                    },
                }
            };

            let canvas_el: Element<'_, Message> = if let Some(sp) = &tab.split {
                let main_focused = !tab.focus_split;
                let main_view =
                    make_view(&tab.terminal, &tab.bounds, &tab.session_id, main_focused);
                let split_view =
                    make_view(&sp.terminal, &sp.bounds, &sp.session_id, tab.focus_split);

                // Panes share the area by `sp.ratio`; FillPortion keeps the
                // divider's fixed width out of the split, exactly as
                // `split_extent` assumes for the hit-test.
                let main_share = (sp.ratio.clamp(SPLIT_MIN, SPLIT_MAX) * 1000.0).round() as u16;
                let pane_len = |share: u16| Length::FillPortion(share.max(1));
                let (main_len, split_len) = (pane_len(main_share), pane_len(1000 - main_share));

                // Focused pane gets an accent edge so you always know where
                // keystrokes land. Click anywhere in a pane to focus it
                // (handled via SplitFocusToggle on the unfocused half).
                let pane = |v: TerminalView, focused: bool, len: Length| -> Element<'_, Message> {
                    let el: Element<'_, Message> =
                        canvas(v).width(Fill).height(Fill).into();
                    let (w, h) = if sp.vertical { (len, Length::Fill) } else { (Length::Fill, len) };
                    let bordered = container(el).width(w).height(h).style(
                        move |_| container::Style {
                            border: iced::Border {
                                color: if focused { c_accent } else { theme::BORDER },
                                width: 1.0,
                                radius: 0.0.into(),
                            },
                            ..Default::default()
                        },
                    );
                    if focused {
                        bordered.into()
                    } else {
                        // Unfocused pane: clicking it moves focus there.
                        iced::widget::mouse_area(bordered)
                            .on_press(Message::SplitFocusToggle)
                            .into()
                    }
                };

                // Drag handle: wide enough to hit, BORDER_STRONG so it reads
                // as structure, accent while it is being dragged.
                let dragging = state.split_drag.is_some();
                let divider: Element<'_, Message> = iced::widget::mouse_area(
                    container(Space::new(
                        if sp.vertical { Length::Fixed(SPLIT_DIVIDER) } else { Fill },
                        if sp.vertical { Fill } else { Length::Fixed(SPLIT_DIVIDER) },
                    ))
                    .style(move |_| container::Style {
                        background: Some(if dragging { c_accent } else { theme::BORDER_STRONG }.into()),
                        ..Default::default()
                    }),
                )
                .on_press(Message::SplitDividerPressed)
                .interaction(if sp.vertical {
                    mouse::Interaction::ResizingHorizontally
                } else {
                    mouse::Interaction::ResizingVertically
                })
                .into();

                if sp.vertical {
                    row![
                        pane(main_view, main_focused, main_len),
                        divider,
                        pane(split_view, tab.focus_split, split_len),
                    ]
                    .width(Fill)
                    .height(Fill)
                    .into()
                } else {
                    column![
                        pane(main_view, main_focused, main_len),
                        divider,
                        pane(split_view, tab.focus_split, split_len),
                    ]
                    .width(Fill)
                    .height(Fill)
                    .into()
                }
            } else {
                let term_view = make_view(&tab.terminal, &tab.bounds, &tab.session_id, true);
                canvas(term_view).width(Fill).height(Fill).into()
            };

            if state.term_search_active {
                return stack![canvas_el, view_terminal_search_bar(state)].into();
            }
            return canvas_el;
        }
    }

    // Empty state (fallback)
    let placeholder = column![
        vertical_space().height(80),
        text("NeoShell").size(36.0 * scale).color(theme::TEXT_MUTED),
        text(i18n::t("welcome.select"))
            .size(14.0 * scale)
            .color(theme::TEXT_MUTED),
    ]
    .spacing(12)
    .align_x(alignment::Horizontal::Center);

    container(placeholder)
        .width(Fill)
        .height(Fill)
        .center_x(Fill)
        .center_y(Fill)
        .style(|_theme| container::Style {
            background: Some(theme::BG_PRIMARY.into()),
            ..Default::default()
        })
        .into()
}

// ---- Transfer progress bar -----------------------------------------------

pub(crate) fn view_transfer_progress(progress: &TransferProgress) -> Element<'static, Message> {
    use std::sync::atomic::Ordering;
    let pct = progress.percent();
    let transferred = progress.transferred.load(Ordering::Relaxed);
    let total = progress.total.load(Ordering::Relaxed);
    let filename = progress.filename.lock().clone();

    // Calculate transfer speed from start_time
    let speed = if let Some(start) = progress.start_time.lock().as_ref() {
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed > 0.5 && transferred > 0 {
            format!(" — {}/s", format_bytes((transferred as f64 / elapsed) as u64))
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let label = if total > 0 {
        format!(
            "{} — {} / {} ({:.0}%){}",
            filename,
            format_bytes(transferred),
            format_bytes(total),
            pct,
            speed
        )
    } else {
        i18n::tf("transfer.preparing", &[("name", &filename)])
    };

    let progress_text = text(label).color(theme::TEXT_PRIMARY).size(11);
    let cancel_btn = button(text(i18n::t("transfer.cancel")).color(theme::DANGER).size(11))
        .on_press(Message::CancelTransfer)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    let header_row = row![progress_text, horizontal_space(), cancel_btn]
        .align_y(alignment::Vertical::Center);

    // Progress bar: fixed-width filled portion inside full-width background
    let bar_width_px = 600.0; // approximate usable width
    let filled_px = (pct / 100.0).min(1.0).max(0.0) * bar_width_px;

    let filled_bar = container(Space::new(filled_px as f32, 6))
        .style(|_| container::Style {
            background: Some(theme::ACCENT.into()),
            border: iced::Border { radius: 3.0.into(), ..Default::default() },
            ..Default::default()
        });

    let bar_bg = container(filled_bar)
        .width(Fill)
        .height(6)
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border { radius: 3.0.into(), ..Default::default() },
            ..Default::default()
        });

    container(
        column![header_row, bar_bg].spacing(4).padding(Padding::from([6, 10]))
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        ..Default::default()
    })
    .into()
}

// ---- File browser --------------------------------------------------------

// ---- Local file panel (left side of Files tab) ------------------------------
