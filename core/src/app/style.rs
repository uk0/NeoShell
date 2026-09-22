use super::*;
// Explicit: through the glob above, `column` is ambiguous with std's `column!`.
use iced::widget::column;

/// Green / orange / red by load: a bar's colour when the theme sets none.
pub(crate) fn heat_color(pct: f64) -> Color {
    if pct > 90.0 {
        theme::DANGER
    } else if pct > 70.0 {
        theme::WARNING
    } else {
        theme::SUCCESS
    }
}

// ---- Listening ports (bottom tab) -------------------------------------------

pub(crate) fn sys_row_sized(label_str: &str, value_str: &str, size: f32) -> Element<'static, Message> {
    let l = label_str.to_string();
    let v = value_str.to_string();
    container(
        row![
            container(text(l).color(theme::TEXT_MUTED).size(size)).width(72),
            container(text(v).color(theme::TEXT_SECONDARY).size(size))
                .width(Fill).align_x(alignment::Horizontal::Right),
        ]
        .spacing(space::S)
        .align_y(alignment::Vertical::Center)
    )
    .padding(Padding::from([4, 10]))
    .width(Fill)
    .into()
}

pub(crate) fn progress_bar_widget_with_color(percent: f64, user_color: Option<Color>) -> Element<'static, Message> {
    let clamped = percent.max(0.0).min(100.0);
    // When the user set a custom progress color in the theme editor, use it.
    // Otherwise keep the heat-gauge (green/orange/red) behavior.
    let bar_color = user_color.unwrap_or_else(|| {
        if clamped > 90.0 { theme::DANGER }
        else if clamped > 70.0 { theme::WARNING }
        else { theme::SUCCESS }
    });

    // Proportional fill: the bar tracks its container's width (sidebar or
    // bottom panel) instead of a hardcoded 196 px that overflowed narrow
    // layouts and underfilled wide ones. 0% renders an empty track — no
    // leftover dot.
    let filled = clamped.round() as u16;
    let track: Element<'static, Message> = if filled == 0 {
        Space::new(Fill, 4).into()
    } else {
        let empty = (100u16 - filled.min(100)).max(1);
        row![
            container(Space::new(Fill, 4))
                .width(Length::FillPortion(filled))
                .style(move |_| container::Style {
                    background: Some(bar_color.into()),
                    border: iced::Border { radius: 2.0.into(), ..Default::default() },
                    ..Default::default()
                }),
            Space::new(Length::FillPortion(empty), 4),
        ]
        .into()
    };

    container(track)
        .padding(Padding::new(2.0).left(10.0).right(10.0).bottom(5.0))
        .width(Fill)
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            ..Default::default()
        })
        .into()
}

// ---- Terminal area -------------------------------------------------------

pub(crate) fn detail_row(label: &str, value: &str) -> Element<'static, Message> {
    let l = label.to_string();
    let v = value.to_string();
    row![
        text(l).color(theme::TEXT_MUTED).size(13).width(140),
        text(v).color(theme::TEXT_PRIMARY).size(13),
    ]
    .spacing(8)
    .into()
}

// ---- File editor (modal overlay) -----------------------------------------

/// Thin horizontal rule used between Settings sections.
pub(crate) fn hr_space() -> Element<'static, Message> {
    container(Space::new(Fill, 1))
        .width(Fill)
        .style(|_| container::Style {
            background: Some(theme::BORDER.into()),
            ..Default::default()
        })
        .into()
}

// ---- About dialog ----------------------------------------------------------

/// Helper: a labeled text input field.
pub(crate) fn labeled_input<'a>(
    label: &'a str,
    value: &'a str,
    on_change: impl Fn(String) -> Message + 'a,
) -> Element<'a, Message> {
    let label_text = text(label).color(theme::TEXT_SECONDARY).size(12);
    let input = input("", value).on_input(on_change).padding(8).size(14);
    column![label_text, input].spacing(4).into()
}

// ---------------------------------------------------------------------------
// Terminal canvas program
// ---------------------------------------------------------------------------

pub(crate) fn format_bytes(bytes: u64) -> String {
    if bytes > 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes > 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes > 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Convert raw size string from `ls -la` (bytes) to human-readable KB/MB/GB.
pub(crate) fn humanize_file_size(size_str: &str) -> String {
    match size_str.trim().parse::<u64>() {
        Ok(bytes) => {
            if bytes >= 1_099_511_627_776 {
                format!("{:.1} TB", bytes as f64 / 1_099_511_627_776.0)
            } else if bytes >= 1_073_741_824 {
                format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
            } else if bytes >= 1_048_576 {
                format!("{:.1} MB", bytes as f64 / 1_048_576.0)
            } else if bytes >= 1024 {
                format!("{:.1} KB", bytes as f64 / 1024.0)
            } else {
                format!("{} B", bytes)
            }
        }
        Err(_) => size_str.to_string(), // Already formatted or not a number
    }
}

pub(crate) fn truncate_str(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}...", truncated)
    } else {
        s.to_string()
    }
}

/// `s` fitted to `cols` display columns — a CJK character takes two, see
/// `terminal::truncate_to_width` — and whether that cut anything. A cut label
/// carries its full text in a tooltip ([`tip_if`]).
pub(crate) fn clip_to_width(s: &str, cols: usize) -> (String, bool) {
    let short = crate::terminal::truncate_to_width(s, cols);
    let cut = short != s;
    (short, cut)
}

/// A column budget meant for the default UI font size, at `scale`: text in
/// the fixed-width sidebar grows with the font, the sidebar does not.
pub(crate) fn cols_at_scale(cols: usize, scale: f32) -> usize {
    ((cols as f32 / scale.max(0.5)).floor() as usize).max(6)
}

/// `s` cut to at most `max_cols` display columns by taking out its middle:
/// the head and the tail stay, joined by "…". For a file name that keeps the
/// extension, and any mark [`visible_name`] put at its end.
pub(crate) fn truncate_middle_to_width(s: &str, max_cols: usize) -> String {
    use crate::terminal::display_width;
    if display_width(s) <= max_cols {
        return s.to_string();
    }
    let Some(budget) = max_cols.checked_sub(1) else {
        return String::new();
    };
    let cols = |c: char| display_width(c.encode_utf8(&mut [0u8; 4]));
    let chars: Vec<char> = s.chars().collect();
    let tail_budget = budget / 2;
    let head_budget = budget - tail_budget;
    let (mut tail_start, mut used) = (chars.len(), 0);
    while tail_start > 0 && used + cols(chars[tail_start - 1]) <= tail_budget {
        used += cols(chars[tail_start - 1]);
        tail_start -= 1;
    }
    // A combining mark whose base was left out goes with it.
    while tail_start < chars.len() && cols(chars[tail_start]) == 0 {
        tail_start += 1;
    }
    let (mut head_end, mut used) = (0, 0);
    while head_end < tail_start && used + cols(chars[head_end]) <= head_budget {
        used += cols(chars[head_end]);
        head_end += 1;
    }
    let mut out: String = chars[..head_end].iter().collect();
    out.push('…');
    out.extend(&chars[tail_start..]);
    out
}

/// A remote name as the file browser and its confirmations show it: exactly,
/// with what would not show made visible. A space at either end, or next to
/// another space, reads "·" — a co-tenant's "project " beside a user's
/// "project" used to look the same — and any other whitespace, control or
/// invisible formatting character (zero-width, bidi override, BOM, soft
/// hyphen) is written as its `\u{…}` escape. A name holding none of these
/// comes back unchanged.
pub(crate) fn visible_name(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == ' ' {
            let edge = i == 0 || i + 1 == chars.len();
            let run = (i > 0 && chars[i - 1] == ' ') || chars.get(i + 1) == Some(&' ');
            out.push(if edge || run { '·' } else { ' ' });
        } else {
            push_visible(&mut out, c, i.checked_sub(1).map(|p| chars[p]));
        }
    }
    out
}

/// A remote path with each component shown as [`visible_name`] shows it.
pub(crate) fn visible_path(path: &str) -> String {
    path.split('/').map(visible_name).collect::<Vec<_>>().join("/")
}

/// `s` with every character that would not show written as its escape, as
/// [`visible_name`] does, but spaces left alone: for a command line.
pub(crate) fn visible_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev = None;
    for c in s.chars() {
        push_visible(&mut out, c, prev);
        prev = Some(c);
    }
    out
}

/// Push `c` onto `out`, or its `\u{…}` escape if it would not show. A
/// variation selector is kept after anything but ASCII — emoji use them — and
/// escaped after ASCII, where it changes nothing on screen.
pub(crate) fn push_visible(out: &mut String, c: char, prev: Option<char>) {
    let selector = matches!(c, '\u{FE00}'..='\u{FE0F}');
    let hidden = c.is_control()
        || (c.is_whitespace() && c != ' ')
        || (selector && prev.is_none_or(|p| p.is_ascii()))
        || matches!(
            c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}'
                | '\u{17B5}' | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}' | '\u{3164}' | '\u{FEFF}' | '\u{FFA0}'
        );
    if hidden {
        out.extend(c.escape_unicode());
    } else {
        out.push(c);
    }
}

/// "folder", "file", … for the confirmations that state what they touch.
pub(crate) fn entry_kind_label(kind: EntryKind) -> &'static str {
    i18n::t(match kind {
        EntryKind::File => "sftp.kind.file",
        EntryKind::Dir => "sftp.kind.dir",
        EntryKind::Symlink => "sftp.kind.symlink",
        EntryKind::Other => "sftp.kind.other",
    })
}

// ---------------------------------------------------------------------------
// Style helpers
// ---------------------------------------------------------------------------

pub(crate) fn bg_primary_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(theme::BG_PRIMARY.into()),
        ..Default::default()
    }
}


/// macOS-style slim scrollbar: no track, 4 px rounded thumb that
/// brightens on hover / drag.
pub(crate) fn slim_scrollbar_style(
    _theme: &Theme,
    status: iced::widget::scrollable::Status,
) -> iced::widget::scrollable::Style {
    use iced::widget::scrollable::{Rail, Scroller, Style};
    let engaged = matches!(
        status,
        iced::widget::scrollable::Status::Hovered { .. }
            | iced::widget::scrollable::Status::Dragged { .. }
    );
    let thumb = if engaged {
        Color::from_rgba(1.0, 1.0, 1.0, 0.35)
    } else {
        Color::from_rgba(1.0, 1.0, 1.0, 0.16)
    };
    let rail = Rail {
        background: None,
        border: iced::Border::default(),
        scroller: Scroller {
            color: thumb,
            border: iced::Border {
                radius: 99.0.into(),
                ..Default::default()
            },
        },
    };
    Style {
        container: container::Style::default(),
        vertical_rail: rail,
        horizontal_rail: rail,
        gap: None,
    }
}

/// Vertical scrollable with the slim scrollbar (4 px thumb, 2 px margin).
pub(crate) fn slim_scroll<'a>(
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::Scrollable<'a, Message> {
    iced::widget::scrollable(content)
        .direction(iced::widget::scrollable::Direction::Vertical(
            iced::widget::scrollable::Scrollbar::new()
                .width(4)
                .scroller_width(4)
                .margin(2),
        ))
        .style(slim_scrollbar_style)
}

/// Input field with rounded corners + accent focus ring (macOS-like).
/// Accent and text follow the live theme, like the other shared styles.
pub(crate) fn input_style(
    _theme: &Theme,
    status: iced::widget::text_input::Status,
) -> iced::widget::text_input::Style {
    let focused = matches!(status, iced::widget::text_input::Status::Focused);
    let live = theme_config::live();
    let accent = live.accent.to_color();
    iced::widget::text_input::Style {
        background: theme::BG_PRIMARY.into(),
        border: iced::Border {
            radius: 8.0.into(),
            width: 1.0,
            color: if focused { accent } else { theme::BORDER },
        },
        icon: theme::TEXT_MUTED,
        placeholder: theme::TEXT_MUTED,
        value: live.text_primary.to_color(),
        selection: tint(accent, 0.35),
    }
}

/// text_input constructor with the shared style pre-applied.
pub(crate) fn input<'a>(placeholder: &str, value: &str) -> iced::widget::TextInput<'a, Message> {
    iced::widget::text_input(placeholder, value).style(input_style)
}

/// `color` at `alpha` opacity — washes and hover fills derived from a theme
/// token, so they follow the user's palette instead of a baked-in RGB.
pub(crate) fn tint(color: Color, alpha: f32) -> Color {
    Color { a: alpha.clamp(0.0, 1.0), ..color }
}

/// Linear blend from `a` toward `b`. `t` is clamped, so unlike scaling the
/// channels the result can never leave the gamut.
pub(crate) fn mix(a: Color, b: Color, t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    Color {
        r: a.r + (b.r - a.r) * t,
        g: a.g + (b.g - a.g) * t,
        b: a.b + (b.b - a.b) * t,
        a: a.a + (b.a - a.a) * t,
    }
}

/// WCAG 2.1 relative luminance.
pub(crate) fn rel_luminance(c: Color) -> f32 {
    let lin = |v: f32| {
        if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b)
}

/// WCAG contrast ratio between two opaque colours; always >= 1.
pub(crate) fn contrast_ratio(a: Color, b: Color) -> f32 {
    let (la, lb) = (rel_luminance(a), rel_luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// How far toward white a filled button moves on hover.
pub(crate) const HOVER_LIFT: f32 = 0.10;

/// Fill and label colour for a solid button in `base`, chosen so the label
/// clears WCAG AA (4.5:1) on the resting fill *and* on the hover fill, for
/// whatever colour the user's theme puts there.
///
/// Mid and dark colours keep white text and are darkened only as far as that
/// needs: the shipped accent #6366F1 measures 3.62:1 under TEXT_PRIMARY and
/// 4.47:1 under white, so it moves 15% toward black. Light colours (Nord
/// frost, Gruvbox yellow, Dracula purple) would turn muddy long before white
/// reads on them, so they keep their own colour and take dark text instead.
pub(crate) fn fill_and_label(base: Color) -> (Color, Color) {
    const AA: f32 = 4.5;
    let base = Color { a: 1.0, ..base };
    let white_reads = |fill: Color| {
        contrast_ratio(Color::WHITE, fill) >= AA
            && contrast_ratio(Color::WHITE, mix(fill, Color::WHITE, HOVER_LIFT)) >= AA
    };
    let darkened = |step: u8| mix(base, Color::BLACK, f32::from(step) * 0.05);
    if let Some(fill) = (0..=6).map(darkened).find(|&f| white_reads(f)) {
        return (fill, Color::WHITE);
    }
    // Hover only lightens, which can only raise dark-on-fill contrast.
    if contrast_ratio(theme::BG_PRIMARY, base) >= AA {
        return (base, theme::BG_PRIMARY);
    }
    // Reads under neither label at its own lightness: keep darkening. Pure
    // black (step 20) passes, so the search always ends inside the range.
    let fill = (7..=20).map(darkened).find(|&f| white_reads(f)).unwrap_or(Color::BLACK);
    (fill, Color::WHITE)
}

/// Solid button in `base` with an AA-safe label (see [`fill_and_label`]).
/// Labels inside must not set their own colour — they inherit `text_color`.
pub(crate) fn filled_button_style(base: Color) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_theme, status| {
        let (fill, label) = fill_and_label(base);
        let background = match status {
            button::Status::Hovered => mix(fill, Color::WHITE, HOVER_LIFT),
            _ => fill,
        };
        button::Style {
            background: Some(background.into()),
            text_color: label,
            border: iced::Border {
                radius: 8.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

/// Primary button in the live accent.
pub(crate) fn accent_button_style(theme: &Theme, status: button::Status) -> button::Style {
    filled_button_style(theme_config::live().accent.to_color())(theme, status)
}

/// Label colour for text that sits on an accent fill but is coloured by the
/// caller — segmented toggles, the palette's selected row.
pub(crate) fn on_accent(accent: Color) -> Color {
    fill_and_label(accent).1
}

pub(crate) fn transparent_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Some(theme::BG_HOVER.into()),
        _ => None,
    };
    button::Style {
        background: bg,
        text_color: theme_config::live().text_primary.to_color(),
        border: iced::Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Secondary action next to a filled primary: hairline outline, no fill.
pub(crate) fn outline_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: matches!(status, button::Status::Hovered)
            .then(|| theme::BG_HOVER.into()),
        text_color: theme_config::live().text_primary.to_color(),
        border: iced::Border {
            color: theme::BORDER_STRONG,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    }
}

pub(crate) fn sidebar_item_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Some(theme::BG_HOVER.into()),
        _ => Some(Color::TRANSPARENT.into()),
    };
    button::Style {
        background: bg,
        text_color: theme_config::live().text_primary.to_color(),
        border: iced::Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// One segment of a tab strip. The active segment keeps its fill whatever the
/// pointer does; hover only previews an inactive one, at half strength, so a
/// hovered tab can never be mistaken for the selected one.
pub(crate) fn segment_style(active: bool, status: button::Status) -> button::Style {
    let background = if active {
        Some(theme::BG_HOVER.into())
    } else if matches!(status, button::Status::Hovered) {
        Some(tint(theme::BG_HOVER, 0.5).into())
    } else {
        None
    };
    button::Style {
        background,
        border: iced::Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Hover label for a control whose face is a glyph ("x", "+", "<|", "R"...),
/// placed below it.
pub(crate) fn tip<'a>(el: impl Into<Element<'a, Message>>, label: &str) -> Element<'a, Message> {
    tip_at(el, label, iced::widget::tooltip::Position::Bottom)
}

/// `el` with `full` as its tooltip when its label was `cut` to fit (see
/// [`clip_to_width`]); as it is otherwise.
pub(crate) fn tip_if<'a>(el: impl Into<Element<'a, Message>>, cut: bool, full: &str) -> Element<'a, Message> {
    if cut {
        tip(el, full)
    } else {
        el.into()
    }
}

/// [`tip`] with an explicit side — the status bar's controls sit on the
/// window's bottom edge and need theirs above.
pub(crate) fn tip_at<'a>(
    el: impl Into<Element<'a, Message>>,
    label: &str,
    position: iced::widget::tooltip::Position,
) -> Element<'a, Message> {
    let live = theme_config::live();
    let scale = live.ui_font_size / 12.0;
    iced::widget::tooltip(
        el,
        text(label.to_string())
            .size(11.0 * scale)
            .color(live.text_primary.to_color()),
        position,
    )
    .gap(space::XS)
    .padding(6)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border {
            color: theme::BORDER_STRONG,
            width: 1.0,
            radius: 6.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
            offset: iced::Vector::new(0.0, 2.0),
            blur_radius: 8.0,
        },
        ..Default::default()
    })
    .into()
}

/// Dimmed full-window layer between the main layout and an overlay. It
/// swallows left clicks, so nothing behind an open dialog can be pressed
/// through it, and claims the pointer (`Idle`), so the stack neither scrolls
/// nor hover-highlights the widgets underneath.
pub(crate) fn scrim<'a>() -> Element<'a, Message> {
    iced::widget::mouse_area(container(Space::new(Fill, Fill)).style(|_| container::Style {
        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.5).into()),
        ..Default::default()
    }))
    .on_press(Message::None)
    .interaction(mouse::Interaction::Idle)
    .into()
}

/// The shared modal surface: raised panel, hairline border, soft shadow.
/// Returns the container so callers can still size or pad it.
pub(crate) fn modal_card<'a>(
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::Container<'a, Message> {
    container(content).style(|_| modal_card_style(theme::BORDER))
}

pub(crate) fn modal_card_style(border: Color) -> container::Style {
    container::Style {
        background: Some(theme::BG_SECONDARY.into()),
        border: iced::Border {
            color: border,
            width: 1.0,
            radius: 10.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    }
}

/// `"#rrggbb"` (the `#` optional, surrounding blanks ignored) to a colour.
/// Anything else — empty, short, non-hex — is None rather than a guess.
pub(crate) fn parse_hex_color(s: &str) -> Option<Color> {
    let hex = s.trim();
    let hex = hex.strip_prefix('#').unwrap_or(hex);
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(Color::from_rgb8((n >> 16) as u8, (n >> 8) as u8, n as u8))
}
