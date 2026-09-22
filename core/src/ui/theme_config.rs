//! User-customizable theme: colors + font sizes persisted to `theme.json`.
//! Runtime state; iced's static `theme::*` constants stay as defaults.
//!
//! Zones currently covered:
//!   - terminal canvas background + default foreground
//!   - primary UI text color (applied to high-traffic widgets only)
//!   - accent color (primary buttons, status LOG/QUIT frames)
//!   - success / danger (status badges, run/stop buttons)
//!   - progress bar (monitor CPU / RAM / disk bars)
//!   - terminal font size (canvas)
//!   - UI font size (applied where we explicitly honor it)
//!   - the full 16-entry ANSI palette the terminal renders SGR colors with
//!
//! Two extras live here for the rest of the app:
//!   - [`PRESETS`] / [`preset_by_name`] / [`preset_names`] — well-known color
//!     schemes, each carrying a complete ANSI table.
//!   - [`live`] / [`set_live`] — a process-global snapshot of the active theme,
//!     so the shared style closures in `app.rs` (which are plain `fn`s with no
//!     access to app state) can reach the user's palette.

use iced::Color;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self { Rgb { r, g, b } }
    pub fn to_color(self) -> Color {
        Color::from_rgb8(self.r, self.g, self.b)
    }
    pub fn to_hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }
}

/// Build an `Rgb` from a packed `0xRRGGBB` literal — the notation the published
/// color schemes below are actually specified in.
const fn hex(v: u32) -> Rgb {
    Rgb::new((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

/// The 16 SGR colors, in ANSI order: 0-7 normal, 8-15 bright.
pub type AnsiPalette = [Rgb; 16];

/// NeoShell's own ANSI table, which a `theme.json` written before this field
/// existed also gets. It mirrors `terminal::ANSI_COLORS`, except that no slot
/// may sit on a default-colour sentinel — see `ThemeConfig::NEOSHELL`.
fn default_ansi() -> AnsiPalette {
    ThemeConfig::NEOSHELL.ansi
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThemeConfig {
    pub text_primary: Rgb,
    pub accent: Rgb,
    pub terminal_fg: Rgb,
    pub terminal_bg: Rgb,
    pub success: Rgb,
    pub danger: Rgb,
    pub progress_bar: Rgb,
    pub terminal_font_size: f32,
    pub ui_font_size: f32,
    /// Added after 0.7.0; `serde(default)` keeps older `theme.json` files loading.
    #[serde(default = "default_ansi")]
    pub ansi: AnsiPalette,
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self::NEOSHELL
    }
}

fn theme_path() -> PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neoshell");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("theme.json")
}

impl ThemeConfig {
    pub fn load() -> Self {
        let mut cfg: Self = std::fs::read_to_string(theme_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        cfg.sanitize();
        cfg
    }

    /// Clamp the font sizes to the range the settings sliders already enforce.
    ///
    /// `theme.json` is a plain, user-editable file and nothing validated it on
    /// the way in. `terminal_font_size` reaches the terminal canvas directly:
    /// 0.0 makes the cell width 0.0, `bounds.width / 0.0` is `inf`, Rust's
    /// saturating float->int cast turns that into `usize::MAX`, and `resize()`
    /// then tries to allocate it. `ui_font_size` of 0.0 collapses every scaled
    /// text size to zero.
    ///
    /// The `is_finite` guard is not optional: `f32::clamp` returns NaN for a
    /// NaN input, so clamping alone would leave the hole open.
    ///
    /// The bounds match `Message::ThemeTerminalFontSize` / `ThemeUiFontSize`
    /// and the two sliders in the Appearance panel exactly.
    fn sanitize(&mut self) {
        let d = Self::NEOSHELL;
        self.terminal_font_size = if self.terminal_font_size.is_finite() {
            self.terminal_font_size.clamp(8.0, 28.0)
        } else {
            d.terminal_font_size
        };
        self.ui_font_size = if self.ui_font_size.is_finite() {
            self.ui_font_size.clamp(10.0, 18.0)
        } else {
            d.ui_font_size
        };
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(theme_path(), json);
        }
    }
}

// ── Color scheme presets ────────────────────────────────────────────────────
//
// Each entry carries the full 16-color ANSI table plus the seven editable
// zones, so applying a preset changes what the terminal actually renders and
// not just the chrome. The names double as lookup keys for `preset_by_name`,
// so they stay in their published form (proper nouns) and are not translated.

impl ThemeConfig {
    /// NeoShell's shipped palette. Also what `Default` and `default_ansi` return.
    pub const NEOSHELL: Self = Self {
        text_primary:       Rgb::new(226, 232, 240),
        accent:             Rgb::new(99, 102, 241),
        terminal_fg:        Rgb::new(226, 232, 240),
        terminal_bg:        Rgb::new(26, 27, 46),
        success:            Rgb::new(34, 197, 94),
        danger:             Rgb::new(239, 68, 68),
        progress_bar:       Rgb::new(99, 102, 241),
        terminal_font_size: 14.0,
        ui_font_size:       12.0,
        // Slots 0 and 7 are #1a1b2f and #e2e8f1 on purpose: one step of blue
        // off `terminal::DEFAULT_BG` (#1a1b2e) and `DEFAULT_FG` (#e2e8f0). Do
        // not "tidy" them back. Grid colours are plain RGB, so those two values
        // double as the renderer's "use the theme's colour" sentinels: an SGR 40
        // cell painted exactly #1a1b2e is taken for an unset background and
        // vanishes into a light terminal_bg, and SGR 37 text exactly #e2e8f0 is
        // drawn in terminal_fg instead. The nudge is invisible, and
        // `no_preset_slot_is_a_default_colour_sentinel` holds every preset to
        // it. It is not a fix for truecolor: `ESC[48;2;26;27;46m` and
        // `ESC[38;2;226;232;240m` still collide, and only a "default" variant
        // in the terminal's colour type, distinct from every RGB value, would
        // close that.
        ansi: [
            hex(0x1a1b2f), hex(0xef4444), hex(0x22c55e), hex(0xf59e0b),
            hex(0x6366f1), hex(0xa855f7), hex(0x06b6d4), hex(0xe2e8f1),
            hex(0x64748b), hex(0xf87171), hex(0x4ade80), hex(0xfbbf24),
            hex(0x818cf8), hex(0xc084fc), hex(0x22d3ee), hex(0xf8fafc),
        ],
    };

    const SOLARIZED_DARK: Self = Self {
        text_primary:       hex(0x93a1a1),
        accent:             hex(0x268bd2),
        terminal_fg:        hex(0x839496),
        terminal_bg:        hex(0x002b36),
        success:            hex(0x859900),
        danger:             hex(0xdc322f),
        progress_bar:       hex(0x268bd2),
        terminal_font_size: 14.0,
        ui_font_size:       12.0,
        ansi: [
            hex(0x073642), hex(0xdc322f), hex(0x859900), hex(0xb58900),
            hex(0x268bd2), hex(0xd33682), hex(0x2aa198), hex(0xeee8d5),
            hex(0x002b36), hex(0xcb4b16), hex(0x586e75), hex(0x657b83),
            hex(0x839496), hex(0x6c71c4), hex(0x93a1a1), hex(0xfdf6e3),
        ],
    };

    /// Same 16-color table as Solarized Dark with the base tones inverted.
    ///
    /// `text_primary` deliberately stays light: it paints UI chrome that is
    /// always drawn on `theme::BG_PRIMARY`, which this preset cannot change.
    /// `terminal_fg` uses base01 rather than base00 because base00 on base3
    /// measures 4.13:1 and would miss AA.
    const SOLARIZED_LIGHT: Self = Self {
        text_primary:       hex(0x93a1a1),
        accent:             hex(0x268bd2),
        terminal_fg:        hex(0x586e75),
        terminal_bg:        hex(0xfdf6e3),
        success:            hex(0x859900),
        danger:             hex(0xdc322f),
        progress_bar:       hex(0x268bd2),
        terminal_font_size: 14.0,
        ui_font_size:       12.0,
        ansi: [
            hex(0x073642), hex(0xdc322f), hex(0x859900), hex(0xb58900),
            hex(0x268bd2), hex(0xd33682), hex(0x2aa198), hex(0xeee8d5),
            hex(0x002b36), hex(0xcb4b16), hex(0x586e75), hex(0x657b83),
            hex(0x839496), hex(0x6c71c4), hex(0x93a1a1), hex(0xfdf6e3),
        ],
    };

    const DRACULA: Self = Self {
        text_primary:       hex(0xf8f8f2),
        accent:             hex(0xbd93f9),
        terminal_fg:        hex(0xf8f8f2),
        terminal_bg:        hex(0x282a36),
        success:            hex(0x50fa7b),
        danger:             hex(0xff5555),
        progress_bar:       hex(0xbd93f9),
        terminal_font_size: 14.0,
        ui_font_size:       12.0,
        ansi: [
            hex(0x21222c), hex(0xff5555), hex(0x50fa7b), hex(0xf1fa8c),
            hex(0xbd93f9), hex(0xff79c6), hex(0x8be9fd), hex(0xf8f8f2),
            hex(0x6272a4), hex(0xff6e6e), hex(0x69ff94), hex(0xffffa5),
            hex(0xd6acff), hex(0xff92df), hex(0xa4ffff), hex(0xffffff),
        ],
    };

    const NORD: Self = Self {
        text_primary:       hex(0xd8dee9),
        accent:             hex(0x88c0d0),
        terminal_fg:        hex(0xd8dee9),
        terminal_bg:        hex(0x2e3440),
        success:            hex(0xa3be8c),
        danger:             hex(0xbf616a),
        progress_bar:       hex(0x88c0d0),
        terminal_font_size: 14.0,
        ui_font_size:       12.0,
        ansi: [
            hex(0x3b4252), hex(0xbf616a), hex(0xa3be8c), hex(0xebcb8b),
            hex(0x81a1c1), hex(0xb48ead), hex(0x88c0d0), hex(0xe5e9f0),
            hex(0x4c566a), hex(0xbf616a), hex(0xa3be8c), hex(0xebcb8b),
            hex(0x81a1c1), hex(0xb48ead), hex(0x8fbcbb), hex(0xeceff4),
        ],
    };

    const GRUVBOX_DARK: Self = Self {
        text_primary:       hex(0xebdbb2),
        accent:             hex(0xfabd2f),
        terminal_fg:        hex(0xebdbb2),
        terminal_bg:        hex(0x282828),
        success:            hex(0xb8bb26),
        danger:             hex(0xfb4934),
        progress_bar:       hex(0xfabd2f),
        terminal_font_size: 14.0,
        ui_font_size:       12.0,
        ansi: [
            hex(0x282828), hex(0xcc241d), hex(0x98971a), hex(0xd79921),
            hex(0x458588), hex(0xb16286), hex(0x689d6a), hex(0xa89984),
            hex(0x928374), hex(0xfb4934), hex(0xb8bb26), hex(0xfabd2f),
            hex(0x83a598), hex(0xd3869b), hex(0x8ec07c), hex(0xebdbb2),
        ],
    };

    const ONE_DARK: Self = Self {
        text_primary:       hex(0xabb2bf),
        accent:             hex(0x61afef),
        terminal_fg:        hex(0xabb2bf),
        terminal_bg:        hex(0x282c34),
        success:            hex(0x98c379),
        danger:             hex(0xe06c75),
        progress_bar:       hex(0x61afef),
        terminal_font_size: 14.0,
        ui_font_size:       12.0,
        ansi: [
            hex(0x282c34), hex(0xe06c75), hex(0x98c379), hex(0xe5c07b),
            hex(0x61afef), hex(0xc678dd), hex(0x56b6c2), hex(0xabb2bf),
            hex(0x5c6370), hex(0xe06c75), hex(0x98c379), hex(0xe5c07b),
            hex(0x61afef), hex(0xc678dd), hex(0x56b6c2), hex(0xffffff),
        ],
    };

    const TOMORROW_NIGHT: Self = Self {
        text_primary:       hex(0xc5c8c6),
        accent:             hex(0x81a2be),
        terminal_fg:        hex(0xc5c8c6),
        terminal_bg:        hex(0x1d1f21),
        success:            hex(0xb5bd68),
        danger:             hex(0xcc6666),
        progress_bar:       hex(0x81a2be),
        terminal_font_size: 14.0,
        ui_font_size:       12.0,
        ansi: [
            hex(0x1d1f21), hex(0xcc6666), hex(0xb5bd68), hex(0xf0c674),
            hex(0x81a2be), hex(0xb294bb), hex(0x8abeb7), hex(0xc5c8c6),
            hex(0x969896), hex(0xcc6666), hex(0xb5bd68), hex(0xf0c674),
            hex(0x81a2be), hex(0xb294bb), hex(0x8abeb7), hex(0xffffff),
        ],
    };
}

/// Every selectable scheme, in menu order. The first entry is the shipped default.
pub const PRESETS: &[(&str, ThemeConfig)] = &[
    ("NeoShell Default", ThemeConfig::NEOSHELL),
    ("Solarized Dark",   ThemeConfig::SOLARIZED_DARK),
    ("Solarized Light",  ThemeConfig::SOLARIZED_LIGHT),
    ("Dracula",          ThemeConfig::DRACULA),
    ("Nord",             ThemeConfig::NORD),
    ("Gruvbox Dark",     ThemeConfig::GRUVBOX_DARK),
    ("One Dark",         ThemeConfig::ONE_DARK),
    ("Tomorrow Night",   ThemeConfig::TOMORROW_NIGHT),
];

/// Look a preset up by its exact name, as listed by [`preset_names`].
pub fn preset_by_name(name: &str) -> Option<ThemeConfig> {
    PRESETS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, cfg)| cfg.clone())
}

/// Preset names in menu order.
pub fn preset_names() -> Vec<&'static str> {
    PRESETS.iter().map(|(n, _)| *n).collect()
}

// ── Live palette ────────────────────────────────────────────────────────────
//
// `app.rs` shares a handful of `fn(&Theme, Status) -> Style` closures between
// widgets. iced hands those no app state, so they can only read globals — which
// is why half the chrome was stuck on the static `theme::*` constants and out of
// the theme editor's reach. `app.rs` calls `set_live` once after `load()` and
// again on every theme change; the style functions call `live()`.

static LIVE: RwLock<ThemeConfig> = RwLock::new(ThemeConfig::NEOSHELL);

/// Snapshot of the active theme. Cheap enough for a style closure: one
/// uncontended read lock plus a clone of ~80 bytes.
pub fn live() -> ThemeConfig {
    LIVE.read().clone()
}

/// Publish a theme to every style closure in the process.
pub fn set_live(cfg: &ThemeConfig) {
    *LIVE.write() = cfg.clone();
}

/// Zones the user can edit in the settings panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeZone {
    TextPrimary,
    Accent,
    TerminalFg,
    TerminalBg,
    Success,
    Danger,
    ProgressBar,
}

impl ThemeZone {
    pub fn get(self, t: &ThemeConfig) -> Rgb {
        match self {
            ThemeZone::TextPrimary => t.text_primary,
            ThemeZone::Accent      => t.accent,
            ThemeZone::TerminalFg  => t.terminal_fg,
            ThemeZone::TerminalBg  => t.terminal_bg,
            ThemeZone::Success     => t.success,
            ThemeZone::Danger      => t.danger,
            ThemeZone::ProgressBar => t.progress_bar,
        }
    }
    pub fn set(self, t: &mut ThemeConfig, v: Rgb) {
        match self {
            ThemeZone::TextPrimary => t.text_primary = v,
            ThemeZone::Accent      => t.accent = v,
            ThemeZone::TerminalFg  => t.terminal_fg = v,
            ThemeZone::TerminalBg  => t.terminal_bg = v,
            ThemeZone::Success     => t.success = v,
            ThemeZone::Danger      => t.danger = v,
            ThemeZone::ProgressBar => t.progress_bar = v,
        }
    }
    pub fn label_key(self) -> &'static str {
        match self {
            ThemeZone::TextPrimary => "theme.zone.text_primary",
            ThemeZone::Accent      => "theme.zone.accent",
            ThemeZone::TerminalFg  => "theme.zone.terminal_fg",
            ThemeZone::TerminalBg  => "theme.zone.terminal_bg",
            ThemeZone::Success     => "theme.zone.success",
            ThemeZone::Danger      => "theme.zone.danger",
            ThemeZone::ProgressBar => "theme.zone.progress_bar",
        }
    }
    pub const ALL: [ThemeZone; 7] = [
        ThemeZone::TextPrimary, ThemeZone::Accent,
        ThemeZone::TerminalFg, ThemeZone::TerminalBg,
        ThemeZone::Success, ThemeZone::Danger,
        ThemeZone::ProgressBar,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linearize(c: u8) -> f64 {
        let c = c as f64 / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }

    fn luminance(c: Rgb) -> f64 {
        0.2126 * linearize(c.r) + 0.7152 * linearize(c.g) + 0.0722 * linearize(c.b)
    }

    fn contrast(a: Rgb, b: Rgb) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// `theme::BG_PRIMARY` as an `Rgb`, for the chrome-readability check below.
    const CHROME_BG: Rgb = hex(0x141525);

    /// The shipped table is the terminal's compile-time one, with a single
    /// allowed difference: where that table sits on a default-colour sentinel,
    /// the theme's slot is the same colour one step of blue off it (see
    /// `NEOSHELL`). Anything else is drift.
    #[test]
    fn default_ansi_matches_the_terminal_renderer() {
        use crate::terminal::{is_default_bg, is_default_fg, ANSI_COLORS};
        let cfg = ThemeConfig::default();
        for (i, slot) in cfg.ansi.iter().enumerate() {
            let term = ANSI_COLORS[i];
            let want = if is_default_fg(term) || is_default_bg(term) {
                (term.r, term.g, term.b + 1)
            } else {
                (term.r, term.g, term.b)
            };
            assert_eq!(
                (slot.r, slot.g, slot.b),
                want,
                "ANSI slot {i} drifted from terminal::ANSI_COLORS"
            );
        }
    }

    /// Grid colours are plain RGB, and the renderer tells "unset" apart by
    /// value (`terminal::is_default_fg` / `is_default_bg`). A palette slot on
    /// one of those values is painted as the theme's default instead of as
    /// itself: with a light terminal_bg, SGR 40 black vanishes and SGR 37
    /// white turns into terminal_fg. Any slot can be asked for as either.
    #[test]
    fn no_preset_slot_is_a_default_colour_sentinel() {
        use crate::terminal::{is_default_bg, is_default_fg};
        for (name, cfg) in PRESETS {
            for (i, slot) in cfg.ansi.iter().enumerate() {
                let c = crate::terminal::Color::rgb(slot.r, slot.g, slot.b);
                assert!(
                    !is_default_bg(c) && !is_default_fg(c),
                    "{name}: ANSI slot {i} ({}) is a default-colour sentinel",
                    slot.to_hex()
                );
            }
        }
    }

    /// A `theme.json` written before the `ansi` field existed must still load,
    /// and must come back with the shipped table rather than 16 black slots.
    #[test]
    fn legacy_json_without_ansi_still_loads() {
        let legacy = r#"{
            "text_primary": {"r":226,"g":232,"b":240},
            "accent": {"r":99,"g":102,"b":241},
            "terminal_fg": {"r":226,"g":232,"b":240},
            "terminal_bg": {"r":26,"g":27,"b":46},
            "success": {"r":34,"g":197,"b":94},
            "danger": {"r":239,"g":68,"b":68},
            "progress_bar": {"r":99,"g":102,"b":241},
            "terminal_font_size": 14.0,
            "ui_font_size": 12.0
        }"#;
        let cfg: ThemeConfig = serde_json::from_str(legacy).expect("legacy theme.json must parse");
        assert_eq!(cfg.ansi, ThemeConfig::NEOSHELL.ansi);
        assert_eq!(cfg, ThemeConfig::default());
    }

    #[test]
    fn every_preset_round_trips_through_json() {
        for (name, cfg) in PRESETS {
            let json = serde_json::to_string(cfg).expect("preset must serialize");
            let back: ThemeConfig =
                serde_json::from_str(&json).expect("preset must deserialize");
            assert_eq!(&back, cfg, "{name} did not survive a JSON round trip");
        }
    }

    #[test]
    fn preset_lookup_matches_the_name_list() {
        let names = preset_names();
        assert_eq!(names.len(), PRESETS.len());
        assert_eq!(names[0], "NeoShell Default");
        for name in &names {
            let cfg = preset_by_name(name).unwrap_or_else(|| panic!("{name} not found"));
            let (_, expected) = PRESETS
                .iter()
                .find(|(n, _)| n == name)
                .expect("name came from PRESETS");
            assert_eq!(&cfg, expected);
        }
        assert!(preset_by_name("Nord ").is_none(), "lookup must be exact");
        assert!(preset_by_name("no such scheme").is_none());
    }

    #[test]
    fn preset_names_are_unique() {
        let mut names = preset_names();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "two presets share a name");
    }

    #[test]
    fn neoshell_preset_is_the_default() {
        assert_eq!(preset_by_name("NeoShell Default"), Some(ThemeConfig::default()));
    }

    /// Terminal text must be readable on the terminal background the same preset
    /// sets, and the chrome text it sets must stay readable on `BG_PRIMARY`,
    /// which no preset can repaint.
    #[test]
    fn every_preset_is_readable() {
        for (name, cfg) in PRESETS {
            let term = contrast(cfg.terminal_fg, cfg.terminal_bg);
            assert!(
                term >= 4.5,
                "{name}: terminal_fg on terminal_bg is {term:.2}:1, below WCAG AA"
            );
            let chrome = contrast(cfg.text_primary, CHROME_BG);
            assert!(
                chrome >= 4.5,
                "{name}: text_primary on the app chrome is {chrome:.2}:1, below WCAG AA"
            );
        }
    }

    /// Font sizes coming off disk must land in the same range the sliders and
    /// the `Message` handlers enforce, including the NaN case.
    #[test]
    fn sanitize_clamps_font_sizes_from_disk() {
        let cases = [
            (0.0_f32, 8.0_f32),
            (-40.0, 8.0),
            (1e30, 28.0),
            (f32::NAN, 14.0),
            (f32::INFINITY, 14.0),
            (16.0, 16.0),
        ];
        for (input, want) in cases {
            let mut cfg = ThemeConfig {
                terminal_font_size: input,
                ui_font_size: input,
                ..ThemeConfig::default()
            };
            cfg.sanitize();
            assert_eq!(
                cfg.terminal_font_size, want,
                "terminal_font_size {input} should clamp to {want}"
            );
            assert!(
                (10.0..=18.0).contains(&cfg.ui_font_size),
                "ui_font_size {input} left the slider range as {}",
                cfg.ui_font_size
            );
        }
    }

    #[test]
    fn live_palette_publishes_and_restores() {
        assert_eq!(live(), ThemeConfig::default());
        let nord = preset_by_name("Nord").expect("Nord preset");
        set_live(&nord);
        assert_eq!(live(), nord);
        assert_eq!(live().ansi[4], hex(0x81a1c1));
        set_live(&ThemeConfig::default());
        assert_eq!(live(), ThemeConfig::default());
    }
}
