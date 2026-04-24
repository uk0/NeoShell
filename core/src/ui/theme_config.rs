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

use iced::Color;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            text_primary:       Rgb::new(226, 232, 240),
            accent:             Rgb::new(99, 102, 241),
            terminal_fg:        Rgb::new(226, 232, 240),
            terminal_bg:        Rgb::new(26, 27, 46),
            success:            Rgb::new(34, 197, 94),
            danger:             Rgb::new(239, 68, 68),
            progress_bar:       Rgb::new(99, 102, 241),
            terminal_font_size: 14.0,
            ui_font_size:       12.0,
        }
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
        std::fs::read_to_string(theme_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(theme_path(), json);
        }
    }
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
