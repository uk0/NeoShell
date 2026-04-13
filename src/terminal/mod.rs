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
    // Hangul Syllables
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
    // Enclosed CJK
    || (0x3200..=0x33FF).contains(&cp)
    // CJK Radicals
    || (0x2E80..=0x2EFF).contains(&cp)
    || (0x2F00..=0x2FDF).contains(&cp)
}

/// Convert a 256-color index to an RGB Color.
fn color_256(idx: u16) -> Color {
    if idx < 16 {
        ANSI_COLORS[idx as usize]
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
}

impl TerminalGrid {
    pub fn new(cols: usize, rows: usize) -> Self {
        let cells = vec![vec![Cell::default(); cols]; rows];
        Self {
            cols,
            rows,
            cells,
            scrollback: VecDeque::with_capacity(5000),
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

    /// Resize the terminal grid, preserving content where possible.
    pub fn resize(&mut self, new_cols: usize, new_rows: usize) {
        if new_cols == 0 || new_rows == 0 {
            return;
        }
        let mut new_cells = vec![vec![Cell::default(); new_cols]; new_rows];
        for (y, row) in self.cells.iter().enumerate() {
            if y >= new_rows {
                break;
            }
            for (x, cell) in row.iter().enumerate() {
                if x >= new_cols {
                    break;
                }
                new_cells[y][x] = cell.clone();
            }
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
    }

    /// Scroll the visible region up by one line.
    fn scroll_up(&mut self) {
        if self.scroll_top == 0 {
            self.scrollback.push_back(self.cells[0].clone());
            if self.scrollback.len() > 5000 {
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
    }

    pub fn scroll_view_down(&mut self, lines: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(lines);
    }

    /// Handle SGR (Select Graphic Rendition) escape parameters.
    fn handle_sgr(&mut self, params: &vte::Params) {
        let params: Vec<u16> = params.iter().flat_map(|sub| sub.iter().copied()).collect();

        if params.is_empty() {
            self.style = CellStyle::default();
            return;
        }

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
                30..=37 => self.style.fg = ANSI_COLORS[(params[i] - 30) as usize],
                39 => self.style.fg = DEFAULT_FG,
                // Standard background colors 40-47
                40..=47 => self.style.bg = ANSI_COLORS[(params[i] - 40) as usize],
                49 => self.style.bg = DEFAULT_BG,
                // Bright foreground 90-97
                90..=97 => self.style.fg = ANSI_COLORS[(params[i] - 90 + 8) as usize],
                // Bright background 100-107
                100..=107 => self.style.bg = ANSI_COLORS[(params[i] - 100 + 8) as usize],
                // Extended foreground color
                38 => {
                    if i + 1 < params.len() {
                        match params[i + 1] {
                            5 => {
                                // 256-color mode
                                if i + 2 < params.len() {
                                    self.style.fg = color_256(params[i + 2]);
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
                                    self.style.bg = color_256(params[i + 2]);
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
            'h' => {
                // Set Mode
                if intermediates == [b'?'] {
                    // DEC Private Mode Set
                    match first {
                        25 => self.cursor_visible = true,
                        1049 | 47 | 1047 => {
                            // Switch to alternate screen buffer
                            self.alt_screen = Some(self.cells.clone());
                            self.cells = vec![vec![Cell::default(); self.cols]; self.rows];
                            self.cursor_x = 0;
                            self.cursor_y = 0;
                        }
                        _ => {}
                    }
                }
            }
            'l' => {
                // Reset Mode
                if intermediates == [b'?'] {
                    // DEC Private Mode Reset
                    match first {
                        25 => self.cursor_visible = false,
                        1049 | 47 | 1047 => {
                            // Switch back from alternate screen buffer
                            if let Some(cells) = self.alt_screen.take() {
                                self.cells = cells;
                            }
                        }
                        _ => {}
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

// ---------------------------------------------------------------------------
// Terminal: wrapper that owns both the parser and the grid, avoiding the
// borrow-conflict of storing Parser inside TerminalGrid (which implements
// Perform).
// ---------------------------------------------------------------------------

pub struct Terminal {
    pub grid: TerminalGrid,
    parser: Parser,
}

impl Terminal {
    pub fn new(cols: usize, rows: usize) -> Self {
        Self {
            grid: TerminalGrid::new(cols, rows),
            parser: Parser::new(),
        }
    }

    /// Feed raw bytes from SSH into the terminal emulator.
    pub fn feed(&mut self, data: &[u8]) {
        for &byte in data {
            self.parser.advance(&mut self.grid, byte);
        }
    }

    /// Resize the terminal grid.
    pub fn resize(&mut self, new_cols: usize, new_rows: usize) {
        self.grid.resize(new_cols, new_rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_print() {
        let mut term = Terminal::new(80, 24);
        term.feed(b"Hello");
        assert_eq!(term.grid.cells[0][0].c, 'H');
        assert_eq!(term.grid.cells[0][1].c, 'e');
        assert_eq!(term.grid.cells[0][2].c, 'l');
        assert_eq!(term.grid.cells[0][3].c, 'l');
        assert_eq!(term.grid.cells[0][4].c, 'o');
        assert_eq!(term.grid.cursor_x, 5);
        assert_eq!(term.grid.cursor_y, 0);
    }

    #[test]
    fn test_newline() {
        let mut term = Terminal::new(80, 24);
        // LF only moves cursor down; CR+LF moves to start of next line
        term.feed(b"A\r\nB");
        assert_eq!(term.grid.cells[0][0].c, 'A');
        assert_eq!(term.grid.cells[1][0].c, 'B');
        assert_eq!(term.grid.cursor_y, 1);
    }

    #[test]
    fn test_carriage_return() {
        let mut term = Terminal::new(80, 24);
        term.feed(b"ABC\rX");
        assert_eq!(term.grid.cells[0][0].c, 'X');
        assert_eq!(term.grid.cells[0][1].c, 'B');
    }

    #[test]
    fn test_cursor_movement() {
        let mut term = Terminal::new(80, 24);
        // ESC [ 5 ; 10 H = move cursor to row 5, col 10
        term.feed(b"\x1b[5;10H");
        assert_eq!(term.grid.cursor_y, 4); // 0-indexed
        assert_eq!(term.grid.cursor_x, 9);
    }

    #[test]
    fn test_erase_display() {
        let mut term = Terminal::new(80, 24);
        term.feed(b"ABCDEF");
        // ESC [ 2 J = clear entire screen
        term.feed(b"\x1b[2J");
        for x in 0..6 {
            assert_eq!(term.grid.cells[0][x].c, ' ');
        }
    }

    #[test]
    fn test_sgr_bold() {
        let mut term = Terminal::new(80, 24);
        // ESC [ 1 m = bold
        term.feed(b"\x1b[1mX");
        assert!(term.grid.cells[0][0].style.bold);
    }

    #[test]
    fn test_sgr_color() {
        let mut term = Terminal::new(80, 24);
        // ESC [ 31 m = red foreground
        term.feed(b"\x1b[31mR");
        assert_eq!(
            term.grid.cells[0][0].style.fg,
            ANSI_COLORS[1] // red
        );
    }

    #[test]
    fn test_scroll() {
        let mut term = Terminal::new(80, 3);
        term.feed(b"Line1\nLine2\nLine3\nLine4");
        // After writing 4 lines in a 3-row terminal, first line should be in scrollback
        assert_eq!(term.grid.scrollback.len(), 1);
        assert_eq!(term.grid.scrollback[0][0].c, 'L');
    }

    #[test]
    fn test_cursor_visibility() {
        let mut term = Terminal::new(80, 24);
        assert!(term.grid.cursor_visible);
        // ESC [ ? 25 l = hide cursor
        term.feed(b"\x1b[?25l");
        assert!(!term.grid.cursor_visible);
        // ESC [ ? 25 h = show cursor
        term.feed(b"\x1b[?25h");
        assert!(term.grid.cursor_visible);
    }

    #[test]
    fn test_alt_screen() {
        let mut term = Terminal::new(80, 24);
        term.feed(b"Main screen");
        // ESC [ ? 1049 h = switch to alt screen
        term.feed(b"\x1b[?1049h");
        assert_eq!(term.grid.cells[0][0].c, ' '); // alt screen is blank
        assert!(term.grid.alt_screen.is_some());
        // ESC [ ? 1049 l = switch back
        term.feed(b"\x1b[?1049l");
        assert_eq!(term.grid.cells[0][0].c, 'M'); // restored
        assert!(term.grid.alt_screen.is_none());
    }

    #[test]
    fn test_resize() {
        let mut term = Terminal::new(80, 24);
        term.feed(b"Hello");
        term.resize(40, 12);
        assert_eq!(term.grid.cols, 40);
        assert_eq!(term.grid.rows, 12);
        assert_eq!(term.grid.cells[0][0].c, 'H');
    }
}
