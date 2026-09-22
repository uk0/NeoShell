use super::*;

/// Re-run search against the focused terminal's scrollback + grid.
pub(crate) fn rerun_terminal_search(state: &mut NeoShell) {
    state.term_search_matches.clear();
    state.term_search_current = 0;
    if state.term_search_query.is_empty() {
        return;
    }
    if let Some(term) = state.focused_terminal().cloned() {
        let grid = term.lock();
        state.term_search_matches =
            grid.search(&state.term_search_query, state.term_search_case_insensitive);
    }
}

/// Adjust the terminal's scroll_offset so the current match sits roughly in
/// the middle of the viewport. No-op if there are no matches.
pub(crate) fn scroll_to_current_match(state: &mut NeoShell) {
    let m_opt = state
        .term_search_matches
        .get(state.term_search_current)
        .copied();
    let term_opt = state.focused_terminal().cloned();
    if let (Some(term), Some(m)) = (term_opt, m_opt) {
        let mut grid = term.lock();
        let sb_len = grid.scrollback.len();
        let rows = grid.rows;
        if m.abs_line >= sb_len {
            grid.scroll_offset = 0;
        } else {
            let target = (sb_len as isize - m.abs_line as isize + (rows / 2) as isize).max(0) as usize;
            grid.scroll_offset = target.min(sb_len);
        }
        grid.generation = grid.generation.wrapping_add(1);
    }
}

/// Where a terminal canvas was last laid out, in window coordinates. The
/// canvas records it every time it draws, and the pointer hit-test reads it
/// back: whatever is actually on screen around the pane — the update banner,
/// the transfer bar, the other half of a split — is measured rather than
/// added up by hand from chrome heights that drift. Empty until the pane's
/// first frame.
#[derive(Clone, Default)]
pub(crate) struct PaneBounds(Arc<parking_lot::Mutex<Option<Rectangle>>>);

impl PaneBounds {
    pub(crate) fn record(&self, bounds: Rectangle) {
        *self.0.lock() = Some(bounds);
    }

    pub(crate) fn get(&self) -> Option<Rectangle> {
        *self.0.lock()
    }
}

/// Top-left of a pane's canvas: where it last drew, or `fallback` before its
/// first frame.
pub(crate) fn pane_origin(drawn: Option<Rectangle>, fallback: (f32, f32)) -> (f32, f32) {
    drawn.map_or(fallback, |b| (b.x, b.y))
}

/// Both canvases of a tab's split as last drawn, main pane first — only once
/// both have drawn: a main pane measured before the split existed still
/// spans the whole area.
pub(crate) fn drawn_split(tab: &TerminalTab) -> Option<(Rectangle, Rectangle)> {
    Some((tab.bounds.get()?, tab.split.as_ref()?.bounds.get()?))
}

/// A mouse press that went to the remote application. Its drag and its
/// release go to the same session, even if the pointer leaves the pane.
#[derive(Debug, Clone)]
pub(crate) struct MouseReport {
    pub(crate) session_id: String,
    pub(crate) button: MouseButton,
    /// Last cell reported, 1-based; motion is only sent when it changes.
    pub(crate) cell: (usize, usize),
}

pub(crate) struct TerminalView {
    pub(crate) grid: Arc<parking_lot::Mutex<TerminalGrid>>,
    pub(crate) selection_start: Option<(usize, usize)>,
    pub(crate) selection_end: Option<(usize, usize)>,
    pub(crate) font_size: f32,
    /// Carried so the canvas can propagate local-grid resizes to the remote
    /// SSH PTY — otherwise the server keeps formatting `ls`, `top`, etc. for
    /// the initial 120×40 while the client only has space for ~90 columns,
    /// and the last few columns of every row get clipped off-screen.
    pub(crate) session_id: String,
    pub(crate) ssh_manager: Arc<crate::ssh::SshManager>,
    /// The theme's terminal background and foreground: what a cell left at
    /// the grid's default colours paints in (see `cell_paint`).
    pub(crate) terminal_bg: Color,
    pub(crate) terminal_fg: Color,
    /// All Cmd+F matches in absolute-line coords; painted as yellow/orange
    /// rectangles on top of the cell background.
    pub(crate) search_matches: Vec<crate::terminal::SearchMatch>,
    /// Index into `search_matches` for the currently selected match; painted
    /// in a brighter color than the rest.
    pub(crate) search_current: Option<usize>,
    /// The pane's [`PaneBounds`]: `draw` records where it was laid out.
    pub(crate) bounds: PaneBounds,
}

/// Persistent state for the terminal canvas. Created once by iced and reused
/// across frames. The `cache` uses interior mutability so `clear()` / `draw()`
/// work through `&self`. `last_generation` is an `AtomicU64` so we can
/// compare-and-store without `&mut`.
pub(crate) struct TerminalViewState {
    pub(crate) cache: canvas::Cache,
    pub(crate) last_generation: AtomicU64,
    /// `theme_colors_key` of the colours the cached geometry was painted
    /// with. A theme edit changes them without touching the grid, so the
    /// generation alone would keep the old colours on screen until the next
    /// byte of output.
    pub(crate) last_colors: AtomicU64,
}

impl Default for TerminalViewState {
    fn default() -> Self {
        Self {
            cache: canvas::Cache::new(),
            last_generation: AtomicU64::new(0),
            last_colors: AtomicU64::new(0),
        }
    }
}

/// The terminal's theme colours as one comparable word.
pub(crate) fn theme_colors_key(bg: Color, fg: Color) -> u64 {
    let [r0, g0, b0, a0] = bg.into_rgba8();
    let [r1, g1, b1, a1] = fg.into_rgba8();
    u64::from_be_bytes([r0, g0, b0, a0, r1, g1, b1, a1])
}

/// A blank cell (space or NUL) on the default background, not inverted. It
/// paints nothing the canvas's terminal_bg fill has not already painted.
#[inline]
pub(crate) fn is_blank_cell(cell: &crate::terminal::Cell) -> bool {
    (cell.c == ' ' || cell.c == '\0')
        && crate::terminal::is_default_bg(cell.style.bg)
        && !cell.style.inverse
}

/// Check whether a row consists entirely of blank cells. Such rows need no
/// rendering at all.
#[inline]
pub(crate) fn is_row_empty(row: &[crate::terminal::Cell]) -> bool {
    row.iter().all(is_blank_cell)
}

/// What one cell paints: a background fill (`None` leaves the canvas's
/// terminal_bg showing) and the glyph colour.
///
/// The grid's `DEFAULT_FG` / `DEFAULT_BG` are sentinels meaning "the theme's
/// colour", never colours to paint as they are. Testing the background
/// against a chrome token (`theme::BG_PRIMARY`) instead put a #1A1B2E block
/// under every default-background glyph as soon as the chrome moved off that
/// value, whatever the terminal background was, and default text ignored the
/// theme's foreground altogether.
pub(crate) fn cell_paint(
    style: &crate::terminal::CellStyle,
    terminal_fg: Color,
    terminal_bg: Color,
) -> (Option<Color>, Color) {
    let fg = if crate::terminal::is_default_fg(style.fg) {
        terminal_fg
    } else {
        cell_color_to_iced(style.fg)
    };
    let bg = (!crate::terminal::is_default_bg(style.bg)).then(|| cell_color_to_iced(style.bg));
    if style.inverse {
        // Reverse video swaps the resolved colours: the cell is filled with
        // the foreground, and the glyph takes the background.
        (Some(fg), bg.unwrap_or(terminal_bg))
    } else {
        (bg, fg)
    }
}

impl<Message> canvas::Program<Message> for TerminalView {
    type State = TerminalViewState;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        // Absolute layout bounds (iced's canvas passes `layout.bounds()`):
        // the pointer hit-test measures from here.
        self.bounds.record(bounds);
        let grid = self.grid.lock();
        let current_gen = grid.generation;

        // Invalidate the geometry cache when the terminal content changes.
        let last_gen = state.last_generation.load(Ordering::Relaxed);
        if current_gen != last_gen {
            state.cache.clear();
            state.last_generation.store(current_gen, Ordering::Relaxed);
        }
        // ...or when the theme's terminal colours do.
        let colors = theme_colors_key(self.terminal_bg, self.terminal_fg);
        if state.last_colors.swap(colors, Ordering::Relaxed) != colors {
            state.cache.clear();
        }

        // Resize terminal grid to fit canvas bounds.
        // cell_h was 1.5x font_size — too loose, top/htop output looked
        // double-spaced. 1.2x matches iTerm2/Windows Terminal defaults.
        // Defensive: theme.json is user-editable and ThemeConfig feeds this
        // directly. A 0.0 / NaN size makes cell_w 0.0, `bounds.width / 0.0` is
        // inf, and `as usize` saturates to usize::MAX — which resize() would
        // then try to allocate.
        let font_size: f32 = if self.font_size.is_finite() {
            self.font_size.clamp(8.0, 28.0)
        } else {
            14.0
        };
        let cell_w = font_size * 0.6;
        let cell_h = font_size * 1.2;
        let new_cols = ((bounds.width / cell_w).floor() as usize).max(2);
        let new_rows = ((bounds.height / cell_h).floor() as usize).max(2);
        let needs_resize = new_cols != grid.cols || new_rows != grid.rows;
        drop(grid); // release lock

        if needs_resize {
            self.grid.lock().resize(new_cols, new_rows);
            state.cache.clear(); // force redraw at new size
            // Propagate to the remote SSH PTY so the server wraps its output
            // to the actual visible width. Without this, `ls`, `top`, etc.
            // output gets clipped because the server still thinks we have
            // the original 120 columns.
            if !self.session_id.is_empty() {
                let _ = self.ssh_manager.resize(
                    &self.session_id,
                    new_cols as u32,
                    new_rows as u32,
                );
            }
        }

        let grid = self.grid.lock();

        let bg_color = self.terminal_bg;
        let fg_color = self.terminal_fg;
        let geometry = state.cache.draw(renderer, bounds.size(), |frame| {
            // Background fill — user-configured terminal background.
            frame.fill_rectangle(Point::ORIGIN, bounds.size(), bg_color);

            // Pre-allocated buffer for batching consecutive same-style ASCII
            // characters into single fill_text calls.
            let mut run_buf = String::with_capacity(256);
            let mut run_start_x: usize = 0;
            let mut run_fg = Color::TRANSPARENT;
            #[allow(unused_assignments)]
            let mut run_y: usize = 0;

            // Flush the current ASCII text run as a single fill_text call.
            let flush_run = |frame: &mut canvas::Frame,
                             buf: &mut String,
                             start_x: usize,
                             y: usize,
                             fg: Color,
                             cell_w: f32,
                             cell_h: f32,
                             font_size: f32| {
                if !buf.is_empty() {
                    frame.fill_text(canvas::Text {
                        content: buf.clone(),
                        position: Point::new(start_x as f32 * cell_w, y as f32 * cell_h),
                        color: fg,
                        size: Pixels(font_size),
                        font: Font::MONOSPACE,
                        ..canvas::Text::default()
                    });
                    buf.clear();
                }
            };

            for y in 0..grid.rows {
                let line = if grid.scroll_offset > 0 {
                    grid.get_visible_line(y)
                } else {
                    &grid.cells[y]
                };

                // Skip entirely empty rows — no iteration needed.
                if is_row_empty(line) {
                    continue;
                }

                run_buf.clear();
                run_y = y;

                let mut x = 0;
                while x < grid.cols {
                    let cell = if x < line.len() { &line[x] } else { break };

                    // Skip continuation cells (right half of wide chars)
                    if cell.wide_cont {
                        x += 1;
                        continue;
                    }

                    let char_cols: usize = if cell.wide { 2 } else { 1 };

                    // Skip empty cells with default background
                    if is_blank_cell(cell) {
                        // Flush any pending ASCII run before the gap
                        flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
                        x += char_cols;
                        continue;
                    }

                    let (bg, fg) = cell_paint(&cell.style, fg_color, bg_color);

                    // Draw background if non-default (cheap GPU op, always per-cell)
                    if let Some(bg) = bg {
                        frame.fill_rectangle(
                            Point::new(x as f32 * cell_w, y as f32 * cell_h),
                            Size::new(char_cols as f32 * cell_w, cell_h),
                            bg,
                        );
                    }

                    // Draw character
                    if cell.c != ' ' && cell.c != '\0' {
                        if cell.wide {
                            // Wide (CJK) characters: flush any ASCII run, then
                            // draw individually with the CJK font.
                            flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);

                            // Render at 1.1x monospace size — keeps CJK legible
                            // without overflowing the 2-cell slot. (Previously
                            // 1.3x caused rows with wide chars to drift visually,
                            // especially in TUI programs like top/htop/nmon.)
                            frame.fill_text(canvas::Text {
                                content: cell.c.to_string(),
                                position: Point::new(
                                    x as f32 * cell_w,
                                    y as f32 * cell_h,
                                ),
                                color: fg,
                                size: Pixels(font_size * 1.1),
                                font: CJK_FONT,
                                ..canvas::Text::default()
                            });
                        } else {
                            // Narrow ASCII: try to batch into a text run.
                            if run_buf.is_empty() {
                                // Start a new run
                                run_start_x = x;
                                run_fg = fg;
                                run_buf.push(cell.c);
                            } else if fg == run_fg {
                                // Continue the run — same foreground color
                                run_buf.push(cell.c);
                            } else {
                                // Foreground changed — flush old run, start new
                                flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
                                run_start_x = x;
                                run_fg = fg;
                                run_buf.push(cell.c);
                            }
                        }
                    } else {
                        // Space/NUL with non-default bg: flush run (bg was drawn above)
                        flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
                    }

                    x += char_cols;
                }

                // Flush any remaining run at end of row
                flush_run(frame, &mut run_buf, run_start_x, run_y, run_fg, cell_w, cell_h, font_size);
            }

            // Draw selection highlight
            if let (Some(sel_start), Some(sel_end)) = (self.selection_start, self.selection_end) {
                let (mut sc, mut sr) = sel_start;
                let (mut ec, mut er) = sel_end;
                if sr > er || (sr == er && sc > ec) {
                    std::mem::swap(&mut sr, &mut er);
                    std::mem::swap(&mut sc, &mut ec);
                }

                let highlight_color = Color::from_rgba(0.39, 0.40, 0.95, 0.3);

                for row in sr..=er.min(grid.rows.saturating_sub(1)) {
                    let start_col = if row == sr { sc } else { 0 };
                    let end_col = if row == er { ec } else { grid.cols.saturating_sub(1) };

                    if end_col >= start_col {
                        frame.fill_rectangle(
                            Point::new(start_col as f32 * cell_w, row as f32 * cell_h),
                            Size::new((end_col - start_col + 1) as f32 * cell_w, cell_h),
                            highlight_color,
                        );
                    }
                }
            }

            // Cmd+F search highlights — draw after content so hits are clearly
            // visible even over colored backgrounds. Current match uses a
            // brighter fill than the rest.
            if !self.search_matches.is_empty() {
                let sb_len = grid.scrollback.len();
                let top_abs = sb_len.saturating_sub(grid.scroll_offset);
                let yellow = Color::from_rgba(0.95, 0.85, 0.20, 0.35);
                let orange = Color::from_rgba(0.95, 0.50, 0.10, 0.70);
                for (i, m) in self.search_matches.iter().enumerate() {
                    if m.abs_line < top_abs { continue; }
                    let vy = m.abs_line - top_abs;
                    if vy >= grid.rows { continue; }
                    let span = m.col_end.saturating_sub(m.col_start);
                    if span == 0 { continue; }
                    let color = if self.search_current == Some(i) { orange } else { yellow };
                    frame.fill_rectangle(
                        Point::new(m.col_start as f32 * cell_w, vy as f32 * cell_h),
                        Size::new(span as f32 * cell_w, cell_h),
                        color,
                    );
                }
            }

            // Cursor (only when not scrolled into history)
            if grid.scroll_offset == 0 && grid.cursor_visible && grid.cursor_y < grid.rows && grid.cursor_x < grid.cols {
                frame.fill_rectangle(
                    Point::new(
                        grid.cursor_x as f32 * cell_w,
                        grid.cursor_y as f32 * cell_h,
                    ),
                    Size::new(2.0, cell_h),
                    theme::ACCENT,
                );
            }

            // Scroll indicator when viewing history
            if grid.scroll_offset > 0 {
                let indicator = format!("\u{2191} {} lines", grid.scroll_offset);
                let text_width = indicator.len() as f32 * cell_w;
                let indicator_x = bounds.size().width - text_width - 8.0;

                // Background for readability
                frame.fill_rectangle(
                    Point::new(indicator_x - 4.0, 2.0),
                    Size::new(text_width + 8.0, cell_h + 2.0),
                    Color::from_rgba(0.1, 0.1, 0.2, 0.85),
                );
                frame.fill_text(canvas::Text {
                    content: indicator,
                    position: Point::new(indicator_x, 2.0),
                    color: Color::from_rgb(0.6, 0.65, 0.95),
                    size: Pixels(font_size),
                    font: Font::MONOSPACE,
                    ..canvas::Text::default()
                });
            }
        });

        vec![geometry]
    }
}

/// Convert our terminal color (r, g, b fields) to an iced Color.
pub(crate) fn cell_color_to_iced(c: crate::terminal::Color) -> Color {
    Color::from_rgb(c.r as f32 / 255.0, c.g as f32 / 255.0, c.b as f32 / 255.0)
}

/// Convert pixel position to terminal grid coordinates (col, row).
/// The terminal canvas starts after the sidebar (280px) and tab bar (34px).
pub(crate) fn pixel_to_grid_with(x: f32, y: f32, sidebar_w: f32, top_offset: f32, font_size: f32) -> Option<(usize, usize)> {
    let term_x = x - sidebar_w;
    let term_y = y - top_offset;
    if term_x < 0.0 || term_y < 0.0 {
        return None;
    }

    // Must match the renderer's cell metrics (TerminalView::draw) exactly, or a
    // click resolves to the wrong row — the drift grows towards the bottom of
    // the screen. Same defensive clamp as the renderer.
    let font_size = if font_size.is_finite() {
        font_size.clamp(8.0, 28.0)
    } else {
        14.0
    };
    let cell_w = font_size * 0.6;
    let cell_h = font_size * 1.2;

    let col = (term_x / cell_w) as usize;
    let row = (term_y / cell_h) as usize;
    Some((col, row))
}

/// Extract selected text from the terminal grid given start and end positions
/// in (col, row) format.
pub(crate) fn extract_selection(grid: &TerminalGrid, start: (usize, usize), end: (usize, usize)) -> String {
    let (mut sc, mut sr) = start;
    let (mut ec, mut er) = end;

    // Normalize: start should be before end
    if sr > er || (sr == er && sc > ec) {
        std::mem::swap(&mut sc, &mut ec);
        std::mem::swap(&mut sr, &mut er);
    }

    let mut result = String::new();
    for row in sr..=er.min(grid.rows.saturating_sub(1)) {
        let start_col = if row == sr { sc.min(grid.cols.saturating_sub(1)) } else { 0 };
        let end_col = if row == er { ec.min(grid.cols.saturating_sub(1)) } else { grid.cols.saturating_sub(1) };

        let line = if grid.scroll_offset > 0 {
            grid.get_visible_line(row)
        } else {
            &grid.cells[row]
        };

        for col in start_col..=end_col {
            if col < line.len() && !line[col].wide_cont {
                result.push(line[col].c);
            }
        }
        // Trim trailing spaces per line
        if row < er {
            let trimmed = result.trim_end_matches(' ');
            result = trimmed.to_string();
            result.push('\n');
        }
    }
    result.trim_end().to_string()
}

// ---------------------------------------------------------------------------
// Keyboard -> terminal byte conversion
// ---------------------------------------------------------------------------

pub(crate) fn key_to_terminal_bytes(
    key: &keyboard::Key,
    modifiers: &keyboard::Modifiers,
    text: Option<&str>,
) -> Option<String> {
    use keyboard::key::Named;
    use keyboard::Key;

    // Ctrl+key → control characters
    if modifiers.control() {
        // Extract the base letter from various sources
        let base_char = match key {
            Key::Character(c) => c.as_str().chars().next(),
            Key::Named(Named::Space) => return Some("\x00".to_string()),
            _ => None,
        };

        if let Some(ch) = base_char {
            if ch.is_ascii_alphabetic() {
                let ctrl_byte = (ch.to_ascii_uppercase() as u8) - b'A' + 1;
                return Some(String::from(ctrl_byte as char));
            }
            // Special ctrl combos
            match ch {
                '[' | '3' => return Some("\x1b".to_string()), // ESC
                '\\' | '4' => return Some("\x1c".to_string()),
                ']' | '5' => return Some("\x1d".to_string()),
                '2' | '@' | '`' => return Some("\x00".to_string()),
                '6' | '^' | '~' => return Some("\x1e".to_string()),
                '7' | '?' => return Some("\x1f".to_string()),
                '8' => return Some("\x7f".to_string()), // DEL
                _ => {}
            }
        }

        // If text field has a control character, send it directly
        if let Some(t) = text {
            if t.len() == 1 {
                let ch = t.chars().next().unwrap();
                if (ch as u32) < 32 {
                    return Some(t.to_string());
                }
            }
        }
    }

    // Alt/Option+key → ESC prefix
    if modifiers.alt() {
        if let Some(t) = text {
            if !t.is_empty() {
                return Some(format!("\x1b{}", t));
            }
        }
        if let Key::Character(c) = key {
            return Some(format!("\x1b{}", c.as_str()));
        }
    }

    // Named/special keys
    if let Key::Named(named) = key {
        // Modified arrow keys (Shift/Ctrl/Alt + arrow)
        if modifiers.shift() || modifiers.control() || modifiers.alt() {
            let base = match named {
                Named::ArrowUp => "A", Named::ArrowDown => "B",
                Named::ArrowRight => "C", Named::ArrowLeft => "D",
                Named::Home => "H", Named::End => "F",
                _ => "",
            };
            if !base.is_empty() {
                let m = match (modifiers.shift(), modifiers.alt(), modifiers.control()) {
                    (true, false, false) => 2, (false, true, false) => 3,
                    (true, true, false) => 4, (false, false, true) => 5,
                    (true, false, true) => 6, (false, true, true) => 7,
                    (true, true, true) => 8, _ => 1,
                };
                if m > 1 { return Some(format!("\x1b[1;{}{}", m, base)); }
            }
        }

        let seq = match named {
            Named::Enter => "\r",
            Named::Backspace => "\x7f",
            Named::Tab if modifiers.shift() => return Some("\x1b[Z".to_string()),
            Named::Tab => "\t",
            Named::Escape => "\x1b",
            Named::ArrowUp => "\x1b[A",
            Named::ArrowDown => "\x1b[B",
            Named::ArrowRight => "\x1b[C",
            Named::ArrowLeft => "\x1b[D",
            Named::Home => "\x1b[H",
            Named::End => "\x1b[F",
            Named::PageUp => "\x1b[5~",
            Named::PageDown => "\x1b[6~",
            Named::Insert => "\x1b[2~",
            Named::Delete => "\x1b[3~",
            Named::F1 => "\x1bOP", Named::F2 => "\x1bOQ",
            Named::F3 => "\x1bOR", Named::F4 => "\x1bOS",
            Named::F5 => "\x1b[15~", Named::F6 => "\x1b[17~",
            Named::F7 => "\x1b[18~", Named::F8 => "\x1b[19~",
            Named::F9 => "\x1b[20~", Named::F10 => "\x1b[21~",
            Named::F11 => "\x1b[23~", Named::F12 => "\x1b[24~",
            Named::Space if modifiers.control() => return Some("\x00".to_string()),
            Named::Space => " ",
            _ => return None,
        };
        return Some(seq.to_string());
    }

    // Character input: use `text` field (contains actual typed character
    // including Shift transformations like ; → :, 9 → (, etc.)
    if let Some(t) = text {
        if !t.is_empty() && !modifiers.control() {
            return Some(t.to_string());
        }
    }

    // Fallback to Key::Character (unmodified)
    if let Key::Character(c) = key {
        Some(c.as_str().to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// 1-based `(col, row)` of the cell under window point `(x, y)` in a grid of
/// `size` = (cols, rows) whose canvas starts at `origin`, with the renderer's
/// cell metrics. Outside the grid it is `None` — unless `clamp`, which pins
/// the point to the nearest edge cell, as xterm does for a drag or release
/// that wandered off the pane.
pub(crate) fn grid_cell_at(
    x: f32,
    y: f32,
    origin: (f32, f32),
    font_size: f32,
    size: (usize, usize),
    clamp: bool,
) -> Option<(usize, usize)> {
    let (cols, rows) = size;
    if cols == 0 || rows == 0 {
        return None;
    }
    let (x, y) = if clamp { (x.max(origin.0), y.max(origin.1)) } else { (x, y) };
    let (col, row) = pixel_to_grid_with(x, y, origin.0, origin.1, font_size)?;
    if clamp {
        Some((col.min(cols - 1) + 1, row.min(rows - 1) + 1))
    } else if col < cols && row < rows {
        Some((col + 1, row + 1))
    } else {
        None
    }
}

/// Whether window point `pos` lies in the second pane of a split whose area
/// starts at `origin` and whose first pane is `main_len` long along the
/// split axis. The divider counts half to each side.
pub(crate) fn in_second_pane(pos: (f32, f32), origin: (f32, f32), main_len: f32, vertical: bool) -> bool {
    let boundary = main_len + SPLIT_DIVIDER / 2.0;
    if vertical {
        pos.0 - origin.0 >= boundary
    } else {
        pos.1 - origin.1 >= boundary
    }
}

/// The terminal's name for a mouse button; `None` for the ones a terminal
/// never reports (back / forward / other).
pub(crate) fn terminal_button(button: mouse::Button) -> Option<MouseButton> {
    match button {
        mouse::Button::Left => Some(MouseButton::Left),
        mouse::Button::Middle => Some(MouseButton::Middle),
        mouse::Button::Right => Some(MouseButton::Right),
        _ => None,
    }
}

/// What a right or middle press on the terminal does.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SecondaryClick {
    /// Report it to the application that asked for the mouse.
    Report,
    /// Paste the clipboard, as a right-click always has.
    Paste,
    Ignore,
}

/// An application that switched mouse reporting on (vim `mouse=a`, htop,
/// tmux, mc) gets the right and middle buttons as it gets the left one and
/// the wheel — a right-click that pasted into it instead was never what it
/// asked for. With reporting off, or Shift held (see `mouse_report_target`),
/// a right-click pastes as before and a middle click does nothing.
pub(crate) fn secondary_click(button: MouseButton, reporting: bool) -> SecondaryClick {
    if reporting {
        SecondaryClick::Report
    } else if button == MouseButton::Right {
        SecondaryClick::Paste
    } else {
        SecondaryClick::Ignore
    }
}

/// Queue a mouse report on the session. Synchronous on purpose: `send_data`
/// only enqueues and never blocks, and sending from here keeps a press, its
/// drag and its release in order — separate tasks may run in any order.
pub(crate) fn send_mouse_report(ssh: &SshManager, session_id: &str, bytes: &[u8]) {
    if let Err(e) = ssh.send_data(session_id, bytes) {
        log::debug!("mouse report to {} dropped: {}", session_id, e);
    }
}

/// Hand a wheel notch to an application that asked for the mouse. `false`
/// when nothing was reported and the caller should scroll the scrollback as
/// before — including while the user is scrolled back into history.
pub(crate) fn report_wheel(state: &NeoShell, button: MouseButton) -> bool {
    let Some((session_id, term)) = state.mouse_report_target() else {
        return false;
    };
    let Some((col, row)) = state.focused_pane_cell(state.cursor_x, state.cursor_y, false) else {
        return false;
    };
    let bytes = {
        let grid = term.lock();
        if grid.scroll_offset > 0 {
            return false;
        }
        grid.encode_mouse(button, col, row, true)
    };
    match bytes {
        Some(bytes) => {
            send_mouse_report(&state.ssh_manager, &session_id, &bytes);
            true
        }
        None => false,
    }
}
