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

// ---- Message handlers moved out of handle_message ----

/// `Message::TerminalInput`, moved out of `handle_message`.
pub(crate) fn on_terminal_input(state: &mut NeoShell, session_id: String, data: String) -> Task<Message> {
    // Track typed commands to capture "sz filename". Scoped so the
    // cmd_buffer borrow ends before command_was_echoed reads the grid.
    let submitted: Option<String> = {
        let buf = state.cmd_buffer.entry(session_id.clone()).or_default();
        if data == "\r" || data == "\n" {
            let cmd = buf.trim().to_string();
            buf.clear();
            Some(cmd)
        } else if data == "\x7f" || data == "\x08" {
            buf.pop(); // Backspace
            None
        } else if data.chars().all(|c| !c.is_control()) {
            buf.push_str(&data);
            None
        } else {
            None
        }
    };
    if let Some(cmd) = submitted {
        // Enter pressed — record to history, but ONLY when the remote
        // echoed the line. These characters came from the keyboard, so
        // at a no-echo prompt they are a password, not a command. And
        // never while locked: the lock wiped the history, and it only
        // comes back with the key.
        if !cmd.is_empty()
            && state.screen == Screen::Main
            && command_was_echoed(state, &session_id, &cmd)
        {
            // Find session title
            let title = state.tabs.iter()
                .find(|t| t.session_id == session_id)
                .map(|t| t.title.clone())
                .unwrap_or_default();
            let host = state.session_host(&session_id);
            // The only producer of history records — and so of
            // history.enc, which is written from `cmd_history` alone.
            // Keep it inside this gate.
            state.cmd_history.push(CmdRecord {
                cmd: cmd.clone(),
                session_title: title,
                host,
                timestamp: unix_now(),
            });
            if state.cmd_history.len() > HISTORY_MAX {
                state.cmd_history.drain(..state.cmd_history.len() - HISTORY_MAX);
            }
            // Written by a paced FlushHistory, not per Enter:
            // write_private fsyncs.
            state.history_sync.dirty = true;
        }
        if cmd.starts_with("sz ") {
            let filename = cmd[3..].trim().to_string();
            if !filename.is_empty() {
                state.sz_filename.insert(session_id.clone(), filename);
            }
        }
    }

    let ssh = state.ssh_manager.clone();
    Task::perform(
        async move {
            ssh.send_data(&session_id, data.as_bytes())?;
            Ok(())
        },
        |result: Result<(), String>| match result {
            Ok(()) => Message::None,
            Err(e) => Message::Error(e),
        },
    )
}

/// `Message::KeyboardEvent`, moved out of `handle_message`.
pub(crate) fn on_keyboard_event(state: &mut NeoShell, key: keyboard::Key, modifiers: keyboard::Modifiers, text: Option<String>, captured: bool) -> Task<Message> {
    if state.screen != Screen::Main { return Task::none(); }

    // ESC dismisses what is on top: the overlay view_main is drawing
    // (one z-order, see `Overlay`), then the terminal search bar.
    // With nothing to dismiss it falls through and reaches the shell
    // as a plain ESC byte, which vim and friends depend on.
    if let keyboard::Key::Named(keyboard::key::Named::Escape) = &key {
        // A text input drops its focus on Esc.
        state.quick_cmd_focused = false;
        if state.close_topmost_overlay() {
            return Task::none();
        }
        if state.term_search_active {
            return Task::done(Message::TerminalSearchClose);
        }
    }

    // Palette gets first dibs on navigation keys; typed characters
    // reach the focused text_input through the widget tree, so we
    // swallow everything else here.
    if state.show_palette {
        match &key {
            keyboard::Key::Named(keyboard::key::Named::ArrowUp) => {
                return Task::done(Message::PaletteNavUp);
            }
            keyboard::Key::Named(keyboard::key::Named::ArrowDown) => {
                return Task::done(Message::PaletteNavDown);
            }
            keyboard::Key::Named(keyboard::key::Named::Enter) => {
                return Task::done(Message::PaletteExecute);
            }
            keyboard::Key::Character(c)
                if modifiers.command() && matches!(c.as_str(), "k" | "K") =>
            {
                state.show_palette = false;
                return Task::none();
            }
            _ => return Task::none(),
        }
    }

    // Tab-rename modal: Enter commits (Esc is handled above).
    if state.tab_rename.is_some() {
        match &key {
            keyboard::Key::Named(keyboard::key::Named::Enter) => {
                return Task::done(Message::TabRenameCommit);
            }
            _ => return Task::none(),
        }
    }

    if state.editor_file_path.is_some() {
        // Allow Cmd+S to save the open editor
        if modifiers.command() {
            if let keyboard::Key::Character(c) = &key {
                if c.as_str() == "s" {
                    return Task::done(Message::SaveEditor);
                }
            }
        }
        return Task::none();
    }
    if state.show_form { return Task::none(); }
    if state.selected_interface.is_some() { return Task::none(); }

    // Cmd/Ctrl+key shortcuts. Note the C/V special case below:
    //   macOS:        ⌘+C / ⌘+V copy & paste (no shift).
    //   Win / Linux:  Ctrl+Shift+C / Ctrl+Shift+V copy & paste,
    //                 so plain Ctrl+C still reaches the terminal as
    //                 the SIGINT byte 0x03 and Ctrl+V as a literal
    //                 0x16 (quoted-insert). This matches Windows
    //                 Terminal / Tabby / Xshell / mintty.
    if modifiers.command() {
        let clipboard_mod = if cfg!(target_os = "macos") {
            !modifiers.shift()
        } else {
            modifiers.shift()
        };
        if let keyboard::Key::Character(c) = &key {
            match c.as_str() {
                // A focused text input pastes on its own; the terminal
                // must not receive the clipboard as well.
                "v" | "V" if clipboard_mod => {
                    if captured {
                        return Task::none();
                    }
                    return Task::done(Message::PasteClipboard);
                }
                "c" | "C" if clipboard_mod => {
                    if state.selection_start.is_some() && state.selection_end.is_some() {
                        return Task::done(Message::CopySelection);
                    }
                    return Task::none();
                }
                // Plain Ctrl+C / Ctrl+V on non-macOS: fall through
                // to the terminal byte handler (SIGINT / literal).
                "c" | "C" | "v" | "V" if !cfg!(target_os = "macos") => {}
                "f" | "F" => return Task::done(Message::ToggleTerminalSearch),
                "j" | "J" => return Task::done(Message::ToggleBottomPanel),
                "k" | "K" => return Task::done(Message::TogglePalette),
                // Cmd+D / Cmd+Shift+D — split the active tab
                // (vertical divider / horizontal divider).
                "d" | "D" => return Task::done(Message::SplitTab(!modifiers.shift())),
                // Cmd+] — toggle pane focus inside a split tab.
                "]" => return Task::done(Message::SplitFocusToggle),
                "t" | "T" => return Task::done(Message::ShowConnectDialog),
                "w" | "W" => {
                    // Cmd+Shift+W = close focused pane (split-aware);
                    // Cmd+W = close current tab.
                    if modifiers.shift() {
                        return Task::done(Message::CloseFocusedPane);
                    }
                    if let Some(idx) = state.active_tab {
                        return Task::done(Message::TabClosed(idx));
                    }
                }
                "1" => return Task::done(Message::SwitchToTab(0)),
                "2" => return Task::done(Message::SwitchToTab(1)),
                "3" => return Task::done(Message::SwitchToTab(2)),
                "4" => return Task::done(Message::SwitchToTab(3)),
                "5" => return Task::done(Message::SwitchToTab(4)),
                "6" => return Task::done(Message::SwitchToTab(5)),
                "7" => return Task::done(Message::SwitchToTab(6)),
                "8" => return Task::done(Message::SwitchToTab(7)),
                "9" => {
                    // Cmd+9 = last tab
                    if !state.tabs.is_empty() {
                        return Task::done(Message::SwitchToTab(state.tabs.len() - 1));
                    }
                }
                "h" | "H" => {
                    state.show_history = !state.show_history;
                    state.history_filter.clear();
                    return Task::none();
                }
                "/" | "?" => {
                    state.show_shortcuts_help = !state.show_shortcuts_help;
                    return Task::none();
                }
                // Cmd/Ctrl + Shift + L → re-lock the vault now.
                // Shift-qualified so it cannot be hit by accident and
                // so plain Ctrl+L still clears the remote screen.
                "l" | "L" if modifiers.shift() => {
                    return Task::done(Message::LockNow);
                }
                // Cmd/Ctrl + Shift + Q → true quit (bypasses close-to-taskbar)
                "q" | "Q" if modifiers.shift() => {
                    return Task::done(Message::QuitApp);
                }
                "+" | "=" | "-" | "0" => return Task::none(), // Block zoom
                _ => {}
            }
        }
        // macOS: any unmatched ⌘+key is swallowed (GUI convention).
        // Win/Linux: let unmatched Ctrl+key fall through to the
        // terminal byte handler so Ctrl+C/V (and Ctrl+A, Ctrl+R,
        // Ctrl+L, etc.) reach the remote shell.
        if cfg!(target_os = "macos") {
            return Task::none();
        }
    }

    // F1 toggles shortcut help (no modifier required)
    if let keyboard::Key::Named(keyboard::key::Named::F1) = &key {
        state.show_shortcuts_help = !state.show_shortcuts_help;
        return Task::none();
    }

    // Ctrl+Tab / Ctrl+Shift+Tab = switch tabs
    if modifiers.control() {
        if let keyboard::Key::Named(keyboard::key::Named::Tab) = &key {
            return if modifiers.shift() {
                Task::done(Message::SwitchToPrevTab)
            } else {
                Task::done(Message::SwitchToNextTab)
            };
        }
    }

    // Overlay guard: when any modal / panel is open, keystrokes are
    // meant for its inputs — never forward them to the terminal.
    // (Fixes hex typed in Settings → Appearance echoing in the shell.)
    if state.any_overlay_open() {
        return Task::none();
    }

    // Quick-command autocomplete: Tab / Down take the top suggestion.
    // A text input lets exactly these keys through uncaptured even
    // while it has focus, so the focus guess is confirmed against the
    // widget tree first. If the input turns out not to be focused,
    // the key still goes to the terminal.
    if !captured && state.quick_cmd_focused && is_autocomplete_key(&key, &modifiers) {
        let accept = state.quick_cmd_suggestions().into_iter().next();
        let fallback: Vec<Message> = state
            .focused_session_id()
            .zip(key_to_terminal_bytes(&key, &modifiers, text.as_deref()))
            .map(|(sid, data)| {
                state
                    .keystroke_targets(sid)
                    .into_iter()
                    .map(|target| Message::TerminalInput(target, data.clone()))
                    .collect()
            })
            .unwrap_or_default();
        return quick_cmd_input_focused().then(move |focused| {
            if focused {
                accept
                    .clone()
                    .map_or_else(Task::none, |s| Task::done(Message::QuickCmdAccept(s)))
            } else {
                Task::batch(fallback.clone().into_iter().map(Task::done))
            }
        });
    }

    // A key a focused text input consumed was typed into that input
    // (quick command box, path fields, search bar). It used to reach
    // the shell too — every quick command ran twice.
    if captured {
        return Task::none();
    }
    // A printable key arriving uncaptured proves no text input has focus.
    if text.as_deref().is_some_and(|t| t.chars().any(|c| !c.is_control())) {
        state.quick_cmd_focused = false;
    }

    if let Some(session_id) = state.focused_session_id() {
        if let Some(data) = key_to_terminal_bytes(&key, &modifiers, text.as_deref()) {
            // Live sync mode fans the keystroke out to every ticked
            // session (the focused one included, deduped).
            let tasks: Vec<Task<Message>> = state
                .keystroke_targets(session_id)
                .into_iter()
                .map(|sid| Task::done(Message::TerminalInput(sid, data.clone())))
                .collect();
            return Task::batch(tasks);
        }
    }
    Task::none()
}

/// `Message::PasteClipboard`, moved out of `handle_message`.
pub(crate) fn on_paste_clipboard(state: &mut NeoShell) -> Task<Message> {
    // A right-click away from the open file menu just closes it.
    if state.remote_menu.take().is_some() { return Task::none(); }
    // Right-click paste is terminal-only. If an overlay is open, a
    // right-click on the overlay backdrop shouldn't send paste chars
    // into the hidden terminal.
    if state.any_overlay_open() { return Task::none(); }
    if let Some(session_id) = state.focused_session_id() {
        let ssh = state.ssh_manager.clone();
        // Sync mode mirrors the paste to every ticked session too.
        let mut targets: Vec<String> = if state.sync_input_on {
            state.broadcast_selected.iter().cloned().collect()
        } else {
            Vec::new()
        };
        if !targets.contains(&session_id) {
            targets.push(session_id);
        }
        // Bracketed paste (DEC 2004) is switched per terminal, so each
        // target's own flag is read here, while the grids are at hand.
        // With it on, a multi-line paste into vim or a shell arrives
        // as text instead of executing line by line.
        let targets: Vec<(String, bool)> = targets
            .into_iter()
            .map(|sid| {
                let bracketed = state
                    .find_terminal_for_session(&sid)
                    .is_some_and(|t| t.lock().bracketed_paste());
                (sid, bracketed)
            })
            .collect();
        return Task::perform(
            async move {
                let mut clipboard = arboard::Clipboard::new()
                    .map_err(|e| format!("Clipboard error: {}", e))?;
                let content = clipboard.get_text()
                    .map_err(|e| format!("Clipboard read error: {}", e))?;
                for (sid, bracketed) in &targets {
                    ssh.send_data(sid, &crate::terminal::encode_paste(&content, *bracketed))?;
                }
                Ok(())
            },
            |r: Result<(), String>| match r {
                Ok(()) => Message::None,
                Err(e) => Message::Error(e),
            },
        );
    }
    Task::none()
}

/// `Message::SplitTab`, moved out of `handle_message`.
pub(crate) fn on_split_tab(state: &mut NeoShell, vertical: bool) -> Task<Message> {
    let Some(idx) = state.active_tab else {
        return Task::none();
    };
    let Some(tab) = state.tabs.get(idx) else {
        return Task::none();
    };
    // One split per tab, none while one is still connecting; need a
    // live main session to duplicate.
    if tab.split.is_some() || tab.split_pending.is_some() || tab.session_id.is_empty() {
        return Task::none();
    }
    let tab_id = tab.id.clone();
    let conn_id = tab.connection_id.clone();
    // Known before the connect, like `ConnectTo`'s: closing the tab
    // withdraws the split's sign-in challenges too.
    let session_id = SshManager::new_session_id();
    if let Some(tab) = state.tabs.get_mut(idx) {
        tab.split_pending = Some(session_id.clone());
    }
    // Cmd+D is not typing elsewhere (see `ConnectTo`).
    state.last_keypress = None;
    let store = state.store.clone();
    let ssh = state.ssh_manager.clone();
    let failed_tab = tab_id.clone();
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                let config = store.get_connection(&conn_id)?;
                let session_id = ssh.connect_config_with_id(&session_id, &config)?;
                Ok((tab_id, vertical, session_id))
            })
            .await
            .map_err(|e| format!("Task: {}", e))?
        },
        move |result: Result<(String, bool, String), String>| match result {
            Ok((tab_id, vertical, session_id)) => {
                Message::SplitConnected(tab_id, vertical, session_id)
            }
            Err(e) => Message::SplitFailed(failed_tab.clone(), e),
        },
    )
}

/// `Message::SplitConnected`, moved out of `handle_message`.
pub(crate) fn on_split_connected(state: &mut NeoShell, tab_id: String, vertical: bool, session_id: String) -> Task<Message> {
    // As in `SshConnected`: output held for this split goes next.
    if state.ssh_held.is_some() {
        state.ssh_manager.waker().notify_one();
    }
    if let Some(tab) = state.tabs.iter_mut().find(|t| t.id == tab_id) {
        // Only the split this tab is still waiting for.
        if tab.split.is_none() && tab.split_pending.as_deref() == Some(session_id.as_str()) {
            tab.split_pending = None;
            let terminal =
                Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24)));
            tab.split = Some(SplitPane {
                session_id: session_id.clone(),
                terminal,
                vertical,
                ratio: 0.5,
                bounds: PaneBounds::default(),
            });
            tab.focus_split = true;
            // The bottom panel follows the focused pane: it shows
            // this session's files now.
            state.current_dir.insert(session_id.clone(), "~".to_string());
            return Task::done(Message::ChangeDir(session_id, "~".to_string()));
        }
    }
    // Tab vanished (or already split) while we were connecting —
    // don't leak the session.
    let ssh = state.ssh_manager.clone();
    Task::perform(
        async move {
            let _ = ssh.disconnect(&session_id);
        },
        |_| Message::None,
    )
}

/// `Message::CloseFocusedPane`, moved out of `handle_message`.
pub(crate) fn on_close_focused_pane(state: &mut NeoShell) -> Task<Message> {
    let Some(idx) = state.active_tab else {
        return Task::none();
    };
    let Some(tab) = state.tabs.get(idx) else {
        return Task::none();
    };
    if tab.split.is_none() {
        return Task::done(Message::TabClosed(idx));
    }
    let sid = tab.focused_session().to_string();
    // Taken out here and now, the survivor promoted as the Closed
    // handler would. No `SshEvent::Closed` comes for it: the
    // disconnect's stop flag ends the reader without a word, and a
    // dead pane left holding the focus turned every key into a
    // "Session not found" error. A Closed that does arrive finds
    // nothing left to do.
    if !remove_split_pane(&mut state.tabs, &sid) {
        return Task::none();
    }
    state.forget_session(&sid);
    // The selection was in the pane that is gone.
    state.selection_start = None;
    state.selection_end = None;
    state.selecting = false;
    // Its sign-in challenges go with it, as a closed tab's do.
    let (withdrawn, front) =
        take_challenges(&mut state.auth_queue, |c| c.session_id == sid);
    for challenge in withdrawn {
        challenge.cancel();
    }
    let auth = if front { state.begin_auth_prompt() } else { Task::none() };
    let ssh = state.ssh_manager.clone();
    let disconnect = Task::perform(
        async move {
            let _ = ssh.disconnect(&sid);
        },
        |_| Message::None,
    );
    Task::batch([auth, disconnect])
}

/// `Message::TerminalMouseDown`, moved out of `handle_message`.
pub(crate) fn on_terminal_mouse_down(state: &mut NeoShell) -> Task<Message> {
    // Passthrough guard: clicks inside an open overlay don't reach here
    // when they hit a widget; this guards the "click outside the modal
    // card but inside the page" case from triggering terminal actions.
    if state.any_overlay_open() { return Task::none(); }
    state.context_menu = None;
    state.remote_menu = None;
    // A click outside every widget takes focus off any text input.
    state.quick_cmd_focused = false;

    // Check if click is on the splitter zone
    // Layout from top: toolbar(30) + tabbar(34) + terminal(Fill) + splitter(4) + bottom(H) + status(24)
    // Splitter center Y ≈ window_height - bottom_panel_height - 24 - 2
    let splitter_y = state.window_height - state.bottom_panel_height - 24.0 - 2.0;
    let hit = !state.bottom_panel_collapsed
        && (state.cursor_y - splitter_y).abs() < 8.0;

    if hit && !state.dragging_splitter {
        state.dragging_splitter = true;
        state.drag_start_y = state.cursor_y;
        state.drag_start_height = state.bottom_panel_height;
        return Task::none();
    }

    // Normal terminal click — don't start selection if dragging
    if state.dragging_splitter {
        return Task::none();
    }
    // The application asked for the mouse (vim `mouse=a`, htop, tmux):
    // the press is reported to it instead of starting a selection.
    // Shift keeps it local (see `mouse_report_target`).
    if let Some((session_id, term)) = state.mouse_report_target() {
        if let Some((col, row)) =
            state.focused_pane_cell(state.cursor_x, state.cursor_y, false)
        {
            let report = term.lock().encode_mouse(MouseButton::Left, col, row, true);
            if let Some(bytes) = report {
                send_mouse_report(&state.ssh_manager, &session_id, &bytes);
                state.mouse_report = Some(MouseReport {
                    session_id,
                    button: MouseButton::Left,
                    cell: (col, row),
                });
                return Task::none();
            }
        }
    }
    state.selecting = true;
    state.selection_start = None;
    state.selection_end = None;
    // Invalidate canvas cache so old selection is cleared
    if let Some(term) = state.focused_terminal() {
        let mut grid = term.lock();
        grid.generation = grid.generation.wrapping_add(1);
    }
    Task::none()
}

/// `Message::TerminalMouseDown`, moved out of `handle_message`.
pub(crate) fn on_terminal_mouse_down_2(state: &mut NeoShell, button: MouseButton) -> Task<Message> {
    // Right or middle. A right-click away from the open file menu
    // just closes it.
    if state.remote_menu.take().is_some() {
        return Task::none();
    }
    if state.any_overlay_open() {
        return Task::none();
    }
    let target = state.mouse_report_target();
    match secondary_click(button, target.is_some()) {
        SecondaryClick::Report => {
            // Over the pane only, and one reported press at a time:
            // `mouse_report` holds the one whose release is owed.
            let cell = state.focused_pane_cell(state.cursor_x, state.cursor_y, false);
            let free = state.mouse_report.is_none();
            if let (Some((session_id, term)), Some((col, row)), true) = (target, cell, free)
            {
                if let Some(bytes) = term.lock().encode_mouse(button, col, row, true) {
                    send_mouse_report(&state.ssh_manager, &session_id, &bytes);
                    state.mouse_report = Some(MouseReport {
                        session_id,
                        button,
                        cell: (col, row),
                    });
                }
            }
            Task::none()
        }
        SecondaryClick::Paste => Task::done(Message::PasteClipboard),
        SecondaryClick::Ignore => Task::none(),
    }
}

/// `Message::TerminalMouseMove`, moved out of `handle_message`.
pub(crate) fn on_terminal_mouse_move(state: &mut NeoShell, x: f32, y: f32) -> Task<Message> {
    state.cursor_x = x;
    state.cursor_y = y;
    // Handle splitter drag
    if state.dragging_splitter {
        let delta = state.drag_start_y - y;
        state.bottom_panel_height = (state.drag_start_height + delta).clamp(80.0, 600.0);
        return Task::none();
    }
    // Split-divider drag: move the ratio by the pointer's travel
    // along the split axis, relative to where the press landed.
    if let Some((start_pos, start_ratio)) = state.split_drag {
        let vertical = state
            .active_tab
            .and_then(|i| state.tabs.get(i))
            .and_then(|t| t.split.as_ref())
            .map(|sp| sp.vertical);
        if let Some(vertical) = vertical {
            let extent = state.split_extent(vertical);
            let pos = if vertical { x } else { y };
            if let Some(sp) = state
                .active_tab
                .and_then(|i| state.tabs.get_mut(i))
                .and_then(|t| t.split.as_mut())
            {
                if extent > 0.0 {
                    sp.ratio = (start_ratio + (pos - start_pos) / extent)
                        .clamp(SPLIT_MIN, SPLIT_MAX);
                }
            }
        }
        return Task::none();
    }
    // A reported press: its drag goes to the same application (DEC
    // 1002 / 1003), pinned to the pane's edge if the pointer leaves
    // it, and only when the cell actually changes.
    if let Some(report) = state.mouse_report.clone() {
        // The cell math measures from the focused pane; if focus moved
        // mid-drag there is nothing sensible to report.
        if state.focused_session_id().as_deref() == Some(report.session_id.as_str()) {
            if let Some(cell) = state.focused_pane_cell(x, y, true) {
                if cell != report.cell {
                    if let Some(r) = state.mouse_report.as_mut() {
                        r.cell = cell;
                    }
                    let bytes = state
                        .find_terminal_for_session(&report.session_id)
                        .and_then(|t| {
                            t.lock().encode_mouse_motion(Some(report.button), cell.0, cell.1)
                        });
                    if let Some(bytes) = bytes {
                        send_mouse_report(&state.ssh_manager, &report.session_id, &bytes);
                    }
                }
            }
        }
        return Task::none();
    }
    // DEC 1003 also wants motion with no button held: over the pane
    // only, and again only when the cell changes.
    if !state.selecting && !state.any_overlay_open() {
        if let Some((session_id, term)) = state.mouse_report_target() {
            let cell = state.focused_pane_cell(x, y, false);
            if cell != state.mouse_motion_cell {
                state.mouse_motion_cell = cell;
                if let Some((col, row)) = cell {
                    let bytes = term.lock().encode_mouse_motion(None, col, row);
                    if let Some(bytes) = bytes {
                        send_mouse_report(&state.ssh_manager, &session_id, &bytes);
                    }
                }
            }
        }
    }
    if state.selecting {
        // Split-aware: measured from the focused pane (8b17f55).
        let (x_off, y_off) = state.focused_pane_origin();
        // Same font source as the canvas (see TerminalView construction),
        // otherwise the hit-test and the renderer disagree.
        if let Some(pos) =
            pixel_to_grid_with(x, y, x_off, y_off, state.theme_cfg.terminal_font_size)
        {
            if state.selection_start.is_none() {
                state.selection_start = Some(pos);
            }
            state.selection_end = Some(pos);
            // Invalidate canvas cache to update selection highlight
            if let Some(term) = state.focused_terminal() {
                let mut grid = term.lock();
                grid.generation = grid.generation.wrapping_add(1);
            }
        }
    }
    Task::none()
}

/// `Message::TerminalMouseUp`, moved out of `handle_message`.
pub(crate) fn on_terminal_mouse_up(state: &mut NeoShell, button: MouseButton) -> Task<Message> {
    let left = button == MouseButton::Left;
    if left {
        // Always reset splitter drag
        state.dragging_splitter = false;
        state.split_drag = None;
        state.selecting = false;
    }
    // The release of a reported press goes to the application that
    // saw the press, wherever the pointer is now.
    if let Some(report) = state.mouse_report.take_if(|r| r.button == button) {
        let cell = if state.focused_session_id().as_deref() == Some(report.session_id.as_str()) {
            state
                .focused_pane_cell(state.cursor_x, state.cursor_y, true)
                .unwrap_or(report.cell)
        } else {
            report.cell
        };
        let bytes = state
            .find_terminal_for_session(&report.session_id)
            .and_then(|t| t.lock().encode_mouse(report.button, cell.0, cell.1, false));
        if let Some(bytes) = bytes {
            send_mouse_report(&state.ssh_manager, &report.session_id, &bytes);
        }
        return Task::none();
    }
    if left && state.selection_start.is_some() && state.selection_end.is_some() {
        return Task::done(Message::CopySelection);
    }
    Task::none()
}

/// `Message::CopySelection`, moved out of `handle_message`.
pub(crate) fn on_copy_selection(state: &mut NeoShell) -> Task<Message> {
    if let (Some(start), Some(end)) = (state.selection_start, state.selection_end) {
        if let Some(term) = state.focused_terminal() {
            let grid = term.lock();
            let text = extract_selection(&grid, start, end);
            if !text.is_empty() {
                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                    let _ = clipboard.set_text(&text);
                }
            }
        }
    }
    state.selection_start = None;
    state.selection_end = None;
    // Invalidate canvas cache to clear selection highlight
    if let Some(term) = state.focused_terminal() {
        let mut grid = term.lock();
        grid.generation = grid.generation.wrapping_add(1);
    }
    Task::none()
}

/// `Message::SplitFailed`, moved out of `handle_message`.
pub(crate) fn on_split_failed(state: &mut NeoShell, tab_id: String, e: String) -> Task<Message> {
    log::error!("{}", e);
    let Some(tab) = state.tabs.iter_mut().find(|t| t.id == tab_id) else {
        // Closed while the split connected: nobody is waiting.
        return Task::none();
    };
    tab.split_pending = None;
    state.error_message = e;
    state.show_error_dialog = true;
    Task::none()
}

/// `Message::SplitDividerPressed`, moved out of `handle_message`.
pub(crate) fn on_split_divider_pressed(state: &mut NeoShell) -> Task<Message> {
    let start = state
        .active_tab
        .and_then(|i| state.tabs.get(i))
        .and_then(|t| t.split.as_ref())
        .map(|sp| {
            let pos = if sp.vertical { state.cursor_x } else { state.cursor_y };
            (pos, sp.ratio)
        });
    state.split_drag = start;
    Task::none()
}

/// `Message::SplitFocusToggle`, moved out of `handle_message`.
pub(crate) fn on_split_focus_toggle(state: &mut NeoShell) -> Task<Message> {
    if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get_mut(idx) {
            if tab.split.is_some() {
                tab.focus_split = !tab.focus_split;
            }
        }
    }
    Task::none()
}

/// `Message::TerminalSearchNext`, moved out of `handle_message`.
pub(crate) fn on_terminal_search_next(state: &mut NeoShell) -> Task<Message> {
    if !state.term_search_matches.is_empty() {
        state.term_search_current =
            (state.term_search_current + 1) % state.term_search_matches.len();
        scroll_to_current_match(state);
    }
    Task::none()
}

/// `Message::TerminalSearchPrev`, moved out of `handle_message`.
pub(crate) fn on_terminal_search_prev(state: &mut NeoShell) -> Task<Message> {
    if !state.term_search_matches.is_empty() {
        let n = state.term_search_matches.len();
        state.term_search_current = (state.term_search_current + n - 1) % n;
        scroll_to_current_match(state);
    }
    Task::none()
}

/// `Message::TerminalScrollUp`, moved out of `handle_message`.
pub(crate) fn on_terminal_scroll_up(state: &mut NeoShell, lines: usize) -> Task<Message> {
    // Passthrough guard: if any overlay is open, the user is scrolling
    // inside it — don't let the event also scroll the terminal below.
    if state.any_overlay_open() { return Task::none(); }
    // An application reading the mouse (less, vim, htop) scrolls itself.
    if report_wheel(state, MouseButton::WheelUp) { return Task::none(); }
    if let Some(term) = state.focused_terminal() {
        term.lock().scroll_view_up(lines);
    }
    Task::none()
}

/// `Message::TerminalScrollDown`, moved out of `handle_message`.
pub(crate) fn on_terminal_scroll_down(state: &mut NeoShell, lines: usize) -> Task<Message> {
    if state.any_overlay_open() { return Task::none(); }
    if report_wheel(state, MouseButton::WheelDown) { return Task::none(); }
    if let Some(term) = state.focused_terminal() {
        term.lock().scroll_view_down(lines);
    }
    Task::none()
}
