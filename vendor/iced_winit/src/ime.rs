//! NeoShell patch (see ../PATCHES.md): lets the application steer the input
//! method, which iced 0.13 has no API for.
//!
//! The runtime turns the input method on for every window. The application
//! turns it off while a password field has focus, so a master password or an
//! OTP answer is never composed by, displayed in, or sent to an IME, and moves
//! the candidate window to where text is being typed (the terminal cursor).
//! Requests are recorded here and applied by the runtime right after the
//! application's `update`, on every window.
use std::sync::Mutex;

/// A pending change. `None` fields leave the current setting alone.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Request {
    /// Turn the input method on or off.
    pub(crate) allowed: Option<bool>,
    /// Candidate window anchor: logical x, y and line height.
    pub(crate) cursor_area: Option<(f32, f32, f32)>,
}

#[derive(Debug)]
struct Pending {
    request: Request,
    /// What the windows currently have, so repeated calls are not reapplied.
    /// macOS drops any in-progress composition on every `set_ime_allowed`.
    allowed: bool,
}

impl Pending {
    const fn new() -> Self {
        Self {
            request: Request {
                allowed: None,
                cursor_area: None,
            },
            allowed: true,
        }
    }

    fn set_allowed(&mut self, allowed: bool) {
        self.request.allowed = (allowed != self.allowed).then_some(allowed);
    }

    fn set_cursor_area(&mut self, area: (f32, f32, f32)) {
        self.request.cursor_area = Some(area);
    }

    fn take(&mut self) -> Request {
        let request = std::mem::take(&mut self.request);
        if let Some(allowed) = request.allowed {
            self.allowed = allowed;
        }
        request
    }
}

static PENDING: Mutex<Pending> = Mutex::new(Pending::new());

fn pending() -> std::sync::MutexGuard<'static, Pending> {
    // A poisoned lock only means a panic elsewhere; the data is two plain
    // values and stays usable.
    PENDING.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Allows or forbids the input method on every window.
///
/// Forbid it while a secure (password) field has focus; allow it everywhere
/// else. Calling it with the current value does nothing.
pub fn set_allowed(allowed: bool) {
    pending().set_allowed(allowed);
}

/// Anchors the input method's candidate window at `(x, y)` in logical
/// coordinates, the same coordinates the application lays out in, with a
/// line of `height` below it.
pub fn set_cursor_area(x: f32, y: f32, height: f32) {
    pending().set_cursor_area((x, y, height));
}

/// Whether a window opened now should start with the input method allowed.
pub(crate) fn allowed() -> bool {
    let pending = pending();
    pending.request.allowed.unwrap_or(pending.allowed)
}

/// Takes the pending request, recording it as applied.
pub(crate) fn take() -> Request {
    pending().take()
}

/// Applies `request` to `window`. `scale` converts logical to physical.
pub(crate) fn apply(
    request: &Request,
    window: &winit::window::Window,
    scale: f64,
) {
    if let Some(allowed) = request.allowed {
        window.set_ime_allowed(allowed);
    }
    if let Some((x, y, height)) = request.cursor_area {
        window.set_ime_cursor_area(
            winit::dpi::PhysicalPosition::new(
                f64::from(x) * scale,
                f64::from(y) * scale,
            ),
            winit::dpi::PhysicalSize::new(1.0, f64::from(height) * scale),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidding_is_applied_once_and_then_remembered() {
        let mut p = Pending::new();
        p.set_allowed(false);
        assert_eq!(p.take().allowed, Some(false));
        p.set_allowed(false);
        assert_eq!(p.take().allowed, None, "same value is not reapplied");
        p.set_allowed(true);
        assert_eq!(p.take().allowed, Some(true));
    }

    #[test]
    fn allowing_when_already_allowed_is_a_no_op() {
        let mut p = Pending::new();
        p.set_allowed(true);
        assert_eq!(p.take(), Request::default());
    }

    #[test]
    fn a_toggle_back_before_it_is_applied_cancels_out() {
        let mut p = Pending::new();
        p.set_allowed(false);
        p.set_allowed(true);
        assert_eq!(p.take().allowed, None);
    }

    #[test]
    fn the_last_cursor_area_wins_and_is_consumed() {
        let mut p = Pending::new();
        p.set_cursor_area((1.0, 2.0, 3.0));
        p.set_cursor_area((4.0, 5.0, 6.0));
        assert_eq!(p.take().cursor_area, Some((4.0, 5.0, 6.0)));
        assert_eq!(p.take().cursor_area, None);
    }
}
