# NeoShell patches to iced_winit 0.13.0

Upstream: crates.io `iced_winit` 0.13.0, checksum `f44cd4e1c594b6334f409282937bf972ba14d31fedf03c23aa595d982a2fda28`.

| File | Change |
|---|---|
| `src/program.rs` | enable the IME per window, deliver commits, apply app requests |
| `src/ime.rs` | new: the app-facing input method control |
| `src/lib.rs` | one line: `pub mod ime;` |
| `Cargo.toml` | three lint allows (see below) |
| `LICENSE` | added: iced's MIT text (the published crate ships none; `Cargo.toml` declares `license = "MIT"`) |

Everything else in `src/` and `README.md` is byte-identical to the published crate.

## Why

iced 0.13 never turns on winit's input method support, so no CJK input method
(Pinyin, Wubi, Japanese, Korean) could compose into any text field — Chinese
connection and group names could only be entered by pasting.

1. **Enable it.** Every window the runtime opens calls
   `set_ime_allowed(ime::allowed())`. winit leaves the IME off by default.
2. **Deliver commits.** `WindowEvent::Ime(Ime::Commit(text))` becomes keyboard
   events; upstream `conversion::window_event` drops every `Ime` event. iced 0.13's
   `text_input` inserts only `text.chars().next()` of a `KeyPressed`, so a
   committed phrase becomes **one event per character** — otherwise 服务器 would
   insert only 服. The events use `Key::Unidentified` (never matches a shortcut)
   and **empty modifiers**: a commit can land while Alt/Option is still held from
   an input-source switch, and a terminal would turn Alt+char into ESC+char.
3. **Let the app forbid it.** `ime::set_allowed(false)` while a password field
   has focus, so a master password or OTP answer is never composed by, shown in,
   or sent to an input method (some cloud IMEs upload keystrokes). Also used on
   screens that only hold password fields.
4. **Place the candidate window.** Each mouse press anchors it at the click (the
   field it focused), and `ime::set_cursor_area` lets the app move it — the
   terminal points it at the text cursor.

Requests from the app are recorded in `ime.rs` and applied to every window
right after the app's `update`. A request equal to the current state is not
reapplied, because macOS drops an in-progress composition on every
`set_ime_allowed`.

Not done: preedit (the composing text drawn inline in the field); the OS
candidate window shows it instead. Inline preedit needs iced 0.14's input
method API — upgrade iced rather than extend this patch.

Known platform limit (winit 0.30, macOS): winit forwards `insertText:` as a
commit only while marked text exists, so a full-width punctuation mark an IME
inserts *without* a composition (e.g. `（` typed directly) arrives as the key's
ASCII character instead. Fixing that means patching winit itself.

## Cargo.toml

The crate is a workspace member so `cargo test --workspace` runs its tests on
all three CI runners. Members lose the lint cap cargo gives crates.io
dependencies, and upstream 0.13.0 has 5 warnings of its own (none in the patched
code): `clippy::too_many_arguments` (2), `clippy::cloned_ref_to_slice_refs` (1)
and rustc `deprecated` (2, futures `try_next`). Exactly those three lints are
allowed. Every upstream `deny`/`forbid` lint stays in force, and the patched
code compiles under all of them.

Note: `src/program.rs` is behind the crate's `program` feature. `cargo test -p
iced_winit` alone does not enable it and so does not compile the patch;
`cargo test --workspace` does, through feature unification with `iced`.

## Removing it

Delete this directory, the `iced_winit` line under `[patch.crates-io]` in the
workspace `Cargo.toml`, and the direct `iced_winit` dependency in
`core/Cargo.toml` once iced is upgraded to a release with input method support.

## Diff against 0.13.0

```diff
--- a/src/program.rs
+++ b/src/program.rs
@@ -705,6 +705,12 @@
                     exit_on_close_request,
                 );
 
+                // NeoShell patch (see ../PATCHES.md): iced 0.13 never enables
+                // winit's IME, so CJK input methods cannot compose into any
+                // text field. Allow it on every window this runtime opens,
+                // unless the app has forbidden it (a password field has focus).
+                window.raw.set_ime_allowed(crate::ime::allowed());
+
                 let logical_size = window.state.logical_size();
 
                 let _ = user_interfaces.insert(
@@ -990,6 +996,53 @@
                                 &window_event,
                                 &mut debug,
                             );
+
+                            // NeoShell patch (see ../PATCHES.md): IME.
+                            match &window_event {
+                                winit::event::WindowEvent::Ime(
+                                    winit::event::Ime::Commit(text),
+                                ) => {
+                                    // text_input inserts only the first char
+                                    // of a KeyPressed's text, so a committed
+                                    // phrase becomes one event per char.
+                                    for c in
+                                        text.chars().filter(|c| !c.is_control())
+                                    {
+                                        let mut buf = [0u8; 4];
+                                        events.push((
+                                            id,
+                                            core::Event::Keyboard(ime_commit_key(
+                                                c.encode_utf8(&mut buf),
+                                            )),
+                                        ));
+                                    }
+                                }
+                                winit::event::WindowEvent::MouseInput {
+                                    state: winit::event::ElementState::Pressed,
+                                    ..
+                                } => {
+                                    // iced 0.13 has no way to report where the
+                                    // focused field is, so anchor the IME
+                                    // candidate window at the click that
+                                    // focused it.
+                                    if let Some(p) =
+                                        window.state.cursor().position()
+                                    {
+                                        let scale = window.state.scale_factor();
+                                        window.raw.set_ime_cursor_area(
+                                            winit::dpi::PhysicalPosition::new(
+                                                f64::from(p.x) * scale,
+                                                f64::from(p.y) * scale,
+                                            ),
+                                            winit::dpi::PhysicalSize::new(
+                                                1.0,
+                                                20.0 * scale,
+                                            ),
+                                        );
+                                    }
+                                }
+                                _ => {}
+                            }
 
                             if let Some(event) = conversion::window_event(
                                 window_event,
@@ -1085,6 +1138,11 @@
                                 &mut debug,
                                 &mut messages,
                             );
+
+                            // NeoShell patch (see ../PATCHES.md): apply the
+                            // input method changes the app asked for during
+                            // this update.
+                            let ime_request = crate::ime::take();
 
                             for (id, window) in window_manager.iter_mut() {
                                 window.state.synchronize(
@@ -1093,6 +1151,12 @@
                                     &window.raw,
                                 );
 
+                                crate::ime::apply(
+                                    &ime_request,
+                                    &window.raw,
+                                    window.state.scale_factor(),
+                                );
+
                                 window.raw.request_redraw();
                             }
 
@@ -1538,3 +1602,51 @@
         _ => false,
     }
 }
+
+/// NeoShell patch (see ../PATCHES.md): the keyboard event an IME-committed
+/// character is delivered as. `Key::Unidentified` keeps it out of every
+/// shortcut match; the character travels in `text`, which is what
+/// `text_input` inserts and what the app forwards to the terminal.
+///
+/// Modifiers are always empty. Committed text is text, not a chord: a commit
+/// can land while Alt/Option is still held from an input-source switch
+/// (Ctrl+Option+Space, Alt+Shift), and a terminal would then send it as a
+/// Meta sequence (ESC + char) instead of the character.
+fn ime_commit_key(text: &str) -> core::keyboard::Event {
+    let modifiers = core::keyboard::Modifiers::empty();
+    use core::keyboard::{self, key};
+
+    keyboard::Event::KeyPressed {
+        key: keyboard::Key::Unidentified,
+        modified_key: keyboard::Key::Unidentified,
+        physical_key: key::Physical::Unidentified(
+            key::NativeCode::Unidentified,
+        ),
+        location: keyboard::Location::Standard,
+        modifiers,
+        text: Some(core::SmolStr::new(text)),
+    }
+}
+
+#[cfg(test)]
+mod ime_tests {
+    use super::*;
+
+    #[test]
+    fn a_committed_char_travels_as_text_on_an_unidentified_key() {
+        let event = ime_commit_key("中");
+        match event {
+            core::keyboard::Event::KeyPressed {
+                key,
+                text,
+                modifiers,
+                ..
+            } => {
+                assert_eq!(key, core::keyboard::Key::Unidentified);
+                assert_eq!(text.as_deref(), Some("中"));
+                assert!(modifiers.is_empty(), "a commit is never a chord");
+            }
+            other => panic!("unexpected event: {other:?}"),
+        }
+    }
+}
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -31,6 +31,9 @@
 #[cfg(feature = "program")]
 pub mod program;
 
+// NeoShell patch (see ../PATCHES.md): input method control for the app.
+pub mod ime;
+
 #[cfg(feature = "system")]
 pub mod system;
 
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -110,10 +110,17 @@
 semicolon_if_nothing_returned = "deny"
 trivially-copy-pass-by-ref = "deny"
 type-complexity = "allow"
+# NeoShell: the three clippy warnings upstream 0.13.0 already carries. The
+# crate is a workspace member here (see PATCHES.md), so they would otherwise
+# show up in every workspace clippy run. Every deny above stays in force.
+too_many_arguments = "allow"
+cloned_ref_to_slice_refs = "allow"
 unused_async = "deny"
 useless_conversion = "deny"
 
 [lints.rust]
+# NeoShell: upstream calls the deprecated futures `try_next` twice.
+deprecated = "allow"
 missing_debug_implementations = "deny"
 missing_docs = "deny"
 unsafe_code = "deny"
```

`src/ime.rs` is new; see the file.
