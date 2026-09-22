# NeoShell patches to ssh2 0.9.5

This directory is the crates.io release of `ssh2` 0.9.5 (the `.crate` whose
sha256 is `2f84d13b3b8a0d4e91a2629911e951db1bb8671512f5c09d7d4ba34500ba68c8`,
the checksum Cargo.lock recorded before vendoring) with **one behavioural
change**. The root `Cargo.toml` points cargo at it through
`[patch.crates-io] ssh2 = { path = "vendor/ssh2" }`.

Vendored: `Cargo.toml`, `src/`, `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`.
Not vendored: `tests/` (integration tests that need a live sshd),
`Cargo.toml.orig`, upstream's CI and VCS dotfiles.

## The change: Windows `mkpath` no longer panics

Upstream builds a `PathBuf` from the raw name bytes the server sends; the
Windows version does `str::from_utf8(&v).unwrap()`. `Sftp::readdir`,
`File::readdir`, `Sftp::readlink` and `Sftp::realpath` all go through it, so a
remote name that is not valid UTF-8 (GBK names on older Chinese servers are
common) panics. NeoShell's release profile sets `panic = "abort"`, so the panic
kills the whole app. NeoShell's recursive SFTP delete and download walk the
tree with `readdir`, so one such name anywhere under the target is enough.

The patch decodes lossily instead:
`PathBuf::from(String::from_utf8_lossy(&v).into_owned())`, in a small
`mkpath_lossy` fn so it is compiled and tested on every platform.

- Valid UTF-8 names: unchanged, byte for byte.
- Invalid names: each bad byte sequence becomes U+FFFD. The entry is still
  listed, but its name no longer matches the bytes on the server, so opening,
  deleting or downloading it fails with an ordinary SFTP error, never a panic.
  Names that differ only in their invalid bytes collapse to the same lossy name.
- Unix: untouched. It keeps the raw bytes and was never affected.

## Supporting edits (no behaviour change)

- `Cargo.toml`: explicit `edition = "2015"` (the implicit default); upstream's
  `[[test]] all` target and its `tempfile` dev-dependency dropped with
  `tests/`; `[lints]` tables that allow upstream's warnings. `vendor/ssh2` is a
  workspace member so `cargo test --workspace` runs the mkpath tests on every
  CI OS. That also builds the crate's unit tests under upstream's
  `#![cfg_attr(test, deny(warnings))]` (`src/lib.rs`), so any rustc warning in
  upstream code becomes an error. If a newer stable rustc fails CI with
  `error: ...` in `vendor/ssh2/src/*` and a note pointing at `src/lib.rs`,
  add that lint name under `[lints.rust]` in `vendor/ssh2/Cargo.toml`.
- `rustfmt.toml`: `disable_all_formatting = true`, so `cargo fmt --all` never
  rewrites upstream code (0.9.5 is not rustfmt-clean under current rustfmt).
- `.gitattributes`: `* -text`. Several upstream `src/` files use CRLF; without
  it `core.autocrlf=input` rewrites them to LF on commit and `diff -r` against
  upstream shows every line as changed.

## Diff against 0.9.5

`src/sftp.rs` uses CRLF line endings upstream and here; the diff is shown with
the CRs stripped.

```diff
--- a/src/sftp.rs
+++ b/src/sftp.rs
@@ -914,8 +914,56 @@
     use std::os::unix::prelude::*;
     PathBuf::from(OsStr::from_bytes(&v))
 }
+// NeoShell patch, see ../PATCHES.md. Upstream 0.9.5 builds this path with
+// `str::from_utf8(&v).unwrap()`, so readdir, readlink or realpath on a remote
+// name that is not valid UTF-8 (GBK names on older Chinese servers are common)
+// panics. NeoShell's release profile sets `panic = "abort"`, so that panic
+// kills the whole process rather than failing one SFTP call. Lossy decoding
+// replaces each invalid byte sequence with U+FFFD: the entry is still listed,
+// but its name no longer matches the bytes on the server, so opening it fails
+// with an ordinary SFTP error, never a panic. Unix keeps the raw bytes and is
+// unchanged. Delete this patch once upstream fixes mkpath.
 #[cfg(windows)]
 fn mkpath(v: Vec<u8>) -> PathBuf {
-    use std::str;
-    PathBuf::from(str::from_utf8(&v).unwrap())
+    mkpath_lossy(v)
+}
+
+// Split out of the Windows mkpath so the conversion is compiled and tested on
+// every platform, not only on Windows.
+#[cfg(any(windows, test))]
+fn mkpath_lossy(v: Vec<u8>) -> PathBuf {
+    PathBuf::from(String::from_utf8_lossy(&v).into_owned())
+}
+
+#[cfg(test)]
+mod mkpath_tests {
+    use super::*;
+
+    #[test]
+    fn mkpath_lossy_replaces_invalid_utf8_instead_of_panicking() {
+        assert_eq!(
+            mkpath_lossy(vec![b'a', 0xff, b'b']),
+            PathBuf::from("a\u{fffd}b")
+        );
+        // "文件.txt" encoded as GBK, which is not valid UTF-8.
+        let gbk = mkpath_lossy(b"\xce\xc4\xbc\xfe.txt".to_vec());
+        let name = gbk.to_str().expect("lossy output is always valid UTF-8");
+        assert!(name.contains('\u{fffd}'), "{:?}", name);
+        assert!(name.ends_with(".txt"), "{:?}", name);
+    }
+
+    #[test]
+    fn mkpath_lossy_keeps_valid_utf8_unchanged() {
+        assert_eq!(
+            mkpath_lossy("文件.txt".as_bytes().to_vec()),
+            PathBuf::from("文件.txt")
+        );
+    }
+
+    // Runs on the Windows CI runner: the real mkpath must not panic.
+    #[cfg(windows)]
+    #[test]
+    fn windows_mkpath_does_not_panic_on_invalid_utf8() {
+        assert_eq!(mkpath(vec![b'a', 0xff, b'b']), PathBuf::from("a\u{fffd}b"));
+    }
 }
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -12,6 +12,9 @@
 [package]
 name = "ssh2"
 version = "0.9.5"
+# NeoShell: explicit, and identical to the implicit default. Silences cargo's
+# "no edition set" warning now that this crate is a workspace member.
+edition = "2015"
 authors = [
     "Alex Crichton <alex@alexcrichton.com>",
     "Wez Furlong <wez@wezfurlong.org>",
@@ -38,9 +41,8 @@
 name = "ssh2"
 path = "src/lib.rs"
 
-[[test]]
-name = "all"
-path = "tests/all/main.rs"
+# NeoShell: upstream's `[[test]] all` (tests/all/main.rs, needs a live sshd) and
+# its only dev-dependency, tempfile, are dropped because tests/ is not vendored.
 
 [dependencies.bitflags]
 version = "2"
@@ -54,9 +56,18 @@
 [dependencies.parking_lot]
 version = "0.12"
 
-[dev-dependencies.tempfile]
-version = "3"
-
 [features]
 openssl-on-win32 = ["libssh2-sys/openssl-on-win32"]
 vendored-openssl = ["libssh2-sys/vendored-openssl"]
+
+# NeoShell: as a path crate ssh2 loses the lint cap cargo gives crates.io
+# dependencies, and as a workspace member its unit tests build under lib.rs's
+# `#![cfg_attr(test, deny(warnings))]`, so any upstream warning would fail
+# `cargo test --workspace`. Allow upstream's lints here rather than edit its
+# source. If a newer rustc adds a lint that fires in this crate, CI fails the
+# same way: add that lint to [lints.rust]. See PATCHES.md.
+[lints.rust]
+mismatched_lifetime_syntaxes = "allow"
+
+[lints.clippy]
+all = "allow"
```

## Re-applying onto a newer upstream

```sh
V=0.9.6                         # the new upstream version
cd vendor/ssh2
curl -sSfL "https://static.crates.io/crates/ssh2/ssh2-$V.crate" | tar -xzf - -C /tmp
rm -rf src && cp -R /tmp/ssh2-$V/src /tmp/ssh2-$V/Cargo.toml /tmp/ssh2-$V/README.md \
  /tmp/ssh2-$V/LICENSE-MIT /tmp/ssh2-$V/LICENSE-APACHE .
perl -pi -e 's/\r\n/\n/' src/sftp.rs      # the diff above is LF
awk '/^```diff$/{f=1;next} /^```$/{f=0} f' PATCHES.md | patch -p1
perl -pi -e 's/\n/\r\n/' src/sftp.rs      # only if upstream's sftp.rs was CRLF
cd ../.. && cargo update -p ssh2 && cargo test --workspace
```

The `Cargo.toml` hunks will likely be rejected once upstream's normalized
manifest changes; redo the three edits listed above by hand.

## Verifying

```sh
diff -r ~/.cargo/registry/src/*/ssh2-0.9.5/src vendor/ssh2/src   # only the mkpath hunk
cargo test --workspace   # sftp::mkpath_tests: 2 tests, 3 on Windows
```

## Deleting the patch

Once an upstream release stops unwrapping in the Windows `mkpath`: delete
`vendor/ssh2/`, the `[patch.crates-io]` block and `"vendor/ssh2"` in
`members` from the root `Cargo.toml`, then run `cargo update -p ssh2`.
