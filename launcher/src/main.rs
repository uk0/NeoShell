#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use libloading::{Library, Symbol};
use std::path::{Path, PathBuf};

/// Base64-encoded ed25519 public key (32 raw bytes) that update libraries must
/// be signed with. Injected at build time:
///   NEOSHELL_UPDATE_PUBKEY=<base64> cargo build --release
/// See scripts/gen-update-key.sh and scripts/sign-update.sh.
const UPDATE_PUBKEY_B64: Option<&str> = option_env!("NEOSHELL_UPDATE_PUBKEY");

fn main() {
    // A backup that itself fails to load must not spin this loop forever.
    let mut rolled_back = false;

    loop {
        let lib_path = find_core_lib();

        // Apply pending update if exists
        apply_pending_update(&lib_path);

        // Load core library
        let lib = match unsafe { Library::new(&lib_path) } {
            Ok(lib) => lib,
            Err(e) => {
                log_line(&format!(
                    "Failed to load core library {:?}: {}",
                    lib_path, e
                ));
                let bak = lib_path_with_ext(&lib_path, "bak");
                if !rolled_back && bak.exists() {
                    log_line("Rolling back to the previous core library...");
                    // Move the failing library aside first, so restoring the
                    // backup cannot collide with it and so it is available for
                    // post-mortem instead of being silently overwritten.
                    let bad = lib_path_with_ext(&lib_path, "bad");
                    let _ = std::fs::remove_file(&bad);
                    let _ = move_file(&lib_path, &bad);
                    match move_file(&bak, &lib_path) {
                        Ok(()) => {
                            rolled_back = true;
                            continue;
                        }
                        Err(e) => log_line(&format!("Rollback failed: {}", e)),
                    }
                } else if rolled_back {
                    log_line("The restored backup does not load either — giving up.");
                }
                std::process::exit(1);
            }
        };

        // Call run()
        let exit_code = unsafe {
            let run: Symbol<extern "C" fn() -> i32> =
                lib.get(b"neoshell_run").expect("Missing neoshell_run symbol");
            run()
        };

        // Unload library before potential swap
        drop(lib);

        // The library loaded AND returned normally, so the backup has done its
        // job. Anything else (a hard failure exit code) keeps it for the next
        // launch, which is the only chance an automatic rollback ever gets.
        if exit_code == 0 || exit_code == 42 {
            let bak = lib_path_with_ext(&lib_path, "bak");
            if bak.exists() {
                let _ = std::fs::remove_file(&bak);
            }
        }

        match exit_code {
            42 => {
                // Restart requested (update applied)
                eprintln!("Restarting for update...");
                continue;
            }
            code => {
                std::process::exit(code);
            }
        }
    }
}

/// Find the core library path.
/// Looks next to the launcher executable.
fn find_core_lib() -> PathBuf {
    let exe = std::env::current_exe().expect("Cannot get exe path");
    let dir = exe.parent().expect("Cannot get exe dir");

    #[cfg(target_os = "macos")]
    let name = "libneoshell_core.dylib";
    #[cfg(target_os = "windows")]
    let name = "neoshell_core.dll";
    #[cfg(target_os = "linux")]
    let name = "libneoshell_core.so";

    // Check next to executable first, then ../lib/ (AppImage layout)
    let candidate = dir.join(name);
    if candidate.exists() {
        return candidate;
    }
    let lib_dir = dir.join("../lib").join(name);
    if lib_dir.exists() {
        return lib_dir;
    }
    candidate
}

/// Check for pending update and apply it.
///
/// Nothing is installed without a valid detached ed25519 signature: the staging
/// directory is an ordinary user-writable path, so "a file is sitting there" is
/// not evidence that we put it there.
fn apply_pending_update(lib_path: &Path) {
    let update_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neoshell")
        .join("updates");

    let Some(file_name) = lib_path.file_name() else {
        return;
    };
    let staged = update_dir.join(file_name);
    if !staged.exists() {
        return;
    }

    let sig_path = append_ext(&staged, "sig");

    // Fail closed. Without a compiled-in public key this build cannot tell a
    // genuine update from a file any local process dropped into the staging
    // directory, and installing it would be code execution as the user.
    let pubkey = match update_pubkey() {
        Some(k) => k,
        None => {
            log_line(&format!(
                "Refusing to apply the staged update at {:?}: update signing is not configured.\n\
                 This build has no NEOSHELL_UPDATE_PUBKEY compiled in, so the library cannot be \
                 authenticated and will NOT be installed.\n\
                 Maintainer: run scripts/gen-update-key.sh, set the printed base64 key as the \
                 NEOSHELL_UPDATE_PUBKEY build environment variable (a CI secret), and sign every \
                 published library with scripts/sign-update.sh.",
                staged
            ));
            return;
        }
    };

    if let Err(e) = verify_staged(&staged, &sig_path, &pubkey) {
        log_line(&format!(
            "Rejecting the staged update at {:?}: {}. Discarding it.",
            staged, e
        ));
        let _ = std::fs::remove_file(&staged);
        let _ = std::fs::remove_file(&sig_path);
        return;
    }

    eprintln!("Found a signed staged update, applying...");
    let bak = lib_path_with_ext(lib_path, "bak");

    // Backup current
    if lib_path.exists() {
        // rename() refuses an existing destination on Windows.
        let _ = std::fs::remove_file(&bak);
        if let Err(e) = move_file(lib_path, &bak) {
            log_line(&format!(
                "Failed to back up the current core library: {}. Update not applied.",
                e
            ));
            return;
        }
    }

    // Move staged -> current
    match move_file(&staged, lib_path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&sig_path);
            eprintln!("Update applied successfully");
        }
        Err(e) => {
            log_line(&format!("Failed to apply update: {}. Rolling back.", e));
            let _ = move_file(&bak, lib_path);
        }
    }
}

/// The compiled-in update signing key, if this build has one.
fn update_pubkey() -> Option<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let b64 = UPDATE_PUBKEY_B64.map(str::trim).filter(|s| !s.is_empty())?;
    match BASE64.decode(b64) {
        Ok(bytes) => match <[u8; 32]>::try_from(bytes) {
            Ok(key) => Some(key),
            Err(v) => {
                log_line(&format!(
                    "NEOSHELL_UPDATE_PUBKEY decoded to {} bytes, expected 32 — ignoring it.",
                    v.len()
                ));
                None
            }
        },
        Err(e) => {
            log_line(&format!(
                "NEOSHELL_UPDATE_PUBKEY is not valid base64 ({}) — ignoring it.",
                e
            ));
            None
        }
    }
}

/// Verify the detached signature sitting next to a staged library.
fn verify_staged(staged: &Path, sig_path: &Path, pubkey: &[u8; 32]) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let raw = std::fs::read(sig_path)
        .map_err(|e| format!("no usable signature at {:?} ({})", sig_path, e))?;
    let sig_bytes = decode_signature(&raw)?;

    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| format!("embedded update public key is invalid: {}", e))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let bytes = std::fs::read(staged).map_err(|e| format!("cannot read staged library: {}", e))?;

    key.verify(&bytes, &signature)
        .map_err(|_| "signature does not match the embedded update public key".to_string())
}

/// Accept either 64 raw bytes or a base64 line.
fn decode_signature(raw: &[u8]) -> Result<[u8; 64], String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    if raw.len() == 64 {
        let mut out = [0u8; 64];
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| "signature is neither 64 raw bytes nor base64 text".to_string())?;
    let bytes = BASE64
        .decode(text.trim())
        .map_err(|e| format!("signature base64: {}", e))?;
    <[u8; 64]>::try_from(bytes).map_err(|v: Vec<u8>| {
        format!("signature must be 64 bytes, got {}", v.len())
    })
}

#[cfg(unix)]
fn is_cross_device(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(18) // EXDEV
}

#[cfg(windows)]
fn is_cross_device(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(17) // ERROR_NOT_SAME_DEVICE
}

#[cfg(not(any(unix, windows)))]
fn is_cross_device(_e: &std::io::Error) -> bool {
    false
}

/// Move a file, falling back to copy + rename when the two paths are on
/// different filesystems. `rename()` alone fails with EXDEV for an app run from
/// a DMG or a layout where the data dir and the install dir are separate
/// mounts, which would make every update silently never apply.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if is_cross_device(&e) => {
            let tmp = append_ext(to, "new");
            let _ = std::fs::remove_file(&tmp);
            std::fs::copy(from, &tmp)?;
            std::fs::File::open(&tmp)?.sync_all()?;
            // Final step is a rename inside the destination directory, so the
            // swap is still atomic from a reader's point of view.
            match std::fs::rename(&tmp, to) {
                Ok(()) => {
                    let _ = std::fs::remove_file(from);
                    Ok(())
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    Err(e)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// `libneoshell_core.dylib` + "sig" -> `libneoshell_core.dylib.sig`
fn append_ext(path: &Path, ext: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(ext);
    PathBuf::from(name)
}

/// `libneoshell_core.dylib` + "bak" -> `libneoshell_core.bak`
fn lib_path_with_ext(path: &Path, ext: &str) -> PathBuf {
    let mut p = path.to_path_buf();
    let name = p
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "neoshell_core".to_string());
    p.set_file_name(format!("{}.{}", name, ext));
    p
}

/// Report to stderr and to the app log file. A release build on Windows has no
/// console at all, and a macOS .app launched from Finder has no visible one, so
/// stderr alone would make these messages unreachable exactly when they matter.
fn log_line(msg: &str) {
    use std::io::Write;

    eprintln!("{}", msg);

    let Some(dir) = dirs::data_dir().map(|d| d.join("neoshell")) else {
        return;
    };
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("neoshell.log"))
    {
        let _ = writeln!(f, "[launcher] {}", msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("neoshell_launcher_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// RFC 8032 section 7.1, TEST 2 — a known-good ed25519 triple, so this
    /// exercises the real verification path rather than a self-made signature.
    fn rfc8032_test2() -> ([u8; 32], Vec<u8>, Vec<u8>) {
        let key: [u8; 32] =
            hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .try_into()
                .unwrap();
        let message = hex("72");
        let sig = hex(concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ));
        (key, message, sig)
    }

    #[test]
    fn accepts_a_valid_detached_signature() {
        let (key, message, sig) = rfc8032_test2();
        let dir = scratch("ok");
        let lib = dir.join("libneoshell_core.dylib");
        let sig_path = append_ext(&lib, "sig");
        std::fs::write(&lib, &message).unwrap();

        // Raw 64-byte sidecar, as written by scripts/sign-update.sh.
        std::fs::write(&sig_path, &sig).unwrap();
        verify_staged(&lib, &sig_path, &key).expect("raw signature must verify");

        // Base64 sidecar with a trailing newline, as `... > file.sig` produces.
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        std::fs::write(&sig_path, format!("{}\n", BASE64.encode(&sig))).unwrap();
        verify_staged(&lib, &sig_path, &key).expect("base64 signature must verify");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_tampered_library_or_wrong_key() {
        let (key, message, sig) = rfc8032_test2();
        let dir = scratch("bad");
        let lib = dir.join("libneoshell_core.dylib");
        let sig_path = append_ext(&lib, "sig");
        std::fs::write(&sig_path, &sig).unwrap();

        // One flipped byte in the library must not verify.
        let mut tampered = message.clone();
        tampered[0] ^= 0xff;
        std::fs::write(&lib, &tampered).unwrap();
        assert!(verify_staged(&lib, &sig_path, &key).is_err());

        // Correct library, different signing key.
        std::fs::write(&lib, &message).unwrap();
        let mut other = key;
        other[0] ^= 0x01;
        assert!(verify_staged(&lib, &sig_path, &other).is_err());

        // Missing sidecar is a refusal, not a pass.
        std::fs::remove_file(&sig_path).unwrap();
        assert!(verify_staged(&lib, &sig_path, &key).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_malformed_signature_files() {
        assert!(decode_signature(b"").is_err());
        assert!(decode_signature(&[0u8; 63]).is_err());
        assert!(decode_signature(b"not base64 at all !!").is_err());
        assert_eq!(decode_signature(&[9u8; 64]).unwrap(), [9u8; 64]);
    }

    #[test]
    fn builds_sidecar_and_backup_paths() {
        let lib = PathBuf::from("/opt/neoshell/libneoshell_core.dylib");
        assert_eq!(
            append_ext(&lib, "sig"),
            PathBuf::from("/opt/neoshell/libneoshell_core.dylib.sig")
        );
        assert_eq!(
            lib_path_with_ext(&lib, "bak"),
            PathBuf::from("/opt/neoshell/libneoshell_core.bak")
        );
    }

    #[test]
    fn move_file_replaces_an_existing_destination() {
        let dir = scratch("move");
        let from = dir.join("a.bin");
        let to = dir.join("b.bin");
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&to, b"old").unwrap();

        move_file(&from, &to).unwrap();
        assert!(!from.exists(), "source must be gone after a move");
        assert_eq!(std::fs::read(&to).unwrap(), b"new");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
