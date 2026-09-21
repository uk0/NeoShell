use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::Mutex;
use serde::Deserialize;

const UPDATE_URL: &str = "https://neoshell.wwwneo.com/updates/update.json";

/// How often the UI subscription re-checks for updates.
/// Consumed by the `time::every(...)` subscription in `app.rs`.
pub const CHECK_INTERVAL_SECS: u64 = 3600; // 1 hour

/// Absolute ceiling on a downloaded core library, independent of what the
/// manifest claims. Real libraries are 20-30 MB; anything near this is hostile
/// or wrong, and the read loop must not fill the user's disk either way.
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Slack allowed over the manifest's `size` before a transfer is aborted.
const SIZE_MARGIN_BYTES: u64 = 64 * 1024;

/// Base64-encoded ed25519 public key (32 raw bytes) used to authenticate update
/// libraries. Injected at build time:
///   NEOSHELL_UPDATE_PUBKEY=<base64> cargo build --release
/// Absent -> updates are refused rather than trusted (see `update_pubkey`).
const UPDATE_PUBKEY_B64: Option<&str> = option_env!("NEOSHELL_UPDATE_PUBKEY");

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub changelog: String,
    pub date: String,
    pub downloads: std::collections::HashMap<String, PlatformDownload>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlatformDownload {
    pub url: String,
    /// Legacy transport checksum. Kept so older manifests still parse; it is
    /// served by the same document as `url`, so it proves integrity only —
    /// never authenticity. `sig` is what actually gates an install.
    #[serde(default)]
    pub md5: String,
    /// Hex-encoded SHA-256 of the library bytes.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Base64 ed25519 detached signature over the library bytes. When absent,
    /// the `<url>.sig` sidecar is fetched instead.
    #[serde(default)]
    pub sig: Option<String>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct UpdateState {
    pub available: bool,
    pub version: String,
    pub changelog: String,
    pub download_progress: f64, // 0.0 - 1.0
    pub ready: bool,            // Downloaded and verified
    pub error: Option<String>,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            available: false,
            version: String::new(),
            changelog: String::new(),
            download_progress: 0.0,
            ready: false,
            error: None,
        }
    }
}

pub struct Updater {
    pub state: Arc<Mutex<UpdateState>>,
    checking: Arc<AtomicBool>,
    downloading: Arc<AtomicBool>,
}

impl Updater {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(UpdateState::default())),
            checking: Arc::new(AtomicBool::new(false)),
            downloading: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get the current platform key for update.json
    fn platform_key() -> &'static str {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            "macos-aarch64"
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            "macos-x86_64"
        }
        #[cfg(target_os = "windows")]
        {
            "windows-x64"
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            "linux-x86_64"
        }
        #[cfg(not(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            target_os = "windows",
            all(target_os = "linux", target_arch = "x86_64"),
        )))]
        {
            "unknown"
        }
    }

    /// Get the staging directory for downloaded updates
    fn staging_dir() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("neoshell")
            .join("updates")
    }

    /// Check for updates in background. Non-blocking.
    pub fn check_async(&self) {
        if self.checking.load(Ordering::Relaxed) {
            return; // Already checking
        }
        self.checking.store(true, Ordering::Relaxed);

        let state = self.state.clone();
        let checking = self.checking.clone();
        let current_version = env!("CARGO_PKG_VERSION").to_string();

        std::thread::spawn(move || {
            match check_for_update(&current_version) {
                Ok(Some(info)) => {
                    let mut s = state.lock();
                    s.available = true;
                    s.version = info.version;
                    s.changelog = info.changelog;
                }
                Ok(None) => {
                    // No update available
                }
                Err(e) => {
                    let mut s = state.lock();
                    s.error = Some(format!("Update check failed: {}", e));
                }
            }
            checking.store(false, Ordering::Relaxed);
        });
    }

    /// Download the update in background. Non-blocking.
    /// A second call while a download is in flight is a no-op: two writers on
    /// the same staging path would interleave into one corrupt file.
    pub fn download_async(&self) {
        if self
            .downloading
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return; // Already downloading
        }

        let state = self.state.clone();
        let downloading = self.downloading.clone();

        std::thread::spawn(move || {
            match download_update(&state) {
                Ok(()) => {
                    let mut s = state.lock();
                    s.ready = true;
                    s.download_progress = 1.0;
                }
                Err(e) => {
                    let mut s = state.lock();
                    s.error = Some(format!("Download failed: {}", e));
                    // Leave no half-finished bar behind: the UI uses
                    // `0.0 < progress < 1.0` to mean "in flight".
                    s.download_progress = 0.0;
                }
            }
            downloading.store(false, Ordering::Release);
        });
    }
}

/// Parse `x.y.z` (tolerating a leading `v` and a `-pre` / `+build` suffix).
/// Returns None for anything that is not three numeric components, so a
/// malformed manifest can never be read as "newer".
fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let trimmed = v.trim().trim_start_matches('v');
    let core = trimmed.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.trim().parse::<u64>().ok()?;
    let minor = parts.next()?.trim().parse::<u64>().ok()?;
    let patch = parts.next()?.trim().parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// True only when `candidate` is a strictly higher release than `current`.
/// Numeric, not lexicographic: "0.10.0" > "0.9.0", and "0.9.9" never beats
/// "0.10.1" (which would be a silent downgrade to an older, weaker core).
fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_semver(candidate), parse_semver(current)) {
        (Some(new), Some(cur)) => new > cur,
        _ => false,
    }
}

fn check_for_update(current_version: &str) -> Result<Option<UpdateInfo>, String> {
    let resp = ureq::get(UPDATE_URL)
        .call()
        .map_err(|e| format!("HTTP error: {}", e))?;

    let info: UpdateInfo = resp
        .into_json()
        .map_err(|e| format!("JSON parse error: {}", e))?;

    if is_newer(&info.version, current_version) {
        Ok(Some(info))
    } else {
        Ok(None)
    }
}

/// The compiled-in update signing key, or an explanation of why there isn't one.
fn update_pubkey() -> Result<[u8; 32], String> {
    let b64 = UPDATE_PUBKEY_B64.map(str::trim).filter(|s| !s.is_empty());
    let Some(b64) = b64 else {
        return Err(
            "update signing is not configured (this build has no NEOSHELL_UPDATE_PUBKEY), \
             so a downloaded library cannot be authenticated — refusing to install one"
                .to_string(),
        );
    };
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| format!("NEOSHELL_UPDATE_PUBKEY is not valid base64: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| "NEOSHELL_UPDATE_PUBKEY must decode to 32 bytes".to_string())
}

/// Digests accumulated while the body was streamed to disk.
struct Digests {
    sha256: String,
    md5: String,
    len: u64,
}

/// Stream `url` into `path`, hashing as it goes. Never buffers the whole body,
/// and aborts as soon as more than `total` (+ a small margin) has arrived.
fn stream_to_file(
    url: &str,
    path: &Path,
    total: u64,
    state: &Arc<Mutex<UpdateState>>,
) -> Result<Digests, String> {
    use md5::Md5;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("Download: {}", e))?;

    let mut file = std::fs::File::create(path).map_err(|e| format!("Create file: {}", e))?;
    let mut reader = resp.into_reader();
    let mut buf = [0u8; 32768];
    let mut downloaded: u64 = 0;
    let mut sha = Sha256::new();
    let mut md5 = Md5::new();
    let cap = total.saturating_add(SIZE_MARGIN_BYTES);

    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("Read: {}", e))?;
        if n == 0 {
            break;
        }
        downloaded += n as u64;
        if downloaded > cap {
            return Err(format!(
                "Oversized download: server sent more than {} bytes (manifest says {})",
                cap, total
            ));
        }
        let chunk = &buf[..n];
        file.write_all(chunk).map_err(|e| format!("Write: {}", e))?;
        sha.update(chunk);
        md5.update(chunk);

        let mut s = state.lock();
        s.download_progress = (downloaded as f64 / total as f64).min(1.0);
    }

    file.sync_all().map_err(|e| format!("Sync: {}", e))?;

    Ok(Digests {
        sha256: format!("{:x}", sha.finalize()),
        md5: format!("{:x}", md5.finalize()),
        len: downloaded,
    })
}

/// Accept either 64 raw bytes or a base64 line.
fn decode_signature(raw: &[u8]) -> Result<[u8; 64], String> {
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
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("signature must be 64 bytes, got {}", v.len()))
}

/// Detached signature for this download: from the manifest when present,
/// otherwise the `<url>.sig` sidecar.
fn fetch_signature(download: &PlatformDownload) -> Result<[u8; 64], String> {
    if let Some(b64) = download
        .sig
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return decode_signature(b64.as_bytes());
    }

    use std::io::Read;
    let url = format!("{}.sig", download.url);
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("Signature fetch ({}): {}", url, e))?;
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(4096)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Signature read: {}", e))?;
    decode_signature(&bytes)
}

fn verify_signature(path: &Path, sig: &[u8; 64], pubkey: &[u8; 32]) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| format!("Embedded update public key is invalid: {}", e))?;
    let signature = Signature::from_bytes(sig);

    // Ed25519 takes the message as one slice, so this single read is inherent;
    // the SHA-256 digest above was streamed while writing, not re-read.
    let bytes = std::fs::read(path).map_err(|e| format!("Read for signature check: {}", e))?;

    key.verify(&bytes, &signature)
        .map_err(|_| "signature does not match the embedded update public key".to_string())
}

fn download_update(state: &Arc<Mutex<UpdateState>>) -> Result<(), String> {
    {
        // A retry starts clean, otherwise the stale error hides the new result.
        let mut s = state.lock();
        s.error = None;
        s.ready = false;
        s.download_progress = 0.0;
    }

    // Fail closed before touching the network: an update this build could not
    // authenticate is worse than no update at all.
    let pubkey = update_pubkey()?;

    // Fetch update info
    let resp = ureq::get(UPDATE_URL)
        .call()
        .map_err(|e| format!("HTTP: {}", e))?;
    let info: UpdateInfo = resp.into_json().map_err(|e| format!("JSON: {}", e))?;

    let platform = Updater::platform_key();
    let download = info
        .downloads
        .get(platform)
        .ok_or_else(|| format!("No download for platform: {}", platform))?;

    let total = download.size;
    if total == 0 || total > MAX_DOWNLOAD_BYTES {
        return Err(format!(
            "Refusing manifest: size {} is outside 1..={}",
            total, MAX_DOWNLOAD_BYTES
        ));
    }

    // Create staging directory
    let staging_dir = Updater::staging_dir();
    std::fs::create_dir_all(&staging_dir).map_err(|e| format!("Create dir: {}", e))?;

    // Determine library filename
    #[cfg(target_os = "macos")]
    let lib_name = "libneoshell_core.dylib";
    #[cfg(target_os = "windows")]
    let lib_name = "neoshell_core.dll";
    #[cfg(target_os = "linux")]
    let lib_name = "libneoshell_core.so";
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let lib_name = "libneoshell_core.so";

    let staged_path = staging_dir.join(lib_name);
    let part_path = staging_dir.join(format!("{}.part", lib_name));
    let sig_path = staging_dir.join(format!("{}.sig", lib_name));

    // Nothing from an earlier attempt may survive into this one. In particular
    // `staged_path` is the exact name the launcher picks up at boot, so it only
    // ever appears once the bytes are complete and verified.
    let _ = std::fs::remove_file(&staged_path);
    let _ = std::fs::remove_file(&part_path);
    let _ = std::fs::remove_file(&sig_path);

    let signature = fetch_signature(download)?;

    let verified = (|| -> Result<(), String> {
        let digests = stream_to_file(&download.url, &part_path, total, state)?;

        if digests.len != total {
            return Err(format!(
                "Truncated download: got {} bytes, manifest says {}",
                digests.len, total
            ));
        }

        match download.sha256.as_deref().map(str::trim) {
            Some(expected) if !expected.is_empty() => {
                if !expected.eq_ignore_ascii_case(&digests.sha256) {
                    return Err(format!(
                        "SHA-256 mismatch: expected {}, got {}",
                        expected, digests.sha256
                    ));
                }
            }
            _ => {
                // Legacy manifest: fall back to the old checksum when present.
                let expected = download.md5.trim();
                if !expected.is_empty() && !expected.eq_ignore_ascii_case(&digests.md5) {
                    return Err(format!(
                        "MD5 mismatch: expected {}, got {}",
                        expected, digests.md5
                    ));
                }
            }
        }

        verify_signature(&part_path, &signature, &pubkey)?;
        Ok(())
    })();

    if let Err(e) = verified {
        let _ = std::fs::remove_file(&part_path);
        return Err(e);
    }

    // Sidecar first: the launcher re-verifies at apply time and must never find
    // a library without its signature.
    std::fs::write(&sig_path, signature).map_err(|e| format!("Write signature: {}", e))?;

    // Publish the staged library atomically (same directory, so no EXDEV).
    std::fs::rename(&part_path, &staged_path).map_err(|e| {
        let _ = std::fs::remove_file(&part_path);
        let _ = std::fs::remove_file(&sig_path);
        format!("Stage update: {}", e)
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_semver() {
        assert_eq!(parse_semver("0.7.0"), Some((0, 7, 0)));
        assert_eq!(parse_semver("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver(" 10.20.30 "), Some((10, 20, 30)));
        assert_eq!(parse_semver("1.2.3-beta.1"), Some((1, 2, 3)));
        assert_eq!(parse_semver("1.2.3+build7"), Some((1, 2, 3)));
    }

    #[test]
    fn rejects_malformed_versions() {
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("1.2"), None);
        assert_eq!(parse_semver("1.2.3.4"), None);
        assert_eq!(parse_semver("abc"), None);
        assert_eq!(parse_semver("1.x.3"), None);
    }

    #[test]
    fn offers_double_digit_minor_over_single_digit() {
        // The lexicographic bug: "0.10.0" > "0.9.0" is false as strings.
        assert!(is_newer("0.10.0", "0.9.0"));
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
    }

    #[test]
    fn refuses_downgrade() {
        assert!(!is_newer("0.9.9", "0.10.1"));
        assert!(!is_newer("0.6.27", "0.7.0"));
        assert!(!is_newer("0.0.1", "0.7.0"));
    }

    #[test]
    fn refuses_equal_version() {
        assert!(!is_newer("0.7.0", "0.7.0"));
        assert!(!is_newer("v0.7.0", "0.7.0"));
    }

    #[test]
    fn refuses_malformed_version() {
        assert!(!is_newer("not-a-version", "0.7.0"));
        assert!(!is_newer("999", "0.7.0"));
        assert!(!is_newer("0.8.0", "garbage"));
    }

    #[test]
    fn decodes_raw_and_base64_signatures() {
        let raw = [7u8; 64];
        assert_eq!(decode_signature(&raw).unwrap(), raw);

        let b64 = BASE64.encode(raw);
        assert_eq!(decode_signature(b64.as_bytes()).unwrap(), raw);
        // Trailing newline from `... > file.sig` must not break it.
        let with_nl = format!("{}\n", b64);
        assert_eq!(decode_signature(with_nl.as_bytes()).unwrap(), raw);
    }

    #[test]
    fn parses_a_signed_manifest() {
        let json = r#"{
            "version": "0.8.0",
            "date": "2026-09-21",
            "changelog": "x",
            "downloads": {
                "macos-aarch64": {
                    "url": "https://example.invalid/libneoshell_core.dylib",
                    "sha256": "aa",
                    "sig": "bb",
                    "md5": "cc",
                    "size": 123
                }
            }
        }"#;
        let info: UpdateInfo = serde_json::from_str(json).unwrap();
        let d = &info.downloads["macos-aarch64"];
        assert_eq!(d.sha256.as_deref(), Some("aa"));
        assert_eq!(d.sig.as_deref(), Some("bb"));
        assert_eq!(d.size, 123);
    }

    #[test]
    fn parses_a_legacy_manifest_without_sha256_or_sig() {
        // Manifests published before signing existed must still deserialize;
        // they simply fail later, at the signature check.
        let json = r#"{
            "version": "0.6.27",
            "date": "2026-04-25",
            "changelog": "x",
            "downloads": {
                "linux-x86_64": {
                    "url": "https://example.invalid/libneoshell_core.so",
                    "md5": "ca6530ebc2d18c8b1fb77c9f1f3c00b6",
                    "size": 20611600
                }
            }
        }"#;
        let info: UpdateInfo = serde_json::from_str(json).unwrap();
        let d = &info.downloads["linux-x86_64"];
        assert!(d.sha256.is_none());
        assert!(d.sig.is_none());
        assert_eq!(d.md5, "ca6530ebc2d18c8b1fb77c9f1f3c00b6");
    }

    #[test]
    fn rejects_wrong_length_signature() {
        let short = BASE64.encode([1u8; 32]);
        assert!(decode_signature(short.as_bytes()).is_err());
        assert!(decode_signature(b"not base64 at all !!").is_err());
    }
}
