use super::*;

/// Resource alert thresholds, persisted to alerts.json.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AlertConfig {
    pub enabled: bool,
    pub cpu_pct: f32,
    pub mem_pct: f32,
    pub disk_pct: f32,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self { enabled: true, cpu_pct: 90.0, mem_pct: 90.0, disk_pct: 90.0 }
    }
}

/// Save one of the small settings files, owner-only and atomic like the
/// rest of what NeoShell writes (see `storage::write_private`). A failure is
/// logged, not shown: the setting still applies for this run and is only
/// lost on restart, which used to happen without a word. Returns whether the
/// file was saved.
/// Save a small settings file off the UI thread. `write_private` fsyncs the
/// file and its directory (F_FULLFSYNC on macOS), and a slider drag saves on
/// every step, so writing inline stalled the window. One writer thread keeps
/// the writes to each file in order, and a newer save of a file replaces one
/// still waiting, so a drag ends in a single write of its last value. A save
/// queued in the last milliseconds before the process exits can be lost.
pub(crate) fn save_setting(path: &std::path::Path, contents: &[u8]) {
    type Save = (std::path::PathBuf, Vec<u8>);
    static WRITER: std::sync::OnceLock<Option<mpsc::Sender<Save>>> = std::sync::OnceLock::new();
    let writer = WRITER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Save>();
        std::thread::Builder::new()
            .name("settings-writer".into())
            .spawn(move || {
                while let Ok(first) = rx.recv() {
                    for (path, contents) in coalesce_saves(std::iter::once(first).chain(rx.try_iter())) {
                        write_setting(&path, &contents);
                    }
                }
            })
            .ok()
            .map(|_| tx)
    });
    let queued = writer
        .as_ref()
        .is_some_and(|tx| tx.send((path.to_path_buf(), contents.to_vec())).is_ok());
    if !queued {
        // No writer thread: write inline rather than lose the setting.
        write_setting(path, contents);
    }
}

/// Write one settings file now, owner-only and atomically. False, and logged,
/// when it could not be saved.
pub(crate) fn write_setting(path: &std::path::Path, contents: &[u8]) -> bool {
    match crate::storage::write_private(path, contents) {
        Ok(()) => true,
        Err(e) => {
            log::error!("could not save {}: {}", path.display(), e);
            false
        }
    }
}

/// The last contents queued for each file, in the order the files were first
/// queued.
pub(crate) fn coalesce_saves(
    saves: impl IntoIterator<Item = (std::path::PathBuf, Vec<u8>)>,
) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::new();
    for (path, contents) in saves {
        match out.iter_mut().find(|(p, _)| *p == path) {
            Some(slot) => slot.1 = contents,
            None => out.push((path, contents)),
        }
    }
    out
}

pub(crate) fn alerts_path() -> std::path::PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("neoshell");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("alerts.json")
}

pub(crate) fn load_alerts() -> AlertConfig {
    std::fs::read_to_string(alerts_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub(crate) fn save_alerts(cfg: &AlertConfig) {
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        save_setting(&alerts_path(), json.as_bytes());
    }
}

// ---- Sidebar groups: folded state and order --------------------------------

/// A reusable command snippet (named command/script) persisted in snippets.json.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Snippet {
    pub id: String,
    pub name: String,
    pub body: String,
}

pub(crate) fn snippets_path() -> std::path::PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("neoshell");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("snippets.json")
}

pub(crate) fn load_snippets() -> Vec<Snippet> {
    std::fs::read_to_string(snippets_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub(crate) fn save_snippets(list: &[Snippet]) {
    if let Ok(json) = serde_json::to_string_pretty(list) {
        save_setting(&snippets_path(), json.as_bytes());
    }
}

/// Load persisted locale preference or detect from system.
pub(crate) fn load_locale() -> String {
    if let Some(config_dir) = dirs::config_dir() {
        let lang_file = config_dir.join("neoshell").join("lang");
        if let Ok(lang) = std::fs::read_to_string(&lang_file) {
            let lang = lang.trim().to_string();
            if !lang.is_empty() {
                return lang;
            }
        }
    }
    // Auto-detect: check LANG / LC_ALL env
    for var in &["LC_ALL", "LANG", "LANGUAGE"] {
        if let Ok(val) = std::env::var(var) {
            let lower = val.to_lowercase();
            if lower.starts_with("zh") {
                return "zh-CN".to_string();
            }
        }
    }
    "en".to_string()
}

/// Load persisted UI scale factor.
pub(crate) fn load_ui_scale() -> f32 {
    if let Some(config_dir) = dirs::config_dir() {
        let scale_file = config_dir.join("neoshell").join("scale");
        if let Ok(s) = std::fs::read_to_string(&scale_file) {
            if let Ok(v) = s.trim().parse::<f32>() {
                if (0.5..=3.0).contains(&v) {
                    return v;
                }
            }
        }
    }
    1.0
}

/// Persist UI scale factor.
pub(crate) fn save_ui_scale(scale: f32) {
    if let Some(config_dir) = dirs::config_dir() {
        let neo_dir = config_dir.join("neoshell");
        save_setting(&neo_dir.join("scale"), format!("{:.2}", scale).as_bytes());
    }
}

/// Load persisted font size.
pub(crate) fn load_font_size() -> f32 {
    if let Some(d) = dirs::config_dir() {
        if let Ok(s) = std::fs::read_to_string(d.join("neoshell").join("fontsize")) {
            if let Ok(v) = s.trim().parse::<f32>() {
                if (8.0..=30.0).contains(&v) { return v; }
            }
        }
    }
    13.0
}

pub(crate) fn save_font_size(size: f32) {
    if let Some(d) = dirs::config_dir() {
        let dir = d.join("neoshell");
        save_setting(&dir.join("fontsize"), format!("{:.1}", size).as_bytes());
    }
}

// ---- Vault idle re-lock ---------------------------------------------------

/// Idle-timeout choices, in minutes. 0 = never re-lock.
pub(crate) const LOCK_TIMEOUT_STEPS: [u32; 7] = [0, 1, 5, 15, 30, 60, 120];

/// Default idle timeout when nothing is persisted yet.
pub(crate) const LOCK_TIMEOUT_DEFAULT: u32 = 15;

/// Snap an arbitrary minute count onto the nearest allowed step. Anything the
/// user could not have produced through the UI — a hand-edited config, a value
/// from a future build — lands on a real choice instead of being discarded.
pub(crate) fn clamp_lock_timeout(mins: u32) -> u32 {
    if LOCK_TIMEOUT_STEPS.contains(&mins) {
        return mins;
    }
    *LOCK_TIMEOUT_STEPS
        .iter()
        .min_by_key(|s| s.abs_diff(mins))
        .unwrap_or(&LOCK_TIMEOUT_DEFAULT)
}

/// Next value up or down the step list, saturating at both ends.
pub(crate) fn cycle_lock_timeout(current: u32, up: bool) -> u32 {
    let cur = clamp_lock_timeout(current);
    let idx = LOCK_TIMEOUT_STEPS.iter().position(|s| *s == cur).unwrap_or(0);
    let next = if up {
        (idx + 1).min(LOCK_TIMEOUT_STEPS.len() - 1)
    } else {
        idx.saturating_sub(1)
    };
    LOCK_TIMEOUT_STEPS[next]
}

/// Is the vault due to re-lock? `false` whenever the timeout is disabled, so
/// the caller never has to special-case 0.
pub(crate) fn idle_lock_due(timeout_mins: u32, idle: Duration) -> bool {
    if timeout_mins == 0 {
        return false;
    }
    idle >= Duration::from_secs(timeout_mins as u64 * 60)
}

/// Load the persisted idle timeout, in minutes.
pub(crate) fn load_lock_timeout() -> u32 {
    if let Some(d) = dirs::config_dir() {
        if let Ok(s) = std::fs::read_to_string(d.join("neoshell").join("locktimeout")) {
            if let Ok(v) = s.trim().parse::<u32>() {
                return clamp_lock_timeout(v);
            }
        }
    }
    LOCK_TIMEOUT_DEFAULT
}

pub(crate) fn save_lock_timeout(mins: u32) {
    if let Some(d) = dirs::config_dir() {
        let dir = d.join("neoshell");
        save_setting(&dir.join("locktimeout"), mins.to_string().as_bytes());
    }
}

/// Human label for an idle-timeout value.
pub(crate) fn lock_timeout_label(mins: u32) -> String {
    if mins == 0 {
        i18n::t("settings.lock_never").to_string()
    } else {
        i18n::tf("settings.lock_minutes", &[("n", &mins.to_string())])
    }
}

/// Persist locale choice to config dir.
pub(crate) fn save_locale(locale: &str) {
    if let Some(config_dir) = dirs::config_dir() {
        let neo_dir = config_dir.join("neoshell");
        save_setting(&neo_dir.join("lang"), locale.as_bytes());
    }
}

/// `preset` carrying `current`'s font sizes: a colour scheme changes colours
/// only. Also how the picker tells which preset is the active one.
pub(crate) fn preset_keeping_fonts(
    mut preset: theme_config::ThemeConfig,
    current: &theme_config::ThemeConfig,
) -> theme_config::ThemeConfig {
    preset.terminal_font_size = current.terminal_font_size;
    preset.ui_font_size = current.ui_font_size;
    preset
}
