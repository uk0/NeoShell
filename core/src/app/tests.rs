use super::*;

#[test]
fn safe_local_basename_strips_remote_directory_components() {
    assert_eq!(
        safe_local_basename("report.tar.gz").as_deref(),
        Some("report.tar.gz")
    );
    assert_eq!(safe_local_basename("logs/app.log").as_deref(), Some("app.log"));
    // The two vectors: `..` traversal, and an absolute name that would
    // otherwise replace the download directory outright.
    assert_eq!(
        safe_local_basename("../../../../tmp/EVIL").as_deref(),
        Some("EVIL")
    );
    assert_eq!(
        safe_local_basename("/Users/victim/.zshrc").as_deref(),
        Some(".zshrc")
    );
    // Whatever comes back must never carry a separator on any platform.
    for name in ["..\\..\\evil.txt", "a/b/c", "/etc/passwd"] {
        if let Some(base) = safe_local_basename(name) {
            assert!(
                !base.contains('/') && !base.contains('\\'),
                "{name:?} produced {base:?}"
            );
        }
    }
}

#[test]
fn safe_local_basename_rejects_degenerate_names() {
    for bad in ["", ".", "..", "/", "foo/..", "a\0b", "a\nb", "a\rb"] {
        assert_eq!(safe_local_basename(bad), None, "should reject {bad:?}");
    }
}

// ---- vault idle re-lock ------------------------------------------

#[test]
fn idle_lock_never_fires_when_disabled() {
    // 0 means "never", and must stay that way no matter how long the
    // session has been idle — this is the switch that keeps the feature
    // out of the way of users who do not want it.
    for secs in [0u64, 60, 3600, 86_400, 86_400 * 365] {
        assert!(
            !idle_lock_due(0, Duration::from_secs(secs)),
            "0 must never lock, idle={secs}s"
        );
    }
}

#[test]
fn idle_lock_fires_at_the_timeout_not_before() {
    let t = 15;
    let deadline = Duration::from_secs(15 * 60);
    assert!(!idle_lock_due(t, Duration::ZERO));
    assert!(!idle_lock_due(t, deadline - Duration::from_secs(1)));
    // Inclusive: a tick that lands exactly on the deadline locks.
    assert!(idle_lock_due(t, deadline));
    assert!(idle_lock_due(t, deadline + Duration::from_secs(1)));
    // A one-minute timeout is the tightest the UI offers; the 20s poll
    // interval means it must still fire well inside two minutes.
    assert!(!idle_lock_due(1, Duration::from_secs(59)));
    assert!(idle_lock_due(1, Duration::from_secs(60)));
}

#[test]
fn idle_lock_does_not_overflow_on_the_largest_timeout() {
    // `timeout_mins * 60` is the only arithmetic here; make sure the
    // widest step cannot wrap and turn "2 hours" into "immediately".
    let max = *LOCK_TIMEOUT_STEPS.last().unwrap();
    assert!(!idle_lock_due(max, Duration::from_secs(max as u64 * 60 - 1)));
    assert!(idle_lock_due(max, Duration::from_secs(max as u64 * 60)));
    // The widest value the type allows is ~8100 years of minutes; it has
    // to stay in range as u64 seconds rather than wrapping to a tiny
    // deadline. `state.lock_timeout_mins` is always clamped, so this is
    // defence against a future caller, not a reachable path today.
    assert!(!idle_lock_due(u32::MAX, Duration::from_secs(1)));
    assert!(!idle_lock_due(
        u32::MAX,
        Duration::from_secs(u32::MAX as u64 * 60 - 1)
    ));
    assert!(idle_lock_due(
        u32::MAX,
        Duration::from_secs(u32::MAX as u64 * 60)
    ));
}

#[test]
fn clamp_lock_timeout_snaps_onto_a_real_step() {
    for step in LOCK_TIMEOUT_STEPS {
        assert_eq!(clamp_lock_timeout(step), step);
    }
    // A hand-edited or future-build value lands on a choice the UI can
    // actually display, rather than being silently dropped to 0 (= never).
    assert_eq!(clamp_lock_timeout(13), 15);
    assert_eq!(clamp_lock_timeout(45), 30);
    // A tie goes to the lower step — i.e. the shorter timeout, which is
    // the safe direction to round in.
    assert_eq!(clamp_lock_timeout(3), 1, "3 is 2 from both 1 and 5");
    assert_eq!(clamp_lock_timeout(10), 5, "10 is 5 from both 5 and 15");
    assert_eq!(clamp_lock_timeout(u32::MAX), 120);
    for weird in [2u32, 7, 44, 99, 1000, u32::MAX] {
        assert!(
            LOCK_TIMEOUT_STEPS.contains(&clamp_lock_timeout(weird)),
            "{weird} clamped off the step list"
        );
    }
}

#[test]
fn cycle_lock_timeout_saturates_at_both_ends() {
    assert_eq!(cycle_lock_timeout(0, false), 0, "cannot go below Never");
    assert_eq!(cycle_lock_timeout(120, true), 120, "cannot go past the top");
    // Walking up from Never reaches the top and stops there.
    let mut v = 0;
    for _ in 0..LOCK_TIMEOUT_STEPS.len() * 2 {
        v = cycle_lock_timeout(v, true);
    }
    assert_eq!(v, 120);
    // And back down to Never.
    for _ in 0..LOCK_TIMEOUT_STEPS.len() * 2 {
        v = cycle_lock_timeout(v, false);
    }
    assert_eq!(v, 0);
    // Stepping from an off-list value still produces an on-list one.
    assert_eq!(cycle_lock_timeout(13, true), 30);
    assert_eq!(cycle_lock_timeout(13, false), 5);
}

#[test]
fn locking_scrubs_plaintext_secrets_out_of_open_forms() {
    let mut conn = ConnectionFormData {
        name: "prod".into(),
        host: "10.0.0.1".into(),
        username: "root".into(),
        password: "hunter2".into(),
        passphrase: "keypass".into(),
        private_key: "/home/me/.ssh/id_ed25519".into(),
        ..Default::default()
    };
    let mut proxy = ProxyFormData {
        name: "bastion".into(),
        password: "proxypw".into(),
        passphrase: "proxypass".into(),
        private_key: "/home/me/.ssh/jump".into(),
        ..Default::default()
    };
    let mut tunnel = TunnelFormData {
        name: "db".into(),
        password: "tunnelpw".into(),
        passphrase: "tunnelpass".into(),
        private_key: "/home/me/.ssh/tunnel".into(),
        forwards_text: "5432:127.0.0.1:5432".into(),
        ..Default::default()
    };

    scrub_form_secrets(&mut conn, &mut proxy, &mut tunnel);

    for secret in [
        &conn.password, &conn.passphrase,
        &proxy.password, &proxy.passphrase,
        &tunnel.password, &tunnel.passphrase,
    ] {
        assert!(secret.is_empty(), "a secret survived the lock: {secret:?}");
    }
    // Non-secret fields are left alone so re-unlocking does not throw the
    // user's half-finished form away. A private-key *path* is not a
    // secret; the key material never enters these structs.
    assert_eq!(conn.host, "10.0.0.1");
    assert_eq!(conn.private_key, "/home/me/.ssh/id_ed25519");
    assert_eq!(proxy.name, "bastion");
    assert_eq!(proxy.private_key, "/home/me/.ssh/jump");
    assert_eq!(tunnel.forwards_text, "5432:127.0.0.1:5432");
    assert_eq!(tunnel.private_key, "/home/me/.ssh/tunnel");
}

#[test]
fn lock_timeout_label_reads_as_a_setting() {
    i18n::set_locale("en");
    assert_eq!(lock_timeout_label(0), "Never");
    assert_eq!(lock_timeout_label(15), "15 min");
    // The {n} placeholder must actually be substituted, in both locales.
    i18n::set_locale("zh-CN");
    let zh = lock_timeout_label(30);
    assert!(!zh.contains("{n}"), "unsubstituted placeholder: {zh}");
    assert!(zh.contains("30"), "{zh}");
    i18n::set_locale("en");
}

/// The forward rules the edit form renders are re-parsed on save, so the
/// text it produces has to survive the round trip. Rendering the three
/// fields by hand silently turned an `R:`/`D:` rule into a local one.
#[test]
fn tunnel_form_renders_forwards_in_parseable_syntax() {
    use crate::tunnel::{ForwardKind, ForwardRule};
    let rules = vec![
        ForwardRule { local_port: 8080, remote_host: "10.0.0.5".into(), remote_port: 80, kind: ForwardKind::Local },
        ForwardRule { local_port: 3000, remote_host: "0.0.0.0".into(), remote_port: 8080, kind: ForwardKind::Remote },
        ForwardRule { local_port: 1080, remote_host: String::new(), remote_port: 0, kind: ForwardKind::Dynamic },
    ];
    // Exactly what `Message::ShowTunnelForm` puts in `forwards_text`.
    let text = rules.iter().map(|f| f.spec()).collect::<Vec<_>>().join("\n");
    let reparsed: Vec<ForwardRule> = text
        .lines()
        .map(|l| ForwardRule::parse(l.trim()).expect("must re-parse"))
        .collect();
    assert_eq!(reparsed, rules, "SaveTunnel would have rewritten the rules");
}

// ---- UI pass -----------------------------------------------------

/// Every filled button must stay readable whatever colour the theme puts
/// under it — every shipped preset's accent and danger, plus the corners
/// of the colour space a user can dial in with the RGB sliders.
#[test]
fn filled_buttons_meet_wcag_aa_at_rest_and_on_hover() {
    let mut bases: Vec<(String, Color)> = crate::ui::theme_config::PRESETS
        .iter()
        .flat_map(|(name, cfg)| {
            [
                (format!("{name} accent"), cfg.accent.to_color()),
                (format!("{name} danger"), cfg.danger.to_color()),
            ]
        })
        .collect();
    for (name, c) in [
        ("white", Color::WHITE),
        ("black", Color::BLACK),
        ("red", Color::from_rgb8(255, 0, 0)),
        ("green", Color::from_rgb8(0, 255, 0)),
        ("blue", Color::from_rgb8(0, 0, 255)),
        ("yellow", Color::from_rgb8(255, 255, 0)),
        ("mid grey", Color::from_rgb8(119, 119, 119)),
        ("slate", Color::from_rgb8(100, 116, 139)),
    ] {
        bases.push((name.to_string(), c));
    }
    for (name, base) in bases {
        let (fill, label) = fill_and_label(base);
        let rest = contrast_ratio(label, fill);
        let hover = contrast_ratio(label, mix(fill, Color::WHITE, HOVER_LIFT));
        assert!(rest >= 4.5, "{name}: label on fill is {rest:.2}:1");
        assert!(hover >= 4.5, "{name}: label on hover fill is {hover:.2}:1");
    }
}

/// The shipped accent keeps white text and only darkens as far as AA
/// needs — it must still read as the same indigo, not a new colour.
#[test]
fn shipped_accent_keeps_white_text_and_its_hue() {
    let accent = theme::ACCENT;
    assert!(
        contrast_ratio(theme::TEXT_PRIMARY, accent) < 4.5,
        "fixture: TEXT_PRIMARY on ACCENT was the failing pair"
    );
    let (fill, label) = fill_and_label(accent);
    assert_eq!(label, Color::WHITE);
    assert!(rel_luminance(fill) < rel_luminance(accent), "fill must be darker");
    for (f, a) in [(fill.r, accent.r), (fill.g, accent.g), (fill.b, accent.b)] {
        assert!(f >= a * 0.8, "darkened more than 20%: {fill:?} from {accent:?}");
    }
}

#[test]
fn mix_and_tint_never_leave_the_gamut() {
    let c = mix(Color::from_rgb(0.9, 0.5, 0.1), Color::WHITE, 7.0);
    assert_eq!(c, Color::WHITE, "t is clamped to 1");
    let c = mix(theme::ACCENT, Color::BLACK, -3.0);
    assert_eq!(c, theme::ACCENT, "t is clamped to 0");
    assert_eq!(tint(theme::ACCENT, 1.7).a, 1.0);
    assert_eq!(tint(theme::ACCENT, -1.0).a, 0.0);
    assert!((contrast_ratio(Color::WHITE, Color::BLACK) - 21.0).abs() < 0.01);
}

/// `ConnectionConfig.color` is free text from the vault; only a real
/// #rrggbb may draw a rail.
#[test]
fn connection_color_tag_parses_only_rrggbb() {
    assert_eq!(parse_hex_color("#ff8800"), Some(Color::from_rgb8(0xff, 0x88, 0x00)));
    assert_eq!(parse_hex_color("22C55E"), Some(Color::from_rgb8(0x22, 0xc5, 0x5e)));
    assert_eq!(parse_hex_color("  #0a0B0c "), Some(Color::from_rgb8(0x0a, 0x0b, 0x0c)));
    for bad in ["", "#", "#fff", "#ff88001", "#gg0000", "red", "#ff 880", "##ff8800", "+ff8800"] {
        assert_eq!(parse_hex_color(bad), None, "{bad:?} must not parse");
    }
}

/// One z-order drives both what view_main draws and what ESC closes; it
/// must list every overlay exactly once and keep the placements its doc
/// comment promises.
#[test]
fn overlay_z_order_is_complete_and_puts_alerts_on_top() {
    use Overlay::*;
    let mut seen = HashSet::new();
    for o in Overlay::Z_ORDER {
        assert!(seen.insert(o), "{o:?} listed twice");
    }
    // Exhaustive on purpose: a new variant fails to compile here until
    // it is added below — and then to Z_ORDER, or this test fails.
    let every = |o: Overlay| match o {
        Palette | ConfirmDelete | AuthPrompt | ConfirmAction | LogViewer | ErrorDialog
        | ProcessDetail | Editor | NetworkDetail | ConnectDialog | History | ProxyManager
        | TunnelManager | TabRename | SftpInput | KeyManager | ShortcutsHelp | Broadcast
        | Snippets | About | Settings | ConnectionForm => o,
    };
    for o in [
        Palette, ConfirmDelete, AuthPrompt, ConfirmAction, LogViewer, ErrorDialog,
        ProcessDetail, Editor, NetworkDetail, ConnectDialog, History, ProxyManager,
        TunnelManager, TabRename, SftpInput, KeyManager, ShortcutsHelp, Broadcast, Snippets,
        About, Settings, ConnectionForm,
    ] {
        assert!(seen.contains(&every(o)), "{o:?} missing from Z_ORDER");
    }

    let z = |o: Overlay| Overlay::Z_ORDER.iter().position(|&x| x == o).unwrap();
    assert_eq!(z(Palette), 0, "the palette is summoned over anything");
    // A failure raised inside a panel must show over that panel.
    for panel in [ProxyManager, TunnelManager, Editor, KeyManager, Settings, ConnectionForm, ConnectDialog] {
        assert!(z(ErrorDialog) < z(panel), "error dialog hidden under {panel:?}");
    }
    // "View log" in the error dialog opens the log viewer over it.
    assert!(z(LogViewer) < z(ErrorDialog));
    // An SSH thread is blocked on the auth prompt, and a test or a key
    // deploy raises it from inside a panel: it must clear all of them.
    for panel in [
        ErrorDialog, ProcessDetail, Editor, ConnectDialog, KeyManager, Settings,
        ConnectionForm, SftpInput,
    ] {
        assert!(z(AuthPrompt) < z(panel), "auth prompt hidden under {panel:?}");
    }
    // The kill confirmation is opened from the process popup.
    assert!(z(ConfirmAction) < z(ProcessDetail));
    // A failed SFTP call reports over the dialog that asked for it.
    assert!(z(ErrorDialog) < z(SftpInput));
}

// ---- feature wiring ------------------------------------------------

fn record(cmd: &str, timestamp: u64) -> CmdRecord {
    CmdRecord {
        cmd: cmd.to_string(),
        session_title: "root@web:22".to_string(),
        host: "web".to_string(),
        timestamp,
    }
}

fn snippet(body: &str) -> Snippet {
    Snippet { id: body.to_string(), name: body.to_string(), body: body.to_string() }
}

#[test]
fn quick_cmd_matches_newest_history_first_then_snippets() {
    let history = vec![
        record("git status", 1),
        record("git log --oneline", 2),
        record("ls -la", 3),
        record("git status", 4), // run again: counts as the newest
    ];
    let snippets = vec![snippet("git pull --rebase"), snippet("docker ps")];
    assert_eq!(
        quick_cmd_matches("git", &history, &snippets),
        vec!["git status", "git log --oneline", "git pull --rebase"],
        "newest first, de-duplicated, snippets after history"
    );
    // Case matters to a shell.
    assert!(quick_cmd_matches("GIT", &history, &snippets).is_empty());
}

#[test]
fn quick_cmd_matches_caps_and_skips_what_it_cannot_offer() {
    let history: Vec<CmdRecord> = (0..20).map(|i| record(&format!("echo {}", i), i)).collect();
    let offered = quick_cmd_matches("echo", &history, &[]);
    assert_eq!(offered.len(), QUICK_CMD_SUGGESTIONS);
    assert_eq!(offered[0], "echo 19", "most recent first");
    // Nothing for an empty input, and never the text exactly as typed.
    assert!(quick_cmd_matches("", &history, &[]).is_empty());
    assert!(quick_cmd_matches("   ", &history, &[]).is_empty());
    assert!(quick_cmd_matches("echo 19", &history, &[]).is_empty());
    // A multi-line snippet cannot go into a one-line input.
    let multi = vec![snippet("cd /srv\nmake deploy"), snippet("cd /srv && make\n")];
    assert_eq!(quick_cmd_matches("cd", &[], &multi), vec!["cd /srv && make"]);
}

#[test]
fn autocomplete_takes_only_plain_tab_and_down() {
    use keyboard::key::Named;
    let none = keyboard::Modifiers::default();
    assert!(is_autocomplete_key(&keyboard::Key::Named(Named::Tab), &none));
    assert!(is_autocomplete_key(&keyboard::Key::Named(Named::ArrowDown), &none));
    assert!(!is_autocomplete_key(&keyboard::Key::Named(Named::ArrowUp), &none));
    // Shift+Tab, Ctrl+Tab (tab switching) and Alt+Down stay with the terminal.
    for m in [keyboard::Modifiers::SHIFT, keyboard::Modifiers::CTRL, keyboard::Modifiers::ALT] {
        assert!(!is_autocomplete_key(&keyboard::Key::Named(Named::Tab), &m));
        assert!(!is_autocomplete_key(&keyboard::Key::Named(Named::ArrowDown), &m));
    }
}

/// `history.json` inside a directory of its own, so parallel tests never
/// share one and each can remove its directory when done.
fn scratch_history(test: &str) -> std::path::PathBuf {
    std::env::temp_dir()
        .join(format!("neoshell-app-test-{}-{}", std::process::id(), test))
        .join("history.json")
}

fn remove_scratch(path: &std::path::Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn history_loader_reads_missing_or_damaged_files_as_empty() {
    let path = scratch_history("damaged");
    remove_scratch(&path);
    assert!(load_history_from(&path).is_empty(), "missing file");
    crate::storage::write_private(&path, b"{ not json").expect("write");
    assert!(load_history_from(&path).is_empty());
    // A record written before a field existed still loads.
    crate::storage::write_private(&path, br#"[{"cmd":"uptime"}]"#).expect("write");
    let loaded = load_history_from(&path);
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].cmd, "uptime");
    assert_eq!(loaded[0].timestamp, 0);
    remove_scratch(&path);
}

/// One unlocked vault shared by the history tests, so Argon2id runs once.
/// Its file is deleted at once: sealing only needs the key, which stays in
/// memory.
fn history_vault() -> &'static ConnectionStore {
    shared_history_vault()
}

/// `history_vault`, in the `Arc` the app holds its store in.
fn shared_history_vault() -> &'static Arc<ConnectionStore> {
    static VAULT: std::sync::OnceLock<Arc<ConnectionStore>> = std::sync::OnceLock::new();
    VAULT.get_or_init(|| {
        let dir = std::env::temp_dir()
            .join(format!("neoshell-app-test-{}-vault", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("vault dir");
        let store = ConnectionStore::with_vault_path(dir.join("vault.json"));
        store.set_master_password("history tests").expect("vault");
        let _ = std::fs::remove_dir_all(&dir);
        Arc::new(store)
    })
}

/// A `HistoryFile` over a directory of its own, removed on drop.
struct HistoryScratch(std::path::PathBuf);

impl HistoryScratch {
    fn new(test: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "neoshell-app-test-{}-sealed-{}",
            std::process::id(),
            test
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        HistoryScratch(dir)
    }

    fn file(&self) -> Arc<HistoryFile> {
        Arc::new(HistoryFile::at(&self.0))
    }

    /// Every name in the directory, sorted.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for HistoryScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Seal `records` and write them, as a paced flush does.
fn seal_to_disk(file: &Arc<HistoryFile>, records: &[CmdRecord]) {
    HistoryFile::snapshot(file, history_vault(), records, false, false)
        .expect("seal")
        .run()
        .expect("write");
}

#[test]
fn sealed_history_is_private_opaque_and_keeps_the_newest_records() {
    let s = HistoryScratch::new("roundtrip");
    let file = s.file();
    let list: Vec<CmdRecord> = (0..HISTORY_MAX as u64 + 20)
        .map(|i| record(&format!("mysql -phunter{}", i), 1_700_000_000 + i))
        .collect();
    seal_to_disk(&file, &list);

    // Neither base64 nor compact JSON ever holds a space.
    let raw = std::fs::read_to_string(&file.sealed).expect("sealed file");
    assert!(
        !raw.contains("mysql -p"),
        "command lines must not reach disk in the clear"
    );
    assert!(serde_json::from_str::<crate::storage::EncryptedBlob>(&raw).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file.sealed)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "history.enc must be owner-only");
    }
    assert_eq!(s.names(), ["history.enc"], "no staging file left behind");

    let load = file.load(history_vault());
    assert!(load.writable && !load.legacy_found);
    let loaded = load.records;
    assert_eq!(loaded.len(), HISTORY_MAX, "capped on the way out");
    assert_eq!(
        loaded.first().map(|r| r.cmd.as_str()),
        Some("mysql -phunter20"),
        "oldest dropped"
    );
    let last = loaded.last().expect("non-empty");
    assert_eq!(last.cmd, format!("mysql -phunter{}", HISTORY_MAX + 19));
    assert_eq!(last.host, "web");
    assert_eq!(last.timestamp, 1_700_000_000 + HISTORY_MAX as u64 + 19);
}

#[test]
fn a_locked_vault_neither_reads_nor_moves_any_history_file() {
    let s = HistoryScratch::new("locked");
    let file = s.file();
    seal_to_disk(&file, &[record("uptime", 1)]);
    let legacy = serde_json::to_vec(&[record("export TOKEN=abc", 2)]).expect("json");
    crate::storage::write_private(&file.legacy, &legacy).expect("legacy");
    let sealed = std::fs::read(&file.sealed).expect("sealed file");

    // Never unlocked: the key is not in memory.
    let locked = ConnectionStore::with_vault_path(s.0.join("vault.json"));
    let load = file.load(&locked);
    assert!(load.records.is_empty(), "nothing is read before the unlock");
    assert!(!load.writable && !load.legacy_found);
    assert!(HistoryFile::snapshot(&file, &locked, &[record("ls", 3)], false, false).is_err());

    // Locked is not damaged: both files are still there, untouched.
    assert_eq!(std::fs::read(&file.sealed).expect("sealed file"), sealed);
    assert_eq!(std::fs::read(&file.legacy).expect("legacy file"), legacy);
    assert_eq!(s.names(), ["history.enc", "history.json"]);
}

#[test]
fn unreadable_sealed_history_is_set_aside_never_written_over() {
    let s = HistoryScratch::new("unreadable");
    let file = s.file();
    let aside = s.0.join("history.enc.unreadable");

    // Tampered: one byte of real ciphertext changed.
    seal_to_disk(&file, &[record("uptime", 1)]);
    let mut blob: crate::storage::EncryptedBlob =
        serde_json::from_slice(&std::fs::read(&file.sealed).expect("sealed")).expect("blob");
    let flipped = if blob.data.starts_with('A') { "B" } else { "A" };
    blob.data.replace_range(..1, flipped);
    let tampered = serde_json::to_vec(&blob).expect("json");
    crate::storage::write_private(&file.sealed, &tampered).expect("write");

    let load = file.load(history_vault());
    assert!(load.records.is_empty());
    assert!(load.writable, "the path is free once the old file is aside");
    assert_eq!(std::fs::read(&aside).expect("set aside"), tampered);
    assert!(!file.sealed.exists());

    // Malformed: a nonce of the wrong length, which must come back as an
    // error rather than a panic in the cipher. It goes beside the first
    // one, not over it.
    let junk = br#"{"nonce":"AAAA","data":"AAAA"}"#;
    crate::storage::write_private(&file.sealed, junk).expect("write");
    assert!(file.load(history_vault()).writable);
    assert_eq!(std::fs::read(&aside).expect("first one kept"), tampered);
    assert_eq!(
        std::fs::read(s.0.join("history.enc.unreadable.1")).expect("set aside"),
        junk
    );

    // The next write starts a fresh file beside them.
    seal_to_disk(&file, &[record("ls", 2)]);
    assert_eq!(file.load(history_vault()).records, vec![record("ls", 2)]);
    assert_eq!(
        s.names(),
        [
            "history.enc",
            "history.enc.unreadable",
            "history.enc.unreadable.1"
        ]
    );
}

#[test]
fn cleartext_history_is_imported_once_then_scrubbed_away() {
    let s = HistoryScratch::new("legacy");
    let file = s.file();
    // What a build before the sealed history left behind.
    let old = [record("export TOKEN=abc", 100), record("uptime", 300)];
    crate::storage::write_private(&file.legacy, &serde_json::to_vec(&old).expect("json"))
        .expect("legacy");
    seal_to_disk(&file, &[record("ls", 200)]);

    let merged = vec![
        record("export TOKEN=abc", 100),
        record("ls", 200),
        record("uptime", 300),
    ];
    let load = file.load(history_vault());
    assert!(load.writable && load.legacy_found);
    assert_eq!(load.records, merged, "merged, oldest first");

    // The write `unlock_history` sends off.
    HistoryFile::snapshot(&file, history_vault(), &load.records, false, true)
        .expect("seal")
        .run()
        .expect("write");
    assert_eq!(s.names(), ["history.enc"], "the cleartext file is gone");
    let raw = std::fs::read_to_string(&file.sealed).expect("sealed");
    assert!(!raw.contains("TOKEN="));

    let again = file.load(history_vault());
    assert!(!again.legacy_found, "one-shot");
    assert_eq!(again.records, merged);
}

#[cfg(unix)]
#[test]
fn retiring_the_cleartext_file_never_writes_through_a_link() {
    let s = HistoryScratch::new("link");
    let file = s.file();
    let target = s.0.join("elsewhere.txt");
    std::fs::write(&target, b"not ours").expect("target");
    std::os::unix::fs::symlink(&target, &file.legacy).expect("symlink");
    retire_legacy_history(&file.legacy).expect("retire");
    assert!(
        std::fs::symlink_metadata(&file.legacy).is_err(),
        "the link is gone"
    );
    assert_eq!(std::fs::read(&target).expect("target"), b"not ours");
}

#[test]
fn an_interrupted_import_does_not_duplicate_records() {
    let s = HistoryScratch::new("reimport");
    let file = s.file();
    let both = vec![record("ls", 100), record("uptime", 200)];
    // The sealed write landed; the cleartext file was never removed.
    seal_to_disk(&file, &both);
    crate::storage::write_private(&file.legacy, &serde_json::to_vec(&both).expect("json"))
        .expect("legacy");
    let load = file.load(history_vault());
    assert!(load.legacy_found);
    assert_eq!(load.records, both);
}

#[test]
fn a_flush_that_runs_late_cannot_undo_a_clear() {
    let s = HistoryScratch::new("order");
    let file = s.file();
    let flush = HistoryFile::snapshot(
        &file,
        history_vault(),
        &[record("ls", 1), record("mysql -phunter2", 2)],
        false,
        false,
    )
    .expect("seal");
    let clear = HistoryFile::snapshot(&file, history_vault(), &[], true, true).expect("seal");
    // The blocking pool runs them in whatever order it likes.
    clear.run().expect("write");
    flush
        .run()
        .expect("a stale snapshot is dropped, not an error");
    assert!(file.load(history_vault()).records.is_empty());
}

#[test]
fn the_unlock_time_load_waits_for_a_write_still_in_flight() {
    let s = HistoryScratch::new("settle");
    let file = s.file();
    let job = HistoryFile::snapshot(&file, history_vault(), &[record("ls", 1)], false, false)
        .expect("seal");
    assert!(
        !file.wait_settled(Duration::from_millis(20)),
        "the write is still out"
    );
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        job.run()
    });
    // Blocks until the write lands, then reads what it wrote.
    let load = file.load(history_vault());
    writer.join().expect("writer thread").expect("write");
    assert!(load.writable);
    assert_eq!(load.records, vec![record("ls", 1)]);

    // A snapshot dropped without running settles too.
    drop(HistoryFile::snapshot(&file, history_vault(), &[], false, false).expect("seal"));
    assert!(file.wait_settled(Duration::ZERO));
}

#[test]
fn locking_wipes_the_history_and_seals_what_disk_has_not_seen() {
    let s = HistoryScratch::new("lock");
    let file = s.file();
    let typed = vec![record("ls", 1), record("mysql -phunter2", 2)];
    let mut records = typed.clone();
    let mut sync = HistorySync {
        dirty: true,
        loaded: true,
        flushed_at: None,
        ..HistorySync::default()
    };

    let job = lock_history(&file, history_vault(), &mut records, &mut sync);
    assert!(records.is_empty(), "no record survives the lock in memory");
    assert!(!sync.dirty && !sync.loaded);
    let much_later = std::time::Instant::now() + Duration::from_secs(3600);
    assert!(
        !history_flush_due(&sync, much_later),
        "nothing is written while locked"
    );
    // The unsaved records were sealed before the key went, not lost.
    job.expect("unsaved records are sealed")
        .run()
        .expect("write");
    assert_eq!(file.load(history_vault()).records, typed);

    // Nothing unsaved: nothing to write, and still wiped.
    let mut records = typed.clone();
    let mut sync = HistorySync {
        dirty: false,
        loaded: true,
        flushed_at: None,
        ..HistorySync::default()
    };
    assert!(lock_history(&file, history_vault(), &mut records, &mut sync).is_none());
    assert!(records.is_empty());

    // Never loaded: wiped, and never written over a file it did not see.
    let mut records = typed;
    let mut sync = HistorySync {
        dirty: true,
        loaded: false,
        flushed_at: None,
        ..HistorySync::default()
    };
    assert!(lock_history(&file, history_vault(), &mut records, &mut sync).is_none());
    assert!(records.is_empty());
}

#[test]
fn only_a_clear_writes_before_the_file_was_loaded() {
    let unloaded = HistorySync::default();
    assert!(
        !history_write_allowed(&unloaded, false),
        "would write over unseen records"
    );
    assert!(
        history_write_allowed(&unloaded, true),
        "a clear replaces them on purpose"
    );
    let loaded = HistorySync {
        loaded: true,
        ..HistorySync::default()
    };
    assert!(history_write_allowed(&loaded, false));
    assert!(history_write_allowed(&loaded, true));
}

#[test]
fn unlocking_hands_the_history_load_to_a_blocking_thread() {
    let s = HistoryScratch::new("offthread");
    let file = s.file();
    // The lock's write, still on its way to disk.
    let write = HistoryFile::snapshot(&file, history_vault(), &[record("ls", 1)], false, false)
        .expect("seal");
    let mut sync = HistorySync::default();
    let started = std::time::Instant::now();
    let (seq, load) = start_history_load(&file, shared_history_vault().clone(), &mut sync);
    // What `update` runs. It used to wait right here, for as long as
    // HISTORY_SETTLE_WAIT, with the window frozen.
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the UI thread waited for the write"
    );
    assert_eq!(
        sync.pending_load,
        Some(PendingLoad {
            seq,
            cleared: false
        })
    );
    // The blocking thread waits instead, then reads what the write left.
    let loader = std::thread::spawn(load);
    std::thread::sleep(Duration::from_millis(100));
    assert!(!loader.is_finished(), "read before the write landed");
    write.run().expect("write");
    let load = loader.join().expect("loader thread");
    assert!(load.writable && !load.unsettled);
    assert_eq!(load.records, vec![record("ls", 1)]);
}

#[test]
fn commands_typed_while_the_history_loads_are_kept_after_the_saved_ones() {
    let s = HistoryScratch::new("typed");
    let mut sync = HistorySync::default();
    let (seq, _) = start_history_load(&s.file(), shared_history_vault().clone(), &mut sync);
    // Typed after the unlock, before the load came back.
    let mut records = vec![record("uptime", 200)];
    sync.dirty = true;
    let saved = HistoryLoad {
        records: vec![record("ls", 100)],
        writable: true,
        ..HistoryLoad::default()
    };
    let landed = land_history_load(&mut records, &mut sync, seq, saved).expect("wanted");
    assert_eq!(
        landed,
        LoadLanded {
            import_legacy: false,
            warning: None
        }
    );
    assert_eq!(records, vec![record("ls", 100), record("uptime", 200)]);
    assert!(sync.loaded, "writes may go out now");
    assert!(sync.dirty, "the typed line is not on disk yet");
    assert_eq!(sync.pending_load, None);

    // Nothing typed meanwhile: nothing new to write, but an imported
    // cleartext file is sealed at once.
    let (seq, _) = start_history_load(&s.file(), shared_history_vault().clone(), &mut sync);
    let mut records = Vec::new();
    let saved = HistoryLoad {
        records: vec![record("ls", 100)],
        writable: true,
        legacy_found: true,
        ..HistoryLoad::default()
    };
    let landed = land_history_load(&mut records, &mut sync, seq, saved).expect("wanted");
    assert!(landed.import_legacy);
    assert!(!sync.dirty);
}

#[test]
fn a_load_overtaken_by_a_lock_or_a_later_unlock_never_lands() {
    let s = HistoryScratch::new("stale");
    let file = s.file();
    let vault = shared_history_vault();
    let saved = || HistoryLoad {
        records: vec![record("mysql -phunter2", 1)],
        writable: true,
        ..HistoryLoad::default()
    };

    // Locked before the load came back.
    let mut sync = HistorySync::default();
    let (seq, _) = start_history_load(&file, vault.clone(), &mut sync);
    let mut records = vec![record("whoami", 5)];
    sync.dirty = true;
    let locks = file.locks.load(Ordering::SeqCst);
    assert!(
        lock_history(&file, vault, &mut records, &mut sync).is_none(),
        "never loaded: nothing is written"
    );
    assert_eq!(file.locks.load(Ordering::SeqCst), locks + 1);
    assert_eq!(
        land_history_load(&mut records, &mut sync, seq, saved()),
        None
    );
    assert!(records.is_empty(), "nothing comes back under the lock");
    assert!(!sync.loaded && !sync.dirty);

    // Two unlocks in a row: only the second load lands.
    let (first, _) = start_history_load(&file, vault.clone(), &mut sync);
    let (second, _) = start_history_load(&file, vault.clone(), &mut sync);
    assert_eq!(
        land_history_load(&mut records, &mut sync, first, saved()),
        None
    );
    assert!(land_history_load(&mut records, &mut sync, second, saved()).is_some());
    assert_eq!(records, vec![record("mysql -phunter2", 1)]);
    // Loading again what memory already holds does not double it.
    let (third, _) = start_history_load(&file, vault.clone(), &mut sync);
    assert!(land_history_load(&mut records, &mut sync, third, saved()).is_some());
    assert_eq!(records, vec![record("mysql -phunter2", 1)]);
}

#[test]
fn a_clear_while_the_history_loads_is_not_undone_when_it_lands() {
    let s = HistoryScratch::new("clearload");
    let mut sync = HistorySync::default();
    let (seq, _) = start_history_load(&s.file(), shared_history_vault().clone(), &mut sync);
    let mut records = vec![record("ls", 10)];
    clear_history(&mut records, &mut sync);
    assert!(records.is_empty() && !sync.dirty);
    records.push(record("pwd", 20));
    sync.dirty = true;
    // Read before the clear reached the disk, a cleartext import with it.
    let stale = HistoryLoad {
        records: vec![record("mysql -phunter2", 1)],
        writable: true,
        legacy_found: true,
        ..HistoryLoad::default()
    };
    let landed = land_history_load(&mut records, &mut sync, seq, stale).expect("wanted");
    assert_eq!(records, vec![record("pwd", 20)]);
    assert!(!landed.import_legacy, "the clear's own write retires it");
    assert!(sync.loaded && sync.dirty);
}

#[test]
fn history_that_cannot_be_saved_is_said_not_only_logged() {
    let s = HistoryScratch::new("stuck");
    let file = s.file();
    seal_to_disk(&file, &[record("ls", 1)]);
    // A write that does not land in time.
    let stuck = HistoryFile::snapshot(
        &file,
        history_vault(),
        &[record("ls", 1), record("pwd", 2)],
        false,
        false,
    )
    .expect("seal");
    let load = file.load_within(history_vault(), Duration::from_millis(20));
    assert!(!load.writable && load.unsettled);
    assert_eq!(
        load.records,
        vec![record("ls", 1)],
        "what is there still shows"
    );
    drop(stuck);

    let mut sync = HistorySync::default();
    let (seq, _) = start_history_load(&file, shared_history_vault().clone(), &mut sync);
    let landed = land_history_load(&mut Vec::new(), &mut sync, seq, load).expect("wanted");
    assert_eq!(landed.warning, Some("history.warn.unsettled"));
    assert!(!sync.loaded, "nothing is written over the file");

    // Unreadable, and not moved aside either.
    let (seq, _) = start_history_load(&file, shared_history_vault().clone(), &mut sync);
    let landed = land_history_load(&mut Vec::new(), &mut sync, seq, HistoryLoad::default());
    assert_eq!(
        landed.and_then(|l| l.warning),
        Some("history.warn.unreadable")
    );
    for key in [
        "history.warn.title",
        "history.warn.unsettled",
        "history.warn.unreadable",
    ] {
        assert_ne!(i18n::t(key), "???", "{key}");
    }
}

#[test]
fn a_lock_while_the_history_loads_is_no_reason_to_set_the_file_aside() {
    let s = HistoryScratch::new("lockmid");
    let file = s.file();
    // A vault of its own: this test locks it.
    let vault = Arc::new(ConnectionStore::with_vault_path(s.0.join("vault.json")));
    vault
        .set_master_password("history lock test")
        .expect("vault");
    HistoryFile::snapshot(&file, &vault, &[record("ls", 1)], false, false)
        .expect("seal")
        .run()
        .expect("write");
    let sealed = std::fs::read(&file.sealed).expect("sealed file");
    // A write still out keeps the load waiting, past its check that the
    // vault is open...
    let flush =
        HistoryFile::snapshot(&file, &vault, &[record("ls", 1)], false, false).expect("seal");
    let mut sync = HistorySync::default();
    let (seq, load) = start_history_load(&file, vault.clone(), &mut sync);
    let loader = std::thread::spawn(load);
    std::thread::sleep(Duration::from_millis(100));
    // ...while the lock lands, and the key goes.
    let mut records = Vec::new();
    assert!(lock_history(&file, &vault, &mut records, &mut sync).is_none());
    vault.lock();
    drop(flush);
    let load = loader.join().expect("loader thread");
    assert!(!load.writable && load.records.is_empty());
    assert_eq!(
        std::fs::read(&file.sealed).expect("left in place"),
        sealed,
        "a file that only lacked the key was set aside as damaged"
    );
    assert!(!s.0.join("history.enc.unreadable").exists());
    assert_eq!(land_history_load(&mut records, &mut sync, seq, load), None);
}

#[test]
fn a_notice_title_goes_with_its_own_message_only() {
    let note = i18n::tf("sftp.err.skipped_names", &[("count", "3")]);
    let bound = Some((fingerprint(&note), "notice.skipped_title"));
    assert_eq!(error_dialog_title(bound, &note), "notice.skipped_title");
    // An error put up afterwards, by any path, is titled as ever.
    assert_eq!(error_dialog_title(bound, "Connection refused"), "err.title");
    assert_eq!(error_dialog_title(None, &note), "err.title");
}

#[test]
fn a_parked_session_gets_one_reconnect_per_press() {
    let parked = i18n::t("exec.err.needs_reconnect");
    assert!(exec_parked(parked));
    assert!(!exec_parked("Failed to open exec channel: timed out"));
    let mut m = ParkedMonitors::default();
    assert!(m.park("s1"), "the first failure parks it");
    assert!(!m.park("s1"), "the next ticks add nothing");
    assert!(m.begin_resume("s1"), "the press sends the reconnect");
    assert!(
        !m.begin_resume("s1"),
        "a second press while it is out sends nothing"
    );
    assert!(!m.park("s1"));
    assert_eq!(
        m.get("s1").map(|p| p.resuming),
        Some(true),
        "a tick failing meanwhile does not re-arm the button"
    );
    // Dismissed, or a wrong code: still parked, the button back, the
    // reason on the panel.
    assert!(!m.finish_resume("s1", Err("no answer".into())));
    assert_eq!(
        m.get("s1"),
        Some(&ParkedMonitor {
            resuming: false,
            error: Some("no answer".into())
        })
    );
    assert!(m.begin_resume("s1"));
    assert_eq!(m.get("s1").and_then(|p| p.error.clone()), None);
    assert!(m.finish_resume("s1", Ok(())), "re-opened");
    assert!(m.get("s1").is_none());
    assert!(!m.begin_resume("s1"), "nothing parked, nothing sent");
    // Data from a fetch, or the session going, clears it as well.
    m.park("s2");
    m.unpark("s2");
    assert!(m.get("s2").is_none());
    for key in [
        "monitor.parked",
        "monitor.reconnect",
        "monitor.reconnecting",
    ] {
        assert_ne!(i18n::t(key), "???", "{key}");
    }
}

#[test]
fn a_skipped_items_report_is_a_completion_to_mention_not_a_failure() {
    let note = i18n::tf("sftp.err.skipped_names", &[("count", "3")]);
    assert_eq!(op_end(Err(note.clone())), OpEnd::Skipped(note));
    assert_eq!(op_end(Ok(())), OpEnd::Quiet);
    assert_eq!(op_end(Err(TRANSFER_CANCELLED.to_string())), OpEnd::Quiet);
    let failed = i18n::tf(
        "sftp.err.delete",
        &[("path", "/srv/a"), ("err", "permission denied")],
    );
    assert_eq!(op_end(Err(failed.clone())), OpEnd::Failed(failed));
    assert!(is_skipped_report(&i18n::tf(
        "sftp.err.skipped_names",
        &[("count", "12")]
    )));
    for other in [
        i18n::t("sftp.err.skipped_names").to_string(),
        i18n::tf("sftp.err.skipped_names", &[("count", "x")]),
        format!(
            "Failed to list '/srv': {}",
            i18n::tf("sftp.err.skipped_names", &[("count", "2")])
        ),
    ] {
        assert!(!is_skipped_report(&other), "{other}");
    }
    assert_ne!(i18n::t("notice.skipped_title"), "???");
}

#[test]
fn paced_history_writes_go_out_at_most_once_a_minute() {
    assert_eq!(HISTORY_FLUSH_INTERVAL, Duration::from_secs(60));
    let t0 = std::time::Instant::now();
    let fresh = HistorySync {
        dirty: true,
        loaded: true,
        flushed_at: None,
        ..HistorySync::default()
    };
    assert!(
        history_flush_due(&fresh, t0),
        "the first write of a session goes at once"
    );

    let sync = HistorySync {
        flushed_at: Some(t0),
        ..fresh
    };
    // The old 3 s tick wrote at every one of these.
    for secs in [0, 3, 6, 30, 59] {
        assert!(
            !history_flush_due(&sync, t0 + Duration::from_secs(secs)),
            "{secs}s after a write"
        );
    }
    assert!(history_flush_due(&sync, t0 + Duration::from_secs(60)));
    assert!(history_flush_due(&sync, t0 + Duration::from_secs(61)));
    assert!(history_flush_due(&sync, t0 + Duration::from_secs(86_400)));
    if let Some(before) = t0.checked_sub(Duration::from_secs(1)) {
        assert!(
            !history_flush_due(&sync, before),
            "a clock read before the write"
        );
    }

    // Nothing new, or not loaded since the unlock: never.
    let later = t0 + Duration::from_secs(600);
    assert!(!history_flush_due(
        &HistorySync {
            dirty: false,
            ..sync
        },
        later
    ));
    assert!(!history_flush_due(
        &HistorySync {
            loaded: false,
            ..sync
        },
        later
    ));
}

// ---- terminal renderer colours -------------------------------------

fn styled(
    fg: crate::terminal::Color,
    bg: crate::terminal::Color,
    inverse: bool,
) -> crate::terminal::CellStyle {
    crate::terminal::CellStyle {
        fg,
        bg,
        inverse,
        ..Default::default()
    }
}

#[test]
fn default_cells_paint_the_theme_colours_and_no_background_block() {
    let plain = crate::terminal::CellStyle::default();
    for (name, preset) in theme_config::PRESETS {
        let (fg, bg) = (preset.terminal_fg.to_color(), preset.terminal_bg.to_color());
        // Before: a #1A1B2E fill under every glyph (it is not BG_PRIMARY
        // any more), and #E2E8F0 text whatever the theme said.
        assert_eq!(cell_paint(&plain, fg, bg), (None, fg), "{name}");
    }
}

#[test]
fn reverse_video_swaps_the_resolved_theme_colours() {
    let light = theme_config::preset_by_name("Solarized Light").expect("preset");
    let (fg, bg) = (light.terminal_fg.to_color(), light.terminal_bg.to_color());
    let inverse = crate::terminal::CellStyle {
        inverse: true,
        ..Default::default()
    };
    assert_eq!(cell_paint(&inverse, fg, bg), (Some(fg), bg));
}

#[test]
fn explicit_cell_colours_are_painted_as_set() {
    use crate::terminal::{Color as Rgb, DEFAULT_BG, DEFAULT_FG};
    let (red, blue) = (Rgb::rgb(205, 49, 49), Rgb::rgb(36, 114, 200));
    let (ired, iblue) = (cell_color_to_iced(red), cell_color_to_iced(blue));
    let (fg, bg) = (Color::from_rgb8(1, 2, 3), Color::from_rgb8(4, 5, 6));
    assert_eq!(
        cell_paint(&styled(red, blue, false), fg, bg),
        (Some(iblue), ired)
    );
    assert_eq!(
        cell_paint(&styled(red, blue, true), fg, bg),
        (Some(ired), iblue)
    );
    // One side explicit, one default: only the default side follows the theme.
    assert_eq!(
        cell_paint(&styled(red, DEFAULT_BG, false), fg, bg),
        (None, ired)
    );
    assert_eq!(
        cell_paint(&styled(DEFAULT_FG, blue, false), fg, bg),
        (Some(iblue), fg)
    );
    assert_eq!(
        cell_paint(&styled(red, DEFAULT_BG, true), fg, bg),
        (Some(ired), bg)
    );
    assert_eq!(
        cell_paint(&styled(DEFAULT_FG, blue, true), fg, bg),
        (Some(fg), iblue)
    );
}

#[test]
fn a_terminal_colour_edit_changes_the_canvas_cache_key() {
    let (bg, fg) = (
        Color::from_rgb8(26, 27, 46),
        Color::from_rgb8(226, 232, 240),
    );
    assert_eq!(theme_colors_key(bg, fg), theme_colors_key(bg, fg));
    assert_ne!(
        theme_colors_key(bg, fg),
        theme_colors_key(Color::from_rgb8(26, 27, 47), fg)
    );
    assert_ne!(
        theme_colors_key(bg, fg),
        theme_colors_key(bg, Color::from_rgb8(226, 232, 241))
    );
    assert_ne!(
        theme_colors_key(bg, fg),
        theme_colors_key(fg, bg),
        "not symmetric"
    );
    // Never the fresh state's 0, so the first frame is always painted.
    assert_ne!(theme_colors_key(Color::BLACK, Color::BLACK), 0);
}

#[test]
fn blank_cells_are_judged_by_the_default_background_sentinel() {
    use crate::terminal::{Cell, Color as Rgb};
    let blank = Cell::default();
    let nul = Cell {
        c: '\0',
        ..Cell::default()
    };
    assert!(is_blank_cell(&blank) && is_blank_cell(&nul));
    assert!(is_row_empty(&[blank.clone(), nul]));

    let mut coloured = Cell::default();
    coloured.style.bg = Rgb::rgb(1, 2, 3);
    let mut inverse = Cell::default();
    inverse.style.inverse = true;
    let glyph = Cell {
        c: 'x',
        ..Cell::default()
    };
    for cell in [&coloured, &inverse, &glyph] {
        assert!(!is_blank_cell(cell), "{cell:?}");
    }
    assert!(!is_row_empty(&[blank, glyph]));
}

#[test]
fn format_ago_picks_the_largest_whole_unit() {
    assert_eq!(format_ago(0), "0s");
    assert_eq!(format_ago(59), "59s");
    assert_eq!(format_ago(60), "1m");
    assert_eq!(format_ago(3599), "59m");
    assert_eq!(format_ago(3600), "1h");
    assert_eq!(format_ago(86_399), "23h");
    assert_eq!(format_ago(86_400 * 3), "3d");
}

#[test]
fn host_from_title_strips_user_port_and_status() {
    assert_eq!(host_from_title("root@10.0.0.7:22"), "10.0.0.7");
    assert_eq!(host_from_title("deploy@web.example.com:2222 [Reconnecting...1]"), "web.example.com");
    assert_eq!(host_from_title("me@::1:22"), "::1");
}

#[test]
fn octal_modes_are_one_to_four_octal_digits() {
    assert_eq!(parse_octal_mode("755"), Some(0o755));
    assert_eq!(parse_octal_mode(" 0644 "), Some(0o644));
    assert_eq!(parse_octal_mode("4755"), Some(0o4755));
    assert_eq!(parse_octal_mode("7777"), Some(0o7777));
    for bad in ["", "8", "0o755", "75a", "-755", "17777", "rwxr-xr-x"] {
        assert_eq!(parse_octal_mode(bad), None, "{bad:?} must not parse");
    }
}

#[test]
fn ls_mode_strings_prefill_the_chmod_dialog() {
    assert_eq!(mode_from_permissions("drwxr-xr-x"), Some(0o755));
    assert_eq!(mode_from_permissions("-rw-r--r--"), Some(0o644));
    assert_eq!(mode_from_permissions("-rwsr-xr-x"), Some(0o4755));
    assert_eq!(mode_from_permissions("drwxrwsr-x"), Some(0o2775));
    assert_eq!(mode_from_permissions("drwxrwxrwt"), Some(0o1777));
    assert_eq!(mode_from_permissions("-rwSr--r-T"), Some(0o5644));
    // ACL / SELinux markers after the ten mode characters are ignored.
    assert_eq!(mode_from_permissions("-rw-r-----+"), Some(0o640));
    assert_eq!(mode_from_permissions(""), None);
    assert_eq!(mode_from_permissions("total"), None);
    assert_eq!(mode_from_permissions("-rwxq-x---"), None);
}

#[test]
fn remote_names_must_be_one_path_component() {
    // Exactly as typed: spaces at the ends are part of a name.
    assert_eq!(valid_remote_name("  logs  ").as_deref(), Some("  logs  "));
    assert_eq!(valid_remote_name("my file.txt").as_deref(), Some("my file.txt"));
    for bad in ["", "   ", ".", "..", "a/b", "/etc", "../x", "a\0b", "a\nb"] {
        assert_eq!(valid_remote_name(bad), None, "{bad:?} must be refused");
    }
    assert_eq!(join_remote_path("/var/www", "site"), "/var/www/site");
    assert_eq!(join_remote_path("/var/www/", "site"), "/var/www/site");
    assert_eq!(join_remote_path("/", "etc"), "/etc");
}

#[test]
fn ports_sort_by_column_and_flip_direction() {
    use crate::ssh::PortInfo;
    let port = |proto: &str, addr: &str, port: u16, pid: Option<u32>, process: &str| PortInfo {
        proto: proto.into(),
        local_addr: addr.into(),
        port,
        pid,
        process: process.into(),
    };
    let mut ports = vec![
        port("tcp", "0.0.0.0", 443, Some(900), "nginx"),
        port("udp", "127.0.0.1", 53, None, ""),
        port("tcp", "127.0.0.1", 22, Some(12), "sshd"),
    ];
    sort_ports(&mut ports, PortSort::Port, false);
    assert_eq!(ports.iter().map(|p| p.port).collect::<Vec<_>>(), vec![22, 53, 443]);
    sort_ports(&mut ports, PortSort::Port, true);
    assert_eq!(ports.iter().map(|p| p.port).collect::<Vec<_>>(), vec![443, 53, 22]);
    // No pid (an unprivileged view) sorts before any known one.
    sort_ports(&mut ports, PortSort::Pid, false);
    assert_eq!(ports.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![None, Some(12), Some(900)]);
    sort_ports(&mut ports, PortSort::Process, false);
    assert_eq!(ports.iter().map(|p| p.process.as_str()).collect::<Vec<_>>(), vec!["", "nginx", "sshd"]);
}

/// Mouse reports carry 1-based cells: one off and a click lands on the
/// wrong row. Pixel -> cell -> wire, through the terminal's own encoder.
#[test]
fn mouse_reports_use_one_based_cells_from_the_pane_origin() {
    let origin = (SIDEBAR_W, 30.0 + 34.0);
    let font = 13.0;
    let (cw, ch) = (font * 0.6, font * 1.2);
    // Inside the third column of the first row.
    let (x, y) = (origin.0 + cw * 2.0 + 1.0, origin.1 + 1.0);
    let cell = grid_cell_at(x, y, origin, font, (80, 24), false);
    assert_eq!(cell, Some((3, 1)));

    let mut grid = TerminalGrid::new(80, 24);
    grid.write(b"\x1b[?1000h\x1b[?1006h");
    assert_eq!(grid.mouse_mode(), MouseMode::Click);
    let (col, row) = cell.expect("inside");
    assert_eq!(
        grid.encode_mouse(MouseButton::Left, col, row, true).as_deref(),
        Some(&b"\x1b[<0;3;1M"[..])
    );

    // Past the last row / column: not reported, unless clamped (a drag
    // or release that left the pane).
    let below = origin.1 + ch * 30.0;
    assert_eq!(grid_cell_at(x, below, origin, font, (80, 24), false), None);
    assert_eq!(grid_cell_at(x, below, origin, font, (80, 24), true), Some((3, 24)));
    assert_eq!(grid_cell_at(0.0, 0.0, origin, font, (80, 24), false), None);
    assert_eq!(grid_cell_at(0.0, 0.0, origin, font, (80, 24), true), Some((1, 1)));
    assert_eq!(grid_cell_at(x, y, origin, font, (0, 0), true), None);
}

#[test]
fn second_pane_starts_past_the_middle_of_the_divider() {
    let origin = (SIDEBAR_W, 64.0);
    // Side by side, main pane 400 px wide.
    assert!(!in_second_pane((SIDEBAR_W + 399.0, 300.0), origin, 400.0, true));
    assert!(!in_second_pane((SIDEBAR_W + 400.0 + SPLIT_DIVIDER / 2.0 - 0.5, 300.0), origin, 400.0, true));
    assert!(in_second_pane((SIDEBAR_W + 400.0 + SPLIT_DIVIDER, 300.0), origin, 400.0, true));
    // Stacked, main pane 200 px tall: only y matters.
    assert!(!in_second_pane((2000.0, 64.0 + 150.0), origin, 200.0, false));
    assert!(in_second_pane((0.0, 64.0 + 210.0), origin, 200.0, false));
}

#[test]
fn remote_text_is_stripped_of_controls_and_capped() {
    assert_eq!(sanitize_remote_text("  Password:\x1b[31m  ", 50), "Password:[31m");
    assert_eq!(sanitize_remote_text("line one\nline two", 50), "line one\nline two");
    let long = "x".repeat(300);
    assert_eq!(sanitize_remote_text(&long, 10), format!("{}...", "x".repeat(10)));
}

#[test]
fn scrubbed_answers_are_gone() {
    let mut answers = vec!["hunter2".to_string(), "123456".to_string()];
    scrub_answers(&mut answers);
    assert!(answers.is_empty());
}

#[test]
fn a_colour_scheme_keeps_the_users_font_sizes() {
    use crate::ui::theme_config::{preset_by_name, preset_names, ThemeConfig};
    let mut mine = ThemeConfig::default();
    mine.terminal_font_size = 17.0;
    mine.ui_font_size = 14.0;
    for name in preset_names() {
        let preset = preset_by_name(name).expect("listed preset exists");
        let applied = preset_keeping_fonts(preset.clone(), &mine);
        assert_eq!(applied.terminal_font_size, 17.0, "{name}");
        assert_eq!(applied.ui_font_size, 14.0, "{name}");
        assert_eq!(applied.ansi, preset.ansi, "{name}: ANSI table comes from the preset");
        assert_eq!(applied.accent, preset.accent, "{name}");
    }
}

/// The welcome screen's "pending import" count and ImportAllSshConfigs
/// must agree on what is already saved.
#[test]
fn ssh_config_key_mirrors_the_import_dedup() {
    use crate::sshconfig::SshHostConfig;
    let host = |alias: &str, hostname: &str| SshHostConfig {
        alias: alias.into(),
        hostname: hostname.into(),
        user: "deploy".into(),
        port: 2222,
        ..Default::default()
    };
    assert_eq!(ssh_config_key(&host("web", "10.0.0.7")).as_deref(), Some("deploy@10.0.0.7:2222"));
    // No HostName line: ssh(1) dials the alias itself.
    assert_eq!(ssh_config_key(&host("web", "")).as_deref(), Some("deploy@web:2222"));
    assert_eq!(ssh_config_key(&host("", "")), None);
}

#[test]
fn truncate_str_counts_chars_not_bytes() {
    // Shape of a real error_message: ASCII plus a translated CJK hint.
    let s = "Authentication failed (username/password) — 用户名或密码不正确";
    assert!(s.len() > s.chars().count(), "fixture must be multi-byte");
    assert!(s.chars().count() > 48);
    // 48 lands inside the CJK run — the byte slice this replaced panicked
    // on exactly this offset.
    let out = truncate_str(s, 48);
    assert_eq!(out.chars().count(), 48 + 3);
    assert!(out.ends_with("..."));
    // No ellipsis when nothing was dropped.
    assert_eq!(truncate_str(s, s.chars().count()), s);
}

// ---- UI behaviour pass -------------------------------------------

/// A challenge raised behind the lock screen (a session reconnecting) or
/// under the palette must not take the keyboard: iced's focus operation
/// unfocuses every other input, so the master password or the query
/// stopped receiving keys and Enter no longer submitted. The focus waits
/// for the modal to be on screen, and is then handed over exactly once.
#[test]
fn auth_focus_waits_until_the_modal_is_on_screen() {
    use Overlay::*;
    assert!(!auth_modal_visible(&Screen::Locked, Some(AuthPrompt)));
    assert!(!auth_modal_visible(&Screen::Setup, Some(AuthPrompt)));
    assert!(!auth_modal_visible(&Screen::Main, Some(Palette)));
    assert!(!auth_modal_visible(&Screen::Main, Some(ConfirmDelete)));
    assert!(!auth_modal_visible(&Screen::Main, None));
    assert!(auth_modal_visible(&Screen::Main, Some(AuthPrompt)));

    // Raised on the lock screen: owed, not handed over.
    let mut owed = true;
    let locked = auth_modal_visible(&Screen::Locked, Some(AuthPrompt));
    assert!(!take_owed_focus(&mut owed, locked));
    assert!(owed, "the focus is still owed once the vault is unlocked");
    // Unlocked, nothing above the modal: handed over — once.
    let shown = auth_modal_visible(&Screen::Main, Some(AuthPrompt));
    assert!(take_owed_focus(&mut owed, shown));
    assert!(
        !take_owed_focus(&mut owed, shown),
        "a focus on every poll tick would pull the cursor back to the first field"
    );
}

/// ESC used to reset these forms to empty — a half-typed connection, its
/// password included. It now only puts away a form that still reads
/// exactly as it was opened.
#[test]
fn esc_only_puts_away_a_form_nothing_was_typed_into() {
    use crate::proxy::{ProxyConfig, ProxyType};
    use crate::tunnel::{ForwardKind, ForwardRule, TunnelConfig};

    // Connection form, as `ShowForm(None)` opens it.
    let opened = ConnectionFormData {
        port: "22".into(),
        auth_type: "password".into(),
        ..Default::default()
    };
    let baseline = opened_connection_form(&opened);
    assert!(opened == baseline, "untouched: ESC closes it");
    let mut typed = opened.clone();
    typed.password = "hunter2".into();
    assert!(typed != baseline, "a typed password keeps the form open");
    let mut named = opened.clone();
    named.host = "10.0.0.7".into();
    assert!(named != baseline);
    // The baseline never holds a secret, whatever it is built from.
    let from_typed = opened_connection_form(&typed);
    assert!(from_typed.password.is_empty() && from_typed.passphrase.is_empty());

    // Proxy form: a new one, and a saved one opened with its secret.
    assert!(proxy_form_pristine(&proxy_form_for(None), None, &[]));
    let mut new_proxy = proxy_form_for(None);
    new_proxy.host = "10.0.0.9".into();
    assert!(!proxy_form_pristine(&new_proxy, None, &[]));
    let proxies = vec![ProxyConfig {
        id: "p1".into(),
        name: "jump".into(),
        proxy_type: ProxyType::SshBastion,
        host: "bastion.example".into(),
        port: 22,
        username: Some("ops".into()),
        password: Some("s3cret".into()),
        auth_type: Some("password".into()),
        private_key: None,
        passphrase: None,
    }];
    let editing = proxy_form_for(Some(&proxies[0]));
    assert!(proxy_form_pristine(&editing, Some("p1"), &proxies));
    let mut changed_pw = editing.clone();
    changed_pw.password.push('!');
    assert!(!proxy_form_pristine(&changed_pw, Some("p1"), &proxies));
    // The proxy was deleted underneath the form: it cannot be told, so
    // the form is kept.
    assert!(!proxy_form_pristine(&editing, Some("p1"), &[]));

    // Tunnel form.
    assert!(tunnel_form_pristine(&tunnel_form_for(None), None, &[]));
    let mut new_tunnel = tunnel_form_for(None);
    new_tunnel.passphrase = "keypass".into();
    assert!(!tunnel_form_pristine(&new_tunnel, None, &[]));
    let tunnels = vec![TunnelConfig {
        id: "t1".into(),
        name: "db".into(),
        ssh_host: "jump.example".into(),
        ssh_port: 22,
        username: "ops".into(),
        auth_type: "password".into(),
        password: Some("tunnelpw".into()),
        private_key: None,
        passphrase: None,
        forwards: vec![ForwardRule {
            local_port: 3000,
            remote_host: "0.0.0.0".into(),
            remote_port: 8080,
            kind: ForwardKind::Remote,
        }],
        auto_start: false,
    }];
    let editing = tunnel_form_for(Some(&tunnels[0]));
    assert!(tunnel_form_pristine(&editing, Some("t1"), &tunnels));
    let mut more_rules = editing.clone();
    more_rules.forwards_text.push_str("\n5432:127.0.0.1:5432");
    assert!(!tunnel_form_pristine(&more_rules, Some("t1"), &tunnels));

    // Snippet editor: the new-snippet fields, then a saved snippet.
    let snippets = vec![snippet("uptime")];
    assert!(snippet_form_pristine("", "", None, &snippets));
    assert!(!snippet_form_pristine("", "df -h", None, &snippets));
    assert!(snippet_form_pristine(
        "uptime",
        "uptime",
        Some("uptime"),
        &snippets
    ));
    assert!(!snippet_form_pristine(
        "uptime",
        "uptime -p",
        Some("uptime"),
        &snippets
    ));
}

/// One bar, one Cancel. Starting a transfer over one in flight replaced
/// its progress — the folder transfer ran on with no bar and nothing could
/// cancel it — and the late end of a cancelled transfer, or any unrelated
/// error, took down whatever bar was showing.
#[test]
fn a_transfer_neither_takes_over_nor_takes_down_another_ones_bar() {
    let mut bar: Option<Arc<TransferProgress>> = None;
    let folder = claim_bar(&mut bar, false).expect("the bar is free");
    // An upload started meanwhile is refused; the folder transfer keeps
    // the bar, and with it its Cancel.
    assert!(claim_bar(&mut bar, false).is_none());
    assert!(bar.as_ref().is_some_and(|p| Arc::ptr_eq(p, &folder)));
    // A drop upload still winding down after its Cancel holds the bar
    // with nothing on it.
    let mut winding_down: Option<Arc<TransferProgress>> = None;
    assert!(bar_busy(winding_down.as_ref(), true));
    assert!(claim_bar(&mut winding_down, true).is_none());
    assert!(winding_down.is_none());

    // The folder transfer is cancelled (CancelTransfer) and another one
    // starts before the folder's thread has let go...
    folder.finished.store(true, Ordering::Relaxed);
    bar = None;
    let next = claim_bar(&mut bar, false).expect("free after a Cancel");
    // ...so the folder's late end must leave the new bar alone.
    release_bar(&mut bar, &folder);
    assert!(bar.as_ref().is_some_and(|p| Arc::ptr_eq(p, &next)));
    release_bar(&mut bar, &next);
    assert!(bar.is_none());

    // A transfer that finished, its end not yet processed, is no longer
    // in the way.
    let done = claim_bar(&mut bar, false).expect("free");
    done.finished.store(true, Ordering::Relaxed);
    assert!(claim_bar(&mut bar, false).is_some());
}

/// Four row actions for every matching connection, then a cut at twelve:
/// with four or more matches the lower-ranked connections fell off the
/// list and Cmd+K could no longer reach them.
#[test]
fn every_matching_connection_stays_reachable_from_the_palette() {
    // Each name is 24 characters longer than the last, which costs it 6
    // points of fuzzy score: the matches rank apart.
    let conns = |n: usize| -> Vec<ConnectionInfo> {
        (0..n)
            .map(|i| ConnectionInfo {
                id: format!("c{i}"),
                name: format!("web{}", "x".repeat(24 * i)),
                host: "10.0.0.1".into(),
                port: 22,
                username: "root".into(),
                auth_type: "password".into(),
                group: String::new(),
                color: String::new(),
                proxy_id: None,
            })
            .collect()
    };
    let connect_ids = |items: &[PaletteItem]| -> Vec<String> {
        items
            .iter()
            .filter_map(|it| match &it.msg {
                Message::ConnectTo(id) => Some(id.clone()),
                _ => None,
            })
            .collect()
    };
    let row_action_of = |it: &PaletteItem| match &it.msg {
        Message::ShowForm(Some(id))
        | Message::TestConnectionInList(id)
        | Message::CloneConnection(id)
        | Message::DeleteConnection(id) => Some(id.clone()),
        _ => None,
    };

    let six = conns(6);
    let items = build_palette_items("web", &six, &[], &HashSet::new());
    assert!(items.len() <= PALETTE_MAX);
    assert_eq!(connect_ids(&items), ["c0", "c1", "c2", "c3", "c4", "c5"]);
    // Row actions for the best match only, right under it.
    let best = items
        .iter()
        .position(|it| matches!(&it.msg, Message::ConnectTo(id) if id == "c0"))
        .expect("best match listed");
    let actions: Vec<String> = items.iter().filter_map(row_action_of).collect();
    assert_eq!(actions, ["c0", "c0", "c0", "c0"]);
    assert!(items[best + 1..best + 5]
        .iter()
        .all(|it| row_action_of(it).as_deref() == Some("c0")));
    // No query, no row actions.
    assert!(build_palette_items("", &six, &[], &HashSet::new())
        .iter()
        .all(|it| row_action_of(it).is_none()));

    // More matches than rows: every row goes to a connection, best first.
    let items = build_palette_items("web", &conns(14), &[], &HashSet::new());
    assert_eq!(items.len(), PALETTE_MAX);
    assert_eq!(connect_ids(&items).len(), PALETTE_MAX);
    assert_eq!(connect_ids(&items)[0], "c0");
}

/// With the update banner showing, the canvas sits ~34 px below where
/// the fixed chrome puts it: a click on row 10 in vim or htop was
/// reported as row 12, and a selection started two rows off. The origin
/// now comes from where the canvas drew.
#[test]
fn the_pointer_is_measured_from_where_the_pane_drew() {
    let font = 13.0;
    let row_h = font * 1.2;
    let fixed = (SIDEBAR_W, 30.0 + 34.0);
    let banner = 34.0;
    let drawn = Rectangle {
        x: SIDEBAR_W,
        y: banner + 30.0 + 34.0,
        width: 800.0,
        height: 480.0,
    };

    // The tab and its canvas share one cell: what `draw` records, the
    // hit-test reads.
    let main_bounds = PaneBounds::default();
    assert_eq!(
        pane_origin(main_bounds.get(), fixed),
        fixed,
        "before the first frame"
    );
    main_bounds.clone().record(drawn);
    let origin = pane_origin(main_bounds.get(), fixed);
    assert_eq!(origin, (drawn.x, drawn.y));
    // The middle of row 10, first column.
    let (x, y) = (drawn.x + 2.0, drawn.y + row_h * 9.5);
    assert_eq!(
        grid_cell_at(x, y, origin, font, (80, 24), false),
        Some((1, 10))
    );
    assert_eq!(
        grid_cell_at(x, y, fixed, font, (80, 24), false),
        Some((1, 12)),
        "what the fixed chrome made of the same click"
    );

    // A stacked split: the extent the divider drag shares out is the two
    // canvases as drawn — the transfer bar under them included — but only
    // once both have drawn.
    let tab = TerminalTab {
        id: "t".into(),
        session_id: "s".into(),
        connection_id: "c".into(),
        title: "root@web:22".into(),
        terminal: Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24))),
        custom_title: None,
        split: Some(SplitPane {
            session_id: "s2".into(),
            terminal: Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24))),
            vertical: false,
            ratio: 0.5,
            bounds: PaneBounds::default(),
        }),
        focus_split: true,
        bounds: main_bounds,
        pending_session_id: String::new(),
        split_pending: None,
    };
    assert!(
        drawn_split(&tab).is_none(),
        "until the second pane has drawn"
    );
    let second = Rectangle {
        y: drawn.y + drawn.height + SPLIT_DIVIDER,
        height: 300.0,
        ..drawn
    };
    if let Some(sp) = &tab.split {
        sp.bounds.record(second);
    }
    let (main, split) = drawn_split(&tab).expect("both drawn");
    assert_eq!(main.height + split.height, 780.0);
    assert_eq!(pane_origin(Some(split), fixed), (second.x, second.y));
}

/// The ports table was cloned and sorted inside the view on every redraw
/// — every 50 ms tick. It is sorted when the data or the sort key
/// changes; the view draws it as it stands.
#[test]
fn a_header_click_resorts_the_ports_table_in_place() {
    use crate::ssh::PortInfo;
    let port = |port: u16, process: &str| PortInfo {
        proto: "tcp".into(),
        local_addr: "0.0.0.0".into(),
        port,
        pid: None,
        process: process.into(),
    };
    let mut ports = vec![port(443, "nginx"), port(22, "SSHD"), port(53, "dnsmasq")];
    let processes =
        |ports: &[PortInfo]| ports.iter().map(|p| p.process.clone()).collect::<Vec<_>>();
    let (mut sort, mut desc) = (PortSort::Port, false);

    resort_ports(&mut ports, &mut sort, &mut desc, PortSort::Process);
    assert_eq!((sort, desc), (PortSort::Process, false));
    assert_eq!(
        processes(&ports),
        ["dnsmasq", "nginx", "SSHD"],
        "case-insensitive"
    );
    resort_ports(&mut ports, &mut sort, &mut desc, PortSort::Process);
    assert!(desc, "the same column flips direction");
    assert_eq!(processes(&ports), ["SSHD", "nginx", "dnsmasq"]);
    resort_ports(&mut ports, &mut sort, &mut desc, PortSort::Port);
    assert_eq!(
        (sort, desc),
        (PortSort::Port, false),
        "a new column starts ascending"
    );
    assert_eq!(
        ports.iter().map(|p| p.port).collect::<Vec<_>>(),
        [22, 53, 443]
    );
}

/// A monitor fetch was started every 3 s whatever happened to the last
/// one. Behind a folder transfer holding the exec lock they queued up —
/// ~600 in 30 minutes, past tokio's 512 blocking threads — and new
/// connections could no longer start.
#[test]
fn a_session_has_one_fetch_out_at_a_time() {
    let mut inflight = InFlight::default();
    assert!(inflight.start("s1"));
    // A 30-minute transfer's worth of 3 s ticks adds nothing.
    for _ in 0..600 {
        assert!(!inflight.start("s1"));
    }
    assert!(inflight.contains("s1"));
    assert!(inflight.start("s2"), "another session is not held up");
    inflight.finish("s1");
    assert!(!inflight.contains("s1"));
    assert!(inflight.start("s1"), "the next tick fetches again");
    assert!(
        !inflight.start(""),
        "a tab with no session has nothing to fetch"
    );
}

/// A right-click pasted even into an application that had asked for the
/// mouse, and the middle button was never reported at all
/// (`MouseButton::Right` / `Middle` were never constructed).
#[test]
fn right_and_middle_clicks_reach_an_application_that_asked_for_the_mouse() {
    use iced::mouse::Button;
    assert_eq!(
        secondary_click(MouseButton::Right, true),
        SecondaryClick::Report
    );
    assert_eq!(
        secondary_click(MouseButton::Middle, true),
        SecondaryClick::Report
    );
    // Reporting off (or Shift held): right-click still pastes.
    assert_eq!(
        secondary_click(MouseButton::Right, false),
        SecondaryClick::Paste
    );
    assert_eq!(
        secondary_click(MouseButton::Middle, false),
        SecondaryClick::Ignore
    );

    assert_eq!(terminal_button(Button::Left), Some(MouseButton::Left));
    assert_eq!(terminal_button(Button::Middle), Some(MouseButton::Middle));
    assert_eq!(terminal_button(Button::Right), Some(MouseButton::Right));
    assert_eq!(terminal_button(Button::Back), None);

    // What the application receives, through the terminal's own encoder.
    let mut grid = TerminalGrid::new(80, 24);
    grid.write(b"\x1b[?1000h\x1b[?1006h");
    assert_eq!(
        grid.encode_mouse(MouseButton::Right, 3, 1, true).as_deref(),
        Some(&b"\x1b[<2;3;1M"[..])
    );
    assert_eq!(
        grid.encode_mouse(MouseButton::Right, 3, 1, false)
            .as_deref(),
        Some(&b"\x1b[<2;3;1m"[..])
    );
    assert_eq!(
        grid.encode_mouse(MouseButton::Middle, 3, 1, true)
            .as_deref(),
        Some(&b"\x1b[<1;3;1M"[..])
    );
}

// ---- exact names, fresh kill checks, withdrawn and unfocused sign-ins,
// ---- folded groups, Chinese connection names -------------------------

/// A co-tenant's 0-byte "project " beside the user's folder "project"
/// read the same in the file list and the confirmation. What would not
/// show is marked now; an ordinary name — a Chinese one included — is
/// left alone.
#[test]
fn visible_name_marks_what_would_not_show() {
    assert_eq!(visible_name("project"), "project");
    assert_eq!(visible_name("project "), "project·");
    assert_eq!(visible_name(" project"), "·project");
    assert_eq!(visible_name("pro  ject"), "pro··ject");
    assert_eq!(visible_name("my file.txt"), "my file.txt", "one space inside is a space");
    assert_ne!(visible_name("project "), visible_name("project"));
    // Other whitespace, controls, invisible formatting: escaped.
    assert_eq!(visible_name("pro\u{200B}ject"), "pro\\u{200b}ject");
    assert_eq!(visible_name("a\tb"), "a\\u{9}b");
    assert_eq!(visible_name("a\u{A0}b"), "a\\u{a0}b");
    assert_eq!(visible_name("a\nb"), "a\\u{a}b");
    assert_eq!(visible_name("evil\u{202E}txt.exe"), "evil\\u{202e}txt.exe");
    // A variation selector after ASCII changes nothing on screen.
    assert_eq!(visible_name("project\u{FE0F}"), "project\\u{fe0f}");
    // Chinese names, the interpunct and emoji stay as they are.
    assert_eq!(visible_name("生产 服务器"), "生产 服务器");
    assert_eq!(visible_name("张三·李四"), "张三·李四");
    assert_eq!(visible_name("❤\u{FE0F}.txt"), "❤\u{FE0F}.txt");
    // Each component of a path.
    assert_eq!(visible_path("/srv/project /a"), "/srv/project·/a");
}

/// A long name loses its middle, so the mark at its end stays in view.
#[test]
fn long_names_keep_their_marked_end() {
    use crate::terminal::display_width;
    let decoy = visible_name("quarterly_report_for_the_board_2024 ");
    let short = truncate_middle_to_width(&decoy, 16);
    assert!(display_width(&short) <= 16, "{short}");
    assert!(short.starts_with("quarter") && short.ends_with('·'), "{short}");
    let cjk = truncate_middle_to_width("年度报告终稿版本确认后归档.docx", 16);
    assert!(display_width(&cjk) <= 16, "{cjk}");
    assert!(cjk.starts_with("年度") && cjk.ends_with(".docx") && cjk.contains('…'), "{cjk}");
    assert_eq!(truncate_middle_to_width("a.txt", 16), "a.txt");
}

/// The confirmation quotes the exact name and states what the row
/// showed: a decoy file "project " reads differently from the folder
/// "project" — and that kind is what the SSH layer is told.
#[test]
fn sftp_confirmations_quote_the_exact_name_and_state_its_kind() {
    let delete = |name: &str, kind: EntryKind| ConfirmAction::SftpDelete {
        session_id: "s".into(),
        dir: "/srv".into(),
        path: join_remote_path("/srv", name),
        name: name.into(),
        kind,
        confirmed: ConfirmedEntry::from(kind),
    };
    let (decoy_q, decoy_path, decoy_marked) =
        confirm_action_text(&delete("project ", EntryKind::File));
    let (real_q, real_path, real_marked) =
        confirm_action_text(&delete("project", EntryKind::Dir));
    assert!(decoy_q.contains("“project·”"), "{decoy_q}");
    assert!(real_q.contains("“project”"), "{real_q}");
    assert_ne!(decoy_q, real_q);
    assert_eq!(decoy_path, "/srv/project·");
    assert_eq!(real_path, "/srv/project");
    assert!(decoy_marked && !real_marked, "the marks are explained when there are some");
    // The kind is stated, in either language.
    assert!(["file", "文件"].iter().any(|k| decoy_q.contains(k)), "{decoy_q}");
    assert!(["folder", "文件夹"].iter().any(|k| real_q.contains(k)), "{real_q}");
    let chmod = ConfirmAction::SftpChmod {
        session_id: "s".into(),
        dir: "/srv".into(),
        path: "/srv/run.sh".into(),
        name: "run.sh".into(),
        kind: EntryKind::File,
        confirmed: ConfirmedEntry::from(EntryKind::File),
        mode: 0o755,
    };
    let (question, subject, _) = confirm_action_text(&chmod);
    assert!(question.contains("“run.sh”") && question.contains("0755"), "{question}");
    assert!(["file", "文件"].iter().any(|k| question.contains(k)), "{question}");
    assert_eq!(subject, "/srv/run.sh");
}

/// The kill confirmation shows the process /proc has under the pid as it
/// opens — not a name `ss` parsed — and the signal goes only while that
/// is still the process: same start time.
#[test]
fn a_kill_goes_only_to_the_process_confirmed() {
    let stat = |start: &str| {
        format!(
            "4242 (nginx: worker) S 1 4242 4242 0 -1 4194624 312 0 0 0 1 2 0 0 20 0 1 0 {} \
             1000000 200 18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 3 0 0\n",
            start
        )
    };
    let first = parse_proc_identity(&stat("98765"), "nginx: worker process ").expect("a process");
    assert_eq!(first.comm, "nginx: worker");
    assert_eq!(kill_command_label(&first), "nginx: worker process");
    // It retitled itself: the same process.
    let retitled =
        parse_proc_identity(&stat("98765"), "nginx: worker process is shutting down").unwrap();
    assert!(same_process(&first, &retitled));
    // The pid changed hands: another start time, no signal.
    let reused = parse_proc_identity(&stat("123456"), "nginx: worker process").unwrap();
    assert!(!same_process(&first, &reused));
    // Gone: nothing printed.
    assert_eq!(parse_proc_identity("", ""), None);
    // A name with parentheses and spaces of its own cannot shift the fields.
    let tricky = parse_proc_identity(
        "77 (a) 1 2 (b) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5555 0 0\n",
        "",
    )
    .unwrap();
    assert_eq!(tricky.comm, "a) 1 2 (b");
    assert_eq!(tricky.start_time, "5555");
    // No command line — a kernel thread — shows as `ps` shows it.
    let kthread =
        parse_proc_identity("2 (kthreadd) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 7 0 0\n", "")
            .unwrap();
    assert_eq!(kill_command_label(&kthread), "[kthreadd]");
    // What would not show, shows.
    let hidden = parse_proc_identity(&stat("1"), "sleep 100\u{202E}fdsa").unwrap();
    assert_eq!(kill_command_label(&hidden), "sleep 100\\u{202e}fdsa");

    // A host without /proc answers through `ps`: the same check, by the
    // start time it prints.
    let ps = parse_ps_identity("Mon Sep 22 01:02:03 2026 /usr/sbin/nginx -g daemon off;\n")
        .expect("a process");
    assert_eq!(ps.start_time, "Mon Sep 22 01:02:03 2026");
    assert_eq!(kill_command_label(&ps), "/usr/sbin/nginx -g daemon off;");
    let padded = parse_ps_identity("Tue Sep  2 01:02:03 2026 sleep 100").unwrap();
    assert_eq!(padded.start_time, "Tue Sep 2 01:02:03 2026");
    let later = parse_ps_identity("Tue Sep  2 01:07:44 2026 sleep 100").unwrap();
    assert!(!same_process(&padded, &later), "the pid changed hands");
    assert_eq!(parse_ps_identity(""), None, "gone");
    assert_eq!(parse_ps_identity("ps: illegal option -- w\n"), None);
}

fn test_tab(session_id: &str, pending: &str) -> TerminalTab {
    TerminalTab {
        id: "t".into(),
        session_id: session_id.into(),
        connection_id: "c".into(),
        title: String::new(),
        terminal: Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24))),
        custom_title: None,
        split: None,
        focus_split: false,
        bounds: PaneBounds::default(),
        pending_session_id: pending.into(),
        split_pending: None,
    }
}

fn test_split(session_id: &str) -> SplitPane {
    SplitPane {
        session_id: session_id.into(),
        terminal: Arc::new(parking_lot::Mutex::new(TerminalGrid::new(80, 24))),
        vertical: true,
        ratio: 0.5,
        bounds: PaneBounds::default(),
    }
}

/// Closing a tab withdraws every sign-in it is waiting on — its connect,
/// under the id picked before the connect; its split's; a reconnect of
/// either — and no other tab's.
#[test]
fn closing_a_tab_withdraws_its_own_sign_in_challenges() {
    let mut tab = test_tab("", "sid-new");
    assert_eq!(tab_auth_sessions(&tab), ["sid-new"], "still connecting");
    tab.session_id = "sid-new".into();
    tab.pending_session_id.clear();
    tab.split_pending = Some("sid-split".into());
    assert_eq!(tab_auth_sessions(&tab), ["sid-new", "sid-split"]);
    tab.split_pending = None;
    tab.split = Some(test_split("sid-2"));
    assert_eq!(tab_auth_sessions(&tab), ["sid-new", "sid-2"]);

    let now = std::time::Instant::now();
    let mut queue: VecDeque<(&str, std::time::Instant)> =
        ["sid-2", "other", "sid-new", "other-2"].into_iter().map(|s| (s, now)).collect();
    let asking = tab_auth_sessions(&tab);
    let pick = |s: &&str| asking.iter().any(|a| a.as_str() == *s);
    let (taken, front) = take_challenges(&mut queue, pick);
    assert_eq!(taken, ["sid-2", "sid-new"]);
    assert!(front, "the one on screen was the tab's: the modal moves on");
    let left: Vec<&str> = queue.iter().map(|(s, _)| *s).collect();
    assert_eq!(left, ["other", "other-2"], "the rest stay, in order");
    let (taken, front) = take_challenges(&mut queue, pick);
    assert!(taken.is_empty() && !front);
    assert_eq!(queue.len(), 2);
}

/// A connect failing in the background takes its own tab away and
/// nothing else — every still-connecting tab used to go with it — and the
/// tab the user is on stays the active one.
#[test]
fn a_failed_connect_leaves_the_active_tab_where_it_was() {
    assert_eq!(active_after_removal(Some(2), 0, 2), Some(1), "[x, A, B] on B");
    assert_eq!(active_after_removal(Some(2), 0, 3), Some(1), "[x, A, B, C] on B, not C");
    assert_eq!(active_after_removal(Some(0), 1, 2), Some(0), "[A, x, B] on A");
    assert_eq!(active_after_removal(Some(1), 1, 2), Some(1), "on the failed one");
    assert_eq!(active_after_removal(Some(2), 2, 2), Some(1));
    assert_eq!(active_after_removal(Some(0), 0, 0), None);
    assert_eq!(active_after_removal(None, 0, 3), None);
}

/// A parked exec connection turns a folder listing into the panels'
/// "Reconnect monitoring" rather than an error dialog per listing — for
/// the focused pane's session, which the panels now show, a split's
/// included.
#[test]
fn a_parked_listing_offers_the_reconnect_for_the_focused_pane() {
    let parked = i18n::t("exec.err.needs_reconnect").to_string();
    assert!(matches!(listing_failed("sid-2", parked), Message::ExecParked(s) if s == "sid-2"));
    assert!(matches!(
        listing_failed("sid-2", "Permission denied".into()),
        Message::Error(e) if e == "Permission denied"
    ));
    let mut tab = test_tab("sid-1", "");
    tab.split = Some(test_split("sid-2"));
    assert_eq!(tab.focused_session(), "sid-1");
    tab.focus_split = true;
    assert_eq!(tab.focused_session(), "sid-2", "the panels follow the focused pane");
}

/// A sign-in challenge takes the keyboard only when the user's own click
/// asked for it; one arriving on its own — another tab reconnecting —
/// shows its modal and waits for a click.
#[test]
fn only_a_challenge_the_user_asked_for_takes_the_keyboard() {
    assert!(!challenge_may_take_focus("reconnect", false));
    assert!(!challenge_may_take_focus("reconnect", true), "never the user's click");
    assert!(challenge_may_take_focus("shell", true), "Connect");
    assert!(challenge_may_take_focus("exec", true), "Reconnect monitoring");
    assert!(!challenge_may_take_focus("shell", false));
    assert!(!challenge_may_take_focus("exec", false));
    assert!(challenge_may_take_focus("test", false));
    assert!(challenge_may_take_focus("deploy", false));
    // Not even then while keys are still arriving from somewhere else.
    let t0 = std::time::Instant::now();
    assert!(typing_recently(Some(t0), t0 + Duration::from_millis(200)));
    assert!(!typing_recently(Some(t0), t0 + AUTH_TYPING_WINDOW));
    assert!(!typing_recently(None, t0));
}

/// Keys — Enter above all — arriving in the modal's first moments were
/// typed before it appeared: the rest of a sudo password and its Enter,
/// say. They are not submitted as this server's answer.
#[test]
fn keys_typed_before_the_modal_appeared_are_no_answer() {
    let t0 = std::time::Instant::now();
    let mut shown = None;
    assert!(!auth_armed(shown, t0), "not on screen");
    note_auth_shown(&mut shown, true, t0);
    assert_eq!(shown, Some(t0));
    note_auth_shown(&mut shown, true, t0 + Duration::from_millis(40));
    assert_eq!(shown, Some(t0), "staying up does not restart it");
    assert!(!auth_armed(shown, t0 + Duration::from_millis(50)), "one poll tick in");
    assert!(!auth_armed(shown, t0 + AUTH_ARM_DELAY - Duration::from_millis(1)));
    assert!(auth_armed(shown, t0 + AUTH_ARM_DELAY));
    // Covered — by the palette, say — and uncovered: the wait starts over.
    note_auth_shown(&mut shown, false, t0 + Duration::from_secs(1));
    assert_eq!(shown, None);
    assert!(!auth_armed(shown, t0 + Duration::from_secs(2)));
    let t1 = t0 + Duration::from_secs(3);
    note_auth_shown(&mut shown, true, t1);
    assert!(!auth_armed(shown, t1 + Duration::from_millis(100)));
    assert!(auth_armed(shown, t1 + AUTH_ARM_DELAY));
}

/// `clear()` left the password's bytes in the buffer the string keeps;
/// the lock zeroes them — and the decrypted proxy and tunnel lists'.
#[test]
fn locking_zeroes_the_secrets_it_scrubs() {
    let mut conn = ConnectionFormData { password: "hunter2".into(), ..Default::default() };
    let mut proxy = ProxyFormData { passphrase: "proxypass".into(), ..Default::default() };
    let mut tunnel = TunnelFormData { password: "tunnelpw".into(), ..Default::default() };
    let buffers = [
        (conn.password.as_ptr(), conn.password.len()),
        (proxy.passphrase.as_ptr(), proxy.passphrase.len()),
        (tunnel.password.as_ptr(), tunnel.password.len()),
    ];
    scrub_form_secrets(&mut conn, &mut proxy, &mut tunnel);
    assert_eq!(conn.password.as_ptr(), buffers[0].0, "the same buffer, kept");
    for (ptr, len) in buffers {
        // SAFETY: each empty string above still owns this allocation, and
        // every byte read was written when the string was made.
        let left = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(left.iter().all(|b| *b == 0), "plaintext left behind: {left:?}");
    }

    let mut proxies = vec![crate::proxy::ProxyConfig {
        id: "p1".into(),
        name: "jump".into(),
        proxy_type: crate::proxy::ProxyType::SshBastion,
        host: "bastion.example".into(),
        port: 22,
        username: Some("ops".into()),
        password: Some("s3cret".into()),
        auth_type: Some("password".into()),
        private_key: None,
        passphrase: Some("keypass".into()),
    }];
    let mut tunnels = vec![crate::tunnel::TunnelConfig {
        id: "t1".into(),
        name: "db".into(),
        ssh_host: "jump.example".into(),
        ssh_port: 22,
        username: "ops".into(),
        auth_type: "password".into(),
        password: Some("tunnelpw".into()),
        private_key: None,
        passphrase: Some("tunnelpass".into()),
        forwards: Vec::new(),
        auto_start: false,
    }];
    scrub_list_secrets(&mut proxies, &mut tunnels);
    assert_eq!((&proxies[0].password, &proxies[0].passphrase), (&None, &None));
    assert_eq!((&tunnels[0].password, &tunnels[0].passphrase), (&None, &None));
    assert_eq!(proxies[0].host, "bastion.example", "only the secrets go");
}

fn sidebar_conn(id: &str, name: &str, group: &str) -> ConnectionInfo {
    ConnectionInfo {
        id: id.into(),
        name: name.into(),
        host: "10.0.0.1".into(),
        port: 22,
        username: "root".into(),
        auth_type: "password".into(),
        group: group.into(),
        color: String::new(),
        proxy_id: None,
    }
}

fn groups_of(names: &[&str]) -> HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

/// A `GroupsFile` over a scratch directory of its own; remove the
/// returned path's directory with `remove_scratch` when done.
fn scratch_groups(test: &str) -> (std::path::PathBuf, GroupsFile) {
    let path = scratch_history(test);
    remove_scratch(&path);
    let dir = path.parent().expect("scratch dir").to_path_buf();
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let file = GroupsFile::at(&dir);
    (path, file)
}

/// The folded groups outlive a restart — Chinese names included — sealed
/// with the vault: the file names no group, and nothing is read or sealed
/// while the vault is locked. Written atomically and owner-only, in the
/// order sealed; a damaged file folds nothing.
#[test]
fn folded_groups_survive_a_restart() {
    let (path, file) = scratch_groups("groups");
    let vault = history_vault();
    assert_eq!(file.load(vault), (HashSet::new(), false), "nothing saved: all open");
    let saved = groups_of(&["生产环境", "开发 / 测试", "", "Web"]);
    file.write(file.snapshot(vault, &saved, false).expect("seal")).expect("write");
    assert_eq!(file.load(vault), (saved.clone(), false));
    let raw = String::from_utf8_lossy(&std::fs::read(&file.sealed).expect("read")).into_owned();
    for name in ["生产环境", "开发", "Web"] {
        assert!(!raw.contains(name), "{name} on disk in the clear: {raw}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file.sealed).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // Locked: nothing is read, nothing sealed.
    let locked = ConnectionStore::with_vault_path(file.sealed.with_file_name("locked.json"));
    assert_eq!(file.load(&locked), (HashSet::new(), false));
    assert!(file.snapshot(&locked, &saved, false).is_err());
    // A snapshot that runs late never lands over a newer one.
    let older = file.snapshot(vault, &groups_of(&["old"]), false).expect("seal");
    let newer = file.snapshot(vault, &groups_of(&["new"]), false).expect("seal");
    file.write(newer).expect("write");
    file.write(older).expect("write");
    assert_eq!(file.load(vault).0, groups_of(&["new"]));
    // A damaged file folds nothing rather than failing.
    crate::storage::write_private(&file.sealed, b"{ not json").expect("write");
    assert_eq!(file.load(vault), (HashSet::new(), false));
    remove_scratch(&path);
}

/// Builds before this wrote the folded groups in the clear, and read them
/// before the vault was open. The first unlock imports that file; the
/// write that seals the import overwrites it and deletes it.
#[test]
fn cleartext_folded_groups_are_imported_then_scrubbed() {
    let (path, file) = scratch_groups("groups-legacy");
    let vault = history_vault();
    crate::storage::write_private(&file.legacy, "[\"生产环境\",\"\"]".as_bytes())
        .expect("legacy file");
    // Not before the unlock.
    let locked = ConnectionStore::with_vault_path(file.sealed.with_file_name("locked.json"));
    assert_eq!(file.load(&locked), (HashSet::new(), false));
    let (groups, legacy_found) = file.load(vault);
    assert!(legacy_found);
    assert_eq!(groups, groups_of(&["生产环境", ""]));
    file.write(file.snapshot(vault, &groups, true).expect("seal")).expect("write");
    assert!(std::fs::symlink_metadata(&file.legacy).is_err(), "the cleartext file is gone");
    assert_eq!(file.load(vault), (groups, false), "and what it held is sealed");
    remove_scratch(&path);
}

/// A group whose last connection is deleted or moved away drops out of
/// the saved set.
#[test]
fn a_group_left_empty_is_forgotten() {
    let conns = vec![sidebar_conn("a", "db", "生产环境"), sidebar_conn("b", "web", "")];
    let mut folded = groups_of(&["生产环境", "", "已删除"]);
    assert!(prune_collapsed_groups(&mut folded, &conns));
    assert_eq!(folded, groups_of(&["生产环境", ""]));
    assert!(!prune_collapsed_groups(&mut folded, &conns), "nothing more to drop");
    let moved = vec![sidebar_conn("a", "db", "测试"), sidebar_conn("b", "web", "")];
    assert!(prune_collapsed_groups(&mut folded, &moved));
    assert_eq!(folded, groups_of(&[""]));
}

/// Searching opens every group with a match, a folded one included,
/// without touching what was saved; with the search cleared it is
/// folded again.
#[test]
fn search_opens_a_folded_group_holding_a_chinese_match() {
    let conns = vec![
        sidebar_conn("1", "订单数据库主节点", "生产环境"),
        sidebar_conn("2", "web-01", "生产环境"),
        sidebar_conn("3", "构建机", "开发"),
    ];
    let folded = groups_of(&["生产环境"]);
    let groups = sidebar_groups(&conns, "数据库", &folded);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].key, "生产环境");
    assert!(!groups[0].collapsed, "a search result is never hidden");
    let ids: Vec<&str> = groups[0].conns.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["1"]);
    assert_eq!(folded, groups_of(&["生产环境"]), "the saved state is as it was");
    let all = sidebar_groups(&conns, "", &folded);
    assert!(all.iter().find(|g| g.key == "生产环境").expect("listed").collapsed);
    assert!(!all.iter().find(|g| g.key == "开发").expect("listed").collapsed);
    assert!(sidebar_groups(&conns, "  ", &folded).iter().any(|g| g.collapsed), "blank is no search");
}

/// Mixed Chinese and English groups: by name without regard to case, in
/// a fixed order, and the ungrouped bucket last.
#[test]
fn groups_sort_by_name_with_ungrouped_last() {
    let conns = vec![
        sidebar_conn("1", "a", ""),
        sidebar_conn("2", "b", "生产"),
        sidebar_conn("3", "c", "web"),
        sidebar_conn("4", "d", "开发"),
        sidebar_conn("5", "e", "Api"),
        sidebar_conn("6", "f", "WEB"),
    ];
    let order: Vec<String> =
        sidebar_groups(&conns, "", &HashSet::new()).into_iter().map(|g| g.key).collect();
    assert_eq!(order, ["Api", "WEB", "web", "开发", "生产", ""]);
}

/// Search works on Chinese names: substrings match, Latin case is
/// ignored, and the full-width letters a Chinese input method types match
/// their ASCII selves — in the sidebar and the palette alike.
#[test]
fn search_matches_chinese_names_and_full_width_letters() {
    let conn = sidebar_conn("1", "生产Web服务器", "华东区");
    for q in ["生产", "web服务", "WEB", "ｗｅｂ", "服务器", "华东", "10.0.0.1"] {
        assert!(connection_matches(&conn, &search_fold(q)), "{q}");
    }
    for q in ["测试", "生 产", "webs"] {
        assert!(!connection_matches(&conn, &search_fold(q)), "{q}");
    }
    assert_eq!(search_fold("ＡＢＣ　１２"), "abc 12");
    assert!(fuzzy_score("服务器", "生产Web服务器").is_some());
    assert!(fuzzy_score("ＷＥＢ", "生产Web服务器").is_some());
    assert!(fuzzy_score("测试", "生产Web服务器").is_none());
}

/// Folding from the keyboard: the palette offers each group by name, and
/// collapse all / expand all.
#[test]
fn the_palette_folds_groups() {
    let conns = vec![sidebar_conn("1", "db", "生产环境"), sidebar_conn("2", "web", "")];
    let toggle_of = |items: &[PaletteItem]| {
        items
            .iter()
            .find(|it| matches!(&it.msg, Message::ToggleGroupCollapsed(g) if g == "生产环境"))
            .map(|it| it.label.clone())
    };
    let open = toggle_of(&build_palette_items("生产", &conns, &[], &HashSet::new()))
        .expect("offered while open");
    let folded = toggle_of(&build_palette_items("生产", &conns, &[], &groups_of(&["生产环境"])))
        .expect("offered while folded");
    assert!(open.contains("生产环境") && folded.contains("生产环境"));
    assert_ne!(open, folded, "collapse, then expand");
    let blank = build_palette_items("", &conns, &[], &HashSet::new());
    assert!(!blank.iter().any(|it| matches!(it.msg, Message::ToggleGroupCollapsed(_))));
    let all = build_palette_items(i18n::t("sidebar.collapse_all"), &conns, &[], &HashSet::new());
    assert!(all.iter().any(|it| matches!(it.msg, Message::SetAllGroupsCollapsed(true))));
}

/// A Chinese name is cut by the columns it takes, not by its character
/// count: it fits the budget a Latin one does, and the cut shows.
#[test]
fn chinese_names_are_cut_to_the_display_width_budget() {
    use crate::terminal::display_width;
    let name = "华东区生产环境订单数据库主节点";
    assert!(name.chars().count() <= 16 && display_width(name) > 20, "the old count let it by");
    let (short, cut) = clip_to_width(name, 20);
    assert!(cut);
    assert!(display_width(&short) <= 20, "{short}");
    assert!(short.starts_with("华东区") && short.ends_with('…'), "{short}");
    let (same, cut) = clip_to_width("root@10.0.0.1:22", 20);
    assert!(!cut);
    assert_eq!(same, "root@10.0.0.1:22");
    // The fixed-width sidebar's budget shrinks as the UI font grows.
    assert_eq!(cols_at_scale(24, 1.0), 24);
    assert!(cols_at_scale(24, 1.5) < 24);
    assert!(cols_at_scale(24, 10.0) >= 6);
}

/// Every string this pass added resolves — in either language, which the
/// tables' parity guarantees.
#[test]
fn strings_added_for_this_pass_resolve() {
    for key in [
        "sftp.kind.file", "sftp.kind.dir", "sftp.kind.symlink", "sftp.kind.other",
        "sftp.confirm_delete_named", "sftp.confirm_delete_dir_named",
        "sftp.confirm_delete_link_named", "sftp.confirm_chmod_named",
        "sftp.rename_title_named", "sftp.chmod_title_named", "sftp.name_marks",
        "process.err.gone", "process.err.changed", "process.signal_n", "files.parked",
        "tunnel.err.start", "shortcuts.key.drag", "shortcuts.key.shift_drag",
        "shortcuts.key.right_click", "shortcuts.key.drop", "tab.split_suffix",
        "sidebar.collapse_all", "sidebar.expand_all", "palette.act.collapse_group",
        "palette.act.expand_group",
    ] {
        assert_ne!(i18n::t(key), "???", "{key}");
    }
}

// ---- round 5: input method, ports, listings, panes, groups ----------

/// The input method is off wherever a secret is typed: on the vault
/// screens whatever has the focus, in every secret field, and in a
/// sign-in answer the server does not echo.
#[test]
fn the_input_method_stays_away_from_secrets() {
    use FocusedField::{AuthAnswer, None as Terminal, Secret, Text};
    let otp = [("Verification code:".to_string(), false)];
    let user = [("Username:".to_string(), true)];
    for screen in [Screen::Setup, Screen::Locked] {
        for focused in [Terminal, Text, Secret, AuthAnswer(0)] {
            assert!(!ime_allowed(&screen, focused, &user), "{screen:?} {focused:?}");
        }
    }
    assert!(ime_allowed(&Screen::Main, Terminal, &[]), "the terminal takes Chinese");
    assert!(ime_allowed(&Screen::Main, Text, &[]), "so do names and searches");
    assert!(!ime_allowed(&Screen::Main, Secret, &[]));
    assert!(!ime_allowed(&Screen::Main, AuthAnswer(0), &otp), "a masked answer");
    assert!(ime_allowed(&Screen::Main, AuthAnswer(0), &user), "an echoed one");
    assert!(!ime_allowed(&Screen::Main, AuthAnswer(1), &user), "no prompt behind it");
}

/// Every secret field is told apart by its id — the setup and unlock
/// passwords, the connection, proxy and tunnel secrets — and so is each
/// sign-in answer, by its prompt's number.
#[test]
fn every_secret_field_is_known_by_its_id() {
    use iced::advanced::widget::Id;
    assert_eq!(SECRET_INPUT_IDS.len(), 9);
    for secret in SECRET_INPUT_IDS {
        let id = Id::from(text_input::Id::new(secret));
        assert_eq!(FocusedField::of(Some(&id)), FocusedField::Secret, "{secret}");
    }
    let unique: HashSet<&str> = SECRET_INPUT_IDS.into_iter().collect();
    assert_eq!(unique.len(), SECRET_INPUT_IDS.len());
    let answer = Id::from(auth_input_id(3));
    assert_eq!(FocusedField::of(Some(&answer)), FocusedField::AuthAnswer(3));
    for other in [PALETTE_INPUT_ID, QUICK_CMD_INPUT_ID, SFTP_INPUT_ID, TERM_SEARCH_INPUT_ID] {
        assert_eq!(FocusedField::of(Some(&Id::new(other))), FocusedField::Text, "{other}");
    }
    assert_eq!(FocusedField::of(None), FocusedField::None);
}

/// A focus the app gives counts at once; an answer from the widget tree
/// asked before that, or older than one already in, is stale.
#[test]
fn stale_focus_answers_are_ignored() {
    use iced::advanced::widget::Id;
    let mut focus = FocusTracker::default();
    let _ = focus.query(); // 1: asked before the app focused a field
    let _ = focus.focus(auth_input_id(0)); // 2, and its own query: 3
    assert_eq!(focus.field, FocusedField::AuthAnswer(0), "known before any answer");
    focus.found(1, None);
    assert_eq!(focus.field, FocusedField::AuthAnswer(0), "asked before the focus moved");
    focus.found(3, Some(Id::from(auth_input_id(0))));
    assert_eq!(focus.field, FocusedField::AuthAnswer(0));
    let _ = focus.query(); // 4
    let _ = focus.query(); // 5
    focus.found(5, None);
    assert_eq!(focus.field, FocusedField::None, "back in the terminal");
    focus.found(4, Some(Id::new(UNLOCK_PW_INPUT_ID)));
    assert_eq!(focus.field, FocusedField::None, "older than the answer in");
    assert!(focus.answered());
    let _ = focus.query();
    assert!(!focus.answered(), "a click's answer is out");
    focus.found(6, None);
    assert!(focus.answered());
    // An answer field past AUTH_MAX_FIELDS is one all the same, while a
    // challenge that long is on screen.
    let far = AUTH_MAX_FIELDS + 5;
    let _ = focus.query();
    focus.found(7, Some(Id::from(auth_input_id(far))));
    assert_eq!(focus.field_for(far + 1), FocusedField::AuthAnswer(far));
    assert_eq!(focus.field_for(1), FocusedField::Text, "no such field on screen");
    let _ = focus.query();
    focus.found(8, Some(Id::new(PALETTE_INPUT_ID)));
    assert_eq!(focus.field_for(far + 1), FocusedField::Text);
}

/// A press anywhere, Tab and Esc may move the focus; other keys and the
/// poll tick do not.
#[test]
fn presses_tab_and_esc_may_move_the_focus() {
    use keyboard::key::Named;
    let key = |named| {
        let none = keyboard::Modifiers::default();
        Message::KeyboardEvent(keyboard::Key::Named(named), none, None, false)
    };
    assert!(moves_focus(&Message::TerminalMouseDown(MouseButton::Left)));
    assert!(moves_focus(&Message::FocusMayHaveMoved));
    assert!(moves_focus(&key(Named::Tab)));
    assert!(moves_focus(&key(Named::Escape)));
    assert!(!moves_focus(&key(Named::Enter)));
    assert!(!moves_focus(&Message::PollSshEvents));
}

/// The candidate window is anchored on the text cursor's cell, measured
/// from the pane origin selection and mouse reporting use: the point
/// maps back to the same cell.
#[test]
fn the_candidate_window_sits_on_the_text_cursor() {
    let origin = (240.0, 64.0);
    let (x, y, h) = ime_cursor_area(origin, 13.0, (10, 2));
    assert!((x - (240.0 + 10.0 * 13.0 * 0.6)).abs() < 1e-3, "{x}");
    assert!((y - (64.0 + 2.0 * 13.0 * 1.2)).abs() < 1e-3, "{y}");
    assert!((h - 13.0 * 1.2).abs() < 1e-3, "{h}");
    let cell = grid_cell_at(x + 1.0, y + 1.0, origin, 13.0, (80, 24), false);
    assert_eq!(cell, Some((11, 3)), "1-based: the cursor's own cell");
    // The renderer's clamp: a silly font size lays out as 28.
    let clamped = ime_cursor_area((0.0, 0.0), 28.0, (1, 1));
    assert_eq!(ime_cursor_area((0.0, 0.0), 99.0, (1, 1)), clamped);
}

/// Full-width digits typed through an input method are the port they
/// read as; anything that is no port is refused, never turned into 22.
#[test]
fn full_width_ports_are_read_and_bad_ports_refused() {
    assert_eq!(parse_port("２２２２"), Ok(Some(2222)));
    assert_eq!(parse_port("\u{3000}８０８０ "), Ok(Some(8080)));
    assert_eq!(parse_port(" 22 "), Ok(Some(22)));
    assert_eq!(parse_port("65535"), Ok(Some(65535)));
    assert_eq!(parse_port(""), Ok(None));
    assert_eq!(parse_port("\u{3000} "), Ok(None));
    for bad in ["0", "０", "65536", "22a", "+22", "-1", "2 2", "二十二", "２２.５"] {
        assert_eq!(parse_port(bad), Err(()), "{bad:?}");
    }
    assert_eq!(form_port("２２２２", 22), Ok(2222));
    assert_eq!(form_port("", 1080), Ok(1080), "a blank field takes the default");
    let err = form_port("２２２x", 22).expect_err("refused");
    assert!(err.contains("２２２x"), "names what was typed: {err}");
}

#[test]
fn the_input_method_waits_for_the_focus_answer_only_where_a_secret_can_be() {
    // A form is open and a click's answer is out: off until it arrives.
    assert!(!focus_settled_or_no_secret_on_screen(false, true));
    // Answered: the focused field decides (see ime_allowed).
    assert!(focus_settled_or_no_secret_on_screen(true, true));
    // No overlay, no secret field on screen: a click never flips it.
    assert!(focus_settled_or_no_secret_on_screen(false, false));
}

#[test]
fn a_burst_of_saves_writes_each_file_once_with_its_last_value() {
    let p = |s: &str| std::path::PathBuf::from(s);
    let saves = vec![
        (p("alerts.json"), b"50".to_vec()),
        (p("scale"), b"1.00".to_vec()),
        (p("alerts.json"), b"55".to_vec()),
        (p("alerts.json"), b"60".to_vec()),
    ];
    assert_eq!(
        coalesce_saves(saves),
        vec![(p("alerts.json"), b"60".to_vec()), (p("scale"), b"1.00".to_vec())]
    );
    assert!(coalesce_saves(Vec::new()).is_empty());
}

#[test]
fn only_the_overlays_with_a_secret_field_wait_for_the_focus_answer() {
    assert_eq!(
        Overlay::HOLDS_SECRETS,
        [Overlay::ConnectionForm, Overlay::ProxyManager, Overlay::TunnelManager, Overlay::AuthPrompt]
    );
    for overlay in [Overlay::Palette, Overlay::SftpInput, Overlay::TabRename, Overlay::Settings] {
        assert!(!Overlay::HOLDS_SECRETS.contains(&overlay), "{overlay:?}");
    }
}

#[test]
fn hiding_a_panel_asks_where_the_focus_went() {
    assert!(moves_focus(&Message::ToggleBottomPanel));
    assert!(moves_focus(&Message::ToggleSidebar));
}

#[test]
fn main_screen_inputs_are_reported_as_text_not_as_the_terminal() {
    use iced::advanced::widget::Id;
    for id in [SIDEBAR_SEARCH_INPUT_ID, LOCAL_PATH_INPUT_ID, REMOTE_PATH_INPUT_ID] {
        assert_eq!(FocusedField::of(Some(&Id::new(id))), FocusedField::Text, "{id}");
        assert!(!SECRET_INPUT_IDS.contains(&id), "{id}");
    }
}

/// Regression: a prompt showing `~` made the browser re-list on every
/// monitor tick. The listing resolves `~` to the login directory and
/// records that; comparing it with the prompt's `~` never settled.
#[test]
fn a_home_prompt_is_followed_once_not_on_every_tick() {
    let mut prompt = HashMap::new();
    let mut current = HashMap::new();
    let mut listings = HashMap::new();
    // Tick 1: the prompt shows ~ and the browser follows it.
    assert!(follow_prompt_cwd(&mut prompt, &mut current, &listings, "s", "~"));
    assert_eq!(current["s"], "~");
    // The listing arrives, resolved, and records the real directory.
    current.insert("s".to_string(), "/home/alice".to_string());
    listings.insert("s".to_string(), Listing::new("/home/alice".into(), Vec::new()));
    // The old rule compared the prompt with that directory: always due.
    assert!(cwd_sync_due(current.get("s").map(String::as_str), listings.get("s"), "~"));
    // Tick 2 and later: the prompt still shows ~ — nothing to do.
    for _ in 0..3 {
        assert!(!follow_prompt_cwd(&mut prompt, &mut current, &listings, "s", "~"));
    }
    // The user opens /var/log by hand; the idle shell does not pull the
    // browser back.
    current.insert("s".to_string(), "/var/log".to_string());
    assert!(!follow_prompt_cwd(&mut prompt, &mut current, &listings, "s", "~"));
    assert_eq!(current["s"], "/var/log");
    // The shell moves: the browser follows.
    assert!(follow_prompt_cwd(&mut prompt, &mut current, &listings, "s", "/etc"));
    assert_eq!(current["s"], "/etc");
}

/// Scenario: the browser shows /home/u/app; the shell cds to /etc and the
/// sync asks for it, so `current_dir` already says /etc. A row still on
/// screen resolves against /home/u/app — and a failed listing puts
/// `current_dir` back, without the sync asking again every tick.
#[test]
fn row_actions_resolve_against_the_listing_on_screen() {
    let row = |name: &str| FileEntry { name: name.into(), ..FileEntry::default() };
    let mut listings = HashMap::new();
    listings.insert("s".to_string(), Listing::new("/home/u/app".into(), vec![row("config.yml")]));
    let mut current = HashMap::new();
    current.insert("s".to_string(), "/etc".to_string());
    let shown = &listings["s"];
    assert_eq!(shown.path_of("config.yml"), "/home/u/app/config.yml");
    assert_eq!(remote_parent(&shown.dir), "/home/u");
    assert_eq!(remote_parent("/"), "/");
    assert_eq!(Listing::new("/".into(), Vec::new()).path_of("etc"), "/etc");

    // The listing of /etc fails: back to what is shown.
    note_listing_failed(&mut current, &mut listings, "s", "/etc");
    assert_eq!(current["s"], "/home/u/app");
    assert_eq!(listings["s"].failed.as_deref(), Some("/etc"));
    assert!(!cwd_sync_due(Some("/home/u/app"), listings.get("s"), "/etc"), "not asked again");
    assert!(cwd_sync_due(Some("/home/u/app"), listings.get("s"), "/var"), "a new cwd is");
    assert!(!cwd_sync_due(Some("/var"), None, "/var"));
    assert!(cwd_sync_due(None, None, "~"));

    // A failure for a directory no longer asked for changes nothing.
    current.insert("s".to_string(), "/srv".to_string());
    note_listing_failed(&mut current, &mut listings, "s", "/etc");
    assert_eq!(current["s"], "/srv");
    // Nor for a session with nothing on screen.
    note_listing_failed(&mut current, &mut listings, "other", "/etc");
    assert!(!current.contains_key("other"));
}

/// Closing the focused pane of a split takes it out at once: a split
/// pane just goes; the main pane hands the tab to the split. A `Closed`
/// arriving after finds nothing more to do.
#[test]
fn closing_a_pane_promotes_the_survivor_once() {
    let mut tabs = vec![test_tab("main", "")];
    tabs[0].split = Some(test_split("split"));
    tabs[0].focus_split = true;
    let split_grid = tabs[0].split.as_ref().expect("split").terminal.clone();
    assert!(remove_split_pane(&mut tabs, "main"));
    assert_eq!(tabs[0].session_id, "split", "promoted");
    assert!(Arc::ptr_eq(&tabs[0].terminal, &split_grid), "with its own screen");
    assert!(tabs[0].split.is_none() && !tabs[0].focus_split);
    assert!(!remove_split_pane(&mut tabs, "main"), "a late Closed: nothing to do");
    assert_eq!(tabs.len(), 1);

    tabs[0].split = Some(test_split("second"));
    assert!(remove_split_pane(&mut tabs, "second"));
    assert_eq!(tabs[0].session_id, "split");
    assert!(tabs[0].split.is_none());
    assert!(!remove_split_pane(&mut tabs, "split"), "no split: the tab closes whole");
    assert!(!remove_split_pane(&mut tabs, ""));
}

/// Rename keeps the name exactly: "report " submitted as it opened is a
/// no-op, not a rename to "report".
#[test]
fn an_unchanged_rename_is_a_no_op() {
    assert_eq!(rename_target("report ", "report "), Ok(None));
    assert_eq!(rename_target("report ", "report"), Ok(Some("report".into())));
    assert_eq!(rename_target("a", " b "), Ok(Some(" b ".into())));
    assert_eq!(rename_target("a\u{7}b", "a\u{7}b"), Ok(None), "even a name it could not type");
    assert_eq!(rename_target("a", "a/b"), Err(()));
    assert_eq!(rename_target("a", "   "), Err(()));
}

/// A challenge from a session no tab or pane holds any more — a connect
/// still dialling when its tab closed — has nobody to answer it.
#[test]
fn a_challenge_whose_tab_is_gone_is_withdrawn() {
    let mut tabs = vec![test_tab("", "dialling")];
    tabs.push(test_tab("live", ""));
    tabs[1].split = Some(test_split("pane"));
    tabs[1].split_pending = Some("pane-dialling".into());
    for held in ["dialling", "live", "pane", "pane-dialling"] {
        assert!(!challenge_orphaned(held, &tabs), "{held}");
    }
    assert!(!challenge_orphaned("", &tabs), "a test or a deploy has its modal");
    tabs.remove(0);
    assert!(challenge_orphaned("dialling", &tabs), "its tab closed while it dialled");
    assert!(challenge_orphaned("gone", &[]));
}

/// Connections sort by group, then by name without regard to case, then
/// by host — in the sidebar, and in the empty palette alike, whatever
/// order the vault handed them over in.
#[test]
fn connections_keep_one_order_everywhere() {
    let mut b = sidebar_conn("3", "db", "生产");
    b.host = "10.0.0.9".into();
    let conns = vec![
        sidebar_conn("1", "web", "生产"),
        b,
        sidebar_conn("2", "DB", "生产"),
        sidebar_conn("4", "api", ""),
        sidebar_conn("5", "Build", "开发"),
    ];
    let groups = sidebar_groups(&conns, "", &HashSet::new());
    let ids: Vec<Vec<&str>> =
        groups.iter().map(|g| g.conns.iter().map(|c| c.id.as_str()).collect()).collect();
    assert_eq!(ids, [vec!["5"], vec!["2", "3", "1"], vec!["4"]]);
    let flat: Vec<&str> = ids.concat();

    let mut reversed = conns.clone();
    reversed.reverse();
    let mut sorted = reversed.clone();
    sorted.sort_by(connection_order);
    assert_eq!(sorted.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), flat);

    let palette: Vec<String> = build_palette_items("", &reversed, &[], &HashSet::new())
        .into_iter()
        .filter_map(|it| match it.msg {
            Message::ConnectTo(id) => Some(id),
            _ => None,
        })
        .collect();
    assert_eq!(palette, flat, "the empty palette lists them as the sidebar does");
}

/// The ungrouped bucket is found by the label it is shown under.
#[test]
fn the_ungrouped_bucket_is_found_by_its_label() {
    let loose = sidebar_conn("1", "db", "");
    let grouped = sidebar_conn("2", "db", "生产");
    // Whichever language is on: another test may switch it.
    let hit = |c: &ConnectionInfo, q: &str| connection_matches(c, &search_fold(q));
    assert!(hit(&loose, "Ungrouped") || hit(&loose, "未分组"));
    assert!(hit(&loose, "ungroup") || hit(&loose, "未分"));
    assert!(!hit(&grouped, "Ungrouped") && !hit(&grouped, "未分组"));
}

/// The palette's column budgets follow the UI font, like the sidebar's.
#[test]
fn palette_budgets_shrink_as_the_ui_font_grows() {
    let label = "x".repeat(PALETTE_LABEL_COLS);
    let meta = "y".repeat(PALETTE_META_COLS);
    let ((_, label_cut), (_, meta_cut)) = palette_row_text(&label, &meta, 1.0);
    assert!(!label_cut && !meta_cut, "they fit at the default size");
    let ((short, label_cut), (_, meta_cut)) = palette_row_text(&label, &meta, 1.5);
    assert!(label_cut && meta_cut, "not at 1.5×");
    assert!(crate::terminal::display_width(&short) <= cols_at_scale(PALETTE_LABEL_COLS, 1.5));
}

/// The reconnect marker is in the UI language, and the title still
/// parses: its base, its host, and whether it is reconnecting.
#[test]
fn the_reconnect_marker_is_translated_and_still_parsed() {
    let base = "deploy@web.example.com:2222";
    let title = reconnecting_title(base, 3);
    assert!(title.starts_with(&format!("{base} [")), "{title}");
    assert!(title.contains('3'), "{title}");
    assert_eq!(title_base(&title), base);
    assert!(title_reconnecting(&title));
    assert!(!title_reconnecting(base));
    assert_eq!(host_from_title(&title), "web.example.com");
}

/// Every string round 5 added resolves, in either language.
#[test]
fn strings_added_in_round_5_resolve() {
    for key in [
        "form.err.title", "form.err.port", "conn.copy_name", "tab.reconnecting",
        "tunnel.err.no_forwards", "tunnel.err.forward_parse", "log.truncated",
        "log.err.read", "filedialog.select_key", "term.sz_refused", "status.sync_badge",
    ] {
        assert_ne!(i18n::t(key), "???", "{key}");
    }
    assert!(i18n::tf("conn.copy_name", &[("name", "db")]).contains("db"));
}

#[test]
fn a_drain_budget_counts_bytes_and_events_and_never_underflows() {
    let mut b = DrainBudget::new(10, 3);
    assert!(b.has_room());
    b.charge(4);
    assert_eq!(
        b,
        DrainBudget {
            bytes: 6,
            events: 2
        }
    );
    // A Closed or an Error: an event, no bytes.
    b.charge(0);
    assert_eq!(
        b,
        DrainBudget {
            bytes: 6,
            events: 1
        }
    );
    assert!(b.has_room());
    b.charge(0);
    assert!(!b.has_room(), "out of events with bytes to spare");

    let mut b = DrainBudget::new(10, 3);
    b.charge(25);
    assert_eq!(
        b,
        DrainBudget {
            bytes: 0,
            events: 2
        },
        "the crossing event is taken whole"
    );
    assert!(!b.has_room());

    let data = SshEvent::Data {
        session_id: "s".into(),
        data: vec![0; 7],
    };
    assert_eq!(ssh_event_bytes(&data), 7);
    assert_eq!(
        ssh_event_bytes(&SshEvent::Closed {
            session_id: "s".into()
        }),
        0
    );
}

/// A flood is taken a budget at a time, and what one drain leaves is the
/// next one's, in order: nothing dropped, nothing taken twice.
#[test]
fn a_drain_stops_at_its_budget_and_the_rest_waits_in_order() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    for i in 0..6u8 {
        tx.send(vec![i; 100_000]).unwrap();
    }
    let drain = || {
        let mut budget = DrainBudget::new(SSH_DRAIN_BYTES, SSH_DRAIN_EVENTS);
        let mut taken = Vec::new();
        while let Some(chunk) = take_within(&rx, &mut budget, |c: &Vec<u8>| c.len()) {
            taken.push(chunk[0]);
        }
        (taken, budget.has_room())
    };
    // 256 KiB: the third 100 kB read crosses the line and is taken whole.
    assert_eq!(drain(), (vec![0, 1, 2], false));
    assert_eq!(drain(), (vec![3, 4, 5], false));
    assert_eq!(drain(), (vec![], true));

    // Many small reads end a drain on the event count instead.
    for _ in 0..SSH_DRAIN_EVENTS + 10 {
        tx.send(vec![1]).unwrap();
    }
    let (taken, room) = drain();
    assert_eq!((taken.len(), room), (SSH_DRAIN_EVENTS, false));
    assert_eq!(rx.try_iter().count(), 10, "the rest still queued");
}

/// Output for a session whose tab is still connecting waits, in its place
/// ahead of everything queued behind it, until the tab shows the session:
/// the handler would find no pane for it and drop it.
#[test]
fn output_that_beats_its_connect_is_held_in_place_until_the_tab_shows_it() {
    let (tx, rx) = mpsc::channel();
    let data = |sid: &str, byte: u8| SshEvent::Data {
        session_id: sid.into(),
        data: vec![byte],
    };
    let drain = |held: &mut Option<SshEvent>, tabs: &[TerminalTab]| {
        let mut budget = DrainBudget::new(SSH_DRAIN_BYTES, SSH_DRAIN_EVENTS);
        let mut taken = Vec::new();
        while let Some(event) = next_ssh_event(held, &rx, &mut budget, tabs) {
            if let SshEvent::Data { data, .. } = event {
                taken.push(data[0]);
            }
        }
        taken
    };
    tx.send(data("dialled", 1)).unwrap();
    tx.send(data("live", 2)).unwrap();
    tx.send(data("dialled", 3)).unwrap();
    let mut tabs = vec![test_tab("", "dialled"), test_tab("live", "")];
    let mut held = None;
    assert_eq!(drain(&mut held, &tabs), [0u8; 0], "nothing overtakes it");
    assert_eq!(drain(&mut held, &tabs), [0u8; 0], "still connecting");
    assert!(held.is_some());
    // `SshConnected`: the tab shows the session now.
    tabs[0].session_id = "dialled".into();
    tabs[0].pending_session_id.clear();
    assert_eq!(drain(&mut held, &tabs), [1, 2, 3]);
    assert!(held.is_none());

    // Closed while connecting: handed on for the handler to drop, as ever.
    tx.send(data("gone", 4)).unwrap();
    tx.send(data("live", 5)).unwrap();
    let mut tabs = vec![test_tab("", "gone"), test_tab("live", "")];
    assert_eq!(drain(&mut held, &tabs), [0u8; 0]);
    tabs.remove(0);
    assert_eq!(drain(&mut held, &tabs), [4, 5]);

    // A split still dialling is connecting too; a live pane is not.
    let mut tab = test_tab("live", "");
    tab.split_pending = Some("pane-dialling".into());
    let tabs = [tab];
    assert!(session_connecting(&tabs, "pane-dialling"));
    assert!(!session_connecting(&tabs, "live"));
    assert!(
        !session_connecting(&tabs, ""),
        "a tab's empty pending id matches nothing"
    );
}

#[test]
fn a_wake_drains_at_once_unless_the_last_drain_was_under_a_frame_ago() {
    let t0 = std::time::Instant::now();
    assert_eq!(wake_drain_at(None, t0), t0, "the first wake");
    let later = t0 + Duration::from_millis(100);
    assert_eq!(
        wake_drain_at(Some(t0), later),
        later,
        "a quiet session's next output"
    );
    let soon = t0 + Duration::from_millis(5);
    assert_eq!(
        wake_drain_at(Some(t0), soon),
        t0 + WAKE_MIN_GAP,
        "output still trickling in"
    );
    assert_eq!(
        wake_drain_at(Some(t0), t0 + WAKE_MIN_GAP),
        t0 + WAKE_MIN_GAP
    );
}

#[test]
fn the_wake_stream_keeps_early_wakes_folds_bursts_and_paces_a_trickle() {
    use iced::futures::StreamExt;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let wake = Arc::new(tokio::sync::Notify::new());
        let mut wakes = Box::pin(ssh_wakes(Arc::clone(&wake)));
        let long = Duration::from_secs(5);
        // Wakes that came while nothing awaited them (the UI still busy
        // with a drain) are kept, and a burst of them is one drain.
        for _ in 0..3 {
            wake.notify_one();
        }
        let first = tokio::time::timeout(long, wakes.next()).await;
        assert!(matches!(first, Ok(Some(Message::PollSshEvents))));
        let quiet = tokio::time::timeout(Duration::from_millis(50), wakes.next()).await;
        assert!(quiet.is_err(), "one drain for the burst");
        // A wake while the stream waits...
        wake.notify_one();
        let second = tokio::time::timeout(long, wakes.next()).await;
        assert!(matches!(second, Ok(Some(Message::PollSshEvents))));
        // ...and one right behind it, as from output that keeps coming:
        // it waits out the rest of a frame.
        let drained = std::time::Instant::now();
        wake.notify_one();
        let third = tokio::time::timeout(long, wakes.next()).await;
        assert!(matches!(third, Ok(Some(Message::PollSshEvents))));
        assert!(
            drained.elapsed() >= Duration::from_millis(10),
            "{:?}",
            drained.elapsed()
        );
    });
}

#[test]
fn the_timer_drain_runs_only_where_something_can_be_waiting() {
    // (on the main screen, sessions, a challenge waiting, a bar moving)
    assert_eq!(
        poll_interval(false, false, false, false),
        None,
        "setup; locked, no session"
    );
    assert_eq!(
        poll_interval(false, true, false, false),
        Some(SAFETY_POLL),
        "sessions run on under the lock"
    );
    assert_eq!(
        poll_interval(false, false, true, false),
        Some(SAFETY_POLL),
        "it still expires"
    );
    assert_eq!(
        poll_interval(false, true, true, true),
        Some(SAFETY_POLL),
        "nothing on screen moves under the lock"
    );
    assert_eq!(
        poll_interval(true, false, false, false),
        Some(SAFETY_POLL),
        "idle"
    );
    assert_eq!(
        poll_interval(true, true, false, false),
        Some(SAFETY_POLL),
        "idle sessions"
    );
    assert_eq!(
        poll_interval(true, true, true, false),
        Some(LIVE_POLL),
        "the sign-in modal"
    );
    assert_eq!(
        poll_interval(true, false, false, true),
        Some(LIVE_POLL),
        "a progress bar"
    );
    assert_eq!(
        LIVE_POLL,
        Duration::from_millis(50),
        "the rate the old poll ran at"
    );
    assert!(SAFETY_POLL <= Duration::from_secs(1));
}

#[test]
fn a_setting_is_saved_owner_only_and_a_failed_save_says_so() {
    let dir =
        std::env::temp_dir().join(format!("neoshell-app-test-{}-settings", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("neoshell").join("fontsize");
    assert!(
        write_setting(&path, b"14.0"),
        "its directory is made on the way"
    );
    assert_eq!(std::fs::read(&path).expect("saved"), b"14.0");
    assert!(write_setting(&path, b"15.0"));
    assert_eq!(std::fs::read(&path).expect("replaced"), b"15.0");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // `fontsize` is a file: nothing can be saved under it.
    let blocked = path.join("lang");
    assert!(!write_setting(&blocked, b"zh"));
    assert!(!blocked.exists());
    let _ = std::fs::remove_dir_all(&dir);
}
