use super::*;

#[derive(Default, Clone, PartialEq)]
pub(crate) struct TunnelFormData {
    pub(crate) name: String,
    pub(crate) ssh_host: String,
    pub(crate) ssh_port: String,
    pub(crate) username: String,
    pub(crate) auth_type: String,  // "password" | "key"
    pub(crate) password: String,
    pub(crate) private_key: String,
    pub(crate) passphrase: String,
    /// Multi-line forwards, one per line, in "LOCAL:REMOTE_HOST:REMOTE_PORT"
    /// or "REMOTE_HOST:REMOTE_PORT->LOCAL" format.
    pub(crate) forwards_text: String,
    pub(crate) auto_start: bool,
}

#[derive(Default, Clone, PartialEq)]
pub(crate) struct ConnectionFormData {
    pub(crate) name: String,
    pub(crate) host: String,
    pub(crate) port: String,
    pub(crate) username: String,
    pub(crate) auth_type: String,
    pub(crate) password: String,
    pub(crate) private_key: String,
    pub(crate) passphrase: String,
    pub(crate) group: String,
    pub(crate) proxy_id: String,
}

#[derive(Default, Clone, PartialEq)]
pub(crate) struct ProxyFormData {
    pub(crate) name: String,
    pub(crate) proxy_type: String, // "socks5h" | "http" | "bastion"
    pub(crate) host: String,
    pub(crate) port: String,
    pub(crate) username: String,
    pub(crate) password: String,
    // SSH bastion fields
    pub(crate) auth_type: String,   // "password" | "key"
    pub(crate) private_key: String, // file path
    pub(crate) passphrase: String,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Wipe every plaintext credential sitting in an open form.
///
/// Re-locking clears the DEK, but a half-filled connection / proxy / tunnel
/// form still holds the password the user typed or that `load()` decrypted.
/// Leaving it there would put the secret back on screen the moment the vault
/// is unlocked again, which is precisely what the lock is for. Zeroized, not
/// just cleared: `clear()` leaves the bytes in the buffer it keeps.
pub(crate) fn scrub_form_secrets(
    conn: &mut ConnectionFormData,
    proxy: &mut ProxyFormData,
    tunnel: &mut TunnelFormData,
) {
    conn.password.zeroize();
    conn.passphrase.zeroize();
    proxy.password.zeroize();
    proxy.passphrase.zeroize();
    tunnel.password.zeroize();
    tunnel.passphrase.zeroize();
}

/// Zero the credentials the proxy and tunnel lists hold decrypted, before the
/// lock drops the lists: a dropped `String` leaves its bytes on the heap.
pub(crate) fn scrub_list_secrets(
    proxies: &mut [crate::proxy::ProxyConfig],
    tunnels: &mut [crate::tunnel::TunnelConfig],
) {
    for p in proxies {
        p.password.zeroize();
        p.passphrase.zeroize();
    }
    for t in tunnels {
        t.password.zeroize();
        t.passphrase.zeroize();
    }
}

// ---- ESC and filled-in forms ------------------------------------------------
//
// ESC puts a form away only while it still reads exactly as it was opened.
// A half-filled connection, password included, used to be wiped by a habitual
// ESC; now typing is only ever thrown away by Cancel.

/// What the connection form is compared against to tell whether ESC may put
/// it away: `form` as just opened, minus any secret. Opening never fills the
/// password or passphrase (`ConnectionInfo` carries neither), so this is the
/// form itself — and should that ever change, the form merely reads as edited
/// and stays, rather than a second copy of a secret outliving the lock.
pub(crate) fn opened_connection_form(form: &ConnectionFormData) -> ConnectionFormData {
    ConnectionFormData {
        password: String::new(),
        passphrase: String::new(),
        ..form.clone()
    }
}

/// The proxy form as `ShowProxyForm` opens it: a saved proxy's fields, or
/// the defaults of a new one.
pub(crate) fn proxy_form_for(saved: Option<&crate::proxy::ProxyConfig>) -> ProxyFormData {
    let Some(p) = saved else {
        return ProxyFormData {
            proxy_type: "socks5h".into(),
            port: "1080".into(),
            ..Default::default()
        };
    };
    ProxyFormData {
        name: p.name.clone(),
        proxy_type: match p.proxy_type {
            crate::proxy::ProxyType::Socks5h => "socks5h".into(),
            crate::proxy::ProxyType::Http => "http".into(),
            crate::proxy::ProxyType::SshBastion => "bastion".into(),
        },
        host: p.host.clone(),
        port: p.port.to_string(),
        username: p.username.clone().unwrap_or_default(),
        password: p.password.clone().unwrap_or_default(),
        auth_type: p.auth_type.clone().unwrap_or_else(|| "password".into()),
        private_key: p.private_key.clone().unwrap_or_default(),
        passphrase: p.passphrase.clone().unwrap_or_default(),
    }
}

/// The tunnel form as `ShowTunnelForm` opens it: a saved tunnel's fields, or
/// the defaults of a new one.
pub(crate) fn tunnel_form_for(saved: Option<&crate::tunnel::TunnelConfig>) -> TunnelFormData {
    let Some(t) = saved else {
        return TunnelFormData {
            ssh_port: "22".into(),
            auth_type: "password".into(),
            ..Default::default()
        };
    };
    TunnelFormData {
        name: t.name.clone(),
        ssh_host: t.ssh_host.clone(),
        ssh_port: t.ssh_port.to_string(),
        username: t.username.clone(),
        auth_type: t.auth_type.clone(),
        password: t.password.clone().unwrap_or_default(),
        private_key: t.private_key.clone().unwrap_or_default(),
        passphrase: t.passphrase.clone().unwrap_or_default(),
        forwards_text: t.forwards.iter()
            // `spec()`, not a hand-rolled format: SaveTunnel re-parses this
            // text, and the 3-field form parses back as Local — silently
            // downgrading an "R:" or "D:" rule the user typed.
            .map(|f| f.spec())
            .collect::<Vec<_>>().join("\n"),
        auto_start: t.auto_start,
    }
}

/// Whether ESC may put the proxy form away: it still reads exactly as
/// `ShowProxyForm` opened it. When the proxy being edited is no longer in
/// `saved` that cannot be told, and the form is kept.
pub(crate) fn proxy_form_pristine(
    form: &ProxyFormData,
    edit_id: Option<&str>,
    saved: &[crate::proxy::ProxyConfig],
) -> bool {
    match edit_id {
        Some(id) => saved
            .iter()
            .find(|p| p.id == id)
            .is_some_and(|p| *form == proxy_form_for(Some(p))),
        None => *form == proxy_form_for(None),
    }
}

/// [`proxy_form_pristine`], for the tunnel form.
pub(crate) fn tunnel_form_pristine(
    form: &TunnelFormData,
    edit_id: Option<&str>,
    saved: &[crate::tunnel::TunnelConfig],
) -> bool {
    match edit_id {
        Some(id) => saved
            .iter()
            .find(|t| t.id == id)
            .is_some_and(|t| *form == tunnel_form_for(Some(t))),
        None => *form == tunnel_form_for(None),
    }
}

/// Whether ESC may put the snippet editor away: the name and body are what
/// `SnippetEdit` put there — the saved snippet's, or empty for a new one.
pub(crate) fn snippet_form_pristine(name: &str, body: &str, edit_id: Option<&str>, saved: &[Snippet]) -> bool {
    match edit_id {
        Some(id) => saved
            .iter()
            .any(|s| s.id == id && s.name == name && s.body == body),
        None => name.is_empty() && body.is_empty(),
    }
}

/// Move any credential still sitting in cleartext in `proxies.json` /
/// `tunnels.json` into the vault. One-shot and idempotent: both stores record
/// that they ran, and a failure leaves the file byte-identical so the next
/// unlock simply retries.
///
/// Must run with the vault OPEN — it is a no-op otherwise — and before
/// anything reads a credential back, which is why it is called synchronously
/// from the unlock arms rather than dispatched as a message.
pub(crate) fn migrate_store_secrets(state: &mut NeoShell) {
    let mut moved = false;
    match state.proxy_store.migrate_secrets() {
        Ok(changed) => moved |= changed,
        Err(e) => log::error!("proxy credential migration: {}", e),
    }
    match state.tunnel_store.migrate_secrets() {
        Ok(changed) => moved |= changed,
        Err(e) => log::error!("tunnel credential migration: {}", e),
    }
    // `state.proxies` / `state.tunnels` were first filled in `Default`, before
    // the vault could decrypt anything, and the edit forms prefill from them.
    // Reload unconditionally so a stale pre-unlock list can never be written
    // back over a real one.
    state.proxies = state.proxy_store.load();
    state.tunnels = state.tunnel_store.load();
    if moved {
        log::info!("credential migration complete");
    }
}

/// Re-lock the vault: wipe the DEK, drop any decrypted secret held in the UI,
/// and return to the lock screen. Returns the write that takes the command
/// history's unsaved records to disk.
///
/// Live SSH sessions are deliberately untouched. They run on their own
/// threads inside `SshManager`, their output is drained by `PollSshEvents`
/// (which is not gated on `Screen::Main`), and `state.tabs` is left intact —
/// so the terminals are still there, still connected, when the vault is
/// unlocked again.
pub(crate) fn lock_vault(state: &mut NeoShell) -> Task<Message> {
    // History first, while the key is still in memory: what the disk has not
    // seen yet is sealed, then every record is wiped. The write itself runs
    // on a blocking thread and carries only ciphertext.
    let flush = lock_history(
        &state.history_file,
        &state.store,
        &mut state.cmd_history,
        &mut state.history_sync,
    )
    .map_or_else(Task::none, spawn_history_write);
    // The folded groups too: a change not saved yet is sealed while the key
    // is here, and the names are forgotten until the next unlock reads them.
    let groups = if state.groups_dirty {
        persist_groups(state, false)
    } else {
        Task::none()
    };
    state.collapsed_groups.clear();
    state.groups_dirty = false;
    state.store.lock();
    scrub_form_secrets(
        &mut state.form,
        &mut state.proxy_form,
        &mut state.tunnel_form,
    );
    // The lists are re-read on unlock; holding decrypted copies across the
    // lock would defeat it.
    scrub_list_secrets(&mut state.proxies, &mut state.tunnels);
    state.proxies.clear();
    state.tunnels.clear();
    state.connections.clear();
    // Nothing below the lock screen is rendered, but an overlay left open
    // would spring back with the vault.
    state.show_form = false;
    state.show_proxy_form = false;
    state.show_proxy_manager = false;
    state.show_tunnel_form = false;
    state.show_tunnel_manager = false;
    state.show_settings = false;
    state.show_key_manager = false;
    state.show_palette = false;
    // A half-typed keyboard-interactive answer is a secret, and the SSH
    // threads behind the queue must not wait on a screen nobody can see:
    // scrub the answers and cancel every challenge (dropping one cancels it).
    scrub_answers(&mut state.auth_answers);
    state.auth_queue.clear();
    state.auth_focus_owed = false;
    state.auth_shown_at = None;
    // A pending destructive action does not survive the lock either.
    state.confirm_action = None;
    state.sftp_input = None;
    state.remote_menu = None;
    // The master password fields too, zeroized like the forms' secrets.
    state.password_input.zeroize();
    state.confirm_input.zeroize();
    state.error_message.clear();
    state.screen = Screen::Locked;
    Task::batch([flush, groups])
}

/// A port as typed into a form. The full-width digits a Chinese input method
/// types in full-width mode (U+FF10..U+FF19) read as ASCII ones, and ASCII
/// and ideographic spaces around it are ignored. `Ok(None)` for a blank
/// field, which takes the form's default; `Err(())` for anything that is not
/// a port from 1 to 65535 — reported, never defaulted.
pub(crate) fn parse_port(input: &str) -> Result<Option<u16>, ()> {
    let digits: String = input
        .trim_matches(|c: char| c.is_ascii_whitespace() || c == '\u{3000}')
        .chars()
        .map(|c| match c {
            '\u{FF10}'..='\u{FF19}' => char::from_u32(c as u32 - 0xFF10 + '0' as u32).unwrap_or(c),
            c => c,
        })
        .collect();
    if digits.is_empty() {
        return Ok(None);
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    match digits.parse::<u16>() {
        Ok(0) | Err(_) => Err(()),
        Ok(port) => Ok(Some(port)),
    }
}

/// [`parse_port`] for a form whose blank port means `default`; `Err` holds
/// the message to show.
pub(crate) fn form_port(input: &str, default: u16) -> Result<u16, String> {
    match parse_port(input) {
        Ok(port) => Ok(port.unwrap_or(default)),
        Err(()) => Err(i18n::tf("form.err.port", &[("port", input.trim())])),
    }
}

// ---- Message handlers moved out of handle_message ----

/// `Message::ConnectTo`, moved out of `handle_message`.
pub(crate) fn on_connect_to(state: &mut NeoShell, id: String) -> Task<Message> {
    if state.connecting_ids.contains(&id) {
        return Task::none();
    }
    state.connecting_ids.insert(id.clone());
    state.show_connect_dialog = false;
    // The key that started this — Enter in the palette — is not
    // typing somewhere else: this connect's sign-in may still take
    // the keyboard (see `deliver_auth_focus`).
    state.last_keypress = None;

    // Create a placeholder tab immediately so user sees feedback
    let tab_id = uuid::Uuid::new_v4().to_string();
    // The session's id, known before the connect is: its sign-in
    // challenges carry it, so closing this tab can withdraw them.
    let session_id = SshManager::new_session_id();
    let terminal = Arc::new(parking_lot::Mutex::new(TerminalGrid::new(120, 40)));
    {
        let mut grid = terminal.lock();
        let connecting = i18n::t("monitor.connecting");
        grid.write(format!("\x1b[33m{}\x1b[0m\r\n", connecting).as_bytes());
    }
    state.tabs.push(TerminalTab {
        id: tab_id.clone(),
        session_id: String::new(), // placeholder
        connection_id: id.clone(),
        title: i18n::t("monitor.connecting").to_string(),
        terminal,
        custom_title: None,
        split: None,
        focus_split: false,
        bounds: PaneBounds::default(),
        pending_session_id: session_id.clone(),
        split_pending: None,
    });
    state.active_tab = Some(state.tabs.len() - 1);

    let store = state.store.clone();
    let ssh = state.ssh_manager.clone();
    let tab_id2 = tab_id.clone();
    let conn_id_for_log = id.clone();
    let conn_id = id.clone();
    Task::perform(
        async move {
            log::info!("connect_to: attempting connection to id={}", conn_id_for_log);
            // Run blocking SSH connect on dedicated thread
            tokio::task::spawn_blocking(move || {
                let config = store.get_connection(&id)?;
                log::info!("connect_to: resolved {}@{}:{} (auth={}, proxy={:?})",
                    config.username, config.host, config.port,
                    config.auth_type, config.proxy_id);
                let session_id = ssh.connect_config_with_id(&session_id, &config)?;
                let title = format!("{}@{}:{}", config.username, config.host, config.port);
                Ok((tab_id2, session_id, title, id))
            }).await.map_err(|e| format!("Task: {}", e))?
        },
        // A failure belongs to this tab alone: it goes, the others
        // connecting beside it stay (see `ConnectFailed`).
        move |result: Result<(String, String, String, String), String>| match result {
            Ok((tab_id, session_id, title, conn_id)) => {
                Message::SshConnected(tab_id, session_id, title, conn_id)
            }
            Err(e) => Message::ConnectFailed(tab_id.clone(), conn_id.clone(), e),
        },
    )
}

/// `Message::SaveForm`, moved out of `handle_message`.
pub(crate) fn on_save_form(state: &mut NeoShell) -> Task<Message> {
    // Nothing is saved on a port that does not read as one: the form
    // stays open under the message.
    let port = match form_port(&state.form.port, 22) {
        Ok(port) => port,
        Err(message) => {
            state.show_notice("form.err.title", message);
            return Task::none();
        }
    };
    let is_edit = state.edit_id.is_some();
    let edit_id = state.edit_id.clone();

    // When editing, preserve existing secrets if form fields are empty
    // (ConnectionInfo doesn't expose secrets, so form shows them as empty)
    let (preserved_pw, preserved_key, preserved_pass) = if let Some(ref id) = edit_id {
        match state.store.get_connection(id) {
            Ok(existing) => (
                existing.password.clone(),
                existing.private_key.clone(),
                existing.passphrase.clone(),
            ),
            Err(_) => (None, None, None),
        }
    } else {
        (None, None, None)
    };
    // The form has no colour field; an edit must not wipe the tag the
    // sidebar draws from it.
    let preserved_color = edit_id
        .as_ref()
        .and_then(|id| state.connections.iter().find(|c| &c.id == id))
        .map(|c| c.color.clone())
        .unwrap_or_default();

    let password = if !state.form.password.is_empty() {
        Some(state.form.password.clone())
    } else if is_edit {
        preserved_pw // keep existing password
    } else {
        None
    };

    let private_key = if !state.form.private_key.is_empty() {
        Some(state.form.private_key.clone())
    } else if is_edit {
        preserved_key
    } else {
        None
    };

    let passphrase = if !state.form.passphrase.is_empty() {
        Some(state.form.passphrase.clone())
    } else if is_edit {
        preserved_pass
    } else {
        None
    };

    let config = ConnectionConfig {
        id: edit_id.clone().unwrap_or_default(),
        name: state.form.name.clone(),
        host: state.form.host.clone(),
        port,
        username: state.form.username.clone(),
        auth_type: state.form.auth_type.clone(),
        password,
        private_key,
        passphrase,
        // Trimmed: the group is the sidebar's grouping and folding
        // key, and "生产 " — a stray space an input method left —
        // would be a second group that reads exactly like "生产".
        group: state.form.group.trim().to_string(),
        color: preserved_color,
        proxy_id: if state.form.proxy_id.is_empty() {
            None
        } else {
            Some(state.form.proxy_id.clone())
        },
    };

    let store = state.store.clone();

    state.show_form = false;
    state.edit_id = None;
    state.form = ConnectionFormData::default();

    Task::perform(
        async move {
            if is_edit {
                store.update_connection(config)?;
            } else {
                store.save_connection(config)?;
            }
            store.get_connections()
        },
        |result| match result {
            Ok(conns) => Message::ConnectionsLoaded(conns),
            Err(e) => Message::Error(e),
        },
    )
}

/// `Message::TestFormConnection`, moved out of `handle_message`.
pub(crate) fn on_test_form_connection(state: &mut NeoShell) -> Task<Message> {
    // Gather form values + preserved secrets (same logic as SaveForm)
    let port = match form_port(&state.form.port, 22) {
        Ok(port) => port,
        Err(message) => {
            state.show_notice("form.err.title", message);
            return Task::none();
        }
    };
    let is_edit = state.edit_id.is_some();
    let (preserved_pw, preserved_key, preserved_pass) = if let Some(ref id) = state.edit_id {
        match state.store.get_connection(id) {
            Ok(existing) => (existing.password.clone(), existing.private_key.clone(), existing.passphrase.clone()),
            Err(_) => (None, None, None),
        }
    } else { (None, None, None) };

    let password = if !state.form.password.is_empty() { Some(state.form.password.clone()) }
        else if is_edit { preserved_pw } else { None };
    let private_key = if !state.form.private_key.is_empty() { Some(state.form.private_key.clone()) }
        else if is_edit { preserved_key } else { None };
    let passphrase = if !state.form.passphrase.is_empty() { Some(state.form.passphrase.clone()) }
        else if is_edit { preserved_pass } else { None };

    let host = state.form.host.clone();
    let username = state.form.username.clone();
    let auth_type = state.form.auth_type.clone();
    let proxy_id = if state.form.proxy_id.is_empty() { None } else { Some(state.form.proxy_id.clone()) };

    state.form_testing = true;
    state.form_test_result = None;

    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                crate::ssh::SshManager::test_connection(
                    &host, port, &username, &auth_type,
                    password.as_deref(), private_key.as_deref(),
                    passphrase.as_deref(), proxy_id.as_deref(),
                )
            }).await.unwrap_or(crate::ssh::ConnectionTestResult {
                ok: false, latency_ms: 0, stage: "internal".into(),
                error: Some("test task failed".into()),
            })
        },
        Message::TestFormConnectionDone,
    )
}

/// `Message::SnippetSave`, moved out of `handle_message`.
pub(crate) fn on_snippet_save(state: &mut NeoShell) -> Task<Message> {
    let name = state.snippet_form_name.trim().to_string();
    let body = state.snippet_form_body.trim().to_string();
    if name.is_empty() || body.is_empty() { return Task::none(); }
    let id = state.snippet_edit_id.clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if let Some(existing) = state.snippets.iter_mut().find(|s| s.id == id) {
        existing.name = name;
        existing.body = body;
    } else {
        state.snippets.push(Snippet { id, name, body });
    }
    save_snippets(&state.snippets);
    state.snippet_edit_id = None;
    state.snippet_form_name.clear();
    state.snippet_form_body.clear();
    Task::none()
}

/// `Message::KeyGenerate`, moved out of `handle_message`.
pub(crate) fn on_key_generate(state: &mut NeoShell) -> Task<Message> {
    let name = state.key_form_name.trim().to_string();
    let name = if name.is_empty() {
        "id_ed25519_neoshell".to_string()
    } else {
        name
    };
    let comment = state.key_form_comment.trim().to_string();
    match crate::sshkeys::generate_ed25519(&name, &comment) {
        Ok(_) => {
            state.key_form_name.clear();
            state.key_form_comment.clear();
            state.local_keys = crate::sshkeys::list_keys();
            state.key_deploy_status = Some(i18n::t("keys.generated").to_string());
        }
        Err(e) => {
            state.key_deploy_status = Some(format!("✗ {}", e));
        }
    }
    Task::none()
}

/// `Message::KeyDeployTo`, moved out of `handle_message`.
pub(crate) fn on_key_deploy_to(state: &mut NeoShell, path: String, conn_id: String) -> Task<Message> {
    let pubkey = state
        .local_keys
        .iter()
        .find(|k| k.path == path)
        .map(|k| k.pubkey.clone());
    let Some(pubkey) = pubkey else {
        return Task::none();
    };
    state.key_deploying = None;
    state.key_deploy_status = Some(i18n::t("keys.deploying").to_string());
    let store = state.store.clone();
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                let config = store.get_connection(&conn_id)?;
                crate::ssh::deploy_pubkey(&config, &pubkey)
            })
            .await
            .map_err(|e| format!("Task: {}", e))?
        },
        Message::KeyDeployDone,
    )
}

/// `Message::ConnectionsLoaded`, moved out of `handle_message`.
pub(crate) fn on_connections_loaded(state: &mut NeoShell, mut conns: Vec<ConnectionInfo>) -> Task<Message> {
    // In the order every list shows them: the vault is a map.
    conns.sort_by(connection_order);
    state.connections = conns;
    // Re-read ~/.ssh/config alongside the list it is compared with:
    // the connect dialog and the welcome screen's importer render
    // from this copy instead of parsing the file on every frame.
    // Opening the connect dialog lands here via LoadConnections.
    state.ssh_config_hosts = crate::sshconfig::parse_ssh_config();
    // A group whose last connection was deleted or moved away is not
    // folded any more: were it to come back, it would come back open.
    if prune_collapsed_groups(&mut state.collapsed_groups, &state.connections) {
        return schedule_groups_save(state);
    }
    Task::none()
}

/// `Message::ConnectFailed`, moved out of `handle_message`.
pub(crate) fn on_connect_failed(state: &mut NeoShell, tab_id: String, connection_id: String, e: String) -> Task<Message> {
    log::error!("{}", e);
    let Some(idx) = state.tabs.iter().position(|t| t.id == tab_id) else {
        // The tab was closed while it connected — a sign-in withdrawn
        // by that close ends here too. Nobody is waiting for this.
        return Task::none();
    };
    state.tabs.remove(idx);
    state.active_tab = active_after_removal(state.active_tab, idx, state.tabs.len());
    // Allow a manual retry.
    state.connecting_ids.remove(&connection_id);
    state.error_message = e;
    state.show_error_dialog = true;
    Task::none()
}

/// `Message::SnippetSend`, moved out of `handle_message`.
pub(crate) fn on_snippet_send(state: &mut NeoShell, id: String) -> Task<Message> {
    if let Some(sn) = state.snippets.iter().find(|s| s.id == id).cloned() {
        // Split-aware: snippet lands in the focused pane.
        if let Some(sid) = state.focused_session_id() {
            let body = if sn.body.ends_with('\n') { sn.body.clone() } else { format!("{}\n", sn.body) };
            let _ = state.ssh_manager.send_data(&sid, body.as_bytes());
        }
        state.show_snippets_panel = false;
    }
    Task::none()
}

/// `Message::SnippetEdit`, moved out of `handle_message`.
pub(crate) fn on_snippet_edit(state: &mut NeoShell, maybe_id: Option<String>) -> Task<Message> {
    state.snippet_edit_id = maybe_id.clone();
    if let Some(id) = maybe_id {
        if let Some(s) = state.snippets.iter().find(|s| s.id == id) {
            state.snippet_form_name = s.name.clone();
            state.snippet_form_body = s.body.clone();
        }
    } else {
        state.snippet_form_name.clear();
        state.snippet_form_body.clear();
    }
    Task::none()
}

/// `Message::KeyCopyPubkey`, moved out of `handle_message`.
pub(crate) fn on_key_copy_pubkey(state: &mut NeoShell, path: String) -> Task<Message> {
    if let Some(k) = state.local_keys.iter().find(|k| k.path == path) {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(&k.pubkey);
        }
        state.key_deploy_status = Some(i18n::t("keys.copied").to_string());
    }
    Task::none()
}

/// `Message::ProxyFormBrowsePrivateKey`, moved out of `handle_message`.
pub(crate) fn on_proxy_form_browse_private_key(state: &mut NeoShell) -> Task<Message> {
    if let Some(path) = rfd::FileDialog::new()
        .set_title(i18n::t("filedialog.select_key"))
        .pick_file()
    {
        state.proxy_form.private_key = path.to_string_lossy().to_string();
    }
    Task::none()
}

/// `Message::TunnelFormBrowseKey`, moved out of `handle_message`.
pub(crate) fn on_tunnel_form_browse_key(state: &mut NeoShell) -> Task<Message> {
    if let Some(path) = rfd::FileDialog::new()
        .set_title(i18n::t("filedialog.select_key"))
        .pick_file()
    {
        state.tunnel_form.private_key = path.to_string_lossy().to_string();
    }
    Task::none()
}
