//! Message handlers moved out of `handle_message` that belong to no
//! narrower module: sessions, tabs, the vault, the window.

use super::*;

/// `Message::CreateVault`, moved out of `handle_message`.
pub(crate) fn on_create_vault(state: &mut NeoShell) -> Task<Message> {
    if state.password_input.len() < 4 {
        state.error_message = i18n::t("setup.err_too_short").to_string();
        return Task::none();
    }
    if state.password_input != state.confirm_input {
        state.error_message = i18n::t("setup.err_mismatch").to_string();
        return Task::none();
    }
    let store = state.store.clone();
    let pw = state.password_input.clone();
    Task::perform(
        async move { store.set_master_password(&pw) },
        |result| match result {
            Ok(()) => Message::VaultCreated,
            Err(e) => Message::Error(e),
        },
    )
}

/// `Message::VaultCreated`, moved out of `handle_message`.
pub(crate) fn on_vault_created(state: &mut NeoShell) -> Task<Message> {
    state.screen = Screen::Main;
    state.password_input.clear();
    state.confirm_input.clear();
    state.error_message.clear();
    state.last_activity = std::time::Instant::now();
    // proxies.json / tunnels.json survive a deleted vault, so a fresh
    // vault can still inherit cleartext credentials to move.
    migrate_store_secrets(state);
    // So does a cleartext history.json, imported the same way.
    let history = unlock_history(state);
    // And a cleartext collapsed_groups.json.
    let groups = unlock_groups(state);
    // tunnels.json survives a deleted vault, so this path needs the
    // auto-start too.
    Task::batch(vec![
        Task::done(Message::LoadConnections),
        Task::done(Message::AutoStartTunnels),
        history,
        groups,
    ])
}

/// `Message::VaultUnlocked`, moved out of `handle_message`.
pub(crate) fn on_vault_unlocked(state: &mut NeoShell) -> Task<Message> {
    state.screen = Screen::Main;
    state.password_input.clear();
    state.error_message.clear();
    state.last_activity = std::time::Instant::now();
    // Synchronous, and before the auto-start below: the migration is
    // what moves the jump-host credentials out of tunnels.json and
    // into the vault, and `AutoStartTunnels` needs them resolved.
    // Doing it as another `Task::done` would leave the ordering to
    // the runtime.
    migrate_store_secrets(state);
    let history = unlock_history(state);
    // Before `LoadConnections` lands: it prunes this set.
    let groups = unlock_groups(state);
    Task::batch(vec![
        Task::done(Message::LoadConnections),
        Task::done(Message::CheckForUpdate),
        Task::done(Message::AutoStartTunnels),
        history,
        groups,
    ])
}

/// `Message::AutoStartTunnels`, moved out of `handle_message`.
pub(crate) fn on_auto_start_tunnels(state: &mut NeoShell) -> Task<Message> {
    for t in state.tunnel_store.load() {
        if !t.auto_start {
            continue;
        }
        let name = t.name.clone();
        // Re-entrant: an idle re-lock followed by an unlock dispatches
        // this again, and every already-running tunnel would otherwise
        // come back as "auto-start failed: tunnel already running".
        if state.tunnel_manager.is_running(&t.id) {
            continue;
        }
        log::info!("auto-starting tunnel '{}'", name);
        // `load()` fills credentials in best-effort and logs at debug
        // on failure; re-fetch through `get_for_connect` so a locked
        // vault is a real error instead of a jump-host handshake that
        // offers an empty password.
        let cfg = match state.tunnel_store.get_for_connect(&t.id) {
            Ok(cfg) => cfg,
            Err(e) => {
                log::warn!("auto-start skipped for '{}': {}", name, e);
                continue;
            }
        };
        if let Err(e) = state.tunnel_manager.start(cfg) {
            log::warn!("auto-start failed for '{}': {}", name, e);
        }
    }
    Task::none()
}

/// `Message::ExecuteDelete`, moved out of `handle_message`.
pub(crate) fn on_execute_delete(state: &mut NeoShell) -> Task<Message> {
    if let Some((id, _)) = state.confirm_delete.take() {
        state.conn_test_results.remove(&id);
        let store = state.store.clone();
        return Task::perform(
            async move {
                store.delete_connection(&id)?;
                store.get_connections()
            },
            |result| match result {
                Ok(conns) => Message::ConnectionsLoaded(conns),
                Err(e) => Message::Error(e),
            },
        );
    }
    Task::none()
}

/// `Message::ShowForm`, moved out of `handle_message`.
pub(crate) fn on_show_form(state: &mut NeoShell, maybe_id: Option<String>) -> Task<Message> {
    state.show_form = true;
    state.show_connect_dialog = false;
    state.form_test_result = None;
    state.form_testing = false;
    if let Some(id) = maybe_id.clone() {
        state.edit_id = Some(id.clone());
        if let Some(info) = state.connections.iter().find(|c| c.id == id) {
            state.form = ConnectionFormData {
                name: info.name.clone(),
                host: info.host.clone(),
                port: info.port.to_string(),
                username: info.username.clone(),
                auth_type: info.auth_type.clone(),
                group: info.group.clone(),
                proxy_id: info.proxy_id.clone().unwrap_or_default(),
                ..Default::default()
            };
        }
    } else {
        state.edit_id = None;
        state.form = ConnectionFormData {
            port: "22".into(),
            auth_type: "password".into(),
            ..Default::default()
        };
    }
    state.form_opened = opened_connection_form(&state.form);
    Task::none()
}

/// `Message::CloneConnection`, moved out of `handle_message`.
pub(crate) fn on_clone_connection(state: &mut NeoShell, id: String) -> Task<Message> {
    if let Ok(src) = state.store.get_connection(&id) {
        let mut clone = src.clone();
        clone.id = uuid::Uuid::new_v4().to_string();
        clone.name = i18n::tf("conn.copy_name", &[("name", &src.name)]);
        let store = state.store.clone();
        return Task::perform(
            async move {
                store.save_connection(clone)?;
                store.get_connections()
            },
            |r| match r {
                Ok(conns) => Message::ConnectionsLoaded(conns),
                Err(e) => Message::Error(e),
            },
        );
    }
    Task::none()
}

/// `Message::TestConnectionInList`, moved out of `handle_message`.
pub(crate) fn on_test_connection_in_list(state: &mut NeoShell, id: String) -> Task<Message> {
    if let Ok(cfg) = state.store.get_connection(&id) {
        let host = cfg.host.clone();
        let port = cfg.port;
        let username = cfg.username.clone();
        let auth_type = cfg.auth_type.clone();
        let password = cfg.password.clone();
        let private_key = cfg.private_key.clone();
        let passphrase = cfg.passphrase.clone();
        let proxy_id = cfg.proxy_id.clone();
        let id_clone = id.clone();
        return Task::perform(
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
            move |r| Message::TestConnectionInListDone(id_clone.clone(), r),
        );
    }
    Task::none()
}

/// `Message::TabSelected`, moved out of `handle_message`.
pub(crate) fn on_tab_selected(state: &mut NeoShell, idx: usize) -> Task<Message> {
    // Double-click (two clicks on the same tab within 400 ms) opens
    // the rename dialog instead of just re-selecting.
    let now = std::time::Instant::now();
    if let Some((last_idx, t)) = state.last_tab_click {
        if last_idx == idx
            && now.duration_since(t) < Duration::from_millis(400)
            && idx < state.tabs.len()
        {
            state.last_tab_click = None;
            state.tab_rename = Some(idx);
            state.tab_rename_input =
                state.tabs[idx].display_title().to_string();
            return state.focus.focus(text_input::Id::new(TAB_RENAME_INPUT_ID));
        }
    }
    state.last_tab_click = Some((idx, now));
    if idx < state.tabs.len() {
        state.active_tab = Some(idx);
    }
    Task::none()
}

/// `Message::TabClosed`, moved out of `handle_message`.
pub(crate) fn on_tab_closed(state: &mut NeoShell, idx: usize) -> Task<Message> {
    if idx < state.tabs.len() {
        let session_id = state.tabs[idx].session_id.clone();
        // Closing a tab also tears down its split pane's session.
        let split_sid = state.tabs[idx]
            .split
            .as_ref()
            .map(|s| s.session_id.clone());
        // Every sign-in the tab is waiting on — its connect, its
        // split's, a reconnect of either — is withdrawn as a cancel:
        // the modal goes, and each SSH thread stops waiting for an
        // answer nobody will give.
        let asking = tab_auth_sessions(&state.tabs[idx]);
        let (withdrawn, front) =
            take_challenges(&mut state.auth_queue, |c| asking.contains(&c.session_id));
        for challenge in withdrawn {
            challenge.cancel();
        }
        // Closed while connecting: the connection can be opened again
        // at once — the connect's own end no longer finds this tab.
        if session_id.is_empty() {
            state.connecting_ids.remove(&state.tabs[idx].connection_id);
        }
        let ssh = state.ssh_manager.clone();
        state.tabs.remove(idx);
        // The modal moves on to the next challenge, if the one on it
        // was this tab's.
        let auth = if front { state.begin_auth_prompt() } else { Task::none() };
        // Cleanup monitoring/file data for this session
        state.server_stats.remove(&session_id);
        state.top_processes.remove(&session_id);
        state.monitor_parked.unpark(&session_id);
        state.file_entries.remove(&session_id);
        state.current_dir.remove(&session_id);
        state.prompt_cwd.remove(&session_id);
        state.alerts_active.remove(&session_id);
        state.broadcast_selected.remove(&session_id);
        if let Some(sp) = &split_sid {
            state.alerts_active.remove(sp);
            state.broadcast_selected.remove(sp);
        }
        if state.tabs.is_empty() {
            state.active_tab = None;
        } else {
            state.active_tab = Some(idx.min(state.tabs.len() - 1));
        }
        let disconnect = Task::perform(
            async move {
                let _ = ssh.disconnect(&session_id);
                if let Some(sp) = split_sid {
                    let _ = ssh.disconnect(&sp);
                }
            },
            |_| Message::None,
        );
        Task::batch([auth, disconnect])
    } else {
        Task::none()
    }
}

/// `Message::ResumeMonitoring`, moved out of `handle_message`.
pub(crate) fn on_resume_monitoring(state: &mut NeoShell, sid: String) -> Task<Message> {
    // One press, one challenge: nothing more goes out while one is.
    if !state.monitor_parked.begin_resume(&sid) {
        return Task::none();
    }
    // The user's own action: its challenge may take the keyboard.
    state.last_keypress = None;
    let ssh = state.ssh_manager.clone();
    Task::perform(
        async move {
            let session_id = sid.clone();
            let result = tokio::task::spawn_blocking(move || ssh.resume_exec(&session_id))
                .await
                .unwrap_or_else(|e| Err(format!("Task: {}", e)));
            (sid, result)
        },
        |(sid, result)| Message::ResumeMonitoringDone(sid, result),
    )
}

/// `Message::ImportSshConfig`, moved out of `handle_message`.
pub(crate) fn on_import_ssh_config(state: &mut NeoShell, config: crate::sshconfig::SshHostConfig) -> Task<Message> {
    state.show_form = true;
    state.show_connect_dialog = false;
    state.edit_id = None;
    state.form = ConnectionFormData {
        name: config.alias.clone(),
        host: if config.hostname.is_empty() {
            config.alias
        } else {
            config.hostname
        },
        port: config.port.to_string(),
        username: config.user,
        auth_type: if config.identity_file.is_empty() {
            "password".to_string()
        } else {
            "key".to_string()
        },
        private_key: config.identity_file,
        group: "SSH Config".to_string(),
        ..Default::default()
    };
    state.form_opened = opened_connection_form(&state.form);
    Task::none()
}

/// `Message::ImportAllSshConfigs`, moved out of `handle_message`.
pub(crate) fn on_import_all_ssh_configs(state: &mut NeoShell) -> Task<Message> {
    // Bulk-import every non-wildcard host from ~/.ssh/config, skipping
    // entries that already match an existing connection (by user@host:port).
    let configs = crate::sshconfig::parse_ssh_config();
    let existing_keys: HashSet<String> = state.connections.iter()
        .map(|c| format!("{}@{}:{}", c.username, c.host, c.port))
        .collect();
    let store = state.store.clone();
    let mut added = 0usize;
    for cfg in configs {
        // Same key the welcome screen counts pending imports with.
        let Some(key) = ssh_config_key(&cfg) else { continue };
        if existing_keys.contains(&key) { continue; }
        let host = if cfg.hostname.is_empty() { cfg.alias.clone() } else { cfg.hostname.clone() };
        let conn = ConnectionConfig {
            id: String::new(),
            name: cfg.alias.clone(),
            host,
            port: cfg.port,
            username: cfg.user.clone(),
            auth_type: if cfg.identity_file.is_empty() { "password".into() } else { "key".into() },
            password: None,
            private_key: if cfg.identity_file.is_empty() { None } else { Some(cfg.identity_file.clone()) },
            passphrase: None,
            group: "SSH Config".into(),
            color: String::new(),
            proxy_id: None,
        };
        if store.save_connection(conn).is_ok() {
            added += 1;
        }
    }
    log::info!("Imported {} entries from ~/.ssh/config", added);
    state.show_connect_dialog = false;
    return Task::perform(
        async move { store.get_connections() },
        |r| match r {
            Ok(conns) => Message::ConnectionsLoaded(conns),
            Err(e) => Message::Error(e),
        },
    );
}

/// `Message::ReplayCommand`, moved out of `handle_message`.
pub(crate) fn on_replay_command(state: &mut NeoShell, cmd: String) -> Task<Message> {
    state.show_history = false;
    state.history_filter.clear();
    if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            let session_id = tab.session_id.clone();
            let ssh = state.ssh_manager.clone();
            let full_cmd = format!("{}\n", cmd);
            return Task::perform(
                async move {
                    ssh.send_data(&session_id, full_cmd.as_bytes())?;
                    Ok(())
                },
                |result: Result<(), String>| match result {
                    Ok(()) => Message::None,
                    Err(e) => Message::Error(e),
                },
            );
        }
    }
    Task::none()
}

/// `Message::SaveProxy`, moved out of `handle_message`.
pub(crate) fn on_save_proxy(state: &mut NeoShell) -> Task<Message> {
    let ptype = match state.proxy_form.proxy_type.as_str() {
        "http" => crate::proxy::ProxyType::Http,
        "bastion" => crate::proxy::ProxyType::SshBastion,
        _ => crate::proxy::ProxyType::Socks5h,
    };
    let default_port: u16 = match ptype {
        crate::proxy::ProxyType::Http => 8080,
        crate::proxy::ProxyType::SshBastion => 22,
        _ => 1080,
    };
    let port = match form_port(&state.proxy_form.port, default_port) {
        Ok(port) => port,
        Err(message) => {
            state.show_notice("form.err.title", message);
            return Task::none();
        }
    };
    let is_bastion = matches!(ptype, crate::proxy::ProxyType::SshBastion);
    let proxy = crate::proxy::ProxyConfig {
        id: state.proxy_edit_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: state.proxy_form.name.clone(),
        proxy_type: ptype,
        host: state.proxy_form.host.clone(),
        port,
        username: if state.proxy_form.username.is_empty() { None } else { Some(state.proxy_form.username.clone()) },
        password: if state.proxy_form.password.is_empty() { None } else { Some(state.proxy_form.password.clone()) },
        auth_type: if is_bastion { Some(state.proxy_form.auth_type.clone()) } else { None },
        private_key: if is_bastion && !state.proxy_form.private_key.is_empty() { Some(state.proxy_form.private_key.clone()) } else { None },
        passphrase: if is_bastion && !state.proxy_form.passphrase.is_empty() { Some(state.proxy_form.passphrase.clone()) } else { None },
    };
    // `try_*`, not the ()-returning shims: with the secret now in
    // the vault, a locked vault means the save did not happen, and
    // silently logging that loses the user's edit.
    let saved = if state.proxy_edit_id.is_some() {
        state.proxy_store.try_update(&proxy)
    } else {
        state.proxy_store.try_add(proxy)
    };
    if let Err(e) = saved {
        state.error_message = e;
        state.show_error_dialog = true;
        return Task::none();
    }
    state.proxies = state.proxy_store.load();
    state.show_proxy_form = false;
    state.proxy_edit_id = None;
    state.proxy_form = ProxyFormData::default();
    Task::none()
}

/// `Message::TestProxy`, moved out of `handle_message`.
pub(crate) fn on_test_proxy(state: &mut NeoShell, id: String) -> Task<Message> {
    if let Some(proxy) = state.proxies.iter().find(|p| p.id == id).cloned() {
        let pid = id.clone();
        return Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    crate::proxy::test_proxy(&proxy)
                }).await.unwrap_or(crate::proxy::ProxyTestResult {
                    reachable: false, latency_ms: 0,
                    error: Some("Task failed".into()),
                })
            },
            move |result| Message::ProxyTestDone(pid.clone(), result),
        );
    }
    Task::none()
}

/// `Message::SaveTunnel`, moved out of `handle_message`.
pub(crate) fn on_save_tunnel(state: &mut NeoShell) -> Task<Message> {
    let forwards: Result<Vec<_>, String> = state.tunnel_form.forwards_text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(crate::tunnel::ForwardRule::parse)
        .collect();
    let forwards = match forwards {
        Ok(f) if !f.is_empty() => f,
        Ok(_) => {
            state.show_notice("form.err.title", i18n::t("tunnel.err.no_forwards").to_string());
            return Task::none();
        }
        Err(e) => {
            let message = i18n::tf("tunnel.err.forward_parse", &[("err", &e)]);
            state.show_notice("form.err.title", message);
            return Task::none();
        }
    };
    let port = match form_port(&state.tunnel_form.ssh_port, 22) {
        Ok(port) => port,
        Err(message) => {
            state.show_notice("form.err.title", message);
            return Task::none();
        }
    };
    let cfg = crate::tunnel::TunnelConfig {
        id: state.tunnel_edit_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: state.tunnel_form.name.clone(),
        ssh_host: state.tunnel_form.ssh_host.clone(),
        ssh_port: port,
        username: state.tunnel_form.username.clone(),
        auth_type: state.tunnel_form.auth_type.clone(),
        password: if state.tunnel_form.password.is_empty() { None } else { Some(state.tunnel_form.password.clone()) },
        private_key: if state.tunnel_form.private_key.is_empty() { None } else { Some(state.tunnel_form.private_key.clone()) },
        passphrase: if state.tunnel_form.passphrase.is_empty() { None } else { Some(state.tunnel_form.passphrase.clone()) },
        forwards,
        auto_start: state.tunnel_form.auto_start,
    };
    if let Err(e) = state.tunnel_store.try_upsert(cfg) {
        state.error_message = e;
        state.show_error_dialog = true;
        return Task::none();
    }
    state.tunnels = state.tunnel_store.load();
    state.show_tunnel_form = false;
    state.tunnel_edit_id = None;
    state.tunnel_form = TunnelFormData::default();
    Task::none()
}

/// `Message::StartTunnel`, moved out of `handle_message`.
pub(crate) fn on_start_tunnel(state: &mut NeoShell, id: String) -> Task<Message> {
    // `get_for_connect`, so a locked vault says so instead of dialling
    // the jump host with an empty password.
    match state.tunnel_store.get_for_connect(&id) {
        Ok(cfg) => {
            if let Err(e) = state.tunnel_manager.start(cfg) {
                state.error_message = i18n::tf("tunnel.err.start", &[("err", &e)]);
                state.show_error_dialog = true;
            }
        }
        Err(e) => {
            state.error_message = i18n::tf("tunnel.err.start", &[("err", &e)]);
            state.show_error_dialog = true;
        }
    }
    Task::none()
}

/// `Message::ConfirmActionExecute`, moved out of `handle_message`.
pub(crate) fn on_confirm_action_execute(state: &mut NeoShell) -> Task<Message> {
    let Some(action) = state.confirm_action.take() else {
        return Task::none();
    };
    let ssh = state.ssh_manager.clone();
    match action {
        // The row the user confirmed goes along: the SSH layer
        // refuses an entry that is no longer the kind shown, and a
        // row whose listing could not be verified; it addresses the
        // entry by the name the server sent, not the text shown. Only
        // a confirmed folder is deleted with what is inside it.
        ConfirmAction::SftpDelete { session_id, dir, path, confirmed, .. } => {
            sftp_op_task(ssh, session_id, dir, move |ssh, sid| {
                ssh.sftp_remove_confirmed(sid, &path, confirmed)
            })
        }
        ConfirmAction::SftpChmod { session_id, dir, path, confirmed, mode, .. } => {
            sftp_op_task(ssh, session_id, dir, move |ssh, sid| {
                ssh.sftp_chmod_confirmed(sid, &path, mode, confirmed)
            })
        }
        ConfirmAction::Kill { session_id, pid, signal, identity, .. } => Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    // Still the process the user confirmed? A pid that
                    // changed hands while the dialog was up would take
                    // the signal meant for another.
                    match read_proc_identity(&ssh, &session_id, pid)? {
                        Some(now) if same_process(&identity, &now) => {
                            ssh.kill_process(&session_id, pid, signal)
                        }
                        Some(_) => Err(i18n::tf(
                            "process.err.changed",
                            &[("pid", &pid.to_string())],
                        )),
                        None => Err(i18n::tf("process.err.gone", &[("pid", &pid.to_string())])),
                    }
                })
                .await
                .unwrap_or_else(|e| Err(format!("Task: {}", e)))
            },
            Message::KillProcessDone,
        ),
    }
}

/// `Message::ShowLogViewer`, moved out of `handle_message`.
pub(crate) fn on_show_log_viewer(state: &mut NeoShell) -> Task<Message> {
    // Toggle: second click closes.
    if state.show_log_viewer {
        state.show_log_viewer = false;
        state.log_viewer_content.clear();
        return Task::none();
    }
    let path = crate::log_file_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => {
            const MAX: usize = 200 * 1024;
            if c.len() > MAX {
                // Snap the raw byte offset forward to a char boundary
                // before slicing — the log holds translated CJK, and
                // both this slice and the unwrap_or(start) fallback
                // below would otherwise land mid-character.
                let mut start = c.len() - MAX;
                while start < c.len() && !c.is_char_boundary(start) {
                    start += 1;
                }
                let aligned = c[start..].find('\n').map(|i| start + i + 1).unwrap_or(start);
                let kb = ((c.len() - aligned) / 1024).to_string();
                format!("{}\n{}", i18n::tf("log.truncated", &[("kb", &kb)]), &c[aligned..])
            } else {
                c
            }
        }
        Err(e) => i18n::tf(
            "log.err.read",
            &[("path", &path.display().to_string()), ("err", &e.to_string())],
        ),
    };
    state.log_viewer_content = content;
    state.show_log_viewer = true;
    Task::none()
}

/// `Message::QuitApp`, moved out of `handle_message`.
pub(crate) fn on_quit_app(state: &mut NeoShell) -> Task<Message> {
    log::info!("User requested quit — closing all SSH sessions and tunnels");
    // Here and now, after the writes already sent off: nothing waits
    // for a background task once the window is gone.
    if !state.history_file.wait_settled(HISTORY_SETTLE_WAIT) {
        log::warn!("command history: an earlier write is still running at quit");
    }
    if state.history_sync.dirty && state.history_sync.loaded {
        let saved = HistoryFile::snapshot(
            &state.history_file,
            &state.store,
            &state.cmd_history,
            false,
            false,
        )
        .and_then(|job| job.run().map_err(|e| e.to_string()));
        if let Err(e) = saved {
            log::warn!("command history not saved: {}", e);
        }
    }
    if state.groups_dirty {
        let saved = state
            .groups_file
            .snapshot(&state.store, &state.collapsed_groups, false)
            .and_then(|job| state.groups_file.write(job).map_err(|e| e.to_string()));
        if let Err(e) = saved {
            log::warn!("folded groups not saved: {}", e);
        }
    }
    for sid in state.ssh_manager.active_sessions() {
        let _ = state.ssh_manager.disconnect(&sid);
    }
    state.tunnel_manager.stop_all();
    let t: Task<Message> = iced::window::get_latest()
        .and_then(|id| iced::window::close(id));
    t
}
