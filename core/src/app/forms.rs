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
