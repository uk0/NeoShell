use super::*;
// Explicit: through the glob above, `column` is ambiguous with std's `column!`.
use iced::widget::column;

pub(crate) fn view_process_detail(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let detail = match &state.process_detail {
        Some(d) => d,
        None => return Space::new(0, 0).into(),
    };

    let title = text(format!("{} · {}", i18n::t("process.title"), detail.pid))
        .size(16.0 * scale).color(c_primary);
    let close_btn = button(text("x").font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(14.0 * scale))
        .on_press(Message::HideProcessDetail)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);

    // Signals, each behind a confirmation naming the pid and command. Not
    // offered for pid 0/1, which kill_process refuses anyway.
    let kill_btns: Element<'_, Message> = if detail.pid > 1 && !detail.session_id.is_empty() {
        row![
            tip(
                button(text(i18n::t("process.sigterm")).color(c_danger).size(11.0 * scale))
                    .on_press(Message::KillProcessRequest(15))
                    .padding(Padding::from([3, 10]))
                    .style(outline_button_style),
                i18n::t("process.sigterm_tip"),
            ),
            tip(
                button(text(i18n::t("process.sigkill")).size(11.0 * scale))
                    .on_press(Message::KillProcessRequest(9))
                    .padding(Padding::from([3, 10]))
                    .style(filled_button_style(c_danger)),
                i18n::t("process.sigkill_tip"),
            ),
        ]
        .spacing(space::S)
        .into()
    } else {
        Space::new(0, 0).into()
    };

    let header = row![title, horizontal_space(), kill_btns, tip(close_btn, i18n::t("tip.close"))]
        .spacing(space::S)
        .align_y(alignment::Vertical::Center);

    let mut body_col = column![].spacing(2);

    // ── Basic Info ──────────────────────────────
    body_col = body_col.push(
        container(text(i18n::t("process.title")).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0]))
    );
    for (key, val) in &detail.fields {
        body_col = body_col.push(
            row![
                text(format!("{}:", key)).color(theme::TEXT_MUTED).size(10.0 * scale).width(95),
                text(val.clone()).font(Font::MONOSPACE).color(c_primary).size(10.0 * scale),
            ].spacing(8)
        );
    }

    // ── Children ────────────────────────────────
    if !detail.children.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.child"), detail.children.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        // Header
        body_col = body_col.push(
            row![
                text(i18n::t("monitor.pid")).color(theme::TEXT_MUTED).size(9.0 * scale).width(60),
                text(i18n::t("monitor.proc_cpu")).color(theme::TEXT_MUTED).size(9.0 * scale).width(40),
                text(i18n::t("monitor.proc_mem")).color(theme::TEXT_MUTED).size(9.0 * scale).width(40),
                text(i18n::t("monitor.proc_cmd")).color(theme::TEXT_MUTED).size(9.0 * scale),
            ].spacing(4)
        );
        for line in &detail.children {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let child_pid: u32 = parts[0].parse().unwrap_or(0);
                let row_content = row![
                    text(parts[0]).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(60),
                    text(parts[1]).color(theme::WARNING).size(9.0 * scale).width(40),
                    text(parts[2]).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(40),
                    text(parts[3..].join(" ")).color(c_primary).size(9.0 * scale),
                ].spacing(4);
                body_col = body_col.push(
                    button(row_content)
                        .on_press(Message::InspectProcess(child_pid))
                        .padding(Padding::from([1, 0]))
                        .style(|_: &Theme, s| {
                            let mut st = button::Style::default();
                            if let button::Status::Hovered = s { st.background = Some(theme::BG_HOVER.into()); }
                            st
                        })
                );
            }
        }
    }

    // ── Listening Ports ─────────────────────────
    if !detail.listen_ports.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.listen"), detail.listen_ports.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        for line in &detail.listen_ports {
            body_col = body_col.push(
                text(line).font(Font::MONOSPACE).color(c_success).size(9.0 * scale)
            );
        }
    }

    // ── Network Connections ─────────────────────
    if !detail.net_conns.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.net"), detail.net_conns.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        for line in &detail.net_conns {
            body_col = body_col.push(
                text(line).font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(9.0 * scale)
            );
        }
    }

    // ── Open File Descriptors ───────────────────
    if !detail.open_fds.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.fds"), detail.open_fds.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        for fd in &detail.open_fds {
            body_col = body_col.push(
                text(fd).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(9.0 * scale)
            );
        }
    }

    // ── Threads ─────────────────────────────────
    if !detail.threads.is_empty() {
        body_col = body_col.push(container(text(format!("{} ({})", i18n::t("process.threads"), detail.threads.len())).color(c_accent).size(12.0 * scale)).padding(Padding::from([6, 0])));
        let thread_ids = detail.threads.join(", ");
        body_col = body_col.push(
            text(thread_ids).font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(9.0 * scale)
        );
    }

    let content = column![
        header,
        slim_scroll(body_col).height(Fill),
    ]
    .spacing(space::S)
    .padding(16)
    .width(560);

    iced::widget::center(modal_card(content).height(500)).into()
}

// ---- Context menu (right-click on connection) -------------------------------

pub(crate) fn view_toolbar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_accent = state.c_accent();
    let c_success = state.c_success();

    let toolbar_style = |_: &Theme, status: button::Status| {
        let mut s = button::Style::default();
        s.background = None;
        if let button::Status::Hovered = status {
            s.background = Some(theme::BG_HOVER.into());
            s.border = iced::Border { radius: 6.0.into(), ..Default::default() };
        }
        s
    };

    let sidebar_icon = if state.sidebar_collapsed { "|>" } else { "<|" };
    let sidebar_btn = button(text(sidebar_icon).font(Font::MONOSPACE).color(theme::TEXT_SECONDARY).size(11.0 * scale))
        .on_press(Message::ToggleSidebar)
        .padding(Padding::from([4, 8]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
                s.border = iced::Border { radius: 6.0.into(), ..Default::default() };
            }
            s
        });

    let sidebar_tip = if state.sidebar_collapsed { "tip.sidebar_show" } else { "tip.sidebar_hide" };
    let sep = || -> Element<'_, Message> {
        container(Space::new(1, 16))
            .style(|_| container::Style { background: Some(theme::BORDER.into()), ..Default::default() })
            .into()
    };

    let active_count = state.tabs.iter().filter(|t| !t.session_id.is_empty()).count();
    let session_info = text(format!("{}/{}", active_count, state.connections.len()))
        .color(theme::TEXT_MUTED).size(10.0 * scale);

    let btn_new = button(text(i18n::t("dialog.new_btn")).color(c_accent).size(12.0 * scale))
        .on_press(Message::ShowConnectDialog).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_proxy = button(text(i18n::t("proxy.title")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowProxyManager).padding(Padding::from([4, 10])).style(toolbar_style);
    let running_tun = state.tunnel_manager.states().iter()
        .filter(|(_, s)| s.is_running()).count();
    let tun_label = if running_tun > 0 {
        format!("{} ({})", i18n::t("tunnel.title"), running_tun)
    } else {
        i18n::t("tunnel.title").to_string()
    };
    let btn_tunnel = button(text(tun_label).color(
        if running_tun > 0 { c_success } else { theme::TEXT_SECONDARY }).size(12.0 * scale))
        .on_press(Message::ShowTunnelManager).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_history = button(text(i18n::t("history.title")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowHistory).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_snippets = button(text(i18n::t("btn.snippets")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowSnippetsPanel).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_broadcast = button(text(i18n::t("btn.broadcast")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowBroadcastDialog).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_keys = button(text(i18n::t("btn.keys")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowKeyManager).padding(Padding::from([4, 10])).style(toolbar_style);
    let btn_settings = button(text(i18n::t("settings.title")).color(theme::TEXT_SECONDARY).size(12.0 * scale))
        .on_press(Message::ShowSettings).padding(Padding::from([4, 10])).style(toolbar_style);

    // Clustered by how often they are reached for: every session / running
    // operations across hosts / one-off setup.
    let bar = row![
        tip(sidebar_btn, i18n::t(sidebar_tip)),
        sep(),
        btn_new,
        btn_history,
        btn_snippets,
        sep(),
        btn_broadcast,
        btn_tunnel,
        sep(),
        btn_proxy,
        btn_keys,
        horizontal_space(),
        session_info,
        btn_settings,
    ]
    .spacing(2)
    .padding(Padding::from([2, 8]))
    .align_y(alignment::Vertical::Center);

    container(bar)
        .width(Fill)
        .height(30)
        .style(|_| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 0.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}

// ---- Bottom panel (Monitor / Files / QuickCmd tabs) -------------------------

pub(crate) fn view_bottom_panel(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    // Tab strip
    let mon_active = state.bottom_panel_tab == BottomTab::Monitor;
    let files_active = state.bottom_panel_tab == BottomTab::Files;
    let cmd_active = state.bottom_panel_tab == BottomTab::QuickCmd;
    let ports_active = state.bottom_panel_tab == BottomTab::Ports;

    let tab_monitor = button(
        text(i18n::t("monitor.system")).color(if mon_active { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::Monitor))
    .padding(Padding::from([4, 14]))
    .style(move |_theme: &Theme, status| segment_style(mon_active, status));

    let tab_files = button(
        text(i18n::t("bottom.files")).color(if files_active { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::Files))
    .padding(Padding::from([4, 14]))
    .style(move |_theme: &Theme, status| segment_style(files_active, status));

    let tab_cmd = button(
        text(i18n::t("bottom.cmd")).color(if cmd_active { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::QuickCmd))
    .padding(Padding::from([4, 14]))
    .style(move |_theme: &Theme, status| segment_style(cmd_active, status));

    let tab_ports = button(
        text(i18n::t("bottom.ports")).color(if ports_active { theme::TEXT_PRIMARY } else { theme::TEXT_MUTED }).size(12.0 * scale)
    )
    .on_press(Message::SwitchBottomTab(BottomTab::Ports))
    .padding(Padding::from([4, 14]))
    .style(move |_theme: &Theme, status| segment_style(ports_active, status));

    let tab_strip = container(
        row![tab_monitor, tab_ports, tab_files, tab_cmd].spacing(4).padding(Padding::from([3, 8]))
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        ..Default::default()
    });

    // Panel content based on selected tab
    let panel_content: Element<'_, Message> = match state.bottom_panel_tab {
        BottomTab::Monitor => view_monitor_panel(state),
        BottomTab::Files => {
            // Dual pane: local (left) | separator | remote (right)
            let local_panel = view_local_files(state);
            let remote_panel = view_file_browser(state);
            let sep: Element<'_, Message> = container(Space::new(1, Fill))
                .style(|_| container::Style { background: Some(theme::BORDER.into()), ..Default::default() })
                .into();
            row![
                container(local_panel).width(Fill).height(Fill),
                sep,
                container(remote_panel).width(Fill).height(Fill),
            ].height(Fill).into()
        }
        BottomTab::QuickCmd => view_quick_commands(state),
        BottomTab::Ports => view_ports_panel(state),
    };

    column![
        tab_strip,
        container(panel_content).width(Fill).height(Fill),
    ]
    .into()
}

// ---- Monitor panel (horizontal layout for bottom area) ----------------------

pub(crate) fn view_monitor_panel(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    // The focused pane's session, split panes included.
    let active_session = state.active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.focused_session());
    // Every font size in this panel is scaled by (ui_font_size / 12) so the
    // Appearance slider in Settings updates monitor labels + process table
    // + network table immediately.
    let scale = state.theme_cfg.ui_font_size / 12.0;
    let c_primary = state.theme_cfg.text_primary.to_color();
    let c_danger  = state.theme_cfg.danger.to_color();
    let c_success = state.theme_cfg.success.to_color();
    let pb_color  = Some(state.theme_cfg.progress_bar.to_color());

    let sid = match active_session {
        Some(s) if !s.is_empty() => s,
        _ => return container(text(i18n::t("monitor.connecting")).color(theme::TEXT_MUTED).size(12.0 * scale))
            .padding(Padding::from([12, 12])).into(),
    };
    if let Some(parked) = state.monitor_parked.get(sid) {
        return view_monitor_parked(sid, parked, "monitor.parked", scale, c_primary, c_danger);
    }

    let stats = state.server_stats.get(sid);
    let processes = state.top_processes.get(sid);

    // ── Column 1: System info ──────────────────────────────────────
    let mut sys_col = column![
        text(i18n::t("monitor.system")).color(c_primary).size(11.0 * scale),
    ].spacing(2);
    let sys_size = 10.0 * scale;
    if let Some(s) = stats {
        sys_col = sys_col.push(sys_row_sized(&i18n::t("monitor.load"), &format!("{:.2} / {:.2} / {:.2}", s.load_1m, s.load_5m, s.load_15m), sys_size));
        let cores = i18n::tf("monitor.cpu_cores", &[("count", &s.cpu_cores.to_string())]);
        if s.cpu_per_core.is_empty() {
            // No /proc/stat (a non-Linux remote): the core count, as before.
            sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.cpu"), &cores, sys_size));
        } else {
            // Real utilisation from the /proc/stat delta — load average is a
            // queue length, not a percentage.
            sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.cpu"), &format!("{:.0}% · {}", s.cpu_percent, cores), sys_size));
            sys_col = sys_col.push(progress_bar_widget_with_color(s.cpu_percent, pb_color));
            if s.cpu_per_core.len() > 1 {
                sys_col = sys_col.push(per_core_bars(&s.cpu_per_core, scale, pb_color));
            }
        }
        sys_col = sys_col.push(sys_row_sized(&i18n::t("monitor.mem"), &format!("{} / {} MB ({:.0}%)", s.mem_used_mb, s.mem_total_mb, s.mem_percent), sys_size));
        sys_col = sys_col.push(progress_bar_widget_with_color(s.mem_percent, pb_color));
        // Zero on a host with no swap configured: nothing to show then.
        if s.swap_total_mb > 0 {
            sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.swap"), &format!("{} / {} MB ({:.0}%)", s.swap_used_mb, s.swap_total_mb, s.swap_percent), sys_size));
            sys_col = sys_col.push(progress_bar_widget_with_color(s.swap_percent, pb_color));
        }
        if s.disks.is_empty() {
            // No per-mount breakdown (df output unparsed): fall back to the
            // aggregate figures, as the old sidebar monitor did, instead of
            // showing no disk at all.
            sys_col = sys_col.push(sys_row_sized(i18n::t("monitor.disk"), &format!("{:.1} / {:.1} GB ({:.0}%)", s.disk_used_gb, s.disk_total_gb, s.disk_percent), sys_size));
            sys_col = sys_col.push(progress_bar_widget_with_color(s.disk_percent, pb_color));
        } else {
            for d in &s.disks {
                sys_col = sys_col.push(sys_row_sized(&truncate_str(&d.mount_point, 10), &format!("{}/{} ({:.0}%)", d.used, d.total, d.percent), sys_size));
                sys_col = sys_col.push(progress_bar_widget_with_color(d.percent, pb_color));
            }
        }
        if !s.uptime.is_empty() {
            sys_col = sys_col.push(sys_row_sized(&i18n::t("monitor.uptime"), &s.uptime, sys_size));
        }
    } else {
        sys_col = sys_col.push(text(i18n::t("monitor.connecting")).color(theme::TEXT_MUTED).size(11.0 * scale));
    }

    // ── Column 2: Network interfaces ───────────────────────────────
    let mut net_col = column![
        text(i18n::t("monitor.network")).color(c_primary).size(11.0 * scale),
    ].spacing(space::XXS);

    if let Some(s) = stats {
        let rx_rate = state.net_rx_rate.get(sid).copied().unwrap_or(0.0);
        let tx_rate = state.net_tx_rate.get(sid).copied().unwrap_or(0.0);
        // Byte columns are right-aligned in fixed widths so digits line up.
        let right = alignment::Horizontal::Right;
        net_col = net_col.push(
            row![
                text(i18n::t("net.speed")).color(theme::TEXT_MUTED).size(9.0 * scale).width(80),
                text(format!("D {}/s", format_bytes(rx_rate as u64))).color(c_success).size(9.0 * scale).width(80).align_x(right),
                text(format!("U {}/s", format_bytes(tx_rate as u64))).color(c_success).size(9.0 * scale).width(80).align_x(right),
            ].spacing(4)
        );

        net_col = net_col.push(
            row![
                text(i18n::t("net.interface")).color(theme::TEXT_MUTED).size(8.0 * scale).width(80),
                text(i18n::t("net.received")).color(theme::TEXT_MUTED).size(8.0 * scale).width(80).align_x(right),
                text(i18n::t("net.sent")).color(theme::TEXT_MUTED).size(8.0 * scale).width(80).align_x(right),
            ].spacing(4)
        );

        for (i, iface) in s.interfaces.iter().enumerate() {
            if iface.name == "lo" { continue; }
            let is_physical = iface.name.starts_with("eth") || iface.name.starts_with("en")
                || iface.name.starts_with("wl") || iface.name.starts_with("bond")
                || iface.name.starts_with("ib");
            let name_color = if is_physical { c_primary } else { theme::TEXT_MUTED };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };

            let iface_row = row![
                text(truncate_str(&iface.name, 10)).color(name_color).size(9.0 * scale).width(80),
                text(format_bytes(iface.rx_bytes)).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(80).align_x(right),
                text(format_bytes(iface.tx_bytes)).color(theme::TEXT_SECONDARY).size(9.0 * scale).width(80).align_x(right),
            ].spacing(4);

            let iface_clone = iface.clone();
            net_col = net_col.push(
                button(
                    container(iface_row)
                        .padding(Padding::from([1, 2]))
                        .width(Fill)
                        .style(move |_| container::Style { background: Some(row_bg.into()), ..Default::default() })
                )
                .on_press(Message::ShowNetworkDetail(iface_clone))
                .padding(0)
                .width(Fill)
                .style(transparent_button_style)
            );
        }

        net_col = net_col.push(
            container(
                row![
                    text(i18n::t("monitor.total")).color(c_accent).size(9.0 * scale).width(80),
                    text(format_bytes(s.net_rx_bytes)).color(c_accent).size(9.0 * scale).width(80).align_x(right),
                    text(format_bytes(s.net_tx_bytes)).color(c_accent).size(9.0 * scale).width(80).align_x(right),
                ].spacing(4)
            ).padding(Padding::from([2, 2]))
        );
    }

    // ── Column 3: Processes ────────────────────────────────────────
    // Numbers right-aligned under right-aligned headers; the command is
    // capped and never wraps, so one long argv cannot blow up a row.
    let num = alignment::Horizontal::Right;
    let mut proc_col = column![
        text(i18n::t("monitor.processes")).color(c_primary).size(11.0 * scale),
        row![
            text(i18n::t("monitor.pid")).color(theme::TEXT_MUTED).size(8.0 * scale).width(44).align_x(num),
            text(i18n::t("monitor.proc_cpu")).color(theme::TEXT_MUTED).size(8.0 * scale).width(36).align_x(num),
            text(i18n::t("monitor.proc_mem")).color(theme::TEXT_MUTED).size(8.0 * scale).width(36).align_x(num),
            text(i18n::t("monitor.proc_cmd")).color(theme::TEXT_MUTED).size(8.0 * scale),
        ].spacing(space::XS),
    ].spacing(space::XXS);

    if let Some(procs) = processes {
        let row_size = 9.0 * scale;
        for (i, p) in procs.iter().take(15).enumerate() {
            let color = if p.cpu > 50.0 { c_danger }
                       else if p.cpu > 20.0 { theme::WARNING }
                       else { theme::TEXT_SECONDARY };
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
            let pid_val = p.pid;
            let prow = row![
                text(format!("{}", p.pid)).color(color).size(row_size).width(44).align_x(num),
                text(format!("{:.1}", p.cpu)).color(color).size(row_size).width(36).align_x(num),
                text(format!("{:.1}", p.mem)).color(color).size(row_size).width(36).align_x(num),
                text(truncate_str(&p.command, 48))
                    .color(color)
                    .size(row_size)
                    .wrapping(iced::widget::text::Wrapping::None),
            ].spacing(space::XS);
            proc_col = proc_col.push(
                button(
                    container(prow).padding(Padding::from([2, 2])).width(Fill)
                        .style(move |_| container::Style { background: Some(row_bg.into()), ..Default::default() })
                )
                .on_press(Message::InspectProcess(pid_val))
                .padding(0)
                .width(Fill)
                .style(|_: &Theme, status| {
                    let mut s = button::Style::default();
                    s.background = None;
                    if let button::Status::Hovered = status {
                        s.background = Some(theme::BG_HOVER.into());
                    }
                    s
                })
            );
        }
    }

    // ── Layout: 2 main columns (left=sys+net, right=processes) ─────
    let left_combined = column![].push(sys_col).push(net_col).spacing(4);

    let left_panel = slim_scroll(left_combined).height(Fill);
    let right_panel = slim_scroll(proc_col).height(Fill);

    // Separator
    let sep: Element<'_, Message> = container(Space::new(1, Fill))
        .style(|_| container::Style {
            background: Some(theme::BORDER.into()),
            ..Default::default()
        })
        .into();

    row![
        container(left_panel).width(Fill).padding(Padding::from([4, 6])),
        sep,
        container(right_panel).width(Fill).padding(Padding::from([4, 4])),
    ]
    .height(Fill)
    .into()
}

/// The monitor panel of a session whose monitoring is parked: why, and the
/// one button that re-opens it. Off while its reconnect is out, so one press
/// is one challenge.
pub(crate) fn view_monitor_parked<'a>(
    session_id: &str,
    parked: &'a ParkedMonitor,
    what: &'static str,
    scale: f32,
    c_primary: Color,
    c_danger: Color,
) -> Element<'a, Message> {
    let action: Element<'a, Message> = if parked.resuming {
        button(
            text(i18n::t("monitor.reconnecting"))
                .color(theme::TEXT_MUTED)
                .size(12.0 * scale),
        )
        .padding(Padding::from([6, 14]))
        .style(transparent_button_style)
        .into()
    } else {
        button(text(i18n::t("monitor.reconnect")).size(12.0 * scale))
            .on_press(Message::ResumeMonitoring(session_id.to_string()))
            .padding(Padding::from([6, 14]))
            .style(accent_button_style)
            .into()
    };
    let mut col = column![
        text(i18n::t(what))
            .color(c_primary)
            .size(12.0 * scale),
        action,
    ]
    .spacing(space::S);
    if let Some(e) = &parked.error {
        col = col.push(text(e.as_str()).color(c_danger).size(11.0 * scale));
    }
    container(col).padding(Padding::from([12, 12])).into()
}

/// Per-core utilisation as a grid of mini bars, eight to a row, each labelled
/// with its core number and percentage.
pub(crate) fn per_core_bars(cores: &[f64], scale: f32, user_color: Option<Color>) -> Element<'static, Message> {
    const PER_ROW: usize = 8;
    let mut grid = column![].spacing(space::XS);
    for (r, chunk) in cores.chunks(PER_ROW).enumerate() {
        let mut line = row![].spacing(space::XS);
        for (i, pct) in chunk.iter().enumerate() {
            let pct = if pct.is_finite() { pct.clamp(0.0, 100.0) } else { 0.0 };
            let color = user_color.unwrap_or_else(|| heat_color(pct));
            let filled = pct.round() as u16;
            let bar: Element<'static, Message> = if filled == 0 {
                Space::new(Fill, 3).into()
            } else {
                row![
                    container(Space::new(Fill, 3))
                        .width(Length::FillPortion(filled))
                        .style(move |_| container::Style {
                            background: Some(color.into()),
                            border: iced::Border { radius: 1.5.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    Space::new(Length::FillPortion((100 - filled.min(100)).max(1)), 3),
                ]
                .into()
            };
            line = line.push(
                column![
                    text(format!("{} {:.0}%", r * PER_ROW + i, pct))
                        .size(8.0 * scale)
                        .color(theme::TEXT_MUTED)
                        .wrapping(iced::widget::text::Wrapping::None),
                    container(bar).width(Fill).style(|_| container::Style {
                        background: Some(theme::BG_TERTIARY.into()),
                        ..Default::default()
                    }),
                ]
                .spacing(1)
                .width(Length::FillPortion(1)),
            );
        }
        // Pad a short last row so its cells keep the same width.
        for _ in chunk.len()..PER_ROW {
            line = line.push(Space::with_width(Length::FillPortion(1)));
        }
        grid = grid.push(line);
    }
    container(grid).padding(Padding::from([2, 10])).width(Fill).into()
}

/// `fetch_listening_ports` for the active session as a sortable table; a row
/// with a known owner opens the process-detail popup.
pub(crate) fn view_ports_panel(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_primary = state.c_primary();
    let fs = 10.0 * scale;
    let num = alignment::Horizontal::Right;
    let left = alignment::Horizontal::Left;
    let sid = state
        .active_tab
        .and_then(|i| state.tabs.get(i))
        .map(|t| t.focused_session())
        .unwrap_or("");
    let current = !sid.is_empty() && state.ports_session == sid;

    let refresh = button(text(i18n::t("btn.refresh")).color(state.c_accent()).size(11.0 * scale))
        .on_press(Message::FetchPorts)
        .padding(Padding::from([2, 8]))
        .style(transparent_button_style);
    let count = if current { state.ports.len() } else { 0 };
    let header = row![
        text(i18n::t("ports.title")).color(c_primary).size(11.0 * scale),
        text(format!("({})", count)).color(theme::TEXT_MUTED).size(fs),
        horizontal_space(),
        text(i18n::t("ports.hint")).color(theme::TEXT_MUTED).size(9.0 * scale),
        tip(refresh, i18n::t("log.refresh")),
    ]
    .spacing(space::S)
    .align_y(alignment::Vertical::Center);

    let sort_head = |label: &str, key: PortSort, width: Length, align: alignment::Horizontal| {
        let active = state.ports_sort == key;
        let arrow = match (active, state.ports_sort_desc) {
            (false, _) => "",
            (true, false) => " ↑",
            (true, true) => " ↓",
        };
        button(
            text(format!("{}{}", i18n::t(label), arrow))
                .size(9.0 * scale)
                .color(if active { c_primary } else { theme::TEXT_MUTED })
                .width(Fill)
                .align_x(align),
        )
        .on_press(Message::PortsSortBy(key))
        .padding(Padding::from([1, 2]))
        .width(width)
        .style(transparent_button_style)
    };
    let columns = row![
        sort_head("ports.proto", PortSort::Proto, Length::Fixed(56.0), left),
        sort_head("ports.addr", PortSort::Addr, Length::FillPortion(2), left),
        sort_head("ports.port", PortSort::Port, Length::Fixed(64.0), num),
        sort_head("ports.pid", PortSort::Pid, Length::Fixed(64.0), num),
        sort_head("ports.process", PortSort::Process, Length::FillPortion(3), left),
    ]
    .spacing(space::XS)
    .padding(Padding::from([0, 4]));

    let mut list = column![].spacing(0);
    let notice = |key: &str| {
        container(text(i18n::t(key)).color(theme::TEXT_MUTED).size(11.0 * scale))
            .padding(Padding::from([10, 8]))
    };
    if !current {
        list = list.push(notice("ports.loading"));
    } else if let Some(e) = &state.ports_error {
        list = list.push(
            container(text(e.clone()).color(state.c_danger()).size(11.0 * scale))
                .padding(Padding::from([10, 8])),
        );
    } else if state.ports.is_empty() {
        let loading = state.ports_inflight.contains(sid);
        list = list.push(notice(if loading { "ports.loading" } else { "ports.empty" }));
    } else {
        // Already in table order: `PortsReceived` / `PortsSortBy` sort it.
        for (i, p) in state.ports.iter().enumerate() {
            let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
            let pid_text = p.pid.map_or_else(|| "—".to_string(), |pid| pid.to_string());
            let line = row![
                text(p.proto.clone()).size(fs).color(theme::TEXT_SECONDARY).width(Length::Fixed(56.0)),
                text(p.local_addr.clone())
                    .size(fs)
                    .color(theme::TEXT_SECONDARY)
                    .width(Length::FillPortion(2))
                    .wrapping(iced::widget::text::Wrapping::None),
                text(p.port.to_string())
                    .size(fs)
                    .color(c_primary)
                    .width(Length::Fixed(64.0))
                    .align_x(num),
                text(pid_text)
                    .size(fs)
                    .color(theme::TEXT_SECONDARY)
                    .width(Length::Fixed(64.0))
                    .align_x(num),
                text(truncate_str(&p.process, 40))
                    .size(fs)
                    .color(c_primary)
                    .width(Length::FillPortion(3))
                    .wrapping(iced::widget::text::Wrapping::None),
            ]
            .spacing(space::XS);
            let cell = container(line)
                .padding(Padding::from([2, 4]))
                .width(Fill)
                .style(move |_| container::Style {
                    background: Some(row_bg.into()),
                    ..Default::default()
                });
            // Without a pid (an unprivileged login cannot see other users'
            // sockets' owners) there is nothing to drill into.
            list = list.push(match p.pid {
                Some(pid) => Element::from(
                    button(cell)
                        .on_press(Message::InspectProcess(pid))
                        .padding(0)
                        .width(Fill)
                        .style(transparent_button_style),
                ),
                None => Element::from(cell),
            });
        }
    }

    column![header, columns, slim_scroll(list).height(Fill)]
        .spacing(space::XS)
        .padding(Padding::from([4, 8]))
        .height(Fill)
        .into()
}

// ---- Quick commands panel ---------------------------------------------------

pub(crate) fn view_quick_commands(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    // Input bar at top
    let cmd_input = input("Enter command...", &state.quick_cmd_input)
        .id(text_input::Id::new(QUICK_CMD_INPUT_ID))
        .on_input(Message::QuickCmdInputChanged)
        .on_submit(Message::SendQuickCmd)
        .padding(6)
        .size(12.0 * scale);

    let send_btn = button(
        text(i18n::t("btn.send")).size(11.0 * scale)
    )
    .on_press(Message::SendQuickCmd)
    .padding(Padding::from([6, 14]))
    .style(accent_button_style);

    let input_bar = container(
        row![cmd_input, send_btn].spacing(4).align_y(alignment::Vertical::Center)
    )
    .padding(Padding::from([4, 6]))
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border { color: theme::BORDER, width: 1.0, radius: 0.0.into() },
        ..Default::default()
    });

    // Recent unique commands list
    let mut col = column![].spacing(2);

    let mut seen = std::collections::HashSet::new();
    let mut count = 0;
    for record in state.cmd_history.iter().rev() {
        if seen.contains(&record.cmd) { continue; }
        seen.insert(record.cmd.clone());
        if count >= 30 { break; }
        count += 1;

        let cmd_display = record.cmd.clone();
        let cmd_action = record.cmd.clone();
        let i = count;
        let row_bg = if i % 2 == 0 { theme::BG_SECONDARY } else { theme::BG_TERTIARY };
        let btn = button(
            text(cmd_display).font(Font::MONOSPACE).color(c_primary).size(11.0 * scale)
        )
        .on_press(Message::ReplayCommand(cmd_action))
        .padding(Padding::from([3, 8]))
        .width(Fill)
        .style(move |_theme: &Theme, status| {
            let mut s = button::Style::default();
            s.background = Some(row_bg.into());
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });
        col = col.push(btn);
    }

    if count == 0 {
        col = col.push(
            container(text(i18n::t("history.empty")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([12, 8]))
        );
    }

    let list: Element<'_, Message> = slim_scroll(col).height(Fill).into();
    let suggestions = state.quick_cmd_suggestions();
    let body: Element<'_, Message> = if suggestions.is_empty() {
        list
    } else {
        // Autocomplete dropdown, floating over the list under the input. The
        // top entry is what Tab / Down accept; any entry can be clicked.
        let mut drop = column![].spacing(0);
        for (i, suggestion) in suggestions.into_iter().enumerate() {
            let top = i == 0;
            drop = drop.push(
                button(
                    text(truncate_str(&suggestion, 120))
                        .font(Font::MONOSPACE)
                        .color(c_primary)
                        .size(11.0 * scale)
                        .wrapping(iced::widget::text::Wrapping::None),
                )
                .on_press(Message::QuickCmdAccept(suggestion))
                .padding(Padding::from([3, 8]))
                .width(Fill)
                .style(move |_theme: &Theme, status| button::Style {
                    background: Some(
                        if top || matches!(status, button::Status::Hovered) {
                            theme::BG_HOVER
                        } else {
                            theme::BG_SECONDARY
                        }
                        .into(),
                    ),
                    ..Default::default()
                }),
            );
        }
        drop = drop.push(
            container(text(i18n::t("quickcmd.accept_hint")).color(theme::TEXT_MUTED).size(9.5 * scale))
                .padding(Padding::from([2, 8])),
        );
        let card = container(drop)
            .width(Fill)
            .max_width(640)
            .style(|_| container::Style {
                background: Some(theme::BG_SECONDARY.into()),
                border: iced::Border { color: theme::BORDER_STRONG, width: 1.0, radius: 4.0.into() },
                shadow: iced::Shadow {
                    color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
                    offset: iced::Vector::new(0.0, 4.0),
                    blur_radius: 12.0,
                },
                ..Default::default()
            });
        stack![list, container(card).padding(Padding::from([0, 6]))].into()
    };

    column![input_bar, body].into()
}

// ---- Welcome screen (no active tab) ----------------------------------------

pub(crate) fn view_network_detail(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let iface = match &state.selected_interface {
        Some(i) => i,
        None => return Space::new(0, 0).into(),
    };

    let (title_str, close_str, lbl_iface, lbl_rx, lbl_tx, lbl_total, lbl_type, if_type_str)
        = net_detail_labels(&iface.name);

    let title = text(title_str).color(c_primary).size(16.0 * scale);

    let close_btn = button(text(close_str).color(theme::TEXT_SECONDARY).size(13.0 * scale))
        .on_press(Message::HideNetworkDetail)
        .padding(Padding::from([6, 16]))
        .style(transparent_button_style);

    let header = row![title, horizontal_space(), close_btn]
        .align_y(alignment::Vertical::Center);

    let rx_text = format_bytes(iface.rx_bytes);
    let tx_text = format_bytes(iface.tx_bytes);
    let total = format_bytes(iface.rx_bytes + iface.tx_bytes);

    let mut info_col = column![].spacing(8);
    info_col = info_col.push(detail_row(&lbl_iface, &iface.name));
    info_col = info_col.push(detail_row(&lbl_rx, &rx_text));
    info_col = info_col.push(detail_row(&lbl_tx, &tx_text));
    info_col = info_col.push(detail_row(&lbl_total, &total));
    info_col = info_col.push(detail_row(&lbl_type, &if_type_str));

    let content = column![header, info_col].spacing(16).padding(24).width(380);

    iced::widget::center(modal_card(content)).into()
}

pub(crate) fn view_status_bar(state: &NeoShell) -> Element<'_, Message> {
    let scale = state.ui_scale();
    let c_accent = state.c_accent();
    let c_danger = state.c_danger();
    // One size for the whole bar, at the readable floor (was 9-10px).
    let fs = 10.5 * scale;

    let version = text(i18n::tf("status.version", &[("version", env!("CARGO_PKG_VERSION"))]))
        .color(theme::TEXT_MUTED).size(fs);

    let session_text = if let Some(idx) = state.active_tab {
        if let Some(tab) = state.tabs.get(idx) {
            text(&tab.title).color(theme::TEXT_SECONDARY).size(fs)
        } else {
            text("").size(fs)
        }
    } else {
        text(i18n::t("status.no_session")).color(theme::TEXT_MUTED).size(fs)
    };

    let counters = text(format!("{}T · {}H", state.tabs.len(), state.cmd_history.len()))
        .font(Font::MONOSPACE).color(theme::TEXT_MUTED).size(fs);

    // SYNC badge — loud on purpose: typing while it's on reaches N boxes.
    let sync_badge: Element<'_, Message> = if state.sync_input_on {
        let n = state.broadcast_selected.len();
        button(
            text(i18n::tf("status.sync_badge", &[("n", &n.to_string())]))
                .font(Font::MONOSPACE)
                .color(Color::WHITE)
                .size(fs),
        )
        .on_press(Message::ToggleSyncInput)
        .padding(Padding::from([1, 6]))
        .style(|_, _| button::Style {
            background: Some(theme::DANGER.into()),
            text_color: Color::WHITE,
            border: iced::Border { radius: 3.0.into(), ..Default::default() },
            ..Default::default()
        })
        .into()
    } else {
        Space::new(0, 0).into()
    };

    // First active threshold alert (clicking opens nothing yet — it's a
    // status readout; the tab dot tells you which box).
    let alert_badge: Element<'_, Message> = if let Some((sid, breaches)) =
        state.alerts_active.iter().next()
    {
        let title = state
            .tabs
            .iter()
            .find_map(|t| {
                if t.session_id == *sid {
                    Some(t.display_title().to_string())
                } else if t.split.as_ref().map(|s| &s.session_id) == Some(sid) {
                    Some(i18n::tf("tab.split_suffix", &[("title", t.display_title())]))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| sid.chars().take(8).collect());
        // Keep the status bar from being elbowed out by a long user@host —
        // or a Chinese tab name, measured by display width.
        let (short, cut) = clip_to_width(&title, 18);
        let more = if state.alerts_active.len() > 1 {
            format!(" +{}", state.alerts_active.len() - 1)
        } else {
            String::new()
        };
        let badge = text(format!("⚠ {}: {}{}", short, breaches.join(" "), more))
            .color(c_danger)
            .size(fs);
        if cut {
            tip_at(badge, &title, iced::widget::tooltip::Position::Top)
        } else {
            badge.into()
        }
    } else {
        Space::new(0, 0).into()
    };

    let lang_label = if state.locale == "zh-CN" { "EN" } else { "CN" };
    let lang_btn = button(text(lang_label).font(Font::MONOSPACE).color(c_accent).size(fs))
        .on_press(Message::ToggleLanguage)
        .padding(Padding::from([1, 5]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            s.border = iced::Border { color: theme::BORDER, width: 1.0, radius: 3.0.into() };
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });

    let mod_key = if cfg!(target_os = "macos") { "Cmd" } else { "Ctrl" };
    let shortcuts_str = i18n::t("status.shortcuts").replace("{mod}", mod_key);
    let shortcuts = text(shortcuts_str).color(theme::TEXT_MUTED).size(fs);

    let help_btn = button(text("?").font(Font::MONOSPACE).color(c_accent).size(fs))
        .on_press(Message::ToggleShortcutsHelp)
        .padding(Padding::from([1, 5]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            s.border = iced::Border { color: theme::BORDER, width: 1.0, radius: 3.0.into() };
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });

    let log_btn = button(text(i18n::t("status.log")).color(c_accent).size(fs))
        .on_press(Message::ShowLogViewer)
        .padding(Padding::from([1, 5]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            s.border = iced::Border { color: theme::BORDER, width: 1.0, radius: 3.0.into() };
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });

    let lock_btn = button(text(i18n::t("lock.now")).color(c_accent).size(fs))
        .on_press(Message::LockNow)
        .padding(Padding::from([1, 5]))
        .style(|_: &Theme, status| {
            let mut s = button::Style::default();
            s.background = None;
            s.border = iced::Border { color: theme::BORDER, width: 1.0, radius: 3.0.into() };
            if let button::Status::Hovered = status {
                s.background = Some(theme::BG_HOVER.into());
            }
            s
        });

    let quit_btn = button(text(i18n::t("status.quit")).color(c_danger).size(fs))
        .on_press(Message::QuitApp)
        .padding(Padding::from([1, 6]))
        .style(move |_: &Theme, status| button::Style {
            background: matches!(status, button::Status::Hovered)
                .then(|| tint(c_danger, 0.15).into()),
            border: iced::Border { color: c_danger, width: 1.0, radius: 3.0.into() },
            ..Default::default()
        });

    // Quit sits alone past a hairline so it is never hit on the way to Lock.
    let quit_sep: Element<'_, Message> = container(Space::new(1, 14))
        .style(|_| container::Style { background: Some(theme::BORDER.into()), ..Default::default() })
        .into();
    let up = iced::widget::tooltip::Position::Top;

    // Active session leftmost — it is what the bar is for.
    let bar = row![
        session_text,
        sync_badge,
        alert_badge,
        horizontal_space(),
        shortcuts,
        counters,
        version,
        log_btn,
        tip_at(help_btn, i18n::t("shortcuts.title"), up),
        tip_at(lang_btn, i18n::t("settings.language"), up),
        lock_btn,
        quit_sep,
        quit_btn,
    ]
        .spacing(space::M)
        .padding(Padding::from([3, 10]))
        .align_y(alignment::Vertical::Center);

    container(bar)
        .width(Fill)
        .height(24)
        .style(|_theme| container::Style {
            background: Some(theme::BG_TERTIARY.into()),
            border: iced::Border {
                color: theme::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
}

// ---- Tunnel manager ---------------------------------------------------------
