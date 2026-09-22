use super::*;

#[derive(Debug, Clone)]
pub(crate) struct ProcessDetailInfo {
    pub(crate) pid: u32,
    pub(crate) fields: Vec<(String, String)>,
    pub(crate) children: Vec<String>,      // child process lines
    pub(crate) threads: Vec<String>,       // thread IDs
    pub(crate) net_conns: Vec<String>,     // network connections (ss output)
    pub(crate) listen_ports: Vec<String>,  // listening ports
    pub(crate) open_fds: Vec<String>,      // file descriptors
    /// Session the details were read over. A kill from the popup goes to this
    /// host even if the user has switched tabs since.
    pub(crate) session_id: String,
}

/// Which process holds a pid right now, read from /proc when the kill
/// confirmation opens and again just before the signal goes. A pid names
/// whatever process holds it at that moment — the popup may be minutes old —
/// and the name `ss` / `netstat` printed is whatever the process chose to
/// call itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcIdentity {
    /// Field 22 of /proc/<pid>/stat, clock ticks after boot: a pid that has
    /// changed hands has a new one. This is what identifies the process.
    pub(crate) start_time: String,
    /// The name in the same stat line — all a kernel thread has to show.
    pub(crate) comm: String,
    /// /proc/<pid>/cmdline with its NULs as spaces: what the confirmation
    /// shows. The process may rewrite it, so it is not part of the identity.
    pub(crate) cmdline: String,
}

/// Sessions whose monitoring is parked (see [`exec_parked`]), with the
/// reconnect the monitor panel's one button sends for each.
#[derive(Debug, Default)]
pub(crate) struct ParkedMonitors(HashMap<String, ParkedMonitor>);

/// One parked session.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ParkedMonitor {
    /// The reconnect is out. The button stays off until it is back: one
    /// press, one challenge.
    pub(crate) resuming: bool,
    /// Why the last reconnect failed.
    pub(crate) error: Option<String>,
}

impl ParkedMonitors {
    /// A fetch found `session_id` parked. True the first time.
    pub(crate) fn park(&mut self, session_id: &str) -> bool {
        if self.0.contains_key(session_id) {
            return false;
        }
        let parked = ParkedMonitor::default();
        self.0.insert(session_id.to_string(), parked);
        true
    }

    /// A fetch came back with data, or the session is gone.
    pub(crate) fn unpark(&mut self, session_id: &str) {
        self.0.remove(session_id);
    }

    pub(crate) fn get(&self, session_id: &str) -> Option<&ParkedMonitor> {
        self.0.get(session_id)
    }

    /// "Reconnect monitoring" was pressed. True when the caller is to send
    /// the reconnect: the session is parked, and none is out already.
    pub(crate) fn begin_resume(&mut self, session_id: &str) -> bool {
        match self.0.get_mut(session_id) {
            Some(p) if !p.resuming => {
                p.resuming = true;
                p.error = None;
                true
            }
            _ => false,
        }
    }

    /// The reconnect came back. True when it re-opened a parked connection.
    pub(crate) fn finish_resume(&mut self, session_id: &str, result: Result<(), String>) -> bool {
        match result {
            Ok(()) => self.0.remove(session_id).is_some(),
            Err(e) => {
                if let Some(p) = self.0.get_mut(session_id) {
                    p.resuming = false;
                    p.error = Some(e);
                }
                false
            }
        }
    }
}

/// Column the listening-ports table is sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortSort {
    Proto,
    Addr,
    Port,
    Pid,
    Process,
}

pub(crate) fn net_detail_labels(iface_name: &str) -> (String, String, String, String, String, String, String, String) {
    let title = i18n::tf("netdetail.title", &[("name", iface_name)]);
    let close = i18n::t("netdetail.close").to_string();
    let lbl_iface = i18n::t("netdetail.interface").to_string();
    let lbl_rx = i18n::t("netdetail.rx").to_string();
    let lbl_tx = i18n::t("netdetail.tx").to_string();
    let lbl_total = i18n::t("netdetail.total_traffic").to_string();
    let lbl_type = i18n::t("netdetail.type").to_string();
    let if_type = if iface_name.starts_with("eth") || iface_name.starts_with("en") {
        i18n::t("netdetail.ethernet")
    } else if iface_name.starts_with("wl") {
        i18n::t("netdetail.wireless")
    } else if iface_name.starts_with("br-") || iface_name.starts_with("docker") {
        i18n::t("netdetail.docker")
    } else if iface_name.starts_with("veth") {
        i18n::t("netdetail.veth")
    } else if iface_name.starts_with("bond") {
        i18n::t("netdetail.bond")
    } else if iface_name.starts_with("tun") || iface_name.starts_with("tap") {
        i18n::t("netdetail.vpn")
    } else if iface_name.starts_with("lo") {
        i18n::t("netdetail.loopback")
    } else {
        i18n::t("netdetail.other")
    }.to_string();
    (title, close, lbl_iface, lbl_rx, lbl_tx, lbl_total, lbl_type, if_type)
}

/// Parse /proc-based process detail output into structured fields.
pub(crate) fn parse_process_detail(pid: u32, output: &str) -> ProcessDetailInfo {
    let mut fields = Vec::new();
    let mut children = Vec::new();
    let mut threads = Vec::new();
    let mut net_conns = Vec::new();
    let mut listen_ports = Vec::new();
    let mut open_fds = Vec::new();

    fields.push(("PID".into(), pid.to_string()));

    // Output format: ___TAG___\nbody\n___TAG2___\nbody2\n...
    // split("___") gives: ["", "TAG", "\nbody\n", "TAG2", "\nbody2\n", ...]
    // Tags are at odd indices (1,3,5,...), bodies at even indices (2,4,6,...)
    let sections: Vec<&str> = output.split("___").collect();
    let mut i = 1; // start at first tag
    while i + 1 < sections.len() {
        let tag = sections[i].trim();
        let body = sections.get(i + 1).map(|s| s.trim()).unwrap_or("");
        i += 2;
        match tag {
            "STATUS" => {
                for line in body.lines() {
                    if let Some((key, val)) = line.split_once(':') {
                        let key = key.trim();
                        // Replace tabs with spaces for clean display
                        let val: String = val.trim().chars()
                            .map(|c| if c == '\t' { ' ' } else { c })
                            .collect();
                        let val = val.trim().to_string();
                        match key {
                            "Name" | "State" | "PPid" | "Threads" => {
                                fields.push((key.into(), val));
                            }
                            "Uid" => {
                                // "0  0  0  0" → take first value
                                let first = val.split_whitespace().next().unwrap_or(&val);
                                fields.push(("Uid".into(), first.to_string()));
                            }
                            "Gid" => {
                                let first = val.split_whitespace().next().unwrap_or(&val);
                                fields.push(("Gid".into(), first.to_string()));
                            }
                            "VmRSS" | "VmSize" | "VmPeak" | "VmSwap" => {
                                fields.push((key.into(), val));
                            }
                            "voluntary_ctxt_switches" => {
                                fields.push(("CtxSwitch(V)".into(), val));
                            }
                            "nonvoluntary_ctxt_switches" => {
                                fields.push(("CtxSwitch(NV)".into(), val));
                            }
                            _ => {}
                        }
                    }
                }
            }
            "CMDLINE" => {
                if !body.is_empty() { fields.push(("Cmdline".into(), body.into())); }
            }
            "IO" => {
                for line in body.lines() {
                    if let Some((key, val)) = line.split_once(':') {
                        let (k, v) = (key.trim(), val.trim());
                        if let Ok(bytes) = v.parse::<u64>() {
                            fields.push((k.into(), format_bytes(bytes)));
                        }
                    }
                }
            }
            "CWD" => {
                if !body.is_empty() { fields.push(("CWD".into(), body.into())); }
            }
            "EXE" => {
                if !body.is_empty() { fields.push(("Executable".into(), body.into())); }
            }
            "FD_COUNT" => {
                if !body.is_empty() { fields.push(("Open FDs".into(), body.into())); }
            }
            "OOM" => {
                if !body.is_empty() { fields.push(("OOM Score".into(), body.into())); }
            }
            "PS" => {
                let parts: Vec<&str> = body.split_whitespace().collect();
                if parts.len() >= 8 {
                    fields.push(("User".into(), parts[2].into()));
                    fields.push(("Nice".into(), parts[3].into()));
                    fields.push(("VSZ".into(), format!("{} KB", parts[4])));
                    fields.push(("RSS".into(), format!("{} KB", parts[5])));
                    fields.push(("Elapsed".into(), parts[6].into()));
                    fields.push(("Stat".into(), parts[7].into()));
                }
            }
            "CHILDREN" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() { children.push(l.to_string()); }
                }
            }
            "THREADS" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() { threads.push(l.to_string()); }
                }
            }
            "NET" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() { net_conns.push(l.to_string()); }
                }
            }
            "LISTEN" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() { listen_ports.push(l.to_string()); }
                }
            }
            "LIMITS" => {
                for line in body.lines() {
                    let l = line.trim();
                    if l.is_empty() || l.starts_with("Limit") { continue; }
                    // Format: "Max open files            1048576              1048576              files"
                    // Clean up: replace multi-spaces/tabs → single space
                    let clean: String = l.split_whitespace().collect::<Vec<&str>>().join(" ");
                    if !clean.is_empty() {
                        fields.push(("Limit".into(), clean));
                    }
                }
            }
            "FDS" => {
                for line in body.lines() {
                    let l = line.trim();
                    if !l.is_empty() && !l.starts_with("total") {
                        // Extract just the symlink target: "... -> /path"
                        if let Some(pos) = l.find("->") {
                            // pos + 2 (end of "->") is always a char boundary and
                            // always <= len; pos + 3 is neither when the target
                            // starts with a multi-byte char or the line ends here.
                            // trim() still drops the separating space.
                            open_fds.push(l[pos + 2..].trim().to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    ProcessDetailInfo {
        pid,
        fields,
        children,
        threads,
        net_conns,
        listen_ports,
        open_fds,
        session_id: String::new(),
    }
}

/// Sort the listening-ports table; ties fall back to port, then protocol.
pub(crate) fn sort_ports(ports: &mut [crate::ssh::PortInfo], key: PortSort, desc: bool) {
    ports.sort_by(|a, b| {
        let primary = match key {
            PortSort::Proto => a.proto.cmp(&b.proto),
            PortSort::Addr => a.local_addr.cmp(&b.local_addr),
            PortSort::Port => a.port.cmp(&b.port),
            PortSort::Pid => a.pid.cmp(&b.pid),
            // Case-insensitive without allocating two strings per comparison.
            PortSort::Process => a
                .process
                .chars()
                .flat_map(char::to_lowercase)
                .cmp(b.process.chars().flat_map(char::to_lowercase)),
        };
        let ord = primary
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.proto.cmp(&b.proto));
        if desc {
            ord.reverse()
        } else {
            ord
        }
    });
}

/// A click on a column header: the same column flips direction, a new one
/// starts ascending — and the table is re-sorted now, in `update`, so the
/// view can draw `ports` as it stands.
pub(crate) fn resort_ports(
    ports: &mut [crate::ssh::PortInfo],
    sort: &mut PortSort,
    desc: &mut bool,
    key: PortSort,
) {
    if *sort == key {
        *desc = !*desc;
    } else {
        *sort = key;
        *desc = false;
    }
    sort_ports(ports, *sort, *desc);
}

/// `ProcIdentity` from /proc/<pid>/stat and /proc/<pid>/cmdline as `cat` and
/// `tr '\0' ' '` print them. `None` when there is no such process: nothing
/// was printed, or not a stat line.
pub(crate) fn parse_proc_identity(stat: &str, cmdline: &str) -> Option<ProcIdentity> {
    // "pid (comm) state ppid ...": comm may hold spaces and parentheses of
    // its own, so it runs to the LAST ')'.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close < open {
        return None;
    }
    // The fields after comm start at field 3 (state); starttime is field 22.
    let start_time = stat[close + 1..].split_whitespace().nth(22 - 3)?;
    if !start_time.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(ProcIdentity {
        start_time: start_time.to_string(),
        comm: stat[open + 1..close].to_string(),
        cmdline: cmdline.trim_end().to_string(),
    })
}

/// `ProcIdentity` from `ps -o lstart= -o args=` in the C locale, for a host
/// without /proc — a BSD or macOS one: the start time, five fields ("Mon Sep
/// 22 01:02:03 2026"), then the command line. `None` when `ps` printed no
/// such line: no such process.
pub(crate) fn parse_ps_identity(out: &str) -> Option<ProcIdentity> {
    let line = out.lines().find(|l| !l.trim().is_empty())?;
    let mut fields = Vec::with_capacity(5);
    let mut rest = line.trim_start();
    for _ in 0..5 {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        fields.push(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    let year_ok = !fields[4].is_empty() && fields[4].bytes().all(|b| b.is_ascii_digit());
    if !year_ok || !fields[3].contains(':') {
        return None;
    }
    let cmdline = rest.trim_end().to_string();
    Some(ProcIdentity {
        start_time: fields.join(" "),
        comm: cmdline.split_whitespace().next().unwrap_or("?").to_string(),
        cmdline,
    })
}

/// Read `pid`'s [`ProcIdentity`] over the session's exec connection: plain
/// reads of /proc — any shell runs them, fish included — with nothing in
/// them but the pid. A host without /proc answers through `ps` instead.
pub(crate) fn read_proc_identity(
    ssh: &SshManager,
    session_id: &str,
    pid: u32,
) -> Result<Option<ProcIdentity>, String> {
    let stat = ssh.exec_command(
        session_id,
        &format!("cat /proc/{}/stat 2>/dev/null || test -d /proc/self || echo NOPROC", pid),
    )?;
    if stat.trim() == "NOPROC" {
        let ps = ssh.exec_command(
            session_id,
            &format!("env LC_ALL=C ps -ww -o lstart= -o args= -p {} 2>/dev/null", pid),
        )?;
        return Ok(parse_ps_identity(&ps));
    }
    let cmdline = ssh.exec_command(
        session_id,
        &format!("tr '\\0' ' ' < /proc/{}/cmdline 2>/dev/null", pid),
    )?;
    Ok(parse_proc_identity(&stat, &cmdline))
}

/// Whether two reads of a pid found the same process: the same start time.
/// A process may rename itself or rewrite its command line (postgres
/// backends do, per query); only a new process gets a new start time.
pub(crate) fn same_process(confirmed: &ProcIdentity, now: &ProcIdentity) -> bool {
    confirmed.start_time == now.start_time
}

/// What the kill confirmation shows for a process: its command line as /proc
/// has it, with whatever would not show made visible, else "[comm]" — a
/// kernel thread has no command line — as `ps` shows it.
pub(crate) fn kill_command_label(identity: &ProcIdentity) -> String {
    let line = if identity.cmdline.trim().is_empty() {
        format!("[{}]", identity.comm)
    } else {
        identity.cmdline.clone()
    };
    truncate_str(&visible_text(&line), 600)
}

pub(crate) fn signal_name(signal: i32) -> String {
    match signal {
        1 => "SIGHUP".to_string(),
        2 => "SIGINT".to_string(),
        9 => "SIGKILL".to_string(),
        15 => "SIGTERM".to_string(),
        n => i18n::tf("process.signal_n", &[("n", &n.to_string())]),
    }
}
