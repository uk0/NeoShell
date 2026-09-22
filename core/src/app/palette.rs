use super::*;

/// One entry in the Cmd+K command palette.
pub(crate) struct PaletteItem {
    pub(crate) label: String,
    pub(crate) meta: String,
    /// Short i18n'd kind tag rendered as a chip: 连接 / 动作 / 片段.
    pub(crate) kind: &'static str,
    pub(crate) msg: Message,
    pub(crate) score: i32,
}

/// Case-insensitive subsequence fuzzy match. Returns None when `query`
/// is not a subsequence of `target`; higher score = better match
/// (prefix + consecutive-run bonuses, mild length penalty).
pub(crate) fn fuzzy_score(query: &str, target: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    // Folded as the sidebar search folds: full-width letters typed through
    // a Chinese input method match their ASCII selves.
    let q: Vec<char> = search_fold(query).chars().collect();
    let t: Vec<char> = search_fold(target).chars().collect();
    let mut qi = 0usize;
    let mut score = 0i32;
    let mut last_hit: Option<usize> = None;
    for (ti, &tc) in t.iter().enumerate() {
        if qi < q.len() && tc == q[qi] {
            score += 10;
            if ti == 0 {
                score += 8;
            }
            if let Some(lh) = last_hit {
                if ti == lh + 1 {
                    score += 6;
                }
            }
            last_hit = Some(ti);
            qi += 1;
        }
    }
    if qi == q.len() {
        Some(score - (t.len() as i32) / 4)
    } else {
        None
    }
}

/// Rows the palette shows at most — its list does not scroll.
pub(crate) const PALETTE_MAX: usize = 12;

/// Display columns a palette row gives its label and its meta at the default
/// UI font size. The card's width is fixed, so both shrink as the font grows
/// (`cols_at_scale`), as the sidebar's do.
pub(crate) const PALETTE_LABEL_COLS: usize = 40;
pub(crate) const PALETTE_META_COLS: usize = 32;

/// A palette row's label and meta cut to its column budgets at UI `scale`,
/// each with whether it was cut.
pub(crate) fn palette_row_text(label: &str, meta: &str, scale: f32) -> ((String, bool), (String, bool)) {
    (
        clip_to_width(label, cols_at_scale(PALETTE_LABEL_COLS, scale)),
        clip_to_width(meta, cols_at_scale(PALETTE_META_COLS, scale)),
    )
}

/// Build the Cmd+K palette item list for `query`, sorted by fuzzy score.
/// Connections first-class, then actions, then snippets.
///
/// Every matching connection's own entry is kept: past [`PALETTE_MAX`] the
/// lowest-placed entry that is *not* a connection goes first, so neither an
/// action nor a snippet can push a connection out of reach. Only when nothing
/// but connections is left do the lowest-ranked of those go, as they always
/// did. The row actions (edit / test / clone / delete) are offered for the
/// single best match only, right under it — four per match used to fill the
/// list with actions and push the other connections off it.
pub(crate) fn build_palette_items(
    query: &str,
    connections: &[ConnectionInfo],
    snippets: &[Snippet],
    collapsed_groups: &HashSet<String>,
) -> Vec<PaletteItem> {
    let q = query.trim();
    let mut items: Vec<PaletteItem> = Vec::new();

    // Connections the palette ranks the same keep the sidebar's order.
    let mut ordered: Vec<&ConnectionInfo> = connections.iter().collect();
    ordered.sort_by(|a, b| connection_order(a, b));
    let rank: HashMap<&str, usize> =
        ordered.iter().enumerate().map(|(n, c)| (c.id.as_str(), n)).collect();

    for c in ordered {
        let label = c.name.clone();
        let meta = format!("{}@{}:{}", c.username, c.host, c.port);
        // The group as the sidebar shows it: "Ungrouped" finds those too.
        let hay = format!("{} {} {}", c.name, meta, group_label(&c.group));
        if let Some(s) = fuzzy_score(q, &hay) {
            items.push(PaletteItem {
                label,
                meta,
                kind: "palette.kind.conn",
                msg: Message::ConnectTo(c.id.clone()),
                score: s + 5, // connections get a small priority bump
            });
        }
    }

    let actions: &[(&str, Message)] = &[
        ("palette.act.new_conn",   Message::ShowForm(None)),
        ("palette.act.connect",    Message::ShowConnectDialog),
        ("palette.act.settings",   Message::ShowSettings),
        ("palette.act.broadcast",  Message::ShowBroadcastDialog),
        ("palette.act.snippets",   Message::ShowSnippetsPanel),
        ("palette.act.keys",       Message::ShowKeyManager),
        ("palette.act.tunnels",    Message::ShowTunnelManager),
        ("palette.act.proxies",    Message::ShowProxyManager),
        ("palette.act.history",    Message::ShowHistory),
        ("palette.act.logs",       Message::ShowLogViewer),
        ("palette.act.sync",       Message::ToggleSyncInput),
        ("palette.act.split_v",    Message::SplitTab(true)),
        ("palette.act.split_h",    Message::SplitTab(false)),
        ("palette.act.import_ssh", Message::ImportAllSshConfigs),
        ("sidebar.collapse_all",   Message::SetAllGroupsCollapsed(true)),
        ("sidebar.expand_all",     Message::SetAllGroupsCollapsed(false)),
    ];
    for (key, msg) in actions {
        let label = i18n::t(key).to_string();
        if let Some(s) = fuzzy_score(q, &label) {
            items.push(PaletteItem {
                label,
                meta: String::new(),
                kind: "palette.kind.action",
                msg: msg.clone(),
                score: s,
            });
        }
    }

    // The keyboard's way to fold one sidebar group (iced 0.13 buttons cannot
    // take focus): type its name. Only for a typed query, like row actions.
    if !q.is_empty() {
        let mut seen: HashSet<&str> = HashSet::new();
        for c in connections {
            if !seen.insert(c.group.as_str()) {
                continue;
            }
            let name = group_label(&c.group);
            if let Some(s) = fuzzy_score(q, &name) {
                let key = if collapsed_groups.contains(&c.group) {
                    "palette.act.expand_group"
                } else {
                    "palette.act.collapse_group"
                };
                items.push(PaletteItem {
                    label: i18n::tf(key, &[("name", &name)]),
                    meta: String::new(),
                    kind: "palette.kind.action",
                    msg: Message::ToggleGroupCollapsed(c.group.clone()),
                    score: s,
                });
            }
        }
    }

    for sn in snippets {
        let hay = format!("{} {}", sn.name, sn.body);
        if let Some(s) = fuzzy_score(q, &hay) {
            items.push(PaletteItem {
                label: sn.name.clone(),
                meta: sn.body.chars().take(40).collect(),
                kind: "palette.kind.snippet",
                msg: Message::SnippetSend(sn.id.clone()),
                score: s,
            });
        }
    }

    // Best score first; among equals, connections first in the sidebar's
    // order, then the rest by label.
    let conn_rank = |it: &PaletteItem| match &it.msg {
        Message::ConnectTo(id) => rank.get(id.as_str()).copied(),
        _ => None,
    };
    items.sort_by(|a, b| {
        b.score.cmp(&a.score).then_with(|| match (conn_rank(a), conn_rank(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.label.cmp(&b.label),
        })
    });

    // Keyboard route to the row actions the sidebar only shows on hover
    // (iced 0.13 buttons cannot take focus) — for the best match, and only
    // for a typed query, so the empty palette keeps its action list.
    let best = if q.is_empty() {
        None
    } else {
        items.iter().enumerate().find_map(|(at, it)| match &it.msg {
            Message::ConnectTo(id) => Some((at, id.clone())),
            _ => None,
        })
    };
    if let Some((at, id)) = best {
        let best = &items[at];
        let row_actions = [
            ("palette.act.edit_conn", Message::ShowForm(Some(id.clone()))),
            (
                "palette.act.test_conn",
                Message::TestConnectionInList(id.clone()),
            ),
            (
                "palette.act.clone_conn",
                Message::CloneConnection(id.clone()),
            ),
            ("palette.act.delete_conn", Message::DeleteConnection(id)),
        ]
        .map(|(key, msg)| PaletteItem {
            label: i18n::tf(key, &[("name", &best.label)]),
            meta: best.meta.clone(),
            kind: "palette.kind.action",
            msg,
            score: best.score - 5,
        });
        items.splice(at + 1..at + 1, row_actions);
    }

    let is_connection = |it: &PaletteItem| matches!(it.msg, Message::ConnectTo(_));
    while items.len() > PALETTE_MAX {
        match items.iter().rposition(|it| !is_connection(it)) {
            Some(i) => {
                items.remove(i);
            }
            None => items.truncate(PALETTE_MAX),
        }
    }
    items
}

// ---------------------------------------------------------------------------
// Application entry point
// ---------------------------------------------------------------------------
