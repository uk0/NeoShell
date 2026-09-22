use super::*;
// Explicit: through the glob above, `column` is ambiguous with std's `column!`.
use iced::widget::column;

pub(crate) fn view_local_files(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    let path_input = input("Local path...", &state.local_path)
        .id(text_input::Id::new(LOCAL_PATH_INPUT_ID))
        .on_input(Message::LocalPathChanged)
        .on_submit(Message::LocalPathSubmit)
        .padding(4)
        .size(11.0 * scale);

    let refresh_btn = button(text(i18n::t("btn.refresh")).color(c_accent).size(11.0 * scale))
        .on_press(Message::RefreshLocalFiles)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    // Upload button (visible when a file is selected)
    let upload_area: Element<'_, Message> = if let Some(ref sel) = state.selected_local_file {
        let fname = std::path::Path::new(sel).file_name()
            .map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        button(
            text(format!("{} {}", i18n::t("file.send_prefix"), fname)).size(10.0 * scale)
        )
        .on_press(Message::UploadLocalFile)
        .padding(Padding::from([3, 8]))
        .style(accent_button_style)
        .into()
    } else {
        Space::new(0, 0).into()
    };

    let header = container(
        column![
            row![path_input, tip(refresh_btn, i18n::t("log.refresh"))]
                .spacing(2)
                .align_y(alignment::Vertical::Center)
                .padding(Padding::from([2, 4])),
            upload_area,
        ].spacing(2)
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        ..Default::default()
    });

    // File list
    let entries = if state.local_entries.is_empty() {
        list_local_dir(&state.local_path)
    } else {
        state.local_entries.clone()
    };

    let mut file_col = column![].spacing(0);

    // Parent directory
    if let Some(parent) = std::path::Path::new(&state.local_path).parent() {
        let parent_path = parent.to_string_lossy().to_string();
        file_col = file_col.push(tip(
            button(text("..").color(c_accent).size(10.0 * scale))
                .on_press(Message::LocalFileClicked(parent_path))
                .padding(Padding::from([2, 6]))
                .width(Fill)
                .style(sidebar_item_style),
            i18n::t("tip.parent_dir"),
        ));
    }

    for (i, entry) in entries.iter().enumerate() {
        let (icon, color) = if entry.is_dir { ("D", theme::ACCENT) } else { ("F", theme::TEXT_PRIMARY) };
        let size_str = if entry.is_dir { String::new() } else { format_bytes(entry.size) };
        let path = entry.path.clone();
        let is_selected = state.selected_local_file.as_deref() == Some(&entry.path);
        let row_bg = if is_selected {
            theme::BG_HOVER
        } else if i % 2 == 0 {
            theme::BG_SECONDARY
        } else {
            theme::BG_TERTIARY
        };

        let entry_row = row![
            text(format!("{} {}", icon, &entry.name)).color(color).size(10.0 * scale).width(Fill),
            text(size_str).color(theme::TEXT_MUTED).size(9.0 * scale),
        ].spacing(4);

        file_col = file_col.push(
            button(
                container(entry_row).padding(Padding::from([2, 6])).width(Fill)
                    .style(move |_| container::Style { background: Some(row_bg.into()), ..Default::default() })
            )
            .on_press(Message::LocalFileClicked(path))
            .padding(0).width(Fill)
            .style(|_: &Theme, status| {
                let mut s = button::Style::default();
                if let button::Status::Hovered = status { s.background = Some(theme::BG_HOVER.into()); }
                s
            })
        );
    }

    column![header, slim_scroll(file_col).height(Fill)]
        .width(Fill)
        .height(Fill)
        .into()
}

pub(crate) fn view_file_browser(state: &NeoShell) -> Element<'_, Message> {
    #[allow(unused_variables)] let scale = state.ui_scale();
    #[allow(unused_variables)] let c_primary = state.c_primary();
    #[allow(unused_variables)] let c_accent = state.c_accent();
    #[allow(unused_variables)] let c_success = state.c_success();
    #[allow(unused_variables)] let c_danger = state.c_danger();
    // The focused pane's session, split panes included.
    let active_session = state
        .active_tab
        .and_then(|idx| state.tabs.get(idx))
        .map(|t| t.focused_session().to_string());

    let sid = match &active_session {
        Some(s) => s.clone(),
        None => return Space::new(Fill, 0).into(),
    };
    // Its exec connection — SFTP runs on it too — is parked: say so, with the
    // one button that re-opens it, as the monitor panel does.
    if let Some(parked) = state.monitor_parked.get(&sid) {
        return view_monitor_parked(&sid, parked, "files.parked", scale, c_primary, c_danger);
    }

    let current_path = state
        .current_dir
        .get(&sid)
        .map(|s| s.as_str())
        .unwrap_or("~");

    let listing = state.file_entries.get(&sid);

    // Header with editable path input and upload button
    let path_value = if state.path_input.is_empty() {
        current_path.to_string()
    } else {
        state.path_input.clone()
    };

    let path_input = input("/path/to/dir", &path_value)
        .id(text_input::Id::new(REMOTE_PATH_INPUT_ID))
        .on_input(Message::PathInputChanged)
        .on_submit(Message::PathInputSubmit)
        .padding(4)
        .size(12.0 * scale);

    let upload_btn = button(text(i18n::t("filebrowser.upload")).color(c_success).size(11.0 * scale))
        .on_press(Message::UploadFile)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    // A whole local folder, through the recursive transfer.
    let upload_dir_btn = tip(
        button(text(i18n::t("filebrowser.upload_dir")).color(c_success).size(11.0 * scale))
            .on_press(Message::UploadDir)
            .padding(Padding::from([4, 8]))
            .style(transparent_button_style),
        i18n::t("tip.upload_dir"),
    );

    let remote_refresh = button(text(i18n::t("btn.refresh")).color(c_accent).size(11.0 * scale))
        .on_press(Message::RefreshRemoteFiles)
        .padding(Padding::from([4, 8]))
        .style(transparent_button_style);

    let header = container(
        row![path_input, tip(remote_refresh, i18n::t("log.refresh")), upload_btn, upload_dir_btn]
            .spacing(4)
            .align_y(alignment::Vertical::Center),
    )
    .padding(Padding::from([4, 6]))
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        border: iced::Border {
            color: theme::BORDER,
            width: 1.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    });

    // Column headers
    let file_header = container(
        row![
            container(text(i18n::t("file.name")).color(theme::TEXT_MUTED).size(10.0 * scale)).width(Fill),
            container(text(i18n::t("file.size")).color(theme::TEXT_MUTED).size(10.0 * scale)).width(80).align_x(alignment::Horizontal::Right),
            container(text(i18n::t("file.modified")).color(theme::TEXT_MUTED).size(10.0 * scale)).width(120).align_x(alignment::Horizontal::Center),
            container(Space::new(70, 0)).width(70),
        ].spacing(4).padding(Padding::from([2, 8]))
    )
    .width(Fill)
    .style(|_| container::Style {
        background: Some(theme::BG_TERTIARY.into()),
        ..Default::default()
    });

    let mut file_col = column![file_header].spacing(0);
    // Directory the right-click menu acts in: the listing's on screen.
    let menu_dir = state.browser_dir(&sid).unwrap_or_else(|| "~".to_string());

    if let Some(listing) = listing {
        let entries = &listing.entries;
        // Build unified file entries (including ".." parent)
        let mut all_entries: Vec<&FileEntry> = Vec::new();
        // Create a static parent entry
        let parent_entry = FileEntry {
            name: "..".to_string(),
            is_dir: true,
            ..FileEntry::default()
        };
        all_entries.push(&parent_entry);
        for e in entries.iter().filter(|e| e.name != "..") {
            all_entries.push(e);
        }

        for entry in &all_entries {
            // The letter says what the row is — the kind a rename, a chmod
            // or a delete from it is checked against.
            let (icon, name_color) = if entry.name == ".." {
                ("..", theme::ACCENT)
            } else {
                match entry.kind() {
                    EntryKind::Dir => ("D", theme::ACCENT),
                    EntryKind::File => ("F", theme::TEXT_PRIMARY),
                    EntryKind::Symlink => ("L", theme::TEXT_PRIMARY),
                    EntryKind::Other => ("?", theme::TEXT_PRIMARY),
                }
            };

            // The name exactly: spaces at its ends or in a run, and anything
            // invisible, are marked (`visible_name`). A long one loses its
            // middle, not its end, and shows whole in a tooltip.
            let shown_name = visible_name(&entry.name);
            let (display_name, name_cut) = if entry.name == ".." {
                ("..".to_string(), false)
            } else {
                let short = truncate_middle_to_width(&shown_name, 28);
                let cut = short != shown_name;
                (format!("{} {}", icon, short), cut)
            };

            let human_size = if entry.size.is_empty() { "".to_string() } else { humanize_file_size(&entry.size) };
            let date_str = if entry.modified.is_empty() { "".to_string() } else { entry.modified.clone() };

            // Build action buttons (fixed 50px column, always present for alignment)
            // Every path from the listing this row is on (see `Listing`).
            let actions: Element<'_, Message> = if !entry.is_dir && entry.name != ".." {
                let full_path = listing.path_of(&entry.name);

                let dl_btn = tip(
                    button(text(i18n::t("btn.download")).color(c_accent).size(10.0 * scale))
                        .on_press(Message::DownloadFile(sid.clone(), full_path.clone()))
                        .padding(Padding::from([1, 3]))
                        .style(transparent_button_style),
                    i18n::t("update.download_btn"),
                );

                if crate::ssh::is_editable_file(&entry.name) {
                    let edit_btn = tip(
                        button(text(i18n::t("btn.edit")).color(c_success).size(10.0 * scale))
                            .on_press(Message::OpenEditor(sid.clone(), full_path))
                            .padding(Padding::from([1, 3]))
                            .style(transparent_button_style),
                        i18n::t("dialog.edit"),
                    );
                    row![dl_btn, edit_btn].spacing(2).into()
                } else {
                    dl_btn
                }
            } else if entry.name != ".." {
                // A folder downloads whole, through the recursive transfer.
                let full_path = listing.path_of(&entry.name);
                tip(
                    button(text(i18n::t("btn.download")).color(c_accent).size(10.0 * scale))
                        .on_press(Message::DownloadDir(sid.clone(), full_path))
                        .padding(Padding::from([1, 3]))
                        .style(transparent_button_style),
                    i18n::t("tip.download_dir"),
                )
            } else {
                Space::new(0, 0).into()
            };

            // Unified columns: Name(left,fill) | Size(right,80) | Date(center,110) | Actions(right,50)
            let name_text = tip_if(
                text(display_name).color(name_color).size(11.0 * scale),
                name_cut,
                &shown_name,
            );
            let entry_row = row![
                container(name_text).width(Fill),
                container(text(human_size).color(theme::TEXT_MUTED).size(10.0 * scale))
                    .width(80).align_x(alignment::Horizontal::Right),
                container(text(date_str).color(theme::TEXT_MUTED).size(10.0 * scale))
                    .width(120).align_x(alignment::Horizontal::Center),
                container(actions).width(70).align_x(alignment::Horizontal::Right)
                    .padding(Padding::new(0.0).right(14.0)),
            ]
            .spacing(4)
            .align_y(alignment::Vertical::Center);

            // All entries use same wrapper (button for dirs, container for files)
            let row_el: Element<'_, Message> = if entry.is_dir {
                let entry_clone = (*entry).clone();
                let sid_clone = sid.clone();
                let dir_btn = button(entry_row)
                    .on_press(Message::FileClicked(sid_clone, listing.dir.clone(), entry_clone))
                    .padding(Padding::from([2, 8]))
                    .width(Fill)
                    .style(sidebar_item_style);
                if entry.name == ".." {
                    tip(dir_btn, i18n::t("tip.parent_dir"))
                } else {
                    dir_btn.into()
                }
            } else {
                container(entry_row)
                    .padding(Padding::from([2, 8]))
                    .width(Fill)
                    .into()
            };
            // Right-click: rename / permissions / delete this row.
            let menu_entry = (entry.name != "..").then(|| (*entry).clone());
            file_col = file_col.push(
                iced::widget::mouse_area(row_el)
                    .on_right_press(Message::RemoteMenuOpen(sid.clone(), menu_dir.clone(), menu_entry)),
            );
        }
    } else {
        file_col = file_col.push(
            container(text(i18n::t("filebrowser.loading")).color(theme::TEXT_MUTED).size(12.0 * scale))
                .padding(Padding::from([8, 10])),
        );
    }

    // A right-click on the list outside any row still offers "New folder".
    let list = iced::widget::mouse_area(slim_scroll(file_col).height(Fill))
        .on_right_press(Message::RemoteMenuOpen(sid.clone(), menu_dir, None));

    column![header, list]
        .height(Length::Fixed(200.0))
        .into()
}

// ---- Network detail popup ------------------------------------------------

// ---- Quick-connect dialog (open new tab to any saved connection) ----------
