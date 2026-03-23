use std::rc::Rc;

use adw::prelude::*;

use crate::bridge::{BackendCommand, BackendHandle};
use crate::window::GuiState;

const STATUS_ROW_ID: &str = "server-status-row";
const LOCKFILES_ROW_ID: &str = "server-lockfiles-row";
const BORG_VERSION_ROW_ID: &str = "server-borg-version-row";

pub fn build_view(state: Rc<GuiState>, backend: BackendHandle) -> gtk::Box {
    let view = gtk::Box::new(gtk::Orientation::Vertical, 0);
    view.set_margin_top(24);
    view.set_margin_bottom(24);
    view.set_margin_start(24);
    view.set_margin_end(24);

    let clamp = adw::Clamp::builder().maximum_size(800).build();
    let inner = gtk::Box::new(gtk::Orientation::Vertical, 16);

    // Server info group
    let info_group = adw::PreferencesGroup::builder()
        .title("Server")
        .build();

    let host_row = adw::ActionRow::builder()
        .title("Host")
        .subtitle("—")
        .activatable(false)
        .build();

    let mac_row = adw::ActionRow::builder()
        .title("MAC Address")
        .subtitle("—")
        .activatable(false)
        .build();

    let status_row = adw::ActionRow::builder()
        .title("Status")
        .subtitle("Checking...")
        .activatable(false)
        .build();
    status_row.set_widget_name(STATUS_ROW_ID);

    let lockfiles_row = adw::ActionRow::builder()
        .title("Active Backups")
        .subtitle("—")
        .activatable(false)
        .build();
    lockfiles_row.set_widget_name(LOCKFILES_ROW_ID);

    info_group.add(&host_row);
    info_group.add(&mac_row);
    info_group.add(&status_row);
    info_group.add(&lockfiles_row);

    // Borg group
    let borg_group = adw::PreferencesGroup::builder()
        .title("Borg")
        .build();

    let borg_version_row = adw::ActionRow::builder()
        .title("Version")
        .subtitle("—")
        .activatable(false)
        .build();
    borg_version_row.set_widget_name(BORG_VERSION_ROW_ID);

    borg_group.add(&borg_version_row);

    // Actions group
    let actions_group = adw::PreferencesGroup::builder()
        .title("Actions")
        .build();

    let wake_btn = gtk::Button::builder()
        .label("Wake Server")
        .css_classes(["suggested-action"])
        .valign(gtk::Align::Center)
        .build();
    let backend_wake = backend.clone();
    wake_btn.connect_clicked(move |_| {
        backend_wake.send(BackendCommand::WakeServer);
    });

    let check_btn = gtk::Button::builder()
        .label("Check Connectivity")
        .valign(gtk::Align::Center)
        .build();
    let backend_check = backend.clone();
    check_btn.connect_clicked(move |_| {
        backend_check.send(BackendCommand::CheckServerReachable);
    });

    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    btn_box.set_margin_top(8);
    btn_box.append(&wake_btn);
    btn_box.append(&check_btn);

    let action_row = adw::ActionRow::builder()
        .activatable(false)
        .build();
    action_row.add_suffix(&btn_box);
    actions_group.add(&action_row);

    inner.append(&info_group);
    inner.append(&borg_group);
    inner.append(&actions_group);
    clamp.set_child(Some(&inner));
    view.append(&clamp);

    // Fill initial data from config
    {
        let cfg = state.config.borrow();
        if let Some(ref c) = *cfg {
            host_row.set_subtitle(&c.server.host);
            mac_row.set_subtitle(&c.server.mac);
        }
    }

    view
}

pub fn refresh(view: &gtk::Box, state: &Rc<GuiState>) {
    // Update config-based rows
    if let Some(ref cfg) = *state.config.borrow() {
        if let Some(row) = find_action_row(view, "Host") {
            row.set_subtitle(&cfg.server.host);
        }
        if let Some(row) = find_action_row(view, "MAC Address") {
            row.set_subtitle(&cfg.server.mac);
        }
    }

    // Update status
    let online = *state.server_online.borrow();
    if let Some(row) = find_row_by_name(view, STATUS_ROW_ID) {
        row.set_subtitle(if online { "Online" } else { "Offline" });
    }

    // Update lockfiles
    let lockfiles = state.lockfiles.borrow();
    if let Some(row) = find_row_by_name(view, LOCKFILES_ROW_ID) {
        if lockfiles.is_empty() {
            row.set_subtitle("None");
        } else {
            row.set_subtitle(&lockfiles.join(", "));
        }
    }

    // Update borg version
    let version = state.borg_version.borrow();
    if let Some(row) = find_row_by_name(view, BORG_VERSION_ROW_ID) {
        row.set_subtitle(version.as_deref().unwrap_or("Not detected"));
    }
}

fn find_action_row(view: &gtk::Box, title: &str) -> Option<adw::ActionRow> {
    fn walk(widget: &gtk::Widget, title: &str) -> Option<adw::ActionRow> {
        if let Some(row) = widget.downcast_ref::<adw::ActionRow>() {
            if row.title() == title {
                return Some(row.clone());
            }
        }
        let mut child = widget.first_child();
        while let Some(c) = child {
            if let Some(found) = walk(&c, title) {
                return Some(found);
            }
            child = c.next_sibling();
        }
        None
    }
    walk(view.upcast_ref(), title)
}

fn find_row_by_name(view: &gtk::Box, name: &str) -> Option<adw::ActionRow> {
    fn walk(widget: &gtk::Widget, name: &str) -> Option<adw::ActionRow> {
        if widget.widget_name() == name {
            return widget.downcast_ref::<adw::ActionRow>().cloned();
        }
        let mut child = widget.first_child();
        while let Some(c) = child {
            if let Some(found) = walk(&c, name) {
                return Some(found);
            }
            child = c.next_sibling();
        }
        None
    }
    walk(view.upcast_ref(), name)
}
