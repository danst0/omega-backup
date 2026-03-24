use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;

use crate::bridge::{BackendCommand, BackendHandle};
use crate::window::GuiState;

/// Holds direct references to the rows we need to update.
struct ServerInner {
    host_row: adw::ActionRow,
    mac_row: adw::ActionRow,
    status_row: adw::ActionRow,
    lockfiles_row: adw::ActionRow,
    borg_version_row: adw::ActionRow,
}

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

    let lockfiles_row = adw::ActionRow::builder()
        .title("Active Backups")
        .subtitle("—")
        .activatable(false)
        .build();

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

    let action_row = adw::ActionRow::builder().activatable(false).build();
    action_row.add_suffix(&btn_box);
    actions_group.add(&action_row);

    inner.append(&info_group);
    inner.append(&borg_group);
    inner.append(&actions_group);
    clamp.set_child(Some(&inner));
    view.append(&clamp);

    // Store direct references
    let server_inner = Rc::new(RefCell::new(ServerInner {
        host_row,
        mac_row,
        status_row,
        lockfiles_row,
        borg_version_row,
    }));
    unsafe {
        view.set_data("server-inner", server_inner);
    }

    view
}

pub fn refresh(view: &gtk::Box, state: &Rc<GuiState>) {
    let server: Option<Rc<RefCell<ServerInner>>> = unsafe {
        view.data::<Rc<RefCell<ServerInner>>>("server-inner")
            .map(|p| (*p.as_ref()).clone())
    };
    let Some(server) = server else { return };
    let s = server.borrow();

    // Update config-based rows
    if let Some(ref cfg) = *state.config.borrow() {
        s.host_row.set_subtitle(&cfg.server.host);
        s.mac_row.set_subtitle(&cfg.server.mac);
    }

    // Update status
    let online = *state.server_online.borrow();
    s.status_row
        .set_subtitle(if online { "Online" } else { "Offline" });

    // Update lockfiles
    let lockfiles = state.lockfiles.borrow();
    if lockfiles.is_empty() {
        s.lockfiles_row.set_subtitle("None");
    } else {
        s.lockfiles_row.set_subtitle(&lockfiles.join(", "));
    }

    // Update borg version
    let version = state.borg_version.borrow();
    s.borg_version_row
        .set_subtitle(version.as_deref().unwrap_or("Not detected"));
}
