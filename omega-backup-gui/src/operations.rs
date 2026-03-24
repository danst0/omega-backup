use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::bridge::{BackendCommand, BackendHandle};
use crate::window::GuiState;

const RUNNING_BANNER_ID: &str = "running-banner";

pub fn build_view(state: Rc<GuiState>, backend: BackendHandle) -> gtk::Box {
    let view = gtk::Box::new(gtk::Orientation::Vertical, 0);
    view.set_margin_top(24);
    view.set_margin_bottom(24);
    view.set_margin_start(24);
    view.set_margin_end(24);

    let clamp = adw::Clamp::builder().maximum_size(800).build();
    let inner = gtk::Box::new(gtk::Orientation::Vertical, 16);

    // ── Running operation banner ───────────────────────────────
    let banner = adw::Banner::builder()
        .title("Operation in progress...")
        .revealed(false)
        .build();
    banner.set_widget_name(RUNNING_BANNER_ID);
    inner.append(&banner);

    // ── Maintenance ────────────────────────────────────────────
    let maint_group = adw::PreferencesGroup::builder()
        .title("Maintenance")
        .description("Prune, compact, and check all client repos")
        .build();

    let skip_check = adw::SwitchRow::builder()
        .title("Skip integrity check")
        .subtitle("Only run prune and compact")
        .build();
    maint_group.add(&skip_check);

    let maint_btn = gtk::Button::builder()
        .label("Run Maintenance")
        .css_classes(["suggested-action"])
        .margin_top(8)
        .build();
    let backend_maint = backend.clone();
    let skip_check_ref = skip_check.clone();
    maint_btn.connect_clicked(move |btn| {
        btn.set_sensitive(false);
        backend_maint.send(BackendCommand::RunMaintenance {
            skip_check: skip_check_ref.is_active(),
            repo: None,
        });
    });
    let maint_btn_row = adw::ActionRow::builder().activatable(false).build();
    maint_btn_row.add_suffix(&maint_btn);
    maint_group.add(&maint_btn_row);
    inner.append(&maint_group);

    // ── Restore Test ───────────────────────────────────────────
    let restore_group = adw::PreferencesGroup::builder()
        .title("Restore Test")
        .description("Verify backup integrity by extracting random files")
        .build();

    let client_combo = build_client_combo(&state, "Client");
    restore_group.add(&client_combo);

    let sample_spin = adw::SpinRow::builder()
        .title("Sample count")
        .subtitle("Number of random files to verify")
        .adjustment(&gtk::Adjustment::new(5.0, 1.0, 50.0, 1.0, 5.0, 0.0))
        .build();
    restore_group.add(&sample_spin);

    let restore_btn = gtk::Button::builder()
        .label("Run Restore Test")
        .css_classes(["suggested-action"])
        .margin_top(8)
        .build();
    let backend_restore = backend.clone();
    let client_combo_ref = client_combo.clone();
    let sample_ref = sample_spin.clone();
    restore_btn.connect_clicked(move |btn| {
        let client = selected_string(&client_combo_ref);
        if client.is_empty() {
            return;
        }
        btn.set_sensitive(false);
        backend_restore.send(BackendCommand::RunRestoreTest {
            client,
            repo: "main".into(),
            list_count: 5,
            sample_count: sample_ref.value() as usize,
        });
    });
    let restore_btn_row = adw::ActionRow::builder().activatable(false).build();
    restore_btn_row.add_suffix(&restore_btn);
    restore_group.add(&restore_btn_row);
    inner.append(&restore_group);

    // ── Init ───────────────────────────────────────────────────
    let init_group = adw::PreferencesGroup::builder()
        .title("Initialize")
        .description("Initialize borg repositories for clients")
        .build();

    let init_combo = build_client_combo_with_all(&state);
    init_group.add(&init_combo);

    let init_btn = gtk::Button::builder()
        .label("Run Init")
        .css_classes(["suggested-action"])
        .margin_top(8)
        .build();
    let backend_init = backend.clone();
    let init_combo_ref = init_combo.clone();
    init_btn.connect_clicked(glib::clone!(
        #[weak]
        view,
        move |btn| {
            let selected = selected_string(&init_combo_ref);
            let target = if selected == "All" {
                "all clients".to_string()
            } else {
                format!("\"{selected}\"")
            };
            let backend_clone = backend_init.clone();
            let client = if selected == "All" {
                None
            } else {
                Some(selected)
            };
            let dialog = adw::AlertDialog::builder()
                .heading("Initialize Repositories?")
                .body(format!(
                    "This will initialize borg repositories for {target}. Existing repos will not be overwritten."
                ))
                .build();
            dialog.add_responses(&[("cancel", "Cancel"), ("init", "Initialize")]);
            dialog.set_response_appearance("init", adw::ResponseAppearance::Suggested);
            dialog.set_default_response(Some("cancel"));
            dialog.set_close_response("cancel");
            let btn_clone = btn.clone();
            dialog.connect_response(None, move |_, response| {
                if response == "init" {
                    btn_clone.set_sensitive(false);
                    backend_clone.send(BackendCommand::RunInit {
                        client: client.clone(),
                    });
                }
            });
            if let Some(w) = view.root().and_then(|r| r.downcast::<gtk::Window>().ok()) {
                dialog.present(Some(&w));
            }
        }
    ));
    let init_btn_row = adw::ActionRow::builder().activatable(false).build();
    init_btn_row.add_suffix(&init_btn);
    init_group.add(&init_btn_row);
    inner.append(&init_group);

    // ── Reset ──────────────────────────────────────────────────
    let reset_group = adw::PreferencesGroup::builder()
        .title("Reset")
        .description("Delete and reinitialize borg repositories")
        .build();

    let reset_combo = build_client_combo(&state, "Client to reset");
    reset_group.add(&reset_combo);

    let reset_btn = gtk::Button::builder()
        .label("Reset")
        .css_classes(["destructive-action"])
        .margin_top(8)
        .build();
    let backend_reset = backend.clone();
    let reset_combo_ref = reset_combo.clone();
    reset_btn.connect_clicked(glib::clone!(
        #[weak]
        view,
        move |btn| {
            let client = selected_string(&reset_combo_ref);
            if client.is_empty() {
                return;
            }
            let backend_clone = backend_reset.clone();
            let client_clone = client.clone();
            // Show confirmation dialog
            let dialog = adw::AlertDialog::builder()
                .heading("Reset Repository?")
                .body(format!(
                    "This will delete and reinitialize all repos for \"{client}\". This cannot be undone."
                ))
                .build();
            dialog.add_responses(&[("cancel", "Cancel"), ("reset", "Reset")]);
            dialog.set_response_appearance("reset", adw::ResponseAppearance::Destructive);
            dialog.set_default_response(Some("cancel"));
            dialog.set_close_response("cancel");
            let btn_clone = btn.clone();
            dialog.connect_response(None, move |_, response| {
                if response == "reset" {
                    btn_clone.set_sensitive(false);
                    backend_clone.send(BackendCommand::RunReset {
                        client: client_clone.clone(),
                        repo: None,
                    });
                }
            });
            if let Some(w) = view.root().and_then(|r| r.downcast::<gtk::Window>().ok()) {
                dialog.present(Some(&w));
            }
        }
    ));
    let reset_btn_row = adw::ActionRow::builder().activatable(false).build();
    reset_btn_row.add_suffix(&reset_btn);
    reset_group.add(&reset_btn_row);
    inner.append(&reset_group);

    clamp.set_child(Some(&inner));
    view.append(&clamp);

    view
}

pub fn refresh(_view: &gtk::Box, _state: &Rc<GuiState>) {
    // Combos are populated at build time from initial config; for dynamic updates
    // we would need to rebuild. For now this is sufficient since config rarely changes.
}

pub fn set_running(view: &gtk::Box, running: bool) {
    // Show/hide running banner and re-enable buttons
    fn walk(widget: &gtk::Widget, running: bool) {
        if widget.widget_name() == RUNNING_BANNER_ID {
            if let Some(banner) = widget.downcast_ref::<adw::Banner>() {
                banner.set_revealed(running);
            }
        }
        // Re-enable buttons when operation completes
        if !running {
            if let Some(btn) = widget.downcast_ref::<gtk::Button>() {
                btn.set_sensitive(true);
            }
        }
        let mut child = widget.first_child();
        while let Some(c) = child {
            walk(&c, running);
            child = c.next_sibling();
        }
    }
    walk(view.upcast_ref(), running);
}

fn build_client_combo(state: &Rc<GuiState>, title: &str) -> adw::ComboRow {
    let model = gtk::StringList::new(&[]);
    if let Some(ref cfg) = *state.config.borrow() {
        for client in &cfg.clients {
            model.append(&client.name);
        }
    }
    adw::ComboRow::builder()
        .title(title)
        .model(&model)
        .build()
}

fn build_client_combo_with_all(state: &Rc<GuiState>) -> adw::ComboRow {
    let model = gtk::StringList::new(&["All"]);
    if let Some(ref cfg) = *state.config.borrow() {
        for client in &cfg.clients {
            model.append(&client.name);
        }
    }
    adw::ComboRow::builder()
        .title("Client")
        .model(&model)
        .build()
}

fn selected_string(combo: &adw::ComboRow) -> String {
    combo
        .selected_item()
        .and_then(|obj| obj.downcast::<gtk::StringObject>().ok())
        .map(|s| s.string().to_string())
        .unwrap_or_default()
}
