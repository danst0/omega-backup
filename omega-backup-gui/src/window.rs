use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use gtk::glib;

use omega_backup_lib::config::{AppState, Config};

use crate::bridge::{BackendCommand, BackendHandle, UiEvent};
use crate::{dashboard, logs, operations, server};

/// Shared GUI state accessible from all views.
pub struct GuiState {
    pub config: RefCell<Option<Arc<Config>>>,
    pub app_state: RefCell<AppState>,
    pub server_online: RefCell<bool>,
    pub lockfiles: RefCell<Vec<String>>,
    pub borg_version: RefCell<Option<String>>,
    pub operation_running: RefCell<bool>,
}

impl Default for GuiState {
    fn default() -> Self {
        Self {
            config: RefCell::new(None),
            app_state: RefCell::new(AppState::default()),
            server_online: RefCell::new(false),
            lockfiles: RefCell::new(vec![]),
            borg_version: RefCell::new(None),
            operation_running: RefCell::new(false),
        }
    }
}

pub fn build_window(app: &adw::Application, backend: BackendHandle) -> adw::ApplicationWindow {
    let state = Rc::new(GuiState::default());

    // ── Build views ────────────────────────────────────────────
    let dashboard_view = dashboard::build_view(state.clone(), backend.clone());
    let server_view = server::build_view(state.clone(), backend.clone());
    let operations_view = operations::build_view(state.clone(), backend.clone());
    let log_view = logs::build_view();

    // ── Content stack ──────────────────────────────────────────
    let stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .build();

    stack.add_titled(&dashboard_view, Some("dashboard"), "Dashboard");
    stack.add_titled(&server_view, Some("server"), "Server");
    stack.add_titled(&operations_view, Some("operations"), "Operations");
    stack.add_titled(&log_view, Some("logs"), "Logs");

    // ── Sidebar ────────────────────────────────────────────────
    let sidebar_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build();

    let items = [
        ("Dashboard", "view-grid-symbolic", "dashboard"),
        ("Server", "network-server-symbolic", "server"),
        ("Operations", "emblem-system-symbolic", "operations"),
        ("Logs", "utilities-terminal-symbolic", "logs"),
    ];

    for (label, icon, _name) in &items {
        let row = sidebar_row(label, icon);
        sidebar_list.append(&row);
    }

    let stack_clone = stack.clone();
    sidebar_list.connect_row_selected(move |_, row| {
        if let Some(row) = row {
            let idx = row.index() as usize;
            if idx < items.len() {
                stack_clone.set_visible_child_name(items[idx].2);
            }
        }
    });

    // Select first row
    if let Some(first_row) = sidebar_list.row_at_index(0) {
        sidebar_list.select_row(Some(&first_row));
    }

    let sidebar_page = adw::NavigationPage::builder()
        .title("Omega Backup")
        .child(&sidebar_list)
        .build();

    let content_page = adw::NavigationPage::builder()
        .title("Omega Backup")
        .child(&stack)
        .build();

    let split_view = adw::NavigationSplitView::builder()
        .sidebar(&sidebar_page)
        .content(&content_page)
        .min_sidebar_width(200.0)
        .max_sidebar_width(260.0)
        .build();

    // ── Toast overlay ──────────────────────────────────────────
    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&split_view));

    // ── Header bar ─────────────────────────────────────────────
    let header = adw::HeaderBar::new();
    let title = adw::WindowTitle::new("Omega Backup", "Management");
    header.set_title_widget(Some(&title));

    // About button
    let about_btn = gtk::Button::builder()
        .icon_name("help-about-symbolic")
        .tooltip_text("About")
        .build();
    about_btn.connect_clicked(glib::clone!(
        #[weak]
        toast_overlay,
        move |_| {
            let dialog = adw::AboutDialog::builder()
                .application_name("Omega Backup")
                .developer_name("danst0")
                .version(env!("CARGO_PKG_VERSION"))
                .application_icon("drive-harddisk-symbolic")
                .license_type(gtk::License::MitX11)
                .build();
            if let Some(w) = toast_overlay.root().and_then(|r| r.downcast::<gtk::Window>().ok()) {
                dialog.present(Some(&w));
            }
        }
    ));
    header.pack_end(&about_btn);

    // Refresh button
    let refresh_btn = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh")
        .build();
    let backend_ref = backend.clone();
    refresh_btn.connect_clicked(move |_| {
        backend_ref.send(BackendCommand::RefreshStatus);
        backend_ref.send(BackendCommand::CheckServerReachable);
    });
    header.pack_end(&refresh_btn);

    // ── Main layout ────────────────────────────────────────────
    let main_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    main_box.append(&header);
    main_box.append(&toast_overlay);

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .content(&main_box)
        .default_width(900)
        .default_height(650)
        .title("Omega Backup")
        .build();

    // ── Wire up backend events via async channel ───────────────
    let ui_rx = backend.ui_rx.clone();
    let toast_ref = toast_overlay.clone();
    let log_tv = logs::get_text_view(&log_view);
    let dashboard_ref = dashboard_view.clone();
    let server_ref = server_view.clone();
    let ops_ref = operations_view.clone();

    glib::spawn_future_local(async move {
        while let Ok(event) = ui_rx.recv().await {
            match event {
                UiEvent::ConfigLoaded(cfg) => {
                    *state.config.borrow_mut() = Some(cfg);
                    dashboard::refresh(&dashboard_ref, &state);
                    server::refresh(&server_ref, &state);
                    operations::refresh(&ops_ref, &state);
                }
                UiEvent::StateUpdated(app_state) => {
                    *state.app_state.borrow_mut() = app_state;
                    dashboard::refresh(&dashboard_ref, &state);
                }
                UiEvent::ServerStatus {
                    online,
                    lockfiles,
                    borg_version,
                } => {
                    *state.server_online.borrow_mut() = online;
                    *state.lockfiles.borrow_mut() = lockfiles;
                    *state.borg_version.borrow_mut() = borg_version;
                    server::refresh(&server_ref, &state);
                    dashboard::refresh(&dashboard_ref, &state);
                }
                UiEvent::OperationStarted { id: _, description } => {
                    *state.operation_running.borrow_mut() = true;
                    operations::set_running(&ops_ref, true);
                    logs::append(&log_tv, &format!("--- {description} ---\n"));
                }
                UiEvent::OperationLog { id: _, line } => {
                    logs::append(&log_tv, &format!("{line}\n"));
                }
                UiEvent::OperationCompleted {
                    id: _,
                    success,
                    summary,
                } => {
                    *state.operation_running.borrow_mut() = false;
                    operations::set_running(&ops_ref, false);
                    logs::append(&log_tv, &format!("{summary}\n\n"));
                    let toast = adw::Toast::new(&summary);
                    toast.set_timeout(5);
                    toast_ref.add_toast(toast);

                    if !success {
                        tracing::error!("{summary}");
                    }
                }
                UiEvent::Error(msg) => {
                    let toast = adw::Toast::new(&msg);
                    toast.set_timeout(10);
                    toast_ref.add_toast(toast);
                    tracing::error!("{msg}");
                }
            }
        }
    });

    // ── Initial load ───────────────────────────────────────────
    backend.send(BackendCommand::LoadConfig);
    backend.send(BackendCommand::CheckServerReachable);

    // Periodic refresh every 60s
    let backend_periodic = backend.clone();
    glib::timeout_add_seconds_local(60, move || {
        backend_periodic.send(BackendCommand::RefreshStatus);
        backend_periodic.send(BackendCommand::CheckServerReachable);
        glib::ControlFlow::Continue
    });

    window
}

fn sidebar_row(label: &str, icon_name: &str) -> gtk::ListBoxRow {
    let hbox = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    hbox.set_margin_top(8);
    hbox.set_margin_bottom(8);
    hbox.set_margin_start(12);
    hbox.set_margin_end(12);

    let icon = gtk::Image::from_icon_name(icon_name);
    let lbl = gtk::Label::new(Some(label));
    lbl.set_halign(gtk::Align::Start);

    hbox.append(&icon);
    hbox.append(&lbl);

    gtk::ListBoxRow::builder().child(&hbox).build()
}
