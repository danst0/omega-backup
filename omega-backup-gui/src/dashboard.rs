use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;

use crate::bridge::BackendHandle;
use crate::window::GuiState;

/// Holds a PreferencesGroup and tracks which rows we've added so we can remove them on refresh.
struct DashboardInner {
    group: adw::PreferencesGroup,
    rows: Vec<adw::ActionRow>,
}

pub fn build_view(state: Rc<GuiState>, _backend: BackendHandle) -> gtk::Box {
    let view = gtk::Box::new(gtk::Orientation::Vertical, 0);
    view.set_margin_top(24);
    view.set_margin_bottom(24);
    view.set_margin_start(24);
    view.set_margin_end(24);

    let clamp = adw::Clamp::builder().maximum_size(800).build();
    let inner_box = gtk::Box::new(gtk::Orientation::Vertical, 16);

    let group = adw::PreferencesGroup::builder()
        .title("Clients")
        .description("Backup status for all managed clients")
        .build();

    inner_box.append(&group);
    clamp.set_child(Some(&inner_box));
    view.append(&clamp);

    let dashboard = Rc::new(RefCell::new(DashboardInner {
        group,
        rows: Vec::new(),
    }));

    // Stash the Rc in the view's widget data so refresh() can retrieve it
    unsafe {
        view.set_data("dashboard-inner", dashboard.clone());
    }

    // Initial populate
    populate(&dashboard, &state);

    view
}

pub fn refresh(view: &gtk::Box, state: &Rc<GuiState>) {
    let dashboard: Option<Rc<RefCell<DashboardInner>>> =
        unsafe { view.data::<Rc<RefCell<DashboardInner>>>("dashboard-inner").map(|p| (*p.as_ref()).clone()) };
    if let Some(dashboard) = dashboard {
        populate(&dashboard, state);
    }
}

fn populate(dashboard: &Rc<RefCell<DashboardInner>>, state: &GuiState) {
    let mut inner = dashboard.borrow_mut();

    // Remove all previously added rows
    let old_rows: Vec<_> = inner.rows.drain(..).collect();
    for row in &old_rows {
        inner.group.remove(row);
    }

    let config = state.config.borrow();
    let Some(ref cfg) = *config else {
        let empty = adw::ActionRow::builder()
            .title("No config loaded")
            .subtitle("Place config.toml in ~/.config/omega-backup/")
            .build();
        inner.group.add(&empty);
        inner.rows.push(empty);
        return;
    };

    let app_state = state.app_state.borrow();

    if cfg.clients.is_empty() {
        let empty = adw::ActionRow::builder()
            .title("No clients configured")
            .subtitle("Add clients to config.toml")
            .build();
        inner.group.add(&empty);
        inner.rows.push(empty);
        return;
    }

    let lockfiles = state.lockfiles.borrow();

    for client in &cfg.clients {
        let cs = app_state.client_summary(&client.name);
        let is_active = lockfiles.iter().any(|l| l == &client.hostname);
        let (dot_css, subtitle) = client_status_info(cs.as_ref(), client.repos.len(), is_active);

        let dot = gtk::DrawingArea::builder()
            .width_request(12)
            .height_request(12)
            .valign(gtk::Align::Center)
            .build();
        let css = dot_css.to_string();
        dot.set_draw_func(move |_, cr, w, h| {
            let color = match css.as_str() {
                "green" => (0.30, 0.78, 0.35),
                "yellow" => (0.95, 0.77, 0.20),
                _ => (0.90, 0.30, 0.30),
            };
            let _ = cr.set_source_rgb(color.0, color.1, color.2);
            let _ = cr.arc(
                w as f64 / 2.0,
                h as f64 / 2.0,
                5.0,
                0.0,
                2.0 * std::f64::consts::PI,
            );
            let _ = cr.fill();
        });

        let row = adw::ActionRow::builder()
            .title(&client.name)
            .subtitle(&subtitle)
            .activatable(false)
            .build();
        row.add_prefix(&dot);

        if is_active {
            let active_label = gtk::Label::builder()
                .label("ACTIVE")
                .css_classes(["success"])
                .valign(gtk::Align::Center)
                .build();
            row.add_suffix(&active_label);
        }

        let repo_label = gtk::Label::builder()
            .label(&format!("{} repos", client.repos.len()))
            .css_classes(["dim-label"])
            .valign(gtk::Align::Center)
            .build();
        row.add_suffix(&repo_label);

        inner.group.add(&row);
        inner.rows.push(row);
    }
}

fn client_status_info(
    cs: Option<&omega_backup_lib::config::ClientSummary>,
    repo_count: usize,
    is_active: bool,
) -> (&'static str, String) {
    let Some(cs) = cs else {
        if is_active {
            return ("green", "Backup running".into());
        }
        return ("red", "Never backed up".into());
    };

    let backup_str = match &cs.last_backup_timestamp {
        Some(ts) => format_age(ts),
        None => "Never".into(),
    };

    let check_str = match &cs.integrity_status {
        Some(s) => s.clone(),
        None => "Unknown".into(),
    };

    let age_hours = cs
        .last_backup_timestamp
        .as_ref()
        .and_then(|ts| parse_age_hours(ts));

    let dot = match age_hours {
        Some(h) if h < 25.0 && check_str != "failed" => "green",
        Some(h) if h < 48.0 => "yellow",
        _ => {
            if cs.last_backup_timestamp.is_some() && check_str != "failed" {
                "yellow"
            } else {
                "red"
            }
        }
    };

    let subtitle =
        format!("Last backup: {backup_str} | Check: {check_str} | Repos: {repo_count}");
    (dot, subtitle)
}

fn format_age(ts: &str) -> String {
    let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") else {
        return ts.to_string();
    };
    let now = chrono::Local::now().naive_local();
    let diff = now - dt;

    if diff.num_hours() < 1 {
        format!("{}m ago", diff.num_minutes())
    } else if diff.num_hours() < 24 {
        format!("{}h ago", diff.num_hours())
    } else {
        format!("{}d ago", diff.num_days())
    }
}

fn parse_age_hours(ts: &str) -> Option<f64> {
    let dt = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S").ok()?;
    let now = chrono::Local::now().naive_local();
    let diff = now - dt;
    Some(diff.num_minutes() as f64 / 60.0)
}
