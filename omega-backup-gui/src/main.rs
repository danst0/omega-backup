mod bridge;
mod dashboard;
mod logs;
mod operations;
mod server;
mod window;

use adw::prelude::*;
use bridge::BackendHandle;

const APP_ID: &str = "com.github.danst0.OmegaBackup";

fn main() -> anyhow::Result<()> {
    let app = adw::Application::builder()
        .application_id(APP_ID)
        .build();

    app.connect_activate(move |app| {
        let backend = BackendHandle::spawn();
        let win = window::build_window(app, backend);
        win.present();
    });

    app.run();
    Ok(())
}
