pub mod backup;
pub mod borg;
pub mod check;
pub mod config;
pub mod distribute;
pub mod init;
pub mod maintenance;
pub mod ntfy;
pub mod reset;
pub mod restic;
pub mod restore;
pub mod ssh;
pub mod status;
pub mod update;
pub mod wol;

/// Optional channel for streaming log output to a GUI or other consumer.
/// When `None`, output goes to stdout via `println!`.
pub type LogSender = tokio::sync::mpsc::UnboundedSender<String>;

/// Send a log line to the channel if present, otherwise print to stdout.
pub fn log_line(tx: &Option<LogSender>, msg: impl Into<String>) {
    let msg = msg.into();
    if let Some(tx) = tx {
        let _ = tx.send(msg);
    } else {
        println!("{msg}");
    }
}
