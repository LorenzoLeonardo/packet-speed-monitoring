use std::sync::Arc;

use tokio::sync::Notify;

pub async fn wait_until_signal(manual_trigger: Arc<Notify>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut term = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");

        tokio::select! {
            _ = term.recv() => {
                log::info!("Received SIGTERM (systemd stop).");
            }
            _ = int.recv() => {
                log::info!("Received SIGINT (Ctrl+C).");
            }
            _ = manual_trigger.notified() => {
                log::info!("Received internal shutdown signal (manual trigger).");
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows, only Ctrl+C is supported directly
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("Received Ctrl+C (Windows)");
            }
            _ = manual_trigger.notified() => {
                log::info!("Received internal shutdown signal (manual trigger).");
            }
        }
        log::info!("Received Ctrl+C (Windows)");
    }
}
