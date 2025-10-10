pub async fn wait_until_signal() {
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
        }
    }

    #[cfg(windows)]
    {
        // On Windows, only Ctrl+C is supported directly
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        log::info!("Received Ctrl+C (Windows)");
    }
}
