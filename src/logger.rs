use std::io::{self, Write};

use chrono::Local;
use fern::Dispatch;
use log::LevelFilter;
use tokio::{
    io::AsyncWriteExt,
    sync::{broadcast, watch},
    task::JoinHandle,
};

use crate::LOG_FILE;

/// Custom writer that forwards each log line to a broadcast channel
#[derive(Clone)]
struct BroadcastWriter {
    tx: broadcast::Sender<String>,
    buffer: String,
}

impl io::Write for BroadcastWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            self.buffer.push_str(s);

            // Process full lines (separated by '\n')
            while let Some(pos) = self.buffer.find('\n') {
                let line = self.buffer[..pos].to_string();
                if !line.is_empty() {
                    let _ = self.tx.send(line);
                }
                // Remove the processed line (and newline)
                self.buffer.drain(..=pos);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let line = self.buffer.to_string();
            if !line.is_empty() {
                let _ = self.tx.send(line);
            }
            self.buffer.clear();
        }
        Ok(())
    }
}

fn logging_level() -> LevelFilter {
    match std::env::var("BROKER_DEBUG").as_deref() {
        Ok("trace") => LevelFilter::Trace,
        Ok("debug") => LevelFilter::Debug,
        Ok("info") => LevelFilter::Info,
        Ok("warn") => LevelFilter::Warn,
        Ok("error") => LevelFilter::Error,
        _ => LevelFilter::Info, // default if unset or unknown
    }
}

pub fn setup_logger() -> broadcast::Sender<String> {
    let level_filter = logging_level();
    let (tx, _) = broadcast::channel::<String>(1000); // 1000-message buffer
    let broadcast_writer = BroadcastWriter {
        tx: tx.clone(),
        buffer: String::new(),
    };
    let boxed_writer: Box<dyn Write + Send> = Box::new(broadcast_writer);

    if let Err(e) = Dispatch::new()
        .format(move |out, message, record| {
            let file = record.file().unwrap_or("unknown_file");
            let line = record.line().map_or(0, |l| l);

            match level_filter {
                LevelFilter::Off
                | LevelFilter::Error
                | LevelFilter::Warn
                | LevelFilter::Debug
                | LevelFilter::Trace
                | LevelFilter::Info => {
                    out.finish(format_args!(
                        "[{}][{}]: {} <{}:{}>",
                        Local::now().format("%b-%d-%Y %H:%M:%S.%f"),
                        record.level(),
                        message,
                        file,
                        line,
                    ));
                }
            }
        })
        .level(level_filter)
        .chain(io::stdout())
        .chain(boxed_writer) // forward to broadcast channel
        .apply()
    {
        log::error!("Logger initialization failed: {e}");
    }

    tx
}

pub struct Log {
    pub tx: broadcast::Sender<String>,
    shutdown_handle: JoinHandle<()>,
    shutdown_sender: watch::Sender<bool>,
}

impl Log {
    pub async fn init() -> anyhow::Result<Self> {
        let tx = setup_logger();
        let (shutdown_sender, mut shutdown_receiver) = watch::channel(false);
        // Open (or create) the log file asynchronously in append mode
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_FILE)
            .await?;
        let mut rx = tx.subscribe();
        // Spawn a background task to write logs into the file
        let shutdown_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    maybe_msg = rx.recv() => {
                        match maybe_msg {
                            Ok(mut msg) => {
                                msg.push_str("\n");
                                if let Err(e) = file.write_all(msg.as_bytes()).await {
                                    eprintln!("Failed to write log to file: {}", e);
                                    break;
                                }
                                if let Err(e) = file.flush().await {
                                    eprintln!("Failed to flush log file: {}", e);
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                // Sender closed, exit loop
                                break;
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                // We lost some messages, you can log or ignore here
                            }
                        }
                    }
                    _ = shutdown_receiver.changed() => {
                        // Shutdown signal received
                        if *shutdown_receiver.borrow() {
                            // Drain remaining messages before exiting
                            while let Ok(mut msg) = rx.try_recv() {
                                msg.push_str("\n");
                                if let Err(e) = file.write_all(msg.as_bytes()).await {
                                    eprintln!("Failed to write log to file: {}", e);
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
            }
        });

        log::info!(
            "{} v{} has started.",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        Ok(Self {
            tx,
            shutdown_handle,
            shutdown_sender,
        })
    }

    /// Call this async method before dropping the logger to flush logs.
    pub async fn shutdown(self) {
        log::info!(
            "{} v{} has ended.",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );

        // Drop the sender to close the broadcast channel,
        // so the background task's rx.recv() returns an error and exits.
        self.shutdown_sender.send(true).ok();
        drop(self.tx);

        // Wait for the background task to finish
        let _ = self.shutdown_handle.await;
    }
}
