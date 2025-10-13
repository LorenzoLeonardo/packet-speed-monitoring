use std::{convert::Infallible, net::SocketAddr, str::FromStr, sync::Arc};

use anyhow::Result;
use axum::{
    Router,
    extract::State,
    response::{Html, Sse, sse::Event},
    routing::get,
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use futures::{Stream, StreamExt};
use ipc_broker::client::ClientHandle;
use tokio::{
    fs,
    sync::{broadcast, watch},
    task::JoinHandle,
};
use tokio_stream::wrappers::BroadcastStream;

use crate::BIND_ADDR;

#[derive(Clone)]
struct AppState {
    tx: broadcast::Sender<String>,
    stopper: WebServerStopper,
}

#[derive(Clone)]
pub struct WebServerStopper {
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl WebServerStopper {
    pub fn stop(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

// Spawn HTTP Server
async fn spawn_http(bind_addr: &str, app: Router, mut stopper: WebServerStopper) {
    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    log::info!("SSE Push Server running using HTTP at http://{bind_addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = stopper.shutdown_rx.changed().await;
            log::debug!("HTTP: shutdown signal received!");
        })
        .await
        .unwrap();
}

// Spawn HTTPS Server
async fn spawn_https(
    bind_addr: &str,
    app: Router,
    stopper: WebServerStopper,
    rustls_config: RustlsConfig,
) {
    let addr = SocketAddr::from_str(bind_addr).unwrap();
    log::info!("SSE Push Server running using HTTPS at https://{bind_addr}");

    let handle = Handle::new();
    let handle_clone = handle.clone();

    // graceful shutdown task
    tokio::spawn({
        let mut shutdown_rx = stopper.shutdown_rx.clone();
        async move {
            let _ = shutdown_rx.changed().await;
            log::debug!("HTTPS: shutdown signal received!");
            handle_clone.shutdown();
        }
    });

    let _ = axum_server::bind_rustls(addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await;
}

pub struct WebServerBuilder {
    bind_addr: Option<String>,
    cert_path: Option<String>,
    key_path: Option<String>,
}

impl WebServerBuilder {
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            cert_path: None,
            key_path: None,
        }
    }

    pub fn bind_addr(mut self, addr: &str) -> Self {
        self.bind_addr = Some(addr.to_string());
        self
    }

    pub fn cert_paths(mut self, cert: &str, key: &str) -> Self {
        self.cert_path = Some(cert.to_string());
        self.key_path = Some(key.to_string());
        self
    }

    pub async fn build(self) -> Result<WebServer> {
        let bind_addr = self.bind_addr.unwrap_or_else(|| BIND_ADDR.to_string());

        // connect to client
        let client = ClientHandle::connect().await?;

        let (tx, _rx) = broadcast::channel(100);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let stopper = WebServerStopper {
            shutdown_tx,
            shutdown_rx,
        };
        let inner_send = tx.clone();
        client
            .subscribe_async("application.lan.speed", "speedInfo", move |value| {
                let _ = inner_send.send(value.to_string());
            })
            .await;

        let state = Arc::new(AppState {
            tx,
            stopper: stopper.clone(),
        });

        let app = Router::new()
            .route("/", get(index_handler))
            .route("/events", get(sse_handler))
            .with_state(state);

        Ok(WebServer {
            bind_addr,
            cert_path: self.cert_path,
            key_path: self.key_path,
            stopper,
            app,
        })
    }
}

pub struct WebServer {
    bind_addr: String,
    cert_path: Option<String>,
    key_path: Option<String>,
    stopper: WebServerStopper,
    app: Router,
}

impl WebServer {
    pub async fn spawn(self) -> (JoinHandle<()>, WebServerStopper) {
        let bind_addr = self.bind_addr.clone();
        let app = self.app.clone();
        let stopper = self.stopper.clone();
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();

        let fut = async move {
            if let (Some(cert), Some(key)) = (cert_path, key_path) {
                match RustlsConfig::from_pem_file(cert, key).await {
                    Ok(rustls_config) => {
                        spawn_https(&bind_addr, app, stopper.clone(), rustls_config).await;
                    }
                    Err(e) => {
                        log::warn!("Falling back to HTTP: failed to load TLS certs: {e}");
                        spawn_http(&bind_addr, app, stopper.clone()).await;
                    }
                }
            } else {
                log::info!("No TLS certs provided — starting HTTP server");
                spawn_http(&bind_addr, app, stopper.clone()).await;
            }
            log::info!("[webserver] webserver thread exiting cleanly.")
        };

        (tokio::spawn(fut), self.stopper)
    }
}

async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Each new client gets its own receiver
    let rx = state.tx.subscribe();
    let mut stopper = state.stopper.clone();
    // Convert broadcast receiver into a Stream of SSE events
    let stream = BroadcastStream::new(rx)
        .take_until(async move {
            // wait until shutdown flag flips
            let _ = stopper.shutdown_rx.changed().await;
            log::info!("[webserver] Server-sent event has stopped.");
        })
        .filter_map(|msg| async move {
            match msg {
                Ok(text) => Some(Ok(Event::default().data(text))),
                Err(_) => None,
            }
        });

    Sse::new(stream)
}

// HTML dashboard
async fn index_handler() -> Html<String> {
    let html = fs::read_to_string("web/index.html")
        .await
        .unwrap_or_else(|_| "<h1>index.html not found</h1>".to_string());
    Html(html)
}
