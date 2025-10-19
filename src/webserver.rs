use std::{convert::Infallible, net::SocketAddr, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    response::{Html, Sse, sse::Event},
    routing::{get, post},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use futures::{Stream, StreamExt, stream};
use ipc_broker::client::IPCClient;
use serde_json::json;
use tokio::{
    fs,
    sync::{broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
};
use tokio_stream::wrappers::BroadcastStream;

use crate::BIND_ADDR;

#[derive(Debug)]
pub enum ControlMessage {
    Start,
    Stop,
    GetStatus(oneshot::Sender<bool>),
    Quit,
}

#[derive(Clone)]
struct AppState {
    tx: broadcast::Sender<String>,
    stopper: WebServerStopper,
    control: mpsc::Sender<ControlMessage>, // new controller channel
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
    log::info!("[webserver] HTTP Webserver started.");
    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    log::info!("SSE Push Server running using HTTP at http://{bind_addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = stopper.shutdown_rx.changed().await;
            log::debug!("HTTP: shutdown signal received!");
        })
        .await
        .unwrap();
    log::info!("[webserver] HTTP Webserver ended.");
}

// Spawn HTTPS Server
async fn spawn_https(
    bind_addr: &str,
    app: Router,
    stopper: WebServerStopper,
    rustls_config: RustlsConfig,
) {
    log::info!("[webserver] HTTPS Webserver started.");
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
    log::info!("[webserver] HTTPS Webserver ended.");
}

pub struct WebServerBuilder {
    bind_addr: Option<String>,
    cert_path: Option<String>,
    key_path: Option<String>,
    client: IPCClient,
    control: Option<mpsc::Sender<ControlMessage>>,
}

impl WebServerBuilder {
    pub fn new(client: IPCClient) -> Self {
        Self {
            bind_addr: None,
            cert_path: None,
            key_path: None,
            client,
            control: None,
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

    pub fn add_control(mut self, control: mpsc::Sender<ControlMessage>) -> Self {
        self.control = Some(control);
        self
    }

    pub async fn spawn(self) -> Result<WebServerHandler> {
        let bind_addr = self.bind_addr.unwrap_or_else(|| BIND_ADDR.to_string());
        let control = self.control.context("No control set")?;
        let (tx, _rx) = broadcast::channel(100);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let stopper = WebServerStopper {
            shutdown_tx,
            shutdown_rx,
        };
        let inner_send = tx.clone();

        self.client
            .subscribe_async("application.lan.speed", "speedInfo", move |value| {
                let _ = inner_send.send(value.to_string());
            })
            .await;

        let state = Arc::new(AppState {
            tx,
            stopper: stopper.clone(),
            control,
        });

        let app = Router::new()
            .route("/", get(index_handler))
            .route("/events", get(sse_handler))
            .route("/start", post(start_handler))
            .route("/stop", post(stop_handler))
            .route("/status", get(status_handler))
            .with_state(state);

        let server = WebServer {
            bind_addr,
            cert_path: self.cert_path,
            key_path: self.key_path,
            stopper,
            app,
        };
        Ok(server.spawn().await)
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
    pub async fn spawn(self) -> WebServerHandler {
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
        };
        WebServerHandler {
            handle: tokio::spawn(fut),
            web_stopper: self.stopper,
        }
    }
}

pub struct WebServerHandler {
    pub handle: JoinHandle<()>,
    web_stopper: WebServerStopper,
}

impl WebServerHandler {
    pub fn stop(&self) {
        self.web_stopper.clone().stop();
    }
}

async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Each new client gets its own receiver
    let rx = state.tx.subscribe();
    let mut stopper = state.stopper.clone();

    // Query current status once
    let (status_tx, status_rx) = oneshot::channel();
    let _ = state
        .control
        .send(ControlMessage::GetStatus(status_tx))
        .await;
    let current_status = status_rx.await.unwrap_or(false);

    // Create an immediate, one-time "status" event
    let initial_event = json!({
        "type": "status",
        "running": current_status
    })
    .to_string();

    // Stream that first sends current status, then continues with broadcast updates
    let initial_stream = stream::once(async move { Ok(Event::default().data(initial_event)) });

    let broadcast_stream = BroadcastStream::new(rx)
        .take_until(async move {
            let _ = stopper.shutdown_rx.changed().await;
            log::info!("[webserver] Server-sent event has stopped.");
        })
        .filter_map(|msg| async move {
            match msg {
                Ok(text) => Some(Ok(Event::default().data(text))),
                Err(_) => None,
            }
        });

    // Combine the two streams
    let combined_stream = initial_stream.chain(broadcast_stream);

    Sse::new(combined_stream)
}

// HTML dashboard
async fn index_handler() -> Html<String> {
    let html = fs::read_to_string("web/index.html")
        .await
        .unwrap_or_else(|_| "<h1>index.html not found</h1>".to_string());
    Html(html)
}

async fn start_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let _ = state.control.send(ControlMessage::Start).await;
    broadcast_status(&state.tx, true).await; // <-- broadcast to all clients
    Json(json!({ "ok": true, "running": true }))
}

async fn stop_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let _ = state.control.send(ControlMessage::Stop).await;
    broadcast_status(&state.tx, false).await; // <-- broadcast to all clients
    Json(json!({ "ok": true, "running": false }))
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let (tx, rx) = oneshot::channel();
    let _ = state.control.send(ControlMessage::GetStatus(tx)).await;
    let running = rx.await.unwrap_or(false);
    Json(json!({ "running": running }))
}

async fn broadcast_status(tx: &broadcast::Sender<String>, running: bool) {
    let payload = json!({
        "type": "status",
        "running": running
    });
    let _ = tx.send(payload.to_string());
}
