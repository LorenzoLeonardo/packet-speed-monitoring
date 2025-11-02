use std::{
    convert::Infallible,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::{self, Body},
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Sse, sse::Event},
    routing::{get, post},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use chrono::{Datelike, Local};
use ipc_broker::client::IPCClient;
use serde_json::json;
use tera::Tera;
use tokio::{
    sync::{
        broadcast::{self, error::RecvError},
        mpsc, oneshot, watch,
    },
    task::JoinHandle,
};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tower::{ServiceExt, service_fn};
use tower_http::services::ServeDir;

use crate::{BIND_ADDR, LOG_FILE, manager::ControlMessage, monitor::device::DeviceInfo};

#[derive(Clone)]
struct AppState {
    tx: broadcast::Sender<String>,
    stopper: WebServerStopper,
    sender_channel: mpsc::Sender<ControlMessage>, // new controller channel
    client_count: Arc<AtomicUsize>,
    log_tx: broadcast::Sender<String>,
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
    log_tx: Option<broadcast::Sender<String>>,
}

impl WebServerBuilder {
    pub fn new(client: IPCClient) -> Self {
        Self {
            bind_addr: None,
            cert_path: None,
            key_path: None,
            client,
            control: None,
            log_tx: None,
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

    pub fn add_sender_channel(mut self, control: mpsc::Sender<ControlMessage>) -> Self {
        self.control = Some(control);
        self
    }

    pub fn add_log_channel(mut self, log: broadcast::Sender<String>) -> Self {
        self.log_tx = Some(log);
        self
    }

    pub async fn spawn(self) -> Result<WebServerHandler> {
        let bind_addr = self.bind_addr.unwrap_or_else(|| BIND_ADDR.to_string());
        let sender_channel = self.control.context("No sender channel set")?;
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

        let log_tx = self.log_tx.context("No log sender channel set")?.clone();
        let state = Arc::new(AppState {
            tx,
            stopper: stopper.clone(),
            sender_channel,
            client_count: Arc::new(AtomicUsize::new(0)),
            log_tx,
        });
        let serve_dir = ServeDir::new("web");
        let app = Router::new()
            .route("/", get(index_handler))
            .route("/events", get(sse_handler))
            .route("/start", post(start_handler))
            .route("/stop", post(stop_handler))
            .route("/status", get(status_handler))
            .route("/select", post(select_handler))
            .route("/log", get(log_stream_handler))
            .route("/log.html", get(log_page_handler))
            .with_state(state)
            .fallback_service(service_fn(move |req| serve_dir.clone().oneshot(req)))
            .layer(middleware::from_fn(check_paths));

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

async fn check_paths(req: Request<Body>, next: Next) -> axum::response::Response {
    let path = req.uri().path().to_string();
    if path.starts_with("/index.html") || path == "/index.html" {
        return Redirect::to("/").into_response();
    }
    next.run(req).await
}

async fn index_handler() -> axum::response::Response {
    let tera = Tera::new("web/*.html").unwrap();
    let mut context = tera::Context::new();
    let year = Local::now().year();
    let copy_right = format!("© {year} Enzo Tech Computer Solutions. All rights reserved.");
    let version = format!("Version {}", std::env!("CARGO_PKG_VERSION"));

    context.insert("copy_right", &copy_right);
    context.insert("app_version", &version);

    let contents = tera.render("index.html", &context).unwrap();
    Html(contents).into_response()
}

async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let client_id = state.client_count.fetch_add(1, Ordering::SeqCst) + 1;
    log::info!("[webserver] A client browser has connected. Total clients: {client_id}");
    // Each new client gets its own receiver
    let mut rx = state.tx.subscribe();
    let mut stopper = state.stopper.clone();

    // Query current status
    let (status_tx, status_rx) = oneshot::channel();
    let _ = state
        .sender_channel
        .send(ControlMessage::GetStatus(status_tx))
        .await;
    let current_status = status_rx.await.unwrap_or(false);

    // Query device list
    let (devinfo_tx, devinfo_rx) = oneshot::channel();
    let _ = state
        .sender_channel
        .send(ControlMessage::GetDeviceInfo(devinfo_tx))
        .await;
    let dev_info = devinfo_rx.await.unwrap_or(Vec::new());

    // Query selected device
    let (selected_tx, selected_rx) = oneshot::channel();
    let _ = state
        .sender_channel
        .send(ControlMessage::GetSelectedDevice(selected_tx))
        .await;
    let selected = selected_rx.await.unwrap_or(None);

    // Send a single "init" message with status, devices, and selected
    let init_event = json!({
        "type": "init",
        "status": {
            "running": current_status
        },
        "devices": dev_info,
        "selected": selected
    })
    .to_string();

    // Create an mpsc channel for pushing SSE events manually
    let (tx, rx_sse) = mpsc::channel::<Result<Event, Infallible>>(16);
    let state_clone = state.clone(); // <-- clone to decrement later

    // Spawn a background task that forwards both the initial event and broadcast updates
    tokio::spawn(async move {
        if let Err(e) = tx.send(Ok(Event::default().data(init_event))).await {
            log::error!("{e}");
            return;
        }

        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = stopper.shutdown_rx.changed() => {
                    log::info!("[webserver] SSE stopped by shutdown signal.");
                    break;
                }

                // Check if client has gone (receiver dropped)
                _ = tx.closed() => {
                    log::info!("[webserver] SSE channel closed (client disconnected early).");
                    break;
                }

                // Receive from broadcast channel
                msg = rx.recv() => {
                    match msg {
                        Ok(text) => {
                            if let Err(e) = tx.send(Ok(Event::default().data(text))).await {
                                log::warn!("[webserver] A client browser has disconnected: {e}");
                                break; // client disconnected
                            }
                        }
                        Err(RecvError::Lagged(n)) => {
                            log::warn!("Lagged: {n}");
                            continue
                        },
                        Err(RecvError::Closed) => {
                            log::error!("[webserver] channel has closed. Bail out!");
                            break
                        },
                    }
                }
            }
        }
        let remaining = state_clone.client_count.fetch_sub(1, Ordering::SeqCst) - 1;
        log::info!("[webserver] Client disconnected. Remaining clients: {remaining}");
    });

    // Convert the mpsc receiver into an SSE-compatible stream
    let stream = ReceiverStream::new(rx_sse);
    Sse::new(stream)
}

async fn start_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let _ = state.sender_channel.send(ControlMessage::Start).await;
    broadcast_status(&state.tx, true).await; // <-- broadcast to all clients
    Json(json!({ "ok": true, "running": true }))
}

async fn stop_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let _ = state.sender_channel.send(ControlMessage::Stop).await;
    broadcast_status(&state.tx, false).await; // <-- broadcast to all clients
    Json(json!({ "ok": true, "running": false }))
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let (tx, rx) = oneshot::channel();
    let _ = state
        .sender_channel
        .send(ControlMessage::GetStatus(tx))
        .await;
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

async fn broadcast_device_list(state: Arc<AppState>) {
    // Query current status
    let (status_tx, status_rx) = oneshot::channel();
    let _ = state
        .sender_channel
        .send(ControlMessage::GetStatus(status_tx))
        .await;
    let current_status = status_rx.await.unwrap_or(false);

    // Query device list
    let (devinfo_tx, devinfo_rx) = oneshot::channel();
    let _ = state
        .sender_channel
        .send(ControlMessage::GetDeviceInfo(devinfo_tx))
        .await;
    let dev_info = devinfo_rx.await.unwrap_or(Vec::new());

    // Query selected device
    let (selected_tx, selected_rx) = oneshot::channel();
    let _ = state
        .sender_channel
        .send(ControlMessage::GetSelectedDevice(selected_tx))
        .await;
    let selected = selected_rx.await.unwrap_or(None);

    // Send a single "init" message with status, devices, and selected
    let payload = json!({
        "type": "init",
        "status": {
            "running": current_status
        },
        "devices": dev_info,
        "selected": selected
    })
    .to_string();

    let _ = state.tx.send(payload.to_string());
}

async fn select_handler(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
) -> Json<serde_json::Value> {
    let bytes = body::to_bytes(request.into_body(), usize::MAX)
        .await
        .unwrap();
    let selection = serde_json::from_slice::<DeviceInfo>(&bytes).unwrap();
    // Convert JSON into DeviceInfo
    let _ = state
        .sender_channel
        .send(ControlMessage::SelectDevice(selection.clone()))
        .await;

    broadcast_device_list(state.clone()).await;

    Json(json!({ "ok": true }))
}

async fn log_page_handler() -> impl IntoResponse {
    // Load the HTML template
    let html_result = tokio::fs::read_to_string("web/log_viewer.html").await;
    let log_result = tokio::fs::read_to_string(LOG_FILE).await; // Your log file

    match (html_result, log_result) {
        (Ok(mut html), Ok(logs)) => {
            // Safely embed the log contents into a <script> tag so they show at page load
            let escaped_logs = html_escape::encode_text(&logs);

            // Inject logs into HTML — placeholder {{LOG_CONTENT}} in your HTML file
            html = html.replace("{{LOG_CONTENT}}", &escaped_logs);

            Html(html)
        }
        (Ok(html), Err(_)) => {
            // If log file missing, just show empty
            Html(html.replace("{{LOG_CONTENT}}", ""))
        }
        (Err(e), _) => Html(format!("<h1>Error loading log viewer: {}</h1>", e)),
    }
}

async fn log_stream_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (tx, rx_sse) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(16);
    let mut log_rx = state.log_tx.subscribe();
    let mut stopper = state.stopper.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = stopper.shutdown_rx.changed() => {
                    log::info!("[webserver] SSE stopped by shutdown signal.");
                    break;
                }

                // Check if client has gone (receiver dropped)
                _ = tx.closed() => {
                    log::info!("[webserver] SSE channel closed (client disconnected early).");
                    break;
                }

                // Receive from broadcast channel
                msg = log_rx.recv() => {
                    match msg {
                        Ok(text) => {
                            if let Err(e) = tx.send(Ok(Event::default().data(text))).await {
                                log::warn!("[webserver] A client browser has disconnected: {e}");
                                break; // client disconnected
                            }
                        }
                        Err(RecvError::Lagged(n)) => {
                            log::warn!("Lagged: {n}");
                            continue
                        },
                        Err(RecvError::Closed) => {
                            log::error!("[webserver] channel has closed. Bail out!");
                            break
                        },
                    }
                }
            }
        }
    });

    let stream = ReceiverStream::new(rx_sse);
    Sse::new(stream)
}
