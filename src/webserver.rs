use std::{convert::Infallible, net::SocketAddr, str::FromStr, sync::Arc};

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

#[derive(Clone)]
struct AppState {
    tx: broadcast::Sender<String>,
    shutdown_rx: watch::Receiver<bool>,
}

pub async fn spawn_webserver(mut shutdown_rx: watch::Receiver<bool>) -> JoinHandle<()> {
    // Create broadcast channel (sender for server, receivers for each client)
    tokio::spawn(async move {
        let (tx, _rx) = broadcast::channel(100);

        let client = ClientHandle::connect().await.unwrap();
        let inner_send = tx.clone();
        client
            .subscribe_async("application.lan.speed", "speedInfo", move |value| {
                let _ = inner_send.send(value.to_string());
            })
            .await;
        let state = Arc::new(AppState {
            tx,
            shutdown_rx: shutdown_rx.clone(),
        });

        // Build router
        let app = Router::new()
            .route("/", get(index_handler))
            .route("/events", get(sse_handler))
            .with_state(state);

        // TLS: load cert & key (PEM files)
        // Put your cert/key at "web/tls/cert.pem" and "web/tls/key.pem" (or change paths)
        let bind_addr = "0.0.0.0:5247";
        match RustlsConfig::from_pem_file("web/tls/cert.pem", "web/tls/key.pem").await {
            Ok(rustls_config) => {
                // Start HTTPS server with graceful shutdown
                log::info!("SSE Push Server running at https://{bind_addr}");
                let addr = SocketAddr::from_str(bind_addr).unwrap();

                // Create a handle for the server
                let handle = Handle::new();
                let handle_clone = handle.clone();

                // Spawn a task to wait for the shutdown_rx signal
                tokio::task::spawn({
                    let mut shutdown_rx = shutdown_rx.clone();
                    async move {
                        // Wait for shutdown signal from somewhere in your app
                        let _ = shutdown_rx.changed().await;
                        log::info!("Oneshot: shutdown signal received!");
                        handle_clone.shutdown();
                    }
                });

                let _ = axum_server::bind_rustls(addr, rustls_config)
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await;
            }
            Err(e) => {
                log::error!("Failed to load TLS cert/key: {}", e);
                // Start HTTP server
                let listen_addr = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
                log::info!("SSE Push Server running at http://{bind_addr}");
                axum::serve(listen_addr, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.changed().await;
                        log::info!("Oneshot: shutdown signal received!");
                    })
                    .await
                    .unwrap();
            }
        }
    })
}

async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Each new client gets its own receiver
    let rx = state.tx.subscribe();
    let mut shutdown_rx = state.shutdown_rx.clone();
    // Convert broadcast receiver into a Stream of SSE events
    let stream = BroadcastStream::new(rx)
        .take_until(async move {
            // wait until shutdown flag flips
            let _ = shutdown_rx.changed().await;
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
