use std::{convert::Infallible, sync::Arc};

use axum::{
    Router,
    extract::State,
    response::{Html, Sse, sse::Event},
    routing::get,
};
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

        // Start server
        log::info!("SSE Push Server running at http://127.0.0.1:5246");
        axum::serve(
            tokio::net::TcpListener::bind("127.0.0.1:5246")
                .await
                .unwrap(),
            app,
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
            println!("🛑 Oneshot: shutdown signal received!");
        })
        .await
        .unwrap();
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
