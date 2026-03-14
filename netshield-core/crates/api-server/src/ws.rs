use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::state::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let rx = state.inner.broadcast_tx.subscribe();
    let mut stream = BroadcastStream::new(rx);

    // Forward broadcast messages to the WebSocket client
    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(broadcast_msg)) => {
                        if let Ok(json) = serde_json::to_string(&broadcast_msg) {
                            if socket.send(Message::Text(json.into())).await.is_err() {
                                break; // Client disconnected
                            }
                        }
                    }
                    Some(Err(_)) => {
                        // Lagged behind — skip and continue
                        continue;
                    }
                    None => break, // Channel closed
                }
            }
            // Handle incoming messages (just ping/pong, close)
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {} // Ignore other client messages
                }
            }
        }
    }
}
