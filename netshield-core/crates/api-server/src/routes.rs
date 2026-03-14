use axum::Router;

use crate::handlers;
use crate::state::AppState;
use crate::ws;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", axum::routing::get(handlers::health))
        .route("/api/v1/stats", axum::routing::get(handlers::stats))
        .route(
            "/api/v1/stats/history",
            axum::routing::get(handlers::stats_history),
        )
        .route("/api/v1/alerts", axum::routing::get(handlers::alerts))
        .route(
            "/api/v1/top-talkers",
            axum::routing::get(handlers::top_talkers),
        )
        .route("/ws", axum::routing::get(ws::ws_handler))
        .with_state(state)
}
