mod state;
mod routes;
mod handlers;
mod mock_source;
mod ws;

use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

pub use state::AppState;

/// Start the NetShield API server.
///
/// # Errors
/// Returns an error if the server cannot bind to the configured address.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("netshield_api_server=info,tower_http=info")
        }))
        .json()
        .init();

    let state = AppState::new();

    // Start the mock packet generator in the background
    let sim_state = state.clone();
    tokio::spawn(async move {
        mock_source::run_mock_traffic(sim_state).await;
    });

    // Start the periodic stats snapshot task
    let stats_state = state.clone();
    tokio::spawn(async move {
        state::snapshot_loop(stats_state).await;
    });

    // Start alert resolution task
    let alert_state = state.clone();
    tokio::spawn(async move {
        state::alert_resolution_loop(alert_state).await;
    });

    let app = routes::build_router(state)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::very_permissive(),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    tracing::info!("NetShield API listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
