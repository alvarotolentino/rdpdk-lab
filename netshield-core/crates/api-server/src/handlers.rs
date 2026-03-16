use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use netshield_common::{Alert, AlertStatus, TrafficStats};

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub uptime_seconds: u64,
    pub version: &'static str,
    pub dpdk_mode: &'static str,
}

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        uptime_seconds: state.inner.start_time.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION"),
        dpdk_mode: state.inner.dpdk_mode,
    })
}

pub async fn stats(State(state): State<AppState>) -> Json<TrafficStats> {
    let acc = state.inner.accumulator.read().await;
    let elapsed = state.inner.start_time.elapsed().as_secs_f64();
    let pps = acc.total_packets as f64 / elapsed.max(0.001);
    let bps = acc.total_bytes as f64 / elapsed.max(0.001);
    let dist = acc.protocol_distribution();

    Json(TrafficStats {
        total_packets: acc.total_packets,
        total_bytes: acc.total_bytes,
        packets_per_second: pps,
        bytes_per_second: bps,
        protocol_distribution: dist,
        window_seconds: elapsed as u64,
        timestamp: Utc::now(),
    })
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub minutes: Option<u64>,
}

#[derive(Serialize)]
pub struct HistoryResponse {
    pub interval_seconds: u64,
    pub data_points: Vec<netshield_common::StatsSnapshot>,
}

pub async fn stats_history(
    State(state): State<AppState>,
    Query(query): Query<HistoryQuery>,
) -> Json<HistoryResponse> {
    let minutes = query.minutes.unwrap_or(5);
    let max_points = (minutes * 60) as usize;

    let history = state.inner.history.read().await;
    let data_points: Vec<_> = history.iter().rev().take(max_points).rev().cloned().collect();

    Json(HistoryResponse {
        interval_seconds: 1,
        data_points,
    })
}

#[derive(Deserialize)]
pub struct AlertsQuery {
    pub status: Option<String>,
}

#[derive(Serialize)]
pub struct AlertsResponse {
    pub alerts: Vec<Alert>,
    pub total: usize,
}

pub async fn alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertsQuery>,
) -> Json<AlertsResponse> {
    let all_alerts = state.inner.alerts.read().await;
    let filtered: Vec<Alert> = match query.status.as_deref() {
        Some("active") => all_alerts
            .iter()
            .filter(|a| a.status == AlertStatus::Active)
            .cloned()
            .collect(),
        Some("resolved") => all_alerts
            .iter()
            .filter(|a| a.status == AlertStatus::Resolved)
            .cloned()
            .collect(),
        _ => all_alerts.clone(),
    };

    let total = filtered.len();
    Json(AlertsResponse {
        alerts: filtered,
        total,
    })
}

#[derive(Deserialize)]
pub struct TopTalkersQuery {
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct TopTalker {
    pub source_ip: String,
    pub packets_per_second: f64,
    pub is_flagged: bool,
}

#[derive(Serialize)]
pub struct TopTalkersResponse {
    pub top_talkers: Vec<TopTalker>,
    pub window_seconds: u64,
}

pub async fn top_talkers(
    State(state): State<AppState>,
    Query(query): Query<TopTalkersQuery>,
) -> Json<TopTalkersResponse> {
    let limit = query.limit.unwrap_or(10);

    let detection = state.inner.detection.read().await;
    let active_alerts = detection.active_alerts();
    let flagged_ips: std::collections::HashSet<std::net::Ipv4Addr> =
        active_alerts.iter().map(|a| a.source_ip).collect();

    // Use the detection engine's internal rate data — approximate via active alerts
    // For a full implementation we'd expose raw rate tracker data
    drop(detection);

    let alerts = state.inner.alerts.read().await;
    let mut talkers: Vec<TopTalker> = alerts
        .iter()
        .filter(|a| a.status == AlertStatus::Active)
        .map(|a| TopTalker {
            source_ip: a.source_ip.to_string(),
            packets_per_second: a.packets_per_second,
            is_flagged: flagged_ips.contains(&a.source_ip),
        })
        .collect();

    talkers.sort_by(|a, b| {
        b.packets_per_second
            .partial_cmp(&a.packets_per_second)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    talkers.truncate(limit);

    Json(TopTalkersResponse {
        top_talkers: talkers,
        window_seconds: 60,
    })
}

/// Request body for the packet ingest endpoint.
#[derive(Deserialize)]
pub struct IngestRequest {
    /// Raw Ethernet frames, each base64-encoded.
    pub packets: Vec<String>,
}

#[derive(Serialize)]
pub struct IngestResponse {
    pub received: usize,
    pub parsed: usize,
    pub alerts_generated: usize,
}

/// Accept a batch of base64-encoded raw packets, parse and run detection.
pub async fn ingest(
    State(state): State<AppState>,
    Json(body): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, StatusCode> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let received = body.packets.len();
    let mut parsed: usize = 0;
    let mut alerts_generated: usize = 0;
    let now = std::time::Instant::now();

    for encoded in &body.packets {
        let raw = engine.decode(encoded).map_err(|_| StatusCode::BAD_REQUEST)?;

        if let Some(alerts) = state.process_raw_packet(&raw, now).await {
            parsed += 1;
            alerts_generated += alerts;
        }
    }

    Ok(Json(IngestResponse {
        received,
        parsed,
        alerts_generated,
    }))
}
