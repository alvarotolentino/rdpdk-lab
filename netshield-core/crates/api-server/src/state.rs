use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use netshield_common::{
    Alert, DetectionConfig, StatsAccumulator, StatsSnapshot, TrafficStats,
};
use netshield_detection::DetectionEngine;
use netshield_packet_parser::parse_packet;
use tokio::sync::{broadcast, RwLock};

const MAX_HISTORY_POINTS: usize = 300; // 5 minutes at 1-second intervals

/// Shared application state wrapped in Arc for concurrent access.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<InnerState>,
}

pub struct InnerState {
    pub detection: RwLock<DetectionEngine>,
    pub accumulator: RwLock<StatsAccumulator>,
    pub history: RwLock<VecDeque<StatsSnapshot>>,
    pub alerts: RwLock<Vec<Alert>>,
    pub start_time: Instant,
    pub broadcast_tx: broadcast::Sender<BroadcastMessage>,
    pub dpdk_mode: &'static str,
}

/// Message types pushed to WebSocket clients.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum BroadcastMessage {
    StatsUpdate(TrafficStats),
    NewAlert(Alert),
    AlertResolved { id: String },
}

impl Default for AppState {
    fn default() -> Self {
        Self::new("mock")
    }
}

impl AppState {
    pub fn new(dpdk_mode: &'static str) -> Self {
        let config = DetectionConfig::default();
        let (broadcast_tx, _) = broadcast::channel(128);

        Self {
            inner: Arc::new(InnerState {
                detection: RwLock::new(DetectionEngine::new(config)),
                accumulator: RwLock::new(StatsAccumulator::default()),
                history: RwLock::new(VecDeque::with_capacity(MAX_HISTORY_POINTS)),
                alerts: RwLock::new(Vec::new()),
                start_time: Instant::now(),
                broadcast_tx,
                dpdk_mode,
            }),
        }
    }

    /// Process a single raw Ethernet frame through the full pipeline:
    /// parse → accumulate stats → detect attacks → broadcast alerts.
    ///
    /// Returns `Some(alert_count)` if the packet parsed successfully,
    /// `None` if parsing failed.
    pub async fn process_raw_packet(&self, raw: &[u8], now: Instant) -> Option<usize> {
        let timestamp_ns = now.elapsed().as_nanos() as u64;
        let meta = parse_packet(raw, timestamp_ns).ok()?;

        {
            let mut acc = self.inner.accumulator.write().await;
            acc.record_packet(meta.protocol, meta.packet_len);
        }

        let new_alerts = {
            let mut detection = self.inner.detection.write().await;
            detection.process_packet(&meta, now)
        };

        let count = new_alerts.len();
        for alert in new_alerts {
            let _ = self
                .inner
                .broadcast_tx
                .send(BroadcastMessage::NewAlert(alert.clone()));
            let mut alerts = self.inner.alerts.write().await;
            alerts.push(alert);
        }

        Some(count)
    }

    /// Snapshot current stats, push to history, and broadcast to WebSocket clients.
    pub async fn take_snapshot(&self) {
        let acc = self.inner.accumulator.read().await;
        let elapsed = self.inner.start_time.elapsed().as_secs_f64();
        let pps = acc.total_packets as f64 / elapsed.max(0.001);
        let bps = acc.total_bytes as f64 / elapsed.max(0.001);
        let dist = acc.protocol_distribution();
        let (tcp_pps, udp_pps, icmp_pps, other_pps) = acc.protocol_pps(elapsed);

        let stats = TrafficStats {
            total_packets: acc.total_packets,
            total_bytes: acc.total_bytes,
            packets_per_second: pps,
            bytes_per_second: bps,
            protocol_distribution: dist,
            window_seconds: elapsed as u64,
            timestamp: Utc::now(),
        };

        let snapshot = StatsSnapshot {
            timestamp: Utc::now(),
            packets_per_second: pps,
            bytes_per_second: bps,
            tcp_pps,
            udp_pps,
            icmp_pps,
            other_pps,
        };

        drop(acc);

        let mut history = self.inner.history.write().await;
        if history.len() >= MAX_HISTORY_POINTS {
            history.pop_front();
        }
        history.push_back(snapshot);
        drop(history);

        // Broadcast to WebSocket clients — ignore error if no receivers
        let _ = self
            .inner
            .broadcast_tx
            .send(BroadcastMessage::StatsUpdate(stats));
    }
}

/// Periodically take stats snapshots (every 1 second).
pub async fn snapshot_loop(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        state.take_snapshot().await;
    }
}

/// Periodically check for stale alerts and resolve them.
pub async fn alert_resolution_loop(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        let now = Instant::now();
        let resolved_ids = {
            let mut detection = state.inner.detection.write().await;
            detection.resolve_stale_alerts(now)
        };

        if !resolved_ids.is_empty() {
            let mut alerts = state.inner.alerts.write().await;
            for id in &resolved_ids {
                if let Some(alert) = alerts.iter_mut().find(|a| a.id == *id) {
                    alert.status = netshield_common::AlertStatus::Resolved;
                }
                let _ = state
                    .inner
                    .broadcast_tx
                    .send(BroadcastMessage::AlertResolved { id: id.clone() });
            }
        }
    }
}
