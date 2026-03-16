//! Packet capture pipeline — bridges the synchronous [`PacketSource`] with the
//! async processing world via a bounded channel.
//!
//! Architecture:
//! ```text
//! [Capture thread]  --rx_burst-->  [mpsc channel]  --recv-->  [Async task]
//!   (OS thread)                     (bounded 64)               (Tokio)
//! ```

use netshield_packet_capture::PacketSource;

use crate::state::AppState;

/// Start the packet capture pipeline.
///
/// Spawns a dedicated OS thread for the blocking packet source (DPDK poll-mode
/// or mock generator) and a Tokio task that processes received batches through
/// the parser → detection → alert pipeline.
pub fn start_capture(source: impl PacketSource, state: AppState) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<Vec<u8>>>(64);

    // Dedicated OS thread for the blocking capture source.
    // DPDK poll-mode drivers must not run inside the Tokio runtime.
    // INVARIANT: thread spawn only fails if the OS is out of resources,
    // which is an unrecoverable condition for a packet capture system.
    #[allow(clippy::expect_used)]
    std::thread::Builder::new()
        .name("packet-capture".into())
        .spawn(move || {
            capture_thread(source, tx);
        })
        .expect("failed to spawn capture thread");

    // Async task processes received batches
    tokio::spawn(process_loop(rx, state));
}

/// Blocking capture loop — runs on a dedicated OS thread.
fn capture_thread(mut source: impl PacketSource, tx: tokio::sync::mpsc::Sender<Vec<Vec<u8>>>) {
    tracing::info!("Capture thread started");
    loop {
        let batch = source.recv_batch(32);
        if batch.is_empty() {
            std::thread::yield_now();
            continue;
        }
        if tx.blocking_send(batch).is_err() {
            tracing::info!("Capture channel closed, stopping");
            break;
        }
    }
}

/// Async processing loop — receives batches from the capture thread and
/// runs each packet through the full pipeline.
async fn process_loop(mut rx: tokio::sync::mpsc::Receiver<Vec<Vec<u8>>>, state: AppState) {
    tracing::info!("Packet processing loop started");
    while let Some(batch) = rx.recv().await {
        let now = std::time::Instant::now();
        for raw in &batch {
            state.process_raw_packet(raw, now).await;
        }
    }
}
