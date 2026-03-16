//! Packet capture abstraction layer.
//!
//! Defines the [`PacketSource`] trait — a synchronous interface for receiving
//! batches of raw Ethernet frames.  Two implementations are provided:
//!
//! - **`dpdk`** (feature `dpdk`): Real DPDK poll-mode capture via `dpdk-sys`.
//! - **`mock`**: Synthetic traffic generator for development/testing.

#[cfg(feature = "dpdk")]
pub mod dpdk;

pub mod mock;

/// A synchronous source of raw Ethernet frames.
///
/// Implementations either poll a real NIC (DPDK) or generate synthetic
/// packets (mock).  The capture thread calls [`recv_batch`] in a tight
/// loop from a dedicated OS thread — never from inside the Tokio runtime.
pub trait PacketSource: Send + 'static {
    /// Receive up to `max_batch` raw Ethernet frames.
    ///
    /// DPDK: calls `rte_eth_rx_burst` — returns immediately with 0..n packets.
    /// Mock: generates a batch and sleeps briefly to simulate poll cadence.
    fn recv_batch(&mut self, max_batch: usize) -> Vec<Vec<u8>>;
}
