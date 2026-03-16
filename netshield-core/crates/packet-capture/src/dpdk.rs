//! Real DPDK packet capture using poll-mode `rx_burst`.

use std::ffi::{CString, c_char, c_void};
use std::os::raw::c_int;

use crate::PacketSource;

/// Configuration for DPDK packet capture.
#[derive(Debug, Clone)]
pub struct DpdkConfig {
    /// EAL arguments (first element is the program name).
    pub eal_args: Vec<String>,
    /// Ethernet port to capture from.
    pub port_id: u16,
    /// RX queue index (typically 0 for single-queue setups).
    pub rx_queue_id: u16,
    /// Number of RX ring descriptors.
    pub num_rx_desc: u16,
    /// Packet mempool size (must be 2^n - 1).
    pub mempool_size: u32,
    /// Per-core mempool cache size.
    pub mempool_cache_size: u32,
    /// Maximum packets per `rx_burst` call.
    pub burst_size: u16,
}

impl Default for DpdkConfig {
    fn default() -> Self {
        Self {
            eal_args: vec![
                "netshield".into(),
                "-l".into(),
                "0".into(),
                "-n".into(),
                "4".into(),
            ],
            port_id: 0,
            rx_queue_id: 0,
            num_rx_desc: 1024,
            mempool_size: 8191,
            mempool_cache_size: 250,
            burst_size: 32,
        }
    }
}

/// Errors that can occur during DPDK initialization.
#[derive(Debug, thiserror::Error)]
pub enum DpdkError {
    #[error("EAL initialization failed (code {0})")]
    EalInit(i32),
    #[error("no DPDK-managed ports available")]
    NoPorts,
    #[error("port {0} not available ({1} ports detected)")]
    PortNotFound(u16, u16),
    #[error("port initialization failed (code {0})")]
    PortInit(i32),
    #[error("EAL argument contains interior NUL byte")]
    NulArg,
}

/// DPDK poll-mode packet source.
///
/// Captures raw Ethernet frames from a DPDK-managed NIC port using
/// `rte_eth_rx_burst`.  Packets are copied out of mbufs into owned
/// `Vec<u8>` buffers (acceptable for a POC; production would use
/// zero-copy mbuf slices).
pub struct DpdkSource {
    port_id: u16,
    rx_queue_id: u16,
    burst_size: u16,
    /// Pre-allocated array of mbuf pointers for rx_burst.
    mbuf_ptrs: Vec<*mut c_void>,
}

// SAFETY: DpdkSource is exclusively owned by the capture thread.
// DPDK mbufs belong to the calling lcore; we never share across threads.
unsafe impl Send for DpdkSource {}

impl DpdkSource {
    /// Initialize the DPDK EAL and configure `port_id` for RX capture.
    ///
    /// # Errors
    ///
    /// Returns [`DpdkError`] if EAL init, port detection, or port setup fails.
    pub fn init(config: &DpdkConfig) -> Result<Self, DpdkError> {
        // Build C-compatible argv
        let c_args: Vec<CString> = config
            .eal_args
            .iter()
            .map(|s| CString::new(s.as_str()).map_err(|_| DpdkError::NulArg))
            .collect::<Result<Vec<_>, _>>()?;

        let mut c_argv: Vec<*mut c_char> =
            c_args.iter().map(|cs| cs.as_ptr() as *mut c_char).collect();
        let argc = c_argv.len() as c_int;

        // SAFETY: valid argc/argv; EAL init is process-wide, called once.
        let ret = unsafe { dpdk_sys::rte_eal_init(argc, c_argv.as_mut_ptr()) };
        if ret < 0 {
            return Err(DpdkError::EalInit(ret));
        }

        // SAFETY: EAL is initialized.
        let port_count = unsafe { dpdk_sys::netshield_port_count() };
        if port_count == 0 {
            return Err(DpdkError::NoPorts);
        }
        if config.port_id >= port_count {
            return Err(DpdkError::PortNotFound(config.port_id, port_count));
        }

        // SAFETY: port_id is valid, mempool params are within bounds.
        let ret = unsafe {
            dpdk_sys::netshield_init_port(
                config.port_id,
                config.num_rx_desc,
                config.mempool_size,
                config.mempool_cache_size,
            )
        };
        if ret < 0 {
            return Err(DpdkError::PortInit(ret));
        }

        tracing::info!(
            port_id = config.port_id,
            rx_desc = config.num_rx_desc,
            burst_size = config.burst_size,
            "DPDK port initialized — poll-mode capture active"
        );

        Ok(Self {
            port_id: config.port_id,
            rx_queue_id: config.rx_queue_id,
            burst_size: config.burst_size,
            mbuf_ptrs: vec![std::ptr::null_mut(); config.burst_size as usize],
        })
    }
}

impl PacketSource for DpdkSource {
    fn recv_batch(&mut self, max_batch: usize) -> Vec<Vec<u8>> {
        let burst = max_batch.min(self.burst_size as usize);

        // SAFETY: mbuf_ptrs is pre-sized, DPDK writes at most `burst` pointers.
        let nb_rx = unsafe {
            dpdk_sys::netshield_rx_burst(
                self.port_id,
                self.rx_queue_id,
                self.mbuf_ptrs.as_mut_ptr(),
                burst as u16,
            )
        };

        let mut packets = Vec::with_capacity(nb_rx as usize);

        for i in 0..nb_rx as usize {
            let mbuf = self.mbuf_ptrs[i];

            // SAFETY: mbuf is a valid pointer returned by rx_burst.
            let data_ptr = unsafe { dpdk_sys::netshield_pkt_data(mbuf) };
            let data_len = unsafe { dpdk_sys::netshield_pkt_len(mbuf) };

            if !data_ptr.is_null() && data_len > 0 {
                // Copy packet data out of the mbuf into an owned buffer.
                // SAFETY: data_ptr is valid for data_len bytes (DPDK guarantee).
                let packet =
                    unsafe { std::slice::from_raw_parts(data_ptr, data_len as usize) }.to_vec();
                packets.push(packet);
            }

            // SAFETY: each mbuf must be freed after use.
            unsafe { dpdk_sys::netshield_pkt_free(mbuf) };
        }

        packets
    }
}

impl Drop for DpdkSource {
    fn drop(&mut self) {
        // SAFETY: port was started in init().
        unsafe { dpdk_sys::netshield_stop_port(self.port_id) };
        tracing::info!(port_id = self.port_id, "DPDK port stopped");
    }
}
