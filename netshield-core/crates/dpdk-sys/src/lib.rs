//! Raw FFI bindings to DPDK via C helper shims.
//!
//! This crate provides the thinnest possible layer between Rust and libdpdk.
//! All DPDK macros and static-inline functions are wrapped in C helpers
//! (`src/helpers.c`) and exposed here as `extern "C"` declarations with
//! primitive types — no bindgen required.
//!
//! # Safety
//!
//! Every function in this crate is `unsafe` — callers must uphold the
//! DPDK threading and memory model invariants documented in the DPDK
//! Programmer's Guide.

#![allow(unsafe_code)]

use std::os::raw::{c_char, c_int, c_void};

extern "C" {
    // ---- EAL (called directly — these are real library symbols) ----

    /// Initialize the DPDK Environment Abstraction Layer.
    /// Must be the first DPDK call. Process-wide, call only once.
    pub fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;

    /// Clean up EAL resources. Call at process shutdown.
    pub fn rte_eal_cleanup() -> c_int;

    // ---- Port management (C helpers) ----

    /// Return the number of available DPDK Ethernet ports.
    pub fn netshield_port_count() -> u16;

    /// Configure `port_id` with one RX queue, create the mempool, and start
    /// the port in promiscuous mode.  Returns 0 on success, negative on error.
    pub fn netshield_init_port(
        port_id: u16,
        nb_rx_desc: u16,
        mempool_size: u32,
        cache_size: u32,
    ) -> c_int;

    /// Stop a previously started port.
    pub fn netshield_stop_port(port_id: u16);

    // ---- Packet reception (C helpers) ----

    /// Receive up to `nb_pkts` packets from `port_id`/`queue_id`.
    /// Returns the number of packets actually received.
    /// Each element of `rx_pkts` is an opaque mbuf pointer.
    pub fn netshield_rx_burst(
        port_id: u16,
        queue_id: u16,
        rx_pkts: *mut *mut c_void,
        nb_pkts: u16,
    ) -> u16;

    // ---- Mbuf accessors (C helpers) ----

    /// Return a pointer to the start of the packet data inside `mbuf`.
    pub fn netshield_pkt_data(mbuf: *mut c_void) -> *const u8;

    /// Return the data length of `mbuf` in bytes.
    pub fn netshield_pkt_len(mbuf: *const c_void) -> u16;

    /// Free an mbuf back to its mempool.
    pub fn netshield_pkt_free(mbuf: *mut c_void);
}
