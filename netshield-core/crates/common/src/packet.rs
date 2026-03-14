use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::Protocol;

/// TCP flag bits extracted from the TCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

impl TcpFlags {
    /// Parse TCP flags from the raw flags byte.
    #[inline]
    pub fn from_raw(raw: u8) -> Self {
        Self {
            fin: raw & 0x01 != 0,
            syn: raw & 0x02 != 0,
            rst: raw & 0x04 != 0,
            psh: raw & 0x08 != 0,
            ack: raw & 0x10 != 0,
        }
    }
}

/// Metadata extracted from a parsed network packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub timestamp_ns: u64,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ether_type: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: Protocol,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_len: u16,
    pub tcp_flags: Option<TcpFlags>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flags_syn_only() {
        let flags = TcpFlags::from_raw(0x02);
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);
        assert!(!flags.rst);
        assert!(!flags.psh);
    }

    #[test]
    fn tcp_flags_syn_ack() {
        let flags = TcpFlags::from_raw(0x12);
        assert!(flags.syn);
        assert!(flags.ack);
    }

    #[test]
    fn packet_metadata_serializes() {
        let meta = PacketMetadata {
            timestamp_ns: 1_000_000,
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            dst_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ether_type: 0x0800,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            protocol: Protocol::Tcp,
            src_port: 12345,
            dst_port: 80,
            packet_len: 64,
            tcp_flags: Some(TcpFlags::from_raw(0x02)),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"protocol\":\"tcp\""));
    }
}
