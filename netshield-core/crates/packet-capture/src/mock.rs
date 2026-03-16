//! Mock packet source — generates synthetic traffic for development and testing.
//!
//! Produces a mix of normal TCP/UDP/ICMP traffic with periodic attack bursts
//! (SYN flood, UDP flood, ICMP flood) from diverse source IPs.

use std::time::Duration;

use crate::PacketSource;

/// Synthetic packet source for development without DPDK hardware.
pub struct MockSource {
    cycle: u64,
}

impl MockSource {
    pub fn new() -> Self {
        Self { cycle: 0 }
    }
}

impl Default for MockSource {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSource for MockSource {
    fn recv_batch(&mut self, _max_batch: usize) -> Vec<Vec<u8>> {
        // Simulate DPDK poll cadence
        std::thread::sleep(Duration::from_millis(10));
        self.cycle += 1;
        generate_batch(self.cycle)
    }
}

fn generate_batch(cycle: u64) -> Vec<Vec<u8>> {
    let mut batch = Vec::with_capacity(40);

    // Normal TCP traffic (majority)
    for i in 0..10 {
        let src = normal_ip(cycle, i);
        batch.push(build_tcp_packet(
            src,
            [10, 0, 0, 100],
            8080 + (i as u16 % 4),
            80,
            0x10,
        ));
    }

    // Normal UDP traffic
    for i in 0..4 {
        let src = normal_ip(cycle, i + 10);
        batch.push(build_udp_packet(
            src,
            [10, 0, 0, 100],
            5000 + i as u16,
            53,
        ));
    }

    // Normal ICMP
    batch.push(build_icmp_packet([10, 0, 1, 1], [10, 0, 0, 100]));

    // --- Attack patterns from multiple IPs ---

    // SYN flood: 3 different attackers, staggered timing
    let syn_attackers: [[u8; 4]; 3] = [[10, 0, 0, 50], [10, 0, 0, 51], [10, 0, 0, 52]];
    for (idx, attacker) in syn_attackers.iter().enumerate() {
        let offset = (idx as u64) * 70;
        if cycle % 300 >= offset && cycle % 300 < offset + 100 {
            for port in 0..50 {
                batch.push(build_tcp_packet(
                    *attacker,
                    [10, 0, 0, 100],
                    40000 + port,
                    80,
                    0x02,
                ));
            }
        }
    }

    // UDP flood: 2 different attackers
    let udp_attackers: [[u8; 4]; 2] = [[10, 0, 0, 22], [10, 0, 0, 23]];
    for (idx, attacker) in udp_attackers.iter().enumerate() {
        let offset = (idx as u64) * 250;
        if cycle % 500 >= offset && cycle % 500 < offset + 50 {
            for port in 0..30 {
                batch.push(build_udp_packet(
                    *attacker,
                    [10, 0, 0, 100],
                    6000 + port,
                    53,
                ));
            }
        }
    }

    // ICMP flood: brief bursts
    if cycle % 400 < 40 {
        let attacker: [u8; 4] = [10, 0, 0, 33];
        for _ in 0..40 {
            batch.push(build_icmp_packet(attacker, [10, 0, 0, 100]));
        }
    }

    batch
}

fn normal_ip(cycle: u64, offset: u64) -> [u8; 4] {
    let last_octet = ((cycle + offset) % 20 + 1) as u8;
    [192, 168, 1, last_octet]
}

fn build_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(54);
    // Ethernet (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0xAA; 6]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 (20 bytes)
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&40u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64);
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);
    // TCP (20 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(0x50);
    pkt.push(tcp_flags);
    pkt.extend_from_slice(&[0xFF, 0xFF]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt
}

fn build_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(42);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xBB; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&28u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64);
    pkt.push(17); // UDP
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 2]);
    pkt
}

fn build_icmp_packet(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(42);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xCC; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&28u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64);
    pkt.push(1); // ICMP
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);
    // ICMP Echo Request (8 bytes)
    pkt.push(8);
    pkt.push(0);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 4]);
    pkt
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn mock_source_generates_packets() {
        // Direct call without sleep for testing
        let batch = generate_batch(1);
        assert!(!batch.is_empty());
        // At minimum: 10 TCP + 4 UDP + 1 ICMP = 15
        assert!(batch.len() >= 15);
    }

    #[test]
    fn mock_source_trait_works() {
        // Verify MockSource implements PacketSource
        fn assert_source<T: PacketSource>(_s: &T) {}
        let src = MockSource::new();
        assert_source(&src);
    }

    #[test]
    fn tcp_packet_valid_ethernet() {
        let pkt = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x02);
        assert_eq!(pkt.len(), 54); // 14 Eth + 20 IP + 20 TCP
        assert_eq!(&pkt[12..14], &[0x08, 0x00]); // IPv4 EtherType
        assert_eq!(pkt[23], 6); // TCP protocol
    }

    #[test]
    fn udp_packet_valid_ethernet() {
        let pkt = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53);
        assert_eq!(pkt.len(), 42); // 14 Eth + 20 IP + 8 UDP
        assert_eq!(pkt[23], 17); // UDP protocol
    }

    #[test]
    fn icmp_packet_valid_ethernet() {
        let pkt = build_icmp_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        assert_eq!(pkt.len(), 42); // 14 Eth + 20 IP + 8 ICMP
        assert_eq!(pkt[23], 1); // ICMP protocol
    }
}
