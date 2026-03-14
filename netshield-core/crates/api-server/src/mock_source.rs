use std::time::{Duration, Instant};

use netshield_packet_parser::parse_packet;

use crate::state::{AppState, BroadcastMessage};

/// Simulates network traffic by generating synthetic packets.
/// This replaces real DPDK packet capture for the POC.
pub async fn run_mock_traffic(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    let mut cycle: u64 = 0;

    loop {
        interval.tick().await;
        cycle += 1;

        // Generate a batch of packets per tick
        let packets = generate_batch(cycle);

        for raw in &packets {
            let now = Instant::now();
            let timestamp_ns = now.elapsed().as_nanos() as u64;

            if let Ok(meta) = parse_packet(raw, timestamp_ns) {
                // Update stats accumulator
                {
                    let mut acc = state.inner.accumulator.write().await;
                    acc.record_packet(meta.protocol, meta.packet_len);
                }

                // Run detection
                let new_alerts = {
                    let mut detection = state.inner.detection.write().await;
                    detection.process_packet(&meta, now)
                };

                // Store and broadcast new alerts
                for alert in new_alerts {
                    let _ = state
                        .inner
                        .broadcast_tx
                        .send(BroadcastMessage::NewAlert(alert.clone()));
                    let mut alerts = state.inner.alerts.write().await;
                    alerts.push(alert);
                }
            }
        }
    }
}

/// Generate a batch of raw Ethernet frames simulating mixed traffic.
fn generate_batch(cycle: u64) -> Vec<Vec<u8>> {
    let mut batch = Vec::with_capacity(20);

    // Normal TCP traffic (majority)
    for i in 0..10 {
        let src = normal_ip(cycle, i);
        batch.push(build_tcp_packet(src, [10, 0, 0, 100], 8080 + (i as u16 % 4), 80, 0x10)); // ACK
    }

    // Normal UDP traffic
    for i in 0..4 {
        let src = normal_ip(cycle, i + 10);
        batch.push(build_udp_packet(src, [10, 0, 0, 100], 5000 + i as u16, 53));
    }

    // Normal ICMP
    batch.push(build_icmp_packet([10, 0, 1, 1], [10, 0, 0, 100]));

    // Simulate attack traffic every 200 cycles (~2 seconds)
    if cycle % 200 < 100 {
        let attacker: [u8; 4] = [10, 0, 0, 50];
        // SYN flood burst — 50 SYN packets
        for port in 0..50 {
            batch.push(build_tcp_packet(attacker, [10, 0, 0, 100], 40000 + port, 80, 0x02)); // SYN
        }
    }

    // Occasional UDP flood
    if cycle % 500 < 50 {
        let attacker: [u8; 4] = [10, 0, 0, 22];
        for port in 0..30 {
            batch.push(build_udp_packet(attacker, [10, 0, 0, 100], 6000 + port, 53));
        }
    }

    batch
}

/// Pick a "normal" source IP from a small pool.
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
    pkt.extend_from_slice(&40u16.to_be_bytes()); // total length
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64); // TTL
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0x00; 2]); // checksum
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // TCP (20 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]); // seq
    pkt.extend_from_slice(&[0x00; 4]); // ack
    pkt.push(0x50); // data offset
    pkt.push(tcp_flags);
    pkt.extend_from_slice(&[0xFF, 0xFF]); // window
    pkt.extend_from_slice(&[0x00; 2]); // checksum
    pkt.extend_from_slice(&[0x00; 2]); // urgent

    pkt
}

fn build_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(42);

    // Ethernet
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xBB; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);

    // IPv4
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&28u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64);
    pkt.push(17); // UDP
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // UDP
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 2]);

    pkt
}

fn build_icmp_packet(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(42);

    // Ethernet
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xCC; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);

    // IPv4
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
    pkt.push(8); // type: Echo Request
    pkt.push(0); // code
    pkt.extend_from_slice(&[0x00; 2]); // checksum
    pkt.extend_from_slice(&[0x00; 4]); // id + seq

    pkt
}
