use rand::Rng;

/// Build a raw Ethernet + IPv4 + TCP packet.
pub fn build_tcp_packet(
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
    pkt.extend_from_slice(&[0x00; 4]); // id + flags + frag
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

/// Build a raw Ethernet + IPv4 + UDP packet.
pub fn build_udp_packet(
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

    // UDP (8 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes()); // length
    pkt.extend_from_slice(&[0x00; 2]); // checksum

    pkt
}

/// Build a raw Ethernet + IPv4 + ICMP Echo Request packet.
pub fn build_icmp_packet(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
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

    // ICMP Echo Request
    pkt.push(8); // type
    pkt.push(0); // code
    pkt.extend_from_slice(&[0x00; 2]); // checksum
    pkt.extend_from_slice(&[0x00; 4]); // id + seq

    pkt
}

/// Generate a random "normal" source IP from the 192.168.1.0/24 subnet.
pub fn random_normal_ip(rng: &mut impl Rng) -> [u8; 4] {
    [192, 168, 1, rng.gen_range(1..=254)]
}

/// Generate a random high port for source.
pub fn random_src_port(rng: &mut impl Rng) -> u16 {
    rng.gen_range(1024..=65535)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tcp_packet_has_correct_length() {
        let pkt = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x02);
        assert_eq!(pkt.len(), 54); // 14 eth + 20 ip + 20 tcp
    }

    #[test]
    fn udp_packet_has_correct_length() {
        let pkt = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53);
        assert_eq!(pkt.len(), 42); // 14 eth + 20 ip + 8 udp
    }

    #[test]
    fn icmp_packet_has_correct_length() {
        let pkt = build_icmp_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        assert_eq!(pkt.len(), 42); // 14 eth + 20 ip + 8 icmp
    }
}
