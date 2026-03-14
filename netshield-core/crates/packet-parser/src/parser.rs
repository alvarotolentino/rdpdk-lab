use std::net::Ipv4Addr;

use netshield_common::{NetShieldError, PacketMetadata, Protocol, TcpFlags};

/// Minimum sizes for protocol headers.
const ETH_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ICMP_HEADER_LEN: usize = 8;

const ETHERTYPE_IPV4: u16 = 0x0800;

/// Parse a raw Ethernet frame into structured packet metadata.
///
/// # Errors
/// Returns `NetShieldError::PacketParse` if the packet is too short
/// or contains an unsupported EtherType.
pub fn parse_packet(raw: &[u8], timestamp_ns: u64) -> Result<PacketMetadata, NetShieldError> {
    if raw.len() < ETH_HEADER_LEN {
        return Err(NetShieldError::PacketParse("packet shorter than Ethernet header"));
    }

    let mut src_mac = [0u8; 6];
    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&raw[0..6]);
    src_mac.copy_from_slice(&raw[6..12]);
    let ether_type = u16::from_be_bytes([raw[12], raw[13]]);

    if ether_type != ETHERTYPE_IPV4 {
        return Err(NetShieldError::PacketParse("unsupported EtherType (only IPv4)"));
    }

    let ip_start = ETH_HEADER_LEN;
    if raw.len() < ip_start + IPV4_HEADER_LEN {
        return Err(NetShieldError::PacketParse("packet shorter than IPv4 header"));
    }

    let ip_header = &raw[ip_start..];
    let ihl = ((ip_header[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_HEADER_LEN || raw.len() < ip_start + ihl {
        return Err(NetShieldError::PacketParse("invalid IPv4 IHL"));
    }

    let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
    let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
    let ip_protocol = ip_header[9];
    let protocol = Protocol::from_ip_protocol(ip_protocol);
    let total_len = u16::from_be_bytes([ip_header[2], ip_header[3]]);

    let l4_start = ip_start + ihl;
    let (src_port, dst_port, tcp_flags) = parse_l4(raw, l4_start, protocol)?;

    Ok(PacketMetadata {
        timestamp_ns,
        src_mac,
        dst_mac,
        ether_type,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_len: total_len,
        tcp_flags,
    })
}

/// Parse layer-4 header to extract ports and TCP flags.
fn parse_l4(
    raw: &[u8],
    l4_start: usize,
    protocol: Protocol,
) -> Result<(u16, u16, Option<TcpFlags>), NetShieldError> {
    match protocol {
        Protocol::Tcp => {
            if raw.len() < l4_start + TCP_HEADER_LEN {
                return Err(NetShieldError::PacketParse("packet shorter than TCP header"));
            }
            let l4 = &raw[l4_start..];
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let flags = TcpFlags::from_raw(l4[13]);
            Ok((src_port, dst_port, Some(flags)))
        }
        Protocol::Udp => {
            if raw.len() < l4_start + UDP_HEADER_LEN {
                return Err(NetShieldError::PacketParse("packet shorter than UDP header"));
            }
            let l4 = &raw[l4_start..];
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            Ok((src_port, dst_port, None))
        }
        Protocol::Icmp => {
            if raw.len() < l4_start + ICMP_HEADER_LEN {
                return Err(NetShieldError::PacketParse("packet shorter than ICMP header"));
            }
            Ok((0, 0, None))
        }
        Protocol::Other => Ok((0, 0, None)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Build a minimal valid TCP SYN packet (Ethernet + IPv4 + TCP).
    fn make_tcp_syn_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(54);

        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0x00; 6]); // dst MAC
        pkt.extend_from_slice(&[0xAA; 6]); // src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total length (20 IP + 20 TCP)
        pkt.extend_from_slice(&[0x00; 4]); // ID, flags, fragment offset
        pkt.push(64); // TTL
        pkt.push(6); // protocol: TCP
        pkt.extend_from_slice(&[0x00; 2]); // checksum (not validated)
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0x00; 4]); // sequence number
        pkt.extend_from_slice(&[0x00; 4]); // ack number
        pkt.push(0x50); // data offset = 5 (20 bytes)
        pkt.push(0x02); // flags: SYN
        pkt.extend_from_slice(&[0xFF, 0xFF]); // window size
        pkt.extend_from_slice(&[0x00; 2]); // checksum
        pkt.extend_from_slice(&[0x00; 2]); // urgent pointer

        pkt
    }

    fn make_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(42);

        // Ethernet header
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        // IPv4 header
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&28u16.to_be_bytes()); // 20 IP + 8 UDP
        pkt.extend_from_slice(&[0x00; 4]);
        pkt.push(64);
        pkt.push(17); // protocol: UDP
        pkt.extend_from_slice(&[0x00; 2]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // UDP header (8 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes()); // length
        pkt.extend_from_slice(&[0x00; 2]); // checksum

        pkt
    }

    #[test]
    fn parse_tcp_syn() {
        let pkt = make_tcp_syn_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80);
        let meta = parse_packet(&pkt, 1000).unwrap();

        assert_eq!(meta.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(meta.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(meta.protocol, Protocol::Tcp);
        assert_eq!(meta.src_port, 12345);
        assert_eq!(meta.dst_port, 80);

        let flags = meta.tcp_flags.unwrap();
        assert!(flags.syn);
        assert!(!flags.ack);
    }

    #[test]
    fn parse_udp() {
        let pkt = make_udp_packet([192, 168, 1, 1], [8, 8, 8, 8], 5000, 53);
        let meta = parse_packet(&pkt, 2000).unwrap();

        assert_eq!(meta.protocol, Protocol::Udp);
        assert_eq!(meta.src_port, 5000);
        assert_eq!(meta.dst_port, 53);
        assert!(meta.tcp_flags.is_none());
    }

    #[test]
    fn reject_too_short() {
        let result = parse_packet(&[0u8; 10], 0);
        assert!(result.is_err());
    }

    #[test]
    fn reject_non_ipv4_ethertype() {
        let mut pkt = vec![0u8; 14];
        pkt[12] = 0x86; // IPv6 EtherType
        pkt[13] = 0xDD;
        let result = parse_packet(&pkt, 0);
        assert!(result.is_err());
    }
}
