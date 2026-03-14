use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::Protocol;

/// Fraction of traffic per protocol (0.0–1.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDistribution {
    pub tcp: f64,
    pub udp: f64,
    pub icmp: f64,
    pub other: f64,
}

/// Aggregated traffic statistics for the current window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub protocol_distribution: ProtocolDistribution,
    pub window_seconds: u64,
    pub timestamp: DateTime<Utc>,
}

/// A single point-in-time snapshot for time-series history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub timestamp: DateTime<Utc>,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub tcp_pps: f64,
    pub udp_pps: f64,
    pub icmp_pps: f64,
    pub other_pps: f64,
}

/// Mutable counters used internally to accumulate stats before creating snapshots.
#[derive(Debug, Clone, Default)]
pub struct StatsAccumulator {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub protocol_counts: HashMap<Protocol, u64>,
    pub protocol_bytes: HashMap<Protocol, u64>,
}

impl StatsAccumulator {
    pub fn record_packet(&mut self, protocol: Protocol, len: u16) {
        self.total_packets += 1;
        self.total_bytes += u64::from(len);
        *self.protocol_counts.entry(protocol).or_insert(0) += 1;
        *self.protocol_bytes.entry(protocol).or_insert(0) += u64::from(len);
    }

    pub fn protocol_distribution(&self) -> ProtocolDistribution {
        let total = self.total_packets.max(1) as f64;
        let count = |p: Protocol| *self.protocol_counts.get(&p).unwrap_or(&0) as f64 / total;
        ProtocolDistribution {
            tcp: count(Protocol::Tcp),
            udp: count(Protocol::Udp),
            icmp: count(Protocol::Icmp),
            other: count(Protocol::Other),
        }
    }

    pub fn protocol_pps(&self, elapsed_secs: f64) -> (f64, f64, f64, f64) {
        let secs = elapsed_secs.max(0.001);
        let pps = |p: Protocol| *self.protocol_counts.get(&p).unwrap_or(&0) as f64 / secs;
        (
            pps(Protocol::Tcp),
            pps(Protocol::Udp),
            pps(Protocol::Icmp),
            pps(Protocol::Other),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_records_packets() {
        let mut acc = StatsAccumulator::default();
        acc.record_packet(Protocol::Tcp, 100);
        acc.record_packet(Protocol::Tcp, 200);
        acc.record_packet(Protocol::Udp, 150);

        assert_eq!(acc.total_packets, 3);
        assert_eq!(acc.total_bytes, 450);
        assert_eq!(acc.protocol_counts[&Protocol::Tcp], 2);
        assert_eq!(acc.protocol_counts[&Protocol::Udp], 1);
    }

    #[test]
    fn protocol_distribution_sums_to_one() {
        let mut acc = StatsAccumulator::default();
        acc.record_packet(Protocol::Tcp, 100);
        acc.record_packet(Protocol::Udp, 100);
        acc.record_packet(Protocol::Icmp, 100);
        acc.record_packet(Protocol::Other, 100);

        let dist = acc.protocol_distribution();
        let sum = dist.tcp + dist.udp + dist.icmp + dist.other;
        assert!((sum - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn protocol_pps_divides_by_elapsed() {
        let mut acc = StatsAccumulator::default();
        for _ in 0..100 {
            acc.record_packet(Protocol::Tcp, 64);
        }
        let (tcp_pps, _, _, _) = acc.protocol_pps(10.0);
        assert!((tcp_pps - 10.0).abs() < f64::EPSILON);
    }
}
