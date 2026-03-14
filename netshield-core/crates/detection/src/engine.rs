use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use chrono::Utc;
use netshield_common::{
    Alert, AlertSeverity, AlertStatus, AttackType, DetectionConfig, PacketMetadata, Protocol,
};

use crate::RateTracker;

/// Orchestrates DDoS detection across all attack types.
#[derive(Debug)]
pub struct DetectionEngine {
    config: DetectionConfig,
    syn_tracker: RateTracker,
    udp_tracker: RateTracker,
    icmp_tracker: RateTracker,
    /// Track active alerts to avoid duplicate alerting within cooldown.
    active_alerts: HashMap<(Ipv4Addr, AttackType), AlertState>,
    alert_counter: u64,
}

#[derive(Debug)]
struct AlertState {
    alert: Alert,
    last_alerted: Instant,
}

impl DetectionEngine {
    pub fn new(config: DetectionConfig) -> Self {
        let window = config.detection_window_seconds;
        Self {
            config,
            syn_tracker: RateTracker::new(window),
            udp_tracker: RateTracker::new(window),
            icmp_tracker: RateTracker::new(window),
            active_alerts: HashMap::new(),
            alert_counter: 0,
        }
    }

    /// Process a single packet and return any new or updated alerts.
    pub fn process_packet(&mut self, meta: &PacketMetadata, now: Instant) -> Vec<Alert> {
        let mut new_alerts = Vec::new();

        match meta.protocol {
            Protocol::Tcp => {
                if let Some(flags) = &meta.tcp_flags {
                    if flags.syn && !flags.ack {
                        self.syn_tracker.record(meta.src_ip, now);
                        let pps = self.syn_tracker.rate_pps(meta.src_ip, now);
                        if pps >= self.config.syn_flood_threshold_pps as f64 {
                            if let Some(alert) =
                                self.maybe_alert(meta.src_ip, AttackType::SynFlood, pps, now)
                            {
                                new_alerts.push(alert);
                            }
                        }
                    }
                }
            }
            Protocol::Udp => {
                self.udp_tracker.record(meta.src_ip, now);
                let pps = self.udp_tracker.rate_pps(meta.src_ip, now);
                if pps >= self.config.udp_flood_threshold_pps as f64 {
                    if let Some(alert) =
                        self.maybe_alert(meta.src_ip, AttackType::UdpFlood, pps, now)
                    {
                        new_alerts.push(alert);
                    }
                }
            }
            Protocol::Icmp => {
                self.icmp_tracker.record(meta.src_ip, now);
                let pps = self.icmp_tracker.rate_pps(meta.src_ip, now);
                if pps >= self.config.icmp_flood_threshold_pps as f64 {
                    if let Some(alert) =
                        self.maybe_alert(meta.src_ip, AttackType::IcmpFlood, pps, now)
                    {
                        new_alerts.push(alert);
                    }
                }
            }
            Protocol::Other => {}
        }

        new_alerts
    }

    /// Return all currently active alerts.
    pub fn active_alerts(&self) -> Vec<Alert> {
        self.active_alerts
            .values()
            .map(|state| state.alert.clone())
            .collect()
    }

    /// Resolve alerts whose source IP has dropped below threshold.
    pub fn resolve_stale_alerts(&mut self, now: Instant) -> Vec<String> {
        let cooldown = std::time::Duration::from_secs(self.config.alert_cooldown_seconds);
        let mut resolved_ids = Vec::new();

        self.active_alerts.retain(|(_ip, _atype), state| {
            if now.duration_since(state.last_alerted) > cooldown {
                state.alert.status = AlertStatus::Resolved;
                resolved_ids.push(state.alert.id.clone());
                false
            } else {
                true
            }
        });

        resolved_ids
    }

    /// Create or refresh an alert, respecting the cooldown period.
    fn maybe_alert(
        &mut self,
        ip: Ipv4Addr,
        attack_type: AttackType,
        pps: f64,
        now: Instant,
    ) -> Option<Alert> {
        let key = (ip, attack_type);
        let cooldown = std::time::Duration::from_secs(self.config.alert_cooldown_seconds);

        if let Some(state) = self.active_alerts.get_mut(&key) {
            // Update existing alert's last_seen and pps, but don't re-emit
            state.alert.last_seen_at = Utc::now();
            state.alert.packets_per_second = pps;
            state.last_alerted = now;
            None
        } else {
            self.alert_counter += 1;
            let severity = Self::classify_severity(attack_type, pps);
            let alert = Alert {
                id: format!("alert-{:06}", self.alert_counter),
                attack_type,
                severity,
                source_ip: ip,
                packets_per_second: pps,
                started_at: Utc::now(),
                last_seen_at: Utc::now(),
                status: AlertStatus::Active,
            };

            let state = AlertState {
                alert: alert.clone(),
                last_alerted: now,
            };
            self.active_alerts.insert(key, state);

            // Check if there's a stale entry to clean up
            let _ = self.resolve_stale_alerts(now.checked_sub(cooldown).unwrap_or(now));

            Some(alert)
        }
    }

    fn classify_severity(attack_type: AttackType, pps: f64) -> AlertSeverity {
        match attack_type {
            AttackType::SynFlood => {
                if pps > 20_000.0 {
                    AlertSeverity::Critical
                } else if pps > 5_000.0 {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Medium
                }
            }
            AttackType::UdpFlood => {
                if pps > 50_000.0 {
                    AlertSeverity::Critical
                } else if pps > 20_000.0 {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Medium
                }
            }
            AttackType::IcmpFlood => {
                if pps > 10_000.0 {
                    AlertSeverity::High
                } else if pps > 5_000.0 {
                    AlertSeverity::Medium
                } else {
                    AlertSeverity::Low
                }
            }
            AttackType::DnsAmplification => {
                if pps > 2_000.0 {
                    AlertSeverity::Critical
                } else {
                    AlertSeverity::High
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netshield_common::TcpFlags;
    use std::time::Duration;

    fn syn_packet(src_ip: Ipv4Addr) -> PacketMetadata {
        PacketMetadata {
            timestamp_ns: 0,
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ether_type: 0x0800,
            src_ip,
            dst_ip: Ipv4Addr::new(10, 0, 0, 100),
            protocol: Protocol::Tcp,
            src_port: 54321,
            dst_port: 80,
            packet_len: 64,
            tcp_flags: Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
            }),
        }
    }

    fn udp_packet(src_ip: Ipv4Addr) -> PacketMetadata {
        PacketMetadata {
            timestamp_ns: 0,
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ether_type: 0x0800,
            src_ip,
            dst_ip: Ipv4Addr::new(10, 0, 0, 100),
            protocol: Protocol::Udp,
            src_port: 5000,
            dst_port: 53,
            packet_len: 512,
            tcp_flags: None,
        }
    }

    fn icmp_packet(src_ip: Ipv4Addr) -> PacketMetadata {
        PacketMetadata {
            timestamp_ns: 0,
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ether_type: 0x0800,
            src_ip,
            dst_ip: Ipv4Addr::new(10, 0, 0, 100),
            protocol: Protocol::Icmp,
            src_port: 0,
            dst_port: 0,
            packet_len: 64,
            tcp_flags: None,
        }
    }

    #[test]
    fn detects_syn_flood() {
        let config = DetectionConfig {
            syn_flood_threshold_pps: 10,
            detection_window_seconds: 10,
            ..DetectionConfig::default()
        };
        let mut engine = DetectionEngine::new(config);
        let now = Instant::now();
        let ip = Ipv4Addr::new(10, 0, 0, 50);

        // Send 200 SYN packets — rate = 200/10 = 20 pps > 10 threshold
        let mut alerts = Vec::new();
        for i in 0..200 {
            let result = engine.process_packet(&syn_packet(ip), now + Duration::from_millis(i));
            alerts.extend(result);
        }

        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].attack_type, AttackType::SynFlood);
        assert_eq!(alerts[0].source_ip, ip);
    }

    #[test]
    fn detects_udp_flood() {
        let config = DetectionConfig {
            udp_flood_threshold_pps: 5,
            detection_window_seconds: 10,
            ..DetectionConfig::default()
        };
        let mut engine = DetectionEngine::new(config);
        let now = Instant::now();
        let ip = Ipv4Addr::new(10, 0, 0, 22);

        let mut alerts = Vec::new();
        for i in 0..100 {
            let result = engine.process_packet(&udp_packet(ip), now + Duration::from_millis(i));
            alerts.extend(result);
        }

        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].attack_type, AttackType::UdpFlood);
    }

    #[test]
    fn detects_icmp_flood() {
        let config = DetectionConfig {
            icmp_flood_threshold_pps: 5,
            detection_window_seconds: 10,
            ..DetectionConfig::default()
        };
        let mut engine = DetectionEngine::new(config);
        let now = Instant::now();
        let ip = Ipv4Addr::new(10, 0, 0, 33);

        let mut alerts = Vec::new();
        for i in 0..100 {
            let result = engine.process_packet(&icmp_packet(ip), now + Duration::from_millis(i));
            alerts.extend(result);
        }

        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].attack_type, AttackType::IcmpFlood);
    }

    #[test]
    fn no_alert_below_threshold() {
        let config = DetectionConfig::default(); // syn threshold = 1000 pps
        let mut engine = DetectionEngine::new(config);
        let now = Instant::now();
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        // Only 5 SYN packets in 10 seconds = 0.5 pps
        let mut alerts = Vec::new();
        for i in 0..5 {
            let result = engine.process_packet(&syn_packet(ip), now + Duration::from_secs(i));
            alerts.extend(result);
        }

        assert!(alerts.is_empty());
    }

    #[test]
    fn resolve_stale_alerts_works() {
        let config = DetectionConfig {
            syn_flood_threshold_pps: 5,
            detection_window_seconds: 10,
            alert_cooldown_seconds: 2,
            ..DetectionConfig::default()
        };
        let mut engine = DetectionEngine::new(config);
        let now = Instant::now();
        let ip = Ipv4Addr::new(10, 0, 0, 50);

        // Trigger an alert
        for i in 0..100 {
            engine.process_packet(&syn_packet(ip), now + Duration::from_millis(i));
        }
        assert!(!engine.active_alerts().is_empty());

        // After cooldown, resolve
        let resolved = engine.resolve_stale_alerts(now + Duration::from_secs(5));
        assert!(!resolved.is_empty());
        assert!(engine.active_alerts().is_empty());
    }
}
