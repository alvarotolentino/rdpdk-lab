use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Type of DDoS attack detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    SynFlood,
    UdpFlood,
    IcmpFlood,
    DnsAmplification,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SynFlood => write!(f, "SYN Flood"),
            Self::UdpFlood => write!(f, "UDP Flood"),
            Self::IcmpFlood => write!(f, "ICMP Flood"),
            Self::DnsAmplification => write!(f, "DNS Amplification"),
        }
    }
}

/// Alert severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Whether an alert is still active or has been resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    Active,
    Resolved,
}

/// A detection alert indicating a potential DDoS attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub attack_type: AttackType,
    pub severity: AlertSeverity,
    pub source_ip: Ipv4Addr,
    pub packets_per_second: f64,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub status: AlertStatus,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(AlertSeverity::Low < AlertSeverity::Medium);
        assert!(AlertSeverity::Medium < AlertSeverity::High);
        assert!(AlertSeverity::High < AlertSeverity::Critical);
    }

    #[test]
    fn attack_type_display() {
        assert_eq!(AttackType::SynFlood.to_string(), "SYN Flood");
        assert_eq!(AttackType::DnsAmplification.to_string(), "DNS Amplification");
    }

    #[test]
    fn alert_serializes() {
        let alert = Alert {
            id: "test-001".into(),
            attack_type: AttackType::SynFlood,
            severity: AlertSeverity::High,
            source_ip: Ipv4Addr::new(10, 0, 0, 50),
            packets_per_second: 50_000.0,
            started_at: Utc::now(),
            last_seen_at: Utc::now(),
            status: AlertStatus::Active,
        };
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"attack_type\":\"syn_flood\""));
        assert!(json.contains("\"severity\":\"high\""));
    }
}
