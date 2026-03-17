use serde::{Deserialize, Serialize};

/// Detection engine thresholds and timing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub syn_flood_threshold_pps: u64,
    pub udp_flood_threshold_pps: u64,
    pub icmp_flood_threshold_pps: u64,
    pub dns_amplification_threshold_pps: u64,
    pub detection_window_seconds: u64,
    pub alert_cooldown_seconds: u64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            syn_flood_threshold_pps: 1_000,
            udp_flood_threshold_pps: 5_000,
            icmp_flood_threshold_pps: 2_000,
            dns_amplification_threshold_pps: 500,
            detection_window_seconds: 10,
            alert_cooldown_seconds: 30,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let cfg = DetectionConfig::default();
        assert_eq!(cfg.syn_flood_threshold_pps, 1_000);
        assert_eq!(cfg.detection_window_seconds, 10);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = DetectionConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: DetectionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.syn_flood_threshold_pps, cfg.syn_flood_threshold_pps);
    }
}
