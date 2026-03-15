use rand::Rng;

use crate::generator::{
    build_icmp_packet, build_tcp_packet, build_udp_packet, random_normal_ip, random_src_port,
};

/// A traffic scenario that generates a specific pattern of packets.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Scenario {
    /// Normal mixed traffic — TCP, UDP, ICMP at safe rates.
    Normal,
    /// SYN flood from a single attacker IP.
    SynFlood,
    /// UDP flood from a single attacker IP.
    UdpFlood,
    /// ICMP flood from a single attacker IP.
    IcmpFlood,
    /// Realistic mix: background normal traffic with periodic attack bursts.
    Mixed,
}

/// Configuration for a single simulation run.
#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    pub scenario: Scenario,
    /// Target packets per tick (each tick = 10ms).
    pub packets_per_tick: u32,
    /// Fraction of traffic that is attack traffic (0.0–1.0), used in `Mixed` mode.
    pub attack_ratio: f64,
    /// Attacker IP for flood scenarios.
    pub attacker_ip: [u8; 4],
    /// Target IP for all traffic.
    pub target_ip: [u8; 4],
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        Self {
            scenario: Scenario::Mixed,
            packets_per_tick: 50,
            attack_ratio: 0.1,
            attacker_ip: [10, 0, 0, 50],
            target_ip: [10, 0, 0, 100],
        }
    }
}

/// Generate a batch of raw packets for one tick based on the scenario.
pub fn generate_tick(config: &ScenarioConfig, rng: &mut impl Rng) -> Vec<Vec<u8>> {
    let count = config.packets_per_tick as usize;
    let mut batch = Vec::with_capacity(count);

    match config.scenario {
        Scenario::Normal => generate_normal_traffic(&mut batch, count, config, rng),
        Scenario::SynFlood => generate_syn_flood(&mut batch, count, config, rng),
        Scenario::UdpFlood => generate_udp_flood(&mut batch, count, config, rng),
        Scenario::IcmpFlood => generate_icmp_flood(&mut batch, count, config),
        Scenario::Mixed => generate_mixed_traffic(&mut batch, count, config, rng),
    }

    batch
}

fn generate_normal_traffic(
    batch: &mut Vec<Vec<u8>>,
    count: usize,
    config: &ScenarioConfig,
    rng: &mut impl Rng,
) {
    for _ in 0..count {
        let src = random_normal_ip(rng);
        let choice: f64 = rng.gen();
        if choice < 0.6 {
            // TCP ACK (normal established connection)
            batch.push(build_tcp_packet(
                src,
                config.target_ip,
                random_src_port(rng),
                80,
                0x10, // ACK
            ));
        } else if choice < 0.9 {
            // UDP DNS query
            batch.push(build_udp_packet(
                src,
                config.target_ip,
                random_src_port(rng),
                53,
            ));
        } else {
            // ICMP ping
            batch.push(build_icmp_packet(src, config.target_ip));
        }
    }
}

fn generate_syn_flood(
    batch: &mut Vec<Vec<u8>>,
    count: usize,
    config: &ScenarioConfig,
    rng: &mut impl Rng,
) {
    for _ in 0..count {
        batch.push(build_tcp_packet(
            config.attacker_ip,
            config.target_ip,
            random_src_port(rng),
            80,
            0x02, // SYN
        ));
    }
}

fn generate_udp_flood(
    batch: &mut Vec<Vec<u8>>,
    count: usize,
    config: &ScenarioConfig,
    rng: &mut impl Rng,
) {
    for _ in 0..count {
        batch.push(build_udp_packet(
            config.attacker_ip,
            config.target_ip,
            random_src_port(rng),
            53,
        ));
    }
}

fn generate_icmp_flood(batch: &mut Vec<Vec<u8>>, count: usize, config: &ScenarioConfig) {
    for _ in 0..count {
        batch.push(build_icmp_packet(config.attacker_ip, config.target_ip));
    }
}

fn generate_mixed_traffic(
    batch: &mut Vec<Vec<u8>>,
    count: usize,
    config: &ScenarioConfig,
    rng: &mut impl Rng,
) {
    let attack_count = (count as f64 * config.attack_ratio) as usize;
    let normal_count = count.saturating_sub(attack_count);

    // Normal background traffic
    generate_normal_traffic(batch, normal_count, config, rng);

    // Attack traffic — cycle through attack types
    for i in 0..attack_count {
        match i % 3 {
            0 => batch.push(build_tcp_packet(
                config.attacker_ip,
                config.target_ip,
                random_src_port(rng),
                80,
                0x02, // SYN
            )),
            1 => batch.push(build_udp_packet(
                config.attacker_ip,
                config.target_ip,
                random_src_port(rng),
                53,
            )),
            _ => batch.push(build_icmp_packet(config.attacker_ip, config.target_ip)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn normal_scenario_generates_correct_count() {
        let config = ScenarioConfig {
            scenario: Scenario::Normal,
            packets_per_tick: 100,
            ..Default::default()
        };
        let mut rng = rand::thread_rng();
        let batch = generate_tick(&config, &mut rng);
        assert_eq!(batch.len(), 100);
    }

    #[test]
    fn syn_flood_generates_only_syn_packets() {
        let config = ScenarioConfig {
            scenario: Scenario::SynFlood,
            packets_per_tick: 50,
            ..Default::default()
        };
        let mut rng = rand::thread_rng();
        let batch = generate_tick(&config, &mut rng);
        assert_eq!(batch.len(), 50);
        // All packets should be TCP (protocol byte at offset 23 = 6)
        for pkt in &batch {
            assert_eq!(pkt[23], 6, "expected TCP protocol");
            // TCP flags at offset 47 should be SYN (0x02)
            assert_eq!(pkt[47], 0x02, "expected SYN flag");
        }
    }

    #[test]
    fn mixed_scenario_includes_both_normal_and_attack() {
        let config = ScenarioConfig {
            scenario: Scenario::Mixed,
            packets_per_tick: 100,
            attack_ratio: 0.3,
            ..Default::default()
        };
        let mut rng = rand::thread_rng();
        let batch = generate_tick(&config, &mut rng);
        assert_eq!(batch.len(), 100);
    }
}
