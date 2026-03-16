use std::time::{Duration, Instant};

use base64::Engine;
use clap::Parser;
use netshield_common::{DetectionConfig, StatsAccumulator};
use netshield_detection::DetectionEngine;
use netshield_packet_parser::parse_packet;
use tracing::{info, warn};

use traffic_simulator::scenarios::{Scenario, ScenarioConfig};

/// NetShield Traffic Simulator — generate synthetic network traffic
/// and run it through the detection pipeline for testing and benchmarking.
///
/// In local mode (default), packets are processed through a built-in
/// detection engine. In remote mode (--target), packets are POSTed
/// to a running API server's /api/v1/ingest endpoint.
#[derive(Parser)]
#[command(name = "traffic-simulator", version, about)]
struct Cli {
    /// Traffic scenario to run.
    #[arg(short, long, value_enum, default_value = "mixed")]
    scenario: Scenario,

    /// Packets generated per 10ms tick.
    #[arg(short, long, default_value = "50")]
    packets_per_tick: u32,

    /// Duration to run the simulation (seconds). 0 = run forever.
    #[arg(short, long, default_value = "30")]
    duration: u64,

    /// Attack traffic ratio for mixed scenario (0.0–1.0).
    #[arg(short, long, default_value = "0.1")]
    attack_ratio: f64,

    /// API server URL to send traffic to (e.g. http://localhost:3001).
    /// When set, packets are POSTed to the server instead of processed locally.
    #[arg(short, long)]
    target: Option<String>,

    /// SYN flood threshold (packets/sec) for local detection engine.
    #[arg(long, default_value = "1000")]
    syn_threshold: u64,

    /// UDP flood threshold (packets/sec) for local detection engine.
    #[arg(long, default_value = "5000")]
    udp_threshold: u64,

    /// ICMP flood threshold (packets/sec) for local detection engine.
    #[arg(long, default_value = "2000")]
    icmp_threshold: u64,

    /// Print stats every N seconds.
    #[arg(long, default_value = "5")]
    report_interval: u64,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let scenario_config = ScenarioConfig {
        scenario: cli.scenario,
        packets_per_tick: cli.packets_per_tick,
        attack_ratio: cli.attack_ratio.clamp(0.0, 1.0),
        attacker_ip: [10, 0, 0, 50],
        target_ip: [10, 0, 0, 100],
    };

    info!(
        scenario = ?cli.scenario,
        packets_per_tick = cli.packets_per_tick,
        duration_secs = cli.duration,
        mode = if cli.target.is_some() { "remote" } else { "local" },
        "Starting traffic simulation"
    );

    if let Some(target_url) = cli.target {
        run_remote(scenario_config, &target_url, cli.duration, cli.report_interval).await;
    } else {
        let detection_config = DetectionConfig {
            syn_flood_threshold_pps: cli.syn_threshold,
            udp_flood_threshold_pps: cli.udp_threshold,
            icmp_flood_threshold_pps: cli.icmp_threshold,
            ..Default::default()
        };
        run_local(scenario_config, detection_config, cli.duration, cli.report_interval).await;
    }
}

/// Local mode: run the detection pipeline in-process.
async fn run_local(
    scenario_config: ScenarioConfig,
    detection_config: DetectionConfig,
    duration_secs: u64,
    report_interval_secs: u64,
) {
    let mut engine = DetectionEngine::new(detection_config);
    let mut accumulator = StatsAccumulator::default();
    let mut rng = rand::thread_rng();

    let sim_start = Instant::now();
    let run_forever = duration_secs == 0;
    let sim_duration = Duration::from_secs(duration_secs);
    let report_interval = Duration::from_secs(report_interval_secs);
    let tick_interval = Duration::from_millis(10);

    let mut interval = tokio::time::interval(tick_interval);
    let mut last_report = sim_start;
    let mut total_alerts: u64 = 0;

    loop {
        interval.tick().await;
        let now = Instant::now();

        if !run_forever && now.duration_since(sim_start) >= sim_duration {
            break;
        }

        let batch = traffic_simulator::scenarios::generate_tick(&scenario_config, &mut rng);

        for raw in &batch {
            let timestamp_ns = now.elapsed().as_nanos() as u64;

            if let Ok(meta) = parse_packet(raw, timestamp_ns) {
                accumulator.record_packet(meta.protocol, meta.packet_len);
                let new_alerts = engine.process_packet(&meta, now);
                for alert in &new_alerts {
                    warn!(
                        attack_type = ?alert.attack_type,
                        source_ip = %alert.source_ip,
                        severity = ?alert.severity,
                        pps = alert.packets_per_second,
                        "ALERT DETECTED"
                    );
                }
                total_alerts += new_alerts.len() as u64;
            }
        }

        if now.duration_since(last_report) >= report_interval {
            let elapsed = now.duration_since(sim_start).as_secs_f64();
            let pps = accumulator.total_packets as f64 / elapsed;
            let (tcp_pps, udp_pps, icmp_pps, other_pps) = accumulator.protocol_pps(elapsed);

            info!(
                elapsed_secs = format!("{elapsed:.1}"),
                total_packets = accumulator.total_packets,
                avg_pps = format!("{pps:.0}"),
                tcp_pps = format!("{tcp_pps:.0}"),
                udp_pps = format!("{udp_pps:.0}"),
                icmp_pps = format!("{icmp_pps:.0}"),
                other_pps = format!("{other_pps:.0}"),
                total_alerts,
                "Simulation report"
            );
            last_report = now;
        }

        let _ = engine.resolve_stale_alerts(now);
    }

    let elapsed = sim_start.elapsed().as_secs_f64();
    let pps = accumulator.total_packets as f64 / elapsed.max(0.001);
    let dist = accumulator.protocol_distribution();

    info!("=== SIMULATION COMPLETE ===");
    info!(
        duration_secs = format!("{elapsed:.1}"),
        total_packets = accumulator.total_packets,
        avg_pps = format!("{pps:.0}"),
        total_alerts,
        tcp_pct = format!("{:.1}%", dist.tcp * 100.0),
        udp_pct = format!("{:.1}%", dist.udp * 100.0),
        icmp_pct = format!("{:.1}%", dist.icmp * 100.0),
        other_pct = format!("{:.1}%", dist.other * 100.0),
        "Final statistics"
    );
}

/// Remote mode: POST base64-encoded packets to the API server.
async fn run_remote(
    scenario_config: ScenarioConfig,
    target_url: &str,
    duration_secs: u64,
    report_interval_secs: u64,
) {
    let client = reqwest::Client::new();
    let ingest_url = format!("{}/api/v1/ingest", target_url.trim_end_matches('/'));
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut rng = rand::thread_rng();

    let sim_start = Instant::now();
    let run_forever = duration_secs == 0;
    let sim_duration = Duration::from_secs(duration_secs);
    let report_interval = Duration::from_secs(report_interval_secs);
    let tick_interval = Duration::from_millis(10);

    let mut interval = tokio::time::interval(tick_interval);
    let mut last_report = sim_start;
    let mut total_sent: u64 = 0;
    let mut total_parsed: u64 = 0;
    let mut total_alerts: u64 = 0;
    let mut send_errors: u64 = 0;

    info!(target = %ingest_url, "Sending traffic to remote API server");

    loop {
        interval.tick().await;
        let now = Instant::now();

        if !run_forever && now.duration_since(sim_start) >= sim_duration {
            break;
        }

        let batch = traffic_simulator::scenarios::generate_tick(&scenario_config, &mut rng);
        let encoded: Vec<String> = batch.iter().map(|pkt| b64.encode(pkt)).collect();
        let batch_size = encoded.len() as u64;

        let payload = serde_json::json!({ "packets": encoded });

        match client.post(&ingest_url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(result) = resp.json::<serde_json::Value>().await {
                    total_parsed += result["parsed"].as_u64().unwrap_or(0);
                    total_alerts += result["alerts_generated"].as_u64().unwrap_or(0);
                }
                total_sent += batch_size;
            }
            Ok(resp) => {
                send_errors += 1;
                if send_errors <= 3 {
                    warn!(status = %resp.status(), "Ingest request failed");
                }
            }
            Err(e) => {
                send_errors += 1;
                if send_errors <= 3 {
                    warn!(error = %e, "Failed to reach API server");
                }
            }
        }

        if now.duration_since(last_report) >= report_interval {
            let elapsed = now.duration_since(sim_start).as_secs_f64();
            let pps = total_sent as f64 / elapsed;

            info!(
                elapsed_secs = format!("{elapsed:.1}"),
                total_sent,
                total_parsed,
                total_alerts,
                send_errors,
                avg_pps = format!("{pps:.0}"),
                "Remote simulation report"
            );
            last_report = now;
        }
    }

    let elapsed = sim_start.elapsed().as_secs_f64();
    let pps = total_sent as f64 / elapsed.max(0.001);

    info!("=== SIMULATION COMPLETE ===");
    info!(
        duration_secs = format!("{elapsed:.1}"),
        total_sent,
        total_parsed,
        total_alerts,
        send_errors,
        avg_pps = format!("{pps:.0}"),
        "Final statistics"
    );
}
