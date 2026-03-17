use clap::Parser;

/// NetShield API Server — DDoS detection with DPDK packet capture.
#[derive(Parser)]
#[command(name = "api-server", version, about)]
struct Cli {
    /// Run with synthetic mock traffic instead of DPDK capture
    #[arg(long)]
    mock: bool,

    /// DPDK EAL arguments (space-separated)
    #[arg(long, default_value = "netshield -l 0 -n 4")]
    eal_args: String,

    /// DPDK port ID to capture from
    #[arg(long, default_value_t = 0)]
    dpdk_port: u16,

    /// Number of RX ring descriptors
    #[arg(long, default_value_t = 1024)]
    rx_desc: u16,

    /// Maximum packets per rx_burst call
    #[arg(long, default_value_t = 32)]
    burst_size: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _cli = Cli::parse();

    // DPDK mode: primary capture backend (Linux with DPDK installed)
    #[cfg(feature = "dpdk")]
    if !_cli.mock {
        let config = netshield_packet_capture::dpdk::DpdkConfig {
            eal_args: _cli.eal_args.split_whitespace().map(String::from).collect(),
            port_id: _cli.dpdk_port,
            num_rx_desc: _cli.rx_desc,
            burst_size: _cli.burst_size,
            ..Default::default()
        };
        match netshield_packet_capture::dpdk::DpdkSource::init(&config) {
            Ok(source) => return netshield_api_server::run(source, "dpdk").await,
            Err(e) => {
                eprintln!("DPDK initialization failed: {e}");
                eprintln!("Falling back to mock traffic source");
            }
        }
    }

    // Mock mode: development fallback (any platform)
    {
        let source = netshield_packet_capture::mock::MockSource::new();
        netshield_api_server::run(source, "mock").await
    }
}
