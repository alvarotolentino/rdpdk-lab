# NetShield — DPDK Network Traffic Analyzer POC

Real-time DDoS detection proof-of-concept built on **DPDK** (Data Plane Development Kit) for high-performance packet capture, with a Rust backend, React dashboard, and Docker deployment.

## Architecture

```
┌─────────────────┐       ┌──────────────────────────────────────────────┐
│ React Dashboard │──────▶│          Rust API Server (Axum)              │
│(Vite + Chart.js)│ REST  │  ┌──────────────┐                            │
│                 │  +WS  │  │ DPDK Capture  │  poll-mode rx_burst       │
│•Throughput chart│◀───── │  │ (dpdk-sys FFI)│───┐                       │
│• Protocol pie   │       │  └──────────────┘    │ raw Ethernet frames   │
│• Alert table    │       │  ┌──────────┐    ┌───▼───────┐  ┌────────┐   │
│• Top talkers    │       │  │ Packet   │───▶│ Detection │─▶│ Alerts │   │
└─────────────────┘       │  │ Parser   │    │ Engine    │  │+ Stats │   │
                          │  └──────────┘    └───────────┘  └────────┘   │
                          │  Feature flags: --features dpdk | mock       │
                          └──────────────────────────────────────────────┘
                           ┌──────────────────────────────────────────────┐
                           │     Traffic Simulator (standalone CLI)       │
                           │  Configurable attack scenarios for testing   │
                           └──────────────────────────────────────────────┘
```

## DPDK Integration

NetShield captures packets directly from the NIC using DPDK's poll-mode driver, bypassing the kernel network stack for near-line-rate packet processing.

### How It Works

1. **`dpdk-sys`** — Raw FFI crate with C helper shims that wrap DPDK macros and static inlines (`rte_eth_rx_burst`, `rte_pktmbuf_mtod`, etc.). Uses `pkg-config` + `cc` to link against `libdpdk`.
2. **`packet-capture`** — Safe Rust abstraction layer defining the `PacketSource` trait:
   - `DpdkSource` (feature `dpdk`): Initializes EAL, configures the port, runs `rx_burst` in a poll loop on a dedicated OS thread.
   - `MockSource` (always available): Generates synthetic traffic for development without DPDK hardware.
3. **`api-server`** — Generic over `PacketSource`. A bounded channel bridges the blocking capture thread to the async Tokio processing pipeline.

### DPDK Prerequisites (Linux)

```bash
# Install DPDK development libraries (Debian/Ubuntu)
sudo apt-get install dpdk-dev libdpdk-dev libnuma-dev pkg-config

# Allocate hugepages (required by DPDK)
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages

# Bind a NIC to DPDK-compatible driver (replace 0000:03:00.0 with your PCI address)
sudo modprobe vfio-pci
sudo dpdk-devbind --bind=vfio-pci 0000:03:00.0
```

### Running with DPDK

```bash
cd netshield-core

# Build with DPDK support
cargo build --release --bin api-server --features dpdk

# Run with a physical NIC (port 0)
sudo ./target/release/api-server --eal-args "netshield -l 0,1 -n 4" --dpdk-port 0

# Run with pcap virtual device (no physical NIC required)
sudo ./target/release/api-server \
    --eal-args "netshield -l 0 -n 4 --vdev=net_pcap0,iface=eth0"

# Run in mock mode (no DPDK, any platform)
cargo run --release --bin api-server -- --mock
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--mock` | false | Use synthetic traffic instead of DPDK |
| `--eal-args` | `"netshield -l 0 -n 4"` | DPDK EAL initialization arguments |
| `--dpdk-port` | `0` | Ethernet port ID to capture from |
| `--rx-desc` | `1024` | Number of RX ring descriptors |
| `--burst-size` | `32` | Maximum packets per rx_burst call |

## Project Structure

```
rdpdk-lab/
├── netshield-core/           # Rust workspace
│   ├── crates/
│   │   ├── dpdk-sys/         # Raw FFI bindings to libdpdk (C shims)
│   │   ├── packet-capture/   # PacketSource trait: DpdkSource + MockSource
│   │   ├── common/           # Shared types, errors, configs
│   │   ├── packet-parser/    # Ethernet/IPv4/TCP/UDP/ICMP parser
│   │   ├── detection/        # DDoS detection engine (rate tracking)
│   │   ├── api-server/       # REST + WebSocket server (Axum)
│   │   └── traffic-simulator/# Standalone traffic generator CLI
│   └── Dockerfile            # Multi-stage build with DPDK
├── dashboard/                # React 19 + Vite 8 SPA
│   ├── src/
│   │   ├── components/       # Header, StatsCards, Charts, AlertList, TopTalkers
│   │   ├── api.js            # REST + WebSocket client
│   │   └── App.jsx           # Main layout with polling + live updates
│   ├── nginx.conf            # Production reverse proxy config
│   └── Dockerfile
├── traffic-simulator/
│   └── Dockerfile            # Standalone simulator container
└── docker-compose.yml        # Orchestrates all services (DPDK + mock profiles)
```

## Quick Start

### Prerequisites

- **Rust** 1.82+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Node.js** 22+ (`nvm install 22`)
- **Docker** & Docker Compose (optional, for containerized deployment)
- **DPDK** (optional, for real packet capture — Linux only, see [DPDK Prerequisites](#dpdk-prerequisites-linux))

### Run Locally (Mock Mode — Any Platform)

**1. Start the backend:**

```bash
cd netshield-core
cargo run --release --bin api-server -- --mock
```

The API server starts on `http://localhost:3001` with synthetic traffic generation.

**2. Start the dashboard (dev mode):**

```bash
cd dashboard
npm install
npm run dev
```

Opens at `http://localhost:5173` with Vite proxy forwarding API/WS to the backend.

**3. Run the traffic simulator (optional):**

```bash
cd netshield-core
cargo run --release --bin traffic-simulator -- --scenario syn-flood --duration 30
```

### Run with Docker (DPDK Mode)

```bash
# Default: backend (mock fallback) + Dashboard — works everywhere
docker compose up --build

# With traffic simulator
docker compose --profile with-simulator up --build

# DPDK with pcap vdev (Linux host with DPDK libs only)
docker compose -f docker-compose.yml -f docker-compose.dpdk.yml up --build
```

- Dashboard: `http://localhost:8080`
- Backend API: `http://localhost:3001`

> **Note:** The DPDK binary automatically falls back to mock traffic when
> DPDK EAL or port initialization fails (e.g. Docker Desktop on Windows/macOS).

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Service health and version |
| GET | `/api/v1/stats` | Current traffic statistics |
| GET | `/api/v1/stats/history` | Time-series stats snapshots |
| GET | `/api/v1/alerts?status=active` | Active/resolved alerts |
| GET | `/api/v1/top-talkers` | Top source IPs by packet count |
| POST | `/api/v1/ingest` | Ingest raw packets (base64 JSON) |
| WS | `/ws` | Real-time stats and alert stream |

## Detection Capabilities

| Attack Type | Detection Method | Default Threshold |
|-------------|-----------------|-------------------|
| SYN Flood | Per-IP SYN packet rate | 1,000 PPS |
| UDP Flood | Per-IP UDP packet rate | 5,000 PPS |
| ICMP Flood | Per-IP ICMP packet rate | 2,000 PPS |

Alerts include severity classification (Low / Medium / High / Critical) based on how far the rate exceeds the threshold, with cooldown-based deduplication.

## Traffic Simulator

The standalone simulator supports five scenarios:

```bash
traffic-simulator --help

# Examples:
traffic-simulator --scenario normal --duration 60
traffic-simulator --scenario syn-flood --packets-per-tick 100 --duration 30
traffic-simulator --scenario mixed --attack-ratio 0.3 --duration 120
traffic-simulator --scenario udp-flood --udp-threshold 2000
traffic-simulator --duration 0   # run forever

# Remote mode — send traffic to a running API server
traffic-simulator --scenario syn-flood --target http://localhost:3001 --duration 30
```

| Scenario | Description |
|----------|-------------|
| `normal` | Mixed TCP/UDP/ICMP at safe rates |
| `syn-flood` | SYN packets from single attacker IP |
| `udp-flood` | UDP packets from single attacker IP |
| `icmp-flood` | ICMP packets from single attacker IP |
| `mixed` | Background normal + periodic attack bursts |

## Development

```bash
# Run all tests (37 tests across 6 crates)
cd netshield-core && cargo test --workspace

# Lint (without dpdk feature — requires Linux+DPDK)
cargo clippy --all-targets -- -D warnings

# Dashboard lint
cd dashboard && npx eslint .

# Production dashboard build
npm run build
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Packet Capture | **DPDK** (poll-mode rx_burst via C FFI shims) |
| Backend | Rust 2021, Axum 0.8, Tokio, Tower |
| Detection | Sliding-window rate tracking, per-IP counters |
| Packet Parsing | Zero-copy Ethernet/IPv4/L4 header extraction |
| Frontend | React 19, Vite 8, Chart.js, CSS custom properties |
| Deployment | Docker multi-stage builds (DPDK), nginx reverse proxy |

## Crate Architecture

```
dpdk-sys              Raw C FFI (pkg-config + cc, excluded from workspace)
   │
packet-capture        PacketSource trait: DpdkSource | MockSource
   │
api-server            Axum server, generic over PacketSource
   ├── common         Shared types (Protocol, Alert, Stats, Config)
   ├── packet-parser  Ethernet/IPv4/TCP/UDP/ICMP parsing
   └── detection      Rate-based DDoS detection engine

traffic-simulator     Standalone CLI for load testing
```

## License

MIT
