# NetShield — DPDK Network Traffic Analyzer POC

Real-time DDoS detection proof-of-concept with a Rust backend, React dashboard, and Docker deployment.

## Architecture

```
┌─────────────────┐       ┌──────────────────────────────────────────────┐
│ React Dashboard │──────▶│          Rust API Server (Axum)              │
│(Vite + Chart.js)│ REST  │  ┌──────────┐  ┌───────────┐  ┌─────────┐    │
│                 │  +WS  │  │ Packet   │─▶│ Detection │─▶│ Alerts  │    │
│•Throughput chart│◀───── │  │ Parser   │  │ Engine    │  │ + Stats │    │
│• Protocol pie   │       │  └──────────┘  └───────────┘  └─────────┘    │
│• Alert table    │       │  Mock traffic source (POC) / DPDK (prod)     │
│• Top talkers    │       └──────────────────────────────────────────────┘
└─────────────────┘
                           ┌──────────────────────────────────────────────┐
                           │     Traffic Simulator (standalone CLI)       │
                           │  Configurable attack scenarios for testing   │
                           └──────────────────────────────────────────────┘
```

## Project Structure

```
rdpdk-lab/
├── netshield-core/           # Rust workspace
│   ├── crates/
│   │   ├── common/           # Shared types, errors, configs
│   │   ├── packet-parser/    # Ethernet/IPv4/TCP/UDP/ICMP parser
│   │   ├── detection/        # DDoS detection engine (rate tracking)
│   │   ├── api-server/       # REST + WebSocket server (Axum)
│   │   └── traffic-simulator/# Standalone traffic generator CLI
│   └── Dockerfile
├── dashboard/                # React 19 + Vite 8 SPA
│   ├── src/
│   │   ├── components/       # Header, StatsCards, Charts, AlertList, TopTalkers
│   │   ├── api.js            # REST + WebSocket client
│   │   └── App.jsx           # Main layout with polling + live updates
│   ├── nginx.conf            # Production reverse proxy config
│   └── Dockerfile
├── traffic-simulator/
│   └── Dockerfile            # Standalone simulator container
└── docker-compose.yml        # Orchestrates all services
```

## Quick Start

### Prerequisites

- **Rust** 1.82+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Node.js** 22+ (`nvm install 22`)
- **Docker** & Docker Compose (optional, for containerized deployment)

### Run Locally

**1. Start the backend:**

```bash
cd netshield-core
cargo run --release --bin api-server
```

The API server starts on `http://localhost:3001` with mock traffic generation.

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

### Run with Docker

```bash
# Backend + Dashboard
docker compose up --build

# Include the traffic simulator
docker compose --profile with-simulator up --build
```

- Dashboard: `http://localhost:8080`
- Backend API: `http://localhost:3001`

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Service health and version |
| GET | `/api/v1/stats` | Current traffic statistics |
| GET | `/api/v1/stats/history` | Time-series stats snapshots |
| GET | `/api/v1/alerts?status=active` | Active/resolved alerts |
| GET | `/api/v1/top-talkers` | Top source IPs by packet count |
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
# Run all tests (32 tests across 5 crates)
cd netshield-core && cargo test --workspace

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Dashboard lint
cd dashboard && npx eslint .

# Production dashboard build
npm run build
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust 2021, Axum 0.8, Tokio, Tower |
| Detection | Sliding-window rate tracking, per-IP counters |
| Packet Parsing | Zero-copy Ethernet/IPv4/L4 header extraction |
| Frontend | React 19, Vite 8, Chart.js, CSS custom properties |
| Deployment | Docker multi-stage builds, nginx reverse proxy |

## License

MIT
