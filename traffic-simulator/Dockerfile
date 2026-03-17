# --- Build stage ---
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Copy workspace manifests first for dependency caching
COPY netshield-core/Cargo.toml netshield-core/Cargo.lock netshield-core/
COPY netshield-core/crates/common/Cargo.toml netshield-core/crates/common/Cargo.toml
COPY netshield-core/crates/packet-parser/Cargo.toml netshield-core/crates/packet-parser/Cargo.toml
COPY netshield-core/crates/detection/Cargo.toml netshield-core/crates/detection/Cargo.toml
COPY netshield-core/crates/packet-capture/Cargo.toml netshield-core/crates/packet-capture/Cargo.toml
COPY netshield-core/crates/api-server/Cargo.toml netshield-core/crates/api-server/Cargo.toml
COPY netshield-core/crates/traffic-simulator/Cargo.toml netshield-core/crates/traffic-simulator/Cargo.toml

# Stubs for dependency caching
RUN mkdir -p netshield-core/crates/common/src && echo "pub fn stub() {}" > netshield-core/crates/common/src/lib.rs \
 && mkdir -p netshield-core/crates/packet-parser/src && echo "pub fn stub() {}" > netshield-core/crates/packet-parser/src/lib.rs \
 && mkdir -p netshield-core/crates/detection/src && echo "pub fn stub() {}" > netshield-core/crates/detection/src/lib.rs \
 && mkdir -p netshield-core/crates/packet-capture/src && echo "pub fn stub() {}" > netshield-core/crates/packet-capture/src/lib.rs \
 && mkdir -p netshield-core/crates/api-server/src && echo "fn main() {}" > netshield-core/crates/api-server/src/main.rs \
 && echo "pub fn stub() {}" > netshield-core/crates/api-server/src/lib.rs \
 && mkdir -p netshield-core/crates/traffic-simulator/src && echo "fn main() {}" > netshield-core/crates/traffic-simulator/src/main.rs \
 && echo "pub fn stub() {}" > netshield-core/crates/traffic-simulator/src/lib.rs

RUN cd netshield-core && cargo build --release --bin traffic-simulator 2>/dev/null || true

# Copy actual source
COPY netshield-core/crates/ netshield-core/crates/
RUN find netshield-core/crates -name "*.rs" -exec touch {} +

RUN cd netshield-core && cargo build --release --bin traffic-simulator

# --- Runtime stage ---
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 netshield \
 && useradd --uid 1000 --gid netshield --shell /bin/false netshield

COPY --from=builder /app/netshield-core/target/release/traffic-simulator /usr/local/bin/traffic-simulator

USER netshield

ENTRYPOINT ["/usr/local/bin/traffic-simulator"]
CMD ["--scenario", "mixed", "--duration", "60", "--packets-per-tick", "50"]
