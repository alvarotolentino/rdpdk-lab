# --- Build stage ---
FROM rust:1.85-bookworm AS builder

# Install DPDK development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    dpdk-dev \
    libdpdk-dev \
    libnuma-dev \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/common/Cargo.toml crates/common/Cargo.toml
COPY crates/packet-parser/Cargo.toml crates/packet-parser/Cargo.toml
COPY crates/detection/Cargo.toml crates/detection/Cargo.toml
COPY crates/packet-capture/Cargo.toml crates/packet-capture/Cargo.toml
COPY crates/dpdk-sys/Cargo.toml crates/dpdk-sys/Cargo.toml
COPY crates/api-server/Cargo.toml crates/api-server/Cargo.toml
COPY crates/traffic-simulator/Cargo.toml crates/traffic-simulator/Cargo.toml

# Copy C sources needed by dpdk-sys build.rs
COPY crates/dpdk-sys/build.rs crates/dpdk-sys/build.rs
COPY crates/dpdk-sys/src/helpers.c crates/dpdk-sys/src/helpers.c

# Create stub source files so cargo can resolve the dependency graph
RUN mkdir -p crates/common/src && echo "pub fn stub() {}" > crates/common/src/lib.rs \
 && mkdir -p crates/packet-parser/src && echo "pub fn stub() {}" > crates/packet-parser/src/lib.rs \
 && mkdir -p crates/detection/src && echo "pub fn stub() {}" > crates/detection/src/lib.rs \
 && mkdir -p crates/packet-capture/src && echo "pub fn stub() {}" > crates/packet-capture/src/lib.rs \
 && mkdir -p crates/dpdk-sys/src && echo "" > crates/dpdk-sys/src/lib.rs \
 && mkdir -p crates/api-server/src && echo "fn main() {}" > crates/api-server/src/main.rs \
 && echo "pub fn stub() {}" > crates/api-server/src/lib.rs \
 && mkdir -p crates/traffic-simulator/src && echo "fn main() {}" > crates/traffic-simulator/src/main.rs \
 && echo "pub fn stub() {}" > crates/traffic-simulator/src/lib.rs

# Build dependencies only (cached unless Cargo.toml changes)
RUN cargo build --release --bin api-server --features dpdk 2>/dev/null || true

# Copy actual source code
COPY crates/ crates/

# Touch files so cargo sees them as newer than the stubs
RUN find crates -name "*.rs" -exec touch {} + \
 && find crates -name "*.c" -exec touch {} +

# Build the real binary with DPDK support
RUN cargo build --release --bin api-server --features dpdk

# --- Runtime stage ---
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libnuma1 \
    libfdt1 \
    libjansson4 \
    libbsd0 \
    libelf1 \
    libpcap0.8 \
    libatomic1 \
    libmnl0 \
    libibverbs1 \
 && rm -rf /var/lib/apt/lists/*

# Copy DPDK shared libraries from the builder (avoids installing full dpdk-dev at runtime)
COPY --from=builder /usr/lib/x86_64-linux-gnu/librte_*.so* /lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libdpdk*.so* /lib/x86_64-linux-gnu/
RUN ldconfig

COPY --from=builder /app/target/release/api-server /usr/local/bin/api-server

# DPDK requires privileged access for hugepages and NIC binding.
# Run as root inside a privileged container.

EXPOSE 3001

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:3001/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/api-server"]
