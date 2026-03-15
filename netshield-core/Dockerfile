# --- Build stage ---
FROM rust:1.82-bookworm AS builder

WORKDIR /app

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/common/Cargo.toml crates/common/Cargo.toml
COPY crates/packet-parser/Cargo.toml crates/packet-parser/Cargo.toml
COPY crates/detection/Cargo.toml crates/detection/Cargo.toml
COPY crates/api-server/Cargo.toml crates/api-server/Cargo.toml
COPY crates/traffic-simulator/Cargo.toml crates/traffic-simulator/Cargo.toml

# Create stub source files so cargo can resolve the dependency graph
RUN mkdir -p crates/common/src && echo "pub fn stub() {}" > crates/common/src/lib.rs \
 && mkdir -p crates/packet-parser/src && echo "pub fn stub() {}" > crates/packet-parser/src/lib.rs \
 && mkdir -p crates/detection/src && echo "pub fn stub() {}" > crates/detection/src/lib.rs \
 && mkdir -p crates/api-server/src && echo "fn main() {}" > crates/api-server/src/main.rs \
 && echo "pub fn stub() {}" > crates/api-server/src/lib.rs \
 && mkdir -p crates/traffic-simulator/src && echo "fn main() {}" > crates/traffic-simulator/src/main.rs \
 && echo "pub fn stub() {}" > crates/traffic-simulator/src/lib.rs

# Build dependencies only (cached unless Cargo.toml changes)
RUN cargo build --release --bin api-server 2>/dev/null || true

# Copy actual source code
COPY crates/ crates/

# Touch files so cargo sees them as newer than the stubs
RUN find crates -name "*.rs" -exec touch {} +

# Build the real binary
RUN cargo build --release --bin api-server

# --- Runtime stage ---
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 netshield \
 && useradd --uid 1000 --gid netshield --shell /bin/false netshield

COPY --from=builder /app/target/release/api-server /usr/local/bin/api-server

USER netshield

EXPOSE 3001

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:3001/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/api-server"]
