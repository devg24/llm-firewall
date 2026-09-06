# ==============================================================================
# Build Stage
# ==============================================================================
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Install build dependencies required for native crypto and ML crates
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/guardian-core/Cargo.toml crates/guardian-core/
COPY crates/guardian-proxy/Cargo.toml crates/guardian-proxy/
COPY crates/guardian-cli/Cargo.toml crates/guardian-cli/

# Copy full source tree
COPY crates/ crates/
COPY src/ src/

# Build release binary for the workspace CLI
RUN cargo build --release --bin llm-firewall-rs
RUN strip /app/target/release/llm-firewall-rs

# ==============================================================================
# Runtime Stage
# ==============================================================================
FROM debian:bookworm-slim AS runner

# Install runtime dependencies: ca-certificates for TLS, curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root user and group
RUN groupadd -g 1000 guardian && \
    useradd -u 1000 -g guardian -m -s /bin/bash guardian

# Create persistent data directory for audit ledgers
RUN mkdir -p /data ~/.guardian && \
    chown -R guardian:guardian /data /home/guardian

# Copy binary from builder
COPY --from=builder /app/target/release/llm-firewall-rs /usr/local/bin/llm-firewall

USER guardian
WORKDIR /home/guardian

# Default configuration
ENV PORT=3000
ENV UPSTREAM_URL=https://api.openai.com
ENV ANTHROPIC_UPSTREAM_URL=https://api.anthropic.com
ENV RUST_LOG=info

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

ENTRYPOINT ["/usr/local/bin/llm-firewall"]
