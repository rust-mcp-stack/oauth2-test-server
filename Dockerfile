# =============================================================================
# OAuth2 Test Server Dockerfile
# =============================================================================
# This Dockerfile supports multiple build configurations:
# - Build stages: builder (default), slim, minimal
# - Target architectures: amd64, arm64
# - Base images: debian (default), alpine
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder - Compiles the Rust application
# -----------------------------------------------------------------------------
# Use buildx for multi-platform builds: docker buildx build --platform linux/amd64,linux/arm64
FROM rust:1.82-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /build

# Copy dependency manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy source to build dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --locked 2>/dev/null || true

# Now copy the actual source
COPY src/ ./src/

# Build the application with optimizations
RUN cargo build --release --locked \
    --bin oauth2-test-server \
    --features "testing,config"

# -----------------------------------------------------------------------------
# Stage 2: Runtime - Debian-based (default)
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime-debian

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    dumb-init \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash appuser

WORKDIR /home/appuser

# Copy binary from builder
COPY --from=builder /build/target/release/oauth2-test-server .

# Create directories for config and data
RUN mkdir -p config data

# Create non-root user (already done above)
USER appuser

# Expose default port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8090/.well-known/openid-configuration || exit 1

# Default command (configurable via environment)
CMD ["oauth2-test-server"]

# -----------------------------------------------------------------------------
# Stage 3: Runtime - Alpine-based (smaller image)
# -----------------------------------------------------------------------------
FROM alpine:3.20 AS runtime-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    openssl \
    dumb-init \
    curl

# Create app user
RUN adduser -D -s /bin/sh appuser

WORKDIR /home/appuser

# Copy binary from builder
COPY --from=builder /build/target/release/oauth2-test-server .

# Create directories for config and data
RUN mkdir -p config data

# Ownership
RUN chown -R appuser:appuser /home/appuser

USER appuser

# Expose default port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8090/.well-known/openid-configuration || exit 1

# Default command
CMD ["oauth2-test-server"]

# -----------------------------------------------------------------------------
# Stage 4: Minimal - Distroless (smallest image, no shell)
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12 AS runtime-minimal

# Copy binary from builder
COPY --from=builder /build/target/release/oauth2-test-server /

# Create directories
RUN mkdir -p /home/nonroot/config /home/nonroot/data && \
    chown -R nonroot:nonroot /home/nonroot

USER nonroot

# Expose default port
EXPOSE 8090

# Health check (using wget from busybox)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8090/.well-known/openid-configuration || exit 1

# Default command
CMD ["oauth2-test-server"]

# =============================================================================
# DEFAULT BUILD TARGET (uses runtime-debian)
# =============================================================================
FROM runtime-debian AS default
