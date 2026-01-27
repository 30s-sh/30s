# syntax=docker/dockerfile:1

# Build stage
FROM rust:1.92-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build in release mode with sqlx offline
ENV SQLX_OFFLINE=true
RUN cargo build --release --package api

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/api /app/api

# Run as non-root user
RUN useradd -r -s /bin/false ssh
USER ssh

EXPOSE 8080

ENV THIRTY_SECS_HOST=0.0.0.0
ENV THIRTY_SECS_PORT=8080

CMD ["/app/api"]
