# === Stage 1: Build flowsense ===
FROM rust:1-slim AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/flowsense

# === Stage 2: Runtime ===
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    tinyproxy \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/flowsense /usr/local/bin/flowsense
COPY docker/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--json"]
