# === Stage 1: Build flowsense ===
FROM rust:1-slim AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/flowsense

# === Stage 2: Build microsocks ===
FROM debian:bookworm-slim AS microsocks

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev make git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/rofl0r/microsocks.git /tmp/microsocks \
    && cd /tmp/microsocks \
    && make \
    && strip microsocks

# === Stage 3: Runtime ===
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/flowsense /usr/local/bin/flowsense
COPY --from=microsocks /tmp/microsocks/microsocks /usr/local/bin/microsocks
COPY docker/entrypoint.sh /entrypoint.sh

ENV SOCKS_PORT=1080

EXPOSE 1080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--json"]
