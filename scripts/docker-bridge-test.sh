#!/usr/bin/env bash
# flowsense L2 bridge test via Docker
#
# Creates a Docker container that curls blocked domains.
# flowsense listens on the Docker bridge interface and sees all traffic.
#
# Usage: sudo ./scripts/docker-bridge-test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/flowsense"
RESULTS_DIR="$PROJECT_DIR/tests/smoke-results"
EVIDENCE_FILE="$RESULTS_DIR/evidence-bridge.jsonl"
NETWORK_NAME="flowsense-test"
CONTAINER_NAME="flowsense-probe"

DOMAINS=(
    "discord.com"
    "discord.gg"
    "linkedin.com"
    "x.com"
    "twitter.com"
    "instagram.com"
    "facebook.com"
    "t.me"
    "youtube.com"
    "protonvpn.com"
    "nordvpn.com"
    "amnezia.org"
    "medium.com"
    "patreon.com"
    "soundcloud.com"
    "archive.org"
    "4pda.to"
)

# --- Preflight ---

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "building flowsense..."
    cargo build --release --manifest-path="$PROJECT_DIR/Cargo.toml" 2>/dev/null
fi

mkdir -p "$RESULTS_DIR"
rm -f "$EVIDENCE_FILE"

# --- Create Docker network ---

echo "=== flowsense Docker bridge test ==="
echo ""

# Cleanup from previous run
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
docker network rm "$NETWORK_NAME" 2>/dev/null || true

echo "creating Docker network '$NETWORK_NAME'..."
docker network create "$NETWORK_NAME" >/dev/null

# Find the bridge interface for this network
BRIDGE_IF=$(docker network inspect "$NETWORK_NAME" -f '{{.Id}}' | cut -c1-12)
BRIDGE_IF="br-${BRIDGE_IF}"

if ! ip link show "$BRIDGE_IF" &>/dev/null; then
    echo "error: bridge interface $BRIDGE_IF not found"
    docker network rm "$NETWORK_NAME" 2>/dev/null || true
    exit 1
fi

echo "bridge interface: $BRIDGE_IF"
echo "domains: ${#DOMAINS[@]}"
echo ""

# --- Build probe script inside container ---

PROBE_SCRIPT='#!/bin/sh
echo "=== probe starting ==="
for domain in '"$(printf '"%s" ' "${DOMAINS[@]}")"'; do
    real_ip=$(dig +short "$domain" @8.8.8.8 2>/dev/null | grep -E "^[0-9]+\." | head -1)
    if [ -z "$real_ip" ]; then
        printf "  %-30s DNS FAILED\n" "$domain"
        continue
    fi
    printf "  %-30s (%s) " "$domain" "$real_ip"
    http_code=$(curl -so /dev/null -w "%{http_code}" \
        --connect-timeout 5 \
        --max-time 10 \
        --resolve "$domain:443:$real_ip" \
        "https://$domain/" 2>/dev/null || true)
    if [ -z "$http_code" ] || [ "$http_code" = "000" ]; then
        printf "BLOCKED\n"
    else
        printf "HTTP %s\n" "$http_code"
    fi
    sleep 0.3
done
echo "=== probe done ==="
'

# --- Start flowsense on bridge ---

echo "starting flowsense on $BRIDGE_IF..."
"$BINARY" -i "$BRIDGE_IF" --json -w "$EVIDENCE_FILE" &
FLOWSENSE_PID=$!
sleep 1

if ! kill -0 "$FLOWSENSE_PID" 2>/dev/null; then
    echo "error: flowsense failed to start on $BRIDGE_IF"
    docker network rm "$NETWORK_NAME" 2>/dev/null || true
    exit 1
fi

# --- Run probe container ---

echo "starting probe container..."
echo ""

docker run --rm \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --dns 8.8.8.8 \
    alpine:latest \
    sh -c "apk add --no-cache curl bind-tools >/dev/null 2>&1 && $PROBE_SCRIPT"

echo ""
echo "waiting for timeout detectors..."
sleep 8

# --- Stop flowsense ---

kill "$FLOWSENSE_PID" 2>/dev/null || true
wait "$FLOWSENSE_PID" 2>/dev/null || true

# --- Cleanup Docker ---

docker network rm "$NETWORK_NAME" 2>/dev/null || true

# --- Report ---

echo "=== flowsense results ==="
echo ""

if [ ! -f "$EVIDENCE_FILE" ] || [ ! -s "$EVIDENCE_FILE" ]; then
    echo "no signals detected"
    exit 0
fi

TOTAL=$(wc -l < "$EVIDENCE_FILE")
echo "total signals: $TOTAL"
echo ""

echo "signals by type:"
grep -oP '"signal":"[^"]+"' "$EVIDENCE_FILE" \
    | sort | uniq -c | sort -rn \
    | while read count signal; do
        printf "  %4d  %s\n" "$count" "$signal"
    done
echo ""

echo "signals by dst_ip (top 20):"
grep -oP '"dst_ip":"[^"]+"' "$EVIDENCE_FILE" \
    | sort | uniq -c | sort -rn | head -20 \
    | while read count ip; do
        printf "  %4d  %s\n" "$count" "$ip"
    done
echo ""

# Show RST injections
RST_COUNT=$(grep -c "RST_INJECTION" "$EVIDENCE_FILE" 2>/dev/null || true)
if [ -n "$RST_COUNT" ] && [ "$RST_COUNT" -gt 0 ]; then
    echo "RST_INJECTION details:"
    grep "RST_INJECTION" "$EVIDENCE_FILE" | head -20
    echo ""
fi

# Show SILENT_DROP
SILENT_COUNT=$(grep -c "SILENT_DROP" "$EVIDENCE_FILE" 2>/dev/null || true)
if [ -n "$SILENT_COUNT" ] && [ "$SILENT_COUNT" -gt 0 ]; then
    echo "SILENT_DROP details:"
    grep "SILENT_DROP" "$EVIDENCE_FILE" | head -20
    echo ""
fi

echo "raw evidence: $EVIDENCE_FILE"
echo "=== done ==="
