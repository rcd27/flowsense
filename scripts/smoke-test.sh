#!/usr/bin/env bash
# flowsense smoke test — run against known-blocked domains in Russia
# Requires: root (for AF_PACKET), active internet connection behind Russian ISP
#
# Usage: sudo ./scripts/smoke-test.sh [interface]
# Default interface: auto-detect first UP non-loopback interface

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/flowsense"
RESULTS_DIR="$PROJECT_DIR/tests/smoke-results"
EVIDENCE_FILE="$RESULTS_DIR/evidence.jsonl"
REPORT_FILE="$RESULTS_DIR/report.txt"

# Blocked domains — hand-picked from runetfreedom/russia-blocked-geosite
# Mix of RST-blocked, IP-blocked, and throttled services
DOMAINS=(
    # Social / messaging — SNI-blocked (RST injection expected)
    "discord.com"
    "discord.gg"
    "linkedin.com"
    "x.com"
    "twitter.com"
    "instagram.com"
    "facebook.com"
    "t.me"

    # Media — throttled (THROTTLE_CLIFF or THROTTLE_PROBABILISTIC expected)
    "youtube.com"
    "googlevideo.com"

    # VPN / privacy — IP-blocked or RST
    "protonvpn.com"
    "nordvpn.com"
    "windscribe.com"
    "amnezia.org"

    # Tech — various blocking methods
    "medium.com"
    "patreon.com"
    "soundcloud.com"
    "dailymotion.com"
    "archive.org"
    "4pda.to"
)

# --- Setup ---

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (need AF_PACKET)"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "building flowsense..."
    cargo build --release --manifest-path="$PROJECT_DIR/Cargo.toml" 2>/dev/null
fi

# Auto-detect interface or use argument
if [ $# -ge 1 ]; then
    IFACE="$1"
else
    IFACE=$(ip -o link show up | grep -v lo | head -1 | awk -F: '{print $2}' | tr -d ' ')
    if [ -z "$IFACE" ]; then
        echo "error: no active non-loopback interface found"
        exit 1
    fi
fi

echo "=== flowsense smoke test ==="
echo "interface: $IFACE"
echo "domains:   ${#DOMAINS[@]}"
echo ""

mkdir -p "$RESULTS_DIR"
rm -f "$EVIDENCE_FILE" "$REPORT_FILE"

# --- Run flowsense in background ---

echo "starting flowsense on $IFACE..."
"$BINARY" -i "$IFACE" --json -w "$EVIDENCE_FILE" &
FLOWSENSE_PID=$!
sleep 1

if ! kill -0 "$FLOWSENSE_PID" 2>/dev/null; then
    echo "error: flowsense failed to start"
    exit 1
fi

# --- Probe blocked domains ---

echo "probing ${#DOMAINS[@]} domains..."
echo ""

for domain in "${DOMAINS[@]}"; do
    printf "  %-30s" "$domain"

    # Resolve via Google DNS (bypass provider's poisoned DNS)
    real_ip=$(dig +short "$domain" @8.8.8.8 2>/dev/null | grep -E '^[0-9]+\.' | head -1)

    if [ -z "$real_ip" ]; then
        printf "DNS FAILED\n"
        sleep 0.5
        continue
    fi

    printf "(%s) " "$real_ip"

    # HTTPS probe with --resolve to force real IP
    http_code=$(curl -so /dev/null -w "%{http_code}" \
        --connect-timeout 5 \
        --max-time 10 \
        --no-proxy "$domain" \
        --resolve "$domain:443:$real_ip" \
        "https://$domain/" 2>/dev/null || true)

    if [ -z "$http_code" ] || [ "$http_code" = "000" ]; then
        printf "BLOCKED\n"
    else
        printf "HTTP %s\n" "$http_code"
    fi

    sleep 0.5
done

echo ""
echo "waiting for flowsense to process remaining packets..."
sleep 6  # Wait for timeout-based detectors (syn_timeout=5s)

# --- Stop flowsense ---

kill "$FLOWSENSE_PID" 2>/dev/null || true
wait "$FLOWSENSE_PID" 2>/dev/null || true
sleep 1

# --- Generate report ---

echo "=== results ==="
echo ""

if [ ! -f "$EVIDENCE_FILE" ] || [ ! -s "$EVIDENCE_FILE" ]; then
    echo "no signals detected (evidence file empty)"
    exit 0
fi

TOTAL=$(wc -l < "$EVIDENCE_FILE")
echo "total signals: $TOTAL"
echo ""

# Count by signal type
echo "signals by type:"
grep -oP '"signal":"[^"]+"' "$EVIDENCE_FILE" \
    | sort | uniq -c | sort -rn \
    | while read count signal; do
        printf "  %4d  %s\n" "$count" "$signal"
    done

echo ""

# Group by dst_ip
echo "top 20 destination IPs:"
grep -oP '"dst_ip":"[^"]+"' "$EVIDENCE_FILE" \
    | sort | uniq -c | sort -rn | head -20 \
    | while read count ip; do
        printf "  %4d  %s\n" "$count" "$ip"
    done

echo ""

# RST injections specifically
RST_COUNT=$(grep -c "RST_INJECTION" "$EVIDENCE_FILE" 2>/dev/null || echo 0)
if [ "$RST_COUNT" -gt 0 ]; then
    echo "RST_INJECTION details:"
    grep "RST_INJECTION" "$EVIDENCE_FILE" \
        | python3 -c "
import sys, json
for line in sys.stdin:
    s = json.loads(line)
    ev = s.get('evidence', {})
    sni = ev.get('sni', s.get('sni', 'unknown'))
    ttl_e = ev.get('ttl_expected', '?')
    ttl_a = ev.get('ttl_actual', '?')
    print(f'  {s[\"dst_ip\"]}:{s[\"dst_port\"]}  ttl={ttl_e}→{ttl_a}  sni={sni}')
" 2>/dev/null || grep "RST_INJECTION" "$EVIDENCE_FILE" | head -10
fi

# Save report
{
    echo "flowsense smoke test — $(date -Iseconds)"
    echo "interface: $IFACE"
    echo "domains probed: ${#DOMAINS[@]}"
    echo "total signals: $TOTAL"
    echo ""
    echo "=== raw evidence ==="
    cat "$EVIDENCE_FILE"
} > "$REPORT_FILE"

echo ""
echo "full report: $REPORT_FILE"
echo "raw evidence: $EVIDENCE_FILE"
echo "=== done ==="
