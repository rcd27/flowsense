#!/bin/sh
set -e

# --- Configuration ---
BRIDGE=br0
VETH_HOST=veth-br
VETH_NS=veth-socks
NS=socks
SUBNET=10.99.0
HOST_IP=${SUBNET}.1
NS_IP=${SUBNET}.2
SOCKS_PORT=${SOCKS_PORT:-1080}

echo "flowsense: setting up network topology..."

# --- Create bridge ---
ip link add ${BRIDGE} type bridge
ip link set ${BRIDGE} up

# --- Create veth pair ---
ip link add ${VETH_HOST} type veth peer name ${VETH_NS}

# --- Add host-side veth to bridge ---
ip link set ${VETH_HOST} master ${BRIDGE}
ip link set ${VETH_HOST} up

# --- Create network namespace ---
ip netns add ${NS}

# --- Move peer veth into namespace ---
ip link set ${VETH_NS} netns ${NS}

# --- Configure namespace networking ---
ip netns exec ${NS} ip addr add ${NS_IP}/24 dev ${VETH_NS}
ip netns exec ${NS} ip link set ${VETH_NS} up
ip netns exec ${NS} ip link set lo up
ip netns exec ${NS} ip route add default via ${HOST_IP}

# --- Configure bridge IP (acts as gateway for namespace) ---
ip addr add ${HOST_IP}/24 dev ${BRIDGE}

# --- Enable IP forwarding ---
echo 1 > /proc/sys/net/ipv4/ip_forward

# --- NAT: masquerade traffic from socks namespace going to internet ---
iptables -t nat -A POSTROUTING -s ${SUBNET}.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i ${BRIDGE} -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o ${BRIDGE} -m state --state RELATED,ESTABLISHED -j ACCEPT

# --- Start microsocks in namespace (background) ---
echo "flowsense: starting SOCKS5 proxy on :${SOCKS_PORT}..."
ip netns exec ${NS} microsocks -p ${SOCKS_PORT} -b 0.0.0.0 &
SOCKS_PID=$!

# We need microsocks to listen on the namespace IP, but be reachable
# from outside the container. Add a DNAT rule to forward container's
# port to the namespace IP.
iptables -t nat -A PREROUTING -p tcp --dport ${SOCKS_PORT} -j DNAT --to-destination ${NS_IP}:${SOCKS_PORT}
iptables -t nat -A OUTPUT -p tcp --dport ${SOCKS_PORT} -j DNAT --to-destination ${NS_IP}:${SOCKS_PORT}
iptables -A FORWARD -p tcp -d ${NS_IP} --dport ${SOCKS_PORT} -j ACCEPT

# Wait a moment for microsocks to start
sleep 0.5

# Verify microsocks is running
if ! kill -0 ${SOCKS_PID} 2>/dev/null; then
    echo "flowsense: ERROR — microsocks failed to start"
    exit 1
fi

echo "flowsense: SOCKS5 proxy ready on :${SOCKS_PORT}"
echo "flowsense: configure your browser: SOCKS5 → <host-ip>:${SOCKS_PORT}"
echo ""

# --- Cleanup on exit ---
cleanup() {
    echo ""
    echo "flowsense: shutting down..."
    kill ${SOCKS_PID} 2>/dev/null || true
    ip netns del ${NS} 2>/dev/null || true
    ip link del ${BRIDGE} 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- Start flowsense (foreground) ---
# Pass through all CLI arguments except -i (we force br0)
exec flowsense -i ${BRIDGE} "$@"
