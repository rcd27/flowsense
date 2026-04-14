#!/bin/sh
set -e

# ============================================================================
# flowsense Docker test topology
#
# Emulates a real bridge-box: all traffic passes through br0.
# flowsense on br0 sees DNS, SYN, RST, data — everything.
#
#   [client namespace]              [router namespace]
#    curl отсюда                     NAT → eth0 → internet
#    10.99.0.2/24                    10.99.0.1/24
#         |                              |
#     veth-client                    veth-router
#         |                              |
#     ┌───┴──────────────────────────────┴───┐
#     │                br0                    │
#     │          flowsense listens            │
#     └──────────────────────────────────────┘
#
# All traffic between client and router traverses br0.
# flowsense sees DNS responses, SYN packets, RST injections, etc.
# ============================================================================

BRIDGE=br0
NS_CLIENT=client
NS_ROUTER=router

VETH_CLIENT_BR=veth-cl-br    # bridge side of client veth
VETH_CLIENT_NS=veth-cl-ns    # client namespace side
VETH_ROUTER_BR=veth-rt-br    # bridge side of router veth
VETH_ROUTER_NS=veth-rt-ns    # router namespace side

CLIENT_IP=10.99.0.2
ROUTER_IP=10.99.0.1
SUBNET=10.99.0.0/24

PROXY_PORT=${PROXY_PORT:-8080}

echo "flowsense: setting up bridge topology..."

# --- Create bridge (no IP on bridge itself) ---
ip link add ${BRIDGE} type bridge
ip link set ${BRIDGE} up

# --- Create client namespace + veth ---
ip netns add ${NS_CLIENT}
ip link add ${VETH_CLIENT_BR} type veth peer name ${VETH_CLIENT_NS}
ip link set ${VETH_CLIENT_BR} master ${BRIDGE}
ip link set ${VETH_CLIENT_BR} up
ip link set ${VETH_CLIENT_NS} netns ${NS_CLIENT}
ip netns exec ${NS_CLIENT} ip addr add ${CLIENT_IP}/24 dev ${VETH_CLIENT_NS}
ip netns exec ${NS_CLIENT} ip link set ${VETH_CLIENT_NS} up
ip netns exec ${NS_CLIENT} ip link set lo up
ip netns exec ${NS_CLIENT} ip route add default via ${ROUTER_IP}

# --- Create router namespace + veth ---
ip netns add ${NS_ROUTER}
ip link add ${VETH_ROUTER_BR} type veth peer name ${VETH_ROUTER_NS}
ip link set ${VETH_ROUTER_BR} master ${BRIDGE}
ip link set ${VETH_ROUTER_BR} up
ip link set ${VETH_ROUTER_NS} netns ${NS_ROUTER}
ip netns exec ${NS_ROUTER} ip addr add ${ROUTER_IP}/24 dev ${VETH_ROUTER_NS}
ip netns exec ${NS_ROUTER} ip link set ${VETH_ROUTER_NS} up
ip netns exec ${NS_ROUTER} ip link set lo up

# --- Router: enable forwarding + NAT to internet via eth0 ---
# Move default route's gateway info so router namespace can reach internet
# We create a veth pair to connect router namespace to the container's eth0
VETH_WAN_NS=veth-wan-ns
VETH_WAN_HOST=veth-wan-host

ip link add ${VETH_WAN_HOST} type veth peer name ${VETH_WAN_NS}
ip link set ${VETH_WAN_HOST} up
ip link set ${VETH_WAN_NS} netns ${NS_ROUTER}
ip netns exec ${NS_ROUTER} ip link set ${VETH_WAN_NS} up

# Give WAN veth IPs for routing
ip addr add 10.98.0.1/24 dev ${VETH_WAN_HOST}
ip netns exec ${NS_ROUTER} ip addr add 10.98.0.2/24 dev ${VETH_WAN_NS}
ip netns exec ${NS_ROUTER} ip route add default via 10.98.0.1

# Host forwards router traffic to real internet
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 10.98.0.0/24 -o eth0 -j MASQUERADE
iptables -P FORWARD ACCEPT

# Router namespace: forward traffic from client subnet and NAT it
ip netns exec ${NS_ROUTER} sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
ip netns exec ${NS_ROUTER} iptables -t nat -A POSTROUTING -s ${SUBNET} -o ${VETH_WAN_NS} -j MASQUERADE
ip netns exec ${NS_ROUTER} iptables -P FORWARD ACCEPT

echo "flowsense: topology ready"
echo "flowsense:   client (${CLIENT_IP}) ──br0── router (${ROUTER_IP}) ──NAT── internet"
echo ""
echo "flowsense: test from host:"
echo "  docker exec fs-test ip netns exec client curl -s https://example.com"
echo "  docker exec fs-test ip netns exec client curl -s --max-time 10 https://www.youtube.com"
echo ""

# --- Cleanup on exit ---
cleanup() {
    echo ""
    echo "flowsense: shutting down..."
    ip netns del ${NS_CLIENT} 2>/dev/null || true
    ip netns del ${NS_ROUTER} 2>/dev/null || true
    ip link del ${BRIDGE} 2>/dev/null || true
    ip link del ${VETH_WAN_HOST} 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- Start flowsense on bridge (foreground) ---
exec flowsense -i ${BRIDGE} "$@"
