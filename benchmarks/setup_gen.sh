#!/usr/bin/env bash
#
# setup_gen.sh — setup VLAN/QinQ interfaces on the generator machine.
# Creates sub-interfaces with IP .1 (DUT listens on .2).
# Used for S4 (VLAN ACL QinQ) scenarios from spec §6.
#
# Requirements: root, interface IF (default enp6s18).
#
set -euo pipefail

IF="${IF:-enp6s18}"

echo "=== GEN VLAN/QinQ setup (iface=$IF) ==="

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root"
    exit 1
fi

if ! ip link show "$IF" >/dev/null 2>&1; then
    echo "ERROR: interface $IF not found"
    exit 1
fi

echo "[1/6] Setting physical interface MTU..."
ip link set dev "$IF" mtu 1600
ip link set dev "$IF" up

# ------------------------------------------------------------
# VLAN 300
# ------------------------------------------------------------
echo "[2/6] Creating VLAN 300..."
ip link del "${IF}.300" 2>/dev/null || true
ip link add link "$IF" name "${IF}.300" type vlan id 300
ip link set dev "${IF}.300" mtu 1500
ip link set dev "${IF}.300" up
ip addr add 192.168.30.1/24 dev "${IF}.300"

# ------------------------------------------------------------
# VLAN 140
# ------------------------------------------------------------
echo "[3/6] Creating VLAN 140..."
ip link del "${IF}.140" 2>/dev/null || true
ip link add link "$IF" name "${IF}.140" type vlan id 140
ip link set dev "${IF}.140" mtu 1500
ip link set dev "${IF}.140" up
ip addr add 192.168.140.1/24 dev "${IF}.140"

# ------------------------------------------------------------
# QinQ 200/100
# ------------------------------------------------------------
echo "[4/6] Creating QinQ 200/100..."
ip link del "${IF}.200.100" 2>/dev/null || true
ip link del "${IF}.200" 2>/dev/null || true

ip link add link "$IF" name "${IF}.200" type vlan id 200
ip link add link "${IF}.200" name "${IF}.200.100" type vlan id 100

ip link set dev "${IF}.200" mtu 1596
ip link set dev "${IF}.200.100" mtu 1500

ip link set dev "${IF}.200" up
ip link set dev "${IF}.200.100" up
ip addr add 192.168.100.1/24 dev "${IF}.200.100"

# ------------------------------------------------------------
# QinQ 200/101
# ------------------------------------------------------------
echo "[5/6] Creating QinQ 200/101..."
ip link del "${IF}.200.101" 2>/dev/null || true
ip link add link "${IF}.200" name "${IF}.200.101" type vlan id 101
ip link set dev "${IF}.200.101" mtu 1500
ip link set dev "${IF}.200.101" up
ip addr add 192.168.101.1/24 dev "${IF}.200.101"

# ------------------------------------------------------------
# QinQ 130/100
# ------------------------------------------------------------
echo "[6/6] Creating QinQ 130/100..."
ip link del "${IF}.130.100" 2>/dev/null || true
ip link del "${IF}.130" 2>/dev/null || true

ip link add link "$IF" name "${IF}.130" type vlan id 130
ip link add link "${IF}.130" name "${IF}.130.100" type vlan id 100

ip link set dev "${IF}.130" mtu 1596
ip link set dev "${IF}.130.100" mtu 1500

ip link set dev "${IF}.130" up
ip link set dev "${IF}.130.100" up
ip addr add 192.168.130.1/24 dev "${IF}.130.100"

echo
echo "========================================"
echo " GEN configuration complete"
echo "========================================"
echo
ip -br addr show "$IF"
ip -br addr show type vlan
echo
echo "Detailed VLAN configuration:"
ip -d link show type vlan
