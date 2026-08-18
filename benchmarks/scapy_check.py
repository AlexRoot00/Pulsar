#!/usr/bin/env python3
#
# scapy_check.py — functional validation of XDP rules (NOT a load test!).
# Checks drop/allow correctness on individual packets.
# PPS/latency is tested separately via pktgen / MoonGen.
#
# Run (on generator, as root):
#   pip install scapy
#   IFACE=eth0 DUT_MAC=bc:24:11:5b:4a:5a DUT_IP=192.168.0.199 \
#     DUT_IFACE=enp6s18 ./scapy_check.py
#
# Optional: read DUT counters (via ssh or locally if ctl is available):
#   export COUNTERS_CMD="ssh root@192.168.0.199 ebpf-ctl counters show --iface enp6s18"
#   export COUNTERS_CMD="ebpf-ctl counters show --iface enp6s18"   # if running on DUT
#
import os
import subprocess
import sys
import time

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
    Dot1Q, Dot1AD, Raw, sendp, sniff, srp1, get_if_hwaddr,
)

IFACE     = os.environ.get("IFACE", "eth0")
DUT_MAC   = os.environ.get("DUT_MAC", "bc:24:11:5b:4a:5a")
DUT_IP    = os.environ.get("DUT_IP", "192.168.0.199")
DUT_IP6   = os.environ.get("DUT_IP6", "fe80::be24:11ff:fe5b:4a5a")
SRC_IP    = os.environ.get("SRC_IP", "10.0.0.66")   # for testing drop rules
DUT_IFACE = os.environ.get("DUT_IFACE", "enp6s18")  # port name on DUT (for ctl commands)
COUNTERS_CMD = os.environ.get("COUNTERS_CMD", "")   # see header

SRC_MAC = get_if_hwaddr(IFACE)


def read_counters():
    """Return dict 'CounterName' -> int via COUNTERS_CMD (or {} if not set)."""
    if not COUNTERS_CMD:
        return {}
    try:
        out = subprocess.run(COUNTERS_CMD.split(), capture_output=True, text=True, timeout=10)
    except Exception as e:
        print(f"  [warn] failed to read counters: {e}")
        return {}
    res = {}
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            res[parts[0]] = int(parts[-1])
    return res


def delta(c0, c1, name):
    a = c0.get(name, 0)
    b = c1.get(name, 0)
    return b - a


def send_and_sniff(pkt, timeout=2.0):
    """Send a packet and catch whether DUT responds (response => packet NOT dropped)."""
    print(f"  -> sending {pkt.summary()}")
    ans = srp1(pkt, iface=IFACE, timeout=timeout, verbose=0)
    return ans is not None


def banner(t):
    print("\n" + "=" * 60)
    print(t)
    print("=" * 60)


# ---------------------------------------------------------------------------
# S2 — L4 ACL (LPM_TRIE). Check drop for specific 5-tuple.
# ---------------------------------------------------------------------------
def scenario_s2():
    banner("S2: L4 ACL — drop specific TCP 5-tuple")

    # 1) PASS: ICMP echo to DUT should return echo-reply (XDP_PASS -> kernel stack)
    print("[pass] ICMP echo -> DUT (expecting RESPONSE):")
    icmp = Ether(dst=DUT_MAC, src=SRC_MAC) / IP(src=SRC_IP, dst=DUT_IP) / ICMP()
    got = send_and_sniff(icmp)
    print(f"  result: {'RESPONSE received (PASS works)' if got else 'NO response'}")

    # 2) DROP: add rule and send matching packet (expecting NO response + AclDrop growth)
    print("\n[drop] add rule on DUT (example):")
    rule = f"ebpf-ctl acl add drop --iface {DUT_IFACE} src {SRC_IP}:any dst {DUT_IP}:443 --proto tcp"
    print(f"    {rule}")
    print(f"  (delete later: `ebpf-ctl acl list --iface {DUT_IFACE}` -> `ebpf-ctl acl del --id <n> --iface {DUT_IFACE}`)")

    c0 = read_counters()
    tcp = (Ether(dst=DUT_MAC, src=SRC_MAC)
           / IP(src=SRC_IP, dst=DUT_IP)
           / TCP(sport=12345, dport=443, flags="S"))
    got = send_and_sniff(tcp)
    c1 = read_counters()
    print(f"  result: {'RESPONSE received (FAIL: rule did not work)' if got else 'NO response (drop OK)'}")
    if c0 and c1:
        d = delta(c0, c1, "AclDrop")
        print(f"  AclDrop delta = {d}  -> {'OK' if d > 0 else 'did not grow (check rule)'}")
    else:
        print("  (counters not readable: set COUNTERS_CMD for auto AclDrop check)")


# ---------------------------------------------------------------------------
# S4 — VLAN ACL (QinQ). Check tag parsing and RxVlan growth.
# ---------------------------------------------------------------------------
def scenario_s4():
    banner("S4: VLAN ACL — single tag and QinQ")

    print("[vlan] packet with single 802.1Q tag vlan=100:")
    v1 = (Ether(dst=DUT_MAC, src=SRC_MAC)
          / Dot1Q(vlan=100)
          / IP(src=SRC_IP, dst=DUT_IP)
          / UDP(sport=1111, dport=2222) / Raw(b"vlan100"))
    c0 = read_counters()
    sendp(v1, iface=IFACE, verbose=0)
    print("  -> sent")
    c1 = read_counters()
    if c0 and c1:
        print(f"  RxVlan delta = {delta(c0, c1, 'RxVlan')}")
    else:
        print("  (check `ebpf-ctl counters show --iface {DUT_IFACE}` -> RxVlan growth)")

    print("\n[qinq] packet with double tag (outer 200 / inner 100):")
    q = (Ether(dst=DUT_MAC, src=SRC_MAC)
         / Dot1AD(vlan=200)
         / Dot1Q(vlan=100)
         / IP(src=SRC_IP, dst=DUT_IP)
         / UDP(sport=1111, dport=2222) / Raw(b"qinq"))
    c0 = read_counters()
    sendp(q, iface=IFACE, verbose=0)
    print("  -> sent")
    c1 = read_counters()
    if c0 and c1:
        print(f"  RxVlan delta = {delta(c0, c1, 'RxVlan')}")
    else:
        print("  (check `ebpf-ctl counters show --iface {DUT_IFACE}` -> RxVlan growth)")

    print("\n[opt] VLAN rule (drop outer=100):")
    print(f"    ebpf-ctl acl vlan add 100 drop --iface {DUT_IFACE}")
    print(f"    ebpf-ctl acl vlan add 200 drop inner 100 --iface {DUT_IFACE}   # QinQ")
    print("  After this, AclDrop should grow on the same packets.")


if __name__ == "__main__":
    print(f"scapy_check: iface={IFACE} src_mac={SRC_MAC} -> DUT {DUT_IP} ({DUT_MAC})")
    print(f"counters: {'via ' + COUNTERS_CMD if COUNTERS_CMD else 'sniff-only'}")
    scenario_s2()
    scenario_s4()
    print("\nDone. This is a functional check, NOT a load benchmark.")
    print("Coverage: S2 (L4 ACL), S4 (VLAN/QinQ).")
    print("S5 (conntrack) not tested: conntrack is limited and not used.")
