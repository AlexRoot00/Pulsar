#!/usr/bin/env bash
#
# bench_xdp.sh — combined script: XDP counter measurement (DUT mode)
# and comparison of iptables / nftables / eBPF-XDP filter backends (compare mode).
#
# Merge of bench_dut.sh + bench_netfilter.sh.
#
# Modes (env MODE):
#   MODE=dut       — measure XDP dataplane: PPS, Gbps, drop, cpu
#   MODE=compare   — compare drop rules in iptables / nftables / eBPF
#   MODE=both      — first DUT, then compare
#
# Requirements:
#   - XDP attached on IFACE (ip link -> xdp/id:...)
#   - daemon running (ebpf-ctl counters show goes through socket)
#   - installed: bpftool, sysstat (mpstat), iptables, nftables, ebpf-ctl
#
# Example:
#   MODE=dut DURATION=30 IFACE=enp6s18 ./bench_xdp.sh
#   MODE=compare CTL=ebpf-ctl DURATION=30 ./bench_xdp.sh
#

set -euo pipefail

# --------------------------------------------------------------------------
# options
# --------------------------------------------------------------------------
IFACE="${IFACE:-enp6s18}"
DURATION="${DURATION:-30}"
SRC_IP="${SRC_IP:-192.168.0.198}"
DST_IP="${DST_IP:-192.168.0.199}"
PROTO="${PROTO:-udp}"
CTL="${CTL:-./target/release/ebpf-ctl}"
DAEMON_BIN="${DAEMON_BIN:-}"
MODE="${MODE:-dut}"
DEBUG="${DEBUG:-0}"

# --------------------------------------------------------------------------
# sysctl from spec §4.2 (requires root)
# --------------------------------------------------------------------------
sysctl kernel.bpf_stats_enabled=1 \
       net.core.bpf_jit_enable=1 \
       net.core.bpf_jit_harden=0 \
       net.core.netdev_budget=60000 \
       net.core.netdev_budget_usecs=4000 \
       net.core.netdev_max_backlog=250000 >/dev/null 2>&1 || true

[ "$DEBUG" = "1" ] && echo "  [debug] MODE=$MODE IFACE=$IFACE DURATION=$DURATION CTL=$CTL"

# --------------------------------------------------------------------------
# common functions
# --------------------------------------------------------------------------

# read counters via temp file: otherwise awk exits on match,
# pipe closes, and ebpf-ctl catches SIGPIPE (Broken pipe) and panics.
get_counter() {
  local tmp
  tmp=$(mktemp)
  "$CTL" counters show > "$tmp" 2>/dev/null || true
  grep -iw "$1" "$tmp" | awk '{print $2}'
  rm -f "$tmp"
}

# read IP-level RX stats (bytes, packets)
get_rx_stats() {
  ip -s link show "$IFACE" | awk '/RX:/{getline; print $1, $2}'
}

# check that XDP is active
check_xdp() {
  if ! ip link show "$IFACE" | grep -qi "xdp"; then
    echo "WARNING: XDP is not attached on $IFACE!" >&2
    return 1
  fi
}

# start daemon if not running
ensure_daemon() {
  if pgrep -x ebpf-daemon >/dev/null 2>&1; then
    return 0
  fi
  echo "  [ebpf] daemon is not running — starting in background (log test.log)"
  local daemon
  daemon="${DAEMON_BIN:-./target/debug/ebpf-daemon}"
  [ -x "$daemon" ] || daemon="./target/release/ebpf-daemon"
  [ -x "$daemon" ] || daemon="ebpf-daemon"
  "$daemon" > test.log 2>&1 &
  sleep 1
}

# --------------------------------------------------------------------------
# === MODE DUT: measure XDP counters ===
# --------------------------------------------------------------------------
run_dut() {
  echo "== bench_dut: iface=$IFACE, dur=$DURATION =="
  check_xdp || true
  ensure_daemon

  # CPU on RX cores (background, log in /tmp/mpstat.log)
  mpstat -P ALL 1 "$DURATION" > /tmp/mpstat.log 2>&1 &

  local rxp_start rxb_start drp_start acl_start rl_start vlan_start
  rxp_start=$(get_counter rx_packets)
  rxb_start=$(get_counter rx_bytes)
  drp_start=$(get_counter dropped)
  acl_start=$(get_counter acl_drop)
  rl_start=$(get_counter rate_limited)
  vlan_start=$(get_counter rx_vlan)

  sleep "$DURATION"

  local rxp_end rxb_end drp_end acl_end rl_end vlan_end
  rxp_end=$(get_counter rx_packets)
  rxb_end=$(get_counter rx_bytes)
  drp_end=$(get_counter dropped)
  acl_end=$(get_counter acl_drop)
  rl_end=$(get_counter rate_limited)
  vlan_end=$(get_counter rx_vlan)

  awk -v d="$DURATION" -v a="$rxp_start" -v b="$rxp_end" \
      -v ba="$rxb_start" -v bb="$rxb_end" \
      -v da="$drp_start" -v db="$drp_end" \
      -v aa="$acl_start" -v ab="$acl_end" \
      -v ra="$rl_start"  -v rb="$rl_end" \
      -v va="$vlan_start" -v vb="$vlan_end" '
    function num(x){ return (x==""?0:x)+0 }
    BEGIN {
      a=num(a); b=num(b); ba=num(ba); bb=num(bb);
      da=num(da); db=num(db); aa=num(aa); ab=num(ab);
      ra=num(ra); rb=num(rb); va=num(va); vb=num(vb);
      rx=b-a; rbyt=bb-ba; dr=db-da;
      pps=(d>0)?rx/d:0;
      gbps=(d>0)?(rbyt*8/d/1e9):0;
      drop_pct=(rx>0)?(dr*100/rx):0;
      printf "RxPackets/s : %.0f\n", pps;
      printf "Gbps        : %.3f\n", gbps;
      printf "Dropped     : %d (%.2f%%)\n", dr, drop_pct;
      printf "AclDrop     : %d\n", ab-aa;
      printf "RateLimited : %d\n", rb-ra;
      printf "RxVlan      : %d\n", vb-va;
    }
  '
  echo "== CPU (mpstat, RX cores) — see /tmp/mpstat.log =="
  echo "avg idle/user (ALL):"
  awk 'NR>3 && $1=="Average:" {print}' /tmp/mpstat.log
}

# --------------------------------------------------------------------------
# === MODE COMPARE: iptables vs nftables vs eBPF ===
# --------------------------------------------------------------------------

# check for flow rules
ipt_rules_exist() {
  iptables -L INPUT -v -n 2>/dev/null \
    | awk -v s="$SRC_IP" -v d="$DST_IP" '$0 ~ s && $0 ~ d && /DROP/ {found=1} END{exit !found}'
}
have_nft() {
  command -v nft >/dev/null 2>&1
}
nft_rules_exist() {
  nft list ruleset 2>/dev/null | grep -q "ip saddr $SRC_IP ip daddr $DST_IP" || return 1
}
ebpf_rules_exist() {
  "$CTL" acl list 2>/dev/null | grep -q "$SRC_IP" || return 1
}

check_clean() {
  local ok=1
  if ipt_rules_exist; then echo "FAIL: iptables already contains rule $SRC_IP->$DST_IP"; ok=0; fi
  if nft_rules_exist; then echo "FAIL: nftables already contains rule $SRC_IP->$DST_IP"; ok=0; fi
  if ebpf_rules_exist; then echo "FAIL: ebpf-acl already contains rule $SRC_IP"; ok=0; fi
  if [ "$ok" -eq 1 ]; then
    echo "OK: no rules for $SRC_IP->$DST_IP in any subsystem (lists match/empty)"
    return 0
  fi
  return 1
}

# sampling rule counters
ipt_drop_pkts() {
  iptables -L INPUT -v -n -x 2>/dev/null \
    | awk -v s="$SRC_IP" -v d="$DST_IP" '$0 ~ s && $0 ~ d && /DROP/ {print $1; exit}' || true
}
nft_drop_pkts() {
  nft -n list table inet benchfilter 2>/dev/null | awk '
    /counter packets/ {
      for (i=1; i<=NF; i++) if ($i == "packets") { print $(i+1); exit }
    }
  ' || true
}
ebpf_acl_drop() {
  get_counter acl_drop
}
ebpf_rx_pkts() {
  get_counter rx_packets
}

# overall measurement: total RX (bytes/pkts) + CPU for DURATION
measure() {
  local label="$1"
  local b1 p1 b2 p2 rx_b rx_p gbps
  read -r b1 p1 < <(get_rx_stats)
  mpstat -P ALL 1 "$DURATION" > /tmp/mpstat_nf.log 2>&1 &
  sleep "$DURATION"
  read -r b2 p2 < <(get_rx_stats)

  rx_b=$((b2 - b1)); rx_p=$((p2 - p1))
  gbps=$(awk -v d="$DURATION" -v b="$rx_b" 'BEGIN{printf "%.3f", (d>0)?(b*8/d/1e9):0}')
  echo "  [$label] RX total: $rx_p pkts / $rx_b bytes => Gbps=$gbps"
  echo "  [$label] CPU (mpstat, RX cores):"
  awk 'NR>3 && $1=="Average:" {print "    "$0}' /tmp/mpstat_nf.log
}

# delete ONLY our artifacts (for repeated runs after Ctrl-C)
clean_artifacts() {
  nft delete table inet benchfilter 2>/dev/null || true
  iptables -D INPUT -p "$PROTO" -s "$SRC_IP" -d "$DST_IP" -j DROP 2>/dev/null || true
  local id
  id=$("$CTL" acl list 2>/dev/null | awk -v s="$SRC_IP" '$0 ~ s {print $1; exit}' || true)
  [ -n "$id" ] && "$CTL" acl del --id "$id" 2>/dev/null || true
}

stage_iptables() {
  echo "== STEP 1: iptables =="
  iptables -D INPUT -p "$PROTO" -s "$SRC_IP" -d "$DST_IP" -j DROP 2>/dev/null || true
  iptables -A INPUT -p "$PROTO" -s "$SRC_IP" -d "$DST_IP" -j DROP
  local p1 p2 drop
  p1=$(ipt_drop_pkts)
  measure "iptables"
  p2=$(ipt_drop_pkts)
  drop=$(( (${p2:-0}) - (${p1:-0}) ))
  echo "  [iptables] DROP PPS (rule counter): $((drop / DURATION))"
  if [ "$drop" -gt 0 ]; then echo "  [iptables] OK: rule matched $drop packets"; else echo "  [iptables] WARN: counter did not grow (no traffic/match)"; fi
  iptables -D INPUT -p "$PROTO" -s "$SRC_IP" -d "$DST_IP" -j DROP 2>/dev/null || true
  echo "  [iptables] rule deleted"
}

stage_nftables() {
  echo "== STEP 2: nftables =="
  if ! have_nft; then
    echo "  [nftables] WARN: nft not installed, step skipped."
    echo "    sudo apt install nftables   (or: sudo yum install nftables)"
    return 0
  fi

  modprobe nf_tables 2>/dev/null || true

  local p1 p2 drop err tmp
  nft delete table inet benchfilter 2>/dev/null || true

  tmp=$(mktemp)
  cat > "$tmp" <<EOF
table inet benchfilter {
    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr $SRC_IP ip daddr $DST_IP ip protocol $PROTO counter drop
    }
}
EOF
  if ! err=$(nft -f "$tmp" 2>&1); then
    echo "  [nftables] WARN: nft setup failed, step skipped:"
    echo "$err" | sed 's/^/    /'
    echo "    Try: sudo modprobe nf_tables"
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"

  if [ "$DEBUG" = "1" ]; then
    echo "  [nftables debug] nft_drop_pkts p1=$p1"
    echo "  [nftables debug] table listing (-n):"
    nft -n list table inet benchfilter 2>&1 | sed 's/^/    /' || true
  fi
  p1=$(nft_drop_pkts)
  measure "nftables"
  p2=$(nft_drop_pkts)
  if [ "$DEBUG" = "1" ]; then
    echo "  [nftables debug] nft_drop_pkts p2=$p2"
    echo "  [nftables debug] raw nft output:"
    nft -n list table inet benchfilter 2>&1 | sed 's/^/    /' || true
  fi
  drop=$(( (${p2:-0}) - (${p1:-0}) ))
  echo "  [nftables] DROP PPS (rule counter): $((drop / DURATION))"
  if [ "$drop" -gt 0 ]; then echo "  [nftables] OK: rule matched $drop packets"; else echo "  [nftables] WARN: counter did not grow"; fi
  echo "  [nftables] table benchfilter deleted"
}

stage_ebpf() {
  echo "== STEP 3: eBPF (XDP) =="
  check_xdp || true
  ensure_daemon
  if ebpf_rules_exist; then
    local old_id
    old_id=$("$CTL" acl list 2>/dev/null | awk -v s="$SRC_IP" '$0 ~ s {print $1; exit}' || true)
    [ -n "$old_id" ] && "$CTL" acl del --id "$old_id" 2>/dev/null || true
  fi
  "$CTL" acl add drop src "${SRC_IP}:any" dst "${DST_IP}:any" proto "$PROTO" >/dev/null 2>&1 || true
  local id a1 a2 drop rx1 rx2 rx_delta
  id=$("$CTL" acl list 2>/dev/null | awk -v s="$SRC_IP" '$0 ~ s {print $1; exit}' || true)
  a1=$(ebpf_acl_drop)
  rx1=$(ebpf_rx_pkts)
  measure "ebpf"
  a2=$(ebpf_acl_drop)
  rx2=$(ebpf_rx_pkts)
  drop=$(( (${a2:-0}) - (${a1:-0}) ))
  rx_delta=$(( (${rx2:-0}) - (${rx1:-0}) ))
  echo "  [ebpf] AclDrop PPS: $((drop / DURATION))  (NOTE: global counter for all ACL-drops, not per-rule)"
  echo "  [ebpf] RxPackets delta: $rx_delta  (check: traffic reaches eBPF)"
  if [ "$drop" -gt 0 ]; then echo "  [ebpf] OK: ACL matched $drop packets";
  else
    if [ "$rx_delta" -gt 0 ]; then
      echo "  [ebpf] WARN: AclDrop did not grow, but RxPackets grew by $rx_delta — packets don't reach ACL drop (XDP not attached or rule does not match)"
    else
      echo "  [ebpf] WARN: AclDrop and RxPackets did not grow (no traffic or XDP not attached)"
    fi
  fi
  if [ -n "$id" ]; then "$CTL" acl del --id "$id" 2>/dev/null || true; fi
  echo "  [ebpf] rule deleted"
}

run_compare() {
  echo "== bench_netfilter: iface=$IFACE dur=$DURATION src=$SRC_IP dst=$DST_IP proto=$PROTO ==="

  echo "== STEP 0: cleanliness check (no rules for $SRC_IP->$DST_IP anywhere) =="
  if ! check_clean; then
    echo "WARN: found leftovers from previous run — trying auto-cleanup."
    clean_artifacts
    if ! check_clean; then
      echo "ERROR: auto-cleanup failed (rules outside our artifacts). Clean manually. Exiting."
      exit 1
    fi
    echo "OK: after auto-cleanup all subsystems are clean."
  fi

  stage_iptables
  check_clean || echo "WARN: iptables rules left after cleanup!"

  stage_nftables
  check_clean || echo "WARN: nftables rules left after cleanup!"

  stage_ebpf
  check_clean || echo "WARN: ebpf rules left after cleanup!"

  echo "== bench_netfilter finished (all subsystems cleaned) =="
}

# --------------------------------------------------------------------------
# main flow
# --------------------------------------------------------------------------
case "$MODE" in
  dut)    run_dut    ;;
  compare) run_compare ;;
  both)   run_dut; run_compare ;;
  *)      echo "ERROR: unknown MODE=$MODE (dut|compare|both)" >&2; exit 1 ;;
esac
