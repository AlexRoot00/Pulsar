#!/usr/bin/env bash
#
# bench_gen.sh — traffic generator (DUT clone), kernel pktgen.
# Run on the GENERATOR machine. DUT must be on the same L2 segment.
#
# Examples:
#   SIZE=64   DURATION=30 THREADS=1 DUT_IP=192.168.0.199 DUT_MAC=bc:24:11:5b:4a:5a ./bench_gen.sh
#   SIZE=1514 DURATION=30 THREADS=8 RANDOM=1 DUT_IP=... DUT_MAC=... ./bench_gen.sh          # S2 (random 5-tuple, 25G)
#   SIZE=64   VLAN_ID=100            DUT_IP=... DUT_MAC=... ./bench_gen.sh                  # S4 (802.1Q)
#   SIZE=64   VLAN_ID=100 SVLAN_ID=200 DUT_IP=... DUT_MAC=... ./bench_gen.sh               # S4 (QinQ)
#
# Before running: modprobe pktgen (directory /proc/net/pktgen must exist).
# pktgen does NOT do ARP — DUT_MAC is required and must be the real DUT interface MAC.
#
set -euo pipefail

GEN_IFACE="${GEN_IFACE:-eth0}"
DUT_IP="${DUT_IP:-192.168.0.199}"
DUT_MAC="${DUT_MAC:-}"       # if empty — resolved via ARP by DUT_IP (see resolve_mac)

# resolve MAC DUT by IP through ARP (requires L2 access, i.e. DUT on same subnet/segment)
resolve_mac() {
  local ip="$1" ifc="$2" mac=""
  for _ in 1 2 3 4 5 6; do
    mac=$(ip neigh show "$ip" 2>/dev/null | awk 'NF>=5{print $5; exit}')
    [ -n "$mac" ] && { echo "$mac"; return 0; }
    ping -c1 -W1 -I "$ifc" "$ip" >/dev/null 2>&1 || true   # trigger ARP request
    sleep 0.5
  done
  return 1
}
SIZE="${SIZE:-64}"
DURATION="${DURATION:-30}"
COUNT="${COUNT:-0}"        # 0 = infinite (stopped after DURATION)
RND="${RND:-0}"            # 1 = randomize src/dst IP and ports (scenario S2)
VLAN_ID="${VLAN_ID:-}"     # if set — add VLAN tag (S4)
SVLAN_ID="${SVLAN_ID:-}"   # if set — outer QinQ tag (S4)
THREADS="${THREADS:-1}"    # number of pktgen threads (queues); for 25G increase to N cores

# src = IP of our GEN_IFACE (otherwise pktgen sends from 0.0.0.0 and DUT -s rules won't match)
SRC_IP="${SRC_IP:-$(ip -4 addr show "$GEN_IFACE" | awk '/inet /{print $2; exit}' | cut -d/ -f1)}"

PG=/proc/net/pktgen

# stop pktgen on exit (otherwise with COUNT=0 it sends infinitely even after Ctrl-C)
# timeout needed: echo "stop" > pgctrl may hang on deadlock pktgen_mutex
trap 'timeout 5 bash -c "echo stop > \"\$0\"" "$PG/pgctrl" 2>/dev/null || true' EXIT INT TERM

# auto-resolve MAC if not set explicitly
if [ -z "$DUT_MAC" ]; then
  echo "== resolving DUT_MAC for $DUT_IP via ARP on $GEN_IFACE =="
  if ! DUT_MAC=$(resolve_mac "$DUT_IP" "$GEN_IFACE"); then
    echo "ERROR: failed to resolve MAC for $DUT_IP (DUT must be on the same L2 segment)." >&2
    echo "        Specify manually: DUT_MAC=bc:24:11:.. ./bench_gen.sh" >&2
    exit 1
  fi
  echo "== DUT_MAC=$DUT_MAC =="
fi

# how many threads are actually available (by number of kpktgend_*)
tfiles=("$PG"/kpktgend_*)
max_threads=${#tfiles[@]}
if [ "$THREADS" -gt "$max_threads" ]; then
  echo "WARN: THREADS=$THREADS > available kpktgend_*, using $max_threads"
  THREADS=$max_threads
fi

echo "== bench_gen: iface=$GEN_IFACE -> DUT $DUT_IP ($DUT_MAC), size=$SIZE, dur=$DURATION, threads=$THREADS, random=$RND, vlan=$VLAN_ID/$SVLAN_ID, src=$SRC_IP =="

# reset all threads (timeout in case of deadlock pktgen_mutex)
for t in "$PG"/kpktgend_*; do
  timeout 5 bash -c 'echo rem_device_all > "$1"' _ "$t" 2>/dev/null || true
done
sleep 2  # let kernel process device removal

# attach device to each thread i=0..THREADS-1
devs=()
for ((i=0; i<THREADS; i++)); do
  dev="${GEN_IFACE}@${i}"
  echo "add_device $dev" > "$PG/kpktgend_${i}" 2>/dev/null || \
    timeout 5 bash -c 'echo "add_device $1" > "$2"' _ "$dev" "$PG/kpktgend_${i}" 2>/dev/null || true
  devs+=("$dev")
done

configure() {
  local dev="$1"
   echo "count $COUNT"     > "$PG/$dev"
   echo "pkt_size $SIZE"   > "$PG/$dev"
   echo "delay 0"          > "$PG/$dev"
   # in pktgen, IP source is set via src_min/src_max (command "src" does not exist -> EINVAL).
   # src_min==src_max, without IPSRC_RND => fixed src = SRC_IP.
   if [ -n "$SRC_IP" ]; then
     if echo "src_min $SRC_IP" > "$PG/$dev" 2>/dev/null && echo "src_max $SRC_IP" > "$PG/$dev" 2>/dev/null; then
       echo "src set: $SRC_IP -> $dev"
     else
       echo "WARN: failed to set src_min/src_max=$SRC_IP on $dev" >&2
     fi
   fi
   echo "dst $DUT_IP"      > "$PG/$dev"
   echo "dst_mac $DUT_MAC" > "$PG/$dev"

  if [ "$RND" = "1" ]; then
    # randomize 5-tuple for ACL-drop flood (S2)
    echo "flag IPSRC_RND"  > "$PG/$dev"
    echo "flag IPDST_RND"  > "$PG/$dev"
    echo "src_min 10.0.0.1"     > "$PG/$dev"
    echo "src_max 10.255.255.254" > "$PG/$dev"
    echo "dst_min 192.168.0.1"   > "$PG/$dev"
    echo "dst_max 192.168.0.254" > "$PG/$dev"
    echo "flag UDPSRC_RND" > "$PG/$dev"
    echo "flag UDPDST_RND" > "$PG/$dev"
    echo "udp_src_min 1"   > "$PG/$dev"
    echo "udp_src_max 65535" > "$PG/$dev"
    echo "udp_dst_min 1"   > "$PG/$dev"
    echo "udp_dst_max 65535" > "$PG/$dev"
  fi

  if [ -n "$VLAN_ID" ]; then
    echo "vlan_id $VLAN_ID"   > "$PG/$dev" 2>/dev/null || echo "WARN: vlan_id not supported" >&2
    echo "vlan_p 0"           > "$PG/$dev" 2>/dev/null || true
    echo "vlan_cfi 0"         > "$PG/$dev" 2>/dev/null || true
  fi
  if [ -n "$SVLAN_ID" ]; then
    echo "svlan_id $SVLAN_ID" > "$PG/$dev" 2>/dev/null || echo "WARN: svlan_id not supported" >&2
    echo "svlan_p 0"          > "$PG/$dev" 2>/dev/null || true
    echo "svlan_cfi 0"        > "$PG/$dev" 2>/dev/null || true
  fi
}

for dev in "${devs[@]}"; do
  configure "$dev"
done

# save baseline (kernel pktgen does NOT reset counters after rem_device_all+add_device on 5.15)
declare -A baseline
for dev in "${devs[@]}"; do
  baseline["$dev"]=$(awk '/(sent|pkts-sofar):/{print $2; exit}' "$PG/$dev" 2>/dev/null || echo 0)
done

# start pktgen
# With count=0 (infinite), echo start > pgctrl blocks until stop,
# so we run it in background, sleep DURATION, then stop.
# With finite count, start returns immediately — wait just finishes it.
echo start > "$PG/pgctrl" &
_start_pid=$!
sleep "$DURATION"
timeout 5 bash -c 'echo stop > "$1"' _ "$PG/pgctrl" 2>/dev/null || true
wait "$_start_pid" 2>/dev/null || true

# final TX statistics (generator side; real PPS is measured on DUT)
total=0
for dev in "${devs[@]}"; do
  after=$(awk '/(sent|pkts-sofar):/{v=$2} END{print v+0}' "$PG/$dev" 2>/dev/null) || after=0
  s=$((after - ${baseline["$dev"]:-0}))
  [ "$s" -lt 0 ] && s=0
  total=$((total + s))
  echo "  $dev: sent=$s"
done
if [ "$DURATION" -gt 0 ]; then
  awk -v t="$total" -v d="$DURATION" -v s="$SIZE" '
    BEGIN {
      pps=(d>0)?t/d:0;
      gbps=(d>0)?(t*s*8/d/1e9):0;
      printf "== TOTAL sent: %d over %ds => %.0f pps (%.3f Gbps, TX generator side) ==\n", t, d, pps, gbps;
    }'
else
  echo "== TOTAL sent: $total (finite COUNT specified) =="
fi
