# Benchmark Specification for eBPF XDP Dataplane

**Version:** 1.1 · **Date:** 2026-08-16 · **Status:** draft

---

## 1. Purpose and Object

Obtain reproducible performance numbers for the XDP firewall program
(`crates/ebpf-xdp/src/xdp_prog.rs`: parsing, VLAN ACL, L4 ACL/LPM_TRIE,
rate limit token-bucket, conntrack + ringbuf events) and document the methodology.

- **Measurement object** — only XDP dataplane. Userspace (`ctl`/`daemon`)
  serves only as a metrics source (counters from PERCPU, ringbuf `events`).
- **Explicitly excluded:** `ebpf-tc` (TC/NAT, `crates/ebpf-tc/NAT.rs`) — not used
  in deployment; AF_XDP — `xsk_map` is declared (`xdp_prog.rs:30`) but not used
  (`AclAction::Redirect/Inspect` are empty, `xdp_prog.rs:183-184`).

### Constants from code, important for scenarios
- Global rate limit: `MAX_TOKENS=65536`, refill `64000/s` (`maps.rs:77-78`).
- Map sizes: `MAX_CONNTRACK_ENTRIES=1_048_576`, `MAX_L4_ACL_ENTRIES=16_384`,
  `MAX_ACL_PREFIXES=65_536`, `MAX_VLAN_ACL_ENTRIES=16_384` (`maps.rs:3-12`).
- Counters (`api/socket.rs:468`): `RxPackets`(0)/`RxBytes`(1) — input; `Passed`(2),
  `Dropped`(3), `AclDrop`(7), `AclAllow`(8), `RateLimited`(10), `ParseError`(11),
  `RxVlan`(26), `ConntrackHit`(5), `ConntrackMiss`(6).

---

## 2. Distribution and Software

### 2.1 OS DUT
- **RHEL / Rocky Linux / AlmaLinux 9.x** (9.4+) — primary option.
- **Ubuntu Server LTS 22.04 / 24.04** — alternative.
- Kernel **Linux ≥ 6.6** (XDP native + improved BPF); `uname -r` is recorded in report.

### 2.2 DUT packages
`bpftool`, `llvm`/`clang` (LLVM 16+), `libbpf-rs`/`libbpf-dev`, nightly-rustc with
`-Z build-std` for `bpfel-unknown-none`, `iproute2`, `ethtool`, `sysstat`
(`mpstat`/`sar`), `perf`, `nftables`, `iptables`. NIC driver (`igb`/`igc`/`ixgbe`/`mlx5_core`) — as loadable module.

Installation (Ubuntu/Rocky):
```bash
# basic utilities
sudo apt install -y build-essential clang llvm libelf-dev llvm-dev pkg-config iperf3
sudo apt install linux-tools-$(uname -r)
# for bench_xdp.sh (iptables + nftables + sysstat)
sudo apt install -y nftables iptables sysstat
```

Automated installation via init.sh:
```bash
sudo ROLE=dut ./init.sh
```
`init.sh` (ROLE=dut) installs all dependencies and builds eBPF program,
daemon and ctl directly into `target/`. Benchmark scripts stay in `benchmarks/`.

### 3.3 Traffic generators: "install package" vs "build from sources"
Generators are divided into two types of use. For baseline XDP — `iperf3`/pktgen-like
suitability as a control reference, but **pure PPS baseline requires exactly XDP-oriented
or kernel pktgen**; `iperf3` gives lower, since it goes through TCP stack.



### 2.4 How to build eBPF program (dataplane)
```bash
# 1) toolchain (nightly + bpf target)
rustup toolchain install nightly --profile minimal --component rust-src
rustup target add bpfel-unknown-none -t nightly

# 2) build XDP object (artifacts/xdp_prog)
cargo +nightly build -p ebpf-xdp --target bpfel-unknown-none \
  -Z build-std=core,panic_abort --release
# artifact: target/bpfel-unknown-none/release/libebpf_xdp.so

# 3) attach
sudo ip link set dev <iface> xdpdrv  obj target/bpfel-unknown-none/release/libebpf_xdp.so sec xdp
#    (xdpdrv  = native; xdpgeneric = generic)

# 4) detach
sudo ip link set dev <iface> xdp off
```

> Artifact `libebpf_xdp.so` has `.text` section in `sec xdp` (see
> `xdp_prog.rs:71-73`) — `ip ...` searches for `xdp` symbol `xdp_dataplane`.

### 2.5 Benchmark run order

#### DUT requirements
1. XDP attached on IFACE: `sudo ip link set dev enp6s18 xdpdrv obj target/bpfel-unknown-none/release/libebpf_xdp.so sec xdp`
2. Daemon running: `./target/release/ebpf-daemon > test.log 2>&1 &`
3. Counters work: `ebpf-ctl counters show` (or `./target/release/ebpf-ctl counters show` if not in PATH)

#### VLAN/QinQ setup (for scenarios S4 — VLAN ACL QinQ)

For VLAN-tagged scenarios (S4), create sub-interfaces on DUT and Generator:

**On Generator:** `IF=enp6s18 sudo benchmarks/setup_gen.sh` (IP .1)
**On DUT:** `IF=enp6s18 sudo benchmarks/setup_dut.sh` (IP .2)

| Sub-interface | Outer VLAN | Inner VLAN | GEN IP | DUT IP |
|---|---|---|---|---|
| `${IF}.300` | 300 | — | 192.168.30.1/24 | 192.168.30.2/24 |
| `${IF}.140` | 140 | — | 192.168.140.1/24 | 192.168.140.2/24 |
| `${IF}.200.100` | 200 | 100 | 192.168.100.1/24 | 192.168.100.2/24 |
| `${IF}.200.101` | 200 | 101 | 192.168.101.1/24 | 192.168.101.2/24 |
| `${IF}.130.100` | 130 | 100 | 192.168.130.1/24 | 192.168.130.2/24 |

> XDP attaches to physical IF — sees raw frames with 802.1Q tags.
> Sub-interfaces on DUT needed for L3 connectivity; XDP parses VLAN
> in raw frame before kernel extracts tags.

#### Two machines in same L2 segment
```
  - DUT       = 192.168.0.199 (MAC bc:24:11:5b:4a:5a) — accepts and analyzes packets (XDP)
  - Generator = 192.168.0.198 (own MAC)            — generates traffic (kernel pktgen)
```

**On Generator (192.168.0.198):**
```bash
# pktgen must be loaded
modprobe pktgen
# run BEFORE DUT, let it complete DURATION, do NOT press Ctrl-C
GEN_IFACE=enp6s18 DUT_IP=192.168.0.199 DUT_MAC=bc:24:11:5b:4a:5a \
  SIZE=64 DURATION=30 THREADS=4 bash benchmarks/bench_gen.sh
```

**On DUT (192.168.0.199):**

Full backend comparison:
```bash
MODE=compare CTL=./target/release/ebpf-ctl DURATION=30 bash benchmarks/bench_xdp.sh
# options: DEBUG=1 — prints raw nft table and counters; DAEMON_BIN=/path/to/daemon — custom path
```

Only XDP metrics (without iptables/nftables):
```bash
MODE=dut CTL=./target/release/ebpf-ctl DURATION=30 IFACE=enp6s18 bash benchmarks/bench_xdp.sh
```

Counter growth check during run:
```bash
./target/release/ebpf-ctl counters show | grep rx_packets
```

---

## 3. XDP Modes and sysctl

### 3.1 Native (`xdpdrv`) vs Generic (`xdpgeneric`) — how to choose
- **Native** (`xdpdrv`): `sudo ip link set dev <iface> xdpdrv obj …`. Accurate numbers —
  packet passes at early driver stage, before entering netdev backlog. Requires driver
  with XDP support (`ixgbe`/`ice`/`mlx5_core`/`i40e`; at 1G — `igc`/`igb` not on all
  chips have `ndo_xdp_xmit`).
- **Generic** (`xdpgeneric`): `sudo ip link set dev <iface> xdpgeneric obj …`. Works
  on any NIC via `ndo_etharx`/`ndo_xdp_generic`, but through normal NAPI/softirq —
  therefore **less efficient and less accurate**: PPS lower, CPU higher. Used as
  fallback when `xdpdrv` doesn't work on specific chip.

**Conclusion:** measure **B — native** as reference; **C — generic** only as fallback;
**A — without sysctl** for assessing "tuning overhead".

### 3.2 Tuning and sysctl (requires root)
Below is a set of rules. If applied without root, `sysctl` prints
`permission denied … ignoring` and the rule **is NOT applied** — the test will be
less correct. Always run under root or in `--privileged`/netns with needed capabilities.

```
# --- BPF/CPU ---
kernel.bpf_stats_enabled = 1        # REQUIRED: otherwise bpftool/perf don't export BPF-CPU
net.core.bpf_jit_enable = 1         # JIT on for "as in prod" measurements
net.core.bpf_jit_harden = 0         # 0 for benchmark (1 — for production)
kernel.unprivileged_bpf_disabled = 1
kernel.perf_event_paranoid = -1     # so perf/bpftool profile works
kernel.printk = 3 4 1 3             # clean dmesg (not critical)

# --- network: remove NAPI/backlog throttling ---
net.core.netdev_budget = 60000
net.core.netdev_budget_usecs = 4000 # remove NAPI throttling (default 2000/8000)
net.core.rmem_max = 134217728       # 128 MB
net.core.wmem_max = 134217728       # 128 MB
net.core.netdev_max_backlog = 250000

# --- IP ---
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
vm.swappiness = 0                   # so swap doesn't interfere with measurements

# --- CPU ---
# isolate cores (example): cores 2..7 — only for DUT-NIC
# in bootloader:  isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7
# irqbalance OFF; IRQ DUT-NIC on cores 2..7:
#   echo 2-7 > /proc/irq/<IRQ>/smp_affinity_list
```



## 4. Metrics and Sources

### 4.1 KPI (per run)
PPS, Gbps, drop rate (gen→DUT), p50/p99/max latency, CPU utilization on RX cores.

### 5.2 Data sources
- **`counters`** (`maps.rs:537`, PERCPU, 32 slots) — summed across CPUs via `daemon`
  (`manager/maps.rs:169`) or `ctl`. Input — `RxPackets`(0)/`RxBytes`(1); rest —
  output counters (`Dropped`, `AclDrop`, `RateLimited`, `RxVlan`, …).
- **Ringbuf `events`** (`maps.rs:527`, 16 MB) — `EventKind` from `monitoring/mod.rs`.
- **Grafana:** `benchmarks/monitoring/grafana/dashboards/ebpf-xdp-bench.json`.
- System: `perf`, `bpftool prog profile`, `mpstat`, `sar`, `ethtool -S`.

Formulas:

- `PPS = (RxPackets_end − RxPackets_start) / Δt`
- `Gbps = (RxBytes_end − RxBytes_start) * 8 / Δt / 1e9`
- `Drop% = Dropped / RxPackets`

> **Counter note:** `AclDrop` is a **global** counter for all
> ACL-drops in the system, not per-rule. `bench_xdp.sh` (MODE=compare)
> measures delta `(AclDrop_end − AclDrop_start)` and additionally checks
> `RxPackets` as sanity check: if `RxPackets` grew but `AclDrop` didn't —
> means packets reach eBPF, but ACL rule doesn't match (or XDP not attached).

---

## 5. Scenarios

| № | Scenario | What we do | Packets / sizes | KPI |
|---|---|---|---|---|
| S1 | Baseline XDP_PASS | parsing + Pass, no rules | IPv4/IPv6 TCP/UDP, 64/128/256/512/1514 B | PPS, Gbps, CPU@plateau |
| S2 | ACL Drop (LPM_TRIE) | `l4_acl` 0 / 1K / 16K rules → Drop | TCP/UDP random 5-tuple | PPS, ∆PPS vs rule count |
| S3 | Rate limit (global) | UDP flood single src, rule_id=0 | 64 B | 64 Kpps; RateLimited counter |
| S4 | VLAN ACL (QinQ) | 0 / 1 / 2 tags; Allow/Drop/rate | 64 / 1514 B | RxVlan; PPS@vlan_depth=2 |
| S5 | Scale / conntrack | conntrack 0 / 100K / 1M flows | 64 B | PPS ≥ 85% baseline |

Traffic covers 64/128/256/512/1514 B — otherwise "good numbers on 1514"
hide parsing issues on small packets (64B — main stress).

---


---

## 6. Methodology

1. Before each run — record baseline counters (`bpftool map dump`, or restart DUT).
2. Generator maintains target PPS; `daemon` writes counters to Grafana.
3. After run — compute PPS/Gbps/Drop% by Δt (formulas §5.2).
4. CPU: `mpstat -P ALL 1` on RX cores — record average and peak.
5. (Optional) hotspot profile: `bpftool prog profile` or `perf record`.
6. Each point ≥3 runs, 10s warmup, ≥30s measurement, median,
   deviation >5% — repeat.

---
