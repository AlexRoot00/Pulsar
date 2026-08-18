#!/usr/bin/env bash
#
# init.sh — automatic test environment setup (build only, NO XDP attach, NO system copies).
#
# Everything runs from the project directory. No /usr/local/bin, /opt/ebpf, /opt/ebpf-bench.
#
#   ROLE=dut    DUT:   toolchain (nightly+bpf), clang/llvm, build ebpf-xdp + daemon/ctl.
#   ROLE=gen    generator: pktgen (modprobe) + scapy.
#   ROLE=both   everything at once (NOT for RX benchmark — need two machines).
#
# Run (as root):
#   ROLE=dut  ./init.sh
#   ROLE=gen  ./init.sh
#
set -euo pipefail

ROLE="${ROLE:-dut}"
[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (sudo ./init.sh)"; exit 1; }
case "$ROLE" in
  dut|gen|both) ;;
  *) echo "ERROR: ROLE must be dut|gen|both (got='$ROLE')"; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive

echo "== init.sh: ROLE=$ROLE =="

apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl git build-essential pkg-config

# ---------------------------------------------------------------------------
setup_dut() {
  echo "== [dut] system dependencies =="
  apt-get install -y --no-install-recommends \
    clang llvm libelf-dev llvm-dev libbpf-dev \
    sysstat linux-tools-common nftables iptables

  echo "== [dut] Rust toolchain (nightly + bpf target) =="
  if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  fi
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
  rustup toolchain install nightly --profile minimal --component rust-src
  # bpfel-unknown-none — built-in target. rustup target add has no prebuilt
  # rust-std, so it always says "no prebuilt artifacts" — this is NOT an error:
  # build uses -Z build-std (rust-src), rust-std for bpf is built from sources.
  rustup target add --toolchain nightly bpfel-unknown-none 2>/dev/null || true

  echo "== [dut] bpf-linker =="
  cargo install cargo-binstall 2>/dev/null || true
  cargo binstall -y bpf-linker 2>/dev/null || cargo install bpf-linker

  echo "== [dut] build =="
  cargo +nightly build -p ebpf-xdp --target bpfel-unknown-none \
    -Z build-std=core,panic_abort --release
  cargo build --release -p daemon -p ctl

  echo "== [dut] done. All artifacts are local:"
  echo "    target/bpfel-unknown-none/release/libebpf_xdp.so"
  echo "    target/release/ebpf-daemon"
  echo "    target/release/ebpf-ctl"
  echo "    benchmarks/bench_xdp.sh"
  echo "    benchmarks/scapy_check.py"
  echo "    benchmarks/setup_dut.sh"
  echo
  echo "    sudo ip link set dev <IFACE> xdpdrv obj target/bpfel-unknown-none/release/libebpf_xdp.so sec xdp"
  echo "    ./target/release/ebpf-daemon > /tmp/daemon.log 2>&1 &"
  echo "    ./target/release/ebpf-ctl counters show --iface <IFACE>"
}

# ---------------------------------------------------------------------------
setup_gen() {
  echo "== [gen] generator dependencies =="
  apt-get install -y --no-install-recommends \
    linux-modules-extra-"$(uname -r)" linux-tools-"$(uname -r)" linux-tools-common \
    python3-pip

  echo "== [gen] pktgen module =="
  modprobe pktgen || echo "WARN: modprobe pktgen failed (need linux-modules-extra for kernel $(uname -r))"

  echo "== [gen] scapy =="
  pip3 install --break-system-packages scapy 2>/dev/null || pip3 install scapy

  echo "== [gen] done. All in local benchmarks/. Run:"
  echo "    GEN_IFACE=enp6s18 DUT_IP=192.168.0.199 DUT_MAC=bc:24:11:5b:4a:5a SIZE=1514 bash benchmarks/bench_gen.sh"
}

# ---------------------------------------------------------------------------
run_bench() {
  echo "== [bench] running benchmark for ROLE=$ROLE =="
  case "$ROLE" in
    gen)
      echo "== [bench/gen] traffic generator (pktgen) =="
      GEN_IFACE="${GEN_IFACE:-enp6s18}" \
      DUT_IP="${DUT_IP:-192.168.0.199}" \
      DUT_MAC="${DUT_MAC:-}" \
      SIZE="${SIZE:-64}" DURATION="${DURATION:-30}" THREADS="${THREADS:-1}" \
        bash benchmarks/bench_gen.sh
      ;;
    dut)
      echo "== [bench/dut] receiver (XDP analysis) =="
      echo "    requires: XDP attached on \$IFACE and daemon running"
      if ! pgrep -x ebpf-daemon >/dev/null 2>&1; then
        echo "== [bench/dut] starting daemon (background, log test.log) =="
        ./target/release/ebpf-daemon > test.log 2>&1 &
        sleep 1
      fi
      IFACE="${IFACE:-enp6s18}" DURATION="${DURATION:-30}" \
      CTL="${CTL:-./target/release/ebpf-ctl}" MODE="${MODE:-dut}" \
        bash benchmarks/bench_xdp.sh
      ;;
    both)
      echo "WARN: role both — benchmark not started (need TWO machines: DUT + generator)."
      ;;
  esac
}

case "$ROLE" in
  dut)  setup_dut ;;
  gen)  setup_gen ;;
  both) setup_dut; setup_gen ;;
esac

# optionally run benchmark — set BENCH=1
if [ "${BENCH:-0}" = "1" ]; then
  run_bench
else
  echo "== to run benchmark: BENCH=1 $0 =="
fi

echo "== init.sh finished (ROLE=$ROLE) =="
