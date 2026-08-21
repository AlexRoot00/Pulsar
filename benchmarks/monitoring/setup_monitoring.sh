#!/usr/bin/env bash
#
# setup_monitoring.sh — install node_exporter (+ ebpf_exporter on the DUT) and
# a vmagent that remote-writes both into an existing VictoriaMetrics.
#
# Everything is installed as plain systemd units, no docker: the DUT must stay
# as close to a bare box as possible while its XDP dataplane is measured.
#
# Run (as root, on each stand server):
#   ROLE=dut VM_URL=https://vm.example.net/api/v1/write bash setup_monitoring.sh
#   ROLE=gen VM_URL=https://vm.example.net/api/v1/write bash setup_monitoring.sh
#
# Removal (rented boxes get returned):
#   ACTION=uninstall bash setup_monitoring.sh
#
# Useful knobs:
#   EXPORTER_CPUS=0,1     pin exporters away from the RX cores under measurement
#   SCRAPE_INTERVAL=5s    resolution of the metrics during a run
#   EBPF_EXPORTER=0       skip ebpf_exporter on the DUT (see README, it costs)
#   *_VERSION=v1.2.3      pin a release instead of resolving the latest tag
#
set -euo pipefail

ROLE="${ROLE:-dut}"
ACTION="${ACTION:-install}"
STAND="${STAND:-pulsar-bench}"

VM_URL="${VM_URL:-}"
VM_USER="${VM_USER:-}"
VM_PASS="${VM_PASS:-}"

SCRAPE_INTERVAL="${SCRAPE_INTERVAL:-5s}"
EXPORTER_CPUS="${EXPORTER_CPUS:-}"

NODE_EXPORTER_PORT="${NODE_EXPORTER_PORT:-9100}"
EBPF_EXPORTER_PORT="${EBPF_EXPORTER_PORT:-9435}"

# ebpf_exporter ships its BPF programs as example configs; only the ones that
# actually exist in the release are enabled (see pick_ebpf_configs).
EBPF_EXPORTER_CONFIGS="${EBPF_EXPORTER_CONFIGS:-softirqs,runqlat}"

# Fallbacks used when the GitHub API cannot be reached (rate limit, no egress).
NODE_EXPORTER_VERSION="${NODE_EXPORTER_VERSION:-}"
EBPF_EXPORTER_VERSION="${EBPF_EXPORTER_VERSION:-}"
VMUTILS_VERSION="${VMUTILS_VERSION:-}"
NODE_EXPORTER_FALLBACK="v1.9.1"
EBPF_EXPORTER_FALLBACK="v2.4.2"
VMUTILS_FALLBACK="v1.111.0"

TEXTFILE_DIR="/var/lib/node_exporter/textfile"
EBPF_CONF_DIR="/etc/ebpf_exporter"
VMAGENT_CONF="/etc/vmagent/scrape.yml"
VMAGENT_DATA="/var/lib/vmagent"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root"; exit 1; }
case "$ROLE" in dut|gen) ;; *) echo "ERROR: ROLE must be dut|gen (got='$ROLE')"; exit 1 ;; esac

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------
if [ "$ACTION" = "uninstall" ]; then
  echo "== removing monitoring stack =="
  for unit in vmagent ebpf_exporter node_exporter; do
    systemctl disable --now "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/${unit}.service"
  done
  systemctl daemon-reload
  rm -f /usr/local/bin/node_exporter /usr/local/bin/ebpf_exporter /usr/local/bin/vmagent
  rm -rf "$EBPF_CONF_DIR" /etc/vmagent "$VMAGENT_DATA"
  echo "== done (textfile dir $TEXTFILE_DIR kept: it holds benchmark results) =="
  exit 0
fi

[ -n "$VM_URL" ] || { echo "ERROR: set VM_URL=https://<victoriametrics>/api/v1/write"; exit 1; }

for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool is required"; exit 1; }
done

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  GOARCH=amd64 ;;
  aarch64) GOARCH=arm64 ;;
  *) echo "ERROR: unsupported arch $ARCH"; exit 1 ;;
esac

echo "== setup_monitoring: ROLE=$ROLE STAND=$STAND arch=$GOARCH -> $VM_URL =="

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Resolve the latest release tag of a GitHub repo, fall back to a pinned one.
latest_tag() {
  local repo="$1" fallback="$2" tag=""
  tag=$(curl -fsSL --max-time 15 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1) || true
  if [ -z "$tag" ]; then
    echo "WARN: cannot resolve latest tag of $repo, using $fallback" >&2
    tag="$fallback"
  fi
  echo "$tag"
}

# Download a tarball, extract it, and install the named binary into /usr/local/bin.
# The binary is located with `find` so that a changed archive layout does not
# silently break the install.
install_from_tarball() {
  local url="$1" binname="$2" dest="${3:-/usr/local/bin}"
  local tmp
  tmp=$(mktemp -d)
  echo "  fetching $url"
  if ! curl -fsSL --max-time 300 "$url" -o "$tmp/pkg.tar.gz"; then
    echo "ERROR: download failed: $url" >&2
    echo "       check the release page and pin the version explicitly" >&2
    rm -rf "$tmp"; return 1
  fi
  tar -xzf "$tmp/pkg.tar.gz" -C "$tmp"
  local found
  found=$(find "$tmp" -type f -name "$binname" -perm -u+x | head -1)
  if [ -z "$found" ]; then
    echo "ERROR: '$binname' not found inside $url" >&2
    echo "       archive contents:" >&2
    find "$tmp" -maxdepth 2 -type f | sed 's/^/         /' >&2
    rm -rf "$tmp"; return 1
  fi
  install -m 0755 "$found" "$dest/${binname%-prod}"
  echo "  installed $dest/${binname%-prod}"
  # Callers that need sibling files (ebpf_exporter examples) get the temp dir.
  EXTRACT_DIR="$tmp"
}

write_unit() {
  local name="$1" desc="$2" exec="$3"
  {
    echo "[Unit]"
    echo "Description=$desc"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo
    echo "[Service]"
    echo "Type=simple"
    echo "ExecStart=$exec"
    echo "Restart=on-failure"
    echo "RestartSec=2"
    [ -n "$EXPORTER_CPUS" ] && echo "CPUAffinity=$EXPORTER_CPUS"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } > "/etc/systemd/system/${name}.service"
}

# ---------------------------------------------------------------------------
# node_exporter
# ---------------------------------------------------------------------------
install_node_exporter() {
  local tag ver
  tag="${NODE_EXPORTER_VERSION:-$(latest_tag prometheus/node_exporter "$NODE_EXPORTER_FALLBACK")}"
  ver="${tag#v}"
  echo "== node_exporter $tag =="
  install_from_tarball \
    "https://github.com/prometheus/node_exporter/releases/download/${tag}/node_exporter-${ver}.linux-${GOARCH}.tar.gz" \
    node_exporter
  rm -rf "$EXTRACT_DIR"

  mkdir -p "$TEXTFILE_DIR"
  write_unit node_exporter "Prometheus node exporter" \
    "/usr/local/bin/node_exporter --web.listen-address=:${NODE_EXPORTER_PORT} --collector.textfile.directory=${TEXTFILE_DIR}"
}

# ---------------------------------------------------------------------------
# ebpf_exporter (DUT only — it loads its own BPF programs, see README)
# ---------------------------------------------------------------------------

# Keep only the requested example configs that this release actually ships.
pick_ebpf_configs() {
  local avail="$1" want="$2" ok="" missing=""
  local IFS=,
  for name in $want; do
    if [ -f "${avail}/${name}.yaml" ] || [ -f "${avail}/${name}.yml" ]; then
      ok="${ok:+$ok,}$name"
    else
      missing="${missing:+$missing,}$name"
    fi
  done
  [ -n "$missing" ] && echo "WARN: ebpf_exporter configs not in this release, skipped: $missing" >&2
  echo "$ok"
}

install_ebpf_exporter() {
  local tag ver names
  tag="${EBPF_EXPORTER_VERSION:-$(latest_tag cloudflare/ebpf_exporter "$EBPF_EXPORTER_FALLBACK")}"
  ver="${tag#v}"
  echo "== ebpf_exporter $tag =="
  install_from_tarball \
    "https://github.com/cloudflare/ebpf_exporter/releases/download/${tag}/ebpf_exporter-${ver}.linux-${GOARCH}.tar.gz" \
    ebpf_exporter

  # The release carries prebuilt .bpf.o programs next to their yaml configs.
  local examples
  examples=$(find "$EXTRACT_DIR" -type d -name examples | head -1)
  if [ -z "$examples" ]; then
    echo "ERROR: no examples/ directory in the ebpf_exporter release" >&2
    echo "       run ebpf_exporter --help and configure it by hand" >&2
    rm -rf "$EXTRACT_DIR"; return 1
  fi
  mkdir -p "$EBPF_CONF_DIR"
  cp -r "$examples" "$EBPF_CONF_DIR/"
  rm -rf "$EXTRACT_DIR"

  names=$(pick_ebpf_configs "$EBPF_CONF_DIR/examples" "$EBPF_EXPORTER_CONFIGS")
  if [ -z "$names" ]; then
    echo "WARN: none of EBPF_EXPORTER_CONFIGS='$EBPF_EXPORTER_CONFIGS' exist; available:" >&2
    ls -1 "$EBPF_CONF_DIR/examples" | sed 's/\.ya\?ml$//' | sort -u | sed 's/^/         /' >&2
    echo "WARN: skipping ebpf_exporter unit" >&2
    return 0
  fi
  echo "  enabled configs: $names"

  write_unit ebpf_exporter "Cloudflare ebpf_exporter" \
    "/usr/local/bin/ebpf_exporter --config.dir=${EBPF_CONF_DIR}/examples --config.names=${names} --web.listen-address=:${EBPF_EXPORTER_PORT}"
}

# ---------------------------------------------------------------------------
# vmagent
# ---------------------------------------------------------------------------
install_vmagent() {
  local tag targets
  tag="${VMUTILS_VERSION:-$(latest_tag VictoriaMetrics/VictoriaMetrics "$VMUTILS_FALLBACK")}"
  echo "== vmagent $tag =="
  install_from_tarball \
    "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/${tag}/vmutils-linux-${GOARCH}-${tag}.tar.gz" \
    vmagent-prod
  rm -rf "$EXTRACT_DIR"

  mkdir -p /etc/vmagent "$VMAGENT_DATA"

  targets="          - localhost:${NODE_EXPORTER_PORT}"
  if [ "$ROLE" = "dut" ] && [ -f /etc/systemd/system/ebpf_exporter.service ]; then
    targets="${targets}
          - localhost:${EBPF_EXPORTER_PORT}"
  fi

  cat > "$VMAGENT_CONF" <<EOF
# Generated by benchmarks/monitoring/setup_monitoring.sh
global:
  scrape_interval: ${SCRAPE_INTERVAL}
  external_labels:
    stand: ${STAND}
    role: ${ROLE}
    host: $(hostname -s)

scrape_configs:
  - job_name: stand
    static_configs:
      - targets:
${targets}
EOF

  local exec="/usr/local/bin/vmagent -promscrape.config=${VMAGENT_CONF} -remoteWrite.url=${VM_URL} -remoteWrite.tmpDataPath=${VMAGENT_DATA}"
  [ -n "$VM_USER" ] && exec="$exec -remoteWrite.basicAuth.username=${VM_USER}"
  [ -n "$VM_PASS" ] && exec="$exec -remoteWrite.basicAuth.password=${VM_PASS}"
  write_unit vmagent "VictoriaMetrics vmagent" "$exec"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
install_node_exporter

if [ "$ROLE" = "dut" ] && [ "${EBPF_EXPORTER:-1}" = "1" ]; then
  install_ebpf_exporter || echo "WARN: ebpf_exporter not installed, continuing"
else
  echo "== ebpf_exporter skipped (ROLE=$ROLE, EBPF_EXPORTER=${EBPF_EXPORTER:-1}) =="
fi

install_vmagent

systemctl daemon-reload
systemctl enable --now node_exporter
[ -f /etc/systemd/system/ebpf_exporter.service ] && systemctl enable --now ebpf_exporter
systemctl enable --now vmagent

echo
echo "== done. check: =="
echo "    systemctl status node_exporter ebpf_exporter vmagent --no-pager"
echo "    curl -s localhost:${NODE_EXPORTER_PORT}/metrics | head"
echo "    curl -s localhost:8429/targets      # vmagent scrape targets"
echo
echo "== publish a benchmark result into the same TSDB: =="
echo "    write a .prom file into ${TEXTFILE_DIR}/ (see monitoring/README.md)"
