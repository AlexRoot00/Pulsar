//! Work with `lb_backends` map (ARRAY: key=u32 backend_id, value=Backend).
//!
//! Backend describes where to redirect a packet after selection (after ECMP from
//! `select_backend` in ebpf-xdp/src/xdp_prog.rs):
//!   - `addr`/`port`  — address/port of the backend server (IPv4 in ::ffff).
//!   - `ifindex`      — index of egress interface through which the packet
//!                      goes to backend (used in `lb_devmap` for
//!                      `bpf_redirect_map`).
//!   - `family`/`proto` — AF_INET(4) / IP_PROTO_TCP(6) or UDP(17).
//!   - `weight`       — weight for load balancing (currently informational).
//!   - `flags`        — 0 (healthy) or BACKEND_FLAG_UNHEALTHY(0x1).
//!   - `mac`          — L2 MAC of egress interface (currently not used by BPF).
//!
//! Map names match `btf_map!` in ebpf-xdp/src/xdp_prog.rs:
//!   lb_backends, lb_devmap, lb_meta.

use std::process::Command;

use common::{BACKEND_FLAG_UNHEALTHY, Backend};
use std::mem::size_of;

use crate::acl_key::Ipv4;
use crate::maps::{MapError, bpftool_dump, bpftool_run, key_to_hex, map_delete, map_update};

/// Map `lb_backends` (ARRAY: backend_id -> Backend).
pub const LB_BACKENDS_MAP: &str = "lb_backends";
/// Map `lb_devmap` (DEVMAP: backend_id -> ifindex for redirect).
pub const LB_DEV_MAP: &str = "lb_devmap";
/// Map `lb_meta` (ARRAY: 0 -> {num_backends}).
pub const LB_META_MAP: &str = "lb_meta";

/// One backend entry for display in `backend list`.
#[derive(Debug, Clone)]
pub struct BackendEntry {
    pub id: u32,
    pub backend: Backend,
    /// Interface name corresponding to `ifindex` (if resolution succeeded).
    pub dev_name: Option<String>,
}

/// Parameters for adding a backend (from CLI).
pub struct BackendSpec {
    pub ip: Ipv4,
    pub port: u16,
    pub dev: String,
    pub group: u32,
}

impl BackendSpec {
    /// Resolve interface name to ifindex via libc `if_nametoindex`.
    fn ifindex(&self) -> Result<u32, String> {
        // SAFETY: if_nametoindex takes a C-string; self.dev is UTF-8 without
        // internal NUL, so CString is valid. Returns 0 on error.
        let cname = std::ffi::CString::new(self.dev.as_str())
            .map_err(|_| format!("invalid interface name: '{}'", self.dev))?;
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            return Err(format!(
                "interface '{}' not found (if_nametoindex returned 0)",
                self.dev
            ));
        }
        Ok(idx)
    }

    /// Build `Backend` structure (40 bytes) for writing to map.
    fn build(&self, ifindex: u32) -> Backend {
        let addr = self.ip.to_mapped();
        Backend {
            addr,
            port: self.port,
            family: common::AF_INET, // 4
            proto: common::IP_PROTO_TCP,
            ifindex,
            weight: 1,
            backend_group: self.group,
            flags: 0,
            mac: [0u8; 6],
            _pad: [0u8; 2],
        }
    }
}

/// Read all backends from `lb_backends` (by array index 0..MAX_BACKENDS).
/// Returns only configured ones (ifindex != 0), as BPF sees them
/// (`Backend::is_configured`).
pub fn backend_list(iface: &str) -> Result<Vec<BackendEntry>, MapError> {
    let out = bpftool_dump(iface, LB_BACKENDS_MAP)?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&out).map_err(|e| MapError::Json(format!("{e}: {out}")))?;

    let mut result = Vec::new();
    for e in &entries {
        let id = e["key"].as_u64().unwrap_or(0) as u32;
        let b = backend_from_json(&e["value"]);
        if !b.is_configured() {
            continue;
        }
        let dev_name = ifindex_to_name(b.ifindex);
        result.push(BackendEntry {
            id,
            backend: b,
            dev_name,
        });
    }
    Ok(result)
}

/// Find maximum id of configured backend; next id = max+1
/// (if no backends — 0). Matches specification: "id is taken +1 from what
/// already exists".
pub fn next_backend_id(iface: &str) -> Result<u32, MapError> {
    let list = backend_list(iface)?;
    Ok(list.iter().map(|e| e.id).max().map(|m| m + 1).unwrap_or(0))
}

/// Add backend with auto-assigned id (max existing + 1).
/// Returns assigned id.
pub fn backend_add(iface: &str, spec: &BackendSpec) -> Result<u32, MapError> {
    let ifindex = spec.ifindex().map_err(|e| MapError::Json(e))?;
    let id = next_backend_id(iface)?;
    let backend = spec.build(ifindex);

    // Write the backend itself.
    let key = id.to_le_bytes().to_vec();
    let value = backend_to_bytes(&backend);
    map_update(iface, LB_BACKENDS_MAP, &key, &value).map_err(|e| amend(e, LB_BACKENDS_MAP))?;

    // Write ifindex to devmap, so bpf_redirect_map(..., backend_id)
    // knows egress interface. bpftool for DEVMAP expects value in form
    // "hex <ifindex 4 bytes> [id <N>|fd <N>]" — raw 8 bytes it rejects
    // with parser ("expected key or value, got: 00"). Use keyword
    // `id 0` (without program redirect).
    devmap_update(iface, id, ifindex).map_err(|e| amend(e, LB_DEV_MAP))?;

    // Update lb_meta.num_backends = id + 1. The lb_meta map now exists in
    // the BPF object (btf_map!(lb_meta, ...)), value is `LbMeta` (8 bytes:
    // num_backends u32 + _pad u32).
    let mut meta_val = Vec::with_capacity(8);
    meta_val.extend_from_slice(&(id + 1).to_le_bytes());
    meta_val.extend_from_slice(&0u32.to_le_bytes());

    map_update(iface, LB_META_MAP, &0u32.to_le_bytes().to_vec(), &meta_val)
        .map_err(|e| amend(e, LB_META_MAP))?;

    Ok(id)
}

/// Add map name to error message for diagnostics.
fn amend(e: MapError, map: &str) -> MapError {
    match e {
        MapError::Bpftool { code, stderr } => MapError::Bpftool {
            code,
            stderr: format!("[{map}] {stderr}"),
        },
        other => other,
    }
}

/// Convert bytes slice to individual hex tokens for bpftool (`"00"`,`"03"`,...).
fn to_hex_args(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write entry to DEVMAP. Map `lb_devmap` in BPF is declared with value=u32
/// (btf_map!(lb_devmap, ..., u32, u32)), so kernel expects 8-byte value:
/// struct bpf_devmap_val { ifindex, id }.
/// Use format: value hex <ifindex LE> <0 LE> id <id>
/// or value <ifindex 4 bytes> id <id>.
fn devmap_update(iface: &str, backend_id: u32, ifindex: u32) -> Result<(), MapError> {
    // Format: key hex <id> value hex <ifindex LE> <0 LE> id <id>
    // where second u32 = 0 (internal id in devmap)
    let mut args: Vec<String> = vec![
        "update".into(),
        "name".into(),
        LB_DEV_MAP.into(),
        "key".into(),
        "hex".into(),
    ];
    args.extend(to_hex_args(&backend_id.to_le_bytes()));
    args.push("value".into());
    args.push("hex".into());
    args.extend(to_hex_args(&ifindex.to_le_bytes()));
    args.extend(to_hex_args(&0u32.to_le_bytes())); // id = 0
    args.push("id".into());
    args.push("0".into());
    bpftool_run(iface, LB_DEV_MAP, &args).map_err(|e| amend(e, LB_DEV_MAP))
}

/// Delete backend by id: clear slot in lb_backends (write default
/// backend with ifindex=0 => is_configured()==false) and delete from devmap.
pub fn backend_delete(iface: &str, id: u32) -> Result<(), MapError> {
    // Check if backend exists.
    let list = backend_list(iface)?;
    if !list.iter().any(|e| e.id == id) {
        return Err(MapError::Json(format!("backend with id={id} not found")));
    }

    let zero = Backend::default();
    map_update(
        iface,
        LB_BACKENDS_MAP,
        &id.to_le_bytes().to_vec(),
        &backend_to_bytes(&zero),
    )?;
    map_delete(iface, LB_DEV_MAP, &id.to_le_bytes().to_vec())?;
    Ok(())
}

/// Completely clear all backends: delete all entries from lb_backends and
/// lb_devmap. (lb_meta is not used by BPF and may not exist in the loaded
/// object, so we don't touch it.)
pub fn backend_flush(iface: &str) -> Result<usize, MapError> {
    let list = backend_list(iface)?;
    let n = list.len();
    for e in &list {
        let zero = Backend::default();
        map_update(
            iface,
            LB_BACKENDS_MAP,
            &e.id.to_le_bytes().to_vec(),
            &backend_to_bytes(&zero),
        )?;
        map_delete(iface, LB_DEV_MAP, &e.id.to_le_bytes().to_vec())?;
    }
    let mut meta_zero = Vec::with_capacity(8);
    meta_zero.extend_from_slice(&0u32.to_le_bytes());
    meta_zero.extend_from_slice(&0u32.to_le_bytes());
    map_update(iface, LB_META_MAP, &0u32.to_le_bytes().to_vec(), &meta_zero)?;
    Ok(n)
}

/// Serialization / parsing Backend (40 bytes, repr(C), align 8) ///

/// Serialize `Backend` to exactly `size_of::<Backend>()` bytes (field order
/// same as in common::Backend, LITTLE-ENDIAN for multi-byte, since bpfel
/// native). Structure `repr(C, align(8))`: 44 bytes of fields + 4 bytes
/// alignment => final `value_size` from kernel = 48. Pad with zeros to
/// match expected size (otherwise bpftool/kernel rejects).
fn backend_to_bytes(b: &Backend) -> Vec<u8> {
    let mut v = Vec::with_capacity(size_of::<Backend>());
    v.extend_from_slice(&b.addr); // 16
    v.extend_from_slice(&b.port.to_le_bytes()); // 2
    v.push(b.family); // 1
    v.push(b.proto); // 1
    v.extend_from_slice(&b.ifindex.to_le_bytes()); // 4
    v.extend_from_slice(&b.weight.to_le_bytes()); // 4
    v.extend_from_slice(&b.backend_group.to_le_bytes()); // 4
    v.extend_from_slice(&b.flags.to_le_bytes()); // 4
    v.extend_from_slice(&b.mac); // 6
    v.extend_from_slice(&b._pad); // 2
    // Pad to size_of::<Backend>() (including align(8) padding)
    while v.len() < size_of::<Backend>() {
        v.push(0);
    }
    debug_assert_eq!(
        v.len(),
        size_of::<Backend>(),
        "Backend serialize size mismatch"
    );
    v
}

/// Parse `Backend` from JSON representation from bpftool (fields are arrays/numbers).
fn backend_from_json(v: &serde_json::Value) -> Backend {
    Backend {
        addr: arr16(&v["addr"]),
        port: v["port"].as_u64().unwrap_or(0) as u16,
        family: v["family"].as_u64().unwrap_or(0) as u8,
        proto: v["proto"].as_u64().unwrap_or(0) as u8,
        ifindex: v["ifindex"].as_u64().unwrap_or(0) as u32,
        weight: v["weight"].as_u64().unwrap_or(0) as u32,
        backend_group: v["backend_group"].as_u64().unwrap_or(0) as u32,
        flags: v["flags"].as_u64().unwrap_or(0) as u32,
        mac: arr6(&v["mac"]),
        _pad: [0u8; 2],
    }
}

fn arr16(v: &serde_json::Value) -> [u8; 16] {
    let mut a = [0u8; 16];
    if let Some(arr) = v.as_array() {
        for (i, x) in arr.iter().enumerate().take(16) {
            a[i] = x.as_u64().unwrap_or(0) as u8;
        }
    }
    a
}

fn arr6(v: &serde_json::Value) -> [u8; 6] {
    let mut a = [0u8; 6];
    if let Some(arr) = v.as_array() {
        for (i, x) in arr.iter().enumerate().take(6) {
            a[i] = x.as_u64().unwrap_or(0) as u8;
        }
    }
    a
}

/// Resolve ifindex to interface name (for human-readable output).
/// Uses `ip -o link show`, since libc::if_indextoname is inconvenient without
/// buffer allocation; on error returns None.
fn ifindex_to_name(ifindex: u32) -> Option<String> {
    if ifindex == 0 {
        return None;
    }
    let output = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        // Format: "<ifindex>: <name>: ..."
        let idx_end = line.find(':')?;
        let idx: u32 = line[..idx_end].trim().parse().ok()?;
        if idx == ifindex {
            let after = &line[idx_end + 1..];
            let name_end = after.find(':')?;
            let name = &after[..name_end].trim();
            // Remove @... suffix (e.g., eth1@if5)
            let name = name.split('@').next().unwrap_or(name);
            return Some(name.to_string());
        }
    }
    None
}

/// Indicator "backend unhealthy" (for display).
#[allow(dead_code)]
pub fn is_unhealthy(b: &Backend) -> bool {
    b.flags & BACKEND_FLAG_UNHEALTHY != 0
}

/// Debug print of backend key/value in hex (like --print-key for acl).
#[allow(dead_code)]
pub fn backend_to_hex(spec: &BackendSpec) -> Result<String, String> {
    let ifindex = spec.ifindex()?;
    let b = spec.build(ifindex);
    Ok(key_to_hex(&backend_to_bytes(&b)))
}
