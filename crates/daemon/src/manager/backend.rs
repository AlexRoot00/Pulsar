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

use super::{
    acl_key::Ipv4,
    maps::{MapError, key_to_hex, map_delete, map_update, open_map_by_name},
};
use common::{BACKEND_FLAG_UNHEALTHY, Backend};
use libbpf_rs::{MapCore, MapFlags};
use std::mem::size_of;

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
pub fn backend_list() -> Result<Vec<BackendEntry>, MapError> {
    let map = open_map_by_name(LB_BACKENDS_MAP)?;
    let mut result = Vec::new();

    for key_bytes in map.keys() {
        let value_bytes = match map.lookup(&key_bytes, MapFlags::ANY)? {
            Some(v) => v,
            None => continue,
        };
        let b = backend_from_bytes(&value_bytes);
        if !b.is_configured() {
            continue;
        }
        let id = if key_bytes.len() >= 4 {
            u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]])
        } else {
            0
        };
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
pub fn next_backend_id() -> Result<u32, MapError> {
    let list = backend_list()?;
    Ok(list.iter().map(|e| e.id).max().map(|m| m + 1).unwrap_or(0))
}

/// Add backend with auto-assigned id (max existing + 1).
/// Returns assigned id.
pub fn backend_add(spec: &BackendSpec) -> Result<u32, MapError> {
    let ifindex = spec.ifindex().map_err(|e| MapError::Json(e))?;
    let id = next_backend_id()?;
    let backend = spec.build(ifindex);

    // Write the backend itself.
    let key = id.to_le_bytes().to_vec();
    let value = backend_to_bytes(&backend);
    map_update(LB_BACKENDS_MAP, &key, &value).map_err(|e| amend(e, LB_BACKENDS_MAP))?;

    // Write ifindex to devmap, so bpf_redirect_map(..., backend_id)
    // knows egress interface.
    devmap_update(id, ifindex).map_err(|e| amend(e, LB_DEV_MAP))?;

    // Update lb_meta.num_backends = id + 1. The lb_meta map now exists in
    // the BPF object (btf_map!(lb_meta, ...)), value is `LbMeta` (8 bytes:
    // num_backends u32 + _pad u32).
    let mut meta_val = Vec::with_capacity(8);
    meta_val.extend_from_slice(&(id + 1).to_le_bytes());
    meta_val.extend_from_slice(&0u32.to_le_bytes());

    map_update(LB_META_MAP, &0u32.to_le_bytes().to_vec(), &meta_val)
        .map_err(|e| amend(e, LB_META_MAP))?;

    Ok(id)
}

/// Add map name to error message for diagnostics.
fn amend(e: MapError, map: &str) -> MapError {
    match e {
        MapError::Libbpf(s) => MapError::Libbpf(format!("[{map}] {s}")),
        MapError::Json(s) => MapError::Json(format!("[{map}] {s}")),
        MapError::NotFound(s) => MapError::NotFound(format!("[{map}] {s}")),
        MapError::Io(e) => MapError::Io(e),
    }
}

/// Convert bytes to individual hex tokens (unused, kept for debugging).
#[allow(dead_code)]
fn to_hex_args(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write entry to DEVMAP. Map `lb_devmap` in BPF is declared with value=u32
/// (btf_map!(lb_devmap, ..., u32, u32)), so kernel expects 8-byte value:
/// struct bpf_devmap_val { ifindex, id }.
fn devmap_update(backend_id: u32, ifindex: u32) -> Result<(), MapError> {
    let key = backend_id.to_le_bytes().to_vec();
    let mut value = Vec::with_capacity(8);
    value.extend_from_slice(&ifindex.to_le_bytes());
    value.extend_from_slice(&0u32.to_le_bytes()); // id = 0 (no program redirect)
    map_update(LB_DEV_MAP, &key, &value)
}

/// Delete backend by id: clear slot in lb_backends (write default
/// backend with ifindex=0 => is_configured()==false) and delete from devmap.
pub fn backend_delete(id: u32) -> Result<(), MapError> {
    // Check if backend exists.
    let list = backend_list()?;
    if !list.iter().any(|e| e.id == id) {
        return Err(MapError::Json(format!("backend with id={id} not found")));
    }

    let zero = Backend::default();
    map_update(
        LB_BACKENDS_MAP,
        &id.to_le_bytes().to_vec(),
        &backend_to_bytes(&zero),
    )?;
    map_delete(LB_DEV_MAP, &id.to_le_bytes().to_vec())?;
    Ok(())
}

/// Completely clear all backends: delete all entries from lb_backends and
/// lb_devmap. (lb_meta is not used by BPF and may not exist in the loaded
/// object, so we don't touch it.)
pub fn backend_flush() -> Result<usize, MapError> {
    let list = backend_list()?;
    let n = list.len();
    for e in &list {
        let zero = Backend::default();
        map_update(
            LB_BACKENDS_MAP,
            &e.id.to_le_bytes().to_vec(),
            &backend_to_bytes(&zero),
        )?;
        map_delete(LB_DEV_MAP, &e.id.to_le_bytes().to_vec())?;
    }
    let mut meta_zero = Vec::with_capacity(8);
    meta_zero.extend_from_slice(&0u32.to_le_bytes());
    meta_zero.extend_from_slice(&0u32.to_le_bytes());
    map_update(LB_META_MAP, &0u32.to_le_bytes().to_vec(), &meta_zero)?;
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

/// Parse `Backend` from raw bytes as stored in the BPF map.
/// Uses `Backend` struct directly via from_bytes.
fn backend_from_bytes(bytes: &[u8]) -> Backend {
    unsafe {
        if bytes.len() < size_of::<Backend>() {
            return Backend::default();
        }
        let mut b = Backend::default();
        let src = bytes.as_ptr();
        std::ptr::copy_nonoverlapping(src, &mut b as *mut Backend as *mut u8, size_of::<Backend>());
        b
    }
}

/// Resolve ifindex to interface name (for human-readable output).
/// Uses `libc::if_indextoname` directly — no external `ip` command dependency.
fn ifindex_to_name(ifindex: u32) -> Option<String> {
    if ifindex == 0 {
        return None;
    }
    let mut buf = [0u8; libc::IFNAMSIZ as usize];
    let result = unsafe {
        libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char)
    };
    if result.is_null() {
        return None;
    }
    let name_end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let raw_name = std::str::from_utf8(&buf[..name_end]).ok()?;
    let name = raw_name.split('@').next().unwrap_or(raw_name);
    Some(name.to_string())
}

/// Indicator "backend unhealthy" (for display).
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
