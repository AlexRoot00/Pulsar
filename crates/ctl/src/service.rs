//! Work with map `lb_services` (HASH: LbServiceKey -> LbService).
//!
//! Service binds (addr, port, proto) to a group of backends. BPF looks up
//! service by `flow.dst_addr/port/proto` in `lookup_lb_service`
//! (ebpf-xdp/src/xdp_prog.rs) and then selects backend from group
//! `backend_group`.
//!
//! IMPORTANT for key byte order:
//!   - `addr`  — in ::ffff format (like flow.dst_addr, see acl_key::Ipv4::to_mapped).
//!   - `port`  — BIG-ENDIAN (network order), since `flow.dst_port` in BPF
//!               is stored via `u16::from_be_bytes` and compared with key
//!               directly. Write `port.to_be_bytes()`.
//!   - `proto` — u8 (IP_PROTO_TCP=6 / UDP=17).
//!
/// Value `LbService` is exactly 28 bytes (backend_group u32, scheduler u8, flags u8, _pad u16, vip_addr[16], vip_port u16), LE.
use crate::acl_key::Ipv4;
use crate::maps::{MapError, bpftool_dump, map_delete, map_update};
use common;

/// Map name `lb_services` (HASH).
pub const LB_SERVICES_MAP: &str = "lb_services";

/// Service parameters (from CLI).
pub struct ServiceSpec {
    pub addr: Ipv4,
    pub port: u16,
    pub proto: u8,
    pub group: u32,
}

/// One service record for `service list` output.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    pub addr: [u8; 16],
    pub port: u16,
    pub proto: u8,
    pub backend_group: u32,
    pub flags: u32,
    pub family: u8,
}

/// Read all services from `lb_services`.
pub fn service_list(iface: &str) -> Result<Vec<ServiceEntry>, MapError> {
    let out = bpftool_dump(iface, LB_SERVICES_MAP)?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&out).map_err(|e| MapError::Json(format!("{e}: {out}")))?;

    let mut result = Vec::new();
    for e in &entries {
        let addr = arr16(&e["key"]["addr"]);
        // Key stores port in host order (as in BPF), so bpftool
        // returns `port` directly as a correct number (80, not 20480).
        let port = e["key"]["port"].as_u64().unwrap_or(0) as u16;
        let proto = e["key"]["proto"].as_u64().unwrap_or(0) as u8;
        let family = e["key"]["family"].as_u64().unwrap_or(0) as u8;
        let backend_group = e["value"]["backend_group"].as_u64().unwrap_or(0) as u32;
        let flags = e["value"]["flags"].as_u64().unwrap_or(0) as u32;
        result.push(ServiceEntry {
            addr,
            port,
            proto,
            family,
            backend_group,
            flags,
        });
    }
    Ok(result)
}

/// Add a service (key=LbServiceKey, value=LbService).
pub fn service_add(iface: &str, spec: &ServiceSpec) -> Result<(), MapError> {
    let key = service_key_to_bytes(
        &spec.addr.to_mapped(),
        spec.port,
        spec.proto,
        common::AF_INET,
    );
    let value = service_val_to_bytes(spec.group, 0);
    map_update(iface, LB_SERVICES_MAP, &key, &value).map_err(|e| amend(e, LB_SERVICES_MAP))?;
    Ok(())
}

/// Delete service by (addr, port, proto) — key is built the same way as add.
pub fn service_delete(iface: &str, spec: &ServiceSpec) -> Result<(), MapError> {
    let key = service_key_to_bytes(
        &spec.addr.to_mapped(),
        spec.port,
        spec.proto,
        common::AF_INET,
    );
    map_delete(iface, LB_SERVICES_MAP, &key).map_err(|e| amend(e, LB_SERVICES_MAP))?;
    Ok(())
}

/// Completely clear all services.
pub fn service_flush(iface: &str) -> Result<usize, MapError> {
    let list = service_list(iface)?;
    let n = list.len();
    for e in &list {
        let key = service_key_to_bytes(&e.addr, e.port, e.proto, e.family);
        map_delete(iface, LB_SERVICES_MAP, &key)?;
    }
    Ok(n)
}

// ----- serialization -----

/// Serialize `LbServiceKey` (repr(C)):
/// addr[16] + port(2) + proto(1) + family(1) = 20 bytes
/// Structure LbServiceKey size = 20 bytes, alignment = 2.
/// PORT BYTE ORDER: BPF builds key in `lookup_lb_service` from
/// `flow.dst_port`, which is stored via `u16::from_be_bytes`, i.e. in
/// HOST (native / little-endian) order. Therefore we write port as
/// `to_le_bytes()` (for 80 -> bytes `50 00`), OTHERWISE the rule won't match
/// with real packet. (bpftool will show number 20480 = 0x5000 — this is
/// correct host representation of same bytes `50 00`.)
fn service_key_to_bytes(addr: &[u8; 16], port: u16, proto: u8, family: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.extend_from_slice(addr);
    v.extend_from_slice(&port.to_le_bytes());
    v.push(proto);
    v.push(family); // family field
    debug_assert_eq!(v.len(), 20, "LbServiceKey must serialize to 20 bytes");
    v
}

/// Serialize `LbService` (28 bytes, LE): backend_group u32, scheduler u8, flags u8, _pad u16, vip_addr [u8;16], vip_port u16, _pad2 u16.
fn service_val_to_bytes(backend_group: u32, flags: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(28);
    v.extend_from_slice(&backend_group.to_le_bytes());
    v.push(0); // scheduler
    v.push(flags as u8); // flags (only lower 8 bits used)
    v.extend_from_slice(&0u16.to_le_bytes()); // _pad
    v.extend_from_slice(&[0u8; 16]); // vip_addr
    v.extend_from_slice(&0u16.to_le_bytes()); // vip_port
    v.extend_from_slice(&0u16.to_le_bytes()); // _pad2 - to reach 28 bytes
    debug_assert_eq!(v.len(), 28, "LbService must serialize to 28 bytes");
    v
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

/// Append map name to error message for diagnostics.
fn amend(e: MapError, map: &str) -> MapError {
    match e {
        MapError::Bpftool { code, stderr } => MapError::Bpftool {
            code,
            stderr: format!("[{map}] {stderr}"),
        },
        other => other,
    }
}
