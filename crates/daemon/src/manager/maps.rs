 //! Map read/write via libbpf-rs (no bpftool dependency for data operations).
 //!
 // ! All map names match `ebpf-xdp/src/xdp_prog.rs`:
 // !   l4_acl, counters, conntrack, rate_limit, vlan_acl, lb_backends, lb_services.
 
  use super::acl_key::{AclAddr, AclRule, Ipv4, Ipv6, PortSpec, Proto, parse_acl_addr};
  use common::CounterId;
  use common::maps::{L4AclKey, VlanAclKey, VlanAclValue};
  use libbpf_rs::{MapCore, MapFlags, MapHandle};
  use serde_yaml;
  use tracing::info;
 
 /// Map name `l4_acl` (LPM_TRIE, read+write).
 pub const L4_ACL_MAP: &str = "l4_acl";
 /// Map name `counters` (PERCPU_ARRAY, read-only in CLI).
 pub const COUNTERS_MAP: &str = "counters";
 /// Map name `conntrack` (LRU_PERCPU_HASH, read-only in CLI).
 pub const CONNTRACK_MAP: &str = "conntrack";
 /// Map name `rate_limit` (PERCPU_HASH, read-only in CLI).
 pub const RATE_LIMIT_MAP: &str = "rate_limit";
  /// Map name `vlan_acl` (HASH, read+write).
  pub const VLAN_ACL_MAP: &str = "vlan_acl";
  /// Map name `lb_backends` (ARRAY, read+write).
  // Note: LB_BACKENDS_MAP is defined in backend.rs, not here.
  /// Map name `lb_services` (HASH).
  // Note: LB_SERVICES_MAP is defined in service.rs, not here.
 /// Map name `event_mask` (ARRAY, size 1, value u64 bitmask for EventKind).
 pub const EVENT_MASK_MAP: &str = "event_mask";
 
 /// ACL entry for list display.
 #[derive(Debug, Clone)]
 pub struct AclEntry {
     pub id: usize,
     pub prefix_len: u32,
     pub family: u8,
     pub src_addr: [u8; 16],
     pub dst_addr: [u8; 16],
     pub ip_proto: u8,
     pub src_port: u16,
     pub dst_port: u16,
     pub action: String,
     pub rule: AclRule,
 }
 /// VLAN ACL entry for list display.
 #[derive(Debug, Clone)]
 pub struct VlanAclEntry {
     pub id: usize,
     pub outer_vlan: u16,
     pub inner_vlan: u16,
     pub action: String,
     pub rate: u32,
 }
 #[derive(Debug)]
 pub enum MapError {
     /// libbpf call failed.
     Libbpf(String),
     /// Failed to parse data.
     Json(String),
     /// Map not found by name.
     NotFound(String),
     /// I/O error.
     Io(std::io::Error),
 }
 
 impl std::error::Error for MapError {}
 
 impl std::fmt::Display for MapError {
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         match self {
             MapError::Libbpf(s) => write!(f, "libbpf error: {s}"),
             MapError::Json(s) => write!(f, "parse error: {s}"),
             MapError::NotFound(s) => write!(f, "not found: {s}"),
             MapError::Io(e) => write!(f, "io error: {e}"),
         }
     }
 }
 
 impl From<std::io::Error> for MapError {
     fn from(e: std::io::Error) -> Self {
         MapError::Io(e)
     }
 }
 
 impl From<libbpf_rs::Error> for MapError {
     fn from(e: libbpf_rs::Error) -> Self {
         MapError::Libbpf(e.to_string())
     }
 }
 
 // ---------------------------------------------------------------------------
 // Map discovery: iterate all loaded maps via libbpf and match by name.
 // ---------------------------------------------------------------------------
 
 fn next_map_id(after_id: u32) -> Option<u32> {
     let mut next_id: u32 = 0;
     let ret = unsafe { libbpf_rs::libbpf_sys::bpf_map_get_next_id(after_id, &mut next_id) };
     if ret == 0 { Some(next_id) } else { None }
 }
 
 /// Open a loaded map by name. Iterates all map IDs until one matches.
 pub fn open_map_by_name(name: &str) -> Result<MapHandle, MapError> {
     let target = name.to_string();
     let mut after = 0u32;
     let mut seen = std::collections::HashSet::new();
     loop {
         if let Some(map_id) = next_map_id(after) {
             if !seen.insert(map_id) {
                 break;
             }
             after = map_id;
             if let Ok(handle) = MapHandle::from_map_id(map_id) {
                 if handle.name().to_str() == Some(target.as_str()) {
                     return Ok(handle);
                 }
             }
         } else {
             break;
         }
     }
     Err(MapError::NotFound(format!(
         "could not find BPF map named '{name}' among loaded maps"
     )))
}
  
  // ---------------------------------------------------------------------------
  // Key/Value serialization helpers
  // ---------------------------------------------------------------------------
  
  /// Look up a single value from a raw byte key.
  pub fn map_lookup(map_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, MapError> {
     let map = open_map_by_name(map_name)?;
     let value = map.lookup(key, MapFlags::ANY)?;
     Ok(value)
 }
 
 /// Update a map entry.
 pub fn map_update(map_name: &str, key: &[u8], value: &[u8]) -> Result<(), MapError> {
     let map = open_map_by_name(map_name)?;
     map.update(key, value, MapFlags::ANY)?;
     Ok(())
 }
 
 /// Delete a map entry.
 pub fn map_delete(map_name: &str, key: &[u8]) -> Result<(), MapError> {
     let map = open_map_by_name(map_name)?;
     map.delete(key)?;
     Ok(())
 }
 
 /// Convert bytes to hex string (lowercase, space-separated).
 /// Used by CLI for debug printing (`--print-key`).
 pub fn key_to_hex(bytes: &[u8]) -> String {
     let mut s = String::with_capacity(bytes.len() * 3);
     for (i, b) in bytes.iter().enumerate() {
         if i > 0 {
             s.push(' ');
         }
         s.push_str(&format!("{b:02x}"));
     }
     s
 }
 
 // ---------------------------------------------------------------------------
 // Counters
 // ---------------------------------------------------------------------------
 
 /// Get counters map and return (CounterId, value) pairs.
 pub fn counters() -> Result<Vec<(CounterId, u64)>, MapError> {
     let map = open_map_by_name(COUNTERS_MAP)?;
     let is_percpu = map.map_type().is_percpu();
     let mut rows = Vec::new();
 
     for key_bytes in map.keys() {
         let idx = if key_bytes.len() >= 4 {
             u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]])
         } else {
             0
         };
 
         let cell_val = if is_percpu {
             // For percpu maps, use lookup_percpu to get per-CPU values
             match map.lookup_percpu(&key_bytes, MapFlags::ANY)? {
                 Some(percpu_vals) => {
                     // Sum all CPU values
                     percpu_vals.iter().fold(0u64, |acc, val| {
                         if val.len() >= 8 {
                             acc + u64::from_le_bytes({
                                 let mut buf = [0u8; 8];
                                 buf.copy_from_slice(&val[..8]);
                                 buf
                             })
                         } else if val.len() >= 4 {
                             acc + u64::from(u32::from_le_bytes({
                                 let mut buf = [0u8; 4];
                                 buf.copy_from_slice(&val[..4]);
                                 buf
                             }))
                         } else {
                             acc
                         }
                     })
                 }
                 None => 0,
             }
         } else {
             // Non-percpu map
             match map.lookup(&key_bytes, MapFlags::ANY)? {
                 Some(val) => {
                     if val.len() >= 8 {
                         u64::from_le_bytes({
                             let mut buf = [0u8; 8];
                             buf.copy_from_slice(&val[..8]);
                             buf
                         })
                     } else if val.len() >= 4 {
                         u64::from(u32::from_le_bytes({
                             let mut buf = [0u8; 4];
                             buf.copy_from_slice(&val[..4]);
                             buf
                         }))
                     } else {
                         0
                     }
                 }
                 None => 0,
             }
         };
 
         if let Some(cid) = counter_id_from_u32(idx) {
             rows.push((cid, cell_val));
         }
     }
     Ok(rows)
 }
 
 /// Helper function to convert counter ID from u32.
 fn counter_id_from_u32(v: u32) -> Option<CounterId> {
     use CounterId::*;
     match v {
         0 => Some(RxPackets),
         1 => Some(RxBytes),
         2 => Some(Passed),
         3 => Some(Dropped),
         4 => Some(Redirected),
         5 => Some(ConntrackHit),
         6 => Some(ConntrackMiss),
         7 => Some(AclDrop),
         8 => Some(AclAllow),
         9 => Some(AclRedirect),
         10 => Some(RateLimited),
         11 => Some(ParseError),
         12 => Some(TcFragment),
         13 => Some(SlowPath),
         14 => Some(HostFound),
         15 => Some(RxIpv4),
         16 => Some(RxIpv6),
         17 => Some(RxIcmpv6),
         18 => Some(RxTcp),
         19 => Some(RxUdp),
         20 => Some(Unknown),
         21 => Some(BackendUnavailable),
         22 => Some(RedirectFailed),
         23 => Some(BackendSelected),
         24 => Some(ServiceMiss),
         25 => Some(ServiceHit),
         26 => Some(RxVlan),
         _ => None,
     }
 }
 
 /// Count entries in conntrack map.
 pub fn conntrack_count() -> Result<usize, MapError> {
      // Enumerate keys via libbpf-rs. A missing map is treated as empty.
      match open_map_by_name(CONNTRACK_MAP) {
          Ok(map) => Ok(map.keys().count()),
          Err(MapError::NotFound(_)) => Ok(0),
          Err(e) => Err(e),
      }
  }
 
 /// Count entries in rate_limit map.
 pub fn rate_limit_count() -> Result<usize, MapError> {
      // Enumerate keys via libbpf-rs. A missing map is treated as empty.
      match open_map_by_name(RATE_LIMIT_MAP) {
          Ok(map) => Ok(map.keys().count()),
          Err(MapError::NotFound(_)) => Ok(0),
          Err(e) => Err(e),
      }
  }
 
 // ---------------------------------------------------------------------------
 // ACL (l4_acl) — LPM_TRIE
 // ---------------------------------------------------------------------------
 
 /// List ACL entries in l4_acl map.
 pub fn acl_list() -> Result<Vec<AclEntry>, MapError> {
     let map = open_map_by_name(L4_ACL_MAP)?;
     let mut result = Vec::new();
 
     for (i, key_bytes) in map.keys().enumerate() {
         let value_bytes = match map.lookup(&key_bytes, MapFlags::ANY)? {
             Some(v) => v,
             None => continue,
         };
 
         let (prefix_len, family, src_addr, dst_addr, ip_proto, dst_port, src_port, tcp_flags) =
             if key_bytes.len() >= 48 {
                 let prefix_len =
                     u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]]);
                 let family = key_bytes[4];
                 let src_addr: [u8; 16] = key_bytes[5..21].try_into().unwrap_or([0; 16]);
                 let dst_addr: [u8; 16] = key_bytes[21..37].try_into().unwrap_or([0; 16]);
                 let ip_proto = key_bytes[37];
                 let dst_port = u16::from_le_bytes([key_bytes[38], key_bytes[39]]);
                 let src_port = u16::from_le_bytes([key_bytes[40], key_bytes[41]]);
                 let tcp_flags_mask = key_bytes[42];
                 let tcp_flags_value = key_bytes[43];
                 (
                     prefix_len,
                     family,
                     src_addr,
                     dst_addr,
                     ip_proto,
                     dst_port,
                     src_port,
                     tcp_flags_value & tcp_flags_mask,
                 )
             } else {
                 (0, 4, [0u8; 16], [0u8; 16], 0, 0, 0, 0)
             };
 
         let (action_str, acl_action, rate) = if value_bytes.len() >= 8 {
             let action_num = u32::from_le_bytes({
                 let mut buf = [0u8; 4];
                 let len = value_bytes.len().min(4);
                 buf[..len].copy_from_slice(&value_bytes[..len]);
                 buf
             });
             let rate = u32::from_le_bytes({
                 let mut buf = [0u8; 4];
                 if value_bytes.len() >= 8 {
                     buf.copy_from_slice(&value_bytes[4..8]);
                 }
                 buf
             });
             let acl_action = match action_num {
                 0 => common::AclAction::Allow,
                 1 => common::AclAction::Drop,
                 2 => common::AclAction::Redirect,
                 3 => common::AclAction::Inspect,
                 _ => common::AclAction::Allow,
             };
             let action_str = match acl_action {
                 common::AclAction::Allow => "Allow",
                 common::AclAction::Drop => "Drop",
                 common::AclAction::Redirect => "Redirect",
                 common::AclAction::Inspect => "Inspect",
             }
             .to_string();
             (action_str, acl_action, rate)
         } else {
             ("unknown".to_string(), common::AclAction::Allow, 0)
         };
 
         let (src_addr_rule, dst_addr_rule) = if family == 4 {
             (
                 AclAddr::V4(Ipv4::from_mapped(&src_addr)),
                 AclAddr::V4(Ipv4::from_mapped(&dst_addr)),
             )
         } else if family == 6 {
             (
                 AclAddr::V6(Ipv6::from_raw(src_addr, None)),
                 AclAddr::V6(Ipv6::from_raw(dst_addr, None)),
             )
         } else {
             // fallback to IPv4 format
             (
                 AclAddr::V4(Ipv4::from_mapped(&src_addr)),
                 AclAddr::V4(Ipv4::from_mapped(&dst_addr)),
             )
         };
         let proto = match ip_proto {
             6 => Proto::Tcp,
             17 => Proto::Udp,
             1 => Proto::Icmp,
             58 => Proto::Icmpv6,
             _ => Proto::Unknown(ip_proto),
         };
         let rule = AclRule {
             action: acl_action,
             src: src_addr_rule,
             dst: dst_addr_rule,
             proto,
             sport: match src_port {
                 0 => PortSpec::Any,
                 p => PortSpec::Exact(p),
             },
             dport: match dst_port {
                 0 => PortSpec::Any,
                 p => PortSpec::Exact(p),
             },
             tcp_flags,
             rate,
         };
          let entry = AclEntry {
              id: i,
              prefix_len,
              family,
              src_addr,
              dst_addr,
              ip_proto,
              src_port,
              dst_port,
              action: action_str,
              rule,
          };
         result.push(entry);
     }
     Ok(result)
 }
 
 /// Add or update an ACL rule in l4_acl map.
 pub fn acl_add(
     action: &str,
     src: &str,
     dst: &str,
     proto: Option<&str>,
     rate: Option<u32>,
 ) -> Result<(), MapError> {
     let acl_action = match action {
         "allow" => common::AclAction::Allow,
         "drop" => common::AclAction::Drop,
         "redirect" => common::AclAction::Redirect,
         "inspect" => common::AclAction::Inspect,
         other => return Err(MapError::Json(format!("unknown action: {other}"))),
     };
     let proto = match proto {
         Some(p) => Proto::parse(p).map_err(MapError::Json)?,
         None => Proto::Tcp,
     };
     let (src_addr, src_port) = parse_endpoint(src, proto)?;
     let (dst_addr, dst_port) = parse_endpoint(dst, proto)?;
     let action_str = action.to_string();
     let rule = AclRule {
         action: acl_action,
         src: src_addr,
         dst: dst_addr,
         proto,
         sport: src_port,
         dport: dst_port,
         tcp_flags: 0,
         rate: rate.unwrap_or(0),
     };
     let key_bytes = rule.build_key();
     let value_bytes = rule.build_value();
     map_update(L4_ACL_MAP, &key_bytes, &value_bytes)
         .map_err(|e| MapError::Json(format!("[{action_str}] {e}")))?;
     Ok(())
 }
 
 /// Parse "ip:port" or "ip:any" into (AclAddr, PortSpec).
 /// Handles IPv6 addresses with bracket notation: [::1]:80 or ::1:80
 fn parse_endpoint(s: &str, proto: Proto) -> Result<(AclAddr, PortSpec), MapError> {
     // For ICMP and ICMPv6, ports don't exist - allow just <ip> or <ip>:any
     let is_icmp = matches!(proto, Proto::Icmp | Proto::Icmpv6);
 
     if is_icmp {
         // For ICMP, check if it's IPv6 with bracket notation
         if s.starts_with('[') {
             // IPv6 in brackets: [::1] or [::1]:any
             let end = s
                 .find(']')
                 .ok_or_else(|| MapError::Json(format!("unclosed IPv6 bracket")))?;
             let ip_str = &s[1..end];
             let port_part = s.get(end + 1..).unwrap_or("");
             let port = port_part.strip_prefix(':').unwrap_or(port_part);
             let ip = parse_acl_addr(ip_str).map_err(MapError::Json)?;
             let port = if port.is_empty() || port.eq_ignore_ascii_case("any") {
                 PortSpec::Any
             } else {
                 PortSpec::parse(port).map_err(MapError::Json)?
             };
             Ok((ip, port))
         } else if s.matches(':').count() > 1 {
             // IPv6 without brackets: ::1 or ::1:any - split on LAST colon only if it has "any" or port
             if s.ends_with(":any") || s.ends_with(":Any") || s.ends_with(":ANY") {
                 let ip_str = &s[..s.len() - 4];
                 let ip = parse_acl_addr(ip_str).map_err(MapError::Json)?;
                 Ok((ip, PortSpec::Any))
             } else {
                 // Just IPv6 address, no port
                 let ip = parse_acl_addr(s).map_err(MapError::Json)?;
                 Ok((ip, PortSpec::Any))
             }
         } else if s.contains(':') {
             // Could be IPv4-mapped or IPv6 with one colon (rare)
             let (ip_str, port_str) = s.rsplit_once(':').unwrap();
             let ip = parse_acl_addr(ip_str).map_err(MapError::Json)?;
             let port = PortSpec::parse(port_str).map_err(MapError::Json)?;
             Ok((ip, port))
         } else {
             // IPv4
             let ip = parse_acl_addr(s).map_err(MapError::Json)?;
             Ok((ip, PortSpec::Any))
         }
     } else {
         // For TCP/UDP, handle IPv6 addresses which contain colons
         // IPv6 format: [addr]:port or addr:port (for IPv4-mapped)
         let (ip_str, port) = if s.starts_with('[') {
             // IPv6 in brackets: [::1]:80
             let end = s
                 .find(']')
                 .ok_or_else(|| MapError::Json(format!("{s}: unclosed IPv6 bracket")))?;
             let ip_str = &s[1..end];
             let port_part = s.get(end + 1..).unwrap_or("");
             let port = port_part.strip_prefix(':').unwrap_or(port_part);
             (ip_str, port)
         } else if s.matches(':').count() > 1 {
             // IPv6 without brackets: ::1:80 - split on LAST colon
             match s.rsplit_once(':') {
                 Some((ip_str, port)) => (ip_str, port),
                 None => return Err(MapError::Json(format!("{s} must be <ip>:<port|any>"))),
             }
          } else {
              // IPv4: 192.168.0.1:80
              s.rsplit_once(':')
                  .ok_or_else(|| MapError::Json(format!("{s} must be <ip>:<port|any>")))?
          };
 
         let addr = parse_acl_addr(ip_str).map_err(MapError::Json)?;
         let port = PortSpec::parse(port).map_err(MapError::Json)?;
         Ok((addr, port))
     }
 }
 
 /// Delete an ACL entry by its list index.
 pub fn acl_del_by_index(id: usize) -> Result<(), MapError> {
     let entries = acl_list()?;
     if id >= entries.len() {
         return Err(MapError::Json(format!(
             "ACL rule index {} out of range (0..{})",
             id,
             entries.len()
         )));
     }
     let entry = &entries[id];
     let key = L4AclKey {
         prefix_len: entry.prefix_len,
         family: entry.family,
         src_addr: entry.src_addr,
         dst_addr: entry.dst_addr,
         ip_proto: entry.ip_proto,
         dst_port: entry.dst_port,
         src_port: entry.src_port,
         tcp_flags_mask: 0,
         tcp_flags_value: 0,
         _pad: 0,
         _pad2: 0,
     };
      let key_bytes = key.to_bytes();
      // Verify the key exists before deleting
      if map_lookup(L4_ACL_MAP, &key_bytes)?.is_none() {
          return Err(MapError::Json(format!("ACL rule at index {} not found in map", id)));
      }
      map_delete(L4_ACL_MAP, &key_bytes)
 }
 
 // ---------------------------------------------------------------------------
 // VLAN ACL
 // ---------------------------------------------------------------------------
 
 /// Delete a VLAN ACL entry by its list index.
 pub fn vlan_acl_del_by_index(id: usize) -> Result<(), MapError> {
     let entries = vlan_acl_list()?;
     if id >= entries.len() {
         return Err(MapError::Json(format!(
             "VLAN ACL rule index {} out of range (0..{})",
             id,
             entries.len()
         )));
     }
     let entry = &entries[id];
     let key = VlanAclKey {
         outer_vlan: entry.outer_vlan,
         inner_vlan: entry.inner_vlan,
         _pad: [0; 4],
     };
     let key_bytes = unsafe {
         std::slice::from_raw_parts(
             &key as *const VlanAclKey as *const u8,
             std::mem::size_of::<VlanAclKey>(),
         )
     };
     map_delete(VLAN_ACL_MAP, key_bytes)
 }
 
 /// Add or update a VLAN ACL entry.
 pub fn vlan_acl_add(
     vlan_id: u16,
     inner_vlan: Option<u16>,
     action: &str,
     rate: Option<u32>,
 ) -> Result<(), MapError> {
     let acl_action = match action {
         "allow" => common::AclAction::Allow,
         "drop" => common::AclAction::Drop,
         "redirect" => common::AclAction::Redirect,
         "inspect" => common::AclAction::Inspect,
         other => return Err(MapError::Json(format!("unknown action: {other}"))),
     };
     let inner = inner_vlan.unwrap_or(0);
     let key = VlanAclKey {
         outer_vlan: vlan_id,
         inner_vlan: inner,
         _pad: [0; 4],
     };
     let value = VlanAclValue {
         action: acl_action,
         rate: rate.unwrap_or(0),
     };
     let key_bytes = unsafe {
         std::slice::from_raw_parts(
             &key as *const VlanAclKey as *const u8,
             std::mem::size_of::<VlanAclKey>(),
         )
     };
     let value_bytes = unsafe {
         std::slice::from_raw_parts(
             &value as *const VlanAclValue as *const u8,
             std::mem::size_of::<VlanAclValue>(),
         )
     };
     map_update(VLAN_ACL_MAP, key_bytes, value_bytes)
 }
 
 /// List VLAN ACL entries in vlan_acl map.
 pub fn vlan_acl_list() -> Result<Vec<VlanAclEntry>, MapError> {
     let map = open_map_by_name(VLAN_ACL_MAP)?;
     let mut result = Vec::new();
 
     for (i, key_bytes) in map.keys().enumerate() {
         let value_bytes = match map.lookup(&key_bytes, MapFlags::ANY)? {
             Some(v) => v,
             None => continue,
         };
 
         let (outer_vlan, inner_vlan) = if key_bytes.len() >= 4 {
             (
                 u16::from_le_bytes([key_bytes[0], key_bytes[1]]),
                 u16::from_le_bytes([key_bytes[2], key_bytes[3]]),
             )
         } else {
             (0, 0)
         };
 
         let (action_str, rate) = if value_bytes.len() >= 8 {
             let action_num = u32::from_le_bytes({
                 let mut buf = [0u8; 4];
                 let len = value_bytes.len().min(4);
                 buf[..len].copy_from_slice(&value_bytes[..len]);
                 buf
             });
             let action_str = match action_num {
                 0 => "Allow",
                 1 => "Drop",
                 2 => "Redirect",
                 3 => "Inspect",
                 _ => "unknown",
             }
             .to_string();
             let rate = u32::from_le_bytes({
                 let mut buf = [0u8; 4];
                 if value_bytes.len() >= 8 {
                     buf.copy_from_slice(&value_bytes[4..8]);
                 } else {
                     let len = value_bytes.len().saturating_sub(4).min(4);
                     buf[..len].copy_from_slice(&value_bytes[4..4 + len]);
                 }
                 buf
             });
             (action_str, rate)
         } else {
             ("unknown".to_string(), 0)
         };
 
         let entry = VlanAclEntry {
             id: i,
             outer_vlan,
             inner_vlan,
             action: action_str,
             rate,
         };
         result.push(entry);
     }
     Ok(result)
 }
 
 /// Get the event mask u64 value (bitmask of enabled EventKind).
 pub fn event_mask_get() -> Result<u64, MapError> {
     let map = open_map_by_name(EVENT_MASK_MAP)?;
     let key = 0u32.to_le_bytes();
     let value = map.lookup(&key, MapFlags::ANY)?
         .ok_or_else(|| MapError::NotFound("event_mask map entry missing".to_string()))?;
     if value.len() >= 8 {
         Ok(u64::from_le_bytes({
             let mut buf = [0u8; 8];
             buf.copy_from_slice(&value[..8]);
             buf
         }))
     } else {
         Err(MapError::Json(format!(
             "event_mask value too short: {} bytes",
             value.len()
         )))
     }
 }
 
 /// Set the event mask u64 value.
 pub fn event_mask_set(mask: u64) -> Result<(), MapError> {
     let map = open_map_by_name(EVENT_MASK_MAP)?;
     let key = 0u32.to_le_bytes();
     let value = mask.to_le_bytes();
     map.update(&key, &value, MapFlags::ANY)?;
     Ok(())
 }
 
 // ---------------------------------------------------------------------------
 // Config handling
 // ---------------------------------------------------------------------------
 
 /// Clear all entries in a map.
 pub fn clear_map(map_name: &str) -> Result<(), MapError> {
     let map = open_map_by_name(map_name)?;
     for key_bytes in map.keys() {
         // Ignore deletion errors; best effort.
         let _ = map.delete(&key_bytes);
     }
     Ok(())
 }
 
  /// Expand an AddrBlock into a vector of IP address strings (CIDR or single IP).
   fn expand_addr_block(block: &Option<crate::config::AddrBlock>) -> Vec<String> {
       let mut v = Vec::new();
       if let Some(block) = block {
           if let Some(addrs) = &block.addresses {
               for addr in addrs {
                   v.push(addr.clone());
               }
           }
       }
       if v.is_empty() {
           v.push("0.0.0.0/0".to_string());
       }
       v
   }
 
 /// Load configuration from a YAML file and apply it to the BPF maps.
 pub fn reload_config(path: &str) -> Result<(), MapError> {
     use crate::config::Config;
     let content = std::fs::read_to_string(path)
         .map_err(|e| MapError::Io(e))?;
     let config: Config = serde_yaml::from_str(&content)
         .map_err(|e| MapError::Json(e.to_string()))?;
 
     // Clear existing maps
     clear_map(L4_ACL_MAP)?;
     clear_map(VLAN_ACL_MAP)?;
 
     // Process allow and drop sections
      for (section_name, rules) in [("allow", &config.acl.allow), ("drop", &config.acl.drop)] {
          let action = match section_name {
             "allow" => "allow",
             "drop" => "drop",
             _ => continue,
         };
          for rule in rules {
              let rate = rule.rate.unwrap_or(0);

              // Process L4 ACL entries only if rule has src or dst
              if rule.src.is_some() || rule.dst.is_some() {
                  // Build src and dst IP lists
                  let src_ips = expand_addr_block(&rule.src);
                  let dst_ips = expand_addr_block(&rule.dst);
                  // Parse ports and proto from dst addr block
                   let (dport, proto_str) = rule.dst.as_ref()
                       .and_then(|d| d.ports.as_ref())
                       .map(|ports| (ports.number.clone(), ports.proto.clone()))
                       .unwrap_or(("any".to_string(), "tcp".to_string()));
                  for src_ip in &src_ips {
                      for dst_ip in &dst_ips {
                          // Build endpoint strings with port
                          let src_endpoint = format!("{}:any", src_ip);
                          let dst_endpoint = if dport == "any" {
                              format!("{}:any", dst_ip)
                          } else {
                              format!("{}:{}", dst_ip, dport)
                          };
                          // Add L4 ACL rule
                          acl_add(
                              action,
                              &src_endpoint,
                              &dst_endpoint,
                              Some(&proto_str),
                              Some(rate),
                          )?;
                      }
                  }
              }

              // Process VLAN entries (separate from L4 ACL)
              if let Some(ref vlan_list) = rule.vlan {
                  for vlan_spec in vlan_list {
                      for (outer, inner_opt) in vlan_spec.iter() {
                          let inner = inner_opt.unwrap_or(0);
                          vlan_acl_add(
                              outer,
                              Some(inner),
                              action,
                              Some(rate),
                          )?;
                      }
                  }
              }
          }
      }

      // Set event mask from logging section
    let mut mask: u64 = 0;
     if config.logging.PacketDrop { mask |= 1 << common::EventKind::PacketDrop as u64; }
     if config.logging.RateLimited { mask |= 1 << common::EventKind::RateLimited as u64; }
     if config.logging.ConntrackMiss { mask |= 1 << common::EventKind::ConntrackMiss as u64; }
     if config.logging.BackendSelected { mask |= 1 << common::EventKind::BackendSelected as u64; }
     if config.logging.SlowPath { mask |= 1 << common::EventKind::SlowPath as u64; }
     if config.logging.ServiceMatched { mask |= 1 << common::EventKind::ServiceMatched as u64; }
     if config.logging.VlanDetected { mask |= 1 << common::EventKind::VlanDetected as u64; }
     if config.logging.PacketAllow { mask |= 1 << common::EventKind::PacketAllow as u64; }
      event_mask_set(mask)?;

      // Apply rate limiting configuration
      let rl = &config.rate_limit;
      info!(
          "rate_limit: global max_tokens={}, refill_per_sec={}, per_rule_multiplier={}",
          rl.global.max_tokens, rl.global.refill_per_sec, rl.per_rule_multiplier
      );

      // Apply monitoring configuration
      let mon = &config.monitoring;
      info!(
          "monitoring: ringbuf_bytes={}, poll_interval_ms={}",
          mon.ringbuf_bytes, mon.poll_interval_ms
      );

      // Log default ACL action
      info!("acl.default_action: {}", config.acl.default_action);

      Ok(())
 }
 