//! Wrappers around `bpftool` for reading/writing kernel maps.
//!
//! We use `bpftool` as transport (it's already on the target Linux machine
//! and that's how maps were controlled during debugging). This avoids the
//! need to open map-fd directly via libbpf-rs and works with maps loaded
//! by the XDP object (which loads the program itself).
//!
//! All map names match `ebpf-xdp/src/xdp_prog.rs`:
//!   l4_acl, counters, conntrack, rate_limit, vlan_acl, lb_backends, lb_services.

use std::process::Command;

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
pub const LB_BACKENDS_MAP: &str = "lb_backends";
/// Map name `lb_services` (HASH, read+write).
pub const LB_SERVICES_MAP: &str = "lb_services";

#[derive(Debug)]
pub enum MapError {
    /// `bpftool` not found / failed to execute.
    Io(std::io::Error),
    /// `bpftool` returned non-zero code or invalid output.
    Bpftool { code: Option<i32>, stderr: String },
    /// Failed to parse JSON output from `bpftool`.
    Json(String),
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MapError::Io(e) => write!(f, "bpftool execution error: {e}"),
            MapError::Bpftool { code, stderr } => {
                write!(f, "bpftool exited with error {code:?}: {stderr}")
            }
            MapError::Json(s) => write!(f, "bpftool output parse error: {s}"),
        }
    }
}

impl From<std::io::Error> for MapError {
    fn from(e: std::io::Error) -> Self {
        MapError::Io(e)
    }
}

impl From<serde_json::Error> for MapError {
    fn from(e: serde_json::Error) -> Self {
        MapError::Json(e.to_string())
    }
}

/// Find XDP program ID attached to an interface.
pub fn find_xdp_prog_id(iface: &str) -> Result<Option<u32>, MapError> {
    let output = Command::new("bpftool")
        .args(["net", "show", "dev", iface])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Debug: show what bpftool returns
    eprintln!("DEBUG: bpftool net show dev {} output:\n{}", iface, stdout);

    // Parse various formats:
    // Format 1 (traditional):
    //   xdp: prog id 123
    //   xdp: prog/xdp id 123
    // Format 2 (generic XDP, seen on some kernels):
    //   xdp:
    //   end0(2) generic id 534
    // Format 3 (driver XDP):
    //   xdpdrv: prog id 123
    let lines: Vec<&str> = stdout.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let line = line.trim();

        // Format 1 & 3: "xdp: prog id N" or "xdpdrv: prog id N"
        if (line.starts_with("xdp:")
            || line.starts_with("xdpdrv:")
            || line.starts_with("xdpgeneric:"))
            && line.contains("prog")
            && line.contains("id")
        {
            if let Some(idx) = line.find("prog") {
                let rest = &line[idx..];
                if let Some(id_pos) = rest.find("id ") {
                    let after = &rest[id_pos + 3..];
                    let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(id) = num.parse::<u32>() {
                        eprintln!("DEBUG: Found XDP program id: {}", id);
                        return Ok(Some(id));
                    }
                }
            }
        }

        // Format 2: "xdp:" followed by next line with "generic id N"
        if line == "xdp:" && i + 1 < lines.len() {
            let next_line = lines[i + 1].trim();
            if next_line.contains("generic id") {
                if let Some(id_pos) = next_line.find("generic id ") {
                    let after = &next_line[id_pos + 11..];
                    let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(id) = num.parse::<u32>() {
                        eprintln!("DEBUG: Found XDP program id (generic): {}", id);
                        return Ok(Some(id));
                    }
                }
            }
            // Also check for "prog id" on next line
            if next_line.contains("prog") && next_line.contains("id") {
                if let Some(idx) = next_line.find("prog") {
                    let rest = &next_line[idx..];
                    if let Some(id_pos) = rest.find("id ") {
                        let after = &rest[id_pos + 3..];
                        let num: String =
                            after.chars().take_while(|c| c.is_ascii_digit()).collect();
                        if let Ok(id) = num.parse::<u32>() {
                            eprintln!("DEBUG: Found XDP program id (next line): {}", id);
                            return Ok(Some(id));
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Get all map IDs for a given program ID.
pub fn get_map_ids_for_prog(prog_id: u32) -> Result<Vec<u32>, MapError> {
    let output = Command::new("bpftool")
        .args(["prog", "show", "id", &prog_id.to_string()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(MapError::Bpftool {
            code: output.status.code(),
            stderr: format!("{}{}", stdout, stderr),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map_ids: Vec<u32> = Vec::new();
    for line in stdout.lines() {
        if let Some((_, ids)) = line.split_once("map_ids") {
            for id in ids.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
                if let Ok(map_id) = id.trim_matches(':').parse::<u32>() {
                    map_ids.push(map_id);
                }
            }
        }
    }
    Ok(map_ids)
}

/// Get map name and type for a map ID.
fn get_map_info(map_id: u32) -> Result<(String, String), MapError> {
    let output = Command::new("bpftool")
        .args(["map", "show", "id", &map_id.to_string()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(MapError::Bpftool {
            code: output.status.code(),
            stderr: format!("{}{}", stdout, stderr),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut words = stdout.split_whitespace();
    let _id = words.next();
    let map_type = words.next().unwrap_or("").to_string();
    let mut name = String::new();
    while let Some(word) = words.next() {
        if word == "name" {
            name = words.next().unwrap_or("").to_string();
            break;
        }
    }
    Ok((name, map_type))
}

/// Find a map ID by program ID and map name.
pub fn find_map_id_by_prog(iface: &str, map_name: &str) -> Result<u32, MapError> {
    let prog_id = find_xdp_prog_id(iface)?.ok_or_else(|| MapError::Bpftool {
        code: None,
        stderr: format!("No XDP program attached to {}", iface),
    })?;

    let map_ids = get_map_ids_for_prog(prog_id)?;

    for map_id in map_ids {
        let (name, _type) = get_map_info(map_id)?;
        if name == map_name {
            return Ok(map_id);
        }
    }

    Err(MapError::Bpftool {
        code: None,
        stderr: format!("Map '{}' not found in program {}", map_name, prog_id),
    })
}

/// Execute `bpftool map dump id <map_id>` and return raw JSON output.
pub fn bpftool_dump_id(map_id: u32) -> Result<String, MapError> {
    bpftool(&["dump".to_string(), "id".to_string(), map_id.to_string()])
}

/// Execute any subcommand `bpftool map ...` with map ID.
pub fn bpftool_run_id(map_id: u32, args: &[String]) -> Result<(), MapError> {
    let mut full_args = vec!["id".to_string(), map_id.to_string()];
    full_args.extend(args.iter().cloned());
    bpftool(&full_args)?;
    Ok(())
}

/// Execute `bpftool map <sub> <id> ...` and return stdout.
fn bpftool(args: &[String]) -> Result<String, MapError> {
    eprintln!("DEBUG bpftool map {}", args.join(" "));
    let output = Command::new("bpftool").arg("map").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let mut msg = stderr;
        if msg.is_empty() {
            msg = stdout;
        } else if !stdout.is_empty() {
            msg = format!("{msg}\n{stdout}");
        }
        return Err(MapError::Bpftool {
            code: output.status.code(),
            stderr: msg,
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Encode a byte slice as a hex string with spaces (one byte per hex pair):
/// "01 00 00 00 ..."), like in manual bpftool command. Public —
/// used by CLI for debug printing (`--print-key`).
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

/// Encode a byte slice as a list of hex tokens (one per byte: "01","00",...),
/// as expected by bpftool in manual command (`key hex 50 01 00 00 02 ...`).
fn to_hex_bytes(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Add/update an element in map by map ID.
pub fn map_update_id(map_id: u32, key: &[u8], value: &[u8]) -> Result<(), MapError> {
    let mut args: Vec<String> = vec![
        "update".into(),
        "id".into(),
        map_id.to_string(),
        "key".into(),
        "hex".into(),
    ];
    args.extend(to_hex_bytes(key));
    args.push("value".into());
    args.push("hex".into());
    args.extend(to_hex_bytes(value));
    bpftool(&args)?;
    Ok(())
}

/// Delete an element from map by map ID.
pub fn map_delete_id(map_id: u32, key: &[u8]) -> Result<(), MapError> {
    let mut args: Vec<String> = vec![
        "delete".into(),
        "id".into(),
        map_id.to_string(),
        "key".into(),
        "hex".into(),
    ];
    args.extend(to_hex_bytes(key));
    bpftool(&args)?;
    Ok(())
}

/// Execute `bpftool map dump name <map_name>` and return raw JSON output.
pub fn bpftool_dump(iface: &str, map_name: &str) -> Result<String, MapError> {
    let map_id = find_map_id_by_prog(iface, map_name)?;
    bpftool_dump_id(map_id)
}

/// Execute any subcommand `bpftool map ...` with map name.
pub fn bpftool_run(iface: &str, map_name: &str, args: &[String]) -> Result<(), MapError> {
    let map_id = find_map_id_by_prog(iface, map_name)?;
    bpftool_run_id(map_id, args)
}

/// Add/update an element in map by map name.
pub fn map_update(iface: &str, map_name: &str, key: &[u8], value: &[u8]) -> Result<(), MapError> {
    let map_id = find_map_id_by_prog(iface, map_name)?;
    map_update_id(map_id, key, value)
}

/// Delete an element from map by map name.
pub fn map_delete(iface: &str, map_name: &str, key: &[u8]) -> Result<(), MapError> {
    let map_id = find_map_id_by_prog(iface, map_name)?;
    map_delete_id(map_id, key)
}

/// Dump counters map and return (CounterId, value) pairs.
pub fn counters(iface: &str) -> Result<Vec<(common::CounterId, u64)>, MapError> {
    let map_id = find_map_id_by_prog(iface, COUNTERS_MAP)?;
    let out = bpftool_dump_id(map_id)?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&out).map_err(|e| MapError::Json(format!("{e}: {out}")))?;
    let mut rows = Vec::new();
    for e in entries {
        let key = &e["key"];
        let value = &e["value"];
        let idx = key["index"].as_u64().unwrap_or(0) as u32;
        let val = value["value"].as_u64().unwrap_or(0);
        if let Some(cid) = counter_id_from_u32(idx) {
            rows.push((cid, val));
        }
    }
    Ok(rows)
}

pub fn counter_id_from_u32(v: u32) -> Option<common::CounterId> {
    use common::CounterId::*;
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
pub fn conntrack_count(iface: &str) -> Result<usize, MapError> {
    let map_id = find_map_id_by_prog(iface, CONNTRACK_MAP)?;
    let out = bpftool_dump_id(map_id)?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&out).map_err(|e| MapError::Json(format!("{e}: {out}")))?;
    Ok(entries.len())
}

/// Count entries in rate_limit map.
pub fn rate_limit_count(iface: &str) -> Result<usize, MapError> {
    let map_id = find_map_id_by_prog(iface, RATE_LIMIT_MAP)?;
    let out = bpftool_dump_id(map_id)?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&out).map_err(|e| MapError::Json(format!("{e}: {out}")))?;
    Ok(entries.len())
}

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
    pub rule: crate::acl_key::AclRule,
}

/// Parse IPv4/IPv6 address from bpftool JSON array.
pub fn addr_from_json(v: &serde_json::Value) -> [u8; 16] {
    let mut addr = [0u8; 16];
    if let Some(arr) = v.as_array() {
        for (i, x) in arr.iter().enumerate().take(16) {
            addr[i] = x.as_u64().unwrap_or(0) as u8;
        }
    }
    addr
}
