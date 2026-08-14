use crate::acl_key::{AclAddr, AclRule, Ipv4, Ipv6, PortSpec, Proto};
use common::AclAction;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// ACL entry for list display.
#[derive(Debug, Clone)]
pub struct AclEntry {
    pub id: usize,
    pub prefix_len: u32,
    pub family: u8,
    pub ip_proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub action: String,
    pub rule: AclRule,
}

/// Helper function to convert counter ID from u32.
fn counter_id_from_u32(v: u32) -> Option<common::CounterId> {
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

/// Command types that can be sent over the socket
#[derive(Debug, Deserialize, Serialize)]
pub enum Command {
    // ACL commands
    AclList {
        iface: String,
    },
    AclAdd {
        iface: String,
        action: String,
        src: String,
        dst: String,
        proto: Option<String>,
        rate: Option<u32>,
    },
    AclDel {
        iface: String,
        id: usize,
    },
    AclVlanList {
        iface: String,
    },
    AclVlanAdd {
        iface: String,
        vlan_id: u16,
        action: String,
        inner_vlan: Option<u16>,
        rate: Option<u32>,
    },
    AclVlanDel {
        iface: String,
        id: usize,
    },

    // Monitoring commands
    CountersShow {
        iface: String,
    },
    ConntrackShow {
        iface: String,
    },
    RateLimitShow {
        iface: String,
    },

    // Event mask commands
    EventMaskGet,
    EventMaskSet {
        mask: u64,
    },

    // Config reload command
    ConfigReload {
        path: Option<String>,
    },

    // XDP attachment check
    CheckXdpAttached {
        iface: String,
    },
}

/// Response types that can be sent over the socket
#[derive(Debug, Deserialize, Serialize)]
pub enum Response {
    Success(String),
    Error(String),
    /// For list operations that return data
    ListResult(Vec<String>),
    /// For count operations
    CountResult(usize),
    /// For counter data
    CounterResult(Vec<CounterData>),
    /// For attachment check
    AttachmentResult {
        attached: bool,
        prog_id: Option<u32>,
    },
    /// Event mask
    MaskResult(u64),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CounterData {
    pub id: u32,
    pub name: String,
    pub value: u64,
}

/// Send a command to the daemon and return the response
pub fn send_command(command: Command) -> Result<Response, anyhow::Error> {
    let socket_path = "/tmp/ebpf-daemon.sock";

    // Connect to the daemon
    let mut stream = UnixStream::connect(socket_path)?;

    // Set timeout for connection
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Serialize and send command
    let command_data = serde_json::to_vec(&command)?;
    stream.write_all(&command_data)?;

    // Read response
    let mut buffer = [0; 4096];
    let n = stream.read(&mut buffer)?;

    if n == 0 {
        return Err(anyhow::anyhow!("Empty response from daemon"));
    }

    let response_data = &buffer[..n];
    let response: Response = serde_json::from_slice(response_data)?;

    Ok(response)
}

/// Helper functions to convert Response to the expected return types for CLI
pub fn acl_list(iface: &str) -> Result<Vec<AclEntry>, String> {
    match send_command(Command::AclList {
        iface: iface.to_string(),
    }) {
        Ok(response) => {
            match response {
                Response::ListResult(lines) => {
                    let mut entries = Vec::new();
                    for (i, line) in lines.iter().enumerate() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() < 10 {
                            continue;
                        }
                        let id = parts[0].parse::<usize>().unwrap_or(i);
                        let prefix_len = parts[1].parse::<u32>().unwrap_or(0);
                        let family = parts[2].parse::<u8>().unwrap_or(4);
                        let src_str = parts[3];
                        let dst_str = parts[4];
                        let proto_str = parts[5];
                        let sport_str = parts[6];
                        let dport_str = parts[7];
                        let rate_str = parts[8];
                        let action_str = parts[9..].join(" ");

                        let src_addr = parse_ip(src_str, family);
                        let dst_addr = parse_ip(dst_str, family);
                        let ip_proto = match proto_str {
                            "tcp" => 6,
                            "udp" => 17,
                            "icmp" => 1,
                            "icmpv6" => 58,
                            _ => 0,
                        };
                        let src_port = if sport_str == "any" { 0 } else { sport_str.parse().unwrap_or(0) };
                        let dst_port = if dport_str == "any" { 0 } else { dport_str.parse().unwrap_or(0) };
                        let rate = if rate_str == "-" { 0 } else { rate_str.parse().unwrap_or(0) };

                        let action = match action_str.as_str() {
                            "Allow" => AclAction::Allow,
                            "Drop" => AclAction::Drop,
                            "Redirect" => AclAction::Redirect,
                            "Inspect" => AclAction::Inspect,
                            _ => AclAction::Allow,
                        };

                        let proto = match ip_proto {
                            6 => Proto::Tcp,
                            17 => Proto::Udp,
                            1 => Proto::Icmp,
                            58 => Proto::Icmpv6,
                            _ => Proto::Tcp,
                        };

                        let src_ip = if family == 4 {
                            AclAddr::V4(Ipv4::from_mapped(&src_addr))
                        } else {
                            AclAddr::V6(Ipv6::from_raw(src_addr, None))
                        };
                        let dst_ip = if family == 4 {
                            AclAddr::V4(Ipv4::from_mapped(&dst_addr))
                        } else {
                            AclAddr::V6(Ipv6::from_raw(dst_addr, None))
                        };

                        let rule = AclRule {
                            action,
                            src: src_ip,
                            dst: dst_ip,
                            proto,
                            sport: if src_port == 0 { PortSpec::Any } else { PortSpec::Exact(src_port) },
                            dport: if dst_port == 0 { PortSpec::Any } else { PortSpec::Exact(dst_port) },
                            tcp_flags: 0,
                            rate,
                        };

                        entries.push(AclEntry {
                            id,
                            prefix_len,
                            family,
                            ip_proto,
                            src_port,
                            dst_port,
                            action: action_str,
                            rule,
                        });
                    }
                    Ok(entries)
                }
                Response::Error(msg) => Err(msg),
                _ => Err("Unexpected response type".to_string()),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

fn parse_ip(s: &str, family: u8) -> [u8; 16] {
    let mut addr = [0u8; 16];
    if family == 4 {
        if let Some(ip_part) = s.strip_prefix("::ffff:") {
            let octets: Vec<u8> = ip_part.split('.').filter_map(|p| p.parse().ok()).collect();
            if octets.len() == 4 {
                addr[10] = 0xff;
                addr[11] = 0xff;
                addr[12] = octets[0];
                addr[13] = octets[1];
                addr[14] = octets[2];
                addr[15] = octets[3];
            }
        } else {
            let octets: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
            if octets.len() == 4 {
                addr[12] = octets[0];
                addr[13] = octets[1];
                addr[14] = octets[2];
                addr[15] = octets[3];
            }
        }
    } else {
        let parts: Vec<&str> = s.split(':').collect();
        let mut idx = 0;
        for part in parts {
            if part.is_empty() {
                continue;
            }
            if let Ok(val) = u16::from_str_radix(part, 16) {
                if idx + 1 < 16 {
                    addr[idx] = (val >> 8) as u8;
                    addr[idx + 1] = (val & 0xff) as u8;
                    idx += 2;
                }
            }
        }
    }
    addr
}

pub fn acl_add(iface: &str, action: &str, src: &str, dst: &str, proto: Option<&str>, rate: Option<u32>,) -> Result<(), String> {
    match send_command(Command::AclAdd {
        iface: iface.to_string(),
        action: action.to_string(),
        src: src.to_string(),
        dst: dst.to_string(),
        proto: proto.map(|s| s.to_string()),
        rate,
    }) {
        Ok(response) => match response {
            Response::Success(msg) => {
                println!("{}", msg);
                Ok(())
            }
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn acl_del(iface: &str, id: usize) -> Result<(), String> {
    match send_command(Command::AclDel {
        iface: iface.to_string(),
        id,
    }) {
        Ok(response) => match response {
            Response::Success(msg) => {
                println!("{}", msg);
                Ok(())
            }
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn counters(iface: &str) -> Result<Vec<(common::CounterId, u64)>, String> {
    match send_command(Command::CountersShow {
        iface: iface.to_string(),
    }) {
        Ok(response) => match response {
            Response::CounterResult(entries) => {
                let mut result = Vec::new();
                for entry in entries {
                    let cid = counter_id_from_u32(entry.id).unwrap_or(common::CounterId::Unknown);
                    result.push((cid, entry.value));
                }
                Ok(result)
            }
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn conntrack_count(iface: &str) -> Result<usize, String> {
    match send_command(Command::ConntrackShow {
        iface: iface.to_string(),
    }) {
        Ok(response) => match response {
            Response::CountResult(count) => Ok(count),
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn rate_limit_count(iface: &str) -> Result<usize, String> {
    match send_command(Command::RateLimitShow {
        iface: iface.to_string(),
    }) {
        Ok(response) => match response {
            Response::CountResult(count) => Ok(count),
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn check_xdp_attached(iface: &str) -> Result<(bool, Option<u32>), String> {
    match send_command(Command::CheckXdpAttached {
        iface: iface.to_string(),
    }) {
        Ok(response) => match response {
            Response::AttachmentResult { attached, prog_id } => Ok((attached, prog_id)),
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

// VLAN functions
pub fn acl_vlan_list(iface: &str) -> Result<Vec<String>, String> {
    match send_command(Command::AclVlanList {
        iface: iface.to_string(),
    }) {
        Ok(response) => match response {
            Response::ListResult(lines) => Ok(lines),
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn acl_vlan_add(iface: &str, vlan_id: u16, action: &str, inner_vlan: Option<u16>, rate: Option<u32>,) -> Result<(), String> {
    match send_command(Command::AclVlanAdd {
        iface: iface.to_string(),
        vlan_id,
        action: action.to_string(),
        inner_vlan,
        rate,
    }) {
        Ok(response) => match response {
            Response::Success(msg) => {
                println!("{}", msg);
                Ok(())
            }
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn acl_vlan_del(iface: &str, id: usize) -> Result<(), String> {
    match send_command(Command::AclVlanDel {
        iface: iface.to_string(),
        id,
    }) {
        Ok(response) => match response {
            Response::Success(msg) => {
                println!("{}", msg);
                Ok(())
            }
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

// Event mask helpers
pub fn event_mask_get() -> Result<u64, String> {
    match send_command(Command::EventMaskGet) {
        Ok(response) => match response {
            Response::MaskResult(mask) => Ok(mask),
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

pub fn event_mask_set(mask: u64) -> Result<(), String> {
    match send_command(Command::EventMaskSet { mask }) {
        Ok(response) => match response {
            Response::Success(_msg) => {
                // We don't really need the message, but we can print it if we want.
                Ok(())
            }
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

// Config reload helper
pub fn config_reload(path: Option<&str>) -> Result<(), String> {
    match send_command(Command::ConfigReload {
        path: path.map(|p| p.to_string()),
    }) {
        Ok(response) => match response {
            Response::Success(_msg) => Ok(()),
            Response::Error(msg) => Err(msg),
            _ => Err("Unexpected response type".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}