use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;

// Import specific functions from manager modules
use crate::manager::attach::check_xdp_attached;
use crate::manager::backend::{
    backend_add, backend_delete, backend_flush, backend_list, is_unhealthy,
};
use crate::manager::maps::{
    acl_add, acl_del_by_index, acl_list, conntrack_count, counters, rate_limit_count, vlan_acl_add,
    vlan_acl_del_by_index, vlan_acl_list, event_mask_get, event_mask_set, reload_config,
};
use crate::manager::service::{service_add, service_delete, service_flush, service_list};

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

    // Backend commands
    BackendList {
        iface: String,
    },
    BackendAdd {
        iface: String,
        ip: String,
        port: u16,
        dev: String,
        group: Option<u32>,
    },
    BackendRm {
        iface: String,
        id: u32,
    },
    BackendFlush {
        iface: String,
    },

    // Service commands
    ServiceList {
        iface: String,
    },
    ServiceAdd {
        iface: String,
        addr: String,
        port: u16,
        proto: String,
        group: Option<u32>,
    },
    ServiceRm {
        iface: String,
        addr: String,
        port: u16,
        proto: String,
    },
    ServiceFlush {
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

/// Handle a single client connection
fn handle_client(mut stream: UnixStream) -> Result<()> {
    let mut buffer = [0; 65536];

    // Read command from client
    let n = stream.read(&mut buffer)?;
    if n == 0 {
        return Ok(());
    }

    let command_data = &buffer[..n];
    let command: Command = match serde_json::from_slice(command_data) {
        Ok(cmd) => cmd,
        Err(e) => {
            let response = Response::Error(format!("Failed to parse command: {}", e));
            let response_data = serde_json::to_vec(&response)?;
            stream.write_all(&response_data)?;
            return Ok(());
        }
    };

    // Process command and generate response
    let response = match process_command(command) {
        Ok(resp) => resp,
        Err(e) => Response::Error(e.to_string()),
    };

    // Send response back to client
    let response_data = serde_json::to_vec(&response)?;
    stream.write_all(&response_data)?;

    Ok(())
}

/// Process a command and return a response
fn process_command(command: Command) -> Result<Response> {
    match command {
        // ACL commands
        Command::AclList { .. } => {
            let entries = acl_list()?;
            let mut result = Vec::new();
            for entry in entries {
                let ip_proto_str = match entry.ip_proto {
                    6 => "tcp".to_string(),
                    17 => "udp".to_string(),
                    1 => "icmp".to_string(),
                    58 => "icmpv6".to_string(),
                    _ => entry.ip_proto.to_string(),
                };
                let src_port_str = if entry.src_port == 0 {
                    "any".to_string()
                } else {
                    entry.src_port.to_string()
                };
                let dst_port_str = if entry.dst_port == 0 {
                    "any".to_string()
                } else {
                    entry.dst_port.to_string()
                };
                let rate_str = if entry.rule.rate > 0 {
                    entry.rule.rate.to_string()
                } else {
                    "-".to_string()
                };
                result.push(format!(
                    "{:>3} {:<5} {:<4} {:<34} {:<34} {:<4} {:<6} {:<6} {:<5} {}",
                    entry.id,
                    entry.prefix_len,
                    entry.family,
                    format_ip(&entry.src_addr, entry.family),
                    format_ip(&entry.dst_addr, entry.family),
                    ip_proto_str,
                    src_port_str,
                    dst_port_str,
                    rate_str,
                    entry.action
                ));
            }
            Ok(Response::ListResult(result))
        }
        Command::AclAdd {
            action,
            src,
            dst,
            proto,
            rate,
            ..
        } => {
            let proto_opt = proto.as_deref();
            acl_add(&action, &src, &dst, proto_opt, rate).context("Failed to add ACL rule")?;
            Ok(Response::Success("ACL rule added".to_string()))
        }
        Command::AclDel { id, .. } => {
            acl_del_by_index(id).context("Failed to delete ACL rule")?;
            Ok(Response::Success(format!("Deleted ACL rule {}", id)))
        }
        Command::AclVlanList { .. } => {
            let entries = vlan_acl_list()?;
            let mut result = Vec::new();
            for entry in entries {
                let inner_vlan_display = if entry.inner_vlan == 0 {
                    "-".to_string()
                } else {
                    entry.inner_vlan.to_string()
                };
                let action_display = match entry.action.as_str() {
                    "Allow" => "allow".to_string(),
                    "Drop" => "drop".to_string(),
                    "Redirect" => "redirect".to_string(),
                    "Inspect" => "inspect".to_string(),
                    _ => entry.action.to_lowercase(),
                };
                result.push(format!(
                    "{:<5} {:<10} {:<10} {:<8} {:<6}",
                    entry.id, entry.outer_vlan, inner_vlan_display, action_display, entry.rate
                ));
            }
            Ok(Response::ListResult(result))
        }
        Command::AclVlanAdd {
            vlan_id,
            action,
            inner_vlan,
            rate,
            ..
        } => {
            vlan_acl_add(vlan_id, inner_vlan, &action, rate.map(|r| r as u32))
                .context("Failed to add VLAN rule")?;
            Ok(Response::Success(format!(
                "Added VLAN rule: outer_vlan={}",
                vlan_id
            )))
        }
        Command::AclVlanDel { id, .. } => {
            vlan_acl_del_by_index(id).context("Failed to delete VLAN rule")?;
            Ok(Response::Success(format!("Deleted VLAN rule {}", id)))
        }
        // Monitoring commands
        Command::CountersShow { .. } => {
            let counters = counters()?;
            let mut result = Vec::new();
            for (cid, val) in counters {
                result.push(CounterData {
                    id: cid as u32,
                    name: counter_name(cid).to_string(),
                    value: val,
                });
            }
            Ok(Response::CounterResult(result))
        }
        Command::ConntrackShow { .. } => {
            let count = conntrack_count()?;
            Ok(Response::CountResult(count))
        }
        Command::RateLimitShow { .. } => {
            let count = rate_limit_count()?;
            Ok(Response::CountResult(count))
        }
        // Backend commands
        Command::BackendList { .. } => {
            let entries = backend_list()?;
            let mut result = Vec::new();
            for entry in entries {
                let ip = format_mapped(&entry.backend.addr);
                let dev = entry.dev_name.as_deref().unwrap_or("?");
                let flags = if is_unhealthy(&entry.backend) {
                    "unhealthy"
                } else {
                    "ok"
                };
                result.push(format!(
                    "{:<4} {:<18} {:<6} {:<8} {:<6} {}",
                    entry.id, ip, entry.backend.port, dev, entry.backend.backend_group, flags
                ));
            }
            Ok(Response::ListResult(result))
        }
        Command::BackendAdd {
            ip,
            port,
            dev,
            group,
            ..
        } => {
            use crate::manager::acl_key::Ipv4;
            use crate::manager::backend::BackendSpec;
            let ipv4 = Ipv4::parse(&ip).map_err(|e| anyhow::anyhow!("Invalid IP '{ip}': {e}"))?;
            let spec = BackendSpec {
                ip: ipv4,
                port,
                dev,
                group: group.unwrap_or(0),
            };
            let id = backend_add(&spec).context("Failed to add backend")?;
            Ok(Response::Success(format!("Added backend id={}", id)))
        }
        Command::BackendRm { id, .. } => {
            backend_delete(id).context("Failed to delete backend")?;
            Ok(Response::Success(format!("Deleted backend {}", id)))
        }
        Command::BackendFlush { .. } => {
            let count = backend_flush()?;
            Ok(Response::Success(format!("Flushed {} backends", count)))
        }
        // Service commands
        Command::ServiceList { .. } => {
            let entries = service_list()?;
            let mut result = Vec::new();
            for entry in entries {
                result.push(format!(
                    "{:<18} {:<6} {:<6} {:<6} {}",
                    format_mapped(&entry.addr),
                    entry.port,
                    if entry.proto == 6 { "tcp" } else { "udp" },
                    entry.backend_group,
                    entry.flags
                ));
            }
            Ok(Response::ListResult(result))
        }
        Command::ServiceAdd {
            addr,
            port,
            proto,
            group,
            ..
        } => {
            use crate::manager::acl_key::Ipv4;
            use crate::manager::service::ServiceSpec;
            let ipv4 =
                Ipv4::parse(&addr).map_err(|e| anyhow::anyhow!("Invalid address '{addr}': {e}"))?;
            let proto_num = if proto == "tcp" { 6u8 } else { 17u8 };
            let spec = ServiceSpec {
                addr: ipv4,
                port,
                proto: proto_num,
                group: group.unwrap_or(0),
            };
            service_add(&spec).context("Failed to add service")?;
            Ok(Response::Success(format!(
                "Added service {}:{} proto={}",
                addr, port, proto
            )))
        }
        Command::ServiceRm {
            addr, port, proto, ..
        } => {
            use crate::manager::acl_key::Ipv4;
            use crate::manager::service::ServiceSpec;
            let ipv4 =
                Ipv4::parse(&addr).map_err(|e| anyhow::anyhow!("Invalid address '{addr}': {e}"))?;
            let proto_num = if proto == "tcp" { 6u8 } else { 17u8 };
            let spec = ServiceSpec {
                addr: ipv4,
                port,
                proto: proto_num,
                group: 0,
            };
            service_delete(&spec).context("Failed to delete service")?;
            Ok(Response::Success(format!(
                "Removed service {}:{} proto={}",
                addr, port, proto
            )))
        }
        Command::ServiceFlush { .. } => {
            let count = service_flush()?;
            Ok(Response::Success(format!("Flushed {} services", count)))
        }
        // Event mask commands
        Command::EventMaskGet => {
            let mask = event_mask_get()?;
            Ok(Response::MaskResult(mask))
        }
        Command::EventMaskSet { mask } => {
            event_mask_set(mask)?;
            Ok(Response::Success("Event mask set".to_string()))
        }
        // Config reload command
        Command::ConfigReload { path } => {
            let path = path.unwrap_or_else(|| "config2.yml".to_string());
            match reload_config(&path) {
                Ok(()) => Ok(Response::Success("Configuration reloaded".to_string())),
                Err(e) => Err(e.into()),
            }
        }
        // XDP attachment check
        Command::CheckXdpAttached { iface } => {
            let info = check_xdp_attached(&iface)?;
            tracing::debug!("check_xdp_attached raw: {}", info.raw);
            Ok(Response::AttachmentResult {
                attached: info.attached,
                prog_id: info.prog_id,
            })
        }
    }
}

/// Helper function to format an IP address
fn format_ip(addr: &[u8; 16], family: u8) -> String {
    if family == 4 {
        format!("{}.{}.{}.{}", addr[12], addr[13], addr[14], addr[15])
    } else {
        let mut parts: Vec<String> = Vec::new();
        for i in (0..16).step_by(2) {
            let val = u16::from_be_bytes([addr[i], addr[i + 1]]);
            parts.push(format!("{:x}", val));
        }
        parts.join(":")
    }
}

/// Helper function to format an IPv4 address (mapped)
fn format_mapped(mapped: &[u8; 16]) -> String {
    format!(
        "{}.{}.{}.{}",
        mapped[12], mapped[13], mapped[14], mapped[15]
    )
}

/// Helper function to get counter name
fn counter_name(c: common::CounterId) -> &'static str {
    use common::CounterId::*;
    match c {
        RxPackets => "RxPackets",
        RxBytes => "RxBytes",
        Passed => "Passed",
        Dropped => "Dropped",
        Redirected => "Redirected",
        ConntrackHit => "ConntrackHit",
        ConntrackMiss => "ConntrackMiss",
        AclDrop => "AclDrop",
        AclAllow => "AclAllow",
        AclRedirect => "AclRedirect",
        RateLimited => "RateLimited",
        ParseError => "ParseError",
        TcFragment => "TcFragment",
        SlowPath => "SlowPath",
        HostFound => "HostFound",
        RxIpv4 => "RxIpv4",
        RxIpv6 => "RxIpv6",
        RxIcmpv6 => "RxIcmpv6",
        RxTcp => "RxTcp",
        RxUdp => "RxUdp",
        RxVlan => "RxVlan",
        Unknown => "Unknown",
        BackendUnavailable => "BackendUnavailable",
        RedirectFailed => "RedirectFailed",
        BackendSelected => "BackendSelected",
        ServiceMiss => "ServiceMiss",
        ServiceHit => "ServiceHit",
    }
}

/// Start the Unix socket server, using a closure for the running condition.
pub fn start_socket_server_with_shutdown<F: Fn() -> bool + Send + 'static>(
    socket_path: &str,
    is_running: F,
) -> Result<()> {
    use std::os::unix::net::UnixListener;

    // Clean up stale socket
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind socket at {socket_path}"))?;

    listener.set_nonblocking(true)
        .context("Failed to set non-blocking mode")?;

    while is_running() {
        match listener.accept() {
            Ok((stream, _)) => {
                thread::spawn(move || {
                    let _ = handle_client(stream);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => {
                tracing::warn!("Socket accept error: {}", e);
                break;
            }
        }
    }

    let _ = std::fs::remove_file(socket_path);
    Ok(())
}
