//! `ebpf-ctl` — utility for managing `ebpf-xdp` maps.
//!
//! Subcommands:
//!   check-attach --iface <dev>
//!   acl list
//!   acl add <allow|drop> src <ip>:<port|any> dst <ip>:<port|any> [proto tcp|udp|icmp] [rate <pps>] [--print-key]
//!   acl del --id <n>
//!   acl vlan list
//!   acl vlan add <vlan-id> <allow|drop> [inner <inner-vlan-id>] [rate <pps>]
//!   acl vlan del --id <n>
//!   counters show
//!   conntrack show
//!   rate-limit show
//!   event-log list
//!   event-log enable <kind>
//!   event-log disable <kind>
//!   event-log reset
//!   event-log <kind>   # shorthand for enable
//!   test <config>      # validate configuration file (default: config2.yml)
//!   reload [<config>]  # reload configuration in daemon (default: config2.yml)
//!
//! L4 ACL key format (family=4, ::ffff:-addresses, auto-prefix_len)
//! is generated automatically — manual hex is NOT needed. See acl_key.rs
//! and L4_ACL_NOTES.md.
//!
//! CIDR notation is supported for src and dst (e.g., 192.168.0.0/24).
//! Default is /32 (full IP address).
//!

mod acl_key;
mod client;

use std::process::exit;

use acl_key::{AclRule, PortSpec, Proto};
use common::AclAction;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        print_usage();
        return Ok(0);
    }

    match args[0].as_str() {
        "check-attach" => check_attach_cmd(&args[1..]),
        "acl" => acl_cmd(&args[1..]),
        "counters" => counters_cmd(&args[1..]),
        "conntrack" => conntrack_cmd(&args[1..]),
        "rate-limit" => rate_limit_cmd(&args[1..]),
        "event-log" => event_log_cmd(&args[1..]),
        "test" => test_cmd(&args[1..]),
        "reload" => reload_cmd(&args[1..]),
        other => {
            eprintln!("unknown command: '{other}'");
            print_usage();
            Ok(1)
        }
    }
}

fn print_usage() {
    println!(
        "Usage:
   ebpf-ctl check-attach --iface <dev>
   ebpf-ctl acl list
  ebpf-ctl acl add <allow|drop> src <ip>:<port|any> dst <ip>:<port|any> [proto tcp|udp|icmp] [rate <pps>] [--print-key]
  ebpf-ctl acl del --id <n>
  ebpf-ctl acl vlan list
  ebpf-ctl acl vlan add <vlan-id> <allow|drop> [inner <inner-vlan-id>] [rate <pps>]
  ebpf-ctl acl vlan del --id <n>
  ebpf-ctl counters show
  ebpf-ctl conntrack show
  ebpf-ctl rate-limit show
  ebpf-ctl event-log list
  ebpf-ctl event-log enable <kind>
  ebpf-ctl event-log disable <kind>
  ebpf-ctl event-log reset
  ebpf-ctl event-log <kind>   # shorthand for enable
  ebpf-ctl test [<config>]   # validate configuration file (default: config2.yml)
  ebpf-ctl reload [<config>] # reload configuration in daemon (default: config2.yml)
"
    );
}

// ----------------------------------------------------------------------------
// Utility helpers
// ----------------------------------------------------------------------------

/// Extract an option value from args. e.g. get_opt(&["--iface", "-i"], args)
/// Removes the option and its value from the args list.
/// Returns None if the option is not present.
fn get_opt<'a>(opts: &[&str], args: &'a [String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if opts.iter().any(|o| o == arg) {
            if i + 1 < args.len() {
                return Some(args[i + 1].clone());
            }
        }
    }
    None
}

/// Remove option and its value from args, returning remaining positional args.
fn strip_opt(opts: &[&str], args: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let mut skip_next = false;
    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if opts.iter().any(|o| o == arg) {
            skip_next = true; // skip the value too
            continue;
        }
        result.push(arg.clone());
    }
    result
}

fn fmt_acl_addr(addr: &acl_key::AclAddr) -> String {
    match addr {
        acl_key::AclAddr::V4(v4) => {
            let octets = v4.addr();
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
        }
        acl_key::AclAddr::V6(v6) => {
            let bytes = v6.addr();
            let mut parts: Vec<String> = Vec::new();
            for i in (0..16).step_by(2) {
                let val = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
                parts.push(format!("{:x}", val));
            }
            parts.join(":")
        }
    }
}

/// Returns the last byte of the IPv4-mapped form for debug output.
fn src_ip_to_mapped_hex(addr: &acl_key::AclAddr) -> u8 {
    match addr {
        acl_key::AclAddr::V4(v4) => v4.to_mapped()[15],
        acl_key::AclAddr::V6(_) => 0,
    }
}

fn port_name(port: u16) -> String {
    if port == 0 {
        "any".to_string()
    } else {
        port.to_string()
    }
}

fn proto_name(proto: Proto) -> &'static str {
    proto.name()
}

/// Parse endpoint like "192.168.0.1:80" or "0.0.0.0/0:any"
fn parse_endpoint(s: &str, name: &str, proto: Proto) -> Result<(acl_key::AclAddr, u16), String> {
    // Handle "any" or empty
    if s.eq_ignore_ascii_case("any") || s.eq_ignore_ascii_case("*") {
        if matches!(proto, Proto::Icmp | Proto::Icmpv6) {
            // ICMP doesn't have ports - return port 0
            let addr = acl_key::parse_acl_addr("0.0.0.0/0")?;
            return Ok((addr, 0));
        }
        let addr = acl_key::parse_acl_addr("0.0.0.0/0")?;
        return Ok((addr, 0));
    }

    // Split into addr and port parts
    let (addr_str, port_str) = match s.rfind(':') {
        Some(pos) => {
            // Check if this is an IPv6 address (multiple colons) or bracketed
            let colons = s.chars().filter(|&c| c == ':').count();
            if colons > 1 || s.starts_with('[') {
                // IPv6 address with port: e.g. "[::1]:80" or "2001:db8::1:80"
                if pos == 0 {
                    return Err(format!("invalid {name}: '{s}'"));
                }
                (&s[..pos], &s[pos + 1..])
            } else {
                // Single colon: split addr:port (IPv4:port or addr:any)
                (&s[..pos], &s[pos + 1..])
            }
        }
        None => (s, ""),
    };

    let addr = acl_key::parse_acl_addr(addr_str)?;

    // ICMP doesn't have ports
    let is_icmp = matches!(proto, Proto::Icmp | Proto::Icmpv6);
    if is_icmp {
        return Ok((addr, 0));
    }

    let port = PortSpec::parse(port_str)
        .map_err(|e| format!("invalid port in {name}: {e}"))?;

    match port {
        PortSpec::Exact(p) => Ok((addr, p)),
        PortSpec::Any => Ok((addr, 0)),
    }
}

// ----------------------------------------------------------------------------
// acl
// ----------------------------------------------------------------------------

fn acl_cmd(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err("usage: ebpf-ctl acl <list|add|del|vlan> ...".into());
    }
    match args[0].as_str() {
        "list" => acl_list(&args[1..]),
        "add" => acl_add(&args[1..]),
        "del" => acl_del(&args[1..]),
        "vlan" => acl_vlan_cmd(&args[1..]),
        other => Err(format!("unknown acl subcommand: '{other}'")),
    }
}

fn check_attach_cmd(args: &[String]) -> Result<i32, String> {
    let iface = get_opt(&["--iface", "-i"], args)
        .ok_or_else(|| "--iface <dev> required (e.g., end0)".to_string())?;

    let result = client::socket::check_xdp_attached(&iface)
        .map_err(|e| format!("Failed to check XDP attachment: {}", e))?;

    if result.0 {
        println!("OK: XDP attached to '{iface}' (prog id {:?})", result.1);
        Ok(0)
    } else {
        eprintln!(
            "WARNING: XDP not detected on interface '{iface}'.
             Check that the program is loaded, for example:

                   sudo ip link set dev {iface} xdp obj \\

                     target/bpfel-unknown-none/release/libebpf_xdp.so sec xdp verbose"
        );
        Ok(2)
    }
}

fn acl_list(args: &[String]) -> Result<i32, String> {
    let iface = get_opt(&["--iface", "-i"], args)
        .unwrap_or_else(|| "end0".to_string());

    let entries =
        client::socket::acl_list(&iface).map_err(|e| format!("Failed to get ACL list: {}", e))?;

    if entries.is_empty() {
        println!("(l4_acl map is empty)");
        return Ok(0);
    }

    println!(
        "{:<3} {:<5} {:<4} {:<34} {:<34} {:<4} {:<6} {:<6} {:<5} {}",
        "id", "plen", "fam", "src", "dst", "proto", "sport", "dport", "rate", "action"
    );
    for e in entries.iter() {
        println!(
            "{:<3} {:<5} {:<4} {:<34} {:<34} {:<4} {:<6} {:<6} {:<5} {}",
            e.id,
            e.prefix_len,
            e.family,
            fmt_acl_addr(&e.rule.src),
            fmt_acl_addr(&e.rule.dst),
            match e.ip_proto {
                6 => "tcp",
                17 => "udp",
                1 => "icmp",
                58 => "icmpv6",
                _ => "unknown",
            },
            if e.src_port == 0 {
                "any".to_string()
            } else {
                e.src_port.to_string()
            },
            if e.dst_port == 0 {
                "any".to_string()
            } else {
                e.dst_port.to_string()
            },
            if e.rule.rate > 0 {
                e.rule.rate.to_string()
            } else {
                "-".to_string()
            },
            e.action
        );
    }
    Ok(0)
}

fn acl_add(args: &[String]) -> Result<i32, String> {
    let iface = get_opt(&["--iface", "-i"], args)
        .unwrap_or_else(|| "end0".to_string());

    // First positional argument is action (allow | drop).
    let positional = strip_opt(&["--iface", "-i", "--proto", "-p", "proto", "src", "dst", "rate"], args);

    if positional.is_empty() {
        return Err("'allow' or 'drop' action required".into());
    }
    let action = match positional[0].as_str() {
        "drop" => AclAction::Drop,
        "allow" => AclAction::Allow,
        other => return Err(format!("unknown action: '{other}' (expected allow|drop)")),
    };

    let src = get_opt(&["src"], args).ok_or_else(|| "src <ip>:<port|any> required".to_string())?;
    let dst = get_opt(&["dst"], args).ok_or_else(|| "dst <ip>:<port|any> required".to_string())?;
    let proto = match get_opt(&["--proto", "-p", "proto"], args).as_deref() {
        Some(p) => Proto::parse(p)?,
        None => Proto::Tcp,
    };

    let (src_ip, src_port) = parse_endpoint(&src, "src", proto)?;
    let (dst_ip, dst_port) = parse_endpoint(&dst, "dst", proto)?;

    let proto = if matches!(proto, Proto::Icmp) {
        match (src_ip.family(), dst_ip.family()) {
            (10, 10) => Proto::Icmpv6,
            (4, 4) => Proto::Icmp,
            _ => Proto::Icmp,
        }
    } else {
        proto
    };

    let rule = AclRule {
        action,
        src: src_ip,
        dst: dst_ip,
        proto,
        sport: if src_port == 0 { acl_key::PortSpec::Any } else { acl_key::PortSpec::Exact(src_port) },
        dport: if dst_port == 0 { acl_key::PortSpec::Any } else { acl_key::PortSpec::Exact(dst_port) },
        tcp_flags: 0,
        rate: get_opt(&["rate"], args)
            .and_then(|r| r.parse().ok())
            .unwrap_or(0),
    };

    let print_key = args.iter().any(|a| a == "--print-key" || a == "-n");
    if print_key {
        let key_hex = acl_key::key_to_hex(&rule.build_key());
        let val_hex = acl_key::key_to_hex(&rule.build_value());
        println!("key   : {key_hex}");
        println!("value : {val_hex}");
        println!(
            "(action={:?}, prefix_len={}, family={}, key_len={}, src_mapped={:02x})",
            action,
            rule.prefix_len(),
            rule.src.family(),
            rule.build_key().len(),
            src_ip_to_mapped_hex(&rule.src)
        );
        return Ok(0);
    }

    client::socket::acl_add(
        &iface,
        match action {
            AclAction::Allow => "allow",
            AclAction::Drop => "drop",
            AclAction::Redirect => "redirect",
            AclAction::Inspect => "inspect",
        },
        &src,
        &dst,
        Some(proto.name()),
        if rule.rate > 0 { Some(rule.rate) } else { None },
    )
    .map_err(|e| format!("Failed to add rule: {}", e))?;

    let rate_info = if rule.rate > 0 {
        format!(" rate={}", rule.rate)
    } else {
        String::new()
    };
    println!(
        "added rule {:?}: {} {}:{} -> {}:{} (prefix_len={}{})",
        action,
        proto_name(proto),
        fmt_acl_addr(&src_ip),
        port_name(src_port),
        fmt_acl_addr(&dst_ip),
        port_name(dst_port),
        rule.prefix_len(),
        rate_info
    );
    Ok(0)
}

fn acl_del(args: &[String]) -> Result<i32, String> {
    let iface = get_opt(&["--iface", "-i"], args)
        .unwrap_or_else(|| "end0".to_string());

    let id_str =
        get_opt(&["--id"], args).ok_or_else(|| "--id <n> required (see 'acl list')".to_string())?;
    let id: usize = id_str
        .parse()
        .map_err(|_| format!("invalid --id: '{id_str}'"))?;

    client::socket::acl_del(&iface, id).map_err(|e| format!("Failed to delete rule: {}", e))?;

    println!("deleted rule id={id}");
    Ok(0)
}

fn acl_vlan_cmd(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err("usage: ebpf-ctl acl vlan <list|add|del> ...".into());
    }
    match args[0].as_str() {
        "list" => acl_vlan_list(&args[1..]),
        "add" => acl_vlan_add(&args[1..]),
        "del" => acl_vlan_del(&args[1..]),
        other => Err(format!("unknown acl vlan subcommand: '{other}'")),
    }
}

fn acl_vlan_list(args: &[String]) -> Result<i32, String> {
    let iface = get_opt(&["--iface", "-i"], args)
        .unwrap_or_else(|| "end0".to_string());

    let lines =
        client::socket::acl_vlan_list(&iface).map_err(|e| format!("Failed to get VLAN list: {}", e))?;

    if lines.is_empty() {
        println!("(vlan_acl map is empty)");
        return Ok(0);
    }

    println!(
        "{:<5} {:<10} {:<10} {:<8} {:<6}",
        "id", "outer_vlan", "inner_vlan", "action", "rate"
    );
    for line in lines {
        println!("{}", line);
    }
    Ok(0)
}

fn acl_vlan_add(args: &[String]) -> Result<i32, String> {
    let iface = get_opt(&["--iface", "-i"], args)
        .unwrap_or_else(|| "end0".to_string());

    // positional args: <vlan-id> <allow|drop> [inner <inner-vlan-id>] [rate <pps>]
    let positional = strip_opt(&["--iface", "-i", "inner", "rate"], args);

    if positional.len() < 2 {
        return Err("usage: ebpf-ctl acl vlan add <vlan-id> <allow|drop> [inner <inner-vlan-id>] [rate <pps>]".into());
    }

    let vlan_id: u16 = positional[0]
        .parse()
        .map_err(|_| format!("invalid vlan-id: '{}'", positional[0]))?;

    let action = match positional[1].as_str() {
        "allow" => "allow",
        "drop" => "drop",
        other => return Err(format!("unknown action: '{other}' (expected allow|drop)")),
    };

    let inner_vlan = get_opt(&["inner"], args).and_then(|v| v.parse::<u16>().ok());
    let rate = get_opt(&["rate"], args).and_then(|r| r.parse::<u32>().ok());

    client::socket::acl_vlan_add(&iface, vlan_id, action, inner_vlan, rate)
        .map_err(|e| format!("Failed to add VLAN rule: {}", e))?;

    let inner_str = if let Some(iv) = inner_vlan {
        format!(" inner={iv}")
    } else {
        String::new()
    };
    let rate_str = if let Some(r) = rate {
        format!(" rate={r}")
    } else {
        String::new()
    };

    println!("added vlan rule (outer={vlan_id}{inner_str}{rate_str}): {action}");
    Ok(0)
}

fn acl_vlan_del(args: &[String]) -> Result<i32, String> {
    let iface = get_opt(&["--iface", "-i"], args)
        .unwrap_or_else(|| "end0".to_string());

    let id_str =
        get_opt(&["--id"], args).ok_or_else(|| "--id <n> required (see 'acl vlan list')".to_string())?;

    let id: usize = id_str
        .parse()
        .map_err(|_| format!("invalid --id: '{id_str}'"))?;

    client::socket::acl_vlan_del(&iface, id)
        .map_err(|e| format!("Failed to delete VLAN rule: {}", e))?;

    println!("deleted vlan rule id={id}");
    Ok(0)
}

// ----------------------------------------------------------------------------
// counters
// ----------------------------------------------------------------------------

fn counters_cmd(args: &[String]) -> Result<i32, String> {
    if args.is_empty() || args[0] != "show" {
        return Err("usage: ebpf-ctl counters show [--iface <dev>]".into());
    }

    let iface = get_opt(&["--iface", "-i"], &args[1..])
        .unwrap_or_else(|| "end0".to_string());

    let counters = client::socket::counters(&iface)
        .map_err(|e| format!("Failed to get counters: {}", e))?;

    if counters.is_empty() {
        println!("(no counters)");
        return Ok(0);
    }

    println!("{:<20} {:<20}", "counter", "value");
    for (id, value) in counters {
        let name = counter_name(id);
        println!("{:<20} {:<20}", name, value);
    }
    Ok(0)
}

    pub(crate) fn counter_name(id: common::CounterId) -> &'static str {
    match id {
        common::CounterId::RxPackets => "rx_packets",
        common::CounterId::RxBytes => "rx_bytes",
        common::CounterId::Passed => "passed",
        common::CounterId::Dropped => "dropped",
        common::CounterId::Redirected => "redirected",
        common::CounterId::ConntrackHit => "conntrack_hit",
        common::CounterId::ConntrackMiss => "conntrack_miss",
        common::CounterId::AclDrop => "acl_drop",
        common::CounterId::AclAllow => "acl_allow",
        common::CounterId::AclRedirect => "acl_redirect",
        common::CounterId::RateLimited => "rate_limited",
        common::CounterId::ParseError => "parse_error",
        common::CounterId::TcFragment => "tc_fragment",
        common::CounterId::SlowPath => "slow_path",
        common::CounterId::HostFound => "host_found",
        common::CounterId::RxIpv4 => "rx_ipv4",
        common::CounterId::RxIpv6 => "rx_ipv6",
        common::CounterId::RxIcmpv6 => "rx_icmpv6",
        common::CounterId::RxTcp => "rx_tcp",
        common::CounterId::RxUdp => "rx_udp",
        common::CounterId::Unknown => "unknown",
        common::CounterId::BackendUnavailable => "backend_unavailable",
        common::CounterId::RedirectFailed => "redirect_failed",
        common::CounterId::BackendSelected => "backend_selected",
        common::CounterId::ServiceMiss => "service_miss",
        common::CounterId::ServiceHit => "service_hit",
        common::CounterId::RxVlan => "rx_vlan",
    }
}

// ----------------------------------------------------------------------------
// conntrack
// ----------------------------------------------------------------------------

fn conntrack_cmd(args: &[String]) -> Result<i32, String> {
    if args.is_empty() || args[0] != "show" {
        return Err("usage: ebpf-ctl conntrack show [--iface <dev>]".into());
    }

    let iface = get_opt(&["--iface", "-i"], &args[1..])
        .unwrap_or_else(|| "end0".to_string());

    let count = client::socket::conntrack_count(&iface)
        .map_err(|e| format!("Failed to get conntrack info: {}", e))?;

    println!("conntrack entries: {count}");
    Ok(0)
}

// ----------------------------------------------------------------------------
// rate-limit
// ----------------------------------------------------------------------------

fn rate_limit_cmd(args: &[String]) -> Result<i32, String> {
    if args.is_empty() || args[0] != "show" {
        return Err("usage: ebpf-ctl rate-limit show [--iface <dev>]".into());
    }

    let iface = get_opt(&["--iface", "-i"], &args[1..])
        .unwrap_or_else(|| "end0".to_string());

    let count = client::socket::rate_limit_count(&iface)
        .map_err(|e| format!("Failed to get rate-limit info: {}", e))?;

    println!("rate-limit entries: {count}");
    Ok(0)
}

// ----------------------------------------------------------------------------
// event-log
// ----------------------------------------------------------------------------

fn event_log_cmd(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err("usage: ebpf-ctl event-log <list|enable|disable|reset> [<kind>]".into());
    }

    match args[0].as_str() {
        "list" => event_log_list(),
        "reset" => event_log_reset(),
        "enable" => {
            if args.len() < 2 {
                return Err("usage: ebpf-ctl event-log enable <kind>".into());
            }
            event_log_set(&args[1..], true)
        }
        "disable" => {
            if args.len() < 2 {
                return Err("usage: ebpf-ctl event-log disable <kind>".into());
            }
            event_log_set(&args[1..], false)
        }
        _kind => {
            // Shorthand: "event-log <kind>" => enable
            // Re-parse since we took a slice of the original args
            let (parsed_kind, name) = parse_event_kind(&args[0])?;
            let bit = 1u64 << parsed_kind as u64;
            let current_mask = client::socket::event_mask_get()
                .map_err(|e| format!("Failed to get event mask: {}", e))?;
            let new_mask = current_mask | bit;
            client::socket::event_mask_set(new_mask)
                .map_err(|e| format!("Failed to set event mask: {}", e))?;
            println!("enabled event-log: {name}");
            Ok(0)
        }
    }
}

fn event_log_list() -> Result<i32, String> {
    let mask = client::socket::event_mask_get()
        .map_err(|e| format!("Failed to get event mask: {}", e))?;

    println!("event-log mask: {mask:#x}");
    println!("enabled events:");
    for (kind, name) in event_kinds() {
        if mask & (1u64 << kind as u64) != 0 {
            println!("  [x] {name}");
        } else {
            println!("  [ ] {name}");
        }
    }
    Ok(0)
}

fn event_log_reset() -> Result<i32, String> {
    client::socket::config_reload(None)
        .map_err(|e| format!("Failed to reset events: {}", e))?;
    println!("events reset");
    Ok(0)
}

fn event_log_set(args: &[String], enable: bool) -> Result<i32, String> {
    let kind_str = &args[0];
    let (kind, name) = parse_event_kind(kind_str)?;

    let current_mask = client::socket::event_mask_get()
        .map_err(|e| format!("Failed to get event mask: {}", e))?;

    let bit = 1u64 << kind as u64;
    let new_mask = if enable {
        current_mask | bit
    } else {
        current_mask & !bit
    };

    client::socket::event_mask_set(new_mask)
        .map_err(|e| format!("Failed to set event mask: {}", e))?;

    if enable {
        println!("enabled event-log: {name}");
    } else {
        println!("disabled event-log: {name}");
    }
    Ok(0)
}

fn parse_event_kind(s: &str) -> Result<(common::EventKind, &'static str), String> {
    match s.to_lowercase().as_str() {
        "packetdrop" | "packet-drop" | "drop" => Ok((common::EventKind::PacketDrop, "PacketDrop")),
        "ratelimited" | "rate-limited" => Ok((common::EventKind::RateLimited, "RateLimited")),
        "conntrackmiss" | "conntrack-miss" => Ok((common::EventKind::ConntrackMiss, "ConntrackMiss")),
        "backendselected" | "backend-selected" => Ok((common::EventKind::BackendSelected, "BackendSelected")),
        "slowpath" | "slow-path" => Ok((common::EventKind::SlowPath, "SlowPath")),
        "servicematched" | "service-matched" => Ok((common::EventKind::ServiceMatched, "ServiceMatched")),
        "vlandetected" | "vlan-detected" => Ok((common::EventKind::VlanDetected, "VlanDetected")),
        "packetallow" | "packet-allow" => Ok((common::EventKind::PacketAllow, "PacketAllow")),
        _ => Err(format!("unknown event kind: '{s}'\nAvailable: PacketDrop, RateLimited, ConntrackMiss, BackendSelected, SlowPath, ServiceMatched, VlanDetected, PacketAllow\n(shorthand forms supported: packet-drop, rate-limited, conntrack-miss, etc.)")),
    }
}

fn event_kinds() -> Vec<(common::EventKind, &'static str)> {
    vec![
        (common::EventKind::PacketDrop, "PacketDrop"),
        (common::EventKind::RateLimited, "RateLimited"),
        (common::EventKind::ConntrackMiss, "ConntrackMiss"),
        (common::EventKind::BackendSelected, "BackendSelected"),
        (common::EventKind::SlowPath, "SlowPath"),
        (common::EventKind::ServiceMatched, "ServiceMatched"),
        (common::EventKind::VlanDetected, "VlanDetected"),
        (common::EventKind::PacketAllow, "PacketAllow"),
    ]
}

// ----------------------------------------------------------------------------
// test
// ----------------------------------------------------------------------------

fn test_cmd(args: &[String]) -> Result<i32, String> {
    let config_path = if args.is_empty() {
        "config2.yml".to_string()
    } else {
        args[0].clone()
    };

    let contents = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config '{config_path}': {e}"))?;

    println!("Validating config: {config_path}");

    // Try parsing as YAML
    let yaml_value: serde_yaml::Value = match serde_yaml::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            println!("YAML parse error: {e}");
            return Ok(1);
        }
    };

    // Validate top-level structure
    let mapping = yaml_value.as_mapping().ok_or_else(|| {
        "config root must be a mapping".to_string()
    })?;

    let required_sections = ["acl", "logging", "rate_limit", "monitoring"];
    for section in &required_sections {
        if !mapping.contains_key(&serde_yaml::Value::String(section.to_string())) {
            println!("Missing required section: {section}");
            return Ok(1);
        }
    }

    // Validate ACL structure
    let acl = mapping
        .get("acl")
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| "acl section must be a mapping".to_string())?;

    for rule_list_key in &["allow", "drop"] {
        let rules = acl
            .get(*rule_list_key)
            .and_then(|v| v.as_sequence())
            .ok_or_else(|| format!("acl.{rule_list_key} must be a sequence"))?;

        for (i, rule) in rules.iter().enumerate() {
            let rule_map = rule.as_mapping().ok_or_else(|| {
                format!("acl.{rule_list_key}[{i}] must be a mapping")
            })?;

            // Check for vlan
            if let Some(vlan) = rule_map.get("vlan") {
                if !vlan.is_sequence() {
                    return Err(format!("acl.{rule_list_key}[{i}].vlan must be a sequence"));
                }
            }

            // Check src/dst addr blocks
            for dir in &["src", "dst"] {
                if let Some(addr) = rule_map.get(*dir) {
                    let addr_map = addr.as_mapping().ok_or_else(|| {
                        format!("acl.{rule_list_key}[{i}].{dir} must be a mapping")
                    })?;

                    if let Some(addrs) = addr_map.get("addresses") {
                        if !addrs.is_sequence() && !addrs.is_string() && !addrs.is_number() {
                            return Err(format!("acl.{rule_list_key}[{i}].{dir}.addresses must be a sequence"));
                        }
                        let seq = match addrs.as_sequence() {
                            Some(s) => s.clone().into_iter().collect::<Vec<_>>(),
                            None => vec![addrs.clone()],
                        };
                        for addr_elem in &seq {
                            match addr_elem {
                                serde_yaml::Value::String(_) | serde_yaml::Value::Number(_) => {}
                                serde_yaml::Value::Sequence(inner) if inner.len() == 1 => {
                                    let inner_elem = &inner[0];
                                    if !inner_elem.is_string() && !inner_elem.is_number() {
                                        return Err(format!("acl.{rule_list_key}[{i}].{dir}.addresses contains invalid nested element"));
                                    }
                                }
                                _ => {
                                    return Err(format!("acl.{rule_list_key}[{i}].{dir}.addresses must contain strings or single-element sequences"));
                                }
                            }
                        }
                    }
                    if let Some(proto_addrs) = addr_map.get("ipv4") {
                        let pm = proto_addrs.as_mapping().ok_or_else(|| {
                            format!("acl.{rule_list_key}[{i}].{dir}.ipv4 must be a mapping")
                        })?;
                        if pm.get("addresses").map_or(true, |v| !v.is_sequence()) {
                            return Err(format!("acl.{rule_list_key}[{i}].{dir}.ipv4.addresses must be a sequence"));
                        }
                    }
                    if let Some(proto_addrs) = addr_map.get("ipv6") {
                        let pm = proto_addrs.as_mapping().ok_or_else(|| {
                            format!("acl.{rule_list_key}[{i}].{dir}.ipv6 must be a mapping")
                        })?;
                        if pm.get("addresses").map_or(true, |v| !v.is_sequence()) {
                            return Err(format!("acl.{rule_list_key}[{i}].{dir}.ipv6.addresses must be a sequence"));
                        }
                    }
                    if let Some(ports) = addr_map.get("ports") {
                        let ports_map = ports.as_mapping().ok_or_else(|| {
                            format!("acl.{rule_list_key}[{i}].{dir}.ports must be a mapping")
                        })?;
                        if ports_map.get("number").map_or(true, |v| !v.is_string() && !v.is_number()) {
                            return Err(format!("acl.{rule_list_key}[{i}].{dir}.ports.number must be a string or number"));
                        }
                        if ports_map.get("proto").map_or(true, |v| !v.is_string()) {
                            return Err(format!("acl.{rule_list_key}[{i}].{dir}.ports.proto must be a string"));
                        }
                    }
                }
            }
        }
    }

    println!("--- config contents ---");
    println!("{contents}");
    println!("--- end config ---");

    println!("Config file is valid");
    Ok(0)
}

// ----------------------------------------------------------------------------
// reload
// ----------------------------------------------------------------------------

fn reload_cmd(args: &[String]) -> Result<i32, String> {
    let config_path = if args.is_empty() {
        None
    } else {
        Some(args[0].as_str())
    };

    client::socket::config_reload(config_path)
        .map_err(|e| format!("Failed to reload config: {}", e))?;

    match config_path {
        Some(p) => println!("reloaded config: {p}"),
        None => println!("reloaded default config"),
    }
    Ok(0)
}
