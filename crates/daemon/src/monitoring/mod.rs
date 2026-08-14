use std::time::Duration;

use anyhow::{Result, anyhow};
use common::{Event, EventKind, FlowKey};
use libbpf_rs::{MapHandle, RingBufferBuilder};
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct EventsMap {
    id: i32,
    size: usize,
}

impl EventsMap {
    fn open(self) -> Result<MapHandle> {
        MapHandle::from_map_id(self.id as u32)
            .map_err(|e| anyhow!("failed to open map id {} via libbpf-rs: {}", self.id, e))
    }
}

pub struct RingbufMonitor<'a> {
    ringbuf: libbpf_rs::RingBuffer<'a>,
}

impl<'a> RingbufMonitor<'a> {
    pub fn new(prog_id: Option<i32>) -> Result<Self> {
        let events_map = if let Some(prog_id) = prog_id {
            get_events_map_for_prog(prog_id)?
        } else if let Ok(map) = get_events_map_via_bpftool() {
            map
        } else {
            return Err(anyhow::anyhow!(
                "Could not get events map. Use --prog-id <id> or ensure an XDP program is loaded"
            ));
        };

        let map_handle = events_map.clone().open()?;

        info!("Opened events map");
        info!("Events ringbuf size: {} bytes", events_map.size);

        let mut builder = RingBufferBuilder::new();
        builder.add(&map_handle, |data| {
            if let Some(event) = parse_event(data) {
                log_event(&event);
            }
            0
        })?;
        let ringbuf = builder.build()?;

        info!("Starting ringbuf event loop");

        Ok(Self { ringbuf })
    }

    pub fn run_with_condition<F>(&mut self, mut should_continue: F) -> Result<()>
    where
        F: FnMut() -> bool,
    {
        loop {
            if !should_continue() {
                break;
            }

            if let Err(e) = self.ringbuf.poll(Duration::from_millis(100)) {
                warn!("Ringbuf error: {}", e);
            }
        }

        info!("Shutting down");
        Ok(())
    }
}

fn parse_event(data: &[u8]) -> Option<Event> {
    if data.len() < std::mem::size_of::<Event>() {
        return None;
    }

    Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) })
}

fn get_events_map_from_map_id(id: i32) -> Result<EventsMap> {
    let info = get_map_info(id)?;
    if info.name != "events" || info.map_type != "ringbuf" {
        return Err(anyhow!(
            "Map id {} is not events ringbuf (name={}, type={})",
            id,
            info.name,
            info.map_type
        ));
    }

    Ok(EventsMap {
        id,
        size: info.max_entries,
    })
}

fn get_events_map_for_prog(prog_id: i32) -> Result<EventsMap> {
    let map_ids = get_map_ids_for_prog(prog_id)?;
    let mut errors = Vec::new();

    for map_id in map_ids {
        match get_events_map_from_map_id(map_id) {
            Ok(map) => return Ok(map),
            Err(err) => {
                warn!("Skipping map id {}: {}", map_id, err);
                errors.push(format!("map id {map_id}: {err}"));
            }
        }
    }

    Err(anyhow!(
        "Could not find events ringbuf in prog {} maps:\n{}",
        prog_id,
        errors.join("\n")
    ))
}

fn get_map_ids_for_prog(prog_id: i32) -> Result<Vec<i32>> {
    use std::process::Command;

    let output = Command::new("bpftool")
        .args(["prog", "show", "id", &prog_id.to_string()])
        .output()
        .map_err(|e| anyhow!("Failed to execute bpftool: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "bpftool prog show id {} failed: {}{}",
            prog_id,
            stdout,
            stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!("bpftool prog show id {}: {}", prog_id, stdout.trim());

    let mut map_ids: Vec<i32> = Vec::new();
    for line in stdout.lines() {
        if let Some((_, ids)) = line.split_once("map_ids") {
            for id in ids.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
                if let Ok(map_id) = id.trim_matches(':').parse::<i32>() {
                    map_ids.push(map_id);
                }
            }
        }
    }

    if map_ids.is_empty() {
        return Err(anyhow!("No map_ids found for prog {}", prog_id));
    }

    Ok(map_ids)
}

#[derive(Clone, Debug)]
struct MapInfo {
    name: String,
    map_type: String,
    max_entries: usize,
}

fn get_map_info(map_id: i32) -> Result<MapInfo> {
    use std::process::Command;

    let output = Command::new("bpftool")
        .args(["map", "show", "id", &map_id.to_string()])
        .output()
        .map_err(|e| anyhow!("Failed to execute bpftool: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "bpftool map show id {} failed: {}{}",
            map_id,
            stdout,
            stderr
        ));
    }

    parse_map_info(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow!("Could not parse bpftool map info for id {}", map_id))
}

fn parse_map_info(text: &str) -> Option<MapInfo> {
    let mut words = text.split_whitespace();
    let _id = words.next()?;
    let map_type = words.next()?.to_string();
    let mut name = String::new();
    let mut max_entries = 0usize;

    while let Some(word) = words.next() {
        match word {
            "name" => name = words.next()?.to_string(),
            "max_entries" => max_entries = words.next()?.parse().ok()?,
            _ => {}
        }
    }

    if name.is_empty() || max_entries == 0 {
        None
    } else {
        Some(MapInfo {
            name,
            map_type,
            max_entries,
        })
    }
}

fn get_events_map_via_bpftool() -> Result<EventsMap> {
    use std::process::Command;

    let output = Command::new("bpftool")
        .args(["map", "show", "name", "events"])
        .output()
        .map_err(|e| anyhow!("Failed to execute bpftool: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(info) = parse_map_info(line) {
                if info.name == "events" && info.map_type == "ringbuf" {
                    if let Some(id_str) = line.split_whitespace().next() {
                        if let Ok(id) = id_str.trim_matches(':').parse::<i32>() {
                            return Ok(EventsMap {
                                id,
                                size: info.max_entries,
                            });
                        }
                    }
                }
            }
        }
    }

    let output = Command::new("bpftool")
        .args(["prog", "show"])
        .output()
        .map_err(|e| anyhow!("Failed to execute bpftool: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("bpftool failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("bpftool prog show: {}", stdout.trim());

    let mut xdp_progs: Vec<i32> = stdout
        .lines()
        .filter(|line| line.contains(": xdp"))
        .filter_map(|line| {
            line.split_whitespace()
                .next()
                .and_then(|s| s.trim_matches(':').parse::<i32>().ok())
        })
        .collect();
    xdp_progs.sort_unstable_by(|left, right| right.cmp(left));

    if xdp_progs.is_empty() {
        return Err(anyhow!("No XDP programs found"));
    }

    for prog_id in xdp_progs {
        info!("Trying XDP program id: {}", prog_id);
        if let Ok(map) = get_events_map_for_prog(prog_id) {
            return Ok(map);
        }
    }

    Err(anyhow!(
        "Could not find events map for any XDP program. Use --prog-id <id>"
    ))
}

fn log_event(event: &Event) {
    let flow: &FlowKey = &event.flow;
    let src_ip = format_ip(flow.src_addr, flow.family);
    let dst_ip = format_ip(flow.dst_addr, flow.family);
    let proto_name = match flow.ip_proto {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        58 => "ICMPv6",
        _ => "OTHER",
    };

    let event_name = match event.kind {
        EventKind::PacketDrop => "PacketDrop",
        EventKind::RateLimited => "RateLimited",
        EventKind::ConntrackMiss => "ConntrackMiss",
        EventKind::BackendSelected => "BackendSelected",
        EventKind::SlowPath => "SlowPath",
        EventKind::ServiceMatched => "ServiceMatched",
        EventKind::VlanDetected => "VlanDetected",
        EventKind::PacketAllow => "PacketAllow",
    };

    info!(
        timestamp_ns = event.ts_ns,
        event_kind = %event_name,
        ifindex = event.ifindex,
        src = %src_ip,
        dst = %dst_ip,
        src_port = flow.src_port,
        dst_port = flow.dst_port,
        protocol = %proto_name,
        aux0 = event.aux0,
        aux1 = event.aux1,
        "eBPF event"
    );
}

fn format_ip(addr: [u8; 16], family: u8) -> String {
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