//! Consume the eBPF `events` ringbuf and log events.
//!
//! Map/program discovery is done entirely through the libbpf-rs / libbpf API
//! (see `Cargo.toml`); no `bpftool` subprocess is used.

use std::time::Duration;

use anyhow::{Result, anyhow};
use common::{Event, EventKind, FlowKey};
use libbpf_rs::query::{MapInfoIter, ProgInfoIter, ProgInfoQueryOptions};
use libbpf_rs::{MapCore, MapHandle, MapType, ProgramType, RingBufferBuilder};
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
        } else if let Ok(map) = get_events_map_via_libbpf() {
            map
        } else {
            return Err(anyhow!(
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

// ---------------------------------------------------------------------------
// events ringbuf discovery (libbpf-rs query API, no bpftool)
// ---------------------------------------------------------------------------

/// Open a loaded map by its global id and return it if it is the `events`
/// ringbuf. Mirrors the former `bpftool map show id <id>` lookup.
fn events_map_from_id(map_id: u32) -> Result<Option<EventsMap>> {
    let handle = match MapHandle::from_map_id(map_id) {
        Ok(h) => h,
        Err(e) => {
            debug!("events map lookup by id {} failed: {}", map_id, e);
            return Ok(None);
        }
    };

    let is_events_ringbuf =
        handle.name().to_str() == Some("events") && handle.map_type() == MapType::RingBuf;

    Ok(if is_events_ringbuf {
        Some(EventsMap {
            id: map_id as i32,
            size: handle.max_entries() as usize,
        })
    } else {
        None
    })
}

/// Scan every loaded BPF map (via libbpf) for the `events` ringbuf map.
fn events_map_by_name() -> Result<Option<EventsMap>> {
    for info in MapInfoIter::default() {
        if info.ty != MapType::RingBuf {
            continue;
        }
        if info.name.to_str().map(|n| n == "events").unwrap_or(false) {
            return Ok(Some(EventsMap {
                id: info.id as i32,
                size: info.max_entries as usize,
            }));
        }
    }
    Ok(None)
}

/// Find the `events` ringbuf among the maps referenced by program `prog_id`.
///
/// Replaces `bpftool prog show id <prog_id>` + `bpftool map show id <map_id>`:
/// libbpf's program info API already exposes the program's map ids.
fn get_events_map_for_prog(prog_id: i32) -> Result<EventsMap> {
    let opts = ProgInfoQueryOptions::default().include_map_ids(true);
    for prog in ProgInfoIter::with_query_opts(opts) {
        if prog.id != prog_id as u32 {
            continue;
        }
        for map_id in &prog.map_ids {
            if let Some(em) = events_map_from_id(*map_id)? {
                return Ok(em);
            }
        }
    }

    // `map_ids` can be empty on some libbpf/kernel combinations; fall back to a
    // global scan by name (the `events` ringbuf is loaded globally, not per-prog).
    if let Some(em) = events_map_by_name()? {
        return Ok(em);
    }

    Err(anyhow!(
        "no 'events' ringbuf map found for program id {}",
        prog_id
    ))
}

/// Find the `events` ringbuf map. Replaces the former `bpftool`-based discovery:
///  1. scan loaded maps for an `events` ringbuf (was `bpftool map show name events`);
///  2. fall back to scanning XDP programs and inspecting their map ids.
fn get_events_map_via_libbpf() -> Result<EventsMap> {
    if let Some(em) = events_map_by_name()? {
        return Ok(em);
    }

    let opts = ProgInfoQueryOptions::default().include_map_ids(true);
    for prog in ProgInfoIter::with_query_opts(opts) {
        if prog.ty != ProgramType::Xdp {
            continue;
        }
        for map_id in &prog.map_ids {
            if let Some(em) = events_map_from_id(*map_id)? {
                return Ok(em);
            }
        }
    }

    Err(anyhow!(
        "Could not get events map. Use --prog-id <id> or ensure an XDP program is loaded"
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
