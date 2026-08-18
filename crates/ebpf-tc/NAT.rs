/*#[inline(always)]
fn apply_nat(ctx: *mut xdp_md, packet: &Packet, backend: &Backend, vip: &[u8; 16], vip_port: u16) -> Result<(), ParseError> {
    // DNAT
    // VIP -> backend
    rewrite_dst(ctx, packet, backend)?;

    // SNAT (client -> VIP)
    // Disabled: causes BPF stack overflow due to checksum calculations.
    // When SNAT is needed, implement using BPF helpers or per-CPU maps.
    let _ = (vip, vip_port); // Suppress unused warnings

    Ok(())
}

#[inline(always)]
fn rewrite_dst(ctx: *mut xdp_md, packet: &Packet, backend: &Backend) -> Result<(), ParseError> {
    match packet.flow.family {
        AF_INET => { rewrite_ipv4_dst(ctx, packet, backend)?; }
        AF_INET6 => { rewrite_ipv6_dst(ctx, packet, backend)?; }
        _ => {}
    }
    Ok(())
}

#[inline(always)]
fn rewrite_ipv4_dst(ctx: *mut xdp_md,packet: &Packet,backend: &Backend,) -> Result<(), ParseError> {
    let data_end = unsafe { (*ctx).data_end as usize };
    let ip = packet.l3_offset;
    if ip + 20 > data_end {return Err(ParseError::Malformed);}
    // IPv4 destination
    let dst = ip + 16;
    unsafe {
        *((dst + 0) as *mut u8) = backend.addr[12];
        *((dst + 1) as *mut u8) = backend.addr[13];
        *((dst + 2) as *mut u8) = backend.addr[14];
        *((dst + 3) as *mut u8) = backend.addr[15];
    }
    // L4 destination port
    let l4 = packet.l4_offset;
    match packet.flow.ip_proto {
        IP_PROTO_TCP => {
            if l4 + 20 > data_end {return Err(ParseError::Malformed);}
            unsafe {
                *((l4 + 2) as *mut u8) = (backend.port >> 8) as u8;
                *((l4 + 3) as *mut u8) = backend.port as u8;
            }
        }
        IP_PROTO_UDP => {
            if l4 + 8 > data_end {return Err(ParseError::Malformed);}
            unsafe {
                *((l4 + 2) as *mut u8) = (backend.port >> 8) as u8;
                *((l4 + 3) as *mut u8) = backend.port as u8;
            }
        }
        _ => {}
    }
    // recalculate only IPv4 checksum
    update_ipv4_checksum(ip, data_end)?;
    Ok(())
}
// !!!!!!!
#[inline(always)]
fn rewrite_src(ctx: *mut xdp_md,packet: &Packet,vip: &[u8;16],vip_port: u16,) -> Result<(), ParseError> {
    match packet.flow.family {
        AF_INET => {rewrite_ipv4_src(ctx,packet,vip,vip_port,)?;}
        AF_INET6 => {rewrite_ipv6_src(ctx,packet,vip,vip_port,)?;}
        _ => {}
    }
    Ok(())
}
#[inline(always)]
fn rewrite_ipv4_src(ctx: *mut xdp_md,packet: &Packet,vip: &[u8; 16],vip_port: u16,) -> Result<(), ParseError> {
    let data_end = unsafe { (*ctx).data_end as usize };
    let ip = packet.l3_offset;
    if ip + 20 > data_end {return Err(ParseError::Malformed);}
    // IPv4 source address
    let src = ip + 12;
    unsafe {
        *((src + 0) as *mut u8) = vip[12];
        *((src + 1) as *mut u8) = vip[13];
        *((src + 2) as *mut u8) = vip[14];
        *((src + 3) as *mut u8) = vip[15];
    }
    // L4 source port
    let l4 = packet.l4_offset;

    match packet.flow.ip_proto {
        IP_PROTO_TCP => {if l4 + 20 > data_end {return Err(ParseError::Malformed);}
            unsafe {
                *((l4 + 0) as *mut u8) = (vip_port >> 8) as u8;
                *((l4 + 1) as *mut u8) = vip_port as u8;
            }
        }
        IP_PROTO_UDP => {if l4 + 8 > data_end {return Err(ParseError::Malformed);}
            unsafe {
                *((l4 + 0) as *mut u8) = (vip_port >> 8) as u8;
                *((l4 + 1) as *mut u8) = vip_port as u8;
            }
        }

        _ => {}
    }
    update_ipv4_checksum(ip, data_end)?;

    Ok(())
}
#[inline(always)]
fn rewrite_ipv6_src(ctx: *mut xdp_md,packet: &Packet,vip: &[u8;16],vip_port: u16,) -> Result<(), ParseError> {
    let data_end = unsafe {(*ctx).data_end as usize};
    let ip = packet.l3_offset;
    // IPv6 header = 40 bytes
    if ip + 40 > data_end { return Err(ParseError::Malformed);}
    // IPv6 source address offset = 8
    let src = ip + 8;
    unsafe {
        let mut i = 0;
        while i < 16 {
            *((src + i) as *mut u8) = vip[i];
            i += 1;
        }
    }
    let l4 = packet.l4_offset;
    match packet.flow.ip_proto {
        IP_PROTO_TCP => {
            if l4 + 20 > data_end {return Err(ParseError::Malformed);}
            unsafe {
                // source port
                *((l4 + 0) as *mut u8) =(vip_port >> 8) as u8;
                *((l4 + 1) as *mut u8) =vip_port as u8;
            }
        }
        IP_PROTO_UDP => {
            if l4 + 8 > data_end {return Err(ParseError::Malformed);}
            unsafe {
                *((l4 + 0) as *mut u8) =(vip_port >> 8) as u8;
                *((l4 + 1) as *mut u8) =vip_port as u8;
            }
        }
        _ => {}
    }
    Ok(())
}
#[inline(always)]
fn ipv4_checksum(ip: usize) -> u16 {
    let mut sum: u32 = 0;

    let mut i = 0;
    while i < 20 {
        if i != 10 {
            let hi = unsafe { *((ip + i) as *const u8) };
            let lo = unsafe { *((ip + i + 1) as *const u8) };
            sum += ((hi as u16) << 8 | lo as u16) as u32;
        }
        i += 2;
    }
    while sum > 0xffff {sum = (sum & 0xffff) + (sum >> 16);}
    !(sum as u16)
}
#[inline(always)]
fn update_ipv4_checksum(
    ip: usize,
    data_end: usize,
) -> Result<(), ParseError> {
    if ip + 20 > data_end { return Err(ParseError::Malformed);}
    let ihl = ((unsafe { *(ip as *const u8) } & 0x0f) as usize) << 2;
    if ip + ihl > data_end {return Err(ParseError::Malformed);}
    unsafe {
        *((ip + 10) as *mut u8) = 0;
        *((ip + 11) as *mut u8) = 0;
    }

    let csum = ipv4_checksum(ip);
    unsafe {
        *((ip + 10) as *mut u8) = (csum >> 8) as u8;
        *((ip + 11) as *mut u8) = csum as u8;
    }
    Ok(())
}

fn rewrite_ipv6_dst(ctx: *mut xdp_md,packet: &Packet,backend: &Backend,) -> Result<(), ParseError> {
    let data_end = unsafe { (*ctx).data_end as usize };
    let ip = packet.l3_offset;
    // IPv6 fixed header = 40 bytes
    if ip + 40 > data_end {return Err(ParseError::Malformed);}
    // destination address starts at byte 24
    let dst = ip + 24;
    unsafe {
        let mut i = 0;
        while i < 16 {
            *((dst + i) as *mut u8) = backend.addr[i];
            i += 1;
        }
    }
    let l4 = packet.l4_offset;
    match packet.flow.ip_proto {
        IP_PROTO_TCP => {
            if l4 + 20 > data_end {return Err(ParseError::Malformed);}
            unsafe {
                *((l4 + 2) as *mut u8) = (backend.port >> 8) as u8;
                *((l4 + 3) as *mut u8) = backend.port as u8;
            }
        }
        IP_PROTO_UDP => {
            if l4 + 8 > data_end {return Err(ParseError::Malformed);}
            unsafe {
                *((l4 + 2) as *mut u8) = (backend.port >> 8) as u8;
                *((l4 + 3) as *mut u8) = backend.port as u8;
            }
        }
        _ => {}
    }

    Ok(())

}*/

#[inline(always)]
fn redirect_backend(
    ctx: *mut xdp_md,
    packet: &Packet,
    backend_id: u32,
    vip: &[u8; 16],
    vip_port: u16,
) -> Result<u32, ParseError> {
    let backend = match lookup_backend(backend_id) {
        Some(b) => b,
        None => {
            incr_counter(CounterId::BackendUnavailable, 1);
            incr_counter(CounterId::Passed, 1);
            return Ok(XDP_PASS);
        }
    };

    if backend.is_unhealthy() {
        incr_counter(CounterId::BackendUnavailable, 1);
        incr_counter(CounterId::Passed, 1);
        return Ok(XDP_PASS);
    }
    //apply_nat(ctx, packet, &backend, vip, vip_port)?;

    let ret = unsafe {
        bpf_redirect_map((&raw mut lb_devmap).cast::<c_void>(), backend_id, 0,)
    };
    if ret < 0 {
        incr_counter(CounterId::RedirectFailed, 1);
        return Ok(XDP_PASS);
    }
    if ret == XDP_REDIRECT as i64 {
        incr_counter(CounterId::Redirected, 1);
        emit_event(ctx, &packet.flow, EventKind::BackendSelected, backend_id as u64, 0,);
    return Ok(XDP_REDIRECT);
    }
    incr_counter(CounterId::Passed, 1);
    Ok(XDP_PASS)
}

#[inline(always)]
fn lookup_lb_service(flow: &FlowKey) -> Option<LbService> {
let key = LbServiceKey {
    addr: flow.dst_addr,
    port: flow.dst_port,
    proto: flow.ip_proto,
    family: flow.family
};
    let value = unsafe {
        bpf_map_lookup_elem::<LbServiceKey, LbService>(
            (&raw mut lb_services).cast::<c_void>(),
            &key,
        )
    };

    if value.is_null() {
        return None;
    }

    Some(unsafe { *value })
}

/// Number of configured backends from `lb_meta` (written from user-space
/// via `ebpf-ctl backend add`). Reading keeps the map "alive" (otherwise LLVM
/// throws away unused map at link time, and it disappears from the object).
#[inline(always)]
fn meta_num_backends() -> u32 {
    let value = unsafe {
        bpf_map_lookup_elem::<u32, LbMeta>((&raw mut lb_meta).cast::<c_void>(), &0u32)};
    if value.is_null() {return 0;}
    let meta = unsafe { &*value };
    meta.num_backends
}
#[inline(always)]
fn select_backend(flow: &FlowKey,backend_group: u32,) -> Option<u32> {
    let hash = flow_hash(flow);
    let count = meta_num_backends();
    if count == 0 {    return None;}
    let start = hash % MAX_BACKENDS;
    let mut i = 0;
    while i < MAX_BACKENDS {
        let backend_id = (start + i) % MAX_BACKENDS;
        let backend = unsafe {
            bpf_map_lookup_elem::<u32, Backend>(
                (&raw mut lb_backends).cast::<c_void>(),
                &backend_id,
            )
        };
        if backend.is_null() {
            i += 1;
            continue;
        }
        let backend = unsafe { &*backend };
        if backend.backend_group != backend_group {
            i += 1;
            continue;
        }
        if !backend.is_configured() {
            i += 1;
            continue;
        }
        if backend.is_unhealthy() {
            i += 1;
            continue;
        }
        return Some(backend_id);
    }
    None
}
#[inline(always)]
fn apply_load_balance(
    ctx: *mut xdp_md,
    packet: &Packet,
    backend_group: u32,
    vip: &[u8; 16],
    vip_port: u16,
) -> Result<u32, ParseError> {
    let backend_id = match resolve_backend_id(&packet.flow, backend_group) {
        Some(id) => id,
        None => {
            incr_counter(CounterId::Passed, 1);
            return Ok(XDP_PASS);
        }
    };

    redirect_backend(ctx, packet, backend_id, vip, vip_port)
}

#[inline(always)]
//fn resolve_backend_id(flow: &FlowKey) -> Option<u32> {
fn resolve_backend_id(flow: &FlowKey,backend_group: u32,) -> Option<u32>{
    let ct_value = unsafe {
        bpf_map_lookup_elem::<FlowKey, ConntrackValue>(
            (&raw mut conntrack).cast::<c_void>(),
            flow,
            )
        };
    if ct_value.is_null() {return None;}
    let ct_entry = unsafe { &mut *ct_value };
    if ct_entry.backend_id == INVALID_BACKEND_ID {
    let id = match //select_backend(flow) {
            select_backend(flow,backend_group){
            Some(id) => id,
            None => return None,
        };
        ct_entry.backend_id = id;
        incr_counter(CounterId::BackendSelected, 1);
        Some(id)
    } else {
        Some(ct_entry.backend_id)
    }
}
fn lookup_backend(backend_id: u32) -> Option<Backend> {
    if backend_id >= MAX_BACKENDS {return None; }
    let value = unsafe { bpf_map_lookup_elem::<u32, Backend>((&raw mut lb_backends).cast::<c_void>(), &backend_id) };
    if value.is_null() {return None;}
    let backend = unsafe { *value };
    if backend.is_configured() {Some(backend)} 
    else {None}
}

/// Create or update a connection tracking entry.
///
/// New flows are inserted into the conntrack table.
/// Existing flows have their state, timestamps and statistics updated.
fn update_conntrack(packet: &Packet) -> bool {
     // Lookup existing connection.
    let now = unsafe { bpf_ktime_get_ns() };
    let value = unsafe { bpf_map_lookup_elem::<FlowKey, ConntrackValue>((&raw mut conntrack).cast::<c_void>(), &packet.flow) };
    // Create a new conntrack entry for unseen flows.
    if value.is_null() {
        incr_counter(CounterId::ConntrackMiss, 1);
        let initial = ConntrackValue {
            state: ConntrackState::New,
            flags: packet.tcp_flags as u32,
            backend_id: INVALID_BACKEND_ID,
            _pad: 0,
            packets: 1,
            bytes: packet.len,
            first_seen_ns: now,
            last_seen_ns: now,
        };
        let rc = unsafe { bpf_map_update_elem((&raw mut conntrack).cast::<c_void>(), &packet.flow, &initial, BPF_ANY) };
        return rc >= 0;
    }
    // Update existing connection state and statistics.
    incr_counter(CounterId::ConntrackHit, 1);
    let entry = unsafe { &mut *value };
    entry.last_seen_ns = now;
    entry.packets = entry.packets.saturating_add(1);
    entry.bytes = entry.bytes.saturating_add(packet.len);
    update_tcp_state(entry, packet.flow.ip_proto, packet.tcp_flags);
    true
}
/*
      AclAction::Inspect => {
            // TODO:
            // emit_event(...)
            // continue pipeline
        }
    }
    // Update connection tracking.
   
// Apply load balancing and return the final XDP action.
    // apply_load_balance(ctx, &packet)
    match lookup_lb_service(&packet.flow) {
         Some(service) => {
            incr_counter(CounterId::ServiceHit, 1);
         
             if !update_conntrack(&packet) {
                 incr_counter(CounterId::Dropped, 1);
                 emit_event(ctx, &packet.flow, EventKind::ConntrackMiss, packet.len, 0);
                 return Ok(XDP_DROP);
         }
         emit_event(ctx, &packet.flow, EventKind::ServiceMatched, packet.flow.dst_port as u64, service.backend_group as u64,);
            return apply_load_balance(ctx, &packet, service.backend_group, &service.vip_addr, service.vip_port);
        }

        None => {
            incr_counter(CounterId::ServiceMiss, 1);
            incr_counter(CounterId::Passed, 1);
            return Ok(XDP_PASS);
        }
    }

    #[inline(always)]
unsafe fn bpf_redirect_map(map: *mut c_void, key: u32, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32, u64) -> i64 =
        unsafe { core::mem::transmute(51usize) };
    unsafe { helper(map.cast::<c_void>(), key, flags) }
}

    /// 6.AF_XDP redirect for L7 inspection
/// 7.Connection tracking
/// 8. Apply load balancing and return the final XDP action.
     */
    /*
    /// 6.AF_XDP redirect for L7 inspection
/// 7.Connection tracking
/// 8. Apply load balancing and return the final XDP action. */

/*
fn update_tcp_state(entry: &mut ConntrackValue, ip_proto: u8, tcp_flags: u8) {
    if ip_proto != IP_PROTO_TCP {return; }
    if (tcp_flags & TCP_RST) != 0 {entry.state = ConntrackState::Closed;}
    else if entry.state == ConntrackState::New && (tcp_flags & TCP_SYN) != 0 && (tcp_flags & TCP_ACK) != 0{
         entry.state = ConntrackState::Established;}
    else if entry.state == ConntrackState::New && (tcp_flags & TCP_ACK) != 0 {
        entry.state = ConntrackState::Established; } 
    else if entry.state == ConntrackState::Established && (tcp_flags & TCP_FIN) != 0 {
        entry.state = ConntrackState::Closing;} 
    else if entry.state == ConntrackState::Closing && (tcp_flags & TCP_ACK) != 0 {
        entry.state = ConntrackState::Closed;}
    entry.flags = tcp_flags as u32;
} */
/*
#[inline(always)]
fn flow_hash(flow: &FlowKey) -> u32 {
    let mut hash: u32 = 0x811c9dc5;

    // IPv4/IPv6 source
    for byte in flow.src_addr.iter() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }

    // IPv4/IPv6 destination
    for byte in flow.dst_addr.iter() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }

    // Source port
    hash ^= flow.src_port as u32;
    hash = hash.wrapping_mul(0x01000193);

    // Destination port
    hash ^= flow.dst_port as u32;
    hash = hash.wrapping_mul(0x01000193);

    // Protocol
    hash ^= flow.ip_proto as u32;
    hash = hash.wrapping_mul(0x01000193);

    hash
}


#[inline(always)]
*/