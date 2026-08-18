use common::{
    AF_INET, AF_INET6, AclAction, AclValue, Backend, BPF_F_NO_PREALLOC, BPF_ANY,
    BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_DEVMAP, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_PERCPU_HASH,
     ConntrackValue, CounterId, ETH_HDR_LEN, ETH_P_IP, ETH_P_IPV6,
    ETH_TYPE_OFFSET, EVENT_RINGBUF_BYTES, Event, EventKind, FlowKey, IP_FRAG_OFFSET_MASK,
    IP_MF, IP_PROTO_DSTOPTS, IP_PROTO_FRAGMENT, IP_PROTO_HOPOPTS, IP_PROTO_ICMP,
    IP_PROTO_ICMPV6, IP_PROTO_ROUTING, IP_PROTO_TCP, IP_PROTO_UDP, IpLpmKey, L4AclKey,
    L4AclValue, LbMeta, MAX_ACL_PREFIXES, MAX_BACKENDS, MAX_CONNTRACK_ENTRIES,
    MAX_COUNTERS, MAX_IPV6_EXT_HEADERS, MAX_L4_ACL_ENTRIES, MAX_RATE_LIMIT_ENTRIES,VLAN_HDR_LEN,MAX_VLAN_DEPTH,ETH_P_8021Q,ETH_P_8021AD,
    MAX_REFILL_ELAPSED_NS, MAX_TOKENS, MAX_VLAN_ACL_ENTRIES, NSEC_PER_SEC, PACKET_COST, GLOBAL_RATE_LIMIT_RULE_ID, RATE_LIMIT_RULE_ID, RateLimitKey,
    RateLimitValue, REFILL_TOKENS_PER_SEC,xdp_md,ParseError,VlanTag,Packet,
     XDP_ABORTED, XDP_DROP, XDP_PASS, XSKMAP_TYPE, LbService, LbServiceKey, MAX_LB_SERVICES, VlanAclKey, VlanAclValue, btf_ringbuf, btf_map_flags, btf_map
};

use core::{ffi::c_void, mem::size_of, ptr};
// All general / XDP / helper constants (XDP_*, BPF_ANY, ETH_*,
// IP_*, TCP_*, TLS_*, RATE_LIMIT_*, L4_ACL_PREFIX_LEN, etc.) are now
// defined in common/src/maps.rs and available via `use common::*`.

// Only ip_acl has map_flags
btf_map_flags!(ip_acl, BPF_MAP_TYPE_LPM_TRIE, MAX_ACL_PREFIXES, BPF_F_NO_PREALLOC, IpLpmKey, AclValue);
// All others — WITHOUT map_flags
btf_map!(conntrack, BPF_MAP_TYPE_LRU_PERCPU_HASH, MAX_CONNTRACK_ENTRIES, FlowKey, ConntrackValue);
btf_map!(rate_limit, BPF_MAP_TYPE_PERCPU_HASH, MAX_RATE_LIMIT_ENTRIES, RateLimitKey, RateLimitValue);
btf_map!(counters, BPF_MAP_TYPE_PERCPU_ARRAY, MAX_COUNTERS, u32, u64);
btf_map!(lb_backends, BPF_MAP_TYPE_ARRAY, MAX_BACKENDS, u32, Backend);
btf_map!(lb_meta, BPF_MAP_TYPE_ARRAY, 1, u32, LbMeta);
btf_map!(lb_devmap, BPF_MAP_TYPE_DEVMAP, MAX_BACKENDS, u32, u32);
btf_map!(xsk_map, XSKMAP_TYPE, 2, u32, u32);
btf_map_flags!(l4_acl,BPF_MAP_TYPE_LPM_TRIE,MAX_L4_ACL_ENTRIES,BPF_F_NO_PREALLOC,L4AclKey,L4AclValue);
btf_map!(vlan_acl, BPF_MAP_TYPE_HASH, MAX_VLAN_ACL_ENTRIES, VlanAclKey, VlanAclValue);
// Ringbuf — separate macro
btf_ringbuf!(events, EVENT_RINGBUF_BYTES);
btf_map!( lb_services,BPF_MAP_TYPE_HASH,MAX_LB_SERVICES,LbServiceKey,LbService);
btf_map!(event_mask, BPF_MAP_TYPE_ARRAY, 1, u32, u64);
#[inline(always)]
unsafe fn bpf_map_lookup_elem<K, V>(map: *mut c_void, key: *const K) -> *mut V {
    let helper: unsafe extern "C" fn(*mut c_void, *const c_void) -> *mut c_void =
        unsafe { core::mem::transmute(1usize) };
    unsafe { helper(map, key.cast::<c_void>()).cast::<V>() }
}

#[inline(always)]
unsafe fn bpf_map_update_elem<K, V>(map: *mut c_void,key: *const K,value: *const V,flags: u64,) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, u64) -> i64 =
        unsafe { core::mem::transmute(2usize) };
        unsafe { helper( map.cast::<c_void>(), key.cast::<c_void>(), value.cast::<c_void>(), flags, )
    }
}

#[inline(always)]
unsafe fn bpf_ktime_get_ns() -> u64 {
    let helper: unsafe extern "C" fn() -> u64 = unsafe { core::mem::transmute(5usize) };
    unsafe { helper() }
}

#[inline(always)]
unsafe fn bpf_ringbuf_reserve(map: *mut c_void, size: u64, flags: u64) -> *mut c_void {
    let helper: unsafe extern "C" fn(*mut c_void, u64, u64) -> *mut c_void =
        unsafe { core::mem::transmute(131usize) };
    unsafe { helper(map.cast::<c_void>(), size, flags) }
}

#[inline(always)]
unsafe fn bpf_ringbuf_submit(data: *mut c_void, flags: u64) {
    let helper: unsafe extern "C" fn(*mut c_void, u64) = unsafe { core::mem::transmute(132usize) };
    unsafe { helper(data, flags) }
}

#[unsafe(link_section = "xdp")]
#[unsafe(no_mangle)]
pub extern "C" fn xdp_dataplane(ctx: *mut xdp_md) -> u32 {
    match xdp_dataplane_inner(ctx) {
        Ok(action) => action,
        Err(ParseError::Unsupported) => {
            incr_counter(CounterId::Passed, 1);
            XDP_PASS
        }
        Err(ParseError::Malformed) => {
            incr_counter(CounterId::ParseError, 1);
            XDP_ABORTED
        }
    }
}
/// Main XDP dataplane processing pipeline.
/// Packet processing stages:
/// 1.Parse packet
/// 2.Skip fragments
/// 3.Update counters
/// 4.Rate limiting
/// 5.Apply access control rules
/// 6.Connection tracking
/// Returns:
/// - `Ok(XDP_*)` — final XDP action.
/// - `Err(ParseError)` — packet parsing failed.
#[inline(always)]
fn xdp_dataplane_inner(ctx: *mut xdp_md) -> Result<u32, ParseError> {
    // Parse packet.
    let data = unsafe { (*ctx).data as usize };
    let data_end = unsafe { (*ctx).data_end as usize };
    let packet = parse_packet(data,data_end)?;
     // Skip fragmented packets.
	// VLAN statistics/debug
    if packet.vlan_depth > 0 {
        incr_counter(CounterId::RxVlan, 1);

        emit_event(
            ctx,
            &packet.flow,
            EventKind::VlanDetected,
            packet.vlan[0].id as u64,
            packet.vlan_depth as u64,
        );
    }
    // L3 statistics
    match packet.flow.family {
        AF_INET =>incr_counter(CounterId::RxIpv4, 1),
        AF_INET6 =>incr_counter(CounterId::RxIpv6, 1),
        _ => {incr_counter(CounterId::Unknown, 1)}
    }
    // L4 statistics
    match packet.flow.ip_proto {
        IP_PROTO_TCP => {incr_counter(CounterId::RxTcp, 1);}
        IP_PROTO_UDP => {incr_counter(CounterId::RxUdp, 1);}
        IP_PROTO_ICMPV6 => {incr_counter(CounterId::RxIcmpv6, 1);}
        _ => {incr_counter(CounterId::Unknown, 1);} 
	}
    // VLAN ACL check - check if VLAN filtering is enabled
    if packet.vlan_depth > 0 {
        if let Some((vlan_action, vlan_rate)) = check_vlan_acl(&packet) {
            match vlan_action {
                AclAction::Drop => {
                    incr_counter(CounterId::Dropped, 1);
                    emit_event(ctx, &packet.flow, EventKind::PacketDrop, 0, 0);
                    return Ok(XDP_DROP);
                }
                AclAction::Allow => {
                    // VLAN ACL allows - apply rate limiting if configured
                    incr_counter(CounterId::AclAllow, 1);
                    emit_event(ctx, &packet.flow, EventKind::PacketAllow, 0, 0);
                    if vlan_rate > 0 {
                        if !apply_rate_limit(&packet, vlan_rate) {
                            incr_counter(CounterId::Dropped, 1);
                            incr_counter(CounterId::RateLimited, 1);
                            emit_event(ctx, &packet.flow, EventKind::RateLimited, packet.len, 0);
                            return Ok(XDP_DROP);
                        }
                    }
                    // Continue to L4 ACL
                }
                _ => {}
            }
        }
    }
    
    if packet.is_fragment { return Ok(XDP_PASS); }
    // Update traffic counters.
    incr_counter(CounterId::RxPackets, 1);
    incr_counter(CounterId::RxBytes, packet.len);
    // Apply ACL rules and get rate limit for this rule.
    let (acl_action, rate) = acl_action(&packet);
    match acl_action {
        AclAction::Drop => {
            incr_counter(CounterId::Dropped, 1);
            incr_counter(CounterId::AclDrop, 1);
            emit_event(ctx, &packet.flow, EventKind::PacketDrop, 0, 0);
            return Ok(XDP_DROP);
        }
        AclAction::Allow => {
            incr_counter(CounterId::AclAllow, 1);
            emit_event(ctx, &packet.flow, EventKind::PacketAllow, 0, 0);
            // Apply rate limiting:
            // - rate > 0: per-rule rate limiting
            // - rate = 0: global rate limiting (MAX_TOKENS=65536, REFILL=64000/sec)
            if !apply_rate_limit(&packet, rate) {
                incr_counter(CounterId::Dropped, 1);
                incr_counter(CounterId::RateLimited, 1);
                emit_event(ctx, &packet.flow, EventKind::RateLimited, packet.len, 0);
                return Ok(XDP_DROP);
            }
        }
        AclAction::Redirect => {}
	    AclAction::Inspect => {}
    }
    // Load balancing disabled - moved to TC module (ebpf-tc/NAT.rs)
 
    Ok(XDP_PASS)
}

#[inline(always)]
fn acl_action(packet: &Packet) -> (AclAction, u32) {
    match acl_l4(packet) {
        Some((AclAction::Drop, rate)) => {
            incr_counter(CounterId::AclDrop, 1);
            (AclAction::Drop, rate)
        }
        Some((action, rate)) => { (action, rate) }
        None => { (AclAction::Allow, 0) }
    }
}
/// Generate IPv4 CIDR mask for given prefix length (0-32).
/// Returns 4-byte mask in little-endian order (for src_addr[12..15]).
#[inline(always)]
const fn ipv4_cidr_mask(prefix: u32) -> [u8; 4] {
	if prefix >= 32 { [0xff, 0xff, 0xff, 0xff]}
 	else if prefix >= 24 { [0xff, 0xff, 0xff, 0x00] }
 	else if prefix >= 16 { [0xff, 0xff, 0x00, 0x00] }
 	else if prefix >= 8 { [0xff, 0x00, 0x00, 0x00] }
	else { [0x00, 0x00, 0x00, 0x00] }
}

/// Generate IPv6 CIDR mask for given prefix length.
/// Returns 16-byte mask for standard prefixes (8, 16, 32, 64, 128).
#[inline(always)]
const fn ipv6_cidr_mask(prefix: u32) -> [u8; 16] {
    // Only standard prefixes are supported (8, 16, 32, 64, 128)
	if prefix >= 128 { [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] }
 	else if prefix >= 64 { [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] } 
	else if prefix >= 32 { [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] } 
	else if prefix >= 16 { [0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] } 
	else if prefix >= 8 { [0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] } 
	else { [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] }
}

#[inline(always)]
fn acl_l4(packet: &Packet) -> Option<(AclAction, u32)> {
    let flow = &packet.flow;

    // Try each prefix_len with appropriate source masks
    // Prefix lengths: 352, 336, 320, 304, 272
    // Keep bytes:     44,  42,  40,  38,  34
    for i in 0..5 {
        let (prefix_len, keep) = match i {
            0 => (352u32, 44u8),
            1 => (336u32, 42u8),
            2 => (320u32, 40u8),
            3 => (304u32, 38u8),
            _ => (272u32, 34u8),
        };
        
        // Select masks based on address family
        if flow.family == AF_INET6 {
            // IPv6 masks: /128, /64, /32, /16, /8
            for m in 0..5 {
                let mut key = L4AclKey {
                    prefix_len,
                    family: flow.family,
                    src_addr: flow.src_addr,
                    dst_addr: flow.dst_addr,
                    ip_proto: flow.ip_proto,
                    dst_port: flow.dst_port,
                    src_port: flow.src_port,
                    tcp_flags_mask: 0,
                    tcp_flags_value: 0,
                    _pad: 0,
                    _pad2: 0,
                };

                let ipv6_prefix = match m {
                    0 => 128u32,
                    1 => 64u32,
                    2 => 32u32,
                    3 => 16u32,
                    _ => 8u32,
                };
                let mask = ipv6_cidr_mask(ipv6_prefix);
                for j in 0..16 { key.src_addr[j] &= mask[j]; }

                let key_bytes = unsafe { core::slice::from_raw_parts_mut(&key as *const L4AclKey as *mut u8, 48) };
                for j in keep as usize..48 { key_bytes[j] = 0; }

                let val: *mut L4AclValue = unsafe {
                    bpf_map_lookup_elem((&raw mut l4_acl).cast::<c_void>(), &key)
                };
                if !val.is_null() {
                    let acl_val = unsafe { &*val };
                    return Some((acl_val.action, acl_val.rate));
                }
            }
        } else { // AF_INET (IPv4)
            // IPv4 masks: /32, /24, /16, /8, /0
            for m in 0..5 {
                let mut key = L4AclKey {
                    prefix_len,
                    family: flow.family,
                    src_addr: flow.src_addr,
                    dst_addr: flow.dst_addr,
                    ip_proto: flow.ip_proto,
                    dst_port: flow.dst_port,
                    src_port: flow.src_port,
                    tcp_flags_mask: 0,
                    tcp_flags_value: 0,
                    _pad: 0,
                    _pad2: 0,
                };

                let ipv4_prefix = match m {
                    0 => 32u32,
                    1 => 24u32,
                    2 => 16u32,
                    3 => 8u32,
                    _ => 0u32,
                };
                let mask = ipv4_cidr_mask(ipv4_prefix);
                key.src_addr[12] = key.src_addr[12] & mask[0];
                key.src_addr[13] = key.src_addr[13] & mask[1];
                key.src_addr[14] = key.src_addr[14] & mask[2];
                key.src_addr[15] = key.src_addr[15] & mask[3];

                let key_bytes = unsafe { core::slice::from_raw_parts_mut(&key as *const L4AclKey as *mut u8, 48) };
                for j in keep as usize..48 { key_bytes[j] = 0; }
                
                let val: *mut L4AclValue = unsafe { bpf_map_lookup_elem((&raw mut l4_acl).cast::<c_void>(), &key) };
                if !val.is_null() {
                    let acl_val = unsafe { &*val };
                    return Some((acl_val.action, acl_val.rate));
                }
            }
        }
    }
    None
}

/// Parse all VLAN tags (802.1Q / 802.1AD) from the packet.
/// Updates offset and eth_proto, populates vlan array and vlan_depth.
/// Returns Ok(()) on success, Err(ParseError) on malformed packet.
#[inline(always)]
fn parse_vlan(data: usize, data_end: usize, offset: &mut usize, eth_proto: &mut u16, vlan: &mut [VlanTag; MAX_VLAN_DEPTH], vlan_depth: &mut u8) -> Result<(), ParseError> {
    while (*vlan_depth as usize) < MAX_VLAN_DEPTH {
        if *eth_proto != ETH_P_8021Q && *eth_proto != ETH_P_8021AD { break; }
        let tci = read_u16_be(data, data_end, *offset)?;
        *eth_proto = read_u16_be(data, data_end, *offset + 2)?;
        let idx = *vlan_depth as usize;
        vlan[idx].id = tci & 0x0fff;
        vlan[idx].pcp = ((tci >> 13) & 0x7) as u8;
        vlan[idx].dei = (tci & 0x1000) != 0;
        *vlan_depth += 1;
        *offset += VLAN_HDR_LEN;
    }
    Ok(())
}

#[inline(always)]
fn packet_len(data: usize, data_end: usize) -> Result<u64, ParseError>{
    if data_end < data {return Err(ParseError::Malformed);}
    Ok((data_end - data) as u64)
}
#[inline(always)]
fn parse_packet(data: usize, data_end: usize) -> Result<Packet, ParseError> {
    let len = packet_len(data, data_end)?;

    let mut offset = ETH_HDR_LEN;
    let mut eth_proto = read_u16_be(data, data_end, ETH_TYPE_OFFSET)?;

    // Initialize VLAN storage
    let mut vlan = [VlanTag::default(); MAX_VLAN_DEPTH];
    let mut vlan_depth: u8 = 0;

    // Parse VLAN tags (802.1Q / 802.1AD)
    parse_vlan(data, data_end, &mut offset, &mut eth_proto, &mut vlan, &mut vlan_depth)?;

    // Parse IP layer based on eth_proto
    let mut packet = match eth_proto {
        ETH_P_IP   => parse_ipv4(data, data_end, offset, len)?,
        ETH_P_IPV6 => parse_ipv6(data, data_end, offset, len)?,
        _ => return Err(ParseError::Unsupported),
    };

    // Attach VLAN info
    packet.vlan_depth = vlan_depth;
    packet.vlan = vlan;

    Ok(packet)
}
/// Parse an IPv4 packet and construct a `Packet` descriptor.
///
/// Validates IPv4, TCP and UDP headers, detects fragmentation,
/// extracts the flow tuple (addresses, ports, protocol), computes
/// the payload offset, and returns a parsed `Packet`.
///
/// Returns:
/// - `Ok(Packet)` on successful parsing.
/// - `Err(ParseError::Malformed)` for invalid or truncated packets.
/// - `Err(ParseError::Unsupported)` for unsupported L4 protocols.
#[inline(always)]
fn parse_ipv4(data:usize,data_end:usize,l3:usize,packet_len:u64,)->Result<Packet,ParseError>{
    if data+l3+20>data_end{return Err(ParseError::Malformed);}
    let ip=data+l3;
    let version_ihl=unsafe{*(ip as *const u8)};
    if version_ihl>>4!=4{ return Err(ParseError::Malformed);}
    let ihl=((version_ihl&0xf)as usize)<<2;
    if ihl<20||ihl>60{return Err(ParseError::Malformed);}
    if ip+ihl>data_end{return Err(ParseError::Malformed);}
    let frag=unsafe{ u16::from_be_bytes([*((ip+6)as*const u8),*((ip+7)as*const u8)])};
    let is_fragment=(frag&IP_MF)!=0||(frag&IP_FRAG_OFFSET_MASK)!=0;
    if ip+10>=data_end{return Err(ParseError::Malformed);}
    let ip_proto=unsafe{*((ip+9)as*const u8)};
    // Support TCP, UDP, and ICMP (IPv4 ICMP is protocol 1)
    if ip_proto!=IP_PROTO_TCP && ip_proto!=IP_PROTO_UDP && ip_proto!=IP_PROTO_ICMP {
        return Err(ParseError::Unsupported);
    }
    if ip+20>data_end{return Err(ParseError::Malformed);}
    let src=ip+12;
    let dst=ip+16;
    if src+4>data_end||dst+4>data_end{
        return Err(ParseError::Malformed);}
    // For LPM we use standard IPv6 format (all zeros before IPv4 bytes),
    // so prefixes like 0.0.0.0/0 (prefix_len=0) match correctly
    let src_addr=[0,0,0,0,0,0,0,0,0,0,0,0,
        unsafe{*(src as*const u8)},
        unsafe{*((src+1)as*const u8)},
        unsafe{*((src+2)as*const u8)},
        unsafe{*((src+3)as*const u8)}
    ];
    let dst_addr=[0,0,0,0,0,0,0,0,0,0,0,0,
        unsafe{*(dst as*const u8)},
        unsafe{*((dst+1)as*const u8)},
        unsafe{*((dst+2)as*const u8)},
        unsafe{*((dst+3)as*const u8)}
    ];
    let l4_off=l3+ihl;
    let l4=data+l4_off;
    let(src_port,dst_port,tcp_flags,l4_len)=
        if ip_proto==IP_PROTO_TCP{
            if l4+20>data_end{return Err(ParseError::Malformed);}
            let tcp=l4;
            let src_port=unsafe{ u16::from_be_bytes([*(tcp as*const u8),*((tcp+1)as*const u8)])};
            let dst_port=unsafe{ u16::from_be_bytes([*((tcp+2)as*const u8),*((tcp+3)as*const u8)]) };
            if tcp+13>=data_end{ return Err(ParseError::Malformed); }
            let doff=unsafe{*((tcp+12)as*const u8)}>>4;
            if doff<5||doff>15{ return Err(ParseError::Malformed); }
            let tcp_len=(doff as usize)<<2;
            if tcp+tcp_len>data_end{ return Err(ParseError::Malformed); }
            let flags=unsafe{*((tcp+13)as*const u8)};
            (src_port,dst_port,flags,tcp_len)
        } else if ip_proto==IP_PROTO_UDP {
            if l4+8>data_end{return Err(ParseError::Malformed);}
            let udp=l4;
            let src_port=unsafe{u16::from_be_bytes([*(udp as*const u8),*((udp+1)as*const u8)])};
            let dst_port=unsafe{u16::from_be_bytes([*((udp+2)as*const u8),*((udp+3)as*const u8)])};
        (src_port,dst_port,0,8)
        } else {
            // ICMP - no ports
            if l4+8>data_end{return Err(ParseError::Malformed);}
            (0, 0, 0, 8)
        };
    let payload_offset=l4_off+l4_len;
    if data+payload_offset>data_end{ return Err(ParseError::Malformed);}    
	Ok(Packet {
    		flow: FlowKey {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                family: AF_INET,
                ip_proto,
    	    },
    	len: packet_len,
    	tcp_flags,
    	is_fragment,
    	payload_offset,
    	l3_offset: ip,
    	l4_offset: l4,
	vlan_depth: 0,
    	vlan: [VlanTag::default(); MAX_VLAN_DEPTH],
})
}

#[inline(always)]
unsafe fn read_addr16(base: usize) -> [u8; 16] {
    let mut a = core::mem::MaybeUninit::<[u8; 16]>::uninit();
    let p = a.as_mut_ptr() as *mut u8;
    let mut i = 0;
    while i < 16 {
        unsafe { *p.add(i) = *((base + i) as *const u8) }
        i += 1;
    }
    unsafe { a.assume_init() }
}

#[inline(always)]
fn parse_ipv6(data: usize,data_end: usize,l3: usize,packet_len: u64,) -> Result<Packet, ParseError> {
    	// IPv6 fixed header = 40 bytes
	if data + l3 + 40 > data_end { return Err(ParseError::Malformed);}
    let ip = data + l3;
    	// Version
    let version = unsafe { *(ip as *const u8) };
    if version >> 4 != 6 { return Err(ParseError::Malformed);}
    	// Next header
    let mut ip_proto = unsafe { *((ip + 6) as *const u8) };
    	// IPv6 addresses
    let src = ip + 8;
    let dst = ip + 24;
	if src + 16 > data_end || dst + 16 > data_end { return Err(ParseError::Malformed); }
    let src_addr = unsafe { read_addr16(src) };
    let dst_addr = unsafe { read_addr16(dst) };
   	let mut l4_off = l3 + 40;
    let mut is_fragment = false;
//	let l4=data+l4_off;
/*
       Currently we only support Fragment Header

        IPv6:
        base header
            |
            +-- Fragment Header (8 bytes)
                     |
                     +-- TCP/UDP
         */
	for _ in 0..MAX_IPV6_EXT_HEADERS {
    		match ip_proto {
        		IP_PROTO_HOPOPTS | IP_PROTO_ROUTING | IP_PROTO_DSTOPTS => {
		        	if data + l4_off + 2 > data_end {return Err(ParseError::Malformed); }
            			let ext = data + l4_off;
            			let next = unsafe { *(ext as *const u8) };
            			let len = unsafe { *((ext + 1) as *const u8) };
// length in IPv6 extension header:
            // (Hdr Ext Len + 1) * 8
            let ext_len = ((len as usize) + 1) << 3;
            			if data + l4_off + ext_len > data_end { return Err(ParseError::Malformed); }
            			ip_proto = next;
            			l4_off += ext_len;
        			}	
        		IP_PROTO_FRAGMENT => {
            			if data + l4_off + 8 > data_end {return Err(ParseError::Malformed);}
            			is_fragment = true;
            			let frag = data + l4_off;
            			ip_proto = unsafe { *(frag as *const u8)};
            			l4_off += 8;
        			}
        		_ => {
            			break;
        			}
    			}
	}
    let l4 = data + l4_off;
    if ip_proto != IP_PROTO_TCP && ip_proto != IP_PROTO_UDP &&  ip_proto != IP_PROTO_ICMPV6  { return Err(ParseError::Unsupported); }
    let (src_port, dst_port, tcp_flags, l4_len) = 
	match ip_proto {
		IP_PROTO_TCP =>{
		if l4 + 20 > data_end { return Err(ParseError::Malformed);}
        		let tcp = l4;
        		let src_port = unsafe {u16::from_be_bytes([ *(tcp as *const u8), *((tcp + 1) as *const u8)])};
        		let dst_port = unsafe {u16::from_be_bytes([*((tcp + 2) as *const u8),*((tcp + 3) as *const u8)])};
            	let doff = unsafe {*((tcp + 12) as *const u8)} >> 4;
        		if doff < 5 || doff > 15 {return Err(ParseError::Malformed);}
        		let tcp_len = (doff as usize) << 2;
        		if tcp + tcp_len > data_end { return Err(ParseError::Malformed);}
        		let flags = unsafe { *((tcp + 13) as *const u8) };
        		(src_port, dst_port, flags, tcp_len)
			}
		IP_PROTO_UDP =>{
			if l4 + 8 > data_end {return Err(ParseError::Malformed);}
			let udp = l4;
            		let src_port = unsafe { u16::from_be_bytes([*(udp as *const u8), *((udp + 1) as *const u8)])};
            		let dst_port = unsafe { u16::from_be_bytes([ *((udp + 2) as *const u8),*((udp + 3) as *const u8)]) };
    			(src_port, dst_port, 0, 8)
			}
			IP_PROTO_ICMPV6=>{
			    if l4 + 8 > data_end {return Err(ParseError::Malformed);}
  				  (0,0,0,8)
			}
	  		_ => {return Err(ParseError::Unsupported);}
	    };
	let payload_offset = l4_off + l4_len;
	if data + payload_offset > data_end {return Err(ParseError::Malformed);}
    if ip_proto == IP_PROTO_ICMPV6 {incr_counter(CounterId::RxIcmpv6, 1);}
 	Ok(Packet {
    	flow: FlowKey {
        	src_addr,
       		dst_addr,
        	src_port,
        	dst_port,
        	family: AF_INET6,
        	ip_proto,
    	},
    	len: packet_len,
    	tcp_flags,
    	is_fragment,
    	payload_offset,
    	l3_offset: ip,
    	l4_offset: l4,
        vlan_depth: 0,
    vlan: [VlanTag::default(); MAX_VLAN_DEPTH],
	})
}


/// Apply token bucket rate limiting for a packet.
/// 
/// If rate_pps > 0: applies per-rule rate limiting with custom rate.
/// If rate_pps = 0: applies global rate limiting (MAX_TOKENS=65536, REFILL=64000/sec).
/// 
/// Returns `true` if the packet is allowed, `false` if rate limited.
#[inline(always)]
fn apply_rate_limit(packet: &Packet, rate_pps: u32) -> bool {
    // Determine parameters based on whether per-rule rate limiting is enabled
    let (max_tokens, refill_tokens, rule_id) = 
        if rate_pps > 0 {
        // Per-rule rate limiting: scale rate by 256 for burst capacity
        // rate_pps=100 → max_tokens=25600, refill=100/sec
            (
                (rate_pps as u64) * 256,
                rate_pps as u64,
                RATE_LIMIT_RULE_ID,
            )} 
    else {
        // Global rate limiting: MAX_TOKENS=65536, REFILL=64000/sec
        (MAX_TOKENS, REFILL_TOKENS_PER_SEC, GLOBAL_RATE_LIMIT_RULE_ID)
    };

    let key = RateLimitKey {
        addr: packet.flow.src_addr,
        rule_id,
        family: packet.flow.family,
        _pad: [0, 0, 0],
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let value = unsafe { bpf_map_lookup_elem::<RateLimitKey, RateLimitValue>((&raw mut rate_limit).cast::<c_void>(), &key) };
    
    if value.is_null() {
        let initial = RateLimitValue {
            tokens: max_tokens.saturating_sub(PACKET_COST),
            last_refill_ns: now,
            packet_count: 1,
            byte_count: packet.len,
        };
        let rc = unsafe { bpf_map_update_elem((&raw mut rate_limit).cast::<c_void>(), &key, &initial, BPF_ANY) };
        return rc >= 0;
    }
    
    let bucket = unsafe { &mut *value };
    let elapsed = min_u64(now.saturating_sub(bucket.last_refill_ns), MAX_REFILL_ELAPSED_NS);
    let refill = elapsed.saturating_mul(refill_tokens) / NSEC_PER_SEC;
    
    if refill != 0 {
        bucket.tokens = min_u64(max_tokens, bucket.tokens.saturating_add(refill));
        bucket.last_refill_ns = now;
    }
    
    bucket.packet_count = bucket.packet_count.saturating_add(1);
    bucket.byte_count = bucket.byte_count.saturating_add(packet.len);
    
    if bucket.tokens < PACKET_COST { return false; }
    bucket.tokens = bucket.tokens.saturating_sub(PACKET_COST);
    true
}

/// Check VLAN ACL - returns Some((action, rate)) if VLAN ACL rule matches, None otherwise.
/// Supports single VLAN and QinQ (double VLAN).
/// - First checks rule for outer_vlan (with inner_vlan=0) - single VLAN
/// - Then checks rule for (outer_vlan, inner_vlan) - QinQ
#[inline(always)]
fn check_vlan_acl(packet: &Packet) -> Option<(AclAction, u32)> {
    if packet.vlan_depth == 0 { return None; }
    
    let outer_vlan = packet.vlan[0].id;
    
    // Check single VLAN rule first (inner_vlan = 0)
    let key_single = VlanAclKey {
        outer_vlan,
        inner_vlan: 0,
        _pad: [0, 0, 0, 0],
    };
    let val: *mut VlanAclValue = unsafe { bpf_map_lookup_elem((&raw mut vlan_acl).cast::<c_void>(), &key_single) };
    if !val.is_null() {
        let acl_val = unsafe { &*val };
        return Some((acl_val.action, acl_val.rate));
    }
    
    // Check QinQ rule (if we have 2 VLAN tags)
    if packet.vlan_depth >= 2 {
        let inner_vlan = packet.vlan[1].id;
        let key_qinq = VlanAclKey {
            outer_vlan,
            inner_vlan,
            _pad: [0, 0, 0, 0],
        };
        let val: *mut VlanAclValue = unsafe { bpf_map_lookup_elem((&raw mut vlan_acl).cast::<c_void>(), &key_qinq) };
        if !val.is_null() {
            let acl_val = unsafe { &*val };
            return Some((acl_val.action, acl_val.rate));
        }
    }
    
    None
}

#[inline(always)]
fn min_u64(lhs: u64, rhs: u64) -> u64 {if lhs < rhs { lhs } else { rhs }}
#[inline(always)]
fn emit_event(ctx: *mut xdp_md, flow: &FlowKey, kind: EventKind, aux0: u64, aux1: u64) {
    // Check if event kind is enabled via bitmask
    let key: u32 = 0;
    let mask_ptr = unsafe { bpf_map_lookup_elem::<u32, u64>((&raw mut event_mask).cast::<c_void>(), &key) };
    let mask = if mask_ptr.is_null() { u64::MAX } else { unsafe { *mask_ptr } };
    if (mask >> kind as u64) & 1 == 0 {
        return;
    }
    let raw = unsafe { bpf_ringbuf_reserve((&raw mut events).cast::<c_void>(), size_of::<Event>() as u64, 0) };
    if raw.is_null() {return;}
    let ifindex = 
        if ctx.is_null() {0} 
        else {unsafe { (*ctx).ingress_ifindex }};
    let event = raw.cast::<Event>();
    unsafe {
        ptr::write(event,Event {ts_ns: bpf_ktime_get_ns(),kind,ifindex,flow: *flow,aux0,aux1,},);
        bpf_ringbuf_submit(raw, 0);
    }
}

fn incr_counter(counter: CounterId, value: u64) {
    let key = counter as u32;
    let slot = unsafe { bpf_map_lookup_elem::<u32, u64>((&raw mut counters).cast::<c_void>(), &key) };
    if !slot.is_null() {
        let counter = unsafe { &mut *slot };
        *counter = counter.saturating_add(value);
    }
}

#[inline(always)]
fn read_u16_be(data: usize, data_end: usize, off: usize) -> Result<u16, ParseError> {
    if data + off + 2 > data_end { return Err(ParseError::Malformed); }
    let hi = unsafe { *((data + off) as *const u8) };
    let lo = unsafe { *((data + off + 1) as *const u8) };
    Ok(((hi as u16) << 8) | lo as u16)
}
