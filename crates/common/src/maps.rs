use core::mem::size_of;
pub const ANY_PORT: u16 = 0;
pub const MAX_BACKENDS: u32 = 256;
pub const MAX_ACL_PREFIXES: u32 = 65_536;
pub const MAX_FLOW_ACL_ENTRIES: u32 = 262_144;
pub const MAX_CONNTRACK_ENTRIES: u32 = 1_048_576;
pub const MAX_RATE_LIMIT_ENTRIES: u32 = 262_144;
pub const MAX_COUNTERS: u32= 32;
pub const EVENT_RINGBUF_BYTES: u32 = 16 * 1024 * 1024;
pub const  MAX_L7_ACL_ENTRIES: u32 = 16_384;
pub const MAX_L4_ACL_ENTRIES: u32 = 16_384;
pub const MAX_VLAN_ACL_ENTRIES: u32 = 16_384;

pub const BPF_F_NO_PREALLOC: u32 = 1 << 0;
//pub const IP_PROTO_ICMPV6: u8 = 58;
pub const AF_INET: u8 = 4;
pub const AF_INET6: u8 = 6;
pub const IP_LPM_FAMILY_BITS: u32 = 8;
pub const IPV4_MAX_PREFIX_BITS: u32 = IP_LPM_FAMILY_BITS + 32;
pub const IPV6_MAX_PREFIX_BITS: u32 = IP_LPM_FAMILY_BITS + 128;

pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_ICMPV6: u8 = 58;
pub const MAX_IPV6_EXT_HEADERS: usize = 4;
pub const XSKMAP_TYPE: u32 = 17;
pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const MAX_LB_SERVICES:u32=64;
pub const BACKEND_FLAG_UNHEALTHY: u32 = 0x1;

pub const IP_PROTO_HOPOPTS: u8 = 0;
pub const IP_PROTO_DSTOPTS: u8 = 60;
pub const IP_PROTO_FRAGMENT: u8 = 44;
pub const IP_PROTO_ROUTING: u8 = 43;
pub const IP_PROTO_DEST: u8 = 60;

// ===== General constants for XDP/TC dataplane (extracted from xdp_prog.rs / tc_prog.rs) =====

// BPF map helper flags
pub const BPF_ANY: u64 = 0;

// XDP action verdicts (values from uapi/linux/bpf.h: XDP_*)
pub const XDP_ABORTED: u32 = 0;
pub const XDP_DROP: u32 = 1;
pub const XDP_PASS: u32 = 2;
pub const XDP_TX: u32 = 3;
pub const XDP_REDIRECT: u32 = 4;

// Ethernet
pub const ETH_HDR_LEN: usize = 14;
pub const ETH_TYPE_OFFSET: usize = 12;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;

// IPv4 fragmentation
pub const IP_MF: u16 = 0x2000;
pub const IP_FRAG_OFFSET_MASK: u16 = 0x1fff;

// TCP control flags (in TCP header flags byte)
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

// TLS (for L7 inspection, currently commented out in xdp_prog.rs)
pub const TLS_HANDSHAKE: u8 = 0x16;
pub const TLS_CLIENT_HELLO: u8 = 0x01;

// Token bucket rate limiting (per-source IP)
/// rule_id = 0: global rate limiting (MAX_TOKENS=65536, REFILL=64000/sec)
pub const GLOBAL_RATE_LIMIT_RULE_ID: u32 = 0;
/// rule_id = 1+: per-rule rate limiting (used when ACL rule has rate > 0)
pub const RATE_LIMIT_RULE_ID: u32 = 1;
pub const MAX_TOKENS: u64 = 65_536;
pub const REFILL_TOKENS_PER_SEC: u64 = 64_000;
pub const MAX_REFILL_ELAPSED_NS: u64 = 1_000_000_000;
pub const PACKET_COST: u64 = 1;
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

// L4 ACL: prefix bits for LPM_TRIE. Covers entire L4AclKey
// (48 bytes) minus prefix_len field (u32 = 4 bytes) => 44 bytes = 352 bits.
// Used by BPF code when building search key in l4_acl.
pub const L4_ACL_PREFIX_LEN: u32 =
    (size_of::<L4AclKey>() - size_of::<u32>()) as u32 * 8;

// BPF map types (values from uapi/linux/bpf.h: BPF_MAP_TYPE_*)
// Note: BPF_MAP_TYPE_HASH and XSKMAP_TYPE already defined above
// (see lines 26-27), here are the rest.
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
pub const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
pub const BPF_MAP_TYPE_DEVMAP: u32 = 14;

pub const INVALID_BACKEND_ID: u32 = u32::MAX;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapKind {
    LpmTrie = 1,
    LruPercpuHash = 2,
    PercpuHash = 3,
    Array = 4,
    Ringbuf = 5,
    XskMap = 6,
    Hash = 7,
    PercpuArray = 8,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapSpec {
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

impl MapSpec {
    pub const fn new(
        kind: MapKind,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        flags: u32,
    ) -> Self {
        Self {
            kind,
            key_size,
            value_size,
            max_entries,
            flags,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug,Eq, PartialEq)]
pub enum AclAction {
    Allow = 0,
    Drop = 1,
    Redirect = 2,
    Inspect = 3,
}

#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpLpmData {
    pub family: u8,
    pub addr: [u8; 16],
    pub _pad: [u8; 3],
}


#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpLpmKey {
    pub prefix_len: u32,
    pub data: IpLpmData,
}

// IMPORTANT: field order chosen so dst_port comes BEFORE src_port.
// LPM_TRIE checks a single continuous bit prefix from the start of the key,
// therefore "any src_port + specific dst_port" cannot be expressed if
// src_port comes before dst_port (prefix would require src_port==0).
// With dst_port before src_port, the prefix can reach dst_port, excluding
// src_port (semantics "any src_port").
//
// Byte offsets (key 48 bytes, repr(C)):
//   0..4   prefix_len : u32
//   4      family     : u8
//   5..21  src_addr   : [u8;16]
//   21..37 dst_addr   : [u8;16]
//   37     ip_proto   : u8
//   38..40 dst_port   : u16  (BE)
//   40..42 src_port   : u16  (BE)
//   42     tcp_flags_mask : u8
//   43     tcp_flags_value: u8
//   44..46 _pad       : u16
//
// Prefix lengths (bits) from start of key:
//   family+src+dst+proto            = 38 bytes = 304
//   + dst_port                      = 40 bytes = 320
//   + src_port                      = 42 bytes = 336
//   + tcp_flags                     = 44 bytes = 352 (= L4_ACL_PREFIX_LEN)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct L4AclKey {
    pub prefix_len: u32,
    /*
     * L3
     */
    pub family: u8,
    pub src_addr: [u8;16],
    pub dst_addr: [u8;16],

    /*
     * L4
     */
    pub ip_proto: u8,

    pub dst_port: u16,
    pub src_port: u16,

    /*
     * TCP
     */
    pub tcp_flags_mask: u8,
    pub tcp_flags_value: u8,

    pub _pad: u16,
    pub _pad2: u16,
}

impl L4AclKey {
    /// Serialize key to exactly 48 bytes in kernel-expected format
    /// (LPM_TRIE key_size = 48). All multi-byte fields are LITTLE-ENDIAN
    /// (native for bpfel), since BPF stores u16/u32 fields of struct `L4AclKey`
    /// in native order, and LPM_TRIE compares raw bytes.
    ///
    /// Single source of layout — this structure. `ctl` and BPF must
    /// use the same `L4AclKey`, otherwise rules won't match. Field order
    /// (dst_port BEFORE src_port) is critical for LPM: otherwise
    /// "any src_port + specific dst_port" cannot be expressed.
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0..4].copy_from_slice(&self.prefix_len.to_le_bytes());
        b[4] = self.family;
        b[5..21].copy_from_slice(&self.src_addr);
        b[21..37].copy_from_slice(&self.dst_addr);
        b[37] = self.ip_proto;
        // Ports in little-endian (native for bpfel), BPF reads them directly
        b[38..40].copy_from_slice(&self.dst_port.to_le_bytes());
        b[40..42].copy_from_slice(&self.src_port.to_le_bytes());
        b[42] = self.tcp_flags_mask;
        b[43] = self.tcp_flags_value;
        b[44..46].copy_from_slice(&self._pad.to_le_bytes());
        b
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct L4AclValue {
    pub action: AclAction,
    pub priority: u32,
    pub backend_group: u32,
    pub flags: u32,
}

impl IpLpmKey {
    pub fn ipv4(prefix_len: u32, addr_be: [u8; 4]) -> Self {
        let data = IpLpmData {
            family: AF_INET,
            addr: [
                addr_be[0], addr_be[1], addr_be[2], addr_be[3],
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            _pad: [0, 0, 0],
        };
        Self {
            prefix_len: IP_LPM_FAMILY_BITS + prefix_len,
            data,
        }
    }
    pub fn ipv6(prefix_len: u32, addr_be: [u8; 16]) -> Self {
        let data = IpLpmData {
            family: AF_INET6,
            addr: addr_be,
            _pad: [0, 0, 0],
        };

        Self {
            prefix_len: IP_LPM_FAMILY_BITS + prefix_len,
            data,
        }
    }
}


#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AclValue {
    	pub action: AclAction,
    	pub priority: u32,
    	pub backend_group: u32,
    	pub flags: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowAclValue {
    	pub action: AclAction,
    	pub priority: u32,
    	pub backend_group: u32,
    	pub flags: u32,
}

#[repr(C, align(8))]
//#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowKey {
	pub src_addr: [u8; 16],
	pub dst_addr: [u8; 16],
	pub src_port: u16,
 	pub dst_port: u16,
 	pub family: u8,
 	pub ip_proto: u8,
 }

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConntrackState {
    New = 0,
    Established = 1,
    Closing = 2,
    Closed = 3,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConntrackValue {
    pub state: ConntrackState,
    pub flags: u32,
    pub backend_id: u32,
    pub _pad: u32,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateLimitKey {
    pub addr: [u8; 16],
    pub rule_id: u32,
    pub family: u8,
    pub _pad: [u8; 3],
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateLimitValue {
    pub tokens: u64,
    pub last_refill_ns: u64,
    pub packet_count: u64,
    pub byte_count: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(8))]
pub struct Backend {
    pub addr: [u8; 16],

    pub port: u16,
    pub family: u8,
    pub proto: u8,

    pub ifindex: u32,
    pub weight: u32,
    pub backend_group: u32,
    pub flags: u32,

    pub mac: [u8; 6],
    pub _pad: [u8; 2],
}

impl Backend {
    #[inline(always)]
    pub const fn is_configured(self) -> bool {
        self.ifindex != 0
    }

    #[inline(always)]
    pub const fn is_unhealthy(self) -> bool {
        self.flags & BACKEND_FLAG_UNHEALTHY != 0
    }
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LbMeta {
    pub num_backends: u32,
    pub _pad: u32,
}

/// ECMP hash over 5-tuple fields shared by XDP and TC programs.
#[inline(always)]
pub fn ecmp_hash(flow: &FlowKey) -> u32 {
    let mut hash = flow.ip_proto as u32;
    hash ^= flow.src_port as u32 ^ ((flow.src_port as u32) << 16);
    hash ^= flow.dst_port as u32 ^ ((flow.dst_port as u32) << 16);

    let mut i = 0;
    while i < 16 {
        hash ^= u32::from_be_bytes([
            flow.src_addr[i],
            flow.src_addr[i + 1],
            flow.src_addr[i + 2],
            flow.src_addr[i + 3],
        ]);
        hash ^= u32::from_be_bytes([
            flow.dst_addr[i],
            flow.dst_addr[i + 1],
            flow.dst_addr[i + 2],
            flow.dst_addr[i + 3],
        ]);
        i += 4;
    }

    hash
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    PacketDrop = 1,
    RateLimited = 2,
    ConntrackMiss = 3,
    BackendSelected = 4,
    SlowPath = 5,
    ServiceMatched=6,
    VlanDetected=7,
    PacketAllow=8
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    pub ts_ns: u64,
    pub kind: EventKind,
    pub ifindex: u32,
    pub flow: FlowKey,
    pub aux0: u64,
    pub aux1: u64,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterId {
    RxPackets = 0,
    RxBytes = 1,
    Passed = 2,
    Dropped = 3,
    Redirected = 4,
    ConntrackHit = 5,
    ConntrackMiss = 6,
    AclDrop = 7,
    AclAllow=8,
    AclRedirect=9,
    RateLimited = 10,
    ParseError = 11,
    TcFragment = 12,
    SlowPath = 13,
    HostFound = 14,
    RxIpv4 = 15,
    RxIpv6 = 16,
    RxIcmpv6=17,
	RxTcp=18,
	RxUdp=19,
    Unknown = 20,
    BackendUnavailable=21,
    RedirectFailed=22,
    BackendSelected=23,//debug
    ServiceMiss=24,
    ServiceHit=25,
	RxVlan=26,
}

pub const IP_ACL_MAP: MapSpec = MapSpec::new(
    MapKind::LpmTrie,
    size_of::<IpLpmKey>() as u32,
    size_of::<AclValue>() as u32,
    MAX_ACL_PREFIXES,
    BPF_F_NO_PREALLOC,
);

pub const FLOW_ACL_MAP: MapSpec = MapSpec::new(
    MapKind::Hash,
    size_of::<FlowKey>() as u32,
    size_of::<FlowAclValue>() as u32,
    MAX_FLOW_ACL_ENTRIES,
    0,
);

pub const CONNTRACK_MAP: MapSpec = MapSpec::new(
    MapKind::LruPercpuHash,
    size_of::<FlowKey>() as u32,
    size_of::<ConntrackValue>() as u32,
    MAX_CONNTRACK_ENTRIES,
    0,
);

pub const RATE_LIMIT_MAP: MapSpec = MapSpec::new(
    MapKind::PercpuHash,
    size_of::<RateLimitKey>() as u32,
    size_of::<RateLimitValue>() as u32,
    MAX_RATE_LIMIT_ENTRIES,
    0,
);

pub const LB_BACKENDS_MAP: MapSpec = MapSpec::new(
    MapKind::Array,
    size_of::<u32>() as u32,
    size_of::<Backend>() as u32,
    MAX_BACKENDS,
    0,
);

pub const LB_META_MAP: MapSpec = MapSpec::new(
    MapKind::Array,
    size_of::<u32>() as u32,
    size_of::<LbMeta>() as u32,
    1,
    0,
);

pub const EVENTS_MAP: MapSpec = MapSpec::new(MapKind::Ringbuf, 0, 0, EVENT_RINGBUF_BYTES, 0);

pub const EVENT_MASK_MAP: MapSpec = MapSpec::new(
    MapKind::Array,
    size_of::<u32>() as u32,
    size_of::<u64>() as u32,
    1,
    0,
);

pub const COUNTERS_MAP: MapSpec = MapSpec::new(
    MapKind::PercpuArray,
    size_of::<u32>() as u32,
    size_of::<u64>() as u32,
    MAX_COUNTERS,
    0,
);
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LbServiceKey {
    pub addr: [u8; 16],
    pub port: u16,
    pub proto: u8,
    pub family: u8,
}


#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LbService {
    pub backend_group: u32,
    pub scheduler: u8,
    pub flags: u8,
    pub _pad: u16,
    pub vip_addr:[u8;16],
    pub vip_port:u16,
    //pub backend_group:u32,
}


/// VLAN ACL key - supports single VLAN and QinQ (double VLAN)
/// - outer_vlan: always checked
/// - inner_vlan: if != 0, checked together with outer_vlan (QinQ)
///   If inner_vlan == 0, only outer_vlan is checked (single VLAN)
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VlanAclKey {
    /// Outer VLAN ID (0-4095) - always checked
    pub outer_vlan: u16,
    /// Inner VLAN ID (0-4095) - 0 = single VLAN, != 0 = QinQ
    pub inner_vlan: u16,
    /// 4 bytes padding for alignment to 8 bytes
    pub _pad: [u8; 4],
}

/// VLAN ACL value
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlanAclValue {
    pub action: AclAction,
    pub rate: u32,
}
#[repr(C)]
pub struct xdp_md {//XdpMd {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

#[derive(Clone, Copy)]
pub struct Packet {
    pub flow: FlowKey,
    pub len: u64,
    pub tcp_flags: u8,
    pub is_fragment: bool,
    pub payload_offset: usize,
    pub l3_offset: usize,
    pub l4_offset: usize,
    pub vlan_depth: u8,
    pub vlan: [VlanTag; MAX_VLAN_DEPTH],
}
#[derive(Clone, Copy, Default)]
pub struct VlanTag {
    pub id: u16,
    pub pcp: u8,
    pub dei: bool,
}
#[derive(Clone, Copy)]
pub enum ParseError {
    Unsupported,
    Malformed,
}
pub const VLAN_HDR_LEN: usize = 4;
pub const MAX_VLAN_DEPTH: usize = 2; // QinQ support
//const ETH_P_IP: u16     = 0x0800;
//const ETH_P_IPV6: u16   = 0x86DD;

pub const ETH_P_8021Q: u16  = 0x8100; // IEEE 802.1Q
pub const ETH_P_8021AD: u16 = 0x88A8; // IEEE 802.1ad (QinQ)


const _: () = {
    assert!(IPV4_MAX_PREFIX_BITS == 40);
    assert!(IPV6_MAX_PREFIX_BITS == 136);
    assert!(size_of::<IpLpmData>() == 20);
    assert!(size_of::<IpLpmKey>() == 24);
    assert!(size_of::<AclValue>() == 16);
    assert!(size_of::<FlowAclValue>() == 16);
    assert!(size_of::<FlowKey>() == 40);
    assert!(size_of::<ConntrackValue>() == 48);
    assert!(size_of::<RateLimitKey>() == 24);
    assert!(size_of::<RateLimitValue>() == 32);
    assert!(size_of::<Backend>() ==48);// 40);
    assert!(size_of::<LbMeta>() == 8);
    assert!(size_of::<Event>() == 72);
//    assert!(size_of::<L7AclKey>() == 16);
};
#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(size_of::<IpLpmKey>(), 24);
        assert_eq!(size_of::<AclValue>(), 16);
        assert_eq!(size_of::<FlowKey>(), 40);
        assert_eq!(size_of::<ConntrackValue>(), 48);
        assert_eq!(size_of::<RateLimitKey>(), 24);
        assert_eq!(size_of::<RateLimitValue>(), 32);
        assert_eq!(size_of::<Backend>(), 48);
        assert_eq!(size_of::<Event>(), 72);
    }

    #[test]
    fn test_ip_lpm_key_ipv4() {
        let key = IpLpmKey::ipv4(24, [192, 168, 1, 0]);
        assert_eq!(key.prefix_len, IP_LPM_FAMILY_BITS + 24);
        assert_eq!(key.data.family, AF_INET);
        assert_eq!(&key.data.addr[0..4], &[192, 168, 1, 0]);
    }

    #[test]
    fn test_flow_key_equality() {
        let k1 = FlowKey {
            src_addr: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_addr: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_port: 1234,
            dst_port: 80,
            family: AF_INET,
            ip_proto: IP_PROTO_TCP,
        };
        let k2 = k1;
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_acl_action_discriminants() {
        assert_eq!(AclAction::Allow as u32, 0);
        assert_eq!(AclAction::Drop as u32, 1);
        assert_eq!(AclAction::Redirect as u32, 2);
        assert_eq!(AclAction::Inspect as u32, 3);
    }
}
