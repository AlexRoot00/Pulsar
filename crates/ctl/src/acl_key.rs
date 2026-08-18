//! Key/Value construction for `l4_acl` map (BPF_MAP_TYPE_LPM_TRIE).
//!
//! Key format is tightly coupled to what BPF code in
//! `ebpf-xdp/src/xdp_prog.rs` (see also `L4_ACL_NOTES.md`):
//!   - `family` MUST be 4 (common::AF_INET), NOT 2 (libc AF_INET).
//!     This was the main reason why manual rules silently never matched.
//!   - IPv4 address is placed in bytes 12..15 of the [u8;16] array in the
//!     normal IPv6 format (all first 12 bytes = 0, then IPv4): [0,0,0,0,0,0,0,0,0,0,0,0, a,b,c,d].
//!     This is critical for LPM with short prefixes (0.0.0.0/0).
//!   - `prefix_len` (in bits) covers only the fields that need to match.
//!     To ignore ports (any port) — use a shorter prefix.
//!
//! L4AclKey structure (48 bytes), field order:
//!   prefix_len : u32  (4)
//!   family     : u8   (1)
//!   src_addr   : [u8;16]
//!   dst_addr   : [u8;16]
//!   ip_proto   : u8   (1)
//!   dst_port   : u16  (2, big-endian in network order)  -- dst_port BEFORE src_port!
//!   src_port   : u16  (2, big-endian in network order)
//!   tcp_flags_mask : u8
//!   tcp_flags_value: u8
//!   _pad       : u16
//!
//! `prefix_len` is counted from the START of the key (including the 4-byte
//! `prefix_len`), so the base shift = 4 bytes. Prefix lengths (bits):
//!   only (family+src+12byte dst+proto) = 34 bytes = 272  (any port, full /24)
//!   + dst_port                             = 36 bytes = 288
//!   + src_port                             = 38 bytes = 304
//!   + tcp_flags                            = 40 bytes = 320

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

use common::AclAction;

/// Parse "any" or "<port>" from CLI argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortSpec {
    Any,
    Exact(u16),
}

impl PortSpec {
    pub fn parse(s: &str) -> Result<PortSpec, String> {
        if s.eq_ignore_ascii_case("any") || s == "*" {
            return Ok(PortSpec::Any);
        }
        let p: u16 = s
            .parse()
            .map_err(|_| format!("invalid port: '{s}' (expected number or 'any')"))?;
        Ok(PortSpec::Exact(p))
    }
}

/// L4 protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl Proto {
    pub fn parse(s: &str) -> Result<Proto, String> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            "icmp" => Ok(Proto::Icmp),
            "icmpv6" => Ok(Proto::Icmpv6),
            other => Err(format!("unknown proto: '{other}' (tcp|udp|icmp|icmpv6)")),
        }
    }

    pub fn ip_proto(self) -> u8 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
            Proto::Icmp => 1,
            Proto::Icmpv6 => 58,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Icmpv6 => "icmpv6",
        }
    }
}

/// IPv4 address (4 bytes) with CIDR notation support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4 {
    addr: [u8; 4],
    /// Prefix (mask) in bits. None = use automatic calculation.
    prefix: Option<u32>,
}

impl Ipv4 {
    /// Parse IPv4 address with optional CIDR notation.
    /// Supports formats: "192.168.0.1", "192.168.0.0/24", "0.0.0.0/0".
    pub fn parse(s: &str) -> Result<Ipv4, String> {
        let (addr_str, prefix_str) = s
            .split_once('/')
            .map(|(a, p)| (a, Some(p)))
            .unwrap_or((s, None));

        let parts: Vec<&str> = addr_str.split('.').collect();
        if parts.len() != 4 {
            return Err(format!("invalid IPv4: '{s}'"));
        }
        let mut octets = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            octets[i] = p
                .parse()
                .map_err(|_| format!("invalid octet '{p}' in '{s}'"))?;
        }

        let prefix = if let Some(p) = prefix_str {
            let p_bits: u32 = p
                .parse()
                .map_err(|_| format!("invalid prefix: '{p}' in '{s}'"))?;
            if p_bits > 32 {
                return Err(format!("prefix > 32: '{p}' in '{s}'"));
            }
            Some(p_bits)
        } else {
            None
        };

        Ok(Ipv4 {
            addr: octets,
            prefix,
        })
    }

    /// Return IPv4 address as [u8; 4].
    pub fn addr(&self) -> [u8; 4] {
        self.addr
    }

    /// Return prefix in bits.
    /// None = CIDR not set (default 32).
    pub fn prefix_bits(&self) -> Option<u32> {
        self.prefix.or(Some(32))
    }

    /// Convert to [u8;16] in IPv4-mapped IPv6 format (::ffff:w.x.y.z).
    pub fn to_mapped(&self) -> [u8; 16] {
        let [a, b, c, d] = self.addr;
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d]
    }

    /// Convert to [u8;16] for LPM (standard IPv6 format, all zeros before IPv4).
    /// This is required for correct LPM matching with short prefixes (0.0.0.0/0).
    /// If CIDR prefix is specified, host bits are zeroed.
    pub fn to_lpm(&self) -> [u8; 16] {
        let [a, b, c, d] = self.addr;
        let prefix = self.prefix.unwrap_or(32);

        // Zero out host bits based on CIDR prefix
        // For /N, we keep the first N bits and zero the rest
        let (a, b, c, d) = if prefix == 0 {
            (0, 0, 0, 0)
        } else if prefix >= 32 {
            (a, b, c, d)
        } else {
            // Create a mask for the network portion
            // For /N, mask has N leading 1-bits followed by (32-N) 0-bits
            let mask = if prefix == 32 {
                0xFFFF_FFFF
            } else {
                (!0u32) << (32 - prefix)
            };
            let addr = u32::from_be_bytes([a, b, c, d]) & mask;
            let [a, b, c, d] = addr.to_be_bytes();
            (a, b, c, d)
        };

        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d]
    }

    /// Extract IPv4 from ::ffff:-array [u8;16] (bytes 12..15).
    pub fn from_mapped(addr: &[u8; 16]) -> Self {
        Ipv4 {
            addr: [addr[12], addr[13], addr[14], addr[15]],
            prefix: None,
        }
    }
}

/// IPv6 address (16 bytes) with CIDR notation support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6 {
    addr: [u8; 16],
    /// Prefix (mask) in bits. None = use automatic calculation.
    prefix: Option<u32>,
}

impl Ipv6 {
    /// Parse IPv6 address with optional CIDR notation.
    /// Supports formats:
    /// - "2001:db8::1"
    /// - "2001:db8::/64"
    /// - "::1"
    /// - "::/0"
    pub fn parse(s: &str) -> Result<Ipv6, String> {
        let (addr_str, prefix_str) = s
            .split_once('/')
            .map(|(a, p)| (a, Some(p)))
            .unwrap_or((s, None));

        let addr = Self::parse_addr(addr_str)?;

        let prefix = if let Some(p) = prefix_str {
            let p_bits: u32 = p
                .parse()
                .map_err(|_| format!("invalid prefix: '{p}' in '{s}'"))?;
            if p_bits > 128 {
                return Err(format!("prefix > 128: '{p}' in '{s}'"));
            }
            Some(p_bits)
        } else {
            None
        };

        Ok(Ipv6 { addr, prefix })
    }

    /// Create Ipv6 from raw address and prefix.
    pub fn from_raw(addr: [u8; 16], prefix: Option<u32>) -> Self {
        Self { addr, prefix }
    }

    fn parse_addr(s: &str) -> Result<[u8; 16], String> {
        // Handle IPv4-mapped IPv6 (e.g., ::ffff:192.168.0.1)
        if s.contains('.') {
            // Split by last colon
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() < 2 {
                return Err(format!("invalid IPv6: '{s}'"));
            }
            let ipv4_part = parts.last().unwrap();
            let ipv4 = Ipv4::parse(ipv4_part).map_err(|e| format!("invalid IPv4 in IPv6: {e}"))?;
            let mut addr = [0u8; 16];
            addr[10] = 0xff;
            addr[11] = 0xff;
            addr[12..16].copy_from_slice(&ipv4.addr);
            return Ok(addr);
        }

        // Parse standard IPv6
        let parts: Vec<&str> = s.split(':').collect();

        // Handle :: compression - collapse consecutive empty parts into one marker
        let mut hextets = Vec::new();
        let mut seen_double_colon = false;
        let mut i = 0;
        while i < parts.len() {
            let part = parts[i];
            if part.is_empty() {
                if seen_double_colon {
                    return Err(format!("multiple :: in IPv6: '{s}'"));
                }
                seen_double_colon = true;
                hextets.push(None); // Marker for ::
                // Skip all consecutive empty parts (they represent the same ::)
                while i + 1 < parts.len() && parts[i + 1].is_empty() {
                    i += 1;
                }
            } else {
                let val = u16::from_str_radix(part, 16)
                    .map_err(|_| format!("invalid hextet '{part}' in '{s}'"))?;
                hextets.push(Some(val));
            }
            i += 1;
        }

        // Expand :: to zeros
        let hextets_len = hextets.len();
        let mut expanded = Vec::new();
        for hextet in hextets {
            if let Some(val) = hextet {
                expanded.push(val);
            } else {
                // :: expands to fill remaining to 8 hextets
                let needed = 8 - (hextets_len - 1); // -1 because None counts as one
                for _ in 0..needed {
                    expanded.push(0);
                }
            }
        }

        if expanded.len() != 8 {
            return Err(format!(
                "incorrect number of hextets in '{s}': {}",
                expanded.len()
            ));
        }

        let mut addr = [0u8; 16];
        for (i, val) in expanded.iter().enumerate() {
            addr[i * 2] = (val >> 8) as u8;
            addr[i * 2 + 1] = (val & 0xff) as u8;
        }

        Ok(addr)
    }

    /// Return IPv6 address as [u8; 16].
    pub fn addr(&self) -> [u8; 16] {
        self.addr
    }

    /// Return prefix in bits.
    /// None = CIDR not set (default 128).
    pub fn prefix_bits(&self) -> Option<u32> {
        self.prefix.or(Some(128))
    }

    /// Convert to [u8;16] for LPM (standard IPv6 format).
    /// Uses the full 16-byte IPv6 address. If CIDR prefix is specified, host bits are zeroed.
    pub fn to_lpm(&self) -> [u8; 16] {
        let prefix = self.prefix.unwrap_or(128);
        let mut addr = self.addr; // Use full 16-byte IPv6 address

        if prefix == 0 {
            return [0u8; 16];
        }

        let full_bytes = (prefix / 8) as usize; // How many full bytes to keep
        let remaining_bits = (prefix % 8) as u8; // Remaining bits in partial byte

        // Zero out bytes from position full_bytes to end
        for i in full_bytes..16 {
            addr[i] = 0;
        }

        // Apply mask to the partial byte if needed
        if remaining_bits > 0 && full_bytes < 16 {
            let mask = (!0u8) << (8 - remaining_bits);
            addr[full_bytes] &= mask;
        }

        addr
    }
}

/// Address for ACL rule (IPv4 or IPv6).
#[derive(Clone, Copy, Debug)]
pub enum AclAddr {
    V4(Ipv4),
    V6(Ipv6),
}

impl AclAddr {
    pub fn to_lpm(&self) -> [u8; 16] {
        match self {
            AclAddr::V4(v4) => v4.to_lpm(),
            AclAddr::V6(v6) => v6.to_lpm(),
        }
    }

    pub fn prefix_bits(&self) -> Option<u32> {
        match self {
            AclAddr::V4(v4) => v4.prefix_bits(),
            AclAddr::V6(v6) => v6.prefix_bits(),
        }
    }

    pub fn family(&self) -> u8 {
        match self {
            AclAddr::V4(_) => 4,  // AF_INET
            AclAddr::V6(_) => 10, // AF_INET6
        }
    }
}

/// Parse address with auto-detection of IPv4/IPv6.
pub fn parse_acl_addr(s: &str) -> Result<AclAddr, String> {
    if s.contains(':') {
        // IPv6
        Ok(AclAddr::V6(Ipv6::parse(s)?))
    } else {
        // IPv4
        Ok(AclAddr::V4(Ipv4::parse(s)?))
    }
}

/// L4 ACL rule parameters.
#[derive(Clone, Copy, Debug)]
pub struct AclRule {
    pub action: AclAction,
    pub src: AclAddr,
    pub dst: AclAddr,
    pub proto: Proto,
    pub sport: PortSpec,
    pub dport: PortSpec,
    /// If true — match on tcp_flags (not used by CLI, always 0).
    pub tcp_flags: u8,
    /// Rate limiting: packets per second. 0 = no rate limit.
    /// Stored in the `rate` field of the map value (L4AclValue / AclValue / FlowAclValue).
    pub rate: u32,
}

impl AclRule {
    /// Compute prefix_len (in bits) based on CIDR mask and ports.
    ///
    /// Logic:
    /// - Base prefix = 272 bits (prefix_len(4) + family(1) + src_addr(16) + dst_addr[0..12] + proto(1))
    ///   The base covers 12 bytes (96 bits) of dst_addr. For IPv4 in standard format,
    ///   these 12 bytes are zeros. The IPv4 address is in dst_addr[12..15].
    /// - For IPv4: if dst prefix > 0, we need ceil(dst_prefix/8) additional bytes
    ///   to cover the IPv4 address portion (since base covers 96 bits of zeros).
    /// - For IPv6: if dst prefix > 96, we need ceil((dst_prefix-96)/8) additional bytes.
    /// - Ports are added on top, if specified (for non-ICMP)
    pub fn prefix_len(&self) -> u32 {
        // Base prefix: prefix_len(4) + family(1) + src_addr(16) + dst_addr[0..12] + proto(1) = 34 bytes = 272 bits
        let mut bytes = 4u32 + 1 + 16 + 12 + 1; // 34 -> 272

        // Add bytes for dst_addr CIDR prefix
        if let Some(dst_prefix) = self.dst.prefix_bits() {
            if dst_prefix > 0 {
                let additional_bytes = match self.dst {
                    AclAddr::V4(_) => {
                        // IPv4: base covers 96 bits (12 zero bytes)
                        // Need additional bytes for the actual IPv4 address bits
                        // /8 -> 1 byte, /16 -> 2 bytes, /24 -> 3 bytes, /32 -> 4 bytes
                        let needed = (dst_prefix + 7) / 8; // ceil(dst_prefix / 8)
                        needed.min(4)
                    }
                    AclAddr::V6(_) => {
                        // IPv6: base covers 96 bits (12 bytes)
                        // Only need additional bytes if prefix > 96
                        if dst_prefix > 96 {
                            let needed = (dst_prefix - 96 + 7) / 8; // ceil((dst_prefix - 96) / 8)
                            needed.min(4)
                        } else {
                            0
                        }
                    }
                };
                bytes += additional_bytes;
            }
        }

        // ICMP does not have ports - do not add port bytes
        let is_icmp = matches!(self.proto, Proto::Icmp | Proto::Icmpv6);

        // dst_port comes BEFORE src_port in the key, so add it first.
        if !is_icmp {
            if let PortSpec::Exact(_) = self.dport {
                bytes += 2;
            }
            if let PortSpec::Exact(_) = self.sport {
                bytes += 2;
            }
        }
        if self.tcp_flags != 0 {
            bytes += 1;
        }
        bytes * 8
    }

    /// Build key (48 bytes), compatible with BPF.
    ///
    /// `ctl` does NOT build bytes manually and does not depend on the order of
    /// src/dst fields in `L4AclKey`. Instead it fills the structure
    /// `common::L4AclKey` (the single source of layout) and serializes
    /// through `L4AclKey::to_bytes()` — that same function determines the format
    /// for BPF. Thus `ctl` and kernel always use the identical key.
    pub fn build_key(&self) -> Vec<u8> {
        // For LPM use standard IPv6 format (all zeros before IPv4),
        // so prefixes like 0.0.0.0/0 (prefix_len=0) match correctly
        let src_addr = self.src.to_lpm();
        let dst_addr = self.dst.to_lpm();
        let ip_proto = self.proto.ip_proto();
        let family = self.src.family();

        // ICMP does not have ports - always 0
        let is_icmp = matches!(self.proto, Proto::Icmp | Proto::Icmpv6);

        // Exact-port writes as is; Any => 0 (field outside prefix, LPM
        // ignores). Value 0 is correct for "any", and for real
        // port 0 (impossible in TCP/UDP).
        let sport_raw =
            if is_icmp { 0 }
            else {
            match self.sport {
                PortSpec::Exact(s) => s,
                PortSpec::Any => 0,
            }
        };
        let dport_raw = 
            if is_icmp { 0 } 
        else {
            match self.dport {
                PortSpec::Exact(d) => d,
                PortSpec::Any => 0,
            }
        };

        let key = common::L4AclKey {
            prefix_len: self.prefix_len(),
            family,
            src_addr,
            dst_addr,
            ip_proto,
            dst_port: dport_raw,
            src_port: sport_raw,
            tcp_flags_mask: 0,
            tcp_flags_value: 0,
            _pad: 0,
            _pad2: 0,
        };
        key.to_bytes().to_vec()
    }

    /// Build value (16 bytes).
    ///   action: u32 LE, rate: u32 LE, backend_group: u32 LE, flags: u32 LE
    pub fn build_value(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&(self.action as u32).to_le_bytes()); // action = Drop(1)
        v.extend_from_slice(&self.rate.to_le_bytes()); // rate: packets per second
        v.extend_from_slice(&0u32.to_le_bytes()); // backend_group
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        debug_assert_eq!(v.len(), 16, "l4_acl value must be exactly 16 bytes");
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::AclAction;

    /// Drop TCP 192.168.0.221 -> 192.168.0.202 (any port).
    /// With CIDR /32: prefix_len = 304 bits (38 bytes)
    #[test]
    fn test_drop_any_port_matches_notes() {
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("192.168.0.221").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("192.168.0.202").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };

        let key = rule.build_key();
        assert_eq!(key.len(), 48, "l4_acl key must be exactly 48 bytes");
        // prefix_len = 304 little-endian -> 30 01 00 00
        assert_eq!(&key[0..4], &[0x30, 0x01, 0x00, 0x00]);
        // family right after prefix_len, MUST be 4, not 2
        assert_eq!(key[4], 4, "family MUST be 4, not 2");
        // src_addr in bytes 5..21, IPv4 in position 12..15 (standard IPv6 format)
        assert_eq!(&key[17..21], &[192, 168, 0, 221], "src in position 12..15");
        // dst_addr in bytes 21..37, IPv4 in position 12..15
        assert_eq!(&key[33..37], &[192, 168, 0, 202], "dst in position 12..15");
        assert_eq!(key[37], 6); // ip_proto = tcp
        assert_eq!(&key[38..40], &[0, 0]); // dst_port = 0 (any)
        assert_eq!(&key[40..42], &[0, 0]); // src_port = 0 (any)

        // value = 16 bytes, action=Drop(1) LE, rate=0
        let val = rule.build_value();
        assert_eq!(val.len(), 16);
        assert_eq!(&val[0..4], &[1, 0, 0, 0]);
        assert_eq!(&val[4..8], &[0, 0, 0, 0]); // rate = 0
    }

    /// Drop TCP src 192.168.0.221:1234 -> dst 192.168.0.202:80 (exact port).
    /// Prefix = 304 + 2 (dst_port) + 2 (src_port) = 336 bits.
    #[test]
    fn test_exact_port_prefix_336() {
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("192.168.0.221").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("192.168.0.202").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Exact(1234),
            dport: PortSpec::Exact(80),
            tcp_flags: 0,
            rate: 0,
        };
        let key = rule.build_key();
        assert_eq!(key.len(), 48);
        // 336 LE = 50 01 00 00
        assert_eq!(&key[0..4], &[0x50, 0x01, 0x00, 0x00]);
        // dst_port = 80 LE -> [80, 0] (bytes 38..40, BEFORE src_port)
        assert_eq!(&key[38..40], &[80, 0]);
        // src_port = 1234 LE -> [210, 4] (bytes 40..42)
        assert_eq!(&key[40..42], &[210, 4]);
    }

    /// Drop TCP src :any -> dst :80. Key case: match on dst_port.
    /// Prefix = 304 + 2 (dst_port) = 320 bits.
    #[test]
    fn test_any_src_exact_dst_port() {
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("192.168.0.221").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("192.168.0.202").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Exact(80),
            tcp_flags: 0,
            rate: 0,
        };
        let key = rule.build_key();
        assert_eq!(key.len(), 48);
        // 320 LE = 40 01 00 00
        assert_eq!(&key[0..4], &[0x40, 0x01, 0x00, 0x00]);
        // dst_port = 80 LE -> [80, 0]
        assert_eq!(&key[38..40], &[80, 0]); // dst_port = 80 (LE)
        assert_eq!(&key[40..42], &[0, 0]); // src_port = 0, but OUTSIDE prefix
    }

    #[test]
    fn test_udp_proto() {
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("10.0.0.1").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("10.0.0.2").unwrap()),
            proto: Proto::Udp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(rule.build_key()[37], 17);
    }

    #[test]
    fn test_cidr_prefix() {
        // Test with CIDR /0 (match all)
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("0.0.0.0/0").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("192.168.0.202").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        // src.prefix = 0, dst.prefix = 32
        // bytes = 34 (base) + 4 (dst) = 38, prefix_len = 304
        assert_eq!(rule.prefix_len(), 304);
    }

    #[test]
    fn test_ipv4_cidr_prefixes() {
        // Test IPv4 dst CIDR /24 - should add 3 bytes (24 bits = 3 bytes)
        // base 34 + 3 = 37 bytes = 296 bits
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("192.168.0.0/24").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("10.0.0.0/24").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(
            rule.prefix_len(),
            296,
            "IPv4 /24 dst prefix should be 296 bits"
        );

        // Test IPv4 dst CIDR /16 - should add 2 bytes
        // base 34 + 2 = 36 bytes = 288 bits
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("192.168.0.0/24").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("10.0.0.0/16").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(
            rule.prefix_len(),
            288,
            "IPv4 /16 dst prefix should be 288 bits"
        );

        // Test IPv4 dst CIDR /8 - should add 1 byte
        // base 34 + 1 = 35 bytes = 280 bits
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("192.168.0.0/24").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("10.0.0.0/8").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(
            rule.prefix_len(),
            280,
            "IPv4 /8 dst prefix should be 280 bits"
        );

        // Test IPv4 dst CIDR /0 - should add 0 bytes (match all)
        // base 34 + 0 = 34 bytes = 272 bits
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V4(Ipv4::parse("192.168.0.0/24").unwrap()),
            dst: AclAddr::V4(Ipv4::parse("0.0.0.0/0").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(
            rule.prefix_len(),
            272,
            "IPv4 /0 dst prefix should be 272 bits"
        );
    }

    #[test]
    fn test_ipv6_cidr_prefixes() {
        // Test IPv6 dst CIDR /128 - should add 4 bytes
        // base 34 + 4 = 38 bytes = 304 bits
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V6(Ipv6::parse("2001:db8::1/128").unwrap()),
            dst: AclAddr::V6(Ipv6::parse("2001:db8::2/128").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(
            rule.prefix_len(),
            304,
            "IPv6 /128 dst prefix should be 304 bits"
        );

        // Test IPv6 dst CIDR /64 - should add 0 bytes (base covers 96 bits)
        // base 34 + 0 = 34 bytes = 272 bits
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V6(Ipv6::parse("2001:db8::1/128").unwrap()),
            dst: AclAddr::V6(Ipv6::parse("2001:db8:0:0:0:0:0:0/64").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(
            rule.prefix_len(),
            272,
            "IPv6 /64 dst prefix should be 272 bits"
        );

        // Test IPv6 dst CIDR /96 - should add 0 bytes (base covers 96 bits)
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V6(Ipv6::parse("2001:db8::1/128").unwrap()),
            dst: AclAddr::V6(Ipv6::parse("2001:db8:0:1:0:0:0:0/96").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(
            rule.prefix_len(),
            272,
            "IPv6 /96 dst prefix should be 272 bits"
        );

        // Test IPv6 dst CIDR /112 - should add 2 bytes (112-96=16 bits = 2 bytes)
        // base 34 + 2 = 36 bytes = 288 bits
        let rule = AclRule {
            action: AclAction::Drop,
            src: AclAddr::V6(Ipv6::parse("2001:db8::1/128").unwrap()),
            dst: AclAddr::V6(Ipv6::parse("2001:db8:0:1:0:0:0:1/112").unwrap()),
            proto: Proto::Tcp,
            sport: PortSpec::Any,
            dport: PortSpec::Any,
            tcp_flags: 0,
            rate: 0,
        };
        assert_eq!(
            rule.prefix_len(),
            288,
            "IPv6 /112 dst prefix should be 288 bits"
        );
    }
}
