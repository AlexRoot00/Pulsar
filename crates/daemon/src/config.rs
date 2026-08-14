use serde::Deserialize;
use serde::de::Deserializer;

fn flatten_addresses<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    if let serde_yaml::Value::String(s) = &value {
        return Ok(vec![s.clone()]);
    }
    let seq = value.as_sequence().ok_or_else(|| {
        serde::de::Error::custom("expected a sequence of addresses")
    })?;

    let mut result = Vec::new();
    for item in seq {
        match item {
            serde_yaml::Value::String(s) => result.push(s.clone()),
            serde_yaml::Value::Number(n) => result.push(n.to_string()),
            serde_yaml::Value::Sequence(inner) if inner.len() == 1 => {
                match &inner[0] {
                    serde_yaml::Value::String(s) => result.push(s.clone()),
                    serde_yaml::Value::Number(n) => result.push(n.to_string()),
                    _ => {
                        return Err(serde::de::Error::custom(
                            "invalid nested address element",
                        ))
                    }
                }
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "expected string or single-element sequence for address",
                ))
            }
        }
    }
    Ok(result)
}

  #[derive(Debug, Deserialize, Default)]
  pub struct Config {
      pub acl: AclConfig,
      pub logging: LoggingConfig,
      pub rate_limit: RateLimitConfig,
      pub monitoring: MonitoringConfig,
  }

#[derive(Debug, Deserialize, Default)]
  pub struct AclConfig {
      #[serde(default = "default_action")]
      pub default_action: String,
    pub allow: Vec<AclRule>,
    pub drop: Vec<AclRule>,
}

fn default_action() -> String {
    "allow".to_string()
}

#[derive(Debug, Deserialize, Default)]
pub struct AclRule {
    pub src: Option<AddrBlock>,
    pub dst: Option<AddrBlock>,
    pub vlan: Option<Vec<VlanSpec>>,
    pub rate: Option<u32>,
}

#[derive(Debug, Default)]
pub struct AddrBlock {
    pub addresses: Option<Vec<String>>,
    pub ports: Option<PortSpec>,
}

impl<'de> Deserialize<'de> for AddrBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            #[serde(default, deserialize_with = "flatten_addresses")]
            addresses: Vec<String>,
            ipv4: Option<IpList>,
            ipv6: Option<IpList>,
            ports: Option<PortSpec>,
        }

        let helper = Helper::deserialize(deserializer)?;
        let mut addresses = helper.addresses;
        if let Some(ipv4) = &helper.ipv4 {
            addresses.extend(ipv4.addresses.iter().cloned());
        }
        if let Some(ipv6) = &helper.ipv6 {
            addresses.extend(ipv6.addresses.iter().cloned());
        }
        let addresses = if addresses.is_empty() { None } else { Some(addresses) };
        Ok(AddrBlock {
            addresses,
            ports: helper.ports,
        })
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct IpList {
    #[serde(default, deserialize_with = "flatten_addresses")]
    pub addresses: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PortSpec {
    #[serde(default = "default_any")]
    pub number: String,
    #[serde(default = "default_tcp")]
    pub proto: String,
}

fn default_any() -> String {
    "any".to_string()
}

fn default_tcp() -> String {
    "tcp".to_string()
}

#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
pub enum VlanSpec {
    Simple(u16),
    QinQ {
        outer: u16,
        inner: Vec<u16>,
    },
    #[default]
    None,
}

impl VlanSpec {
    pub fn iter(&self) -> Vec<(u16, Option<u16>)> {
        match self {
            VlanSpec::Simple(v) => vec![(*v, None)],
            VlanSpec::QinQ { outer, inner } => inner.iter().map(|i| (*outer, Some(*i))).collect(),
            VlanSpec::None => vec![],
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct LoggingConfig {
    pub PacketDrop: bool,
    pub RateLimited: bool,
    pub ConntrackMiss: bool,
    pub BackendSelected: bool,
    pub SlowPath: bool,
    pub ServiceMatched: bool,
    pub VlanDetected: bool,
    pub PacketAllow: bool,
}

#[derive(Debug, Deserialize, Default)]
  pub struct RateLimitConfig {
      pub global: GlobalRateLimit,
      pub per_rule_multiplier: u32,
  }

#[derive(Debug, Deserialize, Default)]
  pub struct GlobalRateLimit {
      pub max_tokens: u64,
      pub refill_per_sec: u64,
  }

#[derive(Debug, Deserialize, Default)]
  pub struct MonitoringConfig {
      pub ringbuf_bytes: usize,
      pub poll_interval_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parse_config(yaml: &str) -> Result<Config, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    #[test]
    fn test_flat_addresses() {
        let yaml = r#"
src:
  addresses:
    - 192.168.0.2/32
    - 192.168.0.3/32
dst:
  addresses: [10.10.10.3]
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let src = rule.src.expect("src should be present");
        assert!(src.addresses.is_some());
        assert_eq!(src.addresses.unwrap().len(), 2);
        let dst = rule.dst.expect("dst should be present");
        assert_eq!(dst.addresses.unwrap().len(), 1);
    }

    #[test]
    fn test_single_string_address() {
        let yaml = r#"
src:
  addresses: 192.168.0.2/32
dst:
  addresses: 192.168.0.202/24
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let src = rule.src.unwrap();
        assert_eq!(src.addresses.unwrap(), vec!["192.168.0.2/32".to_string()]);
        let dst = rule.dst.unwrap();
        assert_eq!(dst.addresses.unwrap(), vec!["192.168.0.202/24".to_string()]);
    }

    #[test]
    fn test_flat_addresses_with_ipv6() {
        let yaml = r#"
src:
  addresses: [0.0.0.0/0]
  ipv6:
    addresses: ["::/0"]
dst:
  addresses: [10.10.10.3]
  ipv6:
    addresses: ["::/0"]
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let src = rule.src.unwrap();
        assert_eq!(src.addresses.unwrap().len(), 2);
        let dst = rule.dst.unwrap();
        assert_eq!(dst.addresses.unwrap().len(), 2);
    }

    #[test]
    fn test_nested_ipv4_still_works() {
        let yaml = r#"
src:
    ipv4:
      addresses: [192.168.0.2/32]
dst:
    ipv4:
      addresses: [0.0.0.0/0]
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let src = rule.src.unwrap();
        let src_addrs = src.addresses.unwrap();
        assert_eq!(src_addrs.len(), 1);
        assert_eq!(src_addrs[0], "192.168.0.2/32");
    }

    #[test]
    fn test_vlan_simple() {
        let yaml = r#"
vlan:
  - 300
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let vlan = rule.vlan.unwrap();
        assert_eq!(vlan.len(), 1);
        assert!(matches!(vlan[0], VlanSpec::Simple(300)));
    }

    #[test]
    fn test_vlan_qinq() {
        let yaml = r#"
vlan:
  - outer: 200
    inner:
      - 100
      - 101
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let vlan = rule.vlan.unwrap();
        assert_eq!(vlan.len(), 1);
        match &vlan[0] {
            VlanSpec::QinQ { outer, inner } => {
                assert_eq!(*outer, 200);
                assert_eq!(inner.len(), 2);
                assert_eq!(inner[0], 100);
                assert_eq!(inner[1], 101);
            }
            _ => panic!("expected QinQ"),
        }
    }

    #[test]
    fn test_vlan_qinq_single_inner() {
        let yaml = r#"
vlan:
  - outer: 130
    inner:
      - 100
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let vlan = rule.vlan.unwrap();
        assert_eq!(vlan.len(), 1);
        match &vlan[0] {
            VlanSpec::QinQ { outer, inner } => {
                assert_eq!(*outer, 130);
                assert_eq!(inner.len(), 1);
            }
            _ => panic!("expected QinQ"),
        }
    }

    #[test]
    fn test_vlan_mixed() {
        let yaml = r#"
vlan:
  - 300
  - outer: 200
    inner:
      - 100
      - 101
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let vlan = rule.vlan.unwrap();
        assert_eq!(vlan.len(), 2);
        assert!(matches!(vlan[0], VlanSpec::Simple(300)));
        match &vlan[1] {
            VlanSpec::QinQ { outer, inner } => {
                assert_eq!(*outer, 200);
                assert_eq!(inner.len(), 2);
            }
            _ => panic!("expected QinQ for second entry"),
        }
    }

    #[test]
    fn test_rule_with_vlan_no_src_dst() {
        let yaml = r#"
vlan:
  - 140
  - outer: 130
    inner:
      - 100
rate: 1
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        assert!(rule.src.is_none());
        assert!(rule.dst.is_none());
        assert_eq!(rule.rate, Some(1));
        assert_eq!(rule.vlan.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_full_config2_parse() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config2.yml");
        let content = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        let config: Config = parse_config(&content).expect("config2.yml should parse");
        assert_eq!(config.acl.default_action, "allow");
        assert_eq!(config.acl.allow.len(), 2);
        assert_eq!(config.acl.drop.len(), 2);
        assert_eq!(config.logging.PacketDrop, true);
        assert_eq!(config.rate_limit.global.max_tokens, 65536);
        assert_eq!(config.monitoring.ringbuf_bytes, 16777216);
    }

    #[test]
    fn test_config2_qinq_vlan_in_full_config() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config2.yml");
        let content = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        let config: Config = parse_config(&content).expect("config2.yml should parse");
        let first_rule = &config.acl.allow[0];
        let vlan = first_rule.vlan.as_ref().expect("first allow rule should have vlan");
        assert_eq!(vlan.len(), 2);
        assert!(matches!(vlan[0], VlanSpec::Simple(300)));
        match &vlan[1] {
            VlanSpec::QinQ { outer, inner } => {
                assert_eq!(*outer, 200);
                assert_eq!(*inner, vec![100, 101]);
            }
            _ => panic!("expected QinQ"),
        }
    }

    #[test]
    fn test_config2_drop_qinq_vlan() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config2.yml");
        let content = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        let config: Config = parse_config(&content).expect("config2.yml should parse");
        let drop_rule = &config.acl.drop[0];
        let vlan = drop_rule.vlan.as_ref().expect("first drop rule should have vlan");
        assert_eq!(vlan.len(), 2);
        assert!(matches!(vlan[0], VlanSpec::Simple(140)));
        match &vlan[1] {
            VlanSpec::QinQ { outer, inner } => {
                assert_eq!(*outer, 130);
                assert_eq!(*inner, vec![100]);
            }
            _ => panic!("expected QinQ"),
        }
    }

    #[test]
    fn test_config2_icmp_rule() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config2.yml");
        let content = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        let config: Config = parse_config(&content).expect("config2.yml should parse");
        let icmp_rule = &config.acl.drop[1];
        let src = icmp_rule.src.as_ref().unwrap();
        assert_eq!(src.addresses.as_ref().unwrap(), &vec!["fe80::/64".to_string()]);
        let dst = icmp_rule.dst.as_ref().unwrap();
        assert_eq!(dst.addresses.as_ref().unwrap(), &vec!["fe80::c274:2bff:fefa:720c".to_string()]);
        let ports = icmp_rule.dst.as_ref().unwrap().ports.as_ref().unwrap();
        assert_eq!(ports.number, "any");
        assert_eq!(ports.proto, "icmp");
    }

    #[test]
    fn test_nested_sequence_addresses() {
        let yaml = r#"
src:
  addresses:
    - [fe80::/64]
dst:
  addresses:
    - [fe80::c274:2bff:fefa:720c]
"#;
        let rule: AclRule = serde_yaml::from_str(yaml).unwrap();
        let src = rule.src.unwrap();
        assert_eq!(src.addresses.unwrap(), vec!["fe80::/64".to_string()]);
        let dst = rule.dst.unwrap();
        assert_eq!(dst.addresses.unwrap(), vec!["fe80::c274:2bff:fefa:720c".to_string()]);
    }
}