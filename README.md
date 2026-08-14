# Pulsar

Pulsar is a high-performance programmable network security dataplane built with Rust and eBPF.

The project is designed to provide high-speed packet processing in the Linux kernel while maintaining a modular architecture. It combines packet filtering, traffic control, and service delivery into a single programmable dataplane.

## Features

### XDP Module

- IPv4 / IPv6 packet parsing
- Ethernet frame processing
- VLAN / QinQ support
- Access Control Lists (ACL)
- Rate limiting
- Load balancing
- Connection tracking (WIP)
- Packet statistics
- Event reporting

### Control Plane

- CLI management utility
- Control daemon (planned)
- eBPF map management
- Rule management

## Build

```bash
git clone https://github.com/AlexRoot00/pulsar.git
cd pulsar


cargo build --release -p pulsar-ctl
```

## Running

```bash
sudo ./target/release/pulsar-agent
sudo ./target/release/pulsar-ctl
```

## Project Status

Current development focuses on:

- XDP dataplane
- ACL
- VLAN/QinQ
- Rate limiting
- Load balancing
- Control plane

Planned:

- NAT
- VXLAN
- EVPN
- BGP integration
- Distributed control plane

## Testing

The project is currently tested on:

- Linux Kernel 6.x
- XDP (native mode)
- Virtual Ethernet (veth)
- Network namespaces
- VLAN
- QinQ
- IPv4
- IPv6

## License

Apache-2.0
