extern crate netstat;

use rita_common::port_emissary::netstat::*;

struct PortEmissary {
    free_ports: Vec<u16>,
}

impl PortEmissary {
    fn new() -> PortEmissary {
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let sockets_info = get_sockets_info(af_flags, ProtocolFlags::TCP).unwrap();

        let mut used_ports: Vec<u16> = Vec::new();
        for si in sockets_info {
            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_si) => used_ports.push(tcp_si.local_port),
                _ => continue,
            }
        }

        let free_ports: Vec<u16> = (0..65535).filter(|s| !used_ports.contains(s)).collect();

        PortEmissary { free_ports }
    }
}

pub fn free_ports() -> Vec<u16> {
    PortEmissary::new().free_ports
}

#[test]
pub fn test_port_emissary_free_ports() {
    assert_eq!(free_ports().pop().unwrap(), 65534);
}
