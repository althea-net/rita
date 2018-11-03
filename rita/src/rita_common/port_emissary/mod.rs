extern crate netstat;

use rita_common::port_emissary::netstat::*;

/// Retrieves list of free, unused, ports.
pub fn used_ports() -> Result<Vec<u16>, Error> {
    let prot_flags = ProtocolFlags::UDP;
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let sockets_info = match get_sockets_info(af_flags, prot_flags) {
        Err(e) => return Err(e),
        Ok(info) => info,
    };

    let mut used_ports: Vec<u16> = Vec::new();

    for si in sockets_info {
        match si.protocol_socket_info {
            ProtocolSocketInfo::Udp(udp_si) => used_ports.push(udp_si.local_port),
            _ => continue,
        }
    }

    Ok(used_ports)
}

/// Retrieves list of free, unused, ports.
pub fn free_ports() -> Vec<u16> {
    if let Some(ports_inuse) = used_ports().ok() {
        (0..65535).filter(|s| !ports_inuse.contains(s)).collect()
    } else {
        Vec::new()
    }
}

#[test]
pub fn test_port_emissary_free_ports() {
    assert_eq!(free_ports().pop().unwrap(), 65534);
}
