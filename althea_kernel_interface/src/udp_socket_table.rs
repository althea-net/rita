use std::fs::File;
use std::io::prelude::*;
use std::u16;

use super::KernelInterfaceError;
use failure::Error;

/// Helper function for parsing out port number from local_address column
fn parse_local_port(s: &str) -> Result<u16, Error> {
    // second column in table contains local_address
    let local_addr = match s.split_whitespace().nth(1) {
        Some(addr) => addr,
        None => {
            return Err(KernelInterfaceError::RuntimeError(
                "Error parsing local_address column!",
            ))
        }
    };
    // having a format like "00000000:14E9"
    let port = match local_addr.split(":").nth(1) {
        Some(port) => port,
        None => {
            return Err(KernelInterfaceError::RuntimeError(
                "Error parsing local_address column!",
            ))
        }
    };

    match u16::from_str_radix(port, 16) {
        Ok(port) => Ok(port),
        Err(err) => Err(KernelInterfaceError::RuntimeError(
            "Error parsing port from local_address column!",
        )),
    }
}

/// Returns list of ports in use as seen in the UDP socket table (/proc/net/udp)
fn used_ports() -> Result<Vec<u16>, Error> {
    let mut f = match File::open("/proc/net/udp") {
        Ok(file) => file,
        Err(err) => return Err(err),
    };
    let mut udp_sockets_table = String::new();

    if f.read_to_string(&mut udp_sockets_table).is_err() {
        return Err(KernelInterfaceError::RuntimeError(
            "Error reading UDP socket table!",
        ));
    };

    let mut lines = udp_sockets_table.split("\n");

    lines.next(); // advance iterator to skip header

    let ports: Vec<u16> = lines
        .take_while(|line| line.len() > 0)
        .map(|line| parse_local_port(line))
        .filter_map(Result::ok)
        .collect();

    Ok(ports)
}

/// Returns a list of all those ports not found in the UDP socket table.
pub fn free_ports() -> Result<Vec<u16>, Error> {
    let ports_inuse = used_ports()?;
    Ok((0..65535)
        .filter(|port| !(ports_inuse.contains(port)))
        .collect())
}

#[test]
pub fn test_port_emissary_free_ports() {
    assert_eq!(free_ports().pop().unwrap(), 65534);
}
