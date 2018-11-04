use std::fs::File;
use std::io::prelude::*;
use std::u16;

/// Helper function for parsing out port number from local_address column
fn take_local_port(s: &str) -> u16 {
    // second column in table contains local_address
    let local_addr = s.split_whitespace().nth(1).unwrap();
    // having a format like "00000000:14E9"
    let port = local_addr.split(":").nth(1).unwrap();

    u16::from_str_radix(port, 16).unwrap()
}

/// Returns list of ports in use as seen in the UDP socket table (/proc/net/udp)
fn used_ports() -> Vec<u16> {
    let mut f = File::open("/proc/net/udp").expect("UDP socket table not found!");
    let mut udp_sockets_table = String::new();

    f.read_to_string(&mut udp_sockets_table)
        .expect("Error reading UDP socket table!");

    let mut lines = udp_sockets_table.split("\n");

    lines.next(); // advance iterator to skip header

    let ports: Vec<u16> = lines
        .take_while(|line| line.len() > 0)
        .map(|line| take_local_port(line))
        .collect();

    ports
}

/// Returns a list of all those ports not found in the UDP socket table.
pub fn free_ports() -> Vec<u16> {
    (0..65535)
        .filter(|port| !(used_ports().contains(port)))
        .collect()
}

#[test]
pub fn test_port_emissary_free_ports() {
    assert_eq!(free_ports().pop().unwrap(), 65534);
}
