use crate::KernelInterfaceError;
use crate::KernelInterfaceError as Error;
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;

/// Returns a kernel interface runtime error with the given message.
fn runtime_error<T>(msg: &str) -> Result<T, Error> {
    Err(KernelInterfaceError::RuntimeError(msg.to_string()))
}

/// Helper function for parsing out port number from local_address column
fn parse_local_port(s: &str) -> Result<u16, Error> {
    // second column in table contains local_address
    let local_addr = match s.split_whitespace().nth(1) {
        Some(addr) => addr,
        None => return runtime_error("Error parsing local_address column!"),
    };
    // having a format like "00000000:14E9"
    let port = match local_addr.split(':').nth(1) {
        Some(port) => port,
        None => return runtime_error("Error parsing local_address column!"),
    };

    match u16::from_str_radix(port, 16) {
        Ok(port) => Ok(port),
        Err(_) => runtime_error("Error parsing port from local_address column!"),
    }
}

fn read_udp_socket_table() -> Result<String, Error> {
    let mut f = File::open("/proc/net/udp")?;
    let mut contents = String::new();

    f.read_to_string(&mut contents)?;

    Ok(contents)
}

/// Returns list of ports in use as seen in the UDP socket table (/proc/net/udp)
pub fn used_ports() -> Result<HashSet<u16>, Error> {
    let udp_sockets_table = read_udp_socket_table()?;
    let mut lines = udp_sockets_table.split('\n');

    lines.next(); // advance iterator to skip header

    let ports: HashSet<u16> = lines
        .take_while(|line| !line.is_empty()) // until end of the table is reached,
        .map(parse_local_port) // parse each udp port,
        .filter_map(Result::ok) // only taking those which parsed successfully
        .collect();

    Ok(ports)
}

#[test]
pub fn test_parse_local_port_on_valid_string_successful() {
    let line = "1228: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 34229668 2 ffff88007cb08800 0";

    assert_eq!(parse_local_port(line).unwrap(), 5353)
}

#[test]
pub fn test_parse_local_port_failure_on_totally_malformed_string() {
    let line = "abcdefg";

    assert!(parse_local_port(line).is_err())
}

#[test]
pub fn test_parse_local_port_failure_on_malformed_local_address_column() {
    let line = "1228: 00000000_14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 34229668 2 ffff88007cb08800 0";

    assert!(parse_local_port(line).is_err())
}

#[test]
pub fn test_parse_local_port_failure_on_invalid_hex() {
    let line = "1228: 00000000:FFFG 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 34229668 2 ffff88007cb08800 0";

    assert!(parse_local_port(line).is_err())
}
