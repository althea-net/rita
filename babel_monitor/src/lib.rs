//! Babel monitor is an async futures based interface for the Babeld management interface
//! it provides abastractions over the major data this interface provides and an async
//! way to efficiently communicate with it.

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

pub mod parsing;
pub mod structs;

use crate::parsing::{read_babel_sync, validate_preamble};
use crate::structs::{BabelMonitorError, Route};
use parsing::{get_local_fee_sync, parse_interfaces_sync, parse_neighs_sync, parse_routes_sync};
use std::error::Error as ErrorTrait;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::iter::Iterator;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str::FromStr;
use std::str::{self};
use std::thread;
use std::time::Duration;
use structs::{BabeldInterfaceConfig, Interface, Neighbor};

/// we want to ceed the cpu just long enough for Babel
/// to finish what it's doing and warp up it's write
/// on multicore machines this is mostly a waste of time
/// on single core machines it avoids a spinlock until we
/// are pre-empted by the scheduler to allow Babel to finish the
/// job
const SLEEP_TIME: Duration = Duration::from_millis(10);

pub fn find_babel_val(val: &str, line: &str) -> Result<String, BabelMonitorError> {
    let mut iter = line.split(' ');
    while let Some(entry) = iter.next() {
        if entry == val {
            match iter.next() {
                Some(v) => return Ok(v.to_string()),
                None => continue,
            }
        }
    }
    trace!("find_babel_val warn! Can not find {} in {}", val, line);
    Err(BabelMonitorError::VariableNotFound(
        String::from(val),
        String::from(line),
    ))
}

pub fn find_and_parse_babel_val<T: FromStr>(val: &str, line: &str) -> Result<T, BabelMonitorError>
where
    <T as FromStr>::Err: Debug + ErrorTrait + Sync + Send + 'static,
    BabelMonitorError: From<<T as FromStr>::Err>,
{
    match find_babel_val(val, line) {
        Ok(string_val) => match string_val.parse() {
            Ok(parsed_val) => Ok(parsed_val),
            Err(e) => {
                warn!("Error parsing {} from {} with {:?}", val, line, e);
                Err(e.into())
            }
        },
        Err(e) => Err(e),
    }
}

/// Opens a tcpstream to the babel management socket using a standard timeout
/// for both the open and read operations
pub fn open_babel_stream(
    babel_port: u16,
    timeout: Duration,
) -> Result<TcpStream, BabelMonitorError> {
    let socket_string = format!("[::1]:{babel_port}");
    trace!("About to open Babel socket using {}", socket_string);
    let socket: SocketAddr = socket_string.parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&socket, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Consumes the automated Preamble and validates configuration api version
    info!("Starting babel connection");
    let result = read_babel(&mut stream, String::new(), 0)?;
    let preamble = result;
    validate_preamble(preamble)?;
    Ok(stream)
}

/// Read function, you should always pass an empty string to the previous contents field
/// it's used when the function does not find a babel terminator and needs to recuse to get
/// the full message
fn read_babel(
    stream: &mut TcpStream,
    previous_contents: String,
    depth: usize,
) -> Result<String, BabelMonitorError> {
    trace!(
        "starting read babel with {} and {}",
        previous_contents,
        depth
    );
    // 500kbytes / 0.5mbyte
    const BUFFER_SIZE: usize = 500_000;
    let mut buffer = vec![0; BUFFER_SIZE];

    let result = stream.read(&mut buffer);

    if let Err(e) = result {
        if e.kind() == ErrorKind::WouldBlock {
            // response is not yet on the wire wait for it
            thread::sleep(SLEEP_TIME);
            return read_babel(stream, previous_contents, depth + 1);
        } else {
            return Err(e.into());
        }
    }

    let bytes = result?;
    let full_buffer = bytes == BUFFER_SIZE;

    let output = String::from_utf8(buffer.to_vec());
    if let Err(e) = output {
        return Err(BabelMonitorError::TcpError(format!("{e:?}")));
    }
    let output = output?;
    let output = output.trim_matches(char::from(0));
    trace!(
        "Babel monitor got {} bytes with the message {}",
        bytes,
        output
    );

    // It's possible we caught babel in the middle of writing to the socket
    // if we don't see a terminator we either have an error in Babel or an error
    // in our code for expecting one. So it's safe for us to keep trying and building
    // a larger response until we see one. We terminate after 5 tries
    // There is also the possible case that our buffer is full, in that case recurse
    // with no retry limit immediately as we can simply go and read more
    let full_message = previous_contents + output;
    let babel_data = read_babel_sync(&full_message);
    if depth > 50 {
        // prevent infinite recursion in error cases
        warn!("Babel read timed out! {}", output);
        return Err(BabelMonitorError::ReadFailed(
            "Babel read timed out!".to_string(),
        ));
    } else if full_buffer {
        // our buffer is full, we should recurse right away
        warn!("Babel read larger than buffer! Consider increasing it's size");
        return read_babel(stream, full_message, depth);
    } else if let Err(BabelMonitorError::NoTerminator(_)) = babel_data {
        // our buffer was not full but we also did not find a terminator,
        // we must have caught babel while it was interrupted (only really happens
        // in single cpu situations)
        thread::sleep(SLEEP_TIME);
        info!("we didn't get the whole message yet, trying again");
        return read_babel(stream, full_message, depth + 1);
    } else if let Err(e) = babel_data {
        // some other error
        warn!("Babel read failed! {} {:?}", output, e);
        return Err(BabelMonitorError::ReadFailed(format!("{e:?}")));
    }
    let babel_data = babel_data?;

    Ok(babel_data)
}

pub fn run_command(stream: &mut TcpStream, cmd: &str) -> Result<String, BabelMonitorError> {
    info!("Running babel command {}", cmd);
    let cmd = format!("{cmd}\n");
    let bytes = cmd.as_bytes().to_vec();
    let out = stream.write_all(&bytes);

    match out {
        Ok(_) => {
            info!("Command write succeeded, returning output");
            read_babel(stream, String::new(), 0)
        }
        Err(e) => Err(BabelMonitorError::CommandFailed(cmd, format!("{e:?}"))),
    }
}

pub fn parse_interfaces(stream: &mut TcpStream) -> Result<Vec<Interface>, BabelMonitorError> {
    let output = run_command(stream, "dump")?;

    let babel_output = output;
    parse_interfaces_sync(babel_output)
}

/// Gets this routers local fee, what the router charges for bandwidth. The unit is wei (1*10-18 of a dollar) per byte
pub fn get_local_fee(stream: &mut TcpStream) -> Result<u32, BabelMonitorError> {
    let output = run_command(stream, "dump")?;

    let babel_output = output;
    get_local_fee_sync(babel_output)
}

/// Sets this routers local fee, what the router charges for bandwidth. The unit is wei (1*10-18 of a dollar) per byte
pub fn set_local_fee(stream: &mut TcpStream, new_fee: u32) -> Result<(), BabelMonitorError> {
    let result = run_command(stream, &format!("fee {new_fee}"))?;

    let _out = result;
    Ok(())
}

/// Sets the metric factor for babel. This is a weighting value used to decide if this router should select
/// routes based on price or quality of service. A higher value will cause the router to prefer routes with
/// higher quailty of service, a lower value will cause the router to prefer routes with lower price.
pub fn set_metric_factor(stream: &mut TcpStream, new_factor: u32) -> Result<(), BabelMonitorError> {
    let result = run_command(stream, &format!("metric-factor {new_factor}"))?;

    let _out = result;
    Ok(())
}

/// Sets the interval at which Babel will update it's routes from the kernel routing table. If set to zero Babel will only recieve
/// updates from the kernel as changes are made and will never perform a full dump.
pub fn set_kernel_check_interval(
    stream: &mut TcpStream,
    kernel_check_interval: Option<Duration>,
) -> Result<(), BabelMonitorError> {
    let interval = match kernel_check_interval {
        // unit is centiseconds
        Some(d) => (d.as_millis() / 100) as u16,
        None => 0,
    };
    let result = run_command(stream, &format!("kernel-check-interval {interval}"))?;

    let _out = result;
    Ok(())
}

/// Sets the default interface parameters for babel. These are applied at startup and can be overridden per interface, note if modified
/// at runtime then existing interfaces will not be updated.
pub fn set_interface_defaults(
    stream: &mut TcpStream,
    defaults: BabeldInterfaceConfig,
) -> Result<(), BabelMonitorError> {
    let mut command = "default ".to_string();
    command.push_str(&build_interface_config_string(defaults));
    let result = run_command(stream, &command)?;

    let _out = result;
    Ok(())
}

/// internal utility for building the configuration string
fn build_interface_config_string(config: BabeldInterfaceConfig) -> String {
    let mut command = String::new();
    if config.link_quality {
        command.push_str("link-quality yes ");
    } else {
        command.push_str("link-quality no ");
    }
    if config.split_horizon {
        command.push_str("split-horizon yes ");
    } else {
        command.push_str("split-horizon no ");
    }
    command.push_str(&format!("max-rtt-penalty {} ", config.max_rtt_penalty));
    command.push_str(&format!("rtt-min {} ", config.rtt_min));
    command.push_str(&format!("rtt-max {} ", config.rtt_max));
    command.push_str(&format!("hello-interval {} ", config.hello_interval));
    command.push_str(&format!("update-interval {} ", config.update_interval));
    command
}

/// Adds an interface to babel to monitor, neighbors will be discovered on this interface and routes will be advertised
/// optionally this interface can have it's own configuration parameters
pub fn monitor(
    stream: &mut TcpStream,
    iface: &str,
    options: Option<BabeldInterfaceConfig>,
) -> Result<(), BabelMonitorError> {
    let mut command = format!("interface {iface} ");
    if let Some(options) = options {
        command.push_str(&build_interface_config_string(options));
    }
    let result = run_command(stream, &command)?;

    trace!("Babel started monitoring: {}", iface);
    let _out = result;
    Ok(())
}

pub fn redistribute_ip(
    stream: &mut TcpStream,
    ip: &IpAddr,
    allow: bool,
) -> Result<String, BabelMonitorError> {
    let command = format!(
        "redistribute ip {}/128 {}",
        ip,
        if allow { "allow" } else { "deny" }
    );
    let result = run_command(stream, &command)?;

    let _out = result;
    read_babel(stream, String::new(), 0)
}

pub fn unmonitor(stream: &mut TcpStream, iface: &str) -> Result<(), BabelMonitorError> {
    let command = format!("flush interface {iface}");
    let iface = iface.to_string();
    let result = run_command(stream, &command)?;

    trace!("Babel stopped monitoring: {}", iface);
    let _out = result;
    Ok(())
}

pub fn parse_neighs(stream: &mut TcpStream) -> Result<Vec<Neighbor>, BabelMonitorError> {
    let result = run_command(stream, "dump")?;

    let output = result;
    parse_neighs_sync(output)
}

pub fn parse_routes(stream: &mut TcpStream) -> Result<Vec<Route>, BabelMonitorError> {
    let result = run_command(stream, "dump")?;

    let babel_out = result;
    parse_routes_sync(babel_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    static TABLE: &str =
"local fee 1024\n\
metric factor 1900\n\
add interface lo up false\n\
add interface wlan0 up true ipv6 fe80::1a8b:ec1:8542:1bd8 ipv4 10.28.119.131\n\
add interface wg0 up true ipv6 fe80::2cee:2fff:7380:8354 ipv4 10.0.236.201\n\
add interface wg44 up false\n\
add interface wg43 up true ipv6 fe80::d1fd:cb7a:e760:2ec0\n\
add neighbour 14f19a8 address fe80::2cee:2fff:648:8796 if wg0 reach ffff rxcost 256 txcost 256 rtt \
26.723 rttcost 912 cost 1168\n\
add neighbour 14f0640 address fe80::e841:e384:491e:8eb9 if wlan0 reach 9ff7 rxcost 512 txcost 256 \
rtt 19.323 rttcost 508 cost 1020\n\
add neighbour 14f05f0 address fe80::e9d0:498f:6c61:be29 if wlan0 reach feff rxcost 258 txcost 341 \
rtt 18.674 rttcost 473 cost 817\n\
add neighbour 14f0488 address fe80::e914:2335:a76:bda3 if wlan0 reach feff rxcost 258 txcost 256 \
rtt 22.805 rttcost 698 cost 956\n\
add xroute 10.28.119.131/32-::/0 prefix 10.28.119.131/32 from ::/0 metric 0\n\
add route 14f0820 prefix 10.28.7.7/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:5b:fe:c7 \
metric 1596 price 3072 fee 3072 refmetric 638 full-path-rtt 22.805 via fe80::e914:2335:a76:bda3 if wlan0\n\
add route 14f07a0 prefix 10.28.7.7/32 from 0.0.0.0/0 installed no id ba:27:eb:ff:fe:5b:fe:c7 \
metric 1569 price 5032 fee 5032 refmetric 752 full-path-rtt 42.805 via fe80::e9d0:498f:6c61:be29 if wlan0\n\
add route 14f06d8 prefix 10.28.20.151/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:c1:2d:d5 \
metric 817 price 4008 fee 4008 refmetric 0 full-path-rtt 18.674 via fe80::e9d0:498f:6c61:be29 if wlan0 \n\
add route 14f0548 prefix 10.28.244.138/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:d1:3e:ba \
metric 958 price 2048 fee 2048 refmetric 0 full-path-rtt 56.805 via fe80::e914:2335:a76:bda3 if wlan0\n\
add route 241fee0 prefix fdc5:5bcb:24ac:b35a:4b7f:146a:a2a1:bdc4/128 from ::/0 installed no id \
e6:95:6e:ff:fe:44:c4:12 metric 328 price 426000 fee 354600 refmetric 217 full-path-rtt 39.874 via fe80::6459:f009:c4b4:9971 if wg36
ok\n";

    static PREAMBLE: &str =
        "ALTHEA 0.1\nversion babeld-1.8.0-24-g6335378\nhost raspberrypi\nmy-id \
         ba:27:eb:ff:fe:09:06:dd\nok\n";

    static XROUTE_LINE: &str =
        "add xroute 10.28.119.131/32-::/0 prefix 10.28.119.131/32 from ::/0 metric 0";

    static ROUTE_LINE: &str =
        "add route 14f06d8 prefix 10.28.20.151/32 from 0.0.0.0/0 installed yes id \
         ba:27:eb:ff:fe:c1:2d:d5 metric 1306 price 4008 refmetric 0 full-path-rtt 18.674 via \
         fe80::e9d0:498f:6c61:be29 if wlan0";

    static PROBLEM_ROUTE_LINE: &str =
        "add route 241fee0 prefix fdc5:5bcb:24ac:b35a:4b7f:146a:a2a1:bdc4/128 \
         from ::/0 installed no id e6:95:6e:ff:fe:44:c4:12 metric 331 price 426000 fee 354600 refmetric 220 full-path-rtt \
         38.286 via fe80::6459:f009:c4b4:9971 if wg36";

    static NEIGH_LINE: &str =
        "add neighbour 14f05f0 address fe80::e9d0:498f:6c61:be29 if wlan0 reach ffff rxcost \
         256 txcost 256 rtt 29.264 rttcost 1050 cost 1306";

    static IFACE_LINE: &str =
        "add interface wlan0 up true ipv6 fe80::1a8b:ec1:8542:1bd8 ipv4 10.28.119.131";

    static PRICE_LINE: &str = "local price 1024";

    #[test]
    fn line_parse() {
        assert_eq!(find_babel_val("metric", XROUTE_LINE).unwrap(), "0");
        assert_eq!(
            find_babel_val("prefix", XROUTE_LINE).unwrap(),
            "10.28.119.131/32"
        );
        assert_eq!(find_babel_val("route", ROUTE_LINE).unwrap(), "14f06d8");
        assert_eq!(find_babel_val("if", ROUTE_LINE).unwrap(), "wlan0");
        assert_eq!(
            find_babel_val("via", ROUTE_LINE).unwrap(),
            "fe80::e9d0:498f:6c61:be29"
        );
        assert_eq!(
            find_babel_val("route", PROBLEM_ROUTE_LINE).unwrap(),
            "241fee0"
        );
        assert_eq!(find_babel_val("fee", PROBLEM_ROUTE_LINE).unwrap(), "354600");
        assert_eq!(
            find_babel_val("price", PROBLEM_ROUTE_LINE).unwrap(),
            "426000"
        );
        assert_eq!(find_babel_val("if", PROBLEM_ROUTE_LINE).unwrap(), "wg36");
        assert_eq!(
            find_babel_val("prefix", PROBLEM_ROUTE_LINE).unwrap(),
            "fdc5:5bcb:24ac:b35a:4b7f:146a:a2a1:bdc4/128"
        );
        assert_eq!(
            find_babel_val("full-path-rtt", PROBLEM_ROUTE_LINE).unwrap(),
            "38.286"
        );
        assert_eq!(find_babel_val("reach", NEIGH_LINE).unwrap(), "ffff");
        assert_eq!(find_babel_val("rxcost", NEIGH_LINE).unwrap(), "256");
        assert_eq!(find_babel_val("rtt", NEIGH_LINE).unwrap(), "29.264");
        assert_eq!(find_babel_val("interface", IFACE_LINE).unwrap(), "wlan0");
        assert_eq!(find_babel_val("ipv4", IFACE_LINE).unwrap(), "10.28.119.131");
        assert_eq!(find_babel_val("price", PRICE_LINE).unwrap(), "1024");
    }

    #[test]
    fn neigh_parse() {
        let neighs = parse_neighs_sync(TABLE.to_string()).unwrap();
        let neigh = neighs.first();
        assert!(neigh.is_some());
        let neigh = neigh.unwrap();
        assert_eq!(neighs.len(), 4);
        assert_eq!(neigh.id, "14f19a8");
    }

    #[test]
    fn route_parse() {
        let routes = parse_routes_sync(TABLE.to_string()).unwrap();
        assert_eq!(routes.len(), 5);

        let route = routes.first().unwrap();
        assert_eq!(route.price, 3072);
    }

    #[test]
    fn interfaces_parse() {
        let interfaces = parse_interfaces_sync(TABLE.to_string()).unwrap();
        assert_eq!(interfaces.len(), 5);

        let iface = interfaces.first().unwrap();
        assert!(!iface.up);
        let iface = interfaces.get(2).unwrap();
        assert_eq!(iface.ipv4, Some("10.0.236.201".parse().unwrap()));
        let iface = interfaces.get(3).unwrap();
        assert!(iface.ipv4.is_none());
        assert!(iface.ipv6.is_none());
        assert!(!iface.up);
        let iface = interfaces.get(4).unwrap();
        assert!(iface.up);
        assert!(iface.ipv6.is_some());
    }

    #[test]
    fn local_fee_parse() {
        assert_eq!(get_local_fee_sync(TABLE.to_string()).unwrap(), 1024);
    }

    #[test]
    fn multiple_babel_outputs_in_stream() {
        let input = PREAMBLE.to_string() + TABLE + "ok\n";
        let routes = parse_routes_sync(input).unwrap();
        assert_eq!(routes.len(), 5);

        let route = routes.first().unwrap();
        assert_eq!(route.price, 3072);
        // assert that these are equal within the minimum comparison difference
        // of float values
        assert!(route.full_path_rtt - 22.805 < f32::EPSILON.abs());
    }

    #[test]
    fn only_ok_in_output() {
        read_babel_sync("ok\n").unwrap();
    }
}
