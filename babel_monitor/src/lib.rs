//! Babel monitor is an async futures based interface for the Babeld management interface
//! it provides abastractions over the major data this interface provides and an async
//! way to efficiently communicate with it.

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
extern crate futures;

use failure::Error;
use futures::future;
use futures::future::result as future_result;
use futures::future::Either;
use futures::future::Future;
use ipnetwork::IpNetwork;
use std::error::Error as ErrorTrait;
use std::f32;
use std::fmt::Debug;
use std::iter::Iterator;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use tokio::io::read;
use tokio::io::write_all;
use tokio::net::tcp::ConnectFuture;
use tokio::net::TcpStream;
use tokio::timer::Delay;

#[derive(Debug, Fail)]
pub enum BabelMonitorError {
    #[fail(display = "variable '{}' not found in '{}'", _0, _1)]
    VariableNotFound(String, String),
    #[fail(display = "Invalid preamble: {}", _0)]
    InvalidPreamble(String),
    #[fail(display = "Could not find local fee in '{}'", _0)]
    LocalFeeNotFound(String),
    #[fail(display = "Command '{}' failed. {}", _0, _1)]
    CommandFailed(String, String),
    #[fail(display = "Erroneous Babel output:\n{}", _0)]
    ReadFailed(String),
    #[fail(display = "No terminator after Babel output:\n{}", _0)]
    NoTerminator(String),
    #[fail(display = "No Neighbor was found matching address:\n{}", _0)]
    NoNeighbor(String),
    #[fail(display = "Tokio had a failure while it was talking to babel:\n{}", _0)]
    TokioError(String),
}

use crate::BabelMonitorError::{
    CommandFailed, InvalidPreamble, LocalFeeNotFound, NoNeighbor, NoTerminator, ReadFailed,
    TokioError, VariableNotFound,
};

fn find_babel_val(val: &str, line: &str) -> Result<String, Error> {
    let mut iter = line.split(' ');
    while let Some(entry) = iter.next() {
        if entry == val {
            match iter.next() {
                Some(v) => return Ok(v.to_string()),
                None => continue,
            }
        }
    }
    warn!("find_babel_val warn! Can not find {} in {}", val, line);
    Err(VariableNotFound(String::from(val), String::from(line)).into())
}

fn find_and_parse_babel_val<T: FromStr>(val: &str, line: &str) -> Result<T, Error>
where
    <T as FromStr>::Err: Debug + ErrorTrait + Sync + Send + 'static,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub iface: String,
    pub xroute: bool,
    pub installed: bool,
    pub neigh_ip: IpAddr,
    pub prefix: IpNetwork,
    pub metric: u16,
    pub refmetric: u16,
    pub full_path_rtt: f32,
    pub price: u32,
    pub fee: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Neighbor {
    pub id: String,
    pub address: IpAddr,
    pub iface: String,
    pub reach: u16,
    pub txcost: u16,
    pub rxcost: u16,
    pub rtt: f32,
    pub rttcost: u16,
    pub cost: u16,
}

/// Opens a tcpstream to the babel management socket using a standard timeout
/// for both the open and read operations
pub fn open_babel_stream(babel_port: u16) -> ConnectFuture {
    let socket_string = format!("[::1]:{}", babel_port);
    trace!("About to open Babel socket using {}", socket_string);
    let socket: SocketAddr = socket_string.parse().unwrap();
    TcpStream::connect(&socket)
}

/// Read function, you should always pass an empty string to the previous contents field
/// it's used when the function does not find a babel terminator and needs to recuse to get
/// the full message
fn read_babel(
    stream: TcpStream,
    previous_contents: String,
    depth: usize,
) -> impl Future<Item = (TcpStream, String), Error = Error> {
    // 500kbytes / 0.5mbyte
    const BUFFER_SIZE: usize = 500_000;
    let buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
    read(stream, buffer.to_vec())
        .from_err()
        .and_then(move |result| {
            let (stream, buffer, bytes) = result;
            let full_buffer = bytes == BUFFER_SIZE;

            let output = String::from_utf8(buffer);
            if let Err(e) = output {
                return Box::new(future::err(TokioError(format!("{:?}", e)).into()))
                    as Box<dyn Future<Item = (TcpStream, String), Error = Error>>;
            }
            let output = output.unwrap();
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
            if depth > 5 {
                // prevent infinite recursion in error cases
                warn!("Babel read timed out! {}", output);
                return Box::new(future::err(
                    ReadFailed("Babel read timed out!".to_string()).into(),
                ))
                    as Box<dyn Future<Item = (TcpStream, String), Error = Error>>;
            } else if full_buffer {
                // our buffer is full, we should recurse right away
                warn!("Babel read larger than buffer! Consider increasing it's size");
                return Box::new(read_babel(stream, full_message, depth));
            } else if let Err(NoTerminator(_)) = babel_data {
                // our buffer was not full but we also did not find a terminator,
                // we must have caught babel while it was interupped (only really happens
                // in single cpu situations)
                let when = Instant::now() + Duration::from_millis(100);
                trace!("we didn't get the whole message yet, trying again");
                return Box::new(
                    Delay::new(when)
                        .map_err(move |e| panic!("timer failed; err={:?}", e))
                        .and_then(move |_| read_babel(stream, full_message, depth + 1)),
                );
            } else if let Err(e) = babel_data {
                // some other error
                warn!("Babel read failed! {} {:?}", output, e);
                return Box::new(future::err(ReadFailed(format!("{:?}", e)).into()));
            }
            let babel_data = babel_data.unwrap();

            Box::new(future::ok((stream, babel_data)))
        })
}

fn read_babel_sync(output: &str) -> Result<String, BabelMonitorError> {
    let mut ret = String::new();
    for line in output.lines() {
        ret.push_str(line);
        ret.push_str("\n");
        match line.trim() {
            "ok" => {
                trace!(
                    "Babel returned ok; full output:\n{}\nEND OF BABEL OUTPUT",
                    ret
                );
                return Ok(ret);
            }
            "bad" | "no" => {
                warn!(
                    "Babel returned bad/no; full output:\n{}\nEND OF BABEL OUTPUT",
                    ret
                );
                return Err(ReadFailed(ret));
            }
            _ => continue,
        }
    }
    trace!(
        "Terminator was never found; full output:\n{:?}\nEND OF BABEL OUTPUT",
        ret
    );
    Err(NoTerminator(ret))
}

pub fn run_command(
    stream: TcpStream,
    cmd: &str,
) -> impl Future<Item = (TcpStream, String), Error = Error> {
    trace!("Running babel command {}", cmd);
    let cmd = format!("{}\n", cmd);
    let bytes = cmd.as_bytes().to_vec();
    write_all(stream, bytes).then(move |out| {
        if out.is_err() {
            return Box::new(Either::A(future_result(Err(CommandFailed(
                cmd,
                format!("{:?}", out),
            )
            .into()))));
        }
        let (stream, _res) = out.unwrap();
        trace!("Command write succeeded, returning output");
        Box::new(Either::B(read_babel(stream, String::new(), 0)))
    })
}

// Consumes the automated Preamble and validates configuration api version
pub fn start_connection(stream: TcpStream) -> impl Future<Item = TcpStream, Error = Error> {
    trace!("Starting babel connection");
    read_babel(stream, String::new(), 0).then(|result| {
        if let Err(e) = result {
            return Err(e);
        }
        let (stream, preamble) = result.unwrap();
        validate_preamble(preamble)?;
        Ok(stream)
    })
}

fn validate_preamble(preamble: String) -> Result<(), Error> {
    // Note you have changed the config interface, bump to 1.1 in babel
    if preamble.contains("ALTHEA 0.1") {
        trace!("Attached OK to Babel with preamble: {}", preamble);
        Ok(())
    } else {
        Err(InvalidPreamble(preamble).into())
    }
}

pub fn get_local_fee(stream: TcpStream) -> impl Future<Item = (TcpStream, u32), Error = Error> {
    run_command(stream, "dump").then(|output| {
        if let Err(e) = output {
            return Err(e);
        }
        let (stream, babel_output) = output.unwrap();
        Ok((stream, get_local_fee_sync(babel_output)?))
    })
}

fn get_local_fee_sync(babel_output: String) -> Result<u32, Error> {
    let fee_entry = match babel_output.split('\n').next() {
        Some(entry) => entry,
        // Even an empty string wouldn't yield None
        None => return Err(LocalFeeNotFound(String::from("<Babel output is None>")).into()),
    };

    if fee_entry.contains("local fee") {
        let fee = find_babel_val("fee", fee_entry)?.parse()?;
        trace!("Retrieved a local fee of {}", fee);
        return Ok(fee);
    }

    Err(LocalFeeNotFound(String::from(fee_entry)).into())
}

pub fn set_local_fee(
    stream: TcpStream,
    new_fee: u32,
) -> impl Future<Item = TcpStream, Error = Error> {
    run_command(stream, &format!("fee {}", new_fee)).then(|result| {
        if let Err(e) = result {
            return Err(e);
        }
        let (stream, _out) = result.unwrap();
        Ok(stream)
    })
}

pub fn set_metric_factor(
    stream: TcpStream,
    new_factor: u32,
) -> impl Future<Item = TcpStream, Error = Error> {
    run_command(stream, &format!("metric-factor {}", new_factor)).then(|result| {
        if let Err(e) = result {
            return Err(e);
        }
        let (stream, _out) = result.unwrap();
        Ok(stream)
    })
}

pub fn monitor(stream: TcpStream, iface: &str) -> impl Future<Item = TcpStream, Error = Error> {
    let command = &format!(
        "interface {} max-rtt-penalty 500 enable-timestamps true",
        iface
    );
    let iface = iface.to_string();
    run_command(stream, &command).then(move |result| {
        if let Err(e) = result {
            return Err(e);
        }
        trace!("Babel started monitoring: {}", iface);
        let (stream, _out) = result.unwrap();
        Ok(stream)
    })
}

pub fn redistribute_ip(
    stream: TcpStream,
    ip: &IpAddr,
    allow: bool,
) -> impl Future<Item = (TcpStream, String), Error = Error> {
    let command = format!(
        "redistribute ip {}/128 {}",
        ip,
        if allow { "allow" } else { "deny" }
    );
    run_command(stream, &command).then(move |result| {
        if let Err(e) = result {
            return Either::A(future_result(Err(e)));
        }
        let (stream, _out) = result.unwrap();
        Either::B(read_babel(stream, String::new(), 0))
    })
}

pub fn unmonitor(stream: TcpStream, iface: &str) -> impl Future<Item = TcpStream, Error = Error> {
    let command = format!("flush interface {}", iface);
    let iface = iface.to_string();
    run_command(stream, &command).then(move |result| {
        if let Err(e) = result {
            return Err(e);
        }
        trace!("Babel stopped monitoring: {}", iface);
        let (stream, _out) = result.unwrap();
        Ok(stream)
    })
}

pub fn parse_neighs(
    stream: TcpStream,
) -> impl Future<Item = (TcpStream, Vec<Neighbor>), Error = Error> {
    run_command(stream, "dump").then(|result| {
        if let Err(e) = result {
            return Err(e);
        }
        let (stream, output) = result.unwrap();
        Ok((stream, parse_neighs_sync(output)?))
    })
}

fn parse_neighs_sync(output: String) -> Result<Vec<Neighbor>, Error> {
    let mut vector: Vec<Neighbor> = Vec::with_capacity(5);
    let mut found_neigh = false;
    for entry in output.split('\n') {
        if entry.contains("add neighbour") {
            found_neigh = true;
            let neigh = Neighbor {
                id: match find_babel_val("neighbour", entry) {
                    Ok(val) => val,
                    Err(_) => continue,
                },
                address: match find_and_parse_babel_val("address", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
                iface: match find_babel_val("if", entry) {
                    Ok(val) => val,
                    Err(_) => continue,
                },
                reach: match find_babel_val("reach", entry) {
                    Ok(val) => match u16::from_str_radix(&val, 16) {
                        Ok(val) => val,
                        Err(e) => {
                            warn!("Failed to convert reach {:?} {}", e, entry);
                            continue;
                        }
                    },
                    Err(_) => continue,
                },
                txcost: match find_and_parse_babel_val("txcost", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
                rxcost: match find_and_parse_babel_val("rxcost", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
                rtt: match find_and_parse_babel_val("rtt", entry) {
                    Ok(entry) => entry,
                    // it's possible that our neigh does not have rtt enabled, handle
                    Err(_) => 0.0,
                },
                rttcost: match find_and_parse_babel_val("rttcost", entry) {
                    Ok(entry) => entry,
                    // it's possible that our neigh does not have rtt enabled, handle
                    Err(_) => 0,
                },
                cost: match find_and_parse_babel_val("cost", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
            };
            vector.push(neigh);
        }
    }
    if vector.is_empty() && found_neigh {
        bail!("All Babel neigh parsing failed!")
    }
    Ok(vector)
}

pub fn parse_routes(
    stream: TcpStream,
) -> impl Future<Item = (TcpStream, Vec<Route>), Error = Error> {
    run_command(stream, "dump").then(|result| {
        if let Err(e) = result {
            return Err(e);
        }
        let (stream, babel_out) = result.unwrap();
        Ok((stream, parse_routes_sync(babel_out)?))
    })
}

pub fn parse_routes_sync(babel_out: String) -> Result<Vec<Route>, Error> {
    let mut vector: Vec<Route> = Vec::with_capacity(20);
    let mut found_route = false;
    trace!("Got from babel dump: {}", babel_out);

    for entry in babel_out.split('\n') {
        if entry.contains("add route") {
            trace!("Parsing 'add route' entry: {}", entry);
            found_route = true;
            let route = Route {
                id: match find_babel_val("route", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                iface: match find_babel_val("if", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                xroute: false,
                installed: match find_babel_val("installed", entry) {
                    Ok(value) => value.contains("yes"),
                    Err(_) => continue,
                },
                neigh_ip: match find_and_parse_babel_val("via", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                prefix: match find_and_parse_babel_val("prefix", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                metric: match find_and_parse_babel_val("metric", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                refmetric: match find_and_parse_babel_val("refmetric", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                full_path_rtt: match find_and_parse_babel_val("full-path-rtt", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                price: match find_and_parse_babel_val("price", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                fee: match find_and_parse_babel_val("fee", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
            };

            vector.push(route);
        }
    }
    if vector.is_empty() && found_route {
        bail!("All Babel route parsing failed!")
    }
    Ok(vector)
}

/// In this function we take a route snapshot then loop over the routes list twice
/// to find the neighbor local address and then the route to the destination
/// via that neighbor. This could be dramatically more efficient if we had the neighbors
/// local ip lying around somewhere.
pub fn get_route_via_neigh(
    neigh_mesh_ip: IpAddr,
    dest_mesh_ip: IpAddr,
    routes: &[Route],
) -> Result<Route, Error> {
    // First find the neighbors route to itself to get the local address
    for neigh_route in routes.iter() {
        // This will fail on v4 babel routes etc
        if let IpNetwork::V6(ref ip) = neigh_route.prefix {
            if ip.ip() == neigh_mesh_ip {
                let neigh_local_ip = neigh_route.neigh_ip;
                // Now we take the neigh_local_ip and search for a route via that
                for route in routes.iter() {
                    if let IpNetwork::V6(ref ip) = route.prefix {
                        if ip.ip() == dest_mesh_ip && route.neigh_ip == neigh_local_ip {
                            return Ok(route.clone());
                        }
                    }
                }
            }
        }
    }
    Err(NoNeighbor(neigh_mesh_ip.to_string()).into())
}

/// Very simple utility function to get a neighbor given a route that traverses that neighbor
pub fn get_neigh_given_route(route: &Route, neighs: &[Neighbor]) -> Option<Neighbor> {
    for neigh in neighs.iter() {
        if route.neigh_ip == neigh.address {
            return Some(neigh.clone());
        }
    }
    None
}

/// Checks if Babel has an installed route to the given destination
pub fn do_we_have_route(mesh_ip: &IpAddr, routes: &[Route]) -> Result<bool, Error> {
    for route in routes.iter() {
        if let IpNetwork::V6(ref ip) = route.prefix {
            if ip.ip() == *mesh_ip && route.installed {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
/// Returns the installed route to a given destination
pub fn get_installed_route(mesh_ip: &IpAddr, routes: &[Route]) -> Result<Route, Error> {
    let mut exit_route = None;
    for route in routes.iter() {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed && IpAddr::V6(ip.ip()) == *mesh_ip {
                exit_route = Some(route);
                break;
            }
        }
    }
    if exit_route.is_none() {
        bail!("No installed route to that destination!");
    }
    Ok(exit_route.unwrap().clone())
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
        let neigh = neighs.get(0);
        assert!(neigh.is_some());
        let neigh = neigh.unwrap();
        assert_eq!(neighs.len(), 4);
        assert_eq!(neigh.id, "14f19a8");
    }

    #[test]
    fn route_parse() {
        let routes = parse_routes_sync(TABLE.to_string()).unwrap();
        assert_eq!(routes.len(), 5);

        let route = routes.get(0).unwrap();
        assert_eq!(route.price, 3072);
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

        let route = routes.get(0).unwrap();
        assert_eq!(route.price, 3072);
        // assert that these are equal within the minimum comparison difference
        // of float values
        assert!(route.full_path_rtt - 22.805 < f32::EPSILON);
    }

    #[test]
    fn only_ok_in_output() {
        read_babel_sync("ok\n").unwrap();
    }
}
