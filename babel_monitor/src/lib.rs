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

use ipnetwork::{IpNetwork, IpNetworkError};
use std::error::Error as ErrorTrait;
use std::f32;
use std::fmt::Debug;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::iter::Iterator;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::{AddrParseError, IpAddr};
use std::num::{ParseFloatError, ParseIntError};
use std::str::FromStr;
use std::str::{self, ParseBoolError};
use std::thread;
use std::time::Duration;

/// we want to ceed the cpu just long enough for Babel
/// to finish what it's doing and warp up it's write
/// on multicore machines this is mostly a waste of time
/// on single core machines it avoids a spinlock until we
/// are pre-empted by the scheduler to allow Babel to finish the
/// job
const SLEEP_TIME: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub enum BabelMonitorError {
    VariableNotFound(String, String),
    InvalidPreamble(String),
    LocalFeeNotFound(String),
    CommandFailed(String, String),
    ReadFailed(String),
    NoTerminator(String),
    NoNeighbor(String),
    TcpError(String),
    BabelParseError(String),
    ReadFunctionError(std::io::Error),
    BoolParseError(ParseBoolError),
    ParseAddrError(AddrParseError),
    IntParseError(ParseIntError),
    FloatParseError(ParseFloatError),
    NetworkError(IpNetworkError),
    TokioError(String),
    NoRoute(String),
    MiscStringError(String),
}

use crate::BabelMonitorError::{
    CommandFailed, InvalidPreamble, LocalFeeNotFound, NoNeighbor, NoTerminator, ReadFailed,
    TcpError, VariableNotFound,
};

impl From<std::io::Error> for BabelMonitorError {
    fn from(error: std::io::Error) -> Self {
        BabelMonitorError::ReadFunctionError(error)
    }
}
impl From<ParseBoolError> for BabelMonitorError {
    fn from(error: ParseBoolError) -> Self {
        BabelMonitorError::BoolParseError(error)
    }
}
impl From<AddrParseError> for BabelMonitorError {
    fn from(error: AddrParseError) -> Self {
        BabelMonitorError::ParseAddrError(error)
    }
}
impl From<ParseIntError> for BabelMonitorError {
    fn from(error: ParseIntError) -> Self {
        BabelMonitorError::IntParseError(error)
    }
}
impl From<ParseFloatError> for BabelMonitorError {
    fn from(error: ParseFloatError) -> Self {
        BabelMonitorError::FloatParseError(error)
    }
}
impl From<IpNetworkError> for BabelMonitorError {
    fn from(error: IpNetworkError) -> Self {
        BabelMonitorError::NetworkError(error)
    }
}

impl Display for BabelMonitorError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            BabelMonitorError::VariableNotFound(a, b) => {
                write!(f, "variable '{}' not found in '{}'", a, b,)
            }
            BabelMonitorError::InvalidPreamble(a) => write!(f, "Invalid preamble: {}", a,),
            BabelMonitorError::LocalFeeNotFound(a) => {
                write!(f, "Could not find local fee in '{}'", a,)
            }
            BabelMonitorError::CommandFailed(a, b) => write!(f, "Command '{}' failed. {}", a, b,),
            BabelMonitorError::ReadFailed(a) => write!(f, "Erroneous Babel output:\n{}", a,),
            BabelMonitorError::NoTerminator(a) => {
                write!(f, "No terminator after Babel output:\n{}", a,)
            }
            BabelMonitorError::NoNeighbor(a) => {
                write!(f, "No Neighbor was found matching address:\n{}", a,)
            }
            BabelMonitorError::TcpError(a) => {
                write!(f, "Tcp connection failure while talking to babel:\n{}", a,)
            }
            BabelMonitorError::BabelParseError(a) => write!(f, "Babel parsing failed:\n{}", a,),
            BabelMonitorError::ReadFunctionError(e) => write!(f, "{}", e),
            BabelMonitorError::BoolParseError(e) => write!(f, "{}", e),
            BabelMonitorError::ParseAddrError(e) => write!(f, "{}", e),
            BabelMonitorError::IntParseError(e) => write!(f, "{}", e),
            BabelMonitorError::FloatParseError(e) => write!(f, "{}", e),
            BabelMonitorError::NetworkError(e) => write!(f, "{}", e),
            BabelMonitorError::NoRoute(a) => write!(f, "Route not found:\n{}", a,),
            BabelMonitorError::TokioError(a) => write!(
                f,
                "Tokio had a failure while it was talking to babel:\n{}",
                a,
            ),
            BabelMonitorError::MiscStringError(a) => write!(f, "{}", a,),
        }
    }
}

impl std::error::Error for BabelMonitorError {}

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
    Err(VariableNotFound(String::from(val), String::from(line)))
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub up: bool,
    pub ipv6: Option<IpAddr>,
    pub ipv4: Option<IpAddr>,
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
pub fn open_babel_stream(
    babel_port: u16,
    timeout: Duration,
) -> Result<TcpStream, BabelMonitorError> {
    let socket_string = format!("[::1]:{}", babel_port);
    trace!("About to open Babel socket using {}", socket_string);
    let socket: SocketAddr = socket_string.parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&socket, timeout).expect("connect_timeout error");
    stream
        .set_read_timeout(Some(timeout))
        .expect("set_read_timeout failed");
    stream
        .set_write_timeout(Some(timeout))
        .expect("set_write_timeout failed");

    // Consumes the automated Preamble and validates configuration api version
    info!("Starting babel connection");
    let result = read_babel(&mut stream, String::new(), 0);
    if let Err(e) = result {
        return Err(e);
    }
    let preamble = result.unwrap();
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
        return Err(TcpError(format!("{:?}", e)));
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
    if depth > 50 {
        // prevent infinite recursion in error cases
        warn!("Babel read timed out! {}", output);
        return Err(ReadFailed("Babel read timed out!".to_string()));
    } else if full_buffer {
        // our buffer is full, we should recurse right away
        warn!("Babel read larger than buffer! Consider increasing it's size");
        return read_babel(stream, full_message, depth);
    } else if let Err(NoTerminator(_)) = babel_data {
        // our buffer was not full but we also did not find a terminator,
        // we must have caught babel while it was interrupted (only really happens
        // in single cpu situations)
        thread::sleep(SLEEP_TIME);
        info!("we didn't get the whole message yet, trying again");
        return read_babel(stream, full_message, depth + 1);
    } else if let Err(e) = babel_data {
        // some other error
        warn!("Babel read failed! {} {:?}", output, e);
        return Err(ReadFailed(format!("{:?}", e)));
    }
    let babel_data = babel_data.unwrap();

    Ok(babel_data)
}

fn read_babel_sync(output: &str) -> Result<String, BabelMonitorError> {
    let mut ret = String::new();
    for line in output.lines() {
        ret.push_str(line);
        ret.push('\n');
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

pub fn run_command(stream: &mut TcpStream, cmd: &str) -> Result<String, BabelMonitorError> {
    info!("Running babel command {}", cmd);
    let cmd = format!("{}\n", cmd);
    let bytes = cmd.as_bytes().to_vec();
    let out = stream.write_all(&bytes);

    if out.is_err() {
        return Err(CommandFailed(cmd, format!("{:?}", out)));
    }

    let _res = out.unwrap();
    info!("Command write succeeded, returning output");
    read_babel(stream, String::new(), 0)
}

pub fn validate_preamble(preamble: String) -> Result<(), BabelMonitorError> {
    // Note you have changed the config interface, bump to 1.1 in babel
    if preamble.contains("ALTHEA 0.1") {
        trace!("Attached OK to Babel with preamble: {}", preamble);
        Ok(())
    } else {
        Err(InvalidPreamble(preamble))
    }
}

pub fn parse_interfaces(stream: &mut TcpStream) -> Result<Vec<Interface>, BabelMonitorError> {
    let output = run_command(stream, "dump");

    if let Err(e) = output {
        return Err(e);
    }
    let babel_output = output.unwrap();
    parse_interfaces_sync(babel_output)
}

pub fn parse_interfaces_sync(output: String) -> Result<Vec<Interface>, BabelMonitorError> {
    let mut vector: Vec<Interface> = Vec::new();
    let mut found_interface = false;
    for entry in output.split('\n') {
        if entry.contains("add interface") {
            found_interface = true;
            let interface = Interface {
                name: match find_babel_val("interface", entry) {
                    Ok(val) => val,
                    Err(_) => continue,
                },
                up: match find_and_parse_babel_val("up", entry) {
                    Ok(val) => val,
                    Err(_) => continue,
                },
                ipv4: match find_and_parse_babel_val("ipv4", entry) {
                    Ok(val) => Some(val),
                    Err(_) => None,
                },
                ipv6: match find_and_parse_babel_val("ipv6", entry) {
                    Ok(val) => Some(val),
                    Err(_) => None,
                },
            };
            vector.push(interface);
        }
    }
    if vector.is_empty() && found_interface {
        return Err(BabelMonitorError::BabelParseError(
            "All Babel Interface parsing failed!".to_string(),
        ));
    }
    Ok(vector)
}

pub fn get_local_fee(stream: &mut TcpStream) -> Result<u32, BabelMonitorError> {
    let output = run_command(stream, "dump");

    if let Err(e) = output {
        return Err(e);
    }
    let babel_output = output.unwrap();
    get_local_fee_sync(babel_output)
}

pub fn get_local_fee_sync(babel_output: String) -> Result<u32, BabelMonitorError> {
    let fee_entry = match babel_output.split('\n').next() {
        Some(entry) => entry,
        // Even an empty string wouldn't yield None
        None => return Err(LocalFeeNotFound(String::from("<Babel output is None>"))),
    };

    if fee_entry.contains("local fee") {
        let fee = find_babel_val("fee", fee_entry)?.parse()?;
        trace!("Retrieved a local fee of {}", fee);
        return Ok(fee);
    }

    Err(LocalFeeNotFound(String::from(fee_entry)))
}

pub fn set_local_fee(stream: &mut TcpStream, new_fee: u32) -> Result<(), BabelMonitorError> {
    let result = run_command(stream, &format!("fee {}", new_fee));

    if let Err(e) = result {
        return Err(e);
    }
    let _out = result.unwrap();
    Ok(())
}

pub fn set_metric_factor(stream: &mut TcpStream, new_factor: u32) -> Result<(), BabelMonitorError> {
    let result = run_command(stream, &format!("metric-factor {}", new_factor));

    if let Err(e) = result {
        return Err(e);
    }
    let _out = result.unwrap();
    Ok(())
}

pub fn monitor(stream: &mut TcpStream, iface: &str) -> Result<(), BabelMonitorError> {
    let command = &format!(
        "interface {} max-rtt-penalty 500 enable-timestamps true",
        iface
    );
    let iface = iface.to_string();
    let result = run_command(stream, command);

    if let Err(e) = result {
        return Err(e);
    }
    trace!("Babel started monitoring: {}", iface);
    let _out = result.unwrap();
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
    let result = run_command(stream, &command);

    if let Err(e) = result {
        return Err(e);
    }
    let _out = result.unwrap();
    read_babel(stream, String::new(), 0)
}

pub fn unmonitor(stream: &mut TcpStream, iface: &str) -> Result<(), BabelMonitorError> {
    let command = format!("flush interface {}", iface);
    let iface = iface.to_string();
    let result = run_command(stream, &command);

    if let Err(e) = result {
        return Err(e);
    }
    trace!("Babel stopped monitoring: {}", iface);
    let _out = result.unwrap();
    Ok(())
}

pub fn parse_neighs(stream: &mut TcpStream) -> Result<Vec<Neighbor>, BabelMonitorError> {
    let result = run_command(stream, "dump");

    if let Err(e) = result {
        return Err(e);
    }
    let output = result.unwrap();
    parse_neighs_sync(output)
}

pub fn parse_neighs_sync(output: String) -> Result<Vec<Neighbor>, BabelMonitorError> {
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
                // it's possible that the neighbor does not have rtt enabled
                rtt: find_and_parse_babel_val("rtt", entry).unwrap_or(0.0),
                rttcost: find_and_parse_babel_val("rttcost", entry).unwrap_or(0),
                cost: match find_and_parse_babel_val("cost", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
            };
            vector.push(neigh);
        }
    }
    if vector.is_empty() && found_neigh {
        return Err(BabelMonitorError::BabelParseError(
            "All Babel neigh parsing failed!".to_string(),
        ));
    }
    Ok(vector)
}

pub fn parse_routes(stream: &mut TcpStream) -> Result<Vec<Route>, BabelMonitorError> {
    let result = run_command(stream, "dump");

    if let Err(e) = result {
        return Err(e);
    }
    let babel_out = result.unwrap();
    parse_routes_sync(babel_out)
}

pub fn parse_routes_sync(babel_out: String) -> Result<Vec<Route>, BabelMonitorError> {
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
        return Err(BabelMonitorError::BabelParseError(
            "All Babel route parsing failed!".to_string(),
        ));
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
) -> Result<Route, BabelMonitorError> {
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
    Err(NoNeighbor(neigh_mesh_ip.to_string()))
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
pub fn do_we_have_route(mesh_ip: &IpAddr, routes: &[Route]) -> Result<bool, BabelMonitorError> {
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
pub fn get_installed_route(mesh_ip: &IpAddr, routes: &[Route]) -> Result<Route, BabelMonitorError> {
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
        return Err(BabelMonitorError::NoRoute(
            "No installed route to that destination!".to_string(),
        ));
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
    fn interfaces_parse() {
        let interfaces = parse_interfaces_sync(TABLE.to_string()).unwrap();
        assert_eq!(interfaces.len(), 5);

        let iface = interfaces.get(0).unwrap();
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

        let route = routes.get(0).unwrap();
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
