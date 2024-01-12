#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

use althea_kernel_interface::KernelInterface;
use althea_kernel_interface::LinuxCommandRunner;
use althea_types::Identity;
use althea_types::WgKey;
use antenna_forwarding_protocol::process_streams;
use antenna_forwarding_protocol::write_all_spinlock;
use antenna_forwarding_protocol::ExternalStream;
use antenna_forwarding_protocol::ForwardingProtocolMessage;
use antenna_forwarding_protocol::NET_TIMEOUT;
use antenna_forwarding_protocol::SPINLOCK_TIME;
use oping::Ping;
use rand::Rng;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::thread;
use std::time::Duration;
use std::time::Instant;

mod error;
pub use error::AntennaForwardingError;

lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
}

const SLEEP_TIME: Duration = Duration::from_secs(20);
/// The timeout time for pinging a local antenna, 100ms is very
/// very generous here as they should all respond really within 5ms
const PING_TIMEOUT: Duration = Duration::from_millis(100);
/// the amount of time with no activity before we close a forwarding session
const FORWARD_TIMEOUT: Duration = Duration::from_secs(600);

/// Starts a thread that will check in with the provided server repeatedly and forward antennas
/// when the right signal is received. The type bound is so that you can use custom hashers and
/// may not really be worth keeping around.
pub fn start_antenna_forwarding_proxy<S: 'static + std::marker::Send + ::std::hash::BuildHasher>(
    checkin_address: String,
    our_id: Identity,
    server_public_key: WgKey,
    _our_public_key: WgKey,
    our_private_key: WgKey,
    interfaces_to_search: HashSet<String, S>,
) {
    info!("Starting antenna forwarding proxy!");
    // The last resolved IP address for the forwarding proxy. In the case that we suddenly
    // stop getting successful DNS responses we will fall back to the last successful response
    // this covers a pretty small edge case of a failed major DNS server. For example a cloudflare
    // outage where cloudflare responds to all requests with 'no domain', so there isn't failover to the
    // next provider but there's also no entry. This also reduces the number of failed checkins due to simple
    // things like lookup timeouts.
    let mut dns_cache: Option<SocketAddr> = None;
    thread::spawn(move || loop {
        info!("About to checkin with {}", checkin_address);
        // parse checkin address every loop iteration as a way
        // of resolving the domain name on each run
        let socket: SocketAddr = match checkin_address.to_socket_addrs() {
            Ok(mut res) => match res.next() {
                Some(socket) => {
                    dns_cache = Some(socket);
                    socket
                }
                None => {
                    if let Some(last_val) = dns_cache {
                        error!(
                            "Could not perform DNS lookup for {}! Falling back to {}",
                            checkin_address, last_val
                        );
                        last_val
                    } else {
                        error!("Could not perform DNS lookup for {}!", checkin_address);
                        thread::sleep(SLEEP_TIME);
                        continue;
                    }
                }
            },
            Err(_) => {
                error!("Could not parse {}!", checkin_address);
                thread::sleep(SLEEP_TIME);
                continue;
            }
        };
        if let Ok(mut server_stream) = TcpStream::connect_timeout(&socket, NET_TIMEOUT) {
            info!("connected to {}", checkin_address);
            // send our identifier
            let _res = write_all_spinlock(
                &mut server_stream,
                &ForwardingProtocolMessage::new_identification_message(our_id).get_message(),
            );
            // wait for a NET_TIMEOUT and see if the server responds, then read it's entire response
            thread::sleep(NET_TIMEOUT);
            match ForwardingProtocolMessage::read_messages_start(
                &mut server_stream,
                server_public_key,
                our_private_key,
            ) {
                Ok(messages) => {
                    // read messages will return a vec of at least one,
                    match messages.first() {
                        Some(ForwardingProtocolMessage::ForwardMessage {
                            ip,
                            server_port: _server_port,
                            antenna_port,
                        }) => {
                            info!("Got forwarding message, forwarding {}", ip);
                            // if there are other messages in this batch safely form a slice
                            // to pass on
                            let slice = if messages.len() > 1 {
                                &messages[1..]
                            } else {
                                // an empty slice
                                &([] as [ForwardingProtocolMessage; 0])
                            };
                            // setup networking and process the rest of the messages in this batch
                            match setup_networking(*ip, *antenna_port, &interfaces_to_search) {
                                Ok(antenna_sockaddr) => {
                                    forward_connections(antenna_sockaddr, server_stream, slice);
                                }
                                Err(e) => send_error_message(&mut server_stream, format!("{e:?}")),
                            }
                        }
                        Some(ForwardingProtocolMessage::ForwardingCloseMessage) => {}
                        Some(m) => warn!("Wrong start message {:?}", m),
                        None => {}
                    }
                }
                Err(e) => {
                    error!("Failed to read message from server with {:?}", e);
                }
            }
        }
        info!("Waiting for next checkin cycle");
        thread::sleep(SLEEP_TIME)
    });
}

/// Processes an array of messages and takes the appropriate actions
/// returns if the forwarder should shutdown becuase a shutdown message
/// was found in the message batch.
fn process_messages(
    input: &[ForwardingProtocolMessage],
    streams: &mut HashMap<u64, ExternalStream>,
    server_stream: &mut TcpStream,
    last_message: &mut Instant,
    antenna_sockaddr: SocketAddr,
) -> bool {
    for item in input {
        match item {
            // why would the server ID themselves to us?
            ForwardingProtocolMessage::IdentificationMessage { .. } => {
                error!("Why did the server identify?")
            }
            // two forward messages?
            ForwardingProtocolMessage::ForwardMessage { .. } => {
                error!("Got second forward message?")
            }
            // the server doesn't send us error messages, what would we do with it?
            ForwardingProtocolMessage::ErrorMessage { .. } => {
                error!("Server sent us an error message?")
            }
            ForwardingProtocolMessage::ConnectionCloseMessage { stream_id } => {
                trace!("Got close message for stream {}", stream_id);
                *last_message = Instant::now();
                if let Some(stream) = streams.get(stream_id) {
                    let _res = stream.stream.shutdown(Shutdown::Both);
                    streams.remove(stream_id);
                } else {
                    error!("Tried to remove stream {} that we did not have", stream_id);
                }
            }
            ForwardingProtocolMessage::ConnectionDataMessage { stream_id, payload } => {
                trace!(
                    "Got connection message for stream {} payload {} bytes",
                    stream_id,
                    payload.len()
                );
                *last_message = Instant::now();
                if let Some(antenna_stream) = streams.get_mut(stream_id) {
                    if let Err(e) = write_all_spinlock(&mut antenna_stream.stream, payload) {
                        error!(
                            "Failed to write to antenna stream id {} with {:?}",
                            stream_id, e
                        );
                    }
                } else {
                    trace!("Opening stream for {}", stream_id);
                    // we don't have a stream, we need to dial out to the server now
                    if let Ok(mut new_stream) = TcpStream::connect(antenna_sockaddr) {
                        match write_all_spinlock(&mut new_stream, payload) {
                            Ok(_) => {
                                streams.insert(
                                    *stream_id,
                                    ExternalStream {
                                        stream: new_stream,
                                        last_message: Instant::now(),
                                    },
                                );
                            }
                            Err(e) => error!(
                                "Failed to write to antenna stream id {} with {:?}",
                                stream_id, e
                            ),
                        }
                    }
                }
            }
            ForwardingProtocolMessage::ForwardingCloseMessage => {
                trace!("Got halt message");
                // we have a close lets get out of here.
                for stream in streams.values_mut() {
                    let _ = stream.stream.shutdown(Shutdown::Both);
                }
                let _ = server_stream.shutdown(Shutdown::Both);
                return true;
            }
            // we don't use this yet
            ForwardingProtocolMessage::KeepAliveMessage => {}
        }
    }
    false
}

/// Actually forwards the connection by managing the reading and writing from
/// various tcp sockets
fn forward_connections(
    antenna_sockaddr: SocketAddr,
    server_stream: TcpStream,
    first_round_input: &[ForwardingProtocolMessage],
) {
    trace!("Forwarding connections!");
    let mut server_stream = server_stream;
    let mut streams: HashMap<u64, ExternalStream> = HashMap::new();
    let mut last_message = Instant::now();
    process_messages(
        first_round_input,
        &mut streams,
        &mut server_stream,
        &mut last_message,
        antenna_sockaddr,
    );

    while let Ok(vec) = ForwardingProtocolMessage::read_messages(&mut server_stream) {
        if !vec.is_empty() {
            trace!("In forwarding loop! got {} messages", vec.len());
        }
        process_streams(&mut streams, &mut server_stream);
        let should_shutdown = process_messages(
            &vec,
            &mut streams,
            &mut server_stream,
            &mut last_message,
            antenna_sockaddr,
        );
        if should_shutdown {
            break;
        }

        if Instant::now() - last_message > FORWARD_TIMEOUT {
            error!("Fowarding session timed out!");
            break;
        }
        thread::sleep(SPINLOCK_TIME);
    }
}

/// handles the setup of networking to the selected antenna, including finding it and the like
/// returns a socketaddr for the antenna
fn setup_networking<S: ::std::hash::BuildHasher>(
    antenna_ip: IpAddr,
    antenna_port: u16,
    interfaces: &HashSet<String, S>,
) -> Result<SocketAddr, AntennaForwardingError> {
    match find_antenna(antenna_ip, interfaces) {
        Ok(_iface) => {}
        Err(e) => {
            error!("Could not find antenna {:?}", e);
            return Err(e);
        }
    };
    Ok(SocketAddr::new(antenna_ip, antenna_port))
}

/// Finds the antenna on the appropriate physical interface by iterating
/// over the list of provided interfaces, attempting a ping
/// and repeating until the appropriate interface is located
/// TODO handle overlapping edge cases for gateway ip, lan ip, etc
fn find_antenna<S: ::std::hash::BuildHasher>(
    target_ip: IpAddr,
    interfaces: &HashSet<String, S>,
) -> Result<String, AntennaForwardingError> {
    check_blacklist(target_ip)?;
    let our_ip = get_local_ip(target_ip)?;
    for iface in interfaces {
        if iface == "mesh" {
            trace!("Skipping mesh interface");
            continue;
        }
        trace!("Trying interface {}, with test ip {}", iface, our_ip);
        // this acts as a wildcard deletion across all interfaces, which is frankly really
        // dangerous if our default route overlaps, or if you enter an exit route ip
        let _ = KI.run_command("ip", &["route", "del", &format!("{target_ip}/32")]);
        for iface in interfaces {
            // cleans up all previous forwarding ip's in some way this is more dangerous than the previous
            // solution, which only cleaned up the target and destination ip's. But the more through cleanup
            // will hopefully prevent strange aliasing issues with devices on the lan or other networks that
            // may overlap with these routes.
            // this function only errors out when the underlying attempt at running a command fails. So it should
            // not cause issues with failing the find antenna command
            cleanup_interface(iface)?;
        }
        let res = KI.run_command(
            "ip",
            &["addr", "add", &format!("{our_ip}/32"), "dev", iface],
        );
        trace!("Added our own test ip with {:?}", res);
        // you need to use src here to disambiguate the sending address
        // otherwise the first available ipv4 address on the interface will
        // be used
        match KI.run_command(
            "ip",
            &[
                "route",
                "add",
                &format!("{target_ip}/32"),
                "dev",
                iface,
                "src",
                &our_ip.to_string(),
            ],
        ) {
            Ok(r) => {
                // exit status 512 is the code for 'file exists' meaning we are not
                // checking the interface we thought we where. At this point there's
                // no option but to exit
                if let Some(code) = r.status.code() {
                    if code == 512 {
                        error!("Failed to add route");
                        return Err(AntennaForwardingError::IPSetupError);
                    }
                }
                trace!("added route with {:?}", r);
            }
            Err(e) => {
                trace!("Failed to add route with {:?}", e);
                continue;
            }
        }
        let mut pinger = Ping::new();
        pinger.set_timeout(PING_TIMEOUT.as_millis() as f64 / 1000f64)?;
        pinger.add_host(&target_ip.to_string())?;
        let mut response = match pinger.send() {
            Ok(res) => res,
            Err(e) => {
                trace!("Failed to ping with {:?}", e);
                continue;
            }
        };
        if let Some(res) = response.next() {
            trace!("got ping response {:?}", res);
            if res.dropped == 0 {
                return Ok((*iface).to_string());
            }
        }
    }
    Err(AntennaForwardingError::AntennaNotFound)
}

/// Generates a random non overlapping ip within a /24 subnet of the provided
/// target antenna ip.
fn get_local_ip(target_ip: IpAddr) -> Result<IpAddr, AntennaForwardingError> {
    match target_ip {
        IpAddr::V4(address) => {
            let mut rng = rand::thread_rng();
            let mut bytes = address.octets();
            let mut new_ip: u8 = rng.gen();
            // keep trying until we get a different number
            // only editing the last byte is implicitly working
            // within a /24
            while new_ip == bytes[3] {
                new_ip = rng.gen()
            }
            bytes[3] = new_ip;
            Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into())
        }
        //IpAddr::V6(_address) => Err(format_err!("Not supported!")),
        IpAddr::V6(_address) => Err(AntennaForwardingError::IPNotSupported),
    }
}

const IP_BLACKLIST: [Ipv4Addr; 2] = [Ipv4Addr::new(192, 168, 10, 0), Ipv4Addr::new(127, 0, 0, 0)];

/// Checks the forwarding ip blacklist, these are ip's that we don't
/// want the forwarding client working on
fn check_blacklist(ip: IpAddr) -> Result<(), AntennaForwardingError> {
    match ip {
        IpAddr::V4(address) => {
            for ip in IP_BLACKLIST.iter() {
                if compare_ipv4_octets(*ip, address) {
                    return Err(AntennaForwardingError::BlacklistedAddress);
                }
            }
            Ok(())
        }
        IpAddr::V6(_address) => Ok(()),
    }
}

fn compare_ipv4_octets(mask: Ipv4Addr, to_compare: Ipv4Addr) -> bool {
    let mut bytes = to_compare.octets();
    bytes[3] = 0;
    let out: Ipv4Addr = bytes.into();
    mask == out
}

fn send_error_message(server_stream: &mut TcpStream, message: String) {
    let msg = ForwardingProtocolMessage::new_error_message(message);
    let _res = write_all_spinlock(server_stream, &msg.get_message());
    let _res = server_stream.shutdown(Shutdown::Both);
}

fn cleanup_interface(iface: &str) -> Result<(), AntennaForwardingError> {
    let values = KI.get_ip_from_iface(iface)?;
    for (ip, netmask) in values {
        // we only clean up very specific routes, this doesn't prevent us from causing problems
        // but it does help prevent us from doing things like removing the default route.
        if netmask == 32 {
            let _ = KI.run_command("ip", &["addr", "del", &format!("{ip}/32"), "dev", iface]);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist() {
        let res = check_blacklist(Ipv4Addr::new(192, 168, 10, 1).into());
        assert!(res.is_err());
        let res = check_blacklist(Ipv4Addr::new(192, 168, 11, 1).into());
        assert!(res.is_ok());
    }
}
