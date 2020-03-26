#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;

use althea_kernel_interface::KernelInterface;
use althea_kernel_interface::LinuxCommandRunner;
use althea_types::Identity;
use althea_types::WgKey;
use antenna_forwarding_protocol::write_all_spinlock;
use antenna_forwarding_protocol::ConnectionClose;
use antenna_forwarding_protocol::ConnectionMessage;
use antenna_forwarding_protocol::ErrorMessage;
use antenna_forwarding_protocol::ForwardMessage;
use antenna_forwarding_protocol::ForwardingCloseMessage;
use antenna_forwarding_protocol::ForwardingProtocolMessage;
use antenna_forwarding_protocol::IdentificationMessage;
use antenna_forwarding_protocol::BUFFER_SIZE;
use antenna_forwarding_protocol::SPINLOCK_TIME;
use failure::Error;
use oping::Ping;
use rand::thread_rng;
use rand::Rng;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::ErrorKind::WouldBlock;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::process::ExitStatus;
use std::thread;
use std::time::Duration;
use std::time::Instant;

lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
}

/// The network operation timeout for this library
const NET_TIMEOUT: Duration = Duration::from_secs(5);
/// The timeout time for pinging a local antenna, 25ms is very
/// very generous here as they should all respond really within 5ms
const PING_TIMEOUT: Duration = Duration::from_millis(100);
/// the amount of time with no activity before we close a forwarding session
const FORWARD_TIMEOUT: Duration = Duration::from_secs(600);

pub fn start_antenna_forwarding_proxy(
    checkin_address: String,
    our_id: Identity,
    server_public_key: WgKey,
    our_public_key: WgKey,
    our_private_key: WgKey,
    interfaces_to_search: HashSet<String>,
) {
    info!("Starting antenna forwarding proxy!");
    let socket: SocketAddr = match checkin_address.parse() {
        Ok(socket) => socket,
        Err(_) => {
            error!("Could not parse {}!", checkin_address);
            return;
        }
    };

    thread::spawn(move || loop {
        // parse checkin address every loop iteration as a way
        // of resolving the domain name on each run
        trace!("About to checkin with {}", checkin_address);
        if let Ok(mut stream) = TcpStream::connect_timeout(&socket, NET_TIMEOUT) {
            trace!("connected to {}", checkin_address);
            stream
                .set_read_timeout(Some(NET_TIMEOUT))
                .expect("Failed to set read timeout on socket!");
            // send our identifier
            let _res = write_all_spinlock(
                &mut stream,
                &IdentificationMessage::new(our_id).get_message(),
            );
            let mut buf: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
            let res = stream.read(&mut buf);
            match res {
                Ok(bytes) => match ForwardMessage::read_message(&buf) {
                    Ok(msg) => {
                        // we start nonblocking operation here, so that we
                        // can easily wait for the forward response after
                        // sending our ID message, now we need non-blocking
                        // to process messages
                        stream
                            .set_nonblocking(true)
                            .expect("Failed to get nonblocking socket!");

                        trace!("Got fwd message {}", checkin_address);
                        let (bytes_read, forward_message) = msg;

                        // todo it would be technically correct to have packets
                        // after the forward packet, but we don't package things that
                        // way on the server, we should handle the possibility
                        if bytes > bytes_read {
                            error!("Extra messages after forward packet dropped!");
                        }

                        let s = setup_networking(forward_message, &interfaces_to_search);
                        match s {
                            Ok(s) => forward_connections(s, stream),
                            Err(e) => {
                                // the error message never reaches the server because the server
                                // will fail to read it, even if it enters the buffer once the
                                // connection is terminated.
                                stream.set_nodelay(true).expect("Failed to disble Nagle");
                                let a = write_all_spinlock(
                                    &mut stream,
                                    &ErrorMessage::new(format!("{:?}", e)).get_message(),
                                );
                                let b = stream.shutdown(Shutdown::Both);
                                warn!("Error forwarding write {:?} shutdown {:?}", a, b);
                                drop(stream);
                            }
                        }
                    }
                    Err(e) => warn!("Failed to read forward message with {:?}", e),
                },
                // if we don't read successfully we go off into the next
                // iteration of the loop and repeat this all again
                // we could try and keep a single connection open, but we
                // face many of the same problems (keepalive etc)
                Err(e) => trace!("Finished waiting with {:?}", e),
            }
        }
        trace!("Waiting for next checkin cycle");
        thread::sleep(NET_TIMEOUT);
    });
}

/// Actually forwards the connection by managing the reading and writing from
/// various tcp sockets
fn forward_connections(antenna_sockaddr: SocketAddr, server_stream: TcpStream) {
    trace!("Forwarding connections!");
    let mut server_stream = server_stream;
    let mut bytes_read;
    let mut streams: HashMap<u64, TcpStream> = HashMap::new();
    let mut start;
    let mut last_message = Instant::now();
    loop {
        let mut streams_to_remove: Vec<u64> = Vec::new();
        // First we we have to iterate over all of these connections
        // and read to send messages up the server pipe. We need to do
        // this first becuase we may exit in the next section if there's
        // nothing to write
        for (stream_id, antenna_stream) in streams.iter_mut() {
            let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
            // in theory we will figure out if the connection is closed here
            // and then send a closed message
            match antenna_stream.read(&mut buffer) {
                Ok(bytes) => {
                    if bytes != 0 {
                        trace!(
                            "We have {} bytes to write from a antenna input socket",
                            bytes
                        );
                        let msg = ConnectionMessage::new(*stream_id, buffer[0..bytes].to_vec());
                        write_all_spinlock(&mut server_stream, &msg.get_message())
                            .expect(&format!("Failed to write with stream {}", *stream_id));
                    }
                }
                Err(e) => {
                    if e.kind() != WouldBlock {
                        error!("Could not read client socket with {:?}", e);
                        let msg = ConnectionClose::new(*stream_id);
                        write_all_spinlock(&mut server_stream, &msg.get_message())
                            .expect(&format!("Failed to close stream {}", *stream_id));
                        let _ = antenna_stream.shutdown(Shutdown::Write);
                        streams_to_remove.push(*stream_id);
                    }
                }
            }
        }
        for i in streams_to_remove {
            streams.remove(&i);
        }

        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
        match server_stream.read(&mut buffer) {
            Ok(bytes) => {
                if bytes > 0 {
                    trace!("Got {} bytes from the server", bytes);
                }
                bytes_read = bytes;
                start = 0;
            }
            Err(e) => {
                if e.kind() != WouldBlock {
                    error!("Failed to read from server with {:?}", e);
                }
                continue;
            }
        }

        while start < bytes_read {
            let connection = ConnectionMessage::read_message(&buffer[start..bytes_read]);
            let close = ConnectionClose::read_message(&buffer[start..bytes_read]);
            let halt = ForwardingCloseMessage::read_message(&buffer[start..bytes_read]);
            match (connection, close, halt) {
                (Ok((new_start, connection_message)), Err(_), Err(_)) => {
                    trace!("Got connection message");
                    last_message = Instant::now();
                    start = new_start;
                    let stream_id = &connection_message.stream_id;
                    if let Some(antenna_stream) = streams.get_mut(stream_id) {
                        trace!("Message for {}", stream_id);
                        antenna_stream
                            .write_all(&connection_message.payload)
                            .expect("Failed to talk to antenna!");
                    } else {
                        trace!("Opening stream for {}", stream_id);
                        // we don't have a stream, we need to dial out to the server now
                        let mut new_stream = TcpStream::connect(antenna_sockaddr)
                            .expect("Could not contact antenna!");
                        new_stream
                            .set_nonblocking(true)
                            .expect("Could not get nonblocking connection");
                        new_stream
                            .write_all(&connection_message.payload)
                            .expect("Failed to talk to antenna!");
                        streams.insert(*stream_id, new_stream);
                    }
                }
                (Err(_), Ok((new_start, close_message)), Err(_)) => {
                    trace!("Got close message");
                    last_message = Instant::now();
                    start = new_start;
                    let stream_id = &close_message.stream_id;
                    let stream = streams
                        .get(stream_id)
                        .expect("How can we close a stream we don't have?");
                    stream
                        .shutdown(Shutdown::Both)
                        .expect("Failed to shutdown connection!");
                    streams.remove(stream_id);
                }
                (Err(_), Err(_), Ok((_new_start, _halt_message))) => {
                    trace!("Got halt message");
                    // we have a close lets get out of here.
                    for (_id, stream) in streams {
                        stream
                            .shutdown(Shutdown::Both)
                            .expect("Failed to shutdown connection!");
                    }
                    server_stream
                        .shutdown(Shutdown::Both)
                        .expect("Could not shutdown connection!");
                    return;
                }
                (Err(_), Err(_), Err(_)) => {
                    break;
                }
                (Ok(_), Ok(_), Ok(_)) => panic!("Impossible!"),
                (Ok(_), Ok(_), Err(_)) => panic!("Impossible!"),
                (Ok(_), Err(_), Ok(_)) => panic!("Impossible!"),
                (Err(_), Ok(_), Ok(_)) => panic!("Impossible!"),
            }
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
fn setup_networking(
    msg: ForwardMessage,
    interfaces: &HashSet<String>,
) -> Result<SocketAddr, Error> {
    let antenna_ip = msg.ip;
    match find_antenna(antenna_ip, interfaces) {
        Ok(_iface) => {}
        Err(e) => {
            error!("Could not find anntenna {:?}", e);
            return Err(e);
        }
    };
    Ok(SocketAddr::new(antenna_ip, 443))
}

/// Finds the antenna on the appropriate physical interface by iterating
/// over the list of provided interfaces, attempting a ping
/// and repeating until the appropriate interface is located
/// TODO handle overlapping edge cases for gateway ip, lan ip, br-pbs etc
fn find_antenna(ip: IpAddr, interfaces: &HashSet<String>) -> Result<String, Error> {
    let our_ip = get_local_ip(ip);
    for iface in interfaces {
        trace!("Trying interface {}, with test ip {}", iface, our_ip);
        // this acts as a wildcard deletion across all interfaces, which is frankly really
        // dangerous if our default route overlaps, of if you enter an exit route ip
        let _ = KI.run_command("ip", &["route", "del", &format!("{}/32", ip)]);
        for iface in interfaces {
            let _ = KI.run_command(
                "ip",
                &["addr", "del", &format!("{}/32", our_ip), "dev", iface],
            );
        }
        let res = KI.run_command(
            "ip",
            &["addr", "add", &format!("{}/32", our_ip), "dev", iface],
        );
        trace!("Added our own test ip with {:?}", res);
        // you need to use src here to disambiguate the sending address
        // otherwise the first avaialble ipv4 address on the interface will
        // be used
        match KI.run_command(
            "ip",
            &[
                "route",
                "add",
                &format!("{}/32", ip),
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
                        bail!("IP setup failed");
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
        pinger.set_timeout((PING_TIMEOUT.as_millis() as f64 / 1000f64) as f64)?;
        pinger.add_host(&ip.to_string())?;
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
    Err(format_err!("Failed to find Antenna!"))
}

/// Generates a random non overlapping ip within a /24 subnet of the provided
/// target antenna ip.
fn get_local_ip(target_ip: IpAddr) -> IpAddr {
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
            Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into()
        }
        IpAddr::V6(_address) => unimplemented!(),
    }
}
