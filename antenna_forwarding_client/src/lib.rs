#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

use althea_types::Identity;
use althea_types::WgKey;
use antenna_forwarding_protocol::ConnectionClose;
use antenna_forwarding_protocol::ConnectionMessage;
use antenna_forwarding_protocol::ErrorMessage;
use antenna_forwarding_protocol::ForwardMessage;
use antenna_forwarding_protocol::ForwardingCloseMessage;
use antenna_forwarding_protocol::ForwardingProtocolMessage;
use antenna_forwarding_protocol::IdentificationMessage;
use failure::Error;
use oping::Ping;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::time::Instant;

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
                .expect("Failed to get nonblocking socket!");
            // send our identifier
            let _res = stream.write_all(&IdentificationMessage::new(our_id).get_message());
            let mut buf = Vec::new();
            let res = stream.read_to_end(&mut buf);
            match res {
                Ok(bytes) => match ForwardMessage::read_message(&buf) {
                    Ok(msg) => {
                        trace!("Got fwd message {}", checkin_address);
                        let (start, forward_message) = msg;
                        let s =
                            setup_networking(forward_message, &mut stream, &interfaces_to_search);
                        if let Ok(s) = s {
                            forward_connections(s, buf, bytes, stream, start);
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
fn forward_connections(
    antenna_sockaddr: SocketAddr,
    buffer: Vec<u8>,
    bytes_read: usize,
    server_stream: TcpStream,
    start: usize,
) {
    let mut server_stream = server_stream;
    let mut buffer = buffer;
    let mut bytes_read = bytes_read;
    let mut streams: HashMap<u64, TcpStream> = HashMap::new();
    let mut start = start;
    let mut last_message = Instant::now();
    loop {
        while start < bytes_read {
            let connection = ConnectionMessage::read_message(&buffer[start..bytes_read]);
            let close = ConnectionClose::read_message(&buffer[start..bytes_read]);
            let halt = ForwardingCloseMessage::read_message(&buffer[start..bytes_read]);
            match (connection, close, halt) {
                (Ok((new_start, connection_message)), Err(_), Err(_)) => {
                    last_message = Instant::now();
                    start = new_start;
                    let stream_id = &connection_message.stream_id;
                    if let Some(antenna_stream) = streams.get_mut(stream_id) {
                        antenna_stream
                            .write_all(&connection_message.payload)
                            .expect("Failed to talk to antenna!");
                    } else {
                        // we don't have a stream, we need to dial out to the server now
                        let mut new_stream = TcpStream::connect(antenna_sockaddr)
                            .expect("Could not contact antenna!");
                        new_stream
                            .set_nonblocking(false)
                            .expect("Could not get nonblocking connection");
                        new_stream
                            .write_all(&connection_message.payload)
                            .expect("Failed to talk to antenna!");
                        streams.insert(*stream_id, new_stream);
                    }
                }
                (Err(_), Ok((new_start, close_message)), Err(_)) => {
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
                    // todo this might not be needed, this handles trailing bytes
                    // but if everything reads correctly the start should = bytes_read
                    // and break the loop
                    trace!("No more messages, leaving");
                    break;
                }
                (Ok(_), Ok(_), Ok(_)) => panic!("Impossible!"),
                (Ok(_), Ok(_), Err(_)) => panic!("Impossible!"),
                (Ok(_), Err(_), Ok(_)) => panic!("Impossible!"),
                (Err(_), Ok(_), Ok(_)) => panic!("Impossible!"),
            }
        }

        if let Ok(bytes) = server_stream.read_to_end(&mut buffer) {
            bytes_read = bytes;
            start = 0;
        }

        if Instant::now() - last_message > FORWARD_TIMEOUT {
            error!("Fowarding session timed out!");
            break;
        }
    }
}

/// handles the setup of networking to the selected antenna, including finding it and the like
/// returns a socketaddr for the antenna
fn setup_networking(
    msg: ForwardMessage,
    server_stream: &mut TcpStream,
    interfaces: &HashSet<String>,
) -> Result<SocketAddr, Error> {
    let antenna_ip = msg.ip;
    let antenna_iface = match find_antenna(antenna_ip, interfaces) {
        Ok(iface) => iface,
        Err(e) => {
            error!("Could not find anntenna {:?}", e);
            let _ = server_stream.write_all(&ErrorMessage::new(format!("{:?}", e)).get_message());
            let _ = server_stream.shutdown(Shutdown::Both);
            bail!("Can't find antenna!");
        }
    };
    Ok(SocketAddr::new(antenna_ip, 443))
}

/// Finds the antenna on the appropriate physical interface by iterating
/// over the list of provided interfaces, attempting a ping
/// and repeating until the appropriate interface is located
/// TODO actually setup routing to said antenna, maybe implicitly exit when
/// we find the antenna? becuase then routing will be setup
fn find_antenna(ip: IpAddr, interfaces: &HashSet<String>) -> Result<String, Error> {
    for iface in interfaces {
        let mut pinger = Ping::new();
        pinger.set_device(&iface)?;
        pinger.set_timeout((PING_TIMEOUT.as_millis() as f64 / 1000f64) as f64)?;
        pinger.add_host(&ip.to_string())?;
        let mut response = pinger.send()?;
        if let Some(res) = response.next() {
            trace!("got ping response {:?}", res);
            if res.dropped == 0 {
                return Ok((*iface).to_string());
            }
        }
    }
    Err(format_err!("Failed to find Antenna!"))
}
