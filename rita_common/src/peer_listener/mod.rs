//! PeerListener is used to detect nearby mesh peers, it listens on a ff02::/8 ipv6 address, which is
//! a link local multicast address, on each listen port.
//!
//! On initialization a set of ListenInterface objects are created, these are important because they
//! actually hold the sockets required to listen and broadcast on the listen interfaces, every
//! rita_loop iteration we send out our own IP as a UDP broadcast packet and then get our peers
//! off the queue. These are turned into Peer structs which are passed to TunnelManager to do
//! whatever remaining work there may be.
pub mod message;

use self::message::PeerMessage;
use crate::tm_identity_callback;
use crate::IdentityCallback;
use crate::RitaCommonError;
use crate::KI;
use althea_types::LocalIdentity;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::Arc;
use std::sync::RwLock;

lazy_static! {
    pub static ref PEER_LISTENER: Arc<RwLock<HashMap<String, PeerListener>>> =
        Arc::new(RwLock::new(HashMap::from([(
            "default".to_string(),
            PeerListener::default()
        )])));
}

#[derive(Debug)]
pub struct PeerListener {
    pub interfaces: HashMap<String, ListenInterface>,
    pub peers: HashMap<IpAddr, Peer>,

    ///This hashmap is used to map a SocketAddr to the ListenInterface name. This way we are able to get
    /// all the information of the interface after receiving a hello message. For instance, when receiving a
    /// Hello, we are able to determine the udp port to sent the response on using this map.
    pub interface_map: HashMap<SocketAddr, String>,
}

///There are two types of hello messages. When we receive a inital hello (not a response)
///and when we receive a response to a hello we sent. 1 indicates we received a response hello message.
///This is the internal struct that carries information about local identity and which peer to send
///this message to, as well as whether this is a response or intial contact message.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub my_id: LocalIdentity,
    pub to: Peer,
    pub response: bool,
}

impl Hello {
    pub fn new(id: LocalIdentity, peer: Peer, res: bool) -> Hello {
        Hello {
            my_id: id,
            to: peer,
            response: res,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Copy)]
pub struct Peer {
    pub ifidx: u32,
    pub contact_socket: SocketAddr,
}

impl Peer {
    pub fn new(ip: Ipv6Addr, idx: u32) -> Peer {
        let port = settings::get_rita_common().network.rita_hello_port;
        let socket = SocketAddrV6::new(ip, port, 0, idx);
        Peer {
            ifidx: idx,
            contact_socket: socket.into(),
        }
    }
}

impl Default for PeerListener {
    fn default() -> PeerListener {
        PeerListener::new().unwrap()
    }
}

impl PeerListener {
    pub fn new() -> Result<PeerListener, RitaCommonError> {
        Ok(PeerListener {
            interfaces: HashMap::new(),
            peers: HashMap::new(),
            interface_map: HashMap::new(),
        })
    }
}

impl Clone for PeerListener {
    fn clone(&self) -> PeerListener {
        let interfaces = &self.interfaces;
        let mut clone_interfaces = HashMap::new();

        for (name, inter) in interfaces {
            let multi_udp = match inter.multicast_socket.try_clone() {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        "PEER DISCOVERY ERROR: Unable to clone multicast udp, please fix: {:?}",
                        e
                    );
                    continue;
                }
            };
            let local_udp = match inter.linklocal_socket.try_clone() {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        "PEER DISCOVERY ERROR: Unable to clone local udp, please fix: {:?}",
                        e
                    );
                    continue;
                }
            };
            let new_lis = ListenInterface {
                ifname: inter.ifname.clone(),
                ifidx: inter.ifidx,
                multicast_socketaddr: inter.multicast_socketaddr,
                multicast_socket: multi_udp,
                linklocal_socket: local_udp,
                linklocal_ip: inter.linklocal_ip,
            };
            clone_interfaces.insert(name.clone(), new_lis);
        }
        PeerListener {
            interfaces: clone_interfaces,
            peers: self.peers.clone(),
            interface_map: self.interface_map.clone(),
        }
    }
}

/// Creates a listen interface on all interfaces in the peer_interfaces hashmap.
fn listen_to_available_ifaces(peer_listener: &mut PeerListener) {
    info!("PEER LISTENER: starting to listen to interfaces");
    let interfaces = settings::get_rita_common().network.peer_interfaces;
    let iface_list = interfaces;
    for iface in iface_list.iter() {
        if !peer_listener.interfaces.contains_key(iface) {
            match ListenInterface::new(iface) {
                Ok(new_listen_interface) => {
                    info!("Added interface: {:?} to interfaces list", iface);
                    peer_listener
                        .interfaces
                        .insert(new_listen_interface.ifname.clone(), new_listen_interface);
                }
                Err(e) => {
                    error!("Received an error while listening to interfaces: {:?}", e)
                }
            }
        }
    }

    info!(
        "PEER LISTENER: Done listening, Our interface list looks like : {:?}",
        peer_listener.interfaces
    );
}

/// Returns a copy of PL lazy static var
fn get_pl_copy(key: String) -> Option<PeerListener> {
    let pl = PEER_LISTENER.read().unwrap().clone();
    let tmp = pl.get(&key);
    tmp.cloned()
}

/// Sets the PeerListener lazy static to the given value
fn set_pl(key: String, pl: PeerListener) {
    let mut map = PEER_LISTENER.read().unwrap().clone();
    map.insert(key, pl);
    *PEER_LISTENER.write().unwrap() = map;
}

/// Ticks the peer listener module sending ImHere messages and receiving Hello messages from all
/// peers over UDP
pub fn peerlistener_tick() -> PeerListener {
    trace!("Starting PeerListener tick!");

    let key = if cfg!(feature = "integration_test_v2") {
        KI.get_namespace().unwrap()
    } else {
        "default".to_string()
    };
    let mut pl = match get_pl_copy(key.clone()) {
        Some(pl) => pl,
        // we should never get here in prod as the default is created in the initialization, but this is a failsafe either way...
        None => PeerListener::default(),
    };
    info!("Received the PL struct: {:?}", pl);
    send_im_here(&mut pl.interfaces);
    let (a, b) = receive_im_here(&mut pl.interfaces);
    {
        pl.peers = a;
        pl.interface_map = b;
    }
    receive_hello(&mut pl);
    listen_to_available_ifaces(&mut pl);

    set_pl(key, pl.clone());
    info!("We set the PL struct to : {:?}", pl);
    pl
}

#[allow(dead_code)]
pub fn unlisten_interface(interface: String) {
    info!("Peerlistener unlisten on {:?}", interface);
    let ifname_to_delete = interface;
    let key = if cfg!(feature = "integration_test_v2") {
        KI.get_namespace().unwrap()
    } else {
        "default".to_string()
    };
    let mut pl = match get_pl_copy(key.clone()) {
        Some(pl) => pl,
        // we should never get here in prod as the default is created in the initialization, but this is a failsafe either way...
        None => PeerListener::default(),
    };
    if pl.interfaces.contains_key(&ifname_to_delete) {
        pl.interfaces.remove(&ifname_to_delete);
        let mut common = settings::get_rita_common();

        common.network.peer_interfaces.remove(&ifname_to_delete);
        set_pl(key, pl);
        settings::set_rita_common(common);
    } else {
        error!("Tried to unlisten interface that's not present!")
    }
}

#[derive(Debug)]
pub struct ListenInterface {
    ifname: String,
    ifidx: u32,
    multicast_socketaddr: SocketAddrV6,
    pub multicast_socket: UdpSocket,
    pub linklocal_socket: UdpSocket,
    linklocal_ip: Ipv6Addr,
}

impl ListenInterface {
    pub fn new(ifname: &str) -> Result<ListenInterface, RitaCommonError> {
        let network = settings::get_rita_common().network;
        let port = network.rita_hello_port;
        let disc_ip = network.discovery_ip;
        debug!("Binding to {:?} for ListenInterface", ifname);
        // Lookup interface link local ip
        let link_ip = KI.get_link_local_device_ip(ifname)?;

        // Lookup interface index
        let iface_index: u32 = if cfg!(feature = "integration_test_v2") {
            // ip netns exec n-1 cat /sys/class/net/veth-n-1-n-2/iflink
            let ns = KI.get_namespace().unwrap();
            let location = format!("/sys/class/net/{ifname}/ifindex");
            let index = KI
                .run_command("ip", &["netns", "exec", &ns, "cat", &location])
                .unwrap();

            let index = match String::from_utf8(index.stdout) {
                Ok(mut s) => {
                    //this outputs with an extra newline \n on the end which was messing up the next command
                    s.truncate(s.len() - 1);
                    s
                }
                Err(_) => panic!("Could not get index number!"),
            };
            info!("location: {:?}, index {:?}", location, index);

            index.parse().unwrap()
        } else {
            KI.get_ifindex(ifname).unwrap_or(0) as u32
        };
        // Bond to multicast discovery address on each listen port
        let multicast_socketaddr = SocketAddrV6::new(disc_ip, port, 0, iface_index);
        let multicast_socket = UdpSocket::bind(multicast_socketaddr)?;
        let res = multicast_socket.join_multicast_v6(&disc_ip, iface_index);
        trace!("ListenInterface init set multicast v6 with {:?}", res);
        let res = multicast_socket.set_nonblocking(true);
        trace!(
            "ListenInterface multicast init set nonblocking with {:?}",
            res
        );

        let linklocal_socketaddr = SocketAddrV6::new(link_ip, port, 0, iface_index);
        let linklocal_socket = UdpSocket::bind(linklocal_socketaddr)?;
        let res = linklocal_socket.set_nonblocking(true);
        trace!("ListenInterface init set nonblocking with {:?}", res);

        let res = linklocal_socket.join_multicast_v6(&disc_ip, iface_index);
        trace!("ListenInterface Set link local multicast v6 with {:?}", res);

        Ok(ListenInterface {
            ifname: ifname.to_string(),
            ifidx: iface_index,
            multicast_socket,
            linklocal_socket,
            multicast_socketaddr,
            linklocal_ip: link_ip,
        })
    }
}

/// send UDP ImHere messages over IPV6 link local
fn send_im_here(interfaces: &mut HashMap<String, ListenInterface>) {
    info!("About to send ImHere messages");
    for obj in interfaces.iter_mut() {
        let listen_interface = obj.1;
        info!(
            "Sending ImHere to {:?}, with ip {:?}",
            listen_interface.ifname, listen_interface.linklocal_ip
        );
        let message = PeerMessage::ImHere(listen_interface.linklocal_ip);
        let result = listen_interface
            .linklocal_socket
            .send_to(&message.encode(), listen_interface.multicast_socketaddr);
        trace!("Sending ImHere to broadcast gets {:?}", result);
        if result.is_err() {
            info!(
                "Sending ImHere to {:?} failed with {:?}",
                listen_interface.ifname, result
            );
        }
    }
    info!("Done sending ImHere this tick");
}

/// receive UDP ImHere messages over IPV6 link local
fn receive_im_here(
    interfaces: &mut HashMap<String, ListenInterface>,
) -> (HashMap<IpAddr, Peer>, HashMap<SocketAddr, String>) {
    info!("About to receive ImHere");
    let mut output = HashMap::<IpAddr, Peer>::new();
    let mut interface_map = HashMap::<SocketAddr, String>::new();
    for obj in interfaces.iter_mut() {
        info!("PEER LISTENER: Looking at imHere on interface: {:?}", obj.0);
        let listen_interface = obj.1;
        // Since the only datagrams we are interested in are very small (22 bytes plus overhead)
        // this buffer is kept intentionally small to discard larger packets earlier rather than later
        loop {
            let mut datagram: [u8; 100] = [0; 100];
            let (bytes_read, sock_addr) =
                match listen_interface.multicast_socket.recv_from(&mut datagram) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Could not recv ImHere: {:?}", e);
                        // TODO Consider we might want to remove interfaces that produce specific types
                        // of errors from the active list
                        break;
                    }
                };
            info!(
                "Received {} bytes on multicast socket from {:?}",
                bytes_read, sock_addr
            );

            let ipaddr = match PeerMessage::decode(datagram.as_ref()) {
                Ok(PeerMessage::ImHere(ipaddr)) => ipaddr,
                Err(e) => {
                    error!("ImHere decode failed: {:?}", e);
                    continue;
                }
                _ => {
                    error!("Received Hello on multicast socket, Error");
                    continue;
                }
            };

            if ipaddr == listen_interface.linklocal_ip {
                error!("Got ImHere from myself");
                continue;
            }

            if output.contains_key(&ipaddr.into()) {
                info!(
                    "Discarding ImHere We already have a peer with {:?} for this cycle",
                    ipaddr
                );
                continue;
            }
            info!("ImHere with {:?}", ipaddr);
            let peer = Peer::new(ipaddr, listen_interface.ifidx);
            output.insert(peer.contact_socket.ip(), peer);
            interface_map.insert(peer.contact_socket, listen_interface.ifname.clone());
        }
    }
    info!("Done receiving im here messages");
    info!(
        "Setting Peers and interface map to : {:?}\n\n {:?}",
        output, interface_map
    );
    (output, interface_map)
}

/// Send UDP hello message over IPV6
pub fn send_hello(msg: &Hello, socket: &UdpSocket, send_addr: SocketAddr, sender_wgport: u16) {
    trace!("Sending a Hello message");

    let message = PeerMessage::Hello {
        my_id: msg.my_id,
        response: msg.response,
        sender_wgport,
    };
    let encoded_message = PeerMessage::encode(&message).to_vec();
    let result = socket.send_to(&encoded_message, send_addr);
    if result.is_err() {
        info!("Sending Hello message failed with {:?}", result);
    }
}

/// receive UDP hello messages over IPV6 link local ports
pub fn receive_hello(writer: &mut PeerListener) {
    info!("Receiving Hellos");
    for obj in writer.interfaces.iter_mut() {
        let listen_interface = obj.1;

        //datagrams are larger than im here, so buffer is larger
        loop {
            const BUFFER_SIZE: usize = 500;
            let mut datagram: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
            let (bytes_read, sock_addr) =
                match listen_interface.linklocal_socket.recv_from(&mut datagram) {
                    Ok(b) => b,
                    Err(e) => {
                        trace!("Could not recv Hello: {:?}", e);
                        break;
                    }
                };
            if bytes_read == BUFFER_SIZE {
                error!(
                    "Failed to read entire datagram on linklocal peer socket! {:?}",
                    datagram
                );
                continue;
            }
            info!(
                "Received {} bytes on linklocal socket from {:?}",
                bytes_read, sock_addr
            );
            let peer_to_send = Peer {
                contact_socket: sock_addr,
                ifidx: listen_interface.ifidx,
            };

            writer
                .interface_map
                .insert(sock_addr, listen_interface.ifname.clone());

            let encoded_msg = datagram.to_vec();
            match PeerMessage::decode(&encoded_msg) {
                Ok(PeerMessage::ImHere(_ipaddr)) => {
                    error!("Should not revceive Im Here on linklocal socket, Error");
                    continue;
                }
                Ok(PeerMessage::Hello {
                    my_id,
                    response,
                    sender_wgport,
                }) => {
                    //We received an initial hello contact message
                    if !response {
                        info!(
                            "Received a PeerMessage with fields: {:?}, {:?}, {:?}",
                            my_id, response, sender_wgport
                        );

                        let their_id = my_id;
                        let peer = Peer {
                            contact_socket: sock_addr,
                            ifidx: 0,
                        };

                        let tunnel =
                            tm_identity_callback(IdentityCallback::new(their_id, peer, None, None));
                        let tunnel = match tunnel {
                            Some(val) => val,
                            None => {
                                error!("Tunnel Open failure from peer listener");
                                return;
                            }
                        };

                        let our_id = LocalIdentity {
                            global: match settings::get_rita_common().get_identity() {
                                Some(id) => id,
                                None => {
                                    error!("Identity has no mesh IP ready yet in peer listener");
                                    return;
                                }
                            },
                            wg_port: tunnel.0.listen_port,
                            have_tunnel: Some(tunnel.1),
                        };

                        let response_hello = Hello::new(our_id, peer, true);
                        send_hello(
                            &response_hello,
                            &listen_interface.linklocal_socket,
                            sock_addr,
                            sender_wgport,
                        );

                        //we received a hello response message
                    } else {
                        info!(
                            "Received a hello response with id wgport and peer: {:?}",
                            my_id.wg_port
                        );
                        let their_id = my_id;
                        tm_identity_callback(IdentityCallback::new(
                            their_id,
                            peer_to_send,
                            Some(sender_wgport),
                            None,
                        ));
                    }
                }
                Err(e) => {
                    error!("Hello decode failed: {:?}", e);
                    continue;
                }
            };
        }
    }
    info!("Done receiving hellos");
}
