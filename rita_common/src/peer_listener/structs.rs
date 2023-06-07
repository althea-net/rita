use super::ListenInterface;
use althea_types::LocalIdentity;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;

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
        PeerListener::new()
    }
}

impl PeerListener {
    pub fn new() -> PeerListener {
        PeerListener {
            interfaces: HashMap::new(),
            peers: HashMap::new(),
            interface_map: HashMap::new(),
        }
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
