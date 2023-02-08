use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::sync::RwLock;

use althea_types::LocalIdentity;

use crate::RitaCommonError;
use crate::KI;

use super::ListenInterface;

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

/// Returns a copy of PL lazy static var based on what namespace we are in
pub fn get_pl_copy() -> PeerListener {
    let key = get_key();
    let pl = PEER_LISTENER.read().unwrap().clone();
    let tmp = pl.get(&key);
    match tmp {
        Some(pl) => pl.to_owned(),
        None => {
            // we should never get here in prod as the default is created in the initialization, but this is a failsafe either way...
            add_pl();
            PeerListener::default()
        }
    }
}

/// Adds a new pl to the pl lazy static. Use only to initialize a default
pub fn add_pl() {
    let key = get_key();
    let pl = PeerListener::default();
    PEER_LISTENER.write().unwrap().insert(key, pl);
}

pub fn get_key() -> String {
    match KI.get_namespace() {
        Some(string) => string,
        None => "default".to_string(),
    }
}

pub fn get_interfaces() -> HashMap<String, ListenInterface> {
    let key = get_key();
    PEER_LISTENER
        .read()
        .unwrap()
        .get(&key)
        .unwrap()
        .clone()
        .interfaces
}
pub fn get_interface_map() -> HashMap<SocketAddr, String> {
    let key = get_key();
    PEER_LISTENER
        .read()
        .unwrap()
        .get(&key)
        .unwrap()
        .clone()
        .interface_map
}
/// add or update an interface in the map
pub fn add_interface(name: String, listen_iterface: ListenInterface) {
    let key = get_key();
    PEER_LISTENER
        .write()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .interfaces
        .insert(name, listen_iterface);
}
/// remove an interface in the map
pub fn remove_interface(name: String) {
    let key = get_key();
    PEER_LISTENER
        .write()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .interfaces
        .remove(&name);
}
pub fn add_peer(ip: IpAddr, peer: Peer) {
    let key = get_key();
    PEER_LISTENER
        .write()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .peers
        .insert(ip, peer);
}
pub fn add_interface_map(socket: SocketAddr, iface: String) {
    let key = get_key();
    PEER_LISTENER
        .write()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .interface_map
        .insert(socket, iface);
}
