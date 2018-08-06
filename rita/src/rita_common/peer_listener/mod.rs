use actix::prelude::*;
use actix::{Actor, Context};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::BufMut;
use failure::Error;
use settings::RitaCommonSettings;
use std::collections::HashSet;
use std::io;
use std::io::Cursor;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

use rita_common::rita_loop::Tick;

use KI;
use SETTING;

pub const MSG_IM_HERE: u32 = 0x5b6d4158;

#[derive(Debug)]
pub struct PeerListener {
    interfaces: Vec<ListenInterface>,
    peers: Vec<Peer>,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub contact_ip: IpAddr,
    pub ifidx: u32,
    pub contact_socket: SocketAddr,
}

impl Peer {
    pub fn new(ip: Ipv6Addr, idx: u32) -> Peer {
        let port = SETTING.get_network().rita_hello_port;
        let socket = SocketAddrV6::new(ip, port.into(), 0, idx);
        Peer {
            contact_ip: ip.into(),
            ifidx: idx,
            contact_socket: socket.into(),
        }
    }
}

impl Actor for PeerListener {
    type Context = Context<Self>;
}

impl Default for PeerListener {
    fn default() -> PeerListener {
        PeerListener::new().unwrap()
    }
}

impl PeerListener {
    pub fn new() -> Result<PeerListener, Error> {
        Ok(PeerListener {
            interfaces: Vec::new(),
            peers: Vec::new(),
        })
    }
}

impl Supervised for PeerListener {}

impl SystemService for PeerListener {
    // Binds to all ready interfaces
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("PeerListener starting");
        let interfaces = SETTING.get_network().peer_interfaces.clone();
        let iface_list = interfaces;
        for iface in iface_list.iter() {
            let res = ListenInterface::new(iface);
            if res.is_ok() {
                self.interfaces.push(res.unwrap());
            }
        }
    }
}

impl Handler<Tick> for PeerListener {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("Starting PeerListener tick!");
        let res = send_imhere(&mut self.interfaces);
        if res.is_err() {
            error!("Sending ImHere failed with {:?}", res);
        }

        match recieve_imhere(&mut self.interfaces) {
            Ok(new_peers) => {
                self.peers = new_peers;
            }
            Err(e) => {
                error!("Receiving ImHere failed with {:?}", e);
            }
        }

        Ok(())
    }
}

pub struct Listen(pub String);
impl Message for Listen {
    type Result = ();
}

impl Handler<Listen> for PeerListener {
    type Result = ();

    fn handle(&mut self, listen: Listen, _: &mut Context<Self>) -> Self::Result {
        trace!("Peerlistener listen on {:?}", listen.0);
        let new_iface_name = listen.0;
        let new_iface = ListenInterface::new(&new_iface_name);
        match new_iface {
            Ok(n) => {
                self.interfaces.push(n);
                SETTING
                    .get_network_mut()
                    .peer_interfaces
                    .insert(new_iface_name);
            }
            Err(e) => {
                error!("Peer listener failed to listen on {:?}", e);
            }
        }
    }
}

pub struct UnListen(pub String);
impl Message for UnListen {
    type Result = ();
}

impl Handler<UnListen> for PeerListener {
    type Result = ();

    fn handle(&mut self, un_listen: UnListen, _: &mut Context<Self>) -> Self::Result {
        trace!("Peerlistener unlisten on {:?}", un_listen.0);
        let ifname_to_delete = un_listen.0;
        let mut entry_found = false;
        let mut to_del = 0;
        let mut count = 0;
        for item in self.interfaces.iter() {
            if item.ifname == ifname_to_delete {
                to_del = count;
                entry_found = true;
            }
            count = count + 1;
        }
        if entry_found {
            self.interfaces.remove(to_del);
            SETTING
                .get_network_mut()
                .peer_interfaces
                .remove(&ifname_to_delete);
        } else {
            error!("Peer listener failed to unlisten on {:?}", ifname_to_delete);
        }
    }
}

pub struct GetListen;
impl Message for GetListen {
    type Result = Result<HashSet<String>, Error>;
}

impl Handler<GetListen> for PeerListener {
    type Result = Result<HashSet<String>, Error>;
    fn handle(&mut self, _: GetListen, _: &mut Context<Self>) -> Self::Result {
        let mut res = HashSet::new();
        for item in self.interfaces.iter() {
            res.insert(item.ifname.clone());
        }
        Ok(res.clone())
    }
}

#[derive(Debug)]
pub struct GetPeers();
impl Message for GetPeers {
    type Result = Result<Vec<Peer>, Error>;
}

impl Handler<GetPeers> for PeerListener {
    type Result = Result<Vec<Peer>, Error>;

    fn handle(&mut self, _: GetPeers, _: &mut Context<Self>) -> Self::Result {
        Ok(self.peers.clone())
    }
}

#[derive(Debug)]
pub struct ListenInterface {
    ifname: String,
    ifidx: u32,
    multicast_socketaddr: SocketAddrV6,
    multicast_socket: UdpSocket,
    linklocal_socket: UdpSocket,
    linklocal_ip: Ipv6Addr,
}

impl ListenInterface {
    pub fn new(ifname: &str) -> Result<ListenInterface, Error> {
        let port = SETTING.get_network().rita_hello_port;
        let disc_ip = SETTING.get_network().discovery_ip;
        trace!("Binding to {:?} for ListenInterface", ifname);
        // Lookup interface link local ip
        let link_ip = match KI.get_link_local_device_ip(&ifname) {
            Ok(ip) => ip,
            Err(e) => {
                return Err(e);
            }
        };
        // Lookup interface index

        let iface_index = match KI.get_iface_index(&ifname) {
            Ok(idx) => idx,
            Err(_) => 0,
        };
        // Bond to multicast discovery address on each listen port
        let multicast_socketaddr = SocketAddrV6::new(disc_ip, port.into(), 0, iface_index);
        let multicast_socket = UdpSocket::bind(multicast_socketaddr)
            .expect("Failed to bind to peer discovery address!");
        let res = multicast_socket.join_multicast_v6(&disc_ip, iface_index);
        trace!("ListenInterface init set multicast v6 with {:?}", res);
        let res = multicast_socket.set_nonblocking(true);
        trace!(
            "ListenInterface multicast init set nonblocking with {:?}",
            res
        );

        let linklocal_socketaddr = SocketAddrV6::new(link_ip, port.into(), 0, iface_index);
        let linklocal_socket = UdpSocket::bind(linklocal_socketaddr).expect(&format!(
            "ListenInterface Failed to bind to link local address {:?} on {:?} with iface_index {:?} ",
            link_ip, ifname, iface_index
        ));
        let res = linklocal_socket.set_nonblocking(true);
        trace!("ListenInterface init set nonblocking with {:?}", res);

        let res = linklocal_socket.join_multicast_v6(&disc_ip, iface_index);
        trace!("ListenInterface Set link local multicast v6 with {:?}", res);

        Ok(ListenInterface {
            ifname: ifname.to_string(),
            ifidx: iface_index,
            multicast_socket: multicast_socket,
            linklocal_socket: linklocal_socket,
            multicast_socketaddr: multicast_socketaddr,
            linklocal_ip: link_ip,
        })
    }
}

fn encode_im_here(addr: Ipv6Addr) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.put_u32_be(MSG_IM_HERE);
    buf.put_u16_be(22);
    let ipaddr_bytes: [u8; 16] = addr.octets();
    for i in 0..16 {
        buf.put_u8(ipaddr_bytes[i]);
    }
    trace!("Encoded ImHere packet {:x?}", buf);
    buf
}

fn decode_im_here(buf: &mut Vec<u8>) -> Result<Option<Ipv6Addr>, io::Error> {
    trace!("Starting ImHere packet decode!");
    if buf.is_empty() {
        trace!("Recieved an empty ImHere packet!");
        return Ok(None);
    }
    let mut pointer = Cursor::new(&buf);
    let packet_magic = pointer.read_u32::<BigEndian>()?;
    if packet_magic != MSG_IM_HERE {
        trace!(
            "Recieved an ImHere packet with an invalid magic: {:?}",
            packet_magic
        );
        return Ok(None);
    }

    let packet_size = pointer.read_u16::<BigEndian>()?;
    if packet_size < 22 as u16 {
        trace!(
            "Recieved an ImHere packet with an invalid size: {:?}",
            packet_size
        );
        return Ok(None);
    }

    let mut peer_address_arr: [u16; 8] = [0xFFFF; 8];
    for i in (0..8).rev() {
        peer_address_arr[i] = pointer.read_u16::<BigEndian>()?;
    }
    let peer_address = Ipv6Addr::new(
        peer_address_arr[7],
        peer_address_arr[6],
        peer_address_arr[5],
        peer_address_arr[4],
        peer_address_arr[3],
        peer_address_arr[2],
        peer_address_arr[1],
        peer_address_arr[0],
    );

    if peer_address.is_unspecified() || peer_address.is_loopback() || peer_address.is_multicast() {
        trace!(
            "Recieved a valid ImHere with an invalid ip address: {:?}",
            peer_address,
        );
        return Ok(None);
    }

    trace!("ImHere decoding completed successfully {:?}", peer_address);
    Ok(Some(peer_address))
}

fn send_imhere(interfaces: &mut Vec<ListenInterface>) -> Result<(), Error> {
    trace!("About to send ImHere");
    for listen_interface in interfaces.iter_mut() {
        trace!(
            "Sending ImHere to {:?}, with ip {:?}",
            listen_interface.ifname,
            listen_interface.linklocal_ip
        );

        let result = listen_interface.linklocal_socket.send_to(
            &encode_im_here(listen_interface.linklocal_ip.clone()),
            listen_interface.multicast_socketaddr,
        );
        trace!("Sending ImHere to broadcast gets {:?}", result);
    }
    Ok(())
}

fn recieve_imhere(interfaces: &mut Vec<ListenInterface>) -> Result<Vec<Peer>, Error> {
    trace!("About to dequeue ImHere");
    let mut output = Vec::<Peer>::new();
    for listen_interface in interfaces.iter_mut() {
        let mut socket_empty = false;
        // Since the only datagrams we are interested in are very small (22 bytes plus overhead)
        // this buffer is kept intentionally small to discard larger packets earlier rather than later
        while !socket_empty {
            let mut datagram: [u8; 100] = [0; 100];
            let res = listen_interface.multicast_socket.recv_from(&mut datagram);
            if res.is_err() {
                trace!("Could not recv ImHere");
                // TODO Consider we might want to remove interfaces that produce specific types
                // of errors from the active list
                socket_empty = true;
                continue;
            }

            let res = decode_im_here(&mut datagram.to_vec());
            if res.is_err() {
                trace!("ImHere decode failed!");
                continue;
            }

            let res = res.unwrap();
            if res.is_none() {
                trace!("ImHere decode was unsuccessful!");
                continue;
            }
            let ipaddr = res.unwrap();

            if ipaddr == listen_interface.linklocal_ip {
                trace!("Got ImHere from myself");
                continue;
            }

            for peer in output.iter() {
                if peer.contact_ip == ipaddr {
                    trace!(
                        "Discarding ImHere We already have a peer with {:?} for this cycle",
                        ipaddr
                    );
                    continue;
                }
            }
            trace!("ImHere with {:?}", ipaddr);
            let peer = Peer::new(ipaddr, listen_interface.ifidx);
            output.push(peer);
        }
    }
    Ok(output)
}
