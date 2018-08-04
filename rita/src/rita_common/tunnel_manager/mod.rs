use rita_common::peer_listener::Peer;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;

use actix::actors::resolver;
use actix::prelude::*;

use futures::Future;

use althea_types::LocalIdentity;

use KI;

use babel_monitor::{Babel, Route};

use rita_common;
use rita_common::http_client::Hello;

use settings::RitaCommonSettings;
use SETTING;

use failure::Error;

#[cfg(test)]
use actix::actors::mocker::Mocker;
use ipnetwork::IpNetwork;

#[cfg(test)]
type HTTPClient = Mocker<rita_common::http_client::HTTPClient>;

#[cfg(not(test))]
type HTTPClient = rita_common::http_client::HTTPClient;

#[cfg(test)]
type Resolver = Mocker<resolver::Resolver>;

#[cfg(not(test))]
type Resolver = resolver::Resolver;

/* Uncomment when tunnel state handling is added
#[derive(Debug, Clone)]
pub enum TunnelState {
    Init,
    Open,
    Throttled,
    Closed,
}
*/

#[derive(Debug, Clone)]
pub struct Tunnel {
    pub ip: IpAddr,
    pub iface_name: String,
    pub listen_port: u16,
    //    pub tunnel_state: TunnelState,
    pub localid: LocalIdentity,
}

impl Tunnel {
    fn new(ip: IpAddr, our_listen_port: u16, their_id: LocalIdentity) -> Result<Tunnel, Error> {
        let iface_name = KI.setup_wg_if().unwrap();

        //let init = TunnelState::Init;
        let tunnel = Tunnel {
            ip: ip,                       //tunnel endpoint
            iface_name: iface_name,       //name of wg#
            listen_port: our_listen_port, //the port this tunnel resides on
            //            tunnel_state: init,           //how this tunnel feels about it's life
            localid: their_id.clone(), // the identity of the counterparty tunnel once we have it
        };

        let network = SETTING.get_network().clone();

        // TODO you have the iface index use it
        KI.open_tunnel(
            &tunnel.iface_name,
            tunnel.listen_port,
            &SocketAddr::new(ip, their_id.wg_port),
            &their_id.global.wg_public_key,
            Path::new(&network.wg_private_key_path),
            &network.own_ip,
            network.external_nic.clone(),
            &mut SETTING.get_network_mut().default_route,
        )?;

        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;

        let mut babel = Babel::new(stream);

        babel.start_connection()?;
        babel.monitor(&tunnel.iface_name)?;

        Ok(tunnel)
    }
}

pub struct TunnelManager {
    free_ports: Vec<u16>,
    tunnels: Vec<Tunnel>,
}

impl Actor for TunnelManager {
    type Context = Context<Self>;
}
impl Supervised for TunnelManager {}
impl SystemService for TunnelManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Tunnel manager started");
    }
}

impl Default for TunnelManager {
    fn default() -> TunnelManager {
        TunnelManager::new()
    }
}

pub struct IdentityCallback(pub LocalIdentity, pub Peer, pub Option<u16>);
impl Message for IdentityCallback {
    type Result = Option<Tunnel>;
}

// An attempt to contact a neighbor has succeeded or a neighbor has contacted us, either way
// we need to allocate a tunnel for them and place it onto our local storage.  In the case
// that a neighbor contacts us we don't have a port already allocated and we need to choose one
// in the case that we have atempted to contact a neighbor we have already sent them a port that
// we now must attach to their tunnel entry.
impl Handler<IdentityCallback> for TunnelManager {
    type Result = Option<Tunnel>;

    fn handle(&mut self, msg: IdentityCallback, _: &mut Context<Self>) -> Self::Result {
        let peer_local_id = msg.0;
        let peer = msg.1;
        let our_port = match msg.2 {
            Some(port) => port,
            _ => self.get_port(),
        };

        let res = self.open_tunnel(peer_local_id, peer, our_port);
        match res {
            Ok(res) => Some(res),
            Err(e) => {
                warn!("Open Tunnel failed with {:?}", e);
                return None;
            }
        }
    }
}

// An attempt to contact a neighbor has failed and we need to return the port to
// the available ports list
pub struct PortCallback(pub u16);
impl Message for PortCallback {
    type Result = ();
}

impl Handler<PortCallback> for TunnelManager {
    type Result = ();

    fn handle(&mut self, msg: PortCallback, _: &mut Context<Self>) -> Self::Result {
        let port = msg.0;
        self.free_ports.push(port);
    }
}

#[derive(Debug)]
pub struct GetPhyIpFromMeshIp(pub IpAddr);
impl Message for GetPhyIpFromMeshIp {
    type Result = Result<IpAddr, Error>;
}

impl Handler<GetPhyIpFromMeshIp> for TunnelManager {
    type Result = Result<IpAddr, Error>;

    fn handle(&mut self, mesh_ip: GetPhyIpFromMeshIp, _: &mut Context<Self>) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;

        let mut babel = Babel::new(stream);
        babel.start_connection()?;
        let routes = babel.parse_routes()?;

        let mut route_to_des: Option<Route> = None;

        for route in routes {
            // Only ip6
            if let IpNetwork::V6(ref ip) = route.prefix {
                // Only host addresses and installed routes
                if ip.prefix() == 128 && route.installed {
                    if IpAddr::V6(ip.ip()) == mesh_ip.0 {
                        route_to_des = Some(route.clone());
                    }
                }
            }
        }

        match route_to_des {
            Some(route) => Ok(KI.get_wg_remote_ip(&route.iface)?),
            None => bail!("No route found for mesh ip: {:?}", mesh_ip),
        }
    }
}

pub struct GetNeighbors;
impl Message for GetNeighbors {
    type Result = Result<Vec<(LocalIdentity, String, IpAddr)>, Error>;
}

impl Handler<GetNeighbors> for TunnelManager {
    type Result = Result<Vec<(LocalIdentity, String, IpAddr)>, Error>;

    fn handle(&mut self, _: GetNeighbors, _: &mut Context<Self>) -> Self::Result {
        let mut res = Vec::new();
        for tunnel in self.tunnels.iter() {
            res.push((tunnel.localid.clone(), tunnel.iface_name.clone(), tunnel.ip));
        }
        Ok(res)
    }
}

pub struct PeersToContact(pub Vec<Peer>);

impl Message for PeersToContact {
    type Result = ();
}

impl Handler<PeersToContact> for TunnelManager {
    type Result = ();
    fn handle(&mut self, peers: PeersToContact, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("TunnelManager contacting peers");
        for peer in peers.0.iter() {
            let res = self.neighbor_inquiry(peer.clone());
            if res.is_err() {
                warn!("Neighbor inqury for {:?} failed!", peer);
            }
        }
        // Do not contact manual peers if we are not a gateway
        if SETTING.get_network().is_gateway {
            for manual_peer in SETTING.get_network().manual_peers.iter() {
                let ip = manual_peer.parse::<IpAddr>();
                let port = SETTING.get_network().rita_hello_port;
                if ip.is_ok() {
                    let ip = ip.unwrap();
                    let socket = SocketAddr::new(ip, port);
                    let man_peer = Peer {
                        contact_ip: ip,
                        ifidx: 0,
                        contact_socket: socket,
                    };
                    let res = self.neighbor_inquiry(man_peer);
                    if res.is_err() {
                        warn!("Neighbor inqury for {:?} failed!", manual_peer);
                    }
                } else {
                    let res = self.neighbor_inquiry_hostname(manual_peer.to_string());
                    if res.is_err() {
                        warn!("Neighbor inqury for {:?} failed!", manual_peer);
                    }
                }
            }
        }
    }
}

/// Sets out to contact a neighbor, takes a speculative port (only assigned if the neighbor
/// responds successfully) TODO implement callback to return this port
fn contact_neighbor(peer: Peer, our_port: u16) -> Result<(), Error> {
    KI.manual_peers_route(
        &peer.contact_ip,
        &mut SETTING.get_network_mut().default_route,
    ).unwrap();

    let _res = HTTPClient::from_registry().do_send(Hello {
        my_id: LocalIdentity {
            global: SETTING.get_identity(),
            wg_port: our_port,
        },
        to: peer,
    });

    Ok(())
}

impl TunnelManager {
    pub fn new() -> Self {
        let start = SETTING.get_network().wg_start_port;
        let mut ports = Vec::<u16>::new();
        for i in start..65500 {
            ports.push(i);
        }
        TunnelManager {
            free_ports: ports,
            tunnels: Vec::<Tunnel>::new(),
        }
    }

    pub fn get_port(&mut self) -> u16 {
        let port = self.free_ports.pop();
        if port.is_none() {
            panic!("Tunnelmanager ran out of ports!")
        }
        port.unwrap()
    }

    pub fn neighbor_inquiry_hostname(&mut self, their_hostname: String) -> Result<(), Error> {
        trace!("Getting tunnel, inq");

        // possible port allocation
        let our_port = self.get_port();

        let res = Resolver::from_registry()
            .send(resolver::Resolve::host(their_hostname.clone()))
            .then(move |res| match res {
                Ok(Ok(dnsresult)) => {
                    let port = SETTING.get_network().rita_hello_port;
                    let url = format!("http://[{}]:{}/hello", their_hostname, port);
                    info!("Saying hello to: {:?} at ip {:?}", url, dnsresult);
                    if dnsresult.len() > 0 && SETTING.get_network().is_gateway {
                        let their_ip = dnsresult[0].ip();
                        let socket = SocketAddr::new(their_ip, port);
                        let man_peer = Peer {
                            contact_ip: their_ip,
                            ifidx: 0,
                            contact_socket: socket,
                        };
                        let res = contact_neighbor(man_peer, our_port);
                        if res.is_err() {
                            warn!("Contact neighbor failed with {:?}", res);
                        }
                    } else {
                        trace!(
                            "We're not a gateway or we got a zero length dns response: {:?}",
                            dnsresult
                        );
                    }
                    Ok(())
                }
                Err(e) => {
                    warn!("Actor mailbox failure from DNS resolver! {:?}", e);
                    Ok(())
                }

                Ok(Err(e)) => {
                    warn!("DNS resolution failed with {:?}", e);
                    Ok(())
                }
            });
        Arbiter::spawn(res);
        Ok(())
    }

    /// Contacts one neighbor with our LocalIdentity to get their LocalIdentity and wireguard tunnel
    /// interface name.
    pub fn neighbor_inquiry(&mut self, peer: Peer) -> Result<(), Error> {
        trace!("TunnelManager neigh inquiry for {:?}", peer);
        // possible port allocation
        let our_port = self.get_port();

        contact_neighbor(peer, our_port)
    }

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    pub fn open_tunnel(
        &mut self,
        their_id: LocalIdentity,
        peer: Peer,
        our_port: u16,
    ) -> Result<Tunnel, Error> {
        trace!("TunnelManager getting existing tunnel or opening a new one");
        for tunnel in self.tunnels.iter() {
            if tunnel.ip == peer.contact_ip {
                trace!("TunnelManager We already have a tunnel for {:?}", tunnel.ip);
                // return allocated port as it's not required
                self.free_ports.push(our_port);
                return Ok(tunnel.clone());
            }
        }
        trace!(
            "TunnelManager no tunnel found for {:?} creating",
            peer.contact_ip
        );
        let tunnel = Tunnel::new(peer.contact_ip, our_port, their_id.clone());
        match tunnel {
            Ok(tunnel) => {
                self.tunnels.push(tunnel.clone());
                Ok(tunnel)
            }
            Err(e) => {
                warn!("Open Tunnel failed with {:?}", e);
                return Err(e);
            }
        }
    }
}
