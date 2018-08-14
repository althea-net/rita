/*
Tunnel manager manages WireGuard tunnels between mesh peers. In rita_loop PeerListener is called
and asked about what peers it has heard from since the last cycle, these peers are passed to
TunnelManager, which then orchestrates calling these peers over their http endpoints and setting
up tunnels if they respond, likewise if someone calls us their hello goes through network_endpoints
then into TunnelManager to open a tunnel for them.
*/
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;

use actix::actors::resolver;
use actix::prelude::*;

use futures::Future;

use althea_types::Identity;
use althea_types::LocalIdentity;

use KI;

use babel_monitor::{Babel, Route};

use rita_common;
use rita_common::http_client::Hello;
use rita_common::peer_listener::Peer;

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

#[derive(Debug, Fail)]
pub enum TunnelManagerError {
    #[fail(display = "Port Error: {:?}", _0)]
    PortError(String),
}

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
    pub ip: IpAddr,         // Tunnel endpoint
    pub iface_name: String, // name of wg#
    pub listen_ifidx: u32,  // the physical interface this tunnel is listening on
    pub listen_port: u16,   // the local port this tunnel is listening on
    //    pub tunnel_state: TunnelState, // how this exit feels about it's lifecycle
    pub localid: LocalIdentity, // the identity of the counterparty tunnel
}

impl Tunnel {
    fn new(
        ip: IpAddr,
        our_listen_port: u16,
        ifidx: u32,
        their_id: LocalIdentity,
    ) -> Result<Tunnel, Error> {
        let iface_name = KI.setup_wg_if().unwrap();

        //let init = TunnelState::Init;
        let tunnel = Tunnel {
            ip: ip,
            iface_name: iface_name,
            listen_ifidx: ifidx,
            listen_port: our_listen_port,
            //tunnel_state: init,
            localid: their_id.clone(),
        };

        let network = SETTING.get_network().clone();

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

#[derive(PartialEq, Eq, Hash, Debug)]
struct TunnelIdentity {
    /// Identity of the owner of tunnel
    identity: Identity,
    /// Interface index
    ifidx: u32,
}

impl TunnelIdentity {
    fn new(identity: Identity, ifidx: u32) -> TunnelIdentity {
        TunnelIdentity { identity, ifidx }
    }
}

pub struct TunnelManager {
    free_ports: Vec<u16>,
    tunnels: HashMap<TunnelIdentity, Tunnel>,
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
    type Result = Option<(Tunnel, bool)>;
}

// An attempt to contact a neighbor has succeeded or a neighbor has contacted us, either way
// we need to allocate a tunnel for them and place it onto our local storage.  In the case
// that a neighbor contacts us we don't have a port already allocated and we need to choose one
// in the case that we have atempted to contact a neighbor we have already sent them a port that
// we now must attach to their tunnel entry. If we also return a bool for if the tunnel already
// exists
impl Handler<IdentityCallback> for TunnelManager {
    type Result = Option<(Tunnel, bool)>;

    fn handle(&mut self, msg: IdentityCallback, _: &mut Context<Self>) -> Self::Result {
        let peer_local_id = msg.0;
        let peer = msg.1;
        let our_port = match msg.2 {
            Some(port) => port,
            _ => match self.free_ports.pop() {
                Some(p) => p,
                None => {
                    warn!("Failed to allocate tunnel port! All tunnel opening will fail");
                    return None;
                }
            },
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
        for obj in self.tunnels.iter() {
            let tunnel = obj.1;
            res.push((tunnel.localid.clone(), tunnel.iface_name.clone(), tunnel.ip));
        }
        Ok(res)
    }
}

pub struct PeersToContact(pub HashMap<IpAddr, Peer>);

impl Message for PeersToContact {
    type Result = ();
}

/// Takes a list of peers to contact and dispatches requests if you have a WAN connection
/// it will also dispatch neighbor requests to manual peers
impl Handler<PeersToContact> for TunnelManager {
    type Result = ();
    fn handle(&mut self, msg: PeersToContact, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("TunnelManager contacting peers");
        for obj in msg.0.iter() {
            let peer = obj.1;
            let res = self.neighbor_inquiry(peer.clone());
            if res.is_err() {
                warn!("Neighbor inqury for {:?} failed! with {:?}", peer, res);
            }
        }
        // Do not contact manual peers if we are not a gateway
        if SETTING.get_network().is_gateway {
            for manual_peer in SETTING.get_network().manual_peers.iter() {
                let ip = manual_peer.parse::<IpAddr>();
                let port = SETTING.get_network().rita_hello_port;

                match ip {
                    Ok(ip) => {
                        let socket = SocketAddr::new(ip, port);
                        let man_peer = Peer {
                            ifidx: 0,
                            contact_socket: socket,
                        };
                        let res = self.neighbor_inquiry(man_peer);
                        if res.is_err() {
                            warn!(
                                "Neighbor inqury for {:?} failed with: {:?}",
                                manual_peer, res
                            );
                        }
                    }
                    Err(_) => {
                        let res = self.neighbor_inquiry_hostname(manual_peer.to_string());
                        if res.is_err() {
                            warn!(
                                "Neighbor inqury for {:?} failed with: {:?}",
                                manual_peer, res
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Sets out to contact a neighbor, takes a speculative port (only assigned if the neighbor
/// responds successfully)
fn contact_neighbor(peer: Peer, our_port: u16) -> Result<(), Error> {
    KI.manual_peers_route(
        &peer.contact_socket.ip(),
        &mut SETTING.get_network_mut().default_route,
    )?;

    let _res = HTTPClient::from_registry().do_send(Hello {
        my_id: LocalIdentity {
            global: SETTING.get_identity(),
            wg_port: our_port,
            have_tunnel: None,
        },
        to: peer,
    });

    Ok(())
}

impl TunnelManager {
    pub fn new() -> Self {
        let start = SETTING.get_network().wg_start_port;
        let ports = (start..65535).collect();
        TunnelManager {
            free_ports: ports,
            tunnels: HashMap::<TunnelIdentity, Tunnel>::new(),
        }
    }

    /// This function generates a future and hands it off to the Actix arbiter to actually resolve
    /// in the case that the DNS request is successful the hello handler and eventually the Identity
    /// callback continue execution flow. But this function itself returns syncronously
    pub fn neighbor_inquiry_hostname(&mut self, their_hostname: String) -> Result<(), Error> {
        trace!("Getting tunnel, inq");

        let our_port = match self.free_ports.pop() {
            Some(p) => p,
            None => {
                warn!("Failed to allocate tunnel port! All tunnel opening will fail");
                return Err(TunnelManagerError::PortError("No remaining ports!".to_string()).into());
            }
        };

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
                    // We might need a port callback here
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
        let our_port = match self.free_ports.pop() {
            Some(p) => p,
            None => {
                warn!("Failed to allocate tunnel port! All tunnel opening will fail");
                return Err(TunnelManagerError::PortError("No remaining ports!".to_string()).into());
            }
        };

        contact_neighbor(peer, our_port)
    }

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    /// return the tunnel object and if already had a tunnel
    pub fn open_tunnel(
        &mut self,
        their_localid: LocalIdentity,
        peer: Peer,
        our_port: u16,
    ) -> Result<(Tunnel, bool), Error> {
        trace!("getting existing tunnel or opening a new one");
        // ifidx must be a part of the key so that we can open multiple tunnels
        // if we have more than one physical connection to the same peer
        let key = TunnelIdentity::new(their_localid.global.clone(), peer.ifidx);
        let we_have_tunnel = self.tunnels.contains_key(&key);
        let they_have_tunnel = match their_localid.have_tunnel {
            Some(v) => v,
            None => true, // when we don't take the more conservative option
        };

        let mut return_bool = false;

        if we_have_tunnel && they_have_tunnel {
            trace!(
                "We already have a tunnel for {:?}%{:?}",
                peer.contact_socket.ip(),
                peer.ifidx,
            );
            // return allocated port as it's not required
            self.free_ports.push(our_port);
            // Unwrap is safe because we confirm membership
            let tunnel = self.tunnels.get(&key).unwrap();
            return Ok((tunnel.clone(), true));
        }

        if we_have_tunnel && !they_have_tunnel {
            trace!(
                "We have a tunnel but our peer {:?} does not! Handling",
                peer.contact_socket.ip()
            );
            // Unwrap is safe because we confirm membership
            let iface_name = self.tunnels.get(&key).unwrap().iface_name.clone();
            let port = self.tunnels.get(&key).unwrap().listen_port.clone();
            let res = KI.del_interface(&iface_name);
            if res.is_err() {
                warn!(
                    "We failed to delete the interface {:?} with {:?} it's now orphaned",
                    iface_name, res
                );
            }

            // In the case that we have a tunnel and they don't we drop our existing one
            // and agree on the new parameters in this message
            self.tunnels.remove(&key);
            self.free_ports.push(port);
            return_bool = true;
        }

        trace!(
            "no tunnel found for {:?}%{:?} creating",
            peer.contact_socket.ip(),
            peer.ifidx,
        );
        let tunnel = Tunnel::new(
            peer.contact_socket.ip(),
            our_port,
            peer.ifidx,
            their_localid.clone(),
        );

        match tunnel {
            Ok(tunnel) => {
                let new_key =
                    TunnelIdentity::new(tunnel.localid.global.clone(), tunnel.listen_ifidx.clone());
                self.tunnels.insert(new_key, tunnel.clone());
                Ok((tunnel, return_bool))
            }
            Err(e) => {
                warn!("Open Tunnel failed with {:?}", e);
                return Err(e);
            }
        }
    }
}

#[test]
pub fn test_tunnel_manager() {
    let mut tunnel_manager = TunnelManager::new();
    assert_eq!(tunnel_manager.free_ports.pop().unwrap(), 65534);
}
