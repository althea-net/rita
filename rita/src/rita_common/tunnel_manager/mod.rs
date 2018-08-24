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
use std::time::{Duration, Instant};

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
use std::fmt;
use std::io::{Read, Write};

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
    #[fail(display = "Invalid state")]
    InvalidStateError,
}

/// Action that progresses the state machine
#[derive(Debug, Clone)]
pub enum TunnelAction {
    /// Received confirmed membership of an identity
    MembershipConfirmed,
    /// Membership expired for an identity
    MembershipExpired,
}

impl fmt::Display for TunnelAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

///
/// TunnelState indicates a state where a tunnel is currently in.
///
/// State changes:
/// NotRegistered -> (MembershipConfirmed) -> Registered
#[derive(PartialEq, Debug, Clone)]
pub enum TunnelState {
    /// Tunnel is not registered (default)
    NotRegistered,
    /// Tunnel is registered
    Registered,
}

impl fmt::Display for TunnelState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[test]
fn test_tunnel_state() {
    assert_eq!(TunnelState::NotRegistered.to_string(), "NotRegistered");
    assert_eq!(TunnelState::Registered.to_string(), "Registered");
}

#[derive(Debug, Clone)]
pub struct Tunnel {
    pub ip: IpAddr,             // Tunnel endpoint
    pub iface_name: String,     // name of wg#
    pub listen_ifidx: u32,      // the physical interface this tunnel is listening on
    pub listen_port: u16,       // the local port this tunnel is listening on
    pub localid: LocalIdentity, // the identity of the counterparty tunnel
    pub last_contact: Instant,  // When's the last we heard from the other end of this tunnel?
    state: TunnelState,
}

impl Tunnel {
    fn new(
        ip: IpAddr,
        iface_name: String,
        our_listen_port: u16,
        ifidx: u32,
        their_id: LocalIdentity,
    ) -> Tunnel {
        Tunnel {
            ip: ip,
            iface_name: iface_name,
            listen_ifidx: ifidx,
            listen_port: our_listen_port,
            localid: their_id.clone(),
            last_contact: Instant::now(),
            // By default new tunnels are in Registered state
            state: TunnelState::Registered,
        }
    }

    /// Open physical tunnel
    pub fn open(&self) -> Result<(), Error> {
        let network = SETTING.get_network().clone();
        KI.open_tunnel(
            &self.iface_name,
            self.listen_port,
            &SocketAddr::new(self.ip, self.localid.wg_port),
            &self.localid.global.wg_public_key,
            Path::new(&network.wg_private_key_path),
            &network.own_ip,
            network.external_nic.clone(),
            &mut SETTING.get_network_mut().default_route,
        )
    }

    /// Register this tunnel into Babel monitor
    pub fn monitor<T: Read + Write>(&self, stream: T) -> Result<(), Error> {
        info!("Monitoring tunnel {}", self.iface_name);
        let mut babel = Babel::new(stream);
        babel.start_connection()?;
        babel.monitor(&self.iface_name)?;
        Ok(())
    }

    pub fn unmonitor<T: Read + Write>(&self, stream: T) -> Result<(), Error> {
        warn!("Unmonitoring tunnel {}", self.iface_name);
        let mut babel = Babel::new(stream);
        babel.start_connection()?;
        babel.unmonitor(&self.iface_name)?;
        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
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
    tunnels: HashMap<Identity, HashMap<u32, Tunnel>>,
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

pub struct IdentityCallback {
    pub local_identity: LocalIdentity,
    pub peer: Peer,
    pub our_port: Option<u16>,
}

impl IdentityCallback {
    pub fn new(
        local_identity: LocalIdentity,
        peer: Peer,
        our_port: Option<u16>,
    ) -> IdentityCallback {
        IdentityCallback {
            local_identity,
            peer,
            our_port,
        }
    }
}

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
        let our_port = match msg.our_port {
            Some(port) => port,
            _ => match self.free_ports.pop() {
                Some(p) => p,
                None => {
                    warn!("Failed to allocate tunnel port! All tunnel opening will fail");
                    return None;
                }
            },
        };

        let res = self.open_tunnel(msg.local_identity, msg.peer, our_port);
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

fn make_babel_stream() -> Result<TcpStream, Error> {
    let stream = TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
    )?;
    Ok(stream)
}

impl Handler<GetPhyIpFromMeshIp> for TunnelManager {
    type Result = Result<IpAddr, Error>;

    fn handle(&mut self, mesh_ip: GetPhyIpFromMeshIp, _: &mut Context<Self>) -> Self::Result {
        let mut babel = Babel::new(make_babel_stream()?);
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

#[derive(Debug)]
pub struct Neighbor {
    pub identity: LocalIdentity,
    pub iface_name: String,
    pub tunnel_ip: IpAddr,
}

impl Neighbor {
    fn new(identity: LocalIdentity, iface_name: String, tunnel_ip: IpAddr) -> Neighbor {
        Neighbor {
            identity,
            iface_name,
            tunnel_ip,
        }
    }
}

impl Message for GetNeighbors {
    type Result = Result<Vec<Neighbor>, Error>;
}
impl Handler<GetNeighbors> for TunnelManager {
    type Result = Result<Vec<Neighbor>, Error>;

    fn handle(&mut self, _: GetNeighbors, _: &mut Context<Self>) -> Self::Result {
        let mut res = Vec::new();
        for (_, tunnels) in self.tunnels.iter() {
            for (_, tunnel) in tunnels.iter() {
                res.push(Neighbor::new(
                    tunnel.localid.clone(),
                    tunnel.iface_name.clone(),
                    tunnel.ip,
                ));
            }
        }
        Ok(res)
    }
}

/// A message type for deleting all tunnels we haven't heard from for more than the duration.
pub struct TriggerGC(pub Duration);

impl Message for TriggerGC {
    type Result = Result<(), Error>;
}

impl Handler<TriggerGC> for TunnelManager {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: TriggerGC, _ctx: &mut Context<Self>) -> Self::Result {
        let mut good: HashMap<Identity, HashMap<u32, Tunnel>> = HashMap::new();
        let mut timed_out: HashMap<Identity, HashMap<u32, Tunnel>> = HashMap::new();
        // Split entries into good and timed out rebuilding the double hashmap strucutre
        // as you can tell this is enterly copy based and uses 2n ram to prevent borrow
        // checker issues, we should consider a method that does modify in place
        for (identity, tunnels) in self.tunnels.iter() {
            for (ifidx, tunnel) in tunnels.iter() {
                if tunnel.last_contact.elapsed() < msg.0 {
                    if good.contains_key(identity) {
                        good.get_mut(identity)
                            .unwrap()
                            .insert(ifidx.clone(), tunnel.clone());
                    } else {
                        good.insert(identity.clone(), HashMap::new());
                        good.get_mut(identity)
                            .unwrap()
                            .insert(ifidx.clone(), tunnel.clone());
                    }
                } else {
                    if timed_out.contains_key(identity) {
                        timed_out
                            .get_mut(identity)
                            .unwrap()
                            .insert(ifidx.clone(), tunnel.clone());
                    } else {
                        timed_out.insert(identity.clone(), HashMap::new());
                        timed_out
                            .get_mut(identity)
                            .unwrap()
                            .insert(ifidx.clone(), tunnel.clone());
                    }
                }
            }
        }

        info!("TriggerGC: removing tunnels: {:?}", timed_out);

        // Please keep in mind it makes more sense to update the tunnel map *before* yielding the
        // actual interfaces and ports from timed_out.
        //
        // The difference is leaking interfaces on del_interface() failure vs. Rita thinking
        // it has freed ports/interfaces which are still there/claimed.
        //
        // The former would be a mere performance bug while inconsistent-with-reality Rita state
        // would lead to nasty bugs in case del_interface() goes wrong for whatever reason.
        self.tunnels = good;

        for (_ident, tunnels) in timed_out {
            for (_ifidx, tunnel) in tunnels {
                // In the same spirit, we return the port to the free port pool only after tunnel
                // deletion goes well.
                KI.del_interface(&tunnel.iface_name)?;
                self.free_ports.push(tunnel.listen_port);
            }
        }

        Ok(())
    }
}

pub struct PeersToContact {
    pub peers: HashMap<IpAddr, Peer>,
}

impl PeersToContact {
    pub fn new(peers: HashMap<IpAddr, Peer>) -> PeersToContact {
        PeersToContact { peers }
    }
}

impl Message for PeersToContact {
    type Result = ();
}

/// Takes a list of peers to contact and dispatches requests if you have a WAN connection
/// it will also dispatch neighbor requests to manual peers
impl Handler<PeersToContact> for TunnelManager {
    type Result = ();
    fn handle(&mut self, msg: PeersToContact, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("TunnelManager contacting peers");
        for (_, peer) in msg.peers.iter() {
            let res = self.neighbor_inquiry(&peer);
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
                        let res = self.neighbor_inquiry(&man_peer);
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
fn contact_neighbor(peer: &Peer, our_port: u16) -> Result<(), Error> {
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
        to: peer.clone(),
    });

    Ok(())
}

impl TunnelManager {
    pub fn new() -> Self {
        let start = SETTING.get_network().wg_start_port;
        let ports = (start..65535).collect();
        TunnelManager {
            free_ports: ports,
            tunnels: HashMap::new(),
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
                        let res = contact_neighbor(&man_peer, our_port);
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
    pub fn neighbor_inquiry(&mut self, peer: &Peer) -> Result<(), Error> {
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
        let key = their_localid.global.clone();
        let we_have_tunnel = self
            .tunnels
            .get(&key)
            .unwrap_or(&HashMap::new())
            .contains_key(&peer.ifidx);

        let they_have_tunnel = match their_localid.have_tunnel {
            Some(v) => v,
            None => true, // when we don't take the more conservative option
        };

        let mut return_bool = false;
        if we_have_tunnel {
            // Scope the last_contact bump to let go of self.tunnels before next use
            {
                let tunnels = self.tunnels.get_mut(&key).unwrap();
                for hash_obj in tunnels.iter_mut() {
                    let tunnel = hash_obj.1;
                    trace!(
                        "Bumping timestamp after {}s for tunnel: {:?}",
                        tunnel.last_contact.elapsed().as_secs(),
                        tunnel
                    );
                    tunnel.last_contact = Instant::now();
                }
            }

            if they_have_tunnel {
                trace!(
                    "We already have a tunnel for {:?}%{:?}",
                    peer.contact_socket.ip(),
                    peer.ifidx,
                );
                // return allocated port as it's not required
                self.free_ports.push(our_port);
                trace!("Looking up for a tunnels by {:?}", key);
                // Unwrap is safe because we confirm membership
                let tunnels = self.tunnels.get(&key).unwrap();
                // Filter by Tunnel::ifidx
                trace!(
                    "Got tunnels by key {:?}: {:?}. Ifidx is {}",
                    key,
                    tunnels,
                    peer.ifidx
                );
                let tunnel = tunnels
                    .get(&peer.ifidx)
                    .expect("Unable to find tunnel by ifidx how did this happen?");

                return Ok((tunnel.clone(), true));
            } else {
                trace!(
                    "We have a tunnel but our peer {:?} does not! Handling",
                    peer.contact_socket.ip()
                );
                // Unwrapping is safe because we confirm membership. This is done
                // in a separate scope to limit surface of borrow checker.
                let (tunnel, size) = {
                    // Find tunnels by identity
                    let tunnels = self.tunnels.get_mut(&key).unwrap();
                    // Find tunnel by interface index
                    let (_, value) = tunnels.remove_entry(&peer.ifidx).unwrap();
                    // Outer HashMap (self.tunnels) can contain empty HashMaps,
                    // so the resulting tuple will consist of the tunnel itself, and
                    // how many tunnels are still associated with that ID.
                    (value, tunnels.len())
                };
                if size == 0 {
                    // Remove this identity if there are no tunnels associated with it.
                    self.tunnels.remove(&key);
                }

                // Remove interface
                let res = KI.del_interface(&tunnel.iface_name);
                if res.is_err() {
                    warn!(
                        "We failed to delete the interface {:?} with {:?} it's now orphaned",
                        tunnel.iface_name, res
                    );
                }

                // In the case that we have a tunnel and they don't we drop our existing one
                // and agree on the new parameters in this message
                self.tunnels.remove(&key);
                self.free_ports.push(tunnel.listen_port);
                return_bool = true;
            }
        }
        trace!(
            "no tunnel found for {:?}%{:?} creating",
            peer.contact_socket.ip(),
            peer.ifidx,
        );
        // Create new tunnel
        let tunnel = Tunnel::new(
            peer.contact_socket.ip(),
            KI.setup_wg_if().unwrap(),
            our_port,
            peer.ifidx,
            their_localid.clone(),
        );
        // Open tunnel
        match tunnel.open() {
            Ok(_) => info!("Tunnel {:?} is open", tunnel),
            Err(e) => {
                error!("Unable to open tunnel {:?}: {}", tunnel, e);
                return Err(e);
            }
        }
        debug_assert_eq!(tunnel.state, TunnelState::Registered);
        match tunnel.monitor(make_babel_stream()?) {
            Ok(_) => {
                let new_key = tunnel.localid.global.clone();
                // Add a tunnel to internal map based on identity, and interface index.
                self.tunnels
                    .entry(new_key)
                    .or_insert(HashMap::new())
                    .insert(tunnel.listen_ifidx.clone(), tunnel.clone());
                Ok((tunnel, return_bool))
            }
            Err(e) => {
                error!(
                    "Unable to execute babel monitor on tunnel {:?}: {}",
                    tunnel, e
                );
                Err(e)
            }
        }
    }
}

pub struct TunnelStateChange {
    pub identity: Identity,
    pub action: TunnelAction,
}

impl Message for TunnelStateChange {
    type Result = Result<(), Error>;
}

// Called by DAOManager to notify TunnelManager about the registration state of a given peer
impl Handler<TunnelStateChange> for TunnelManager {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: TunnelStateChange, _: &mut Context<Self>) -> Self::Result {
        info!(
            "Tunnel state change request for {:?} with action {:?}",
            msg.identity, msg.action
        );
        // Find a tunnel
        match self.tunnels.get_mut(&msg.identity) {
            Some(tunnels) => {
                for (_, tunnel) in tunnels.iter_mut() {
                    trace!("Handle action {} on tunnel {:?}", msg.action, tunnel);
                    match msg.action {
                        TunnelAction::MembershipConfirmed => {
                            info!(
                                "Membership confirmed for identity {:?} returned tunnel {:?}",
                                msg.identity, tunnel
                            );
                            match tunnel.state {
                                TunnelState::NotRegistered => {
                                    tunnel.monitor(make_babel_stream()?)?;
                                    tunnel.state = TunnelState::Registered;
                                }
                                TunnelState::Registered => {
                                    warn!("Tunnel {:?} already in registered state", tunnel);
                                    continue;
                                }
                            }
                        }
                        TunnelAction::MembershipExpired => {
                            info!("Membership for identity {:?} is expired", msg.identity);
                            match tunnel.state {
                                TunnelState::Registered => {
                                    tunnel.unmonitor(make_babel_stream()?)?;
                                    tunnel.state = TunnelState::NotRegistered;
                                }
                                TunnelState::NotRegistered => {
                                    info!("Tunnel {:?} already in not registered state.", tunnel);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
            None => {
                // TODO: This should probably return error
                warn!("Couldn't find tunnel for identity {:?}", msg.identity);
            }
        }
        Ok(())
    }
}

#[test]
pub fn test_tunnel_manager() {
    let mut tunnel_manager = TunnelManager::new();
    assert_eq!(tunnel_manager.free_ports.pop().unwrap(), 65534);
}

#[test]
pub fn test_tunnel_manager_lookup() {
    use althea_types::EthAddress;
    use std::str::FromStr;

    let mut tunnel_manager = TunnelManager::new();

    // Create dummy identity
    let id = Identity::new(
        "0.0.0.0".parse().unwrap(),
        EthAddress::from_str("ffffffffffffffffffffffffffffffffffffffff").unwrap(),
        String::from("abc0abc1abc2abc3abc4abc5abc6abc7abc8abc9"),
    );
    assert!(tunnel_manager.tunnels.get(&id).is_none());

    // Create dummy tunnel
    tunnel_manager
        .tunnels
        .entry(id.clone())
        .or_insert(HashMap::new())
        .insert(
            0,
            Tunnel::new(
                "0.0.0.0".parse().unwrap(),
                "iface".into(),
                65535,
                0,
                LocalIdentity {
                    wg_port: 65535,
                    have_tunnel: Some(true),
                    global: id.clone(),
                },
            ),
        );
    {
        let existing_tunnel = tunnel_manager
            .tunnels
            .get_mut(&id)
            .unwrap()
            .get_mut(&0u32)
            .expect("Unable to find existing tunnel");
        assert_eq!(existing_tunnel.state, TunnelState::Registered);
        // Verify mutability - manual modifications shouldn't happen elsewhere
        existing_tunnel.state = TunnelState::NotRegistered;
    }

    // Verify if object is modified
    {
        let existing_tunnel = tunnel_manager
            .tunnels
            .get_mut(&id)
            .unwrap()
            .get_mut(&0u32)
            .expect("Unable to find existing tunnel");
        assert_eq!(existing_tunnel.state, TunnelState::NotRegistered);
    }
}
