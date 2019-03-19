//! Tunnel manager manages WireGuard tunnels between mesh peers. In rita_loop PeerListener is called
//! and asked about what peers it has heard from since the last cycle, these peers are passed to
//! TunnelManager, which then orchestrates calling these peers over their http endpoints and setting
//! up tunnels if they respond, likewise if someone calls us their hello goes through network_endpoints
//! then into TunnelManager to open a tunnel for them.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use ::actix::actors::resolver;
use ::actix::prelude::*;

use futures::Future;

use althea_types::Identity;
use althea_types::LocalIdentity;

use crate::KI;

use babel_monitor::Babel;

use crate::rita_common;
use crate::rita_common::hello_handler::Hello;
use crate::rita_common::peer_listener::Peer;

use crate::SETTING;
use settings::RitaCommonSettings;

use failure::Error;

#[cfg(test)]
use ::actix::actors::mocker::Mocker;
use std::fmt;
use std::io::{Read, Write};

#[cfg(test)]
type HelloHandler = Mocker<rita_common::hello_handler::HelloHandler>;

#[cfg(not(test))]
type HelloHandler = rita_common::hello_handler::HelloHandler;

#[cfg(test)]
type Resolver = Mocker<resolver::Resolver>;

#[cfg(not(test))]
type Resolver = resolver::Resolver;

#[derive(Debug, Fail)]
pub enum TunnelManagerError {
    #[fail(display = "Port Error: {:?}", _0)]
    PortError(String),
    #[fail(display = "Invalid state")]
    _InvalidStateError,
}

/// Action that progresses the state machine
#[derive(Debug, Clone)]
pub enum TunnelAction {
    /// Received confirmed membership of an identity
    MembershipConfirmed,
    /// Membership expired for an identity
    MembershipExpired,
    /// Payment is not up to date for identity
    PaymentOverdue,
    /// Payment has resumed
    PaidOnTime,
}

impl fmt::Display for TunnelAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// TunnelState indicates a state where a tunnel is currently in. Made into an enum for adding new
/// states more easily
///
/// State changes:
/// NotRegistered -> MembershipConfirmed(not implemented therefore not added) -> Registered
#[derive(PartialEq, Debug, Eq, Hash, Clone, Copy)]
pub struct TunnelState {
    payment_state: PaymentState,
    registration_state: RegistrationState,
}

#[derive(PartialEq, Debug, Clone, Copy, Eq, Hash)]
pub enum RegistrationState {
    /// Tunnel is not registered
    NotRegistered,
    /// Tunnel is registered (default)
    Registered,
}

#[derive(PartialEq, Debug, Clone, Copy, Eq, Hash)]
pub enum PaymentState {
    /// Tunnel is paid (default)
    Paid,
    /// Tunnel is not paid
    Overdue,
}

impl fmt::Display for RegistrationState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for PaymentState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[test]
fn test_registration_state() {
    assert_eq!(
        RegistrationState::NotRegistered.to_string(),
        "NotRegistered"
    );
    assert_eq!(RegistrationState::Registered.to_string(), "Registered");
}

#[test]
fn test_payment_state() {
    assert_eq!(PaymentState::Paid.to_string(), "Paid");
    assert_eq!(PaymentState::Overdue.to_string(), "Overdue");
}

#[derive(PartialEq, Debug, Clone, Eq, Hash)]
pub struct Tunnel {
    pub ip: IpAddr,              // Tunnel endpoint
    pub iface_name: String,      // name of wg#
    pub listen_ifidx: u32,       // the physical interface this tunnel is listening on
    pub listen_port: u16,        // the local port this tunnel is listening on
    pub neigh_id: LocalIdentity, // the identity of the counterparty tunnel
    pub last_contact: Instant,   // When's the last we heard from the other end of this tunnel?
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
            neigh_id: their_id,
            last_contact: Instant::now(),
            // By default new tunnels are in Registered state
            state: TunnelState {
                payment_state: PaymentState::Paid,
                registration_state: RegistrationState::Registered,
            },
        }
    }

    /// Open a real tunnel to match the virtual tunnel we store in memory
    pub fn open(&self) -> Result<(), Error> {
        let network = SETTING.get_network().clone();
        KI.open_tunnel(
            &self.iface_name,
            self.listen_port,
            &SocketAddr::new(self.ip, self.neigh_id.wg_port),
            &self.neigh_id.global.wg_public_key,
            Path::new(&network.wg_private_key_path),
            &match network.mesh_ip {
                Some(ip) => ip,
                None => bail!("No mesh IP configured yet"),
            },
            network.external_nic.clone(),
            &mut SETTING.get_network_mut().default_route,
        )?;
        KI.set_codel_shaping(&self.iface_name)
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

pub struct TunnelManager {
    free_ports: Vec<u16>,
    tunnels: HashMap<Identity, Vec<Tunnel>>,
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
            _ => match self.get_port() {
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
                None
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

pub fn make_babel_stream() -> Result<TcpStream, Error> {
    let stream = TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
    )?;
    Ok(stream)
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
            for tunnel in tunnels.iter() {
                res.push(Neighbor::new(
                    tunnel.neigh_id,
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
        let stream = match make_babel_stream() {
            Ok(stream) => stream,
            Err(e) => {
                warn!("Tunnel GC failed to open babel stream with {:?}", e);
                return Err(e);
            }
        };
        let mut babel = Babel::new(stream);
        let res = babel.start_connection();
        if res.is_err() {
            warn!("Failed to start Babel RPC connection! {:?}", res);
            bail!("Failed to start Babel RPC connection!");
        }

        let mut good: HashMap<Identity, Vec<Tunnel>> = HashMap::new();
        let mut timed_out: HashMap<Identity, Vec<Tunnel>> = HashMap::new();
        // Split entries into good and timed out rebuilding the double hashmap strucutre
        // as you can tell this is enterly copy based and uses 2n ram to prevent borrow
        // checker issues, we should consider a method that does modify in place
        for (identity, tunnels) in self.tunnels.iter() {
            for tunnel in tunnels.iter() {
                if tunnel.last_contact.elapsed() < msg.0 {
                    if good.contains_key(identity) {
                        good.get_mut(identity).unwrap().push(tunnel.clone());
                    } else {
                        good.insert(identity.clone(), Vec::new());
                        good.get_mut(identity).unwrap().push(tunnel.clone());
                    }
                } else if timed_out.contains_key(identity) {
                    timed_out.get_mut(identity).unwrap().push(tunnel.clone());
                } else {
                    timed_out.insert(identity.clone(), Vec::new());
                    timed_out.get_mut(identity).unwrap().push(tunnel.clone());
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
            for tunnel in tunnels {
                // In the same spirit, we return the port to the free port pool only after tunnel
                // deletion goes well.
                let res = babel.unmonitor(&tunnel.iface_name);
                if res.is_err() {
                    warn!("Failed to unmonitor {} with {:?}", tunnel.iface_name, res);
                }
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

    HelloHandler::from_registry().do_send(Hello {
        my_id: LocalIdentity {
            global: SETTING
                .get_identity()
                .ok_or_else(|| format_err!("Identity has no mesh IP ready yet"))?,
            wg_port: our_port,
            have_tunnel: None,
        },
        to: peer.clone(),
    });

    Ok(())
}

/// determines if the list contains a tunnel with the given target ip
fn have_tunnel_by_ip(ip: IpAddr, tunnels: &[Tunnel]) -> bool {
    for tunnel in tunnels.iter() {
        if tunnel.ip == ip {
            return true;
        }
    }
    false
}

/// determines if the list contains a tunnel with the given target ifidx
fn have_tunnel_by_ifidx(ifidx: u32, tunnels: &[Tunnel]) -> bool {
    for tunnel in tunnels.iter() {
        if tunnel.listen_ifidx == ifidx {
            return true;
        }
    }
    false
}

/// gets the tunnel from the list with the given index
fn get_tunnel_by_ifidx(ifidx: u32, tunnels: &[Tunnel]) -> Option<&Tunnel> {
    for tunnel in tunnels.iter() {
        if tunnel.listen_ifidx == ifidx {
            return Some(tunnel);
        }
    }
    None
}

/// deletes all instances of a given tunnel from the list
fn del_tunnel(to_del: &Tunnel, tunnels: &mut Vec<Tunnel>) {
    tunnels.retain(|val| *val != *to_del)
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

    /// Gets a port off of the internal port list after checking that said port is free
    /// with the operating system
    fn get_port(&mut self) -> Option<u16> {
        let udp_table = KI.used_ports();
        let port = self.free_ports.pop();
        match (port, udp_table) {
            (Some(p), Ok(used_ports)) => {
                if used_ports.contains(&p) {
                    warn!("We tried to allocate a used port!");

                    // don't use push here, you'll get that same
                    // entry back in the next pop and recurse forever
                    // hopefully the port will be free when we get
                    // back to it in a few hours
                    self.free_ports.insert(0, p);

                    self.get_port()
                } else {
                    Some(p)
                }
            }
            (Some(p), Err(e)) => {
                // we can either crash for sure here or take the chance
                // that the port is not actually used, we chose the latter
                warn!("Failed to check if port was in use! {:?}", e);
                Some(p)
            }
            (None, _) => None,
        }
    }

    /// This function generates a future and hands it off to the Actix arbiter to actually resolve
    /// in the case that the DNS request is successful the hello handler and eventually the Identity
    /// callback continue execution flow. But this function itself returns syncronously
    pub fn neighbor_inquiry_hostname(&mut self, their_hostname: String) -> Result<(), Error> {
        trace!("Getting tunnel, inq");

        let our_port = match self.get_port() {
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
                    trace!("Saying hello to: {:?} at ip {:?}", url, dnsresult);
                    if !dnsresult.is_empty() && SETTING.get_network().is_gateway {
                        // dns records may have many ip's if we get multiple it's a load
                        // balanced exit and we need to create tunnels to all of them
                        for dns_socket in dnsresult {
                            let their_ip = dns_socket.ip();
                            let socket = SocketAddr::new(their_ip, port);
                            let man_peer = Peer {
                                ifidx: 0,
                                contact_socket: socket,
                            };
                            let res = contact_neighbor(&man_peer, our_port);
                            if res.is_err() {
                                warn!("Contact neighbor failed with {:?}", res);
                            }
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
        let our_port = match self.get_port() {
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
        let key = their_localid.global;

        let we_have_tunnel = match self.tunnels.get(&key) {
            Some(tunnels) => {
                have_tunnel_by_ifidx(peer.ifidx, tunnels)
                    && have_tunnel_by_ip(peer.contact_socket.ip(), tunnels)
            }
            None => false,
        };

        let they_have_tunnel = match their_localid.have_tunnel {
            Some(v) => v,
            None => true, // when we don't know take the more conservative option
        };

        let mut return_bool = false;
        if we_have_tunnel {
            // Scope the last_contact bump to let go of self.tunnels before next use
            {
                let tunnels = self.tunnels.get_mut(&key).unwrap();
                for tunnel in tunnels.iter_mut() {
                    if tunnel.listen_ifidx == peer.ifidx && tunnel.ip == peer.contact_socket.ip() {
                        trace!("We already have a tunnel for {:?}", tunnel);
                        info!(
                            "Bumping timestamp after {}s for tunnel: {:?}",
                            tunnel.last_contact.elapsed().as_secs(),
                            tunnel
                        );
                        tunnel.last_contact = Instant::now();
                    }
                }
            }

            if they_have_tunnel {
                // return allocated port as it's not required
                self.free_ports.push(our_port);
                trace!("Looking up for a tunnels by {:?}", key);
                // Unwrap is safe because we confirm membership
                let tunnels = &self.tunnels[&key];
                // Filter by Tunnel::ifidx
                trace!(
                    "Got tunnels by key {:?}: {:?}. Ifidx is {}",
                    key,
                    tunnels,
                    peer.ifidx
                );
                let tunnel = get_tunnel_by_ifidx(peer.ifidx, tunnels)
                    .expect("Unable to find tunnel by ifidx how did this happen?");

                return Ok((tunnel.clone(), true));
            } else {
                // In the case that we have a tunnel and they don't we drop our existing one
                // and agree on the new parameters in this message
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
                    let value = get_tunnel_by_ifidx(peer.ifidx, tunnels).unwrap().clone();
                    del_tunnel(&value, tunnels);
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
            their_localid,
        );
        // Open tunnel
        match tunnel.open() {
            Ok(_) => trace!("Tunnel {:?} is open", tunnel),
            Err(e) => {
                error!("Unable to open tunnel {:?}: {}", tunnel, e);
                return Err(e);
            }
        }
        match tunnel.monitor(make_babel_stream()?) {
            Ok(_) => {
                let new_key = tunnel.neigh_id.global;
                // Add a tunnel to internal map based on identity, and interface index.
                self.tunnels
                    .entry(new_key)
                    .or_insert_with(Vec::new)
                    .push(tunnel.clone());
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
// also called by DebtKeeper when someone doesn't pay their bill
impl Handler<TunnelStateChange> for TunnelManager {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: TunnelStateChange, _: &mut Context<Self>) -> Self::Result {
        trace!(
            "Tunnel state change request for {:?} with action {:?}",
            msg.identity,
            msg.action
        );
        let mut tunnel_bw_limits_need_change = false;

        // Find a tunnel
        match self.tunnels.get_mut(&msg.identity) {
            Some(tunnels) => {
                for tunnel in tunnels.iter_mut() {
                    trace!("Handle action {} on tunnel {:?}", msg.action, tunnel);
                    match msg.action {
                        TunnelAction::MembershipConfirmed => {
                            trace!(
                                "Membership confirmed for identity {:?} returned tunnel {:?}",
                                msg.identity,
                                tunnel
                            );
                            match tunnel.state.registration_state {
                                RegistrationState::NotRegistered => {
                                    tunnel.monitor(make_babel_stream()?)?;
                                    tunnel.state.registration_state = RegistrationState::Registered;
                                }
                                RegistrationState::Registered => {
                                    continue;
                                }
                            }
                        }
                        TunnelAction::MembershipExpired => {
                            trace!("Membership for identity {:?} is expired", msg.identity);
                            match tunnel.state.registration_state {
                                RegistrationState::Registered => {
                                    tunnel.unmonitor(make_babel_stream()?)?;
                                    tunnel.state.registration_state =
                                        RegistrationState::NotRegistered;
                                }
                                RegistrationState::NotRegistered => {
                                    continue;
                                }
                            }
                        }
                        TunnelAction::PaidOnTime => {
                            trace!("identity {:?} has paid!", msg.identity);
                            match tunnel.state.payment_state {
                                PaymentState::Paid => {
                                    continue;
                                }
                                PaymentState::Overdue => {
                                    trace!("Tunnel {:?} has returned to a paid state.", tunnel);
                                    tunnel.state.payment_state = PaymentState::Paid;
                                    tunnel_bw_limits_need_change = true;
                                }
                            }
                        }
                        TunnelAction::PaymentOverdue => {
                            trace!("No payment from identity {:?}", msg.identity);
                            match tunnel.state.payment_state {
                                PaymentState::Paid => {
                                    trace!("Tunnel {:?} has entered an overdue state.", tunnel);
                                    tunnel.state.payment_state = PaymentState::Overdue;
                                    tunnel_bw_limits_need_change = true;
                                }
                                PaymentState::Overdue => {
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

        // this is done ouside of the match to make the borrow checker happy
        if tunnel_bw_limits_need_change {
            let res = tunnel_bw_limit_update(&self.tunnels);
            // if this fails consistently it could be a wallet draining attack
            // TODO check for that case
            if res.is_err() {
                error!("Bandwidth limiting failed with {:?}", res);
            }
        }

        Ok(())
    }
}

/// Takes the tunnels list and iterates over it to update all of the traffic control settings
/// since we can't figure out how to combine interfaces badnwidth budgets we're subdividing it
/// here with manual terminal commands whenever there is a change
fn tunnel_bw_limit_update(tunnels: &HashMap<Identity, Vec<Tunnel>>) -> Result<(), Error> {
    // number of interfaces over which we will have to divide free tier BW
    let mut limited_interfaces = 0u16;
    for sublist in tunnels.iter() {
        for tunnel in sublist.1.iter() {
            if tunnel.state.payment_state == PaymentState::Overdue {
                limited_interfaces += 1;
            }
        }
    }
    let bw_per_iface = if limited_interfaces > 0 {
        SETTING.get_payment().free_tier_throughput / u32::from(limited_interfaces)
    } else {
        SETTING.get_payment().free_tier_throughput
    };

    for sublist in tunnels.iter() {
        for tunnel in sublist.1.iter() {
            let payment_state = &tunnel.state.payment_state;
            let iface_name = &tunnel.iface_name;
            let has_limit = KI.has_limit(iface_name)?;

            if *payment_state == PaymentState::Overdue {
                KI.set_classless_limit(iface_name, bw_per_iface)?;
            } else if *payment_state == PaymentState::Paid && has_limit {
                KI.set_codel_shaping(iface_name)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::rita_common::tunnel_manager::RegistrationState;
    use crate::rita_common::tunnel_manager::Tunnel;
    use crate::rita_common::tunnel_manager::TunnelManager;
    use althea_types::Identity;
    use althea_types::LocalIdentity;

    /// gets a mutable reference tunnel from the list with the given index
    fn get_mut_tunnel_by_ifidx(ifidx: u32, tunnels: &mut Vec<Tunnel>) -> Option<&mut Tunnel> {
        for tunnel in tunnels.iter_mut() {
            if tunnel.listen_ifidx == ifidx {
                return Some(tunnel);
            }
        }
        None
    }

    #[test]
    pub fn test_tunnel_manager() {
        let mut tunnel_manager = TunnelManager::new();
        assert_eq!(tunnel_manager.free_ports.pop().unwrap(), 65534);
    }

    #[test]
    pub fn test_tunnel_manager_lookup() {
        use clarity::Address;
        use std::str::FromStr;

        let mut tunnel_manager = TunnelManager::new();

        // Create dummy identity
        let id = Identity::new(
            "0.0.0.0".parse().unwrap(),
            Address::from_str("ffffffffffffffffffffffffffffffffffffffff").unwrap(),
            "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
            None,
        );
        assert!(tunnel_manager.tunnels.get(&id).is_none());

        // Create dummy tunnel
        tunnel_manager
            .tunnels
            .entry(id)
            .or_insert_with(Vec::new)
            .push(Tunnel::new(
                "0.0.0.0".parse().unwrap(),
                "iface".into(),
                65535,
                0,
                LocalIdentity {
                    wg_port: 65535,
                    have_tunnel: Some(true),
                    global: id,
                },
            ));
        {
            let existing_tunnel =
                get_mut_tunnel_by_ifidx(0u32, tunnel_manager.tunnels.get_mut(&id).unwrap())
                    .expect("Unable to find existing tunnel");
            assert_eq!(
                existing_tunnel.state.registration_state,
                RegistrationState::Registered
            );
            // Verify mutability - manual modifications shouldn't happen elsewhere
            existing_tunnel.state.registration_state = RegistrationState::NotRegistered;
        }

        // Verify if object is modified
        {
            let existing_tunnel =
                get_mut_tunnel_by_ifidx(0u32, tunnel_manager.tunnels.get_mut(&id).unwrap())
                    .expect("Unable to find existing tunnel");
            assert_eq!(
                existing_tunnel.state.registration_state,
                RegistrationState::NotRegistered
            );
        }
    }
}
