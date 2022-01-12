//! Tunnel manager manages WireGuard tunnels between mesh peers. In rita_loop PeerListener is called
//! and asked about what peers it has heard from since the last cycle, these peers are passed to
//! TunnelManager, which then orchestrates calling these peers over their http endpoints and setting
//! up tunnels if they respond, likewise if someone calls us their hello goes through network_endpoints
//! then into TunnelManager to open a tunnel for them.

pub mod gc;
pub mod id_callback;
pub mod neighbor_status;
pub mod shaping;

use crate::hello_handler::Hello;
use crate::peer_listener::Hello as NewHello;
use crate::peer_listener::PeerListener;
use crate::peer_listener::PEER_LISTENER;
use crate::peer_listener::{send_hello, Peer};
use crate::rita_loop::is_gateway;
use crate::RitaCommonError;
use crate::FAST_LOOP_TIMEOUT;
use crate::KI;
#[cfg(test)]
use actix::actors::mocker::Mocker;
use actix::actors::resolver;
use actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use althea_kernel_interface::open_tunnel::TunnelOpenArgs;
use althea_types::Identity;
use althea_types::LocalIdentity;
use babel_monitor::monitor;
use babel_monitor::open_babel_stream;
use babel_monitor::unmonitor;
use babel_monitor::BabelMonitorError;
use futures01::Future;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::fmt::Display;
use std::fmt::{Formatter, Result as FmtResult};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(test)]
type HelloHandler = Mocker<crate::hello_handler::HelloHandler>;
#[cfg(not(test))]
type HelloHandler = crate::hello_handler::HelloHandler;
#[cfg(test)]
type Resolver = Mocker<resolver::Resolver>;
#[cfg(not(test))]
type Resolver = resolver::Resolver;

#[derive(Debug)]
pub enum TunnelManagerError {
    _InvalidStateError,
}
impl Display for TunnelManagerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            TunnelManagerError::_InvalidStateError => write!(f, "Invalid state"),
        }
    }
}

/// Used to trigger the enforcement handler
#[derive(Debug, Clone)]
pub enum TunnelAction {
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

/// TunnelState indicates the payment state a tunnel is currently in
/// if this is Overdue the tunnel will use a tbf qdisc to limit traffic on
/// the interface
#[derive(PartialEq, Debug, Clone, Copy, Eq, Hash)]
pub enum PaymentState {
    /// Tunnel is paid (default)
    Paid,
    /// Tunnel is not paid
    Overdue,
}

impl fmt::Display for PaymentState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[test]
fn test_payment_state() {
    assert_eq!(PaymentState::Paid.to_string(), "Paid");
    assert_eq!(PaymentState::Overdue.to_string(), "Overdue");
}

#[derive(PartialEq, Debug, Clone, Eq, Hash)]
pub struct Tunnel {
    /// The tunnel endpoint
    pub ip: IpAddr,
    /// the name of the tunnel in the format of wg# numbers are assigned
    /// in an incrementing fashion but may become inconsistent as tunnels
    /// are closed and reopened.
    pub iface_name: String,
    /// The linux interface id for the physical interface this tunnel is listening on
    pub listen_ifidx: u32,
    /// The port this tunnel is listening on
    pub listen_port: u16,
    /// The identity of the counter party tunnel
    pub neigh_id: LocalIdentity,
    /// An instant representing the last time we heard from this tunnel
    pub last_contact: Instant,
    /// When this tunnel was created
    created: Instant,
    /// Bandwidth limit for codel shaping on this interface, set in mbps be aware this
    /// many or may not actually be set depending on if the host supports codel although
    /// all routers do only exits are in question
    pub speed_limit: Option<usize>,
    /// If true this tunnel is for a light client and is working over ipv4 endpoints
    pub light_client_details: Option<Ipv4Addr>,
    payment_state: PaymentState,
}

impl Display for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tunnel: IP: {} IFACE_NAME: {} IFIDX: {}, PORT: {} WG: {} ETH: {} MESH_IP: {} LAST_SEEN {}, SPEED_LIMIT {:?}, LC {:?}, PAYMENT_STATE: {:?}" , 
        self.ip,
        self.iface_name,
        self.listen_ifidx,
        self.listen_port,
        self.neigh_id.global.wg_public_key,
        self.neigh_id.global.eth_address,
        self.neigh_id.global.mesh_ip,
        (Instant::now() - self.last_contact).as_secs(),
        self.speed_limit,
        self.light_client_details,
        self.payment_state)
    }
}

impl Tunnel {
    pub fn new(
        ip: IpAddr,
        our_listen_port: u16,
        ifidx: u32,
        neigh_id: LocalIdentity,
        light_client_details: Option<Ipv4Addr>,
    ) -> Result<Tunnel, RitaCommonError> {
        let speed_limit = None;
        let iface_name = KI.setup_wg_if()?;
        let mut network = settings::get_rita_common().network;
        let args = TunnelOpenArgs {
            interface: iface_name.clone(),
            port: our_listen_port,
            endpoint: SocketAddr::new(ip, neigh_id.wg_port),
            remote_pub_key: neigh_id.global.wg_public_key,
            private_key_path: Path::new(&network.wg_private_key_path),
            own_ip: match network.mesh_ip {
                Some(ip) => ip,
                None => {
                    return Err(RitaCommonError::MiscStringError(
                        "No mesh IP configured yet".to_string(),
                    ))
                }
            },
            external_nic: network.external_nic.clone(),
            settings_default_route: &mut network.last_default_route,
            allowed_ipv4_address: light_client_details,
        };

        KI.open_tunnel(args)?;
        KI.set_codel_shaping(&iface_name, speed_limit, false)?;

        let now = Instant::now();
        let t = Tunnel {
            ip,
            iface_name,
            listen_ifidx: ifidx,
            listen_port: our_listen_port,
            neigh_id,
            last_contact: now,
            created: now,
            speed_limit,
            light_client_details,
            // By default new tunnels are in paid state
            payment_state: PaymentState::Paid,
        };

        match light_client_details {
            None => {
                // attach to babel
                t.monitor()?;
            }
            Some(_) => {}
        }

        Ok(t)
    }

    pub fn created(&self) -> Instant {
        self.created
    }

    /// Register this tunnel into Babel monitor
    pub fn monitor(&self) -> Result<(), BabelMonitorError> {
        info!("Monitoring tunnel {}", self.iface_name);
        let iface_name = self.iface_name.clone();
        let babel_port = settings::get_rita_common().network.babel_port;

        // this operation blocks while opening and using a tcp stream
        let mut stream = open_babel_stream(babel_port, FAST_LOOP_TIMEOUT)?;
        monitor(&mut stream, &iface_name)
    }

    pub fn unmonitor(&self) -> Result<(), RitaCommonError> {
        warn!("Unmonitoring tunnel {}", self.iface_name);
        let iface_name = self.iface_name.clone();
        let babel_port = settings::get_rita_common().network.babel_port;
        let tunnel = self.clone();

        // this operation blocks while opening and using a tcp stream
        let mut stream = open_babel_stream(babel_port, FAST_LOOP_TIMEOUT)?;
        unmonitor(&mut stream, &iface_name)?;

        // We must wait until we have flushed the interface before deleting it
        // otherwise we will experience this error
        // https://github.com/sudomesh/bugs/issues/24
        if let Err(e) = KI.del_interface(&tunnel.iface_name) {
            error!("Failed to delete wg interface! {:?}", e);
            return Err(e.into());
        }
        Ok(())
    }

    pub fn close_light_client_tunnel(&self) {
        // there's a garbage collector function over in light_client_manager
        // to handle the return of addresses it's less efficient than shooting
        // off a message here but doesn't require conditional complication
        if let Err(e) = KI.del_interface(&self.iface_name) {
            error!("Failed to delete wg interface! {:?}", e);
        }
        // deletes the leftover iptables rule, be sure this matches the rule
        // generated in light client manager exactly
        let _res = KI.add_iptables_rule(
            "iptables",
            &[
                "-D",
                "FORWARD",
                "-i",
                &self.iface_name,
                "--src",
                &format!("{}/32", self.light_client_details.unwrap()),
                "--dst",
                "192.168.20.0/24",
                "-j",
                "ACCEPT",
            ],
        );
    }
}

pub struct TunnelManager {
    free_ports: VecDeque<u16>,
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

pub struct GetNeighbors;

#[derive(Debug, Clone)]
pub struct Neighbor {
    pub identity: LocalIdentity,
    pub iface_name: String,
    pub tunnel_ip: IpAddr,
    pub speed_limit: Option<usize>,
}

impl Neighbor {
    fn new(
        identity: LocalIdentity,
        iface_name: String,
        tunnel_ip: IpAddr,
        speed_limit: Option<usize>,
    ) -> Neighbor {
        Neighbor {
            identity,
            iface_name,
            tunnel_ip,
            speed_limit,
        }
    }
}

impl Message for GetNeighbors {
    type Result = Result<Vec<Neighbor>, RitaCommonError>;
}
impl Handler<GetNeighbors> for TunnelManager {
    type Result = Result<Vec<Neighbor>, RitaCommonError>;

    fn handle(&mut self, _: GetNeighbors, _: &mut Context<Self>) -> Self::Result {
        let mut res = Vec::new();
        for (_, tunnels) in self.tunnels.iter() {
            for tunnel in tunnels.iter() {
                res.push(Neighbor::new(
                    tunnel.neigh_id,
                    tunnel.iface_name.clone(),
                    tunnel.ip,
                    tunnel.speed_limit,
                ));
            }
        }
        Ok(res)
    }
}

pub struct GetTunnels;

impl Message for GetTunnels {
    type Result = Result<Vec<Tunnel>, RitaCommonError>;
}
impl Handler<GetTunnels> for TunnelManager {
    type Result = Result<Vec<Tunnel>, RitaCommonError>;

    fn handle(&mut self, _: GetTunnels, _: &mut Context<Self>) -> Self::Result {
        let mut res = Vec::new();
        for (_, tunnels) in self.tunnels.iter() {
            for tunnel in tunnels.iter() {
                res.push(tunnel.clone());
            }
        }
        Ok(res)
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
        let network_settings = settings::get_rita_common().network;
        let manual_peers = network_settings.manual_peers.clone();
        let is_gateway = is_gateway();
        let rita_hello_port = network_settings.rita_hello_port;
        drop(network_settings);

        // Hold a lock on shared state until we finish sending all messages. This prevents a race condition
        // where the hashmaps get cleared out during subsequent ticks
        let writer = &mut *PEER_LISTENER.write().unwrap();

        trace!("TunnelManager contacting peers");
        for (_, peer) in msg.peers.iter() {
            let res = self.neighbor_inquiry(peer, false, writer);
            if res.is_err() {
                warn!("Neighbor inqury for {:?} failed! with {:?}", peer, res);
            }
        }
        for manual_peer in manual_peers.iter() {
            let ip = manual_peer.parse::<IpAddr>();

            match ip {
                Ok(ip) => {
                    let socket = SocketAddr::new(ip, rita_hello_port);
                    let man_peer = Peer {
                        ifidx: 0,
                        contact_socket: socket,
                    };
                    let res = self.neighbor_inquiry(&man_peer, true, writer);
                    if res.is_err() {
                        warn!(
                            "Neighbor inqury for {:?} failed with: {:?}",
                            manual_peer, res
                        );
                    }
                }
                Err(_) => {
                    // Do not contact manual peers on the internet if we are not a gateway
                    // it will just fill the logs with failed dns resolution attempts or result
                    // in bad behavior, we do allow the addressing of direct ip address gateways
                    // for the special case that the user is attempting some special behavior
                    if is_gateway {
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
fn contact_neighbor(
    peer: &Peer,
    our_port: u16,
    socket: &UdpSocket,
    send_addr: SocketAddr,
) -> Result<(), RitaCommonError> {
    let mut settings = settings::get_rita_common();
    KI.manual_peers_route(
        &peer.contact_socket.ip(),
        &mut settings.network.last_default_route,
    )?;

    let msg = Hello {
        my_id: LocalIdentity {
            global: settings.get_identity().ok_or_else(|| {
                RitaCommonError::MiscStringError("Identity has no mesh IP ready yet".to_string())
            })?,
            wg_port: our_port,
            have_tunnel: None,
        },
        to: *peer,
    };

    settings::set_rita_common(settings);

    let new_msg = NewHello {
        my_id: LocalIdentity {
            global: settings::get_rita_common().get_identity().ok_or_else(|| {
                RitaCommonError::MiscStringError("Identity has no mesh IP ready yet".to_string())
            })?,
            wg_port: our_port,
            have_tunnel: None,
        },
        to: *peer,
        response: false,
    };

    //new send_hello call using udp socket
    send_hello(&new_msg, socket, send_addr, our_port);

    //old hello manager over http
    HelloHandler::from_registry().do_send(msg);

    Ok(())
}

/// Uses Hello Handler to send a Hello over http. Takes a speculative port (only assigned
/// if neighbor responds successfully)
fn contact_manual_peer(peer: &Peer, our_port: u16) -> Result<(), RitaCommonError> {
    let mut settings = settings::get_rita_common();
    KI.manual_peers_route(
        &peer.contact_socket.ip(),
        &mut settings.network.last_default_route,
    )?;

    let msg = Hello {
        my_id: LocalIdentity {
            global: settings.get_identity().ok_or_else(|| {
                RitaCommonError::MiscStringError("Identity has no mesh IP ready yet".to_string())
            })?,
            wg_port: our_port,
            have_tunnel: None,
        },
        to: *peer,
    };

    settings::set_rita_common(settings);

    //old hello manager over http
    HelloHandler::from_registry().do_send(msg);

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
        let start = settings::get_rita_common().network.wg_start_port;
        let ports = (start..65535).collect();
        TunnelManager {
            free_ports: ports,
            tunnels: HashMap::new(),
        }
    }

    /// Gets a port off of the internal port list after checking that said port is free
    /// with the operating system. It maintains a list of all possible ports and gives out
    /// the oldest port, i.e. when it gives out a port, it pushes it back on the end of the
    /// vecdeque so that by the time we come back around to it, it is either in use, or tunnel
    /// allocation has failed so we can use it without issues.
    fn get_port(&mut self) -> u16 {
        let udp_table = KI.used_ports();

        loop {
            let port = match self.free_ports.pop_front() {
                Some(a) => a,
                None => panic!("No elements present in the ports vecdeque"),
            };
            self.free_ports.push_back(port);
            match (port, &udp_table) {
                (p, Ok(used_ports)) => {
                    if used_ports.contains(&p) {
                        continue;
                    } else {
                        return p;
                    }
                }
                (_p, Err(e)) => {
                    // better not to open an individual tunnel than it is to
                    // risk having a failed one
                    panic!("Failed to check if port was in use! UdpTable from get_port returned error {:?}", e);
                }
            }
        }
    }

    /// This function generates a future and hands it off to the Actix arbiter to actually resolve
    /// in the case that the DNS request is successful the hello handler and eventually the Identity
    /// callback continue execution flow. But this function itself returns syncronously
    pub fn neighbor_inquiry_hostname(
        &mut self,
        their_hostname: String,
    ) -> Result<(), RitaCommonError> {
        trace!("Getting tunnel, inq");
        let network_settings = settings::get_rita_common().network;
        let is_gateway = is_gateway();
        let rita_hello_port = network_settings.rita_hello_port;

        let our_port = self.get_port();

        let res = Resolver::from_registry()
            .send(resolver::Resolve::host(their_hostname.clone()))
            .timeout(Duration::from_secs(1))
            .then(move |res| match res {
                Ok(Ok(dnsresult)) => {
                    let url = format!("http://[{}]:{}/hello", their_hostname, rita_hello_port);
                    trace!("Saying hello to: {:?} at ip {:?}", url, dnsresult);
                    if !dnsresult.is_empty() && is_gateway {
                        // dns records may have many ip's if we get multiple it's a load
                        // balanced exit and we need to create tunnels to all of them
                        for dns_socket in dnsresult {
                            let their_ip = dns_socket.ip();
                            let socket = SocketAddr::new(their_ip, rita_hello_port);
                            let man_peer = Peer {
                                ifidx: 0,
                                contact_socket: socket,
                            };

                            let res = contact_manual_peer(&man_peer, our_port);
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
    /// interface name. Sends a Hello over udp, or http if its a manual peer
    pub fn neighbor_inquiry(
        &mut self,
        peer: &Peer,
        is_manual_peer: bool,
        peer_listener: &mut PeerListener,
    ) -> Result<(), RitaCommonError> {
        trace!("TunnelManager neigh inquiry for {:?}", peer);
        let our_port = self.get_port();

        if is_manual_peer {
            contact_manual_peer(peer, our_port)
        } else {
            let iface_name = match peer_listener.interface_map.get(&peer.contact_socket) {
                Some(a) => a,
                None => {
                    return Err(RitaCommonError::MiscStringError(
                        "No interface in the hashmap to send a message".to_string(),
                    ))
                }
            };
            let udp_socket = match peer_listener.interfaces.get(iface_name) {
                Some(a) => &a.linklocal_socket,
                None => {
                    return Err(RitaCommonError::MiscStringError(
                        "No udp socket present for given interface".to_string(),
                    ))
                }
            };
            contact_neighbor(peer, our_port, udp_socket, peer.contact_socket)
        }
    }

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    /// return the tunnel object and if already had a tunnel
    pub fn open_tunnel(
        &mut self,
        their_localid: LocalIdentity,
        peer: Peer,
        our_port: u16,
        light_client_details: Option<Ipv4Addr>,
    ) -> Result<(Tunnel, bool), RitaCommonError> {
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

        // when we don't know take the more conservative option and assume they do have a tunnel
        let they_have_tunnel = their_localid.have_tunnel.unwrap_or(true);

        let mut return_bool = false;
        if we_have_tunnel {
            // Scope the last_contact bump to let go of self.tunnels before next use
            {
                let tunnels = self.tunnels.get_mut(&key).unwrap();
                for tunnel in tunnels.iter_mut() {
                    if tunnel.listen_ifidx == peer.ifidx && tunnel.ip == peer.contact_socket.ip() {
                        trace!("We already have a tunnel for {}", tunnel);
                        trace!(
                            "Bumping timestamp after {}s for tunnel: {}",
                            tunnel.last_contact.elapsed().as_secs(),
                            tunnel
                        );
                        tunnel.last_contact = Instant::now();
                        // update the nickname in case they changed it live
                        tunnel.neigh_id.global.nickname = their_localid.global.nickname;
                    }
                }
            }

            if they_have_tunnel {
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
                info!(
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

                // tell Babel to flush the interface and then delete it
                let res = tunnel.unmonitor();
                if res.is_err() {
                    error!(
                        "We failed to delete the interface {:?} with {:?} it's now orphaned",
                        tunnel.iface_name, res
                    );
                }

                return_bool = true;
            }
        }
        info!(
            "no tunnel found for {:?}%{:?} creating",
            peer.contact_socket.ip(),
            peer.ifidx,
        );

        let (new_key, tunnel) = create_new_tunnel(
            peer.contact_socket.ip(),
            our_port,
            peer.ifidx,
            their_localid,
            light_client_details,
        )?;

        self.tunnels
            .entry(new_key)
            .or_insert_with(Vec::new)
            .push(tunnel.clone());
        Ok((tunnel, return_bool))
    }
}

fn create_new_tunnel(
    peer_ip: IpAddr,
    our_port: u16,
    ifidx: u32,
    their_localid: LocalIdentity,
    light_client_details: Option<Ipv4Addr>,
) -> Result<(Identity, Tunnel), RitaCommonError> {
    // Create new tunnel
    let tunnel = Tunnel::new(
        peer_ip,
        our_port,
        ifidx,
        their_localid,
        light_client_details,
    );
    let tunnel = match tunnel {
        Ok(tunnel) => {
            trace!("Tunnel {:?} is open", tunnel);
            tunnel
        }
        Err(e) => {
            error!("Unable to open tunnel {}", e);
            return Err(e);
        }
    };
    let new_key = tunnel.neigh_id.global;

    Ok((new_key, tunnel))
}

pub struct TunnelChange {
    pub identity: Identity,
    pub action: TunnelAction,
}

pub struct TunnelStateChange {
    pub tunnels: Vec<TunnelChange>,
}

impl Message for TunnelStateChange {
    type Result = Result<(), RitaCommonError>;
}

// Called by DebtKeeper with the updated billing status of every tunnel every round
impl Handler<TunnelStateChange> for TunnelManager {
    type Result = Result<(), RitaCommonError>;

    fn handle(&mut self, msg: TunnelStateChange, _: &mut Context<Self>) -> Self::Result {
        for tunnel in msg.tunnels {
            tunnel_state_change(tunnel, &mut self.tunnels);
        }
        Ok(())
    }
}

fn tunnel_state_change(msg: TunnelChange, tunnels: &mut HashMap<Identity, Vec<Tunnel>>) {
    let id = msg.identity;
    let action = msg.action;
    trace!(
        "Tunnel state change request for {:?} with action {:?}",
        id,
        action,
    );
    let mut tunnel_bw_limits_need_change = false;

    // Find a tunnel
    match tunnels.get_mut(&id) {
        Some(tunnels) => {
            for tunnel in tunnels.iter_mut() {
                trace!("Handle action {} on tunnel {:?}", action, tunnel);
                match action {
                    TunnelAction::PaidOnTime => {
                        trace!("identity {:?} has paid!", id);
                        match tunnel.payment_state {
                            PaymentState::Paid => {
                                continue;
                            }
                            PaymentState::Overdue => {
                                info!(
                                    "Tunnel {} has returned to a paid state.",
                                    tunnel.neigh_id.global.wg_public_key
                                );
                                tunnel.payment_state = PaymentState::Paid;
                                tunnel_bw_limits_need_change = true;
                                // latency detector probably got confused while enforcement
                                // occurred
                                tunnel.speed_limit = None;
                            }
                        }
                    }
                    TunnelAction::PaymentOverdue => {
                        trace!("No payment from identity {:?}", id);
                        match tunnel.payment_state {
                            PaymentState::Paid => {
                                info!(
                                    "Tunnel {} has entered an overdue state.",
                                    tunnel.neigh_id.global.wg_public_key
                                );
                                tunnel.payment_state = PaymentState::Overdue;
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
            // This is now pretty common since there's no more none action
            // and exits have identities for all clients (active or not)
            // on hand
            trace!("Couldn't find tunnel for identity {:?}", id);
        }
    }

    // this is done outside of the match to make the borrow checker happy
    if tunnel_bw_limits_need_change {
        let res = tunnel_bw_limit_update(tunnels);
        // if this fails consistently it could be a wallet draining attack
        // TODO check for that case
        if res.is_err() {
            error!("Bandwidth limiting failed with {:?}", res);
        }
    }
}

/// Takes the tunnels list and iterates over it to update all of the traffic control settings
/// since we can't figure out how to combine interfaces bandwidth budgets we're subdividing it
/// here with manual terminal commands whenever there is a change
fn tunnel_bw_limit_update(tunnels: &HashMap<Identity, Vec<Tunnel>>) -> Result<(), RitaCommonError> {
    info!("Running tunnel bw limit update!");
    // number of interfaces over which we will have to divide free tier BW
    let mut limited_interfaces = 0u16;
    for sublist in tunnels.iter() {
        for tunnel in sublist.1.iter() {
            if tunnel.payment_state == PaymentState::Overdue {
                limited_interfaces += 1;
            }
        }
    }
    let payment = settings::get_rita_common().payment;
    let bw_per_iface = if limited_interfaces > 0 {
        payment.free_tier_throughput / u32::from(limited_interfaces)
    } else {
        payment.free_tier_throughput
    };

    for sublist in tunnels.iter() {
        for tunnel in sublist.1.iter() {
            let payment_state = &tunnel.payment_state;
            let iface_name = &tunnel.iface_name;
            let has_limit = KI.has_limit(iface_name)?;

            if *payment_state == PaymentState::Overdue {
                KI.set_classless_limit(iface_name, bw_per_iface)?;
            } else if *payment_state == PaymentState::Paid && has_limit {
                KI.set_codel_shaping(iface_name, None, false)?;
            }
        }
    }
    Ok(())
}

pub fn get_test_id() -> Identity {
    Identity {
        mesh_ip: "::1".parse().unwrap(),
        eth_address: "0x4288C538A553357Bb6c3b77Cf1A60Da6E77931F6"
            .parse()
            .unwrap(),
        wg_public_key: "GIaAXDi1PbGq3PsKqBnT6kIPoE2K1Ssv9HSb7++dzl4="
            .parse()
            .unwrap(),
        nickname: None,
    }
}

pub fn get_test_tunnel(ip: Ipv4Addr, light: bool) -> Tunnel {
    let light_client_details = if light { Some(ip) } else { None };
    Tunnel {
        ip: ip.into(),
        iface_name: "iface".to_string(),
        listen_ifidx: 0,
        listen_port: 65535,
        neigh_id: LocalIdentity {
            wg_port: 65535,
            have_tunnel: Some(true),
            global: get_test_id(),
        },
        last_contact: Instant::now(),
        created: Instant::now(),
        speed_limit: None,
        light_client_details,
        payment_state: PaymentState::Paid,
    }
}

#[cfg(test)]
pub mod tests {
    use super::PaymentState;
    use crate::tunnel_manager::get_test_tunnel;
    use crate::tunnel_manager::Tunnel;
    use crate::tunnel_manager::TunnelManager;
    use althea_types::Identity;

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
        assert_eq!(tunnel_manager.free_ports.pop_back().unwrap(), 65534);
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
            .push(get_test_tunnel("0.0.0.0".parse().unwrap(), false));
        {
            let existing_tunnel =
                get_mut_tunnel_by_ifidx(0u32, tunnel_manager.tunnels.get_mut(&id).unwrap())
                    .expect("Unable to find existing tunnel");
            assert_eq!(existing_tunnel.payment_state, PaymentState::Paid);
            // Verify mutability - manual modifications shouldn't happen elsewhere
            existing_tunnel.payment_state = PaymentState::Overdue;
        }

        // Verify if object is modified
        {
            let existing_tunnel =
                get_mut_tunnel_by_ifidx(0u32, tunnel_manager.tunnels.get_mut(&id).unwrap())
                    .expect("Unable to find existing tunnel");
            assert_eq!(existing_tunnel.payment_state, PaymentState::Overdue);
        }
    }
}
