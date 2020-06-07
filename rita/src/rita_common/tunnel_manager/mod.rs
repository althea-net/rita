//! Tunnel manager manages WireGuard tunnels between mesh peers. In rita_loop PeerListener is called
//! and asked about what peers it has heard from since the last cycle, these peers are passed to
//! TunnelManager, which then orchestrates calling these peers over their http endpoints and setting
//! up tunnels if they respond, likewise if someone calls us their hello goes through network_endpoints
//! then into TunnelManager to open a tunnel for them.

pub mod id_callback;
pub mod shaping;

use crate::rita_common;
use crate::rita_common::hello_handler::Hello;
use crate::rita_common::peer_listener::Peer;
use crate::KI;
use crate::SETTING;
#[cfg(test)]
use actix::actors::mocker::Mocker;
use actix::actors::resolver;
use actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use althea_kernel_interface::open_tunnel::TunnelOpenArgs;
use althea_types::Identity;
use althea_types::LocalIdentity;
use babel_monitor::monitor;
use babel_monitor::open_babel_stream;
use babel_monitor::start_connection;
use babel_monitor::unmonitor;
use failure::Error;
use futures01::Future;
use rand::thread_rng;
use rand::Rng;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::timer::Delay;

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
#[allow(dead_code)]
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
    pub ip: IpAddr,                             // Tunnel endpoint
    pub iface_name: String,                     // name of wg#
    pub listen_ifidx: u32, // the physical interface this tunnel is listening on
    pub listen_port: u16,  // the local port this tunnel is listening on
    pub neigh_id: LocalIdentity, // the identity of the counterparty tunnel
    pub last_contact: Instant, // When's the last we heard from the other end of this tunnel?
    pub speed_limit: Option<usize>, // banwidth limit in mbps, used for Codel shaping
    pub light_client_details: Option<Ipv4Addr>, // if Some this tunnel is for a light client
    state: TunnelState,
}

impl Display for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tunnel: IP: {} IFACE_NAME: {} IFIDX: {}, PORT: {} WG: {} ETH: {} MESH_IP: {} LAST_SEEN {}, SPEED_LIMIT {:?}, LC {:?}, STATE: {:?}" , 
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
        self.state)
    }
}

impl Tunnel {
    pub fn new(
        ip: IpAddr,
        iface_name: String,
        our_listen_port: u16,
        ifidx: u32,
        their_id: LocalIdentity,
        light_client_details: Option<Ipv4Addr>,
    ) -> Tunnel {
        Tunnel {
            ip,
            iface_name,
            listen_ifidx: ifidx,
            listen_port: our_listen_port,
            neigh_id: their_id,
            last_contact: Instant::now(),
            speed_limit: None,
            light_client_details,
            // By default new tunnels are in Registered state
            state: TunnelState {
                payment_state: PaymentState::Paid,
                registration_state: RegistrationState::Registered,
            },
        }
    }

    /// Open a real tunnel to match the virtual tunnel we store in memory
    pub fn open(&self, light_client_details: Option<Ipv4Addr>) -> Result<(), Error> {
        let network = SETTING.get_network().clone();
        let args = TunnelOpenArgs {
            interface: self.iface_name.clone(),
            port: self.listen_port,
            endpoint: SocketAddr::new(self.ip, self.neigh_id.wg_port),
            remote_pub_key: self.neigh_id.global.wg_public_key,
            private_key_path: Path::new(&network.wg_private_key_path),
            own_ip: match network.mesh_ip {
                Some(ip) => ip,
                None => bail!("No mesh IP configured yet"),
            },
            external_nic: network.external_nic.clone(),
            settings_default_route: &mut SETTING.get_network_mut().default_route,
            allowed_ipv4_address: light_client_details,
        };

        KI.open_tunnel(args)?;
        KI.set_codel_shaping(&self.iface_name, self.speed_limit)
    }

    /// Register this tunnel into Babel monitor
    pub fn monitor(&self, retry_count: u8) {
        info!("Monitoring tunnel {}", self.iface_name);
        let iface_name = self.iface_name.clone();
        let babel_port = SETTING.get_network().babel_port;
        let tunnel = self.clone();

        Arbiter::spawn(
            open_babel_stream(babel_port)
                .from_err()
                .and_then(move |stream| {
                    start_connection(stream).and_then(move |stream| monitor(stream, &iface_name))
                })
                .then(move |res| {
                    // Errors here seem very very rare, I've only ever seen it happen
                    // twice myself and I couldn't reproduce it, nontheless it's a pretty
                    // bad situation so we will retry
                    if let Err(e) = res {
                        warn!("Tunnel monitor failed with {:?}, retrying in 1 second", e);
                        let when = Instant::now() + Duration::from_secs(1);
                        let fut = Delay::new(when)
                            .map_err(move |e| panic!("timer failed; err={:?}", e))
                            .and_then(move |_| {
                                TunnelManager::from_registry().do_send(TunnelMonitorFailure {
                                    tunnel_to_retry: tunnel,
                                    retry_count,
                                });
                                Ok(())
                            });
                        Arbiter::spawn(fut);
                    }
                    Ok(())
                }),
        )
    }

    pub fn unmonitor(&self, retry_count: u8) {
        warn!("Unmonitoring tunnel {}", self.iface_name);
        let iface_name = self.iface_name.clone();
        let babel_port = SETTING.get_network().babel_port;
        let tunnel = self.clone();

        Arbiter::spawn(
            open_babel_stream(babel_port)
                .from_err()
                .and_then(move |stream| {
                    start_connection(stream).and_then(move |stream| unmonitor(stream, &iface_name))
                })
                .then(move |res| {
                    // Errors here seem very very rare, I've only ever seen it happen
                    // twice myself and I couldn't reproduce it, nontheless it's a pretty
                    // bad situation so we will retry
                    if let Err(e) = res {
                        warn!("Tunnel unmonitor failed with {:?}, retrying in 1 second", e);
                        let when = Instant::now() + Duration::from_secs(1);
                        let fut = Delay::new(when)
                            .map_err(move |e| panic!("timer failed; err={:?}", e))
                            .and_then(move |_| {
                                TunnelManager::from_registry().do_send(TunnelUnMonitorFailure {
                                    tunnel_to_retry: tunnel,
                                    retry_count,
                                });
                                Ok(())
                            });
                        Arbiter::spawn(fut);
                    } else {
                        // We must wait until we have flushed the interface before deleting it
                        // otherwise we will experience this error
                        // https://github.com/sudomesh/bugs/issues/24
                        if let Err(e) = KI.del_interface(&tunnel.iface_name) {
                            error!("Failed to delete wg interface! {:?}", e);
                        }
                        TunnelManager::from_registry().do_send(PortCallback(tunnel.listen_port));
                    }
                    Ok(())
                }),
        )
    }

    pub fn close_light_client_tunnel(&self) {
        // there's a garbage collector function over in light_client_manager
        // to handle the return of addresses it's less efficient than shooting
        // off a message here but doesn't require conditional complication
        if let Err(e) = KI.del_interface(&self.iface_name) {
            error!("Failed to delete wg interface! {:?}", e);
        }
        TunnelManager::from_registry().do_send(PortCallback(self.listen_port));
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

/// When listening on a tunnel fails we need to try again
pub struct TunnelMonitorFailure {
    pub tunnel_to_retry: Tunnel,
    pub retry_count: u8,
}

impl Message for TunnelMonitorFailure {
    type Result = ();
}

impl Handler<TunnelMonitorFailure> for TunnelManager {
    type Result = ();

    fn handle(&mut self, msg: TunnelMonitorFailure, _: &mut Context<Self>) -> Self::Result {
        let tunnel_to_retry = msg.tunnel_to_retry;
        let retry_count = msg.retry_count;

        if retry_count < 10 {
            tunnel_to_retry.monitor(retry_count + 1);
        } else {
            // this could result in networking not working, it's better to panic if we can't
            // do anything over the span of 10 retries and 10 seconds
            let message =
                "ERROR: Monitoring tunnel has failed! The tunnels cache is an incorrect state";
            error!("{}", message);
            panic!(message);
        }
    }
}

/// When listening on a tunnel fails we need to try again
pub struct TunnelUnMonitorFailure {
    pub tunnel_to_retry: Tunnel,
    pub retry_count: u8,
}

impl Message for TunnelUnMonitorFailure {
    type Result = ();
}

impl Handler<TunnelUnMonitorFailure> for TunnelManager {
    type Result = ();

    fn handle(&mut self, msg: TunnelUnMonitorFailure, _: &mut Context<Self>) -> Self::Result {
        let tunnel_to_retry = msg.tunnel_to_retry;
        let retry_count = msg.retry_count;

        if retry_count < 10 {
            tunnel_to_retry.unmonitor(retry_count + 1);
        } else {
            error!(
                "Unmonitoring tunnel has failed! Babel will now listen on a non-existant tunnel"
            );
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
                    tunnel.speed_limit,
                ));
            }
        }
        Ok(res)
    }
}

pub struct GetTunnels;

impl Message for GetTunnels {
    type Result = Result<Vec<Tunnel>, Error>;
}
impl Handler<GetTunnels> for TunnelManager {
    type Result = Result<Vec<Tunnel>, Error>;

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

/// A message type for deleting all tunnels we haven't heard from for more than the duration.
pub struct TriggerGC {
    /// if we do not receive a hello within this many seconds we attempt to gc the tunnel
    /// this garbage collection can be avoided if the tunnel has seen a handshake within
    /// tunnel_handshake_timeout time
    pub tunnel_timeout: Duration,
    /// The backup value that prevents us from deleting an active tunnel. We check the last
    /// handshake on the tunnel and if it's within this amount of time we don't GC it.
    pub tunnel_handshake_timeout: Duration,
}

impl Message for TriggerGC {
    type Result = Result<(), Error>;
}

impl Handler<TriggerGC> for TunnelManager {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: TriggerGC, _ctx: &mut Context<Self>) -> Self::Result {
        let mut good: HashMap<Identity, Vec<Tunnel>> = HashMap::new();
        let mut timed_out: HashMap<Identity, Vec<Tunnel>> = HashMap::new();
        // Split entries into good and timed out rebuilding the double hashmap structure
        // as you can tell this is totally copy based and uses 2n ram to prevent borrow
        // checker issues, we should consider a method that does modify in place
        for (_identity, tunnels) in self.tunnels.iter() {
            for tunnel in tunnels.iter() {
                if tunnel.last_contact.elapsed() < msg.tunnel_timeout
                    || check_handshake_time(msg.tunnel_handshake_timeout, &tunnel.iface_name)
                {
                    insert_into_tunnel_list(tunnel, &mut good);
                } else {
                    insert_into_tunnel_list(tunnel, &mut timed_out)
                }
            }
        }

        for (id, tunnels) in timed_out.iter() {
            for tunnel in tunnels {
                info!("TriggerGC: removing tunnel: {} {}", id, tunnel);
            }
        }

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
                match tunnel.light_client_details {
                    None => {
                        // In the same spirit, we return the port to the free port pool only after tunnel
                        // deletion goes well.
                        tunnel.unmonitor(0);
                    }
                    Some(_) => {
                        tunnel.close_light_client_tunnel();
                    }
                }
            }
        }

        Ok(())
    }
}

/// A simple helper function to reduce the number of if/else statements in tunnel GC
fn insert_into_tunnel_list(input: &Tunnel, tunnels_list: &mut HashMap<Identity, Vec<Tunnel>>) {
    let identity = &input.neigh_id.global;
    let input = input.clone();
    if tunnels_list.contains_key(identity) {
        tunnels_list.get_mut(identity).unwrap().push(input);
    } else {
        tunnels_list.insert(*identity, Vec::new());
        tunnels_list.get_mut(identity).unwrap().push(input);
    }
}

/// This function checks the handshake time of a tunnel when compared to the handshake timeout,
/// it returns true if we fail to get the handshake time (erring on the side of caution) and only
/// false if all last tunnel handshakes are older than the allowed time limit
fn check_handshake_time(handshake_timeout: Duration, ifname: &str) -> bool {
    let res = KI.get_last_handshake_time(ifname);
    match res {
        Ok(handshakes) => {
            for (_key, time) in handshakes {
                match time.elapsed() {
                    Ok(elapsed) => {
                        if elapsed < handshake_timeout {
                            return true;
                        }
                    }
                    Err(_e) => {
                        // handshake in the future, possible system clock change
                        return true;
                    }
                }
            }
            false
        }
        Err(e) => {
            error!("Could not get tunnel handshake with {:?}", e);
            true
        }
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
        let network_settings = SETTING.get_network();
        let manual_peers = network_settings.manual_peers.clone();
        let is_gateway = network_settings.is_gateway;
        let rita_hello_port = network_settings.rita_hello_port;
        drop(network_settings);

        trace!("TunnelManager contacting peers");
        for (_, peer) in msg.peers.iter() {
            let res = self.neighbor_inquiry(&peer);
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
                    let res = self.neighbor_inquiry(&man_peer);
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
    /// with the operating system, level argument is always zero for callers and is used
    /// interally to prevent unchecked recursion
    fn get_port(&mut self, level: usize) -> Option<u16> {
        let udp_table = KI.used_ports();
        let mut rng = thread_rng();
        let val = rng.gen_range(0, self.free_ports.len());
        let port = self.free_ports.remove(val);
        match (port, udp_table) {
            (p, Ok(used_ports)) => {
                if used_ports.contains(&p) {
                    warn!(
                        "We tried to allocate a used port {}!, there are {} ports remaining",
                        p,
                        self.free_ports.len()
                    );

                    if level < 10 {
                        self.free_ports.push(p);
                        self.get_port(level + 1)
                    } else {
                        // we've tried a bunch of ports and all are used
                        // break recusion and die, hopefully to be restarted in 15min
                        error!("We ran out of ports!");
                        panic!("We ran out of ports!");
                    }
                } else {
                    Some(p)
                }
            }
            (_p, Err(e)) => {
                // better not to open an individual tunnel than it is to
                // risk having a failed one
                warn!("Failed to check if port was in use! {:?}", e);
                None
            }
        }
    }

    /// This function generates a future and hands it off to the Actix arbiter to actually resolve
    /// in the case that the DNS request is successful the hello handler and eventually the Identity
    /// callback continue execution flow. But this function itself returns syncronously
    pub fn neighbor_inquiry_hostname(&mut self, their_hostname: String) -> Result<(), Error> {
        trace!("Getting tunnel, inq");
        let network_settings = SETTING.get_network();
        let is_gateway = network_settings.is_gateway;
        let rita_hello_port = network_settings.rita_hello_port;
        drop(network_settings);

        let our_port = match self.get_port(0) {
            Some(p) => p,
            None => {
                warn!("Failed to allocate tunnel port! All tunnel opening will fail");
                return Err(
                    TunnelManagerError::PortError("No remaining ports!".to_string()).into(),
                );
            }
        };

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
                    TunnelManager::from_registry().do_send(PortCallback(our_port));
                    Ok(())
                }

                Ok(Err(e)) => {
                    warn!("DNS resolution failed with {:?}", e);
                    TunnelManager::from_registry().do_send(PortCallback(our_port));
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
        let our_port = match self.get_port(0) {
            Some(p) => p,
            None => {
                warn!("Failed to allocate tunnel port! All tunnel opening will fail");
                return Err(
                    TunnelManagerError::PortError("No remaining ports!".to_string()).into(),
                );
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
        light_client_details: Option<Ipv4Addr>,
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
) -> Result<(Identity, Tunnel), Error> {
    // Create new tunnel
    let tunnel = Tunnel::new(
        peer_ip,
        KI.setup_wg_if().unwrap(),
        our_port,
        ifidx,
        their_localid,
        light_client_details,
    );
    let new_key = tunnel.neigh_id.global;

    // actually create the tunnel
    match tunnel.open(light_client_details) {
        Ok(_) => trace!("Tunnel {:?} is open", tunnel),
        Err(e) => {
            error!("Unable to open tunnel {:?}: {}", tunnel, e);
            return Err(e);
        }
    }
    match light_client_details {
        None => {
            // attach babel, the argument indicates that this is attempt zero
            tunnel.monitor(0);
        }
        Some(_) => {}
    }
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
    type Result = Result<(), Error>;
}

// Called by DebtKeeper with the updated billing status of every tunnel every round
impl Handler<TunnelStateChange> for TunnelManager {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: TunnelStateChange, _: &mut Context<Self>) -> Self::Result {
        for tunnel in msg.tunnels {
            let res = tunnel_state_change(tunnel, &mut self.tunnels);
            if res.is_err() {
                error!("Tunnel state change failed with {:?}", res);
            }
        }
        Ok(())
    }
}

fn tunnel_state_change(
    msg: TunnelChange,
    tunnels: &mut HashMap<Identity, Vec<Tunnel>>,
) -> Result<(), Error> {
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
                    TunnelAction::MembershipConfirmed => {
                        trace!(
                            "Membership confirmed for identity {:?} returned tunnel {:?}",
                            id,
                            tunnel
                        );
                        match tunnel.state.registration_state {
                            RegistrationState::NotRegistered => {
                                if tunnel.light_client_details.is_none() {
                                    tunnel.monitor(0);
                                }
                                tunnel.state.registration_state = RegistrationState::Registered;
                            }
                            RegistrationState::Registered => {
                                continue;
                            }
                        }
                    }
                    TunnelAction::MembershipExpired => {
                        trace!("Membership for identity {:?} is expired", id);
                        match tunnel.state.registration_state {
                            RegistrationState::Registered => {
                                if tunnel.light_client_details.is_none() {
                                    tunnel.unmonitor(0);
                                }
                                tunnel.state.registration_state = RegistrationState::NotRegistered;
                            }
                            RegistrationState::NotRegistered => {
                                continue;
                            }
                        }
                    }
                    TunnelAction::PaidOnTime => {
                        trace!("identity {:?} has paid!", id);
                        match tunnel.state.payment_state {
                            PaymentState::Paid => {
                                continue;
                            }
                            PaymentState::Overdue => {
                                info!(
                                    "Tunnel {} has returned to a paid state.",
                                    tunnel.neigh_id.global.wg_public_key
                                );
                                tunnel.state.payment_state = PaymentState::Paid;
                                tunnel_bw_limits_need_change = true;
                                // latency detector probably got confused while enforcement
                                // occurred
                                tunnel.speed_limit = None;
                            }
                        }
                    }
                    TunnelAction::PaymentOverdue => {
                        trace!("No payment from identity {:?}", id);
                        match tunnel.state.payment_state {
                            PaymentState::Paid => {
                                info!(
                                    "Tunnel {} has entered an overdue state.",
                                    tunnel.neigh_id.global.wg_public_key
                                );
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
            // This is now pretty common since there's no more none action
            // and exits have identities for all clients (active or not)
            // on hand
            trace!("Couldn't find tunnel for identity {:?}", id);
        }
    }

    // this is done ouside of the match to make the borrow checker happy
    if tunnel_bw_limits_need_change {
        let res = tunnel_bw_limit_update(&tunnels);
        // if this fails consistently it could be a wallet draining attack
        // TODO check for that case
        if res.is_err() {
            error!("Bandwidth limiting failed with {:?}", res);
        }
    }

    Ok(())
}

/// Takes the tunnels list and iterates over it to update all of the traffic control settings
/// since we can't figure out how to combine interfaces bandwidth budgets we're subdividing it
/// here with manual terminal commands whenever there is a change
fn tunnel_bw_limit_update(tunnels: &HashMap<Identity, Vec<Tunnel>>) -> Result<(), Error> {
    info!("Running tunnel bw limit update!");
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
                KI.set_codel_shaping(iface_name, None)?;
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
                None,
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
