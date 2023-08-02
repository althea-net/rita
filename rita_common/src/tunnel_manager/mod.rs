//! Tunnel manager manages WireGuard tunnels between mesh peers. In rita_loop PeerListener is called
//! and asked about what peers it has heard from since the last cycle, these peers are passed to
//! TunnelManager, which then orchestrates calling these peers over their http endpoints and setting
//! up tunnels if they respond, likewise if someone calls us their hello goes through network_endpoints
//! then into TunnelManager to open a tunnel for them.

pub mod contact_peers;
pub mod gc;
pub mod id_callback;
pub mod neighbor_status;
pub mod shaping;

use crate::blockchain_oracle::potential_payment_issues_detected;
use crate::peer_listener::structs::Peer;
use crate::RitaCommonError;
use crate::FAST_LOOP_TIMEOUT;
use crate::KI;
use althea_kernel_interface::open_tunnel::TunnelOpenArgs;
use althea_types::Identity;
use althea_types::LocalIdentity;
use babel_monitor::monitor;
use babel_monitor::open_babel_stream;
use babel_monitor::structs::BabelMonitorError;
use babel_monitor::structs::Interface;
use babel_monitor::unmonitor;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;
use std::fmt::Display;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

lazy_static! {
    static ref TUNNEL_MANAGER: Arc<RwLock<HashMap<u32, TunnelManager>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Gets TunnelManager copy from the static ref, or default if no value has been set
pub fn get_tunnel_manager() -> TunnelManager {
    let netns = KI.check_integration_test_netns();
    TUNNEL_MANAGER
        .read()
        .unwrap()
        .clone()
        .get(&netns)
        .cloned()
        .unwrap_or_default()
}

/// Gets a write ref for the tunnel manager lock, since this is a mutable reference
/// the lock will be held until you drop the return value, this lets the caller abstract the namespace handling
/// but still hold the lock in the local thread to prevent parallel modification
pub fn get_tunnel_manager_write_ref(input: &mut HashMap<u32, TunnelManager>) -> &mut TunnelManager {
    let netns = KI.check_integration_test_netns();
    input.entry(netns).or_insert_with(TunnelManager::default);
    input.get_mut(&netns).unwrap()
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
        write!(f, "{self:?}")
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
        write!(f, "{self:?}")
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
    payment_state: PaymentState,
}

impl Display for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tunnel: IP: {} IFACE_NAME: {} IFIDX: {}, PORT: {} WG: {} ETH: {} MESH_IP: {} LAST_SEEN {}, SPEED_LIMIT {:?}, PAYMENT_STATE: {:?}" , 
        self.ip,
        self.iface_name,
        self.listen_ifidx,
        self.listen_port,
        self.neigh_id.global.wg_public_key,
        self.neigh_id.global.eth_address,
        self.neigh_id.global.mesh_ip,
        (Instant::now() - self.last_contact).as_secs(),
        self.speed_limit,
        self.payment_state)
    }
}

impl Tunnel {
    pub fn new(
        ip: IpAddr,
        our_listen_port: u16,
        ifidx: u32,
        neigh_id: LocalIdentity,
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
            own_ip_v2: network.mesh_ip_v2,
            external_nic: network.external_nic.clone(),
            settings_default_route: &mut network.last_default_route,
        };

        KI.open_tunnel(args)?;
        KI.set_codel_shaping(&iface_name, speed_limit)?;

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
            // By default new tunnels are in paid state
            payment_state: PaymentState::Paid,
        };

        // attach to babel
        t.monitor()?;

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
}

#[derive(Clone)]
pub struct TunnelManager {
    free_ports: VecDeque<u16>,
    tunnels: HashMap<Identity, Vec<Tunnel>>,
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

/// This function goes through all tunnels preset in rita memory and add them to babel is they are not present already
pub fn tm_monitor_check(interface_list: &[Interface]) {
    // Hashset of all interface names. This allows for an O(n) search instead of O(n^2)
    let mut interface_map: HashSet<String> = HashSet::new();
    for int in interface_list {
        interface_map.insert(int.name.clone());
    }

    let rita_tunnels = get_tunnel_manager().tunnels;
    for (_, tunnels) in rita_tunnels.iter() {
        for tun in tunnels.iter() {
            if !interface_map.contains(&tun.iface_name) {
                info!(
                    "Babel was not monitored a tunnel, Readding the tunnel: {:?}",
                    tun.iface_name
                );
                let res = tun.monitor();
                if let Err(e) = res {
                    error!("Unable to re-add tunnel to babel with: {:?}", e);
                }
            }
        }
    }
}

pub fn tm_get_neighbors() -> Vec<Neighbor> {
    let tunnel_manager = get_tunnel_manager();
    let mut res = Vec::new();
    for (_, tunnels) in tunnel_manager.tunnels.iter() {
        for tunnel in tunnels.iter() {
            res.push(Neighbor::new(
                tunnel.neigh_id,
                tunnel.iface_name.clone(),
                tunnel.ip,
                tunnel.speed_limit,
            ));
        }
    }
    res
}

pub fn tm_get_tunnels() -> Result<Vec<Tunnel>, RitaCommonError> {
    let tunnel_manager = get_tunnel_manager();
    let mut res = Vec::new();
    for (_, tunnels) in tunnel_manager.tunnels.iter() {
        for tunnel in tunnels.iter() {
            res.push(tunnel.clone());
        }
    }
    Ok(res)
}

/// Gets a port off of the internal port list after checking that said port is free
/// with the operating system. It maintains a list of all possible ports and gives out
/// the oldest port, i.e. when it gives out a port, it pushes it back on the end of the
/// vecdeque so that by the time we come back around to it, it is either in use, or tunnel
/// allocation has failed so we can use it without issues.
fn tm_get_port() -> u16 {
    let udp_table = KI.used_ports();
    let tm_pin = &mut *TUNNEL_MANAGER.write().unwrap();
    let tunnel_manager = get_tunnel_manager_write_ref(tm_pin);

    loop {
        let port = match tunnel_manager.free_ports.pop_front() {
            Some(a) => a,
            None => {
                error!("No elements present in the ports vecdeque");
                panic!("No elements present in the ports vecdeque")
            }
        };
        tunnel_manager.free_ports.push_back(port);
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
                error!("Failed to check if port was in use! UdpTable from get_port returned error {:?}", e);

                panic!("Failed to check if port was in use! UdpTable from get_port returned error {:?}", e);
            }
        }
    }
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
    tunnels.iter().find(|&tunnel| tunnel.listen_ifidx == ifidx)
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

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    /// return the tunnel object and if already had a tunnel
    pub fn open_tunnel(
        &mut self,
        their_localid: LocalIdentity,
        peer: Peer,
        our_port: u16,
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
                let tunnels = match self.tunnels.get_mut(&key) {
                    Some(a) => a,
                    None => {
                        error!("Logic Error: Identity {:?} doesnt exist", key.clone());
                        panic!("Identity not in hashmap");
                    }
                };
                for tunnel in tunnels.iter_mut() {
                    if tunnel.listen_ifidx == peer.ifidx && tunnel.ip == peer.contact_socket.ip() {
                        info!("We already have a tunnel for {}", tunnel);
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
                let tunnel = match get_tunnel_by_ifidx(peer.ifidx, tunnels) {
                    Some(a) => a,
                    _ => {
                        error!("Unable to find tunnel by ifidx how did this happen?");
                        panic!("Unable to find tunnel by ifidx how did this happen?");
                    }
                };

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
                    let tunnels = match self.tunnels.get_mut(&key) {
                        Some(a) => a,
                        None => {
                            error!("LOGIC ERROR: Unable to find a tunnel that should exist, we already confirmed membership");
                            panic!("Unable to find tunnel");
                        }
                    };
                    // Find tunnel by interface index
                    let value = match get_tunnel_by_ifidx(peer.ifidx, tunnels) {
                        Some(a) => a.clone(),
                        None => {
                            error!("LOGIC ERROR: Unable to find a tunnel with ifidx when membership is already confirmed");
                            panic!("Uanble to find tunnel");
                        }
                    };
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
) -> Result<(Identity, Tunnel), RitaCommonError> {
    // Create new tunnel
    let tunnel = Tunnel::new(peer_ip, our_port, ifidx, their_localid);
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

/// Called by DebtKeeper with the updated billing status of every tunnel every round
pub fn tm_tunnel_state_change(msg: TunnelStateChange) -> Result<(), RitaCommonError> {
    let tm_pin = &mut *TUNNEL_MANAGER.write().unwrap();
    let tunnel_manager = get_tunnel_manager_write_ref(tm_pin);
    for tunnel in msg.tunnels {
        tunnel_state_change(tunnel, &mut tunnel_manager.tunnels);
    }
    Ok(())
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
        if potential_payment_issues_detected() {
            warn!("Potential payment issue detected");
            return;
        }
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
                KI.set_codel_shaping(iface_name, None)?;
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

pub fn get_test_tunnel(ip: Ipv4Addr) -> Tunnel {
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
    fn get_mut_tunnel_by_ifidx(ifidx: u32, tunnels: &mut [Tunnel]) -> Option<&mut Tunnel> {
        tunnels
            .iter_mut()
            .find(|tunnel| tunnel.listen_ifidx == ifidx)
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
            .push(get_test_tunnel("0.0.0.0".parse().unwrap()));
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
