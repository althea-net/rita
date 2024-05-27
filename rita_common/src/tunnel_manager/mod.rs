//! Tunnel manager manages WireGuard tunnels between mesh peers. In rita_loop PeerListener is called
//! and asked about what peers it has heard from since the last cycle, these peers are passed to
//! TunnelManager, which then orchestrates calling these peers over their http endpoints and setting
//! up tunnels if they respond, likewise if someone calls us their hello goes through network_endpoints
//! then into TunnelManager to open a tunnel for them.

pub mod contact_peers;
pub mod error;
pub mod gc;
pub mod id_callback;
pub mod neighbor_status;
pub mod shaping;

use crate::blockchain_oracle::potential_payment_issues_detected;
use crate::insert_into_tunnel_list;
use crate::peer_listener::structs::Peer;
use crate::tunnel_manager::error::TunnelManagerError;
use crate::RitaCommonError;
use crate::Shaper;
use crate::FAST_LOOP_TIMEOUT;
use crate::KI;
use crate::TUNNEL_HANDSHAKE_TIMEOUT;
use crate::TUNNEL_TIMEOUT;
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
use std::fmt;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

lazy_static! {
    static ref TUNNEL_MANAGER: Arc<RwLock<TunnelManager>> =
        Arc::new(RwLock::new(TunnelManager::default()));
}

pub fn get_tunnel_manager() -> TunnelManager {
    TUNNEL_MANAGER.read().unwrap().clone()
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
        let mut network = settings::get_rita_common().network;
        let own_ip = match network.mesh_ip {
            Some(ip) => ip,
            None => {
                return Err(RitaCommonError::MiscStringError(
                    "No mesh IP configured yet".to_string(),
                ))
            }
        };
        // after this step we have created a blank wg interface that we should clean up if we fail
        let iface_name = KI.create_blank_wg_numbered_wg_interface()?;

        let args = TunnelOpenArgs {
            interface: iface_name.clone(),
            port: our_listen_port,
            endpoint: SocketAddr::new(ip, neigh_id.wg_port),
            remote_pub_key: neigh_id.global.wg_public_key,
            private_key_path: Path::new(&network.wg_private_key_path),
            own_ip,
            own_ip_v2: network.mesh_ip_v2,
            external_nic: network.external_nic.clone(),
            settings_default_route: &mut network.last_default_route,
        };

        if let Err(e) = KI.open_tunnel(args) {
            error!("Failed open tunnel! {:?}", e);
            // cleanup after our failed attempt
            KI.del_interface(&iface_name)?;
            return Err(e.into());
        }
        // a failure here isn't fatal, we just won't have traffic shaping
        if let Err(e) = KI.set_codel_shaping(&iface_name, speed_limit) {
            error!("Failed to setup codel shaping on tunnel! {:?}", e);
        }

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

        // If we fail to set this up in babeld we should try again in a moment
        if let Err(e) = t.monitor() {
            error!("Failed to monitor tunnel! {:?}", e);
            // cleanup after our failed attempt
            KI.del_interface(&t.iface_name)?;
            return Err(e.into());
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
        let babel_settings = settings::get_rita_common().network.babeld_settings.clone();

        // this operation blocks while opening and using a tcp stream
        let mut stream = open_babel_stream(babel_port, FAST_LOOP_TIMEOUT)?;
        monitor(&mut stream, &iface_name, babel_settings.interface_defaults)
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
    tunnels: HashMap<Identity, Vec<Tunnel>>,
    shaper: Shaper,
}

impl Default for TunnelManager {
    fn default() -> TunnelManager {
        TunnelManager::new()
    }
}

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

/// Simple helper function to run tunnel GC + check babel interfaces
pub fn tm_common_slow_loop_helper(babel_interfaces: Vec<Interface>) {
    let tunnel_manager = &mut *TUNNEL_MANAGER.write().unwrap();
    tunnel_manager.monitor_check(&babel_interfaces);
    trace!("Sending tunnel GC");
    tunnel_manager.tunnel_gc(TUNNEL_TIMEOUT, TUNNEL_HANDSHAKE_TIMEOUT, babel_interfaces);
}

/// Called by DebtKeeper with the updated billing status of every tunnel every round
pub fn tm_tunnel_state_change(msg: Vec<TunnelChange>) -> Result<(), RitaCommonError> {
    let tunnel_manager = &mut *TUNNEL_MANAGER.write().unwrap();
    for tunnel in msg {
        tunnel_manager.tunnel_payment_state_change(tunnel);
    }
    Ok(())
}

impl TunnelManager {
    pub fn new() -> Self {
        TunnelManager {
            tunnels: HashMap::new(),
            shaper: Shaper::default(),
        }
    }

    /// Gets all ports currently in use by TunnelManager
    fn get_all_used_ports(&self) -> HashSet<u16> {
        let mut ports = HashSet::new();
        for (_, tl) in self.tunnels.iter() {
            for t in tl {
                if !ports.insert(t.listen_port) {
                    // we panic here in tests so we can identify the issue
                    if cfg!(test) || cfg!(integration_test) || cfg!(legacy_integration_test) {
                        panic!("Found duplicate port in use by tunnel manager!?");
                    }
                }
            }
        }
        ports
    }

    /// Gets a port off of the internal port list after checking that said port is free
    /// with the operating system.
    fn get_next_available_port(&self) -> Result<u16, TunnelManagerError> {
        let udp_table = KI.used_ports()?;
        let used_ports = self.get_all_used_ports();

        let start = settings::get_rita_common().network.wg_start_port;
        for port in start..65535 {
            if udp_table.contains(&port) || used_ports.contains(&port) {
                continue;
            } else {
                return Ok(port);
            }
        }
        Err(TunnelManagerError::NoFreePortsError)
    }

    /// This function goes through all tunnels preset in rita memory and add them to babel is they are not present already
    pub fn monitor_check(&self, interface_list: &[Interface]) {
        // Hashset of all interface names. This allows for an O(n) search instead of O(n^2)
        let mut interface_map: HashSet<String> = HashSet::new();
        for int in interface_list {
            interface_map.insert(int.name.clone());
        }

        let rita_tunnels = self.tunnels.iter();
        for (_, tunnels) in rita_tunnels {
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

    /// gets the tunnel from the list with the same ifidx, ip, and identity
    fn get_tunnel_mut(&mut self, ifidx: u32, ip: IpAddr, id: Identity) -> Option<&mut Tunnel> {
        for (index_id, tunnel_list) in self.tunnels.iter_mut() {
            for tunnel in tunnel_list.iter_mut() {
                // ensure a match, including an index match to protect against misfiled tunnels
                if tunnel.listen_ifidx == ifidx
                    && tunnel.neigh_id.global == id
                    && *index_id == id
                    && tunnel.ip == ip
                {
                    return Some(tunnel);
                }
            }
        }
        None
    }

    /// deletes all instances of a given tunnel with the same ip, ifidx, and wgkey
    fn del_tunnel(&mut self, target_tunnel: Tunnel) {
        // the problem with just running 'retain' with the tunnel is that duplicates may remain
        // say for example a duplicate tunnel set has different open times, the duplicate would
        // not be equal and thus not be deleted.
        // Instead we find matching tunnels and then mark them for deletion, the tunnel won't change out
        // from under us so we can be sure that the matches we found are being deleted in the second loop
        for (_, tunnel_list) in self.tunnels.iter_mut() {
            let mut tunnels_to_delete: Vec<Tunnel> = Vec::new();

            for tunnel in tunnel_list.iter() {
                if target_tunnel.listen_ifidx == tunnel.listen_ifidx
                    && target_tunnel.ip == tunnel.ip
                    && target_tunnel.neigh_id.global == tunnel.neigh_id.global
                {
                    tunnels_to_delete.push(tunnel.clone());
                }
            }

            for to_del in tunnels_to_delete {
                tunnel_list.retain(|val| *val != to_del)
            }
        }
    }

    fn add_new_tunnel_to_list(
        &mut self,
        peer_ip: IpAddr,
        ifidx: u32,
        their_localid: LocalIdentity,
    ) -> Result<Tunnel, RitaCommonError> {
        let our_port = self.get_next_available_port()?;
        // Create new tunnel
        let tunnel = Tunnel::new(peer_ip, our_port, ifidx, their_localid);
        match tunnel {
            Ok(tunnel) => {
                trace!("Tunnel {:?} is open", tunnel);
                insert_into_tunnel_list(&tunnel, &mut self.tunnels);
                Ok(tunnel)
            }
            Err(e) => {
                error!("Unable to open tunnel {}", e);
                Err(e)
            }
        }
    }

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    /// return the tunnel object and if we already had a tunnel
    pub fn open_tunnel(
        &mut self,
        their_localid: LocalIdentity,
        peer: Peer,
    ) -> Result<(Tunnel, bool), RitaCommonError> {
        trace!("getting existing tunnel or opening a new one");

        let our_tunnel =
            self.get_tunnel_mut(peer.ifidx, peer.contact_socket.ip(), their_localid.global);

        // when we don't know take the more conservative option and assume they do have a tunnel
        let they_have_tunnel = their_localid.have_tunnel.unwrap_or(true);

        match our_tunnel {
            Some(our_tunnel) => {
                // bump the last seen time on this tunnel so it doesn't get deleted
                our_tunnel.last_contact = Instant::now();
                // update the nickname in case they changed it live
                our_tunnel.neigh_id.global.nickname = their_localid.global.nickname;

                if they_have_tunnel {
                    Ok((our_tunnel.clone(), true))
                } else {
                    // In the case that we have a tunnel and they don't we drop our existing one
                    // and agree on the new parameters in this message
                    info!(
                        "We have a tunnel but our peer {:?} does not! Handling",
                        peer.contact_socket.ip()
                    );
                    // tell Babel to flush the interface and then delete it, if this fails we continue
                    // with what we're doing becuase we don't know the state of the remaining tunnel
                    // so we leave it orphaned to be cleared on system reboot.
                    let res = our_tunnel.unmonitor();
                    if res.is_err() {
                        error!(
                            "We failed to unmonitor the interface {:?} with {:?} it's now orphaned",
                            our_tunnel.iface_name, res
                        );
                    }
                    // drop the mutable tunnel reference via cloning
                    let our_tunnel = our_tunnel.clone();
                    self.del_tunnel(our_tunnel);
                    // create a new tunnel with details from this message
                    let tunnel = self.add_new_tunnel_to_list(
                        peer.contact_socket.ip(),
                        peer.ifidx,
                        their_localid,
                    )?;
                    Ok((tunnel, true))
                }
            }
            None => {
                info!(
                    "no tunnel found for {:?}%{:?} creating",
                    peer.contact_socket.ip(),
                    peer.ifidx,
                );
                let tunnel = self.add_new_tunnel_to_list(
                    peer.contact_socket.ip(),
                    peer.ifidx,
                    their_localid,
                )?;
                Ok((tunnel, false))
            }
        }
    }

    /// Updates the tunnel payment state based on if the user has paid or not
    fn tunnel_payment_state_change(&mut self, msg: TunnelChange) {
        let id = msg.identity;
        let action = msg.action;
        trace!(
            "Tunnel state change request for {:?} with action {:?}",
            id,
            action,
        );

        // Find a tunnel
        match self.tunnels.get_mut(&id) {
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
                                }
                                PaymentState::Overdue => {
                                    continue;
                                }
                            }
                        }
                    }
                }
                // update the bw limits if required, don't gate calling this function
                // if payment issues are occuring it may fail to enforce, it must be called
                // again later even if there are no changes to ensure everything is in a proper state
                let res = tunnel_bw_limit_update(&tunnels);
                if res.is_err() {
                    error!("Bandwidth limiting failed with {:?}", res);
                }
            }
            None => {
                // This is now pretty common since there's no more none action
                // and exits have identities for all clients (active or not)
                // on hand
                trace!("Couldn't find tunnel for identity {:?}", id);
            }
        }
    }
}

/// A single use internal struct used to flag what tunnels need to be updated
pub struct TunnelChange {
    pub identity: Identity,
    pub action: TunnelAction,
}

/// Takes a vec of tunnels and then updates the bandwidth limits on them. The calling functions
/// ensure that this is only done when required. We further optimize by checking the qdisc before
/// performing the update here
fn tunnel_bw_limit_update(tunnels: &[Tunnel]) -> Result<(), RitaCommonError> {
    info!("Running tunnel bw limit update!");

    let payment = settings::get_rita_common().payment;
    let bw_per_iface = payment.free_tier_throughput;

    for tunnel in tunnels {
        let payment_state = &tunnel.payment_state;
        let iface_name = &tunnel.iface_name;
        let has_limit = KI.has_limit(iface_name)?;

        if *payment_state == PaymentState::Overdue
            && !has_limit
            && !potential_payment_issues_detected()
        {
            KI.set_classless_limit(iface_name, bw_per_iface)?;
        } else if *payment_state == PaymentState::Paid && has_limit {
            KI.set_codel_shaping(iface_name, None)?;
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
            .or_default()
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
