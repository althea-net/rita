use super::Tunnel;
use crate::tunnel_manager::TUNNEL_MANAGER;
use crate::KI;
use althea_types::Identity;
use babel_monitor::structs::Interface;
use std::time::Duration;
use std::{collections::HashMap, time::Instant};

/// Performs a cleanup of all babel tunnels that we have not heard from in the configured time
/// tunnel_timeout:
///
/// if we do not receive a hello within this many seconds we attempt to gc the tunnel
/// this garbage collection can be avoided if the tunnel has seen a handshake within
/// tunnel_handshake_timeout time
///
/// tunnel_handshake_timeout
///
/// The backup value that prevents us from deleting an active tunnel. We check the last
/// handshake on the tunnel and if it's within this amount of time we don't GC it.
///
/// babel_interfaces
/// a vector of babel interfaces, if we find an interface that babel doesn't classify as
/// 'up' we will gc it for recreation via the normal hello/ihu process, this prevents us
/// from having tunnels that don't work for babel peers
pub fn tm_trigger_gc(
    tunnel_timeout: Duration,
    tunnel_handshake_timeout: Duration,
    babel_interfaces: Vec<Interface>,
) {
    let tunnel_manager = &mut *TUNNEL_MANAGER.write().unwrap();

    let interfaces = into_interfaces_hashmap(&babel_interfaces);
    trace!("Starting tunnel gc {:?}", interfaces);
    let mut good: HashMap<Identity, Vec<Tunnel>> = HashMap::new();
    let mut to_delete: HashMap<Identity, Vec<Tunnel>> = HashMap::new();
    // Split entries into good and timed out rebuilding the double hashmap structure
    // as you can tell this is totally copy based and uses 2n ram to prevent borrow
    // checker issues, we should consider a method that does modify in place
    for (_identity, tunnels) in tunnel_manager.tunnels.iter() {
        for tunnel in tunnels.iter() {
            if tunnel_should_be_kept(
                tunnel,
                tunnel_handshake_timeout,
                tunnel_timeout,
                &interfaces,
            ) {
                insert_into_tunnel_list(tunnel, &mut good);
            } else {
                insert_into_tunnel_list(tunnel, &mut to_delete)
            }
        }
    }

    for (id, tunnels) in to_delete.iter() {
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
    tunnel_manager.tunnels = good;

    unmonitor_tunnels(to_delete);
}

fn unmonitor_tunnels(to_delete: HashMap<Identity, Vec<Tunnel>>) {
    for (_ident, tunnels) in to_delete {
        for tunnel in tunnels {
            // In the same spirit, we return the port to the free port pool only after tunnel
            // deletion goes well.
            if let Err(e) = tunnel.unmonitor() {
                error!(
                    "Tunnel unmonitor failed during gc, garbage idle tunnel! {:?}",
                    e
                );
            }
        }
    }
}

/// This routine has two independent purposes, first is to clear out tunnels
/// that should be 'up' in babel but for some reason are not. In this case communication
/// with babel has failed when creating the tunnel. We provide a grace period of TUNNEL_TIMEOUT
/// from when the tunnel was first created to prevent immediate removal while tunnels are still
/// bootstrapping. Second our goal is to remove tunnel that we have not heard from for a long time
/// but these are only removed if they have a handshake and it's long enough ago to be the same as
/// TUNNEL_TIMEOUT. This means tunnel that have never handshaked but are up will never be removed
/// but this is an ok outcome.
/// This routine has two independent purposes
///
/// 1) clean up tunnels we think are working but actually are not.
///
///   This can happen when Rita has successfully opened a tunnel, it's got handshakes
///   and we've sent the listen command off to babel. But somehow the tunnel has been
///   disrupted and babel has it marked as down. In this case we want to remove the tunnel
///   to allow it to be recreated correctly.
///
///   There is a complication here, tunnels don't come up immediately, so we add a time check
///   where we check the initial creation time of the tunnel and provide a grace period.
///
///   A second case where this can happen is if tunnel negotiation fails somehow, with proper timing
///   tunnel negotiation can't fail but I believe there to be a race condition that causes incorrect
///   tunnel negotiation, in that case we see that the tunnel has had no successful handshakes within
///   the timeout period and we remove it.
///
/// 2) Clean up tunnels for nodes that have long since gone offline
///
///   Long running nodes like gateways and exits may have thousands of nodes connect and go offline
///   many for good. Since we don't have to run out of tunnel ports and also maintaining a longer list
///   of tunnels is just a pain we want to garbage collect these. If we have not heard from the peer for
///   Tunnel_Timeout time we will remove it.
///
///   The complication in this case is that sometimes sector antennas like to aggregate multicast communication
///   meaning we may not 'hear' from a peer for quite some time because we never see it's multicast hello. But in
///   fact the connection is both opening and working. To deal with this edge case we check the handshake time on
///   the wireguard tunnel, which is the same as asking if unicast communication over this tunnel has been recently
///   successful. In theory we could look for a neighbor that's online from the tunnel interface in the babel routing
///   table and solve both this and the previous complication at once. So that's a possible improvement to this routine.
fn tunnel_should_be_kept(
    tunnel: &Tunnel,
    tunnel_handshake_timeout: Duration,
    tunnel_timeout: Duration,
    interfaces: &HashMap<String, bool>,
) -> bool {
    let since_created = Instant::now().checked_duration_since(tunnel.created());
    let since_last_contact = Instant::now().checked_duration_since(tunnel.last_contact);
    // this is almost always true, unless one of the two is in the future versus 'now' it's safe to just skip this
    // for the next gc round in that case.
    if let (Some(since_created), Some(since_last_contact)) = (since_created, since_last_contact) {
        let handshake_timeout = !check_handshake_time(tunnel_handshake_timeout, &tunnel.iface_name);
        let created_recently = since_created < tunnel_timeout;
        let tunnel_up = tunnel_up(interfaces, &tunnel.iface_name);
        let contact_timeout = since_last_contact > tunnel_timeout;

        match (
            created_recently,
            contact_timeout,
            handshake_timeout,
            tunnel_up,
        ) {
            // recently created tunnels should always be kept while they converge
            (true, _, _, _) => true,
            // this is a good tunnel
            (false, false, false, true) => true,
            // contact timeout, but handshakes are going and babel is connected, this is a good tunnel suffering
            // from multicast optimization
            (false, true, false, true) => true,
            // we haven't heard from the neighbors Rita or Wireguard, fully disconnected
            (false, true, true, _) => false,
            // No recent handshakes, but recent contact from Rita, we should recreate this tunnel as it's probably
            // suffering from the negotiation race condition
            (false, false, true, _) => false,
            // tunnel up, handshakes moving, but not up in babel, needs to be recreated in order to pass traffic
            (false, false, false, false) => false,
            // tunnel up, handshakes moving, but not up in babel, needs to be recreated in order to pass traffic but
            // it's also suffering from multicast optimization, meaning this tunnel may not re-open quickly.
            // Better to take that chance than simply not function. A better solution her may be to unlisten
            // and re-listen in babel on this tunnel
            (false, true, false, false) => false,
        }
    } else {
        true
    }
}

/// A simple helper function to reduce the number of if/else statements in tunnel GC
fn insert_into_tunnel_list(input: &Tunnel, tunnels_list: &mut HashMap<Identity, Vec<Tunnel>>) {
    let identity = &input.neigh_id.global;
    let input = input.clone();
    match tunnels_list.get_mut(identity) {
        None => {
            tunnels_list.insert(*identity, vec![input]);
        }
        Some(v) => v.push(input),
    }
}

/// This function checks the handshake time of a tunnel when compared to the handshake timeout,
/// it returns false if we fail to get the handshake time or if all last tunnel handshakes are
/// older than the allowed time limit
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
            false
        }
    }
}

/// sorts the interfaces vector into a hashmap of interface name to up status
fn into_interfaces_hashmap(interfaces: &[Interface]) -> HashMap<String, bool> {
    let mut ret = HashMap::new();
    for interface in interfaces {
        ret.insert(interface.name.clone(), interface.up);
    }
    ret
}

/// Searches the list of Babel tunnels for a given tunnel, if the tunnel is found
/// and it is down (not up in this case) we return false, indicating that this tunnel
/// needs to be deleted. If we do not find the tunnel return true. Because it is possible
/// that during a tunnel monitor failure we may encounter such a tunnel, this happens with
/// some frequency
fn tunnel_up(interfaces: &HashMap<String, bool>, tunnel_name: &str) -> bool {
    trace!("Checking if {} is up", tunnel_name);
    if let Some(up) = interfaces.get(tunnel_name) {
        if !up {
            warn!("Found Babel interface that's not up, removing!");
            false
        } else {
            true
        }
    } else {
        error!("Could not find interface {} in Babel, did monitor fail?", tunnel_name);
        true
    }
}
