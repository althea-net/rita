//! This module adds support for light clients, light clients being android hpones which connect directly to a client hotspot and have their
//! traffic piped out over the clients exit tunnel in exchange for payment. Light clients do not register to exits neither do they participate
//! in routing in any way. The billing and connection process is sort of a 'mini exit' at the router level. This isn't an ideal design at all,
//! especially since the client traffic exits unencrypted at one point on the participating Rita Client router. Sadly this is unavoidable as
//! far as I can tell due to the restrictive nature of how and when Android allows ipv6 routing.

use actix_web_async::http::StatusCode;
use actix_web_async::{web::Json, HttpRequest, HttpResponse};
use althea_kernel_interface::wg_iface_counter::prepare_usage_history;
use althea_kernel_interface::wg_iface_counter::WgUsage;
use althea_types::{Identity, LightClientLocalIdentity, LocalIdentity, WgKey};
use rita_common::debt_keeper::traffic_update;
use rita_common::debt_keeper::Traffic;
use rita_common::peer_listener::Peer;
use rita_common::tunnel_manager::id_callback::IdentityCallback;
use rita_common::tunnel_manager::Tunnel;
use rita_common::utils::ip_increment::incrementv4;
use rita_common::{tm_identity_callback, KI};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use crate::traffic_watcher::get_exit_dest_price;
use crate::RitaClientError;

lazy_static! {
    static ref LIGHT_CLIENT_MANAGER: Arc<RwLock<LightClientManager>> =
        Arc::new(RwLock::new(LightClientManager::default()));
}

/// Sets up a variant of the exit tunnel nat rules, assumes that the exit
/// tunnel is already created and doesn't change the system routing table
fn setup_light_client_forwarding(client_addr: Ipv4Addr, nic: &str) -> Result<(), RitaClientError> {
    // the way this works is pretty heavy on the routes and iptables rules
    // it wouldn't be feasible if we expected more than a few dozen phone
    // clients on a single device. Instead of having an aggregating network
    // like br-lan to allow us to treat multiple interfaces as a single nic
    // we manipulate routes and iptables rules for the wg tunnels directly
    // this is easier to manage programatically but as mentioned before
    // doesn't exactly scale well.
    // Key points to note here is that the routes and addresses
    // get cleaned up on their own whent the interface is deleted but
    // the iptables rule does not and requires explicit deletion
    trace!("adding light client nat rules");
    KI.add_ipv4("192.168.20.0".parse().unwrap(), nic)?;
    KI.run_command(
        "ip",
        &["route", "add", &format!("{}/32", client_addr), "dev", nic],
    )?;
    // forwards phone client packets while blocking other destinations this
    // needs to be cleaned up at some point
    KI.add_iptables_rule(
        "iptables",
        &[
            "-I",
            "FORWARD",
            "-i",
            nic,
            "--src",
            &format!("{}/32", client_addr),
            "-j",
            "ACCEPT",
        ],
    )?;
    Ok(())
}

/// Response to the light_client_hello endpoint on the Rita client module with a modified hello packet
/// this modified packet includes an ipv4 address and opens a modified tunnel that is attached to the
/// phone network bridge into a natted ipv4 network rather than into a Babel network.
pub async fn light_client_hello_response(req: (Json<LocalIdentity>, HttpRequest)) -> HttpResponse {
    let their_id = *req.0;
    let light_client_address = lcm_get_address(GetAddress(their_id));
    let exit_dest_price = get_exit_dest_price();

    let err_mesg = "Malformed light client hello tcp packet!";
    let socket = match req.1.peer_addr() {
        Some(val) => val,
        None => {
            error!("{}", err_mesg);
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(err_mesg);
        }
    };
    let (light_client_address_option, light_client_address) = match light_client_address {
        Ok(addr) => (Some(addr), addr),
        Err(e) => {
            let err_mesg = "Could not allocate address!";
            error!("{} {}", err_mesg, e);
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(err_mesg);
        }
    };
    trace!("Got light client Hello from {:?}", req.1.peer_addr());
    trace!(
        "opening tunnel in light_client_hello_response for {:?}",
        their_id
    );
    let peer = Peer {
        contact_socket: socket,
        ifidx: 0, // only works because we lookup ifname in kernel interface
    };
    let tunnel = tm_identity_callback(IdentityCallback::new(
        their_id,
        peer,
        None,
        light_client_address_option,
    ));
    let (tunnel, have_tunnel) = match tunnel {
        Some(val) => val,
        None => {
            error!("Light Client Manager: tunnel open failure!");
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(err_mesg);
        }
    };
    let lci = LightClientLocalIdentity {
        global: match settings::get_rita_client().get_identity() {
            Some(id) => id,
            None => {
                error!("Light Client Manager: Identity has no mesh IP ready yet");
                return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(err_mesg);
            }
        },
        wg_port: tunnel.listen_port,
        have_tunnel: Some(have_tunnel),
        tunnel_address: light_client_address,
        price: settings::get_rita_client().payment.light_client_fee as u128 + exit_dest_price,
    };
    // Two bools -> 4 state truth table, in 3 of
    // those states we need to re-add these rules
    // router phone
    // false false  we need to add rules to new tunnel
    // true  false  tunnel will be re-created so new rules
    // false true   new tunnel on our side new rules
    // true  true   only case where we don't need to run this
    if let Some(they_have_tunnel) = their_id.have_tunnel {
        if !(have_tunnel && they_have_tunnel) {
            if let Err(e) = setup_light_client_forwarding(light_client_address, &tunnel.iface_name)
            {
                error!("Light Client Manager: {}", e);
                return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(err_mesg);
            }
        }
    } else {
        error!("Light clients should never send the none tunnel option!");
    }
    // We send the callback, which can safely allocate a port because it already successfully
    // contacted a neighbor. The exception to this is when the TCP session fails at exactly
    // the wrong time.
    HttpResponse::Ok().json(lci)
}

pub struct LightClientManager {
    start_address: Ipv4Addr,
    prefix: u8,
    assigned_addresses: HashMap<Identity, Ipv4Addr>,
    last_seen_bytes: HashMap<WgKey, WgUsage>,
}

impl Default for LightClientManager {
    fn default() -> LightClientManager {
        LightClientManager {
            start_address: "192.168.20.1".parse().unwrap(),
            prefix: 24,
            assigned_addresses: HashMap::new(),
            last_seen_bytes: HashMap::new(),
        }
    }
}

pub struct GetAddress(LocalIdentity);

pub fn lcm_get_address(msg: GetAddress) -> Result<Ipv4Addr, RitaClientError> {
    let lcm = &mut *LIGHT_CLIENT_MANAGER.write().unwrap();
    let requester_id = msg.0;
    assign_client_address(
        &mut lcm.assigned_addresses,
        requester_id.global,
        lcm.start_address,
        lcm.prefix,
    )
}

fn assign_client_address(
    assigned_addresses: &mut HashMap<Identity, Ipv4Addr>,
    requester_id: Identity,
    start_address: Ipv4Addr,
    prefix: u8,
) -> Result<Ipv4Addr, RitaClientError> {
    trace!("Assigning light client address");
    // we already have an ip for this id on record, send the same one out
    if let Some(ip) = assigned_addresses.get(&requester_id) {
        trace!("Found existing record, no ip assigned");
        return Ok(*ip);
    }
    let assigned_ips = {
        let mut set = HashSet::new();
        for (_id, ip) in assigned_addresses.iter() {
            set.insert(ip);
        }
        set
    };

    // get the first unused address this is kinda inefficient, I'm sure we could do this in all O(1) operations
    // but at the cost of more memory usage, which I'd rather avoid. Either way it's trivial
    // both in terms of memory and cpu at the scale of only 16 bits of address space (ipv4 private range size)
    let mut new_address: Ipv4Addr = start_address;
    while assigned_ips.contains(&new_address) {
        trace!("light client address {} is already assigned", new_address);
        new_address = incrementv4(new_address, prefix)?;
    }
    assigned_addresses.insert(requester_id, new_address);
    trace!(
        "finished selecting light client address, it is {}",
        new_address
    );
    Ok(new_address)
}

/// Returns addresses not assigned to tunnels to the pool, this is
/// inefficient versus having tunnel manager notify us when it deletes
/// a tunnel but it turns out getting the conditional complication required
/// for that to all workout is moderately complicated.
fn return_addresses(tunnels: &[Tunnel], assigned_addresses: &mut HashMap<Identity, Ipv4Addr>) {
    trace!(
        "starting address GC tunnels {:?}, addresses {:?}",
        tunnels,
        assigned_addresses
    );
    let mut addresses_to_remove: Vec<Identity> = Vec::new();
    for (id, ip) in assigned_addresses.iter() {
        let mut found = false;
        for tunnel in tunnels.iter() {
            if let Some(tunnel_ip) = tunnel.light_client_details {
                if tunnel_ip == *ip {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            addresses_to_remove.push(*id);
        }
    }
    info!("{} LC ADDR GC", addresses_to_remove.len());
    for id in addresses_to_remove {
        assigned_addresses.remove(&id);
    }
    info!("{} LC ACTIVE", assigned_addresses.len());
}

/// Traffic watcher implementation for light clients, this is conceptually
/// very simple, just iterate over tunnels from tunnel manager, determine
/// which ones are light clients, those that are check their usage and shoot
/// off a message to debt keeper with an updated debt total. Conceptually similar
/// to the exit billing system. Biggest difference is that the phone client doesn't
/// need to concern itself with full route prices. Because this data is not being
/// 'forwarded' but instead sent over the exit tunnel and paid for in the same way
/// client usage is.
pub struct Watch {
    pub tunnels: Vec<Tunnel>,
    pub exit_dest_price: u128,
}

pub fn lcm_watch(msg: Watch) {
    let lcm = &mut *LIGHT_CLIENT_MANAGER.write().unwrap();
    trace!("Starting light client traffic watcher");
    let our_price =
        settings::get_rita_client().payment.light_client_fee as u128 + msg.exit_dest_price;
    let tunnels = msg.tunnels;
    let mut debts: HashMap<Identity, i128> = HashMap::new();
    for tunnel in tunnels.iter() {
        if let Some(_val) = tunnel.light_client_details {
            if let Ok(counter) = KI.read_wg_counters(&tunnel.iface_name) {
                prepare_usage_history(&counter, &mut lcm.last_seen_bytes);
                // there should only be one, more than one client on a single
                // interface is not supported
                assert!(counter.len() == 1);
                // get only the first element
                let (key, usage) = counter.iter().next().unwrap();
                // unwrap is safe before prepare usage history will ensure an entry exits
                let last_seen_usage = lcm.last_seen_bytes.get_mut(key).unwrap();
                let round_upload = usage.upload - last_seen_usage.upload;
                let round_download = usage.download - last_seen_usage.download;
                *last_seen_usage = *usage;
                let debt = ((round_upload + round_download) * our_price as u64) as i128;
                subtract_or_insert_and_subtract(&mut debts, tunnel.neigh_id.global, debt);
            }
        }
    }
    let mut traffic_vec = Vec::new();
    for (from, amount) in debts {
        traffic_vec.push(Traffic {
            from,
            amount: amount.into(),
        })
    }
    traffic_update(traffic_vec);
    // tunnel address garbage collection
    return_addresses(&tunnels, &mut lcm.assigned_addresses);
}

/// inserts and also negates since negative means they owe us and we can never owe phone clients
fn subtract_or_insert_and_subtract(data: &mut HashMap<Identity, i128>, i: Identity, debt: i128) {
    if let Some(val) = data.get_mut(&i) {
        *val -= debt;
    } else {
        data.insert(i, -debt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clu::generate_mesh_ip;
    use rita_common::tunnel_manager::get_test_id;
    use rita_common::tunnel_manager::get_test_tunnel;

    fn get_random_id() -> Identity {
        Identity {
            mesh_ip: generate_mesh_ip().unwrap(),
            eth_address: "0x4288C538A553357Bb6c3b77Cf1A60Da6E77931F6"
                .parse()
                .unwrap(),
            wg_public_key: "GIaAXDi1PbGq3PsKqBnT6kIPoE2K1Ssv9HSb7++dzl4="
                .parse()
                .unwrap(),
            nickname: None,
        }
    }

    #[test]
    fn test_basic_assign() {
        let mut assigned_addresses = HashMap::new();
        let res: Ipv4Addr = assign_client_address(
            &mut assigned_addresses,
            get_random_id(),
            "192.168.1.0".parse().unwrap(),
            24,
        )
        .expect("Failed to assign ip");
        assert_eq!("192.168.1.0".parse::<Ipv4Addr>().unwrap(), res);
        let res: Ipv4Addr = assign_client_address(
            &mut assigned_addresses,
            get_random_id(),
            "192.168.1.0".parse().unwrap(),
            24,
        )
        .expect("Failed to assign ip");
        assert_eq!("192.168.1.1".parse::<Ipv4Addr>().unwrap(), res);
        let res: Ipv4Addr = assign_client_address(
            &mut assigned_addresses,
            get_random_id(),
            "192.168.1.0".parse().unwrap(),
            24,
        )
        .expect("Failed to assign ip");
        assert_eq!("192.168.1.2".parse::<Ipv4Addr>().unwrap(), res);
    }

    #[test]
    fn test_failed_assign() {
        let mut assigned_addresses = HashMap::new();
        let _res = assign_client_address(
            &mut assigned_addresses,
            get_test_id(),
            "192.168.1.255".parse().unwrap(),
            24,
        );
        let res = assign_client_address(
            &mut assigned_addresses,
            get_random_id(),
            "192.168.1.255".parse().unwrap(),
            24,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_gc() {
        let mut assigned_addresses = HashMap::new();
        let _res = assign_client_address(
            &mut assigned_addresses,
            get_test_id(),
            "192.168.1.0".parse().unwrap(),
            24,
        );
        let _res = assign_client_address(
            &mut assigned_addresses,
            get_random_id(),
            "192.168.1.0".parse().unwrap(),
            24,
        );
        let empty_tunnels = [] as [Tunnel; 0];
        return_addresses(&empty_tunnels, &mut assigned_addresses);
        assert!(assigned_addresses.is_empty());
    }

    #[test]
    fn test_not_gc() {
        let mut assigned_addresses = HashMap::new();
        let ip = "192.168.1.0".parse().unwrap();
        let _res = assign_client_address(&mut assigned_addresses, get_test_id(), ip, 24);
        let _res = assign_client_address(&mut assigned_addresses, get_random_id(), ip, 24);
        let tunnels = [get_test_tunnel(ip, true)];
        println!("{:?}", assigned_addresses);
        return_addresses(&tunnels, &mut assigned_addresses);
        assert_eq!(assigned_addresses.len(), 1);
    }
}
