//! Manages the Heartbeat from the router. This is a piece of metric data that is controlled by the system logging setting
//! if logging is enabled the system will send a heartbeat in the Rita client loop every CLIENT_LOOP_SPEED seconds. This
//! heartbeat contains data about routing, balance, and implicit in it's sending data that the router is up and functioning.
//! This data is sent as a udp fire and forget packet. Take note that if this packet is larger than the MTU you may run into
//! issues, so be careful expanding it. It's usually about 1kbyte at the moment.
//!
//! Note that if an Operator address is configured it has the effect of forcing heartbeats on as the operator interface is
//! useless without them
//!
//! There is a strong argument for moving most of the data in the heartbeat to the operator checkin function down in
//! crate::rita_client::operator_update but that would require a server refactor that I haven't wanted to get into yet.
//!
//! This packet is encrypted using the usual LibSodium box construction and sent to the heartbeat server in the following format
//! WgKey, Nonce, Ciphertext for the HeartBeatMessage. This consumes 32 bytes, 24 bytes, and to the end of the message

use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use babel_monitor::get_installed_route;
use babel_monitor::get_neigh_given_route;
use rita_common::network_monitor::GetNetworkInfo;
use rita_common::network_monitor::NetworkMonitor;
use rita_common::tunnel_manager::Neighbor as RitaNeighbor;

use actix::actors::resolver;
use actix::{Arbiter, SystemService};
use althea_types::HeartbeatMessage;
use althea_types::Identity;
use althea_types::WgKey;
use babel_monitor::Neighbor as NeighborLegacy;
use babel_monitor::Route as RouteLegacy;
use failure::Error;
use futures01::future::Future;
use settings::client::ExitServer;
use sodiumoxide::crypto::box_;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

type Resolver = resolver::Resolver;

pub struct HeartbeatCache {
    dns: VecDeque<SocketAddr>,
    exit_route: RouteLegacy,
    exit_neighbor_babel: NeighborLegacy,
    exit_neighbor_rita: RitaNeighbor,
}

#[cfg(not(feature = "operator_debug"))]
lazy_static! {
    pub static ref HEARTBEAT_SERVER_KEY: WgKey = "hizclQFo/ArWY+/9+AJ0LBY2dTiQK4smy5icM7GA5ng="
        .parse()
        .unwrap();
}
#[cfg(feature = "operator_debug")]
lazy_static! {
    pub static ref HEARTBEAT_SERVER_KEY: WgKey = "RECW5xQfDzo3bzaZtzepM/+qWRuFTohChKKzUqGA0n4="
        .parse()
        .unwrap();
}
lazy_static! {
    pub static ref HEARTBEAT_CACHE: Arc<RwLock<Option<HeartbeatCache>>> =
        Arc::new(RwLock::new(None));
}

pub fn send_udp_heartbeat() {
    #[cfg(not(feature = "operator_debug"))]
    let heartbeat_url = "operator.althea.net:33333";
    #[cfg(feature = "operator_debug")]
    let heartbeat_url = "192.168.10.2:33333";

    trace!("attempting to send heartbeat");
    let dns_request = Resolver::from_registry()
        .send(resolver::Resolve::host(heartbeat_url.to_string()))
        .timeout(CLIENT_LOOP_TIMEOUT);
    let network_info = NetworkMonitor::from_registry()
        .send(GetNetworkInfo {})
        .timeout(CLIENT_LOOP_TIMEOUT);
    // Check for the basics first, before doing any of the hard futures work
    let (our_id, selected_exit_details) = if let (Some(id), Some(exit)) = (
        settings::get_rita_client().get_identity(),
        get_selected_exit(),
    ) {
        let exit_info = exit.info;
        match exit_info.general_details() {
            Some(details) => (id, details.clone()),
            None => return,
        }
    } else {
        return;
    };
    trace!("we have heartbeat basic info");

    let res = dns_request.join(network_info).then(move |res| {
        // In this block we handle gathering all the info and the many ways gathering it could fail
        // once we have succeeded even if only once we have a cached value that is updated regularly
        // if for some reason the cache update fails, we can still progress with the heartbeat
        match res {
            Ok((Ok(dnsresult), Ok(network_info))) => {
                match get_selected_exit_route(&network_info.babel_routes) {
                    Ok(route) => {
                        let neigh_option =
                            get_neigh_given_route(&route, &network_info.babel_neighbors);
                        let neigh_option =
                            get_rita_neigh_option(neigh_option, &network_info.rita_neighbors);
                        if let Some((neigh, rita_neigh)) = neigh_option {
                            // Now that we have all the info we can stop and try to update the
                            // heartbeat cache
                            let mut hb_cache = HEARTBEAT_CACHE.write().unwrap();
                            if let Some(ref mut hb_cache) = &mut *hb_cache {
                                trace!("we have heartbeat dns");
                                // having successfully talked to the DNS server does not mean we have any dns records
                                // this is where we disambiguate that. If we have seen records before we reject and refuse
                                // to update if the server tells us there are no longer any records. Yes this does actually
                                // happen very rarely, even on the worlds most reliable DNS servers
                                if !dnsresult.is_empty() {
                                    hb_cache.dns = dnsresult;
                                }
                                hb_cache.exit_route = route;
                                hb_cache.exit_neighbor_babel = neigh;
                                hb_cache.exit_neighbor_rita = rita_neigh;
                            } else {
                                *hb_cache = Some(HeartbeatCache {
                                    dns: dnsresult,
                                    exit_route: route,
                                    exit_neighbor_babel: neigh,
                                    exit_neighbor_rita: rita_neigh,
                                });
                            }
                        } else {
                            warn!("Failed to find neigh for heartbeat!");
                        }
                    }
                    Err(e) => warn!("Failed to get heartbeat route with {:?}", e),
                }
            }
            Err(e) => {
                warn!("Failed to resolve domain and get network info! {:?}", e);
            }
            Ok((Err(e), _)) => {
                warn!("DNS resolution failed with {:?}", e);
            }
            Ok((_, Err(e))) => {
                warn!("Could not get network info with {:?}", e);
            }
        }
        // Now we actually send the heartbeat, using the cached data if it is
        // available. We should only ever see it not be available for short periods
        // on startup
        let hb_cache = &*HEARTBEAT_CACHE.read().unwrap();
        if let Some(hb_cache) = hb_cache {
            // this is intentional behavior, if we have multiple DNS records we should
            // send heartbeats to all of them
            for dns_socket in hb_cache.dns.iter() {
                trace!("sending heartbeat");
                send_udp_heartbeat_packet(
                    dns_socket,
                    our_id,
                    selected_exit_details.exit_price,
                    hb_cache.exit_route.clone(),
                    hb_cache.exit_neighbor_babel.clone(),
                    hb_cache.exit_neighbor_rita.identity.global,
                );
            }
        } else {
            warn!("Cache not populated, can't heartbeat!");
        }
        Ok(())
    });

    Arbiter::spawn(res);
}

fn get_selected_exit_route(route_dump: &[RouteLegacy]) -> Result<RouteLegacy, Error> {
    let rita_client = settings::get_rita_client();
    let exit_client = rita_client.exit_client;
    let exit_mesh_ip = if let Some(e) = exit_client.get_current_exit() {
        e.selected_exit
            .selected_id
            .expect("Expected Exit ip, none present")
    } else {
        return Err(format_err!("No Exit"));
    };
    get_installed_route(&exit_mesh_ip, route_dump)
}

fn get_selected_exit() -> Option<ExitServer> {
    let rita_client = settings::get_rita_client();
    let exit_client = rita_client.exit_client;
    let exit = exit_client.get_current_exit()?;
    Some(exit.clone())
}

fn get_rita_neigh_option(
    neigh: Option<NeighborLegacy>,
    rita_neighbors: &[RitaNeighbor],
) -> Option<(NeighborLegacy, RitaNeighbor)> {
    match neigh {
        Some(neigh) => {
            get_rita_neighbor(&neigh, rita_neighbors).map(|rita_neigh| (neigh, rita_neigh))
        }
        None => None,
    }
}

fn get_rita_neighbor(
    neigh: &NeighborLegacy,
    rita_neighbors: &[RitaNeighbor],
) -> Option<RitaNeighbor> {
    for rita_neighbor in rita_neighbors.iter() {
        if rita_neighbor.iface_name.contains(&neigh.iface) {
            return Some(rita_neighbor.clone());
        }
    }
    None
}

fn send_udp_heartbeat_packet(
    dns_socket: &SocketAddr,
    our_id: Identity,
    exit_price: u64,
    exit_route: RouteLegacy,
    exit_neighbor: NeighborLegacy,
    exit_neighbor_id: Identity,
) {
    trace!("building heartbeat packet");
    let rita_client = settings::get_rita_client();
    let network_settings = rita_client.network;
    let low_balance_notification = settings::get_rita_client()
        .exit_client
        .low_balance_notification;
    let our_publickey = network_settings.wg_public_key.expect("No public key?");
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();
    let their_publickey: WgKey = *HEARTBEAT_SERVER_KEY;
    let their_publickey = their_publickey.into();
    drop(network_settings);

    let remote_ip = dns_socket.ip();
    let remote_port = dns_socket.port();
    let remote = dns_socket;

    let local_socketaddr = SocketAddr::from(([0, 0, 0, 0], remote_port));
    let local_socket = match UdpSocket::bind(&local_socketaddr) {
        Ok(s) => s,
        Err(e) => {
            error!("Couldn't bind to UDP heartbeat socket {:?}", e);
            return;
        }
    };

    trace!("Sending heartbeat to {:?}", remote_ip);
    let mut rita_client = settings::get_rita_client();
    let payment = rita_client.payment;
    let message = HeartbeatMessage {
        id: our_id,
        organizer_address: settings::get_rita_client().operator.operator_address,
        balance: payment.balance.clone(),
        exit_dest_price: exit_price + exit_route.price as u64,
        upstream_id: exit_neighbor_id,
        exit_route,
        exit_neighbor,
        notify_balance: low_balance_notification,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    // serde will only fail under specific circumstances with specific structs
    // given the fixed nature of our application here I think this is safe
    let plaintext = serde_json::to_vec(&message).unwrap();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, &their_publickey, &our_secretkey);

    let mut packet_contents = Vec::new();
    // build the packet from slices
    packet_contents.extend_from_slice(our_publickey.as_ref());
    packet_contents.extend_from_slice(&nonce.0);
    packet_contents.extend_from_slice(&ciphertext);

    if let Err(e) = local_socket.set_write_timeout(Some(Duration::new(0, 100))) {
        trace!("Failed to set socket timeout {:?}, skipping!", e);
        return;
    }

    match local_socket.send_to(&packet_contents, &remote) {
        Ok(bytes) => info!("Sent {} heartbeat bytes", bytes),
        Err(e) => error!("Failed to send heartbeat with {:?}", e),
    }
    rita_client.payment = payment;
    settings::set_rita_client(rita_client);
}