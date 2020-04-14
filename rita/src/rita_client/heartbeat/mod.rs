//! Manages the Heartbeat from the router. This is a piece of metric data that is controlled by the system logging setting
//! if logging is enabled the system will send a heartbeat in the Rita client loop every CLIENT_LOOP_SPEED seconds. This
//! heartbeat contains data about routing, balance, and implicit in it's sending data that the router is up and functioning.
//! This data is sent as a udp fire and forget packet. Take note that if this packet is larger than the MTU you may run into
//! issues, so be careful expanding it.
//!
//! This packet is encrypted using the usual box construction and sent to the heartbeat server in the following format
//! WgKey, Nonce, Ciphertext for the HeartBeatMessage. This consumes 32 bytes, 24 bytes, and to the end of the message

use crate::rita_client::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::rita_common::network_monitor::GetNetworkInfo;
use crate::rita_common::network_monitor::NetworkMonitor;
use crate::rita_common::tunnel_manager::Neighbor as RitaNeighbor;
use crate::SETTING;
use actix::actors::resolver;
use actix::{Arbiter, SystemService};
use althea_types::ContactDetails;
use althea_types::HeartbeatMessage;
use althea_types::Identity;
use althea_types::WgKey;
use babel_monitor::get_installed_route;
use babel_monitor::get_neigh_given_route;
use babel_monitor::Neighbor;
use babel_monitor::Route;
use failure::Error;
use futures01::future::Future;
use settings::client::ExitServer;
use settings::client::RitaClientSettings;
use settings::RitaCommonSettings;
use sodiumoxide::crypto::box_;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

type Resolver = resolver::Resolver;

lazy_static! {
    pub static ref HEARTBEAT_SERVER_KEY: WgKey = "hizclQFo/ArWY+/9+AJ0LBY2dTiQK4smy5icM7GA5ng="
        .parse()
        .unwrap();
}

pub fn send_udp_heartbeat() {
    let dns_request = Resolver::from_registry()
        .send(resolver::Resolve::host(
            SETTING.get_log().heartbeat_url.clone(),
        ))
        .timeout(CLIENT_LOOP_TIMEOUT);
    let network_info = NetworkMonitor::from_registry()
        .send(GetNetworkInfo {})
        .timeout(CLIENT_LOOP_TIMEOUT);
    // Check for the basics first, before doing any of the hard futures work
    let (our_id, selected_exit_details) =
        if let (Some(id), Some(exit)) = (SETTING.get_identity(), get_selected_exit()) {
            let exit_info = exit.info;
            match exit_info.general_details() {
                Some(details) => (id, details.clone()),
                None => return,
            }
        } else {
            return;
        };

    let res = dns_request.join(network_info).then(move |res| match res {
        Ok((Ok(dnsresult), Ok(network_info))) => {
            if dnsresult.is_empty() {
                trace!("Got zero length dns response: {:?}", dnsresult);
            }

            if let Ok(route) = get_selected_exit_route(&network_info.babel_routes) {
                let neigh_option = get_neigh_given_route(&route, &network_info.babel_neighbors);
                let neigh_option =
                    get_rita_neigh_option(neigh_option, &network_info.rita_neighbors);
                if let Some((neigh, rita_neigh)) = neigh_option {
                    for dns_socket in dnsresult {
                        send_udp_heartbeat_packet(
                            dns_socket,
                            our_id,
                            selected_exit_details.exit_price,
                            route.clone(),
                            neigh.clone(),
                            rita_neigh.identity.global,
                        );
                    }
                }
            }
            Ok(())
        }
        Err(e) => {
            warn!("Failed to resolve domain and get network info! {:?}", e);
            Ok(())
        }
        Ok((Err(e), _)) => {
            warn!("DNS resolution failed with {:?}", e);
            Ok(())
        }
        Ok((_, Err(e))) => {
            warn!("Could not get network info with {:?}", e);
            Ok(())
        }
    });

    Arbiter::spawn(res);
}

fn get_selected_exit_route(route_dump: &[Route]) -> Result<Route, Error> {
    let exit_client = SETTING.get_exit_client();
    let exit_mesh_ip = if let Some(e) = exit_client.get_current_exit() {
        e.id.mesh_ip
    } else {
        return Err(format_err!("No Exit"));
    };
    get_installed_route(&exit_mesh_ip, route_dump)
}

fn get_selected_exit() -> Option<ExitServer> {
    let exit_client = SETTING.get_exit_client();
    let exit = if let Some(e) = exit_client.get_current_exit() {
        e
    } else {
        return None;
    };
    Some(exit.clone())
}

fn get_rita_neigh_option(
    neigh: Option<Neighbor>,
    rita_neighbors: &[RitaNeighbor],
) -> Option<(Neighbor, RitaNeighbor)> {
    match neigh {
        Some(neigh) => match get_rita_neighbor(&neigh, rita_neighbors) {
            Some(rita_neigh) => Some((neigh, rita_neigh)),
            None => None,
        },
        None => None,
    }
}

fn get_rita_neighbor(neigh: &Neighbor, rita_neighbors: &[RitaNeighbor]) -> Option<RitaNeighbor> {
    for rita_neighbor in rita_neighbors.iter() {
        if rita_neighbor.iface_name.contains(&neigh.iface) {
            return Some(rita_neighbor.clone());
        }
    }
    None
}

fn send_udp_heartbeat_packet(
    dns_socket: SocketAddr,
    our_id: Identity,
    exit_price: u64,
    exit_route: Route,
    exit_neighbor: Neighbor,
    exit_neighbor_id: Identity,
) {
    let network_settings = SETTING.get_network();
    let reg_details = SETTING.get_exit_client().reg_details.clone();
    let our_publickey = network_settings.wg_public_key.expect("No public key?");
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();
    let their_publickey: WgKey = *HEARTBEAT_SERVER_KEY;
    let their_publickey = their_publickey.into();

    let contact_details = match reg_details {
        Some(details) => ContactDetails {
            phone: details.phone,
            email: details.email,
        },
        None => ContactDetails {
            phone: None,
            email: None,
        },
    };
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

    let message = HeartbeatMessage {
        id: our_id,
        organizer_address: SETTING.get_operator().operator_address,
        balance: SETTING.get_payment().balance.clone(),
        exit_dest_price: exit_price + exit_route.price as u64,
        upstream_id: exit_neighbor_id,
        exit_route,
        exit_neighbor,
        contact_details,
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
        Ok(bytes) => trace!("Sent {} heartbeat bytes", bytes),
        Err(e) => error!("Failed to send heartbeat with {:?}", e),
    }
}
