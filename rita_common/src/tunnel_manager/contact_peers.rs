//! This file contains http hello sending and handling functions, these are used exclusively for
//! manual peers, or peers that are not on the local network and require hello's routed over networks that
//! are not althea, such as the larger internet. While manual peers can be used for any peer to peer connection
//! it's mostly used for Gateways to reach exits and bridge them into the local babel mesh network, allowing clients
//! to reach them and send traffic to the internet.

use crate::peer_listener::send_hello;
use crate::peer_listener::structs::Hello as NewHello;
use crate::peer_listener::structs::Peer;
use crate::peer_listener::structs::PeerListener;
use crate::rita_loop::is_gateway;
use crate::tm_identity_callback;
use crate::tunnel_manager::get_tunnel_manager;
use crate::IdentityCallback;
use crate::RitaCommonError;
use althea_kernel_interface::ip_route::manual_peers_route;
use althea_types::LocalIdentity;
use futures::future::join_all;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Resolves a hostname and sends a hello to the resulting IP, this function may block, this is the
/// primary reason peer discovery is given it's own thread currently.
pub async fn tm_neighbor_inquiry_hostname(their_hostname: String) -> Result<(), RitaCommonError> {
    info!("neighbor_inquiry_hostname {}", their_hostname);
    let network_settings = settings::get_rita_common().network;
    let rita_hello_port = network_settings.rita_hello_port;

    // note this may block and should only be called in the peer discovery loop where blocking is accounted for
    // note we add the hello port to make this a valid socket address which must include one, any port could be used here
    let res = format!("{their_hostname}:{rita_hello_port}").to_socket_addrs();
    match res {
        Ok(dnsresult) => {
            let url = format!("http://[{their_hostname}]:{rita_hello_port}/hello");
            info!("Saying hostname hello to: {:?} at ip {:?}", url, dnsresult);
            if dnsresult.clone().next().is_some() {
                // dns records may have many ip's if we get multiple it's a load
                // balanced exit and we need to create tunnels to all of them
                for dns_socket in dnsresult {
                    let their_ip = dns_socket.ip();
                    let socket = SocketAddr::new(their_ip, rita_hello_port);
                    let man_peer = Peer {
                        ifidx: 0,
                        contact_socket: socket,
                    };
                    let res = tm_neighbor_inquiry_manual_peer(man_peer).await;
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
        }
        Err(e) => {
            warn!("DNS resolution failed with {:?} for {}", e, their_hostname);
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct Hello {
    pub my_id: LocalIdentity,
    pub to: Peer,
}

pub async fn tm_neighbor_inquiry_manual_peer(peer: Peer) -> Result<(), RitaCommonError> {
    trace!("TunnelManager neigh inquiry for {:?}", peer);
    let our_port = get_tunnel_manager().get_next_available_port()?;
    let mut settings = settings::get_rita_common();
    let changed = manual_peers_route(
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
        to: peer,
    };

    if changed {
        settings::set_rita_common(settings);
    }

    trace!("Sending Hello {:?}", msg);

    // ipv6 addresses need the [] bracket format, ipv4 address literals do not
    let endpoint = if msg.to.contact_socket.is_ipv4() {
        format!(
            "http://{}:{}/hello",
            msg.to.contact_socket.ip(),
            msg.to.contact_socket.port()
        )
    } else {
        format!(
            "http://[{}]:{}/hello",
            msg.to.contact_socket.ip(),
            msg.to.contact_socket.port()
        )
    };

    let client = awc::Client::default();
    info!("Sending hello request to manual peer: {}", endpoint);
    let response = client
        .post(endpoint)
        .timeout(Duration::from_secs(5))
        .send_json(&msg.my_id)
        .await;

    let mut response = match response {
        Ok(a) => a,
        Err(e) => {
            error!("Error serializing our request {:?}", e);
            return Err(RitaCommonError::SendRequestError(e));
        }
    };

    let response: LocalIdentity = match response.json().await {
        Ok(a) => a,
        Err(e) => {
            error!("Got error deserializing Hello {:?}", e);
            return Err(RitaCommonError::JsonPayloadError(e));
        }
    };

    info!("Received a local identity, setting a tunnel");
    let peer = msg.to;
    let wg_port = msg.my_id.wg_port;
    match tm_identity_callback(IdentityCallback::new(response, peer, Some(wg_port))) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Contacts one neighbor with our LocalIdentity to get their LocalIdentity and wireguard tunnel
/// interface name. Sends a Hello over udp
pub fn tm_neighbor_inquiry_udp_peer(peer: &Peer, pl: &PeerListener) -> Result<(), RitaCommonError> {
    trace!("TunnelManager neigh inquiry for {:?}", peer);
    let our_port = get_tunnel_manager().get_next_available_port()?;

    let peer_listener = pl;
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

    // new send_hello call using udp socket
    // We do not need the old http hello except for exits, which are called as manual peers
    send_hello(&new_msg, udp_socket, peer.contact_socket, our_port)
}

/// takes a list of peers to contact and dispatches UDP hello messages to peers discovered via IPv6 link local
/// multicast peer discovery, also sends http hello messages to manual peers, only resolves manual peers with
/// hostnames if the devices is detected to be a gateway.
pub async fn tm_contact_peers(pl: &PeerListener) {
    let network_settings = settings::get_rita_common().network;
    let manual_peers = network_settings.manual_peers.clone();
    let is_gateway = is_gateway();
    let rita_hello_port = network_settings.rita_hello_port;
    drop(network_settings);

    trace!("TunnelManager contacting peers");

    let mut manual_peers_ip_fut = Vec::new();
    let mut manual_peers_dns_fut = Vec::new();
    for (_, peer) in pl.peers.iter() {
        trace!("contacting peer found by UDP {:?}", peer);
        if let Err(e) = tm_neighbor_inquiry_udp_peer(peer, pl) {
            error!("Neighbor inqury for {} failed with: {:?}", peer.ifidx, e);
        }
    }
    for manual_peer in manual_peers.iter() {
        trace!("contacting manual peer {:?}", manual_peer);
        let ip = manual_peer.parse::<IpAddr>();

        match ip {
            Ok(ip) => {
                let socket = SocketAddr::new(ip, rita_hello_port);
                let man_peer = Peer {
                    ifidx: 0,
                    contact_socket: socket,
                };
                // we must run these in the local context because the peer struct does not live long enough
                manual_peers_ip_fut.push(tm_neighbor_inquiry_manual_peer(man_peer));
            }
            Err(_) => {
                // Do not contact manual peers on the internet if we are not a gateway
                // it will just fill the logs with failed dns resolution attempts or result
                // in bad behavior, we do allow the addressing of direct ip address gateways
                // for the special case that the user is attempting some special behavior
                if is_gateway {
                    manual_peers_dns_fut
                        .push(tm_neighbor_inquiry_hostname(manual_peer.to_string()));
                }
            }
        }
    }

    // now that we've constructed our futures arrays, now we execute them in parallel
    // executing udp peers in this way has no advantage of doing them sync becuase it's all
    // sync actions, but for manual peers the advantage is huge since there are half a dozen exits
    // and they each may take seconds to respond, joining the udp peers in just lets us run their sync
    // operations while efficiencly waiting for http exit responses
    let manual_result_ip = join_all(manual_peers_ip_fut).await;
    let manual_result_dns = join_all(manual_peers_dns_fut).await;
    for r in manual_result_ip {
        if let Err(e) = r {
            error!("Neighbor inqury for ip failed with: {:?}", e);
        }
    }
    for r in manual_result_dns {
        if let Err(e) = r {
            error!("Neighbor inqury for dns failed with: {:?}", e);
        }
    }
}
