//! This file contains http hello sending and handling functions, these are used exclusively for
//! manual peers, or peers that are not on the local network and require hello's routed over networks that
//! are not althea, such as the larger internet. While manual peers can be used for any peer to peer connection
//! it's mostly used for Gateways to reach exits and bridge them into the local babel mesh network, allowing clients
//! to reach them and send traffic to the internet.

use crate::hello_handler::handle_hello;
use crate::hello_handler::Hello;
use crate::peer_listener::Hello as NewHello;
use crate::peer_listener::PeerListener;
use crate::peer_listener::PEER_LISTENER;
use crate::peer_listener::{send_hello, Peer};
use crate::rita_loop::is_gateway;
use crate::tunnel_manager::tm_get_port;
use crate::RitaCommonError;
use crate::KI;
use althea_types::LocalIdentity;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr, UdpSocket};

/// Resolves a hostname and sends a hello to the resulting IP, this function may block, this is the
/// primary reason peer discovery is given it's own thread currently.
pub async fn tm_neighbor_inquiry_hostname(their_hostname: String) -> Result<(), RitaCommonError> {
    info!("neighbor_inquiry_hostname {}", their_hostname);
    let network_settings = settings::get_rita_common().network;
    let is_gateway = is_gateway();
    let rita_hello_port = network_settings.rita_hello_port;

    let our_port = tm_get_port();

    // note this may block and should only be called in the peer discovery loop where blocking is accounted for
    // note we add the hello port to make this a valid socket address which must include one, any port could be used here
    let res = format!("{}:{}", their_hostname, rita_hello_port).to_socket_addrs();
    match res {
        Ok(dnsresult) => {
            let url = format!("http://[{}]:{}/hello", their_hostname, rita_hello_port);
            info!("Saying hostname hello to: {:?} at ip {:?}", url, dnsresult);
            if dnsresult.clone().next().is_some() && is_gateway {
                // dns records may have many ip's if we get multiple it's a load
                // balanced exit and we need to create tunnels to all of them
                for dns_socket in dnsresult {
                    let their_ip = dns_socket.ip();
                    let socket = SocketAddr::new(their_ip, rita_hello_port);
                    let man_peer = Peer {
                        ifidx: 0,
                        contact_socket: socket,
                    };
                    let res = contact_manual_peer(&man_peer, our_port).await;
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

/// Contacts one neighbor with our LocalIdentity to get their LocalIdentity and wireguard tunnel
/// interface name. Sends a Hello over udp, or http if its a manual peer
pub async fn tm_neighbor_inquiry(
    peer: &Peer,
    is_manual_peer: bool,
    peer_listener: &mut PeerListener,
) -> Result<(), RitaCommonError> {
    trace!("TunnelManager neigh inquiry for {:?}", peer);
    let our_port = tm_get_port();

    if is_manual_peer {
        contact_manual_peer(peer, our_port).await
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
        contact_neighbor(peer, our_port, udp_socket, peer.contact_socket).await
    }
}

/// takes a list of peers to contact and dispatches UDP hello messages to peers discovered via IPv6 link local
/// multicast peer discovery, also sends http hello messages to manual peers, only resolves manual peers with
/// hostnames if the devices is detected to be a gateway.
pub async fn tm_contact_peers(peers: HashMap<IpAddr, Peer>) {
    let network_settings = settings::get_rita_common().network;
    let manual_peers = network_settings.manual_peers.clone();
    let is_gateway = is_gateway();
    let rita_hello_port = network_settings.rita_hello_port;
    drop(network_settings);
    // Hold a lock on shared state until we finish sending all messages. This prevents a race condition
    // where the hashmaps get cleared out during subsequent ticks
    info!("TunnelManager contacting peers");
    let writer = &mut *PEER_LISTENER.write().unwrap();

    for (_, peer) in peers.iter() {
        info!("contacting peer found by UDP {:?}", peer);
        let res = tm_neighbor_inquiry(peer, false, writer).await;
        if res.is_err() {
            warn!("Neighbor inqury for {:?} failed! with {:?}", peer, res);
        }
    }
    for manual_peer in manual_peers.iter() {
        info!("contacting manual peer {:?}", manual_peer);
        let ip = manual_peer.parse::<IpAddr>();

        match ip {
            Ok(ip) => {
                let socket = SocketAddr::new(ip, rita_hello_port);
                let man_peer = Peer {
                    ifidx: 0,
                    contact_socket: socket,
                };
                let res = tm_neighbor_inquiry(&man_peer, true, writer).await;
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
                    let res = tm_neighbor_inquiry_hostname(manual_peer.to_string()).await;
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

/// Sets out to contacts a local mesh neighbor, takes a speculative port (only assigned if the neighbor
/// responds successfully). This function is used for mesh peers
async fn contact_neighbor(
    peer: &Peer,
    our_port: u16,
    socket: &UdpSocket,
    send_addr: SocketAddr,
) -> Result<(), RitaCommonError> {
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
    send_hello(&new_msg, socket, send_addr, our_port);

    Ok(())
}

/// Uses Hello Handler to send a Hello over http. Takes a speculative port (only assigned
/// if neighbor responds successfully)
async fn contact_manual_peer(peer: &Peer, our_port: u16) -> Result<(), RitaCommonError> {
    let mut settings = settings::get_rita_common();
    let changed = KI.manual_peers_route(
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

    if changed {
        settings::set_rita_common(settings);
    }

    //old hello manager over http
    handle_hello(msg).await;

    Ok(())
}
