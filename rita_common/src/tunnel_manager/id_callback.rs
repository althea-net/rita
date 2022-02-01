use crate::peer_listener::Peer;
use crate::tunnel_manager::Tunnel;
use althea_types::LocalIdentity;
use std::net::Ipv4Addr;

use super::TUNNEL_MANAGER;

pub struct IdentityCallback {
    pub local_identity: LocalIdentity,
    pub peer: Peer,
    pub our_port: Option<u16>,
    pub light_client_details: Option<Ipv4Addr>,
}

impl IdentityCallback {
    pub fn new(
        local_identity: LocalIdentity,
        peer: Peer,
        our_port: Option<u16>,
        light_client_details: Option<Ipv4Addr>,
    ) -> IdentityCallback {
        IdentityCallback {
            local_identity,
            peer,
            our_port,
            light_client_details,
        }
    }
}

/// An attempt to contact a neighbor has succeeded or a neighbor has contacted us, either way
/// we need to allocate a tunnel for them and place it onto our local storage.  In the case
/// that a neighbor contacts us we don't have a port already allocated and we need to choose one
/// in the case that we have atempted to contact a neighbor we have already sent them a port that
/// we now must attach to their tunnel entry. If we also return a bool for if the tunnel already
/// exists
pub fn tm_identity_callback(msg: IdentityCallback) -> Option<(Tunnel, bool)> {
    let mut tunnel_manager = TUNNEL_MANAGER.write().unwrap();
    let our_port = match msg.our_port {
        Some(port) => port,
        _ => tunnel_manager.get_port(),
    };

    let res = tunnel_manager.open_tunnel(
        msg.local_identity,
        msg.peer,
        our_port,
        msg.light_client_details,
    );
    match res {
        Ok(res) => Some(res),
        Err(e) => {
            warn!("Open Tunnel failed with {:?}", e);
            None
        }
    }
}
