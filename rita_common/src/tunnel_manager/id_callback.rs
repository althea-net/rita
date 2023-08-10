use crate::tunnel_manager::{get_tunnel_manager_write_ref, Tunnel, TUNNEL_MANAGER};
use crate::{peer_listener::structs::Peer, RitaCommonError};
use althea_types::LocalIdentity;

#[derive(Clone, Debug)]
pub struct IdentityCallback {
    pub local_identity: LocalIdentity,
    pub peer: Peer,
    pub our_port: Option<u16>,
}

impl IdentityCallback {
    pub fn new(
        local_identity: LocalIdentity,
        peer: Peer,
        our_port: Option<u16>,
    ) -> IdentityCallback {
        IdentityCallback {
            local_identity,
            peer,
            our_port,
        }
    }
}

/// An attempt to contact a neighbor has succeeded or a neighbor has contacted us, either way
/// we need to allocate a tunnel for them and place it onto our local storage.  In the case
/// that a neighbor contacts us we don't have a port already allocated and we need to choose one
/// in the case that we have attempted to contact a neighbor we have already sent them a port that
/// we now must attach to their tunnel entry. If we also return a bool for if the tunnel already
/// exists
pub fn tm_identity_callback(msg: IdentityCallback) -> Result<(Tunnel, bool), RitaCommonError> {
    info!("Tm identity callback with msg: {:?}", msg);
    let tm_pin = &mut *TUNNEL_MANAGER.write().unwrap();
    let tunnel_manager = get_tunnel_manager_write_ref(tm_pin);
    tunnel_manager.open_tunnel(msg.local_identity, msg.peer)
}
