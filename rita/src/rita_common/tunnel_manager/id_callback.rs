use crate::rita_common::peer_listener::Peer;
use crate::rita_common::tunnel_manager::Tunnel;
use crate::rita_common::tunnel_manager::TunnelManager;
use actix::{Context, Handler, Message};
use althea_types::LocalIdentity;

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

impl Message for IdentityCallback {
    type Result = Option<(Tunnel, bool)>;
}

// An attempt to contact a neighbor has succeeded or a neighbor has contacted us, either way
// we need to allocate a tunnel for them and place it onto our local storage.  In the case
// that a neighbor contacts us we don't have a port already allocated and we need to choose one
// in the case that we have atempted to contact a neighbor we have already sent them a port that
// we now must attach to their tunnel entry. If we also return a bool for if the tunnel already
// exists
impl Handler<IdentityCallback> for TunnelManager {
    type Result = Option<(Tunnel, bool)>;

    fn handle(&mut self, msg: IdentityCallback, _: &mut Context<Self>) -> Self::Result {
        let our_port = match msg.our_port {
            Some(port) => port,
            _ => match self.get_port(0) {
                Some(p) => p,
                None => {
                    warn!("Failed to allocate tunnel port! All tunnel opening will fail");
                    return None;
                }
            },
        };

        let res = self.open_tunnel(msg.local_identity, msg.peer, our_port);
        match res {
            Ok(res) => Some(res),
            Err(e) => {
                warn!("Open Tunnel failed with {:?}", e);
                None
            }
        }
    }
}
