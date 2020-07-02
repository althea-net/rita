use super::Tunnel;
use super::TunnelManager;
use crate::KI;
use actix::{Context, Handler, Message};
use althea_types::Identity;
use failure::Error;
use std::collections::HashMap;
use std::time::Duration;

/// A message type for deleting all tunnels we haven't heard from for more than the duration.
pub struct TriggerGC {
    /// if we do not receive a hello within this many seconds we attempt to gc the tunnel
    /// this garbage collection can be avoided if the tunnel has seen a handshake within
    /// tunnel_handshake_timeout time
    pub tunnel_timeout: Duration,
    /// The backup value that prevents us from deleting an active tunnel. We check the last
    /// handshake on the tunnel and if it's within this amount of time we don't GC it.
    pub tunnel_handshake_timeout: Duration,
}

impl Message for TriggerGC {
    type Result = Result<(), Error>;
}

impl Handler<TriggerGC> for TunnelManager {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: TriggerGC, _ctx: &mut Context<Self>) -> Self::Result {
        let mut good: HashMap<Identity, Vec<Tunnel>> = HashMap::new();
        let mut timed_out: HashMap<Identity, Vec<Tunnel>> = HashMap::new();
        // Split entries into good and timed out rebuilding the double hashmap structure
        // as you can tell this is totally copy based and uses 2n ram to prevent borrow
        // checker issues, we should consider a method that does modify in place
        for (_identity, tunnels) in self.tunnels.iter() {
            for tunnel in tunnels.iter() {
                if tunnel.last_contact.elapsed() < msg.tunnel_timeout
                    || check_handshake_time(msg.tunnel_handshake_timeout, &tunnel.iface_name)
                {
                    insert_into_tunnel_list(tunnel, &mut good);
                } else {
                    insert_into_tunnel_list(tunnel, &mut timed_out)
                }
            }
        }

        for (id, tunnels) in timed_out.iter() {
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
        self.tunnels = good;

        for (_ident, tunnels) in timed_out {
            for tunnel in tunnels {
                match tunnel.light_client_details {
                    None => {
                        // In the same spirit, we return the port to the free port pool only after tunnel
                        // deletion goes well.
                        tunnel.unmonitor(0);
                    }
                    Some(_) => {
                        tunnel.close_light_client_tunnel();
                    }
                }
            }
        }

        Ok(())
    }
}

/// A simple helper function to reduce the number of if/else statements in tunnel GC
fn insert_into_tunnel_list(input: &Tunnel, tunnels_list: &mut HashMap<Identity, Vec<Tunnel>>) {
    let identity = &input.neigh_id.global;
    let input = input.clone();
    if tunnels_list.contains_key(identity) {
        tunnels_list.get_mut(identity).unwrap().push(input);
    } else {
        tunnels_list.insert(*identity, Vec::new());
        tunnels_list.get_mut(identity).unwrap().push(input);
    }
}

/// This function checks the handshake time of a tunnel when compared to the handshake timeout,
/// it returns true if we fail to get the handshake time (erring on the side of caution) and only
/// false if all last tunnel handshakes are older than the allowed time limit
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
            true
        }
    }
}
