use super::PaymentState;
use super::TUNNEL_MANAGER;
use althea_types::Identity;
use althea_types::NeighborStatus;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

lazy_static! {
    static ref NEIGHBOR_STATUS: Arc<RwLock<HashMap<Identity, NeighborStatus>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// A cross thread accessible object representing the status of a given interface, this is not perfect as it's
/// a mapping by identity, meaning that if a given id has multiple tunnels using different shaped speeds it may not
/// paint the full picture, that being said my observation is that this never seems to be the case, I can of course be wrong
#[allow(dead_code)]
pub fn get_neighbor_status() -> HashMap<Identity, NeighborStatus> {
    NEIGHBOR_STATUS.read().unwrap().clone()
}

/// Handles updates to neighbor status with lazy static lock
pub fn update_neighbor_status() {
    let tunnel_manager = &mut *TUNNEL_MANAGER.write().unwrap();
    let mut external_list = NEIGHBOR_STATUS.write().unwrap();
    for (id, tunnel_list) in tunnel_manager.tunnels.iter() {
        // we may have many tunnels with this same peer, we want to get
        // the lowest shaper value of any of the recently active tunnels
        let mut lowest_shaper_speed = None;
        let mut enforced = false;
        for tunnel in tunnel_list.iter() {
            match (tunnel.speed_limit, lowest_shaper_speed) {
                (Some(new), Some(current)) => {
                    if new < current {
                        lowest_shaper_speed = Some(new);
                    }
                }
                (Some(new), None) => lowest_shaper_speed = Some(new),
                (None, Some(_)) => {}
                (None, None) => {}
            }
            if tunnel.payment_state == PaymentState::Overdue {
                enforced = true;
            }
        }

        external_list.insert(
            *id,
            NeighborStatus {
                id: *id,
                shaper_speed: lowest_shaper_speed,
                enforced,
            },
        );
    }
}
