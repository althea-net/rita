use super::TunnelManager;
use crate::KI;
use crate::SETTING;
use actix::{Context, Handler, Message};
use althea_types::Identity;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

lazy_static! {
    static ref INTERFACE_MBPS: Arc<RwLock<HashMap<Identity, Option<usize>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

lazy_static! {
    static ref RESET_FLAG: AtomicBool = AtomicBool::new(false);
}

/// A cross thread accessible object representing the shaping level of a given interface, this is not perfect as it's
/// a mapping by identity, meaning that if a given id has multiple tunnels using different shaped speeds it may not
/// paint the full picture, that being said my observation is that this never seems to be the case, I can of course be wrong
/// TODO we only ever interact with tunnel speed shaping here, we should consider moving this subcomponent to locked data
/// rather than actor data as part of the actix-removal refactor
#[allow(dead_code)]
pub fn get_shaping_status() -> HashMap<Identity, Option<usize>> {
    INTERFACE_MBPS.read().unwrap().clone()
}

#[allow(dead_code)]
pub fn flag_reset_shaper() {
    RESET_FLAG.store(true, Ordering::Relaxed)
}

pub struct ShapeMany {
    pub to_shape: Vec<ShapingAdjust>,
}

/// Message sent by network monitor when it determines that an iface is bloated
pub struct ShapingAdjust {
    pub iface: String,
    pub action: ShapingAdjustAction,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ShapingAdjustAction {
    IncreaseSpeed,
    ReduceSpeed,
}

impl Message for ShapeMany {
    type Result = ();
}

impl Handler<ShapeMany> for TunnelManager {
    type Result = ();

    fn handle(&mut self, msg: ShapeMany, _: &mut Context<Self>) -> Self::Result {
        let network_settings = SETTING.get_network();
        let minimum_bandwidth_limit = network_settings.shaper_settings.min_speed;
        let starting_bandwidth_limit = network_settings.shaper_settings.max_speed;
        let bandwidth_limit_enabled = network_settings.shaper_settings.enabled;
        drop(network_settings);

        // get the lowest speed from each set of tunnels by
        // id and store that for external reference
        let mut external_list = INTERFACE_MBPS.write().unwrap();
        for (id, tunnel_list) in self.tunnels.iter() {
            let mut lowest = None;
            for tunnel in tunnel_list.iter() {
                match (tunnel.speed_limit, lowest) {
                    (Some(new), Some(current)) => {
                        if new < current {
                            lowest = Some(new);
                        }
                    }
                    (Some(new), None) => lowest = Some(new),
                    (None, Some(_)) => {}
                    (None, None) => {}
                }
            }
            external_list.insert(*id, lowest);
        }
        drop(external_list);

        // removes shaping without requiring a restart if the flag is set or
        // if it's set in the settings
        if !bandwidth_limit_enabled || RESET_FLAG.load(Ordering::Relaxed) {
            for (_id, tunnel_list) in self.tunnels.iter_mut() {
                for tunnel in tunnel_list {
                    if tunnel.speed_limit != None {
                        set_shaping_or_error(&tunnel.iface_name, None);
                        tunnel.speed_limit = None;
                    }
                }
            }
            RESET_FLAG.store(false, Ordering::Relaxed);
            return;
        }

        for shaping_command in msg.to_shape {
            let action = shaping_command.action;
            let iface = shaping_command.iface;
            for (id, tunnel_list) in self.tunnels.iter_mut() {
                for tunnel in tunnel_list {
                    if tunnel.iface_name == iface {
                        match (tunnel.speed_limit, action) {
                            // nothing to do in this case
                            (None, ShapingAdjustAction::IncreaseSpeed) => {}
                            // start at the starting limit
                            (None, ShapingAdjustAction::ReduceSpeed) => {
                                tunnel.speed_limit = Some(starting_bandwidth_limit);
                                set_shaping_or_error(&iface, Some(starting_bandwidth_limit))
                            }
                            // after that cut the value by 20% each time
                            (Some(val), ShapingAdjustAction::ReduceSpeed) => {
                                let new_val = (val as f32 * 0.8f32) as usize;
                                if new_val < minimum_bandwidth_limit {
                                    error!("Interface {} for peer {} is showing bloat but we can't reduce it's bandwidth any further. Current value {}", iface, id.wg_public_key, val);
                                } else {
                                    info!(
                                    "Interface {} for peer {} is showing bloat new speed value {}",
                                    iface, id.wg_public_key, new_val
                                );
                                    set_shaping_or_error(&iface, Some(new_val));
                                    tunnel.speed_limit = Some(new_val);
                                }
                            }
                            // increase the value by 5% until we reach the starting value
                            (Some(val), ShapingAdjustAction::IncreaseSpeed) => {
                                let new_val = increase_speed(val);
                                if new_val < starting_bandwidth_limit {
                                    info!(
                                    "Interface {} for peer {} has not shown bloat new speed value {}",
                                    iface, id.wg_public_key, new_val
                                    );
                                    set_shaping_or_error(&iface, Some(new_val));
                                    tunnel.speed_limit = Some(new_val);
                                } else {
                                    info!(
                                        "Can not increase on Interface {} for peer {}",
                                        iface, id.wg_public_key
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// tiny little helper function for GotBloat() limit is in mbps
fn set_shaping_or_error(iface: &str, limit: Option<usize>) {
    if let Err(e) = KI.set_codel_shaping(iface, limit) {
        error!("Failed to shape tunnel for bloat! {}", e);
    }
}

/// increase the speed by 5% or 1mbps if the value is too small
/// for a 5% increase
fn increase_speed(input: usize) -> usize {
    let new = (input as f32 * 1.05f32) as usize;
    if new == input {
        input + 1
    } else {
        new
    }
}
