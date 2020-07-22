//! This module is responsible for checking in with the operator server and getting updated local settings

use crate::rita_client::dashboard::system_chain::set_system_blockchain;
use crate::rita_client::dashboard::wifi::reset_wifi_pass;
use crate::rita_client::rita_loop::is_gateway_client;
use crate::rita_client::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::rita_common::rita_loop::is_gateway;
use crate::rita_common::tunnel_manager::shaping::flag_reset_shaper;
use crate::rita_common::tunnel_manager::shaping::get_shaping_status;
use crate::rita_common::utils::option_convert;
use crate::KI;
use crate::SETTING;
use actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use actix_web::Error;
use actix_web::{client, HttpMessage};
use althea_kernel_interface::hardware_info::get_hardware_info;
use althea_kernel_interface::opkg_feeds::get_release_feed;
use althea_kernel_interface::opkg_feeds::set_release_feed;
use althea_types::NeighborStatus;
use althea_types::OperatorAction;
use althea_types::OperatorCheckinMessage;
use althea_types::OperatorUpdateMessage;
use futures01::Future;
use num256::Uint256;
use serde_json::Map;
use serde_json::Value;
use settings::client::RitaClientSettings;
use settings::RitaCommonSettings;
use std::time::Duration;

/// Things that you are not allowed to put into the merge json field of the OperatorUpdate,
/// this mostly includes dangerous local things like eth private keys (erase money)
/// ports (destory all networking) etc etc
const FORBIDDEN_MERGE_VALUES: [&str; 5] = [
    "eth_private_key",
    "eth_address",
    "mesh_ip",
    "external_nic",
    "peer_interfaces",
];

pub struct OperatorUpdate;

impl Actor for OperatorUpdate {
    type Context = Context<Self>;
}

impl Supervised for OperatorUpdate {}
impl SystemService for OperatorUpdate {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("OperatorUpdate started");
    }
}

impl OperatorUpdate {
    pub fn new() -> Self {
        OperatorUpdate
    }
}

impl Default for OperatorUpdate {
    fn default() -> OperatorUpdate {
        OperatorUpdate::new()
    }
}

/// How long we wait for a response from the server
/// this value must be less than or equal to the CLIENT_LOOP_SPEED
/// in the rita_client loop
pub const OPERATOR_UPDATE_TIMEOUT: Duration = CLIENT_LOOP_TIMEOUT;

#[derive(Message)]
pub struct Update;

impl Handler<Update> for OperatorUpdate {
    type Result = ();

    fn handle(&mut self, _msg: Update, _ctx: &mut Context<Self>) -> Self::Result {
        checkin();
    }
}

/// Checks in with the operator server
fn checkin() {
    #[cfg(not(feature = "operator_debug"))]
    let url = "https://operator.althea.net:8080/checkin";
    #[cfg(feature = "operator_debug")]
    let url = "http://192.168.10.2:8080/checkin";

    let logging_enabled = SETTING.get_log().enabled;
    let operator_settings = SETTING.get_operator();
    let system_chain = SETTING.get_payment().system_chain;
    let operator_address = operator_settings.operator_address;
    let use_operator_price =
        operator_settings.use_operator_price || operator_settings.force_use_operator_price;
    // a node is logically a gateway from a users perspective if it is directly connected to the
    // exit as a mesh client, even if the is_gateway var mostly governs things related to WAN use.
    // So we accept either of these conditions being true.
    let is_gateway = is_gateway() || is_gateway_client();
    let id = SETTING.get_identity().unwrap();

    let contact_info = option_convert(SETTING.get_exit_client().contact_info.clone());
    let install_details = operator_settings.installation_details.clone();
    let billing_details = operator_settings.billing_details.clone();

    drop(operator_settings);

    // if the user has disabled logging and has no operator configured we don't check in
    // if the user configures an operator but has disabled logging then we assume they still
    // want the operator to work properly and we will continue to checkin
    if operator_address.is_none() && !logging_enabled {
        info!("No Operator configured and logging disabled, not checking in!");
        return;
    }

    match operator_address {
        Some(address) => info!("Operator checkin using {} and {}", url, address),
        None => info!(
            "Operator checkin for default settings {} and {}",
            url, system_chain
        ),
    }

    let speeds = get_shaping_status();
    let mut neighbor_info = Vec::new();
    for (id, speed) in speeds {
        neighbor_info.push(NeighborStatus {
            id,
            shaper_speed: speed,
        });
    }

    let hardware_info = match get_hardware_info(SETTING.get_network().device.clone()) {
        Ok(info) => Some(info),
        Err(e) => {
            error!("Failed to get hardware info with {:?}", e);
            None
        }
    };

    let res = client::post(url)
        .header("User-Agent", "Actix-web")
        .json(OperatorCheckinMessage {
            id,
            operator_address,
            system_chain,
            neighbor_info: Some(neighbor_info),
            contact_info,
            install_details,
            billing_details,
            hardware_info,
        })
        .unwrap()
        .send()
        .timeout(OPERATOR_UPDATE_TIMEOUT)
        .from_err()
        .and_then(move |response| {
            trace!("Response is {:?}", response.status());
            trace!("Response is {:?}", response.headers());
            response
                .json()
                .from_err()
                .and_then(move |new_settings: OperatorUpdateMessage| {
                    trace!("Updating from operator settings");
                    let mut payment = SETTING.get_payment_mut();
                    let starting_token_bridge_core = payment.bridge_addresses.clone();

                    if use_operator_price {
                        // This will be true on devices that have integrated switches
                        // and a wan port configured. Mostly not a problem since we stopped
                        // shipping wan ports by default
                        if is_gateway {
                            payment.local_fee = new_settings.gateway;
                        } else {
                            payment.local_fee = new_settings.relay;
                        }
                        payment.light_client_fee = new_settings.phone_relay;
                    } else {
                        info!("User has disabled the OperatorUpdate!");
                    }

                    payment.max_fee = new_settings.max;
                    payment.balance_warning_level = new_settings.warning.into();
                    if let Some(new_chain) = new_settings.system_chain {
                        if payment.system_chain != new_chain {
                            set_system_blockchain(new_chain, &mut payment);
                        }
                    }
                    if let Some(new_chain) = new_settings.withdraw_chain {
                        payment.withdraw_chain = new_chain;
                    }
                    drop(payment);
                    trace!("Done with payment");

                    let mut operator = SETTING.get_operator_mut();
                    let new_operator_fee = Uint256::from(new_settings.operator_fee);
                    operator.operator_fee = new_operator_fee;
                    drop(operator);

                    merge_settings_safely(new_settings.merge_json);

                    // update the release feed to the provided release
                    // gated on "None" to prevent reading a file if there is
                    // no update. Maybe someday match will be smart enough to
                    // avoid that on it's own
                    if new_settings.release_feed.is_some() {
                        handle_release_feed_update(new_settings.release_feed);
                    }

                    match new_settings.operator_action {
                        Some(OperatorAction::ResetShaper) => flag_reset_shaper(),
                        Some(OperatorAction::Reboot) => {
                            let _res = KI.run_command("reboot", &[]);
                        }
                        Some(OperatorAction::ResetRouterPassword) => {
                            SETTING.get_network_mut().rita_dashboard_password = None;
                        }
                        Some(OperatorAction::ResetWiFiPassword) => {
                            let _res = reset_wifi_pass();
                        }
                        None => {}
                    }

                    let mut network = SETTING.get_network_mut();
                    network.shaper_settings = new_settings.shaper_settings;
                    drop(network);

                    trace!("Successfully completed OperatorUpdate");
                    Ok(())
                })
        })
        .then(|res: Result<(), Error>| {
            if let Err(e) = res {
                error!("Failed to perform operator checkin with {:?}", e);
            }
            Ok(())
        });

    Arbiter::spawn(res);
}

/// Allows for online updating of the release feed, note that this not run
/// on every device startup meaning just editing it the config is not sufficient
fn handle_release_feed_update(val: Option<String>) {
    match (val, get_release_feed()) {
        (None, _) => {}
        (Some(_new_feed), Err(e)) => {
            error!("Failed to read current release feed! {:?}", e);
        }
        (Some(new_feed), Ok(old_feed)) => {
            // we parse rather than just matching on a ReleaseState enum because
            // that's the easiest way to get the Custom(val) variant to deserialize
            // since from_str is implemented in althea types to work well with that
            // case, serde can't handle it well in the general case for various reasons
            if let Ok(new_feed) = new_feed.parse() {
                if new_feed != old_feed {
                    if let Err(e) = set_release_feed(new_feed) {
                        error!("Failed to set new release feed! {:?}", e);
                    }
                }
            }
        }
    }
}

/// Merges an arbitrary settings string, after first filtering for several
/// forbidden values
fn merge_settings_safely(new_settings: Value) {
    trace!("Got new settings from server {:?}", new_settings);
    // merge in arbitrary setting change string if it's not blank
    if new_settings != "" {
        if let Value::Object(map) = new_settings.clone() {
            let contains_forbidden_key = contains_forbidden_key(map, &FORBIDDEN_MERGE_VALUES);
            if !contains_forbidden_key {
                match SETTING.merge(new_settings.clone()) {
                    Ok(_) => trace!("Merged new settings successfully {:?}", new_settings),
                    Err(e) => error!(
                        "Failed to merge OperatorUpdate settings {:?} {:?}",
                        new_settings, e
                    ),
                }
            } else {
                info!("Merge Json contains forbidden key! {:?}", new_settings);
            }
        }
    }
}

/// Recursively traverses down a json object looking for items in the
/// forbidden keys list
fn contains_forbidden_key(map: Map<String, Value>, forbidden_values: &[&str]) -> bool {
    // check if any top level keys are forbidden
    for item in forbidden_values.iter() {
        println!("Checking key {} versus {:?}", item, map);
        if map.contains_key(*item) {
            return true;
        }
    }
    // bfs for subkeys that are forbidden
    let mut results: Vec<bool> = Vec::new();
    for (_name, new_obj) in map.iter() {
        if let Value::Object(new_map) = new_obj {
            results.push(contains_forbidden_key(new_map.clone(), forbidden_values));
        }
    }
    // look over all the results, any true values
    // mean we end our check
    for result in results {
        if result {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORBIDDEN_MERGE_VALUES: [&str; 2] = ["test_key", "other_test_key"];

    #[test]
    fn test_contains_key() {
        // exact key match should fail
        let object = json!({"localization": { "wyre_enabled": true, "wyre_account_id": "test_key", "test_key": false}});
        if let Value::Object(map) = object {
            assert!(contains_forbidden_key(map, &FORBIDDEN_MERGE_VALUES));
        } else {
            panic!("Not a json map!");
        }

        // slightly modified key should not match
        let object = json!({"localization": { "wyre_enabled": true, "wyre_account_id": "test_key", "test_key1": false}});
        if let Value::Object(map) = object {
            assert!(!contains_forbidden_key(map, &FORBIDDEN_MERGE_VALUES));
        } else {
            panic!("Not a json map!");
        }
    }
}
