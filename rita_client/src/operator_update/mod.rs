//! This module is responsible for checking in with the operator server and getting updated local settings
pub mod updater;

use crate::dashboard::system_chain::set_system_blockchain;
use crate::dashboard::wifi::reset_wifi_pass;
use crate::rita_loop::is_gateway_client;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::set_router_update_instruction;
use althea_kernel_interface::opkg_feeds::CUSTOMFEEDS;
use rita_common::rita_loop::is_gateway;
use rita_common::tunnel_manager::neighbor_status::get_neighbor_status;
use rita_common::tunnel_manager::shaping::flag_reset_shaper;
use rita_common::utils::option_convert;
use updater::update_rita;

use actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use actix_web::Error;
use actix_web::{client, HttpMessage};
use althea_kernel_interface::hardware_info::get_hardware_info;
use althea_kernel_interface::opkg_feeds::get_release_feed;
use althea_kernel_interface::opkg_feeds::set_release_feed;

use althea_types::OperatorAction;
use althea_types::OperatorCheckinMessage;
use althea_types::OperatorUpdateMessage;
use futures01::Future;
use num256::Uint256;
use rita_common::KI;
use serde_json::Map;
use serde_json::Value;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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
pub struct UptimeStruct {
    pub prev_time: Duration,
}
impl Default for UptimeStruct {
    fn default() -> Self {
        UptimeStruct {
            prev_time: Duration::new(0, 0),
        }
    }
}
impl UptimeStruct {
    pub fn new() -> UptimeStruct {
        UptimeStruct {
            prev_time: Duration::new(0, 0),
        }
    }
    pub fn time_elapsed(&mut self, rita_uptime: &Instant) -> Duration {
        let cur_time = rita_uptime.elapsed();
        if cur_time.as_secs() < self.prev_time.as_secs() {
            Duration::new(0, 0)
        } else {
            self.prev_time = cur_time;
            cur_time
        }
    }
}

lazy_static! {
    pub static ref RITA_UPTIME: Instant = Instant::now();
    pub static ref TIME_PASSED: Arc<RwLock<UptimeStruct>> =
        Arc::new(RwLock::new(UptimeStruct::new()));
}

/// Perform operator updates every UPDATE_FREQUENCY seconds,
/// even if we are called more often than that
const UPDATE_FREQUENCY: Duration = Duration::from_secs(60);

pub struct OperatorUpdate {
    last_update: Instant,
}

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
        OperatorUpdate {
            last_update: Instant::now(),
        }
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
        let time_elapsed = Instant::now().checked_duration_since(self.last_update);
        if time_elapsed.is_some() && time_elapsed.unwrap() > UPDATE_FREQUENCY {
            checkin();
            self.last_update = Instant::now();
        }
    }
}

/// Checks in with the operator server
fn checkin() {
    #[cfg(not(feature = "operator_debug"))]
    let url = "https://operator.althea.net:8080/checkin";
    #[cfg(feature = "operator_debug")]
    let url = "http://192.168.10.2:8080/checkin";

    let rita_client = settings::get_rita_client();
    let id = rita_client.get_identity().unwrap();
    let logging_enabled = rita_client.log.enabled;
    let operator_settings = rita_client.operator;
    let system_chain = rita_client.payment.system_chain;
    let operator_address = operator_settings.operator_address;
    let use_operator_price =
        operator_settings.use_operator_price || operator_settings.force_use_operator_price;
    // a node is logically a gateway from a users perspective if it is directly connected to the
    // exit as a mesh client, even if the is_gateway var mostly governs things related to WAN use.
    // So we accept either of these conditions being true.
    let is_gateway = is_gateway() || is_gateway_client();

    let contact_info = option_convert(rita_client.exit_client.contact_info.clone());
    let install_details = operator_settings.installation_details.clone();
    let billing_details = operator_settings.billing_details;
    let user_bandwidth_limit = rita_client.network.user_bandwidth_limit;

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

    let status = get_neighbor_status();
    let mut neighbor_info = Vec::new();
    for (_, status) in status {
        neighbor_info.push(status);
    }

    let hardware_info = match get_hardware_info(rita_client.network.device) {
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
            user_bandwidth_limit,
            rita_uptime: TIME_PASSED.write().unwrap().time_elapsed(&RITA_UPTIME),
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
                    let mut rita_client = settings::get_rita_client();

                    let mut network = rita_client.network;
                    trace!("Updating from operator settings");
                    let mut payment = rita_client.payment;

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
                    rita_client.payment = payment;
                    trace!("Done with payment");

                    let mut operator = rita_client.operator;
                    let new_operator_fee = Uint256::from(new_settings.operator_fee);
                    operator.operator_fee = new_operator_fee;
                    rita_client.operator = operator;

                    merge_settings_safely(new_settings.merge_json);

                    //Every tick, update the local router update instructions
                    set_router_update_instruction(new_settings.local_update_instruction);

                    match new_settings.operator_action {
                        Some(OperatorAction::ResetShaper) => flag_reset_shaper(),
                        Some(OperatorAction::Reboot) => {
                            let _res = KI.run_command("reboot", &[]);
                        }
                        Some(OperatorAction::ResetRouterPassword) => {
                            network.rita_dashboard_password = None;
                        }
                        Some(OperatorAction::ResetWiFiPassword) => {
                            let _res = reset_wifi_pass();
                        }
                        Some(OperatorAction::ChangeOperatorAddress { new_address }) => {
                            rita_client.operator.operator_address = new_address;
                        }
                        Some(OperatorAction::Update { instruction }) => {
                            info!(
                                "Received an update command from op tools! The instruction is {:?}",
                                instruction
                            );
                            let _res = update_rita(instruction);
                        }
                        Some(OperatorAction::ChangeReleaseFeedAndUpdate { feed: _ }) => {}
                        None => {}
                    }

                    network.shaper_settings = new_settings.shaper_settings;
                    rita_client.network = network;

                    settings::set_rita_client(rita_client);
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
    match (val, get_release_feed(CUSTOMFEEDS)) {
        (None, _) => {}
        (Some(new_feed), Err(_)) => {
            if let Err(e) = set_release_feed(&new_feed, CUSTOMFEEDS) {
                error!("Failed to set new release feed! {:?}", e);
            }
        }
        (Some(new_feed), Ok(old_feed)) => {
            if !old_feed.contains(&new_feed) {
                if let Err(e) = set_release_feed(&new_feed, CUSTOMFEEDS) {
                    error!("Failed to set new release feed! {:?}", e);
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
                match settings::get_rita_client().merge(new_settings.clone()) {
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
    use serde_json::json;

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
#[test]
fn test_rita_uptime() {
    // exact key match should fail
    let uptime = TIME_PASSED.read().unwrap();
    let time = uptime.prev_time;
    println!("Time: {}", time.as_secs());
}
