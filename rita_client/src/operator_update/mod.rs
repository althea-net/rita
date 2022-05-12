//! This module is responsible for checking in with the operator server and getting updated local settings
pub mod updater;

use crate::dashboard::system_chain::set_system_blockchain;
use crate::dashboard::wifi::reset_wifi_pass;
use crate::rita_loop::is_gateway_client;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::set_router_update_instruction;
use althea_kernel_interface::hardware_info::get_hardware_info;
use althea_types::get_sequence_num;
use althea_types::ContactStorage;
use althea_types::ContactType;
use althea_types::HardwareInfo;
use althea_types::OperatorAction;
use althea_types::OperatorCheckinMessage;
use althea_types::OperatorUpdateMessage;
use num256::Uint256;
use rita_common::rita_loop::is_gateway;
use rita_common::tunnel_manager::neighbor_status::get_neighbor_status;
use rita_common::tunnel_manager::shaping::flag_reset_shaper;
use rita_common::utils::option_convert;
use rita_common::KI;
use serde_json::Map;
use serde_json::Value;
use settings::client::RitaClientSettings;
use settings::network::NetworkSettings;
use settings::payment::PaymentSettings;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use updater::update_system;

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
    /// stores the startup time for Rita, used to compute uptime
    static ref RITA_UPTIME: Instant = Instant::now();
    /// a timer of when we last ran an operator update, used to
    /// keep from running updates too often
    static ref OPERATOR_UPDATE: Arc<RwLock<Instant>> =
        Arc::new(RwLock::new(Instant::now()));
}

/// Perform operator updates every UPDATE_FREQUENCY seconds,
/// even if we are called more often than that
const UPDATE_FREQUENCY: Duration = Duration::from_secs(60);

/// How long we wait for a response from the server
/// this value must be less than or equal to the CLIENT_LOOP_SPEED
/// in the rita_client loop
pub const OPERATOR_UPDATE_TIMEOUT: Duration = CLIENT_LOOP_TIMEOUT;

pub struct Update;

pub async fn operator_update() {
    let operator_update = &mut *OPERATOR_UPDATE.write().unwrap();
    let time_elapsed = Instant::now().checked_duration_since(*operator_update);
    if time_elapsed.is_some() && time_elapsed.unwrap() > UPDATE_FREQUENCY {
        checkin().await;
        *operator_update = Instant::now();
    }
}

/// Checks in with the operator server
async fn checkin() {
    let url: &str;
    if cfg!(feature = "dev_env") {
        url = "http://0.0.0.0:8080/checkin";
    } else if cfg!(feature = "operator_debug") {
        url = "http://192.168.10.2:8080/checkin";
    } else {
        url = "https://operator.althea.net:8080/checkin";
    }

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

    // disable hardware info sending if logging is disabled
    let hardware_info = match logging_enabled {
        true => match get_hardware_info(rita_client.network.device) {
            Ok(info) => Some(info),
            Err(e) => {
                error!("Failed to get hardware info with {:?}", e);
                None
            }
        },
        false => None,
    };

    hardware_info_logs(&hardware_info);

    let client = awc::Client::default();
    let response = client
        .post(url)
        .timeout(OPERATOR_UPDATE_TIMEOUT)
        .send_json(&OperatorCheckinMessage {
            id,
            operator_address,
            system_chain,
            neighbor_info: Some(neighbor_info),
            contact_info,
            install_details,
            billing_details,
            hardware_info,
            user_bandwidth_limit,
            rita_uptime: RITA_UPTIME.elapsed(),
        })
        .await;

    let response = match response {
        Ok(mut response) => {
            trace!("Response is {:?}", response.status());
            trace!("Response is {:?}", response.headers());
            response.json().await
        }
        Err(e) => {
            error!("Failed to perform operator checkin with {:?}", e);
            return;
        }
    };

    let new_settings: OperatorUpdateMessage = match response {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to perform operator checkin with {:?}", e);
            return;
        }
    };

    let mut rita_client = settings::get_rita_client();

    let update = check_contacts_update(
        rita_client.exit_client.contact_info.clone(),
        new_settings.contact_info.clone(),
    );
    if update {
        rita_client.exit_client.contact_info = option_convert(new_settings.contact_info.clone());
    }

    let network = rita_client.network.clone();
    trace!("Updating from operator settings");
    let payment = update_payment_settings(
        rita_client.payment,
        use_operator_price,
        is_gateway,
        new_settings.clone(),
    );
    rita_client.payment = payment;
    trace!("Done with payment");

    let mut operator = rita_client.operator;
    let new_operator_fee = Uint256::from(new_settings.operator_fee);
    operator.operator_fee = new_operator_fee;
    operator.installation_details = None;
    rita_client.operator = operator;
    merge_settings_safely(new_settings.merge_json.clone());

    // Every tick, update the local router update instructions
    let update_instructions = match (
        new_settings.local_update_instruction.clone(),
        new_settings.local_update_instruction_v2.clone(),
    ) {
        (None, None) => None,
        (Some(legacy), None) => Some(legacy.into()),
        (_, Some(new)) => Some(new),
    };
    set_router_update_instruction(update_instructions);

    perform_operator_update(new_settings, rita_client, network)
}

/// logs some hardware info that may help debug this router
fn hardware_info_logs(info: &Option<HardwareInfo>) {
    if let Some(info) = info {
        info!(
            "HardwareInfo: Allocated memory {}/{}",
            info.allocated_memory, info.system_memory
        );
        info!(
            "HardwareInfo: 15 minute load average {}",
            info.load_avg_fifteen_minute
        );
        info!("HardwareInfo: logical cores {}", info.logical_processors);
        info!("HardwareInfo: model {}", info.model);
        info!("HardwareInfo: uptime {}", info.system_uptime.as_secs());
        let mut total_wifi_clients = 0;
        for wifi in info.wifi_devices.iter() {
            for _ in wifi.station_data.iter() {
                total_wifi_clients += 1;
            }
        }
        info!("HardwareInfo: total wifi clients {}", total_wifi_clients);
        info!(
            "HardwareInfo: Kernel version {}",
            info.system_kernel_version,
        );
    }
}

/// checks the operatoraction and performs it, if any.
fn perform_operator_update(
    new_settings: OperatorUpdateMessage,
    mut rita_client: RitaClientSettings,
    mut network: NetworkSettings,
) {
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
        Some(OperatorAction::UpdateV2 { instruction }) => {
            info!(
                "Received an update command from op tools! The instruction is {:?}",
                instruction
            );
            let res = update_system(instruction);
            info!("Update command result is {:?}", res);
        }
        Some(OperatorAction::Update { instruction }) => {
            info!(
                "Received a legacy update command from op tools! The instruction is {:?}",
                instruction
            );
            let res = update_system(instruction.into());
            info!("Update command result is {:?}", res);
        }
        Some(OperatorAction::SetMinGas { new_min_gas }) => {
            info!(
                "Updated min gas from {} to {}",
                rita_client.payment.min_gas, new_min_gas
            );
            rita_client.payment.min_gas = new_min_gas;
        }
        None => {}
    }
    network.shaper_settings = new_settings.shaper_settings;
    rita_client.network = network;
    settings::set_rita_client(rita_client);
    trace!("Successfully completed OperatorUpdate");
}

/// Creates a payment settings from OperatorUpdateMessage to be returned and applied
fn update_payment_settings(
    mut payment: PaymentSettings,
    use_operator_price: bool,
    is_gateway: bool,
    new_settings: OperatorUpdateMessage,
) -> PaymentSettings {
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
    payment
}

/// Returns true if the contact info sent through OperatorUpdateMessage have been more
/// recently updated than the router's current contact info
fn check_contacts_update(current: Option<ContactStorage>, incoming: Option<ContactType>) -> bool {
    // the current sequence number to check the update against
    let current_sequence = match current {
        Some(storage) => get_sequence_num(storage),
        None => 0,
    };
    if let Some(info) = incoming {
        // the incoming sequence number
        let seq = match info {
            althea_types::ContactType::Phone {
                number: _,
                sequence_number,
            } => sequence_number,
            althea_types::ContactType::Email {
                email: _,
                sequence_number,
            } => sequence_number,
            althea_types::ContactType::Both {
                number: _,
                email: _,
                sequence_number,
            } => sequence_number,
            althea_types::ContactType::Bad {
                invalid_number: _,
                invalid_email: _,
                sequence_number,
            } => sequence_number,
        };
        if seq.unwrap_or(0) > current_sequence {
            return true;
        }
        // else the existing config is more recent, so do not update
        return false;
    }
    false
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
