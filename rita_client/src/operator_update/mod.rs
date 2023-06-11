//! This module is responsible for checking in with the operator server and getting updated local settings
pub mod update_loop;
pub mod updater;
extern crate openssh_keys;
use crate::dashboard::system_chain::set_system_blockchain;
use crate::exit_manager::{get_client_pub_ipv6, get_selected_exit_ip};
use crate::rita_loop::is_gateway_client;
use crate::{
    extend_hardware_info, reset_wifi_pass, set_router_update_instruction, set_wifi_multi_internal,
};
use althea_kernel_interface::hardware_info::get_hardware_info;
use althea_types::get_sequence_num;
use althea_types::{
    AuthorizedKeys, BillingDetails, ContactStorage, ContactType, CurExitInfo, ExitConnection,
    HardwareInfo, OperatorAction, OperatorCheckinMessage, OperatorUpdateMessage, UsageHour,
    UsageTracker,
};
use num256::Uint256;
use rita_common::rita_loop::is_gateway;
use rita_common::tunnel_manager::neighbor_status::get_neighbor_status;
use rita_common::tunnel_manager::shaping::flag_reset_shaper;
use rita_common::usage_tracker::UsageType::{Client, Relay};
use rita_common::usage_tracker::{get_current_hour, get_usage_data};
use rita_common::utils::option_convert;
use rita_common::DROPBEAR_AUTHORIZED_KEYS;
use rita_common::KI;
use serde_json::Map;
use serde_json::Value;
use settings::client::RitaClientSettings;
use settings::network::NetworkSettings;
use settings::payment::PaymentSettings;
use std::collections::{HashSet, VecDeque};
use std::fs::{remove_file, rename, File};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
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
}

/// Perform operator updates every UPDATE_FREQUENCY seconds,
const UPDATE_FREQUENCY: Duration = Duration::from_secs(60);

/// How long we wait for a response from the server
/// this value must be less than or equal to the UPDATE_FREQUENCY
/// in the rita_client loop
pub const OPERATOR_UPDATE_TIMEOUT: Duration = UPDATE_FREQUENCY;

/// Checks in with the operator server
pub async fn operator_update(ops_last_seen_usage_hour: Option<u64>) -> u64 {
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
    let operator_settings = rita_client.operator.clone();
    let system_chain = rita_client.payment.system_chain;
    let operator_address = operator_settings.operator_address;
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
        return 0;
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
        true => match get_hardware_info(rita_client.network.device.clone()) {
            Ok(info) => Some(extend_hardware_info(info)),
            Err(e) => {
                error!("Failed to get hardware info with {:?}", e);
                None
            }
        },
        false => None,
    };

    hardware_info_logs(&hardware_info);

    // Get current exit info
    let cur_cluster = rita_client.exit_client.current_exit.clone();
    let cur_exit = Some(CurExitInfo {
        cluster_name: cur_cluster.clone(),
        // Hopefully ops fills this in
        instance_name: None,
        instance_ip: match cur_cluster {
            Some(a) => get_selected_exit_ip(a),
            None => None,
        },
    });

    let current_hour = match get_current_hour() {
        Ok(hour) => hour,
        Err(e) => {
            error!("System time is set earlier than unix epoch {:?}", e);
            return 0;
        }
    };
    let last_seen_hour = ops_last_seen_usage_hour.unwrap_or(0);
    let mut hours_to_send: u64 = 0;
    // first check whats the last saved hr, send everything from that hr on
    // but, we need to save a var of the last x hrs not seen, and load that up with the next checkin cycle if >0.
    if current_hour - last_seen_hour > 0 {
        hours_to_send = current_hour - last_seen_hour;
    }
    let mut usage_tracker_data: Option<UsageTracker> = None;
    // only deal with this if we actually do need to send some hours
    // if ops_last_seen_usage_hour is a None the thread has restarted and we are waiting for ops to tell us how much
    // data we need to send, which will be populated with the next checkin cycle
    if hours_to_send != 0 && ops_last_seen_usage_hour.is_some() {
        let mut usage_data_client = get_usage_data(Client);
        let mut usage_data_relay = get_usage_data(Relay);
        let mut new_client_data: VecDeque<UsageHour> = VecDeque::new();
        let mut new_relay_data: VecDeque<UsageHour> = VecDeque::new();
        for _hour in 0..hours_to_send {
            // pop front, add to front of new vecdeque if exists.
            while let Some(data) = usage_data_client.pop_front() {
                if data.index > last_seen_hour {
                    new_client_data.push_front(UsageHour {
                        up: data.up,
                        down: data.down,
                        price: data.price,
                        index: data.index,
                    });
                    break;
                }
            }

            // pop front, add to front of new vecdeque if exists.
            while let Some(data) = usage_data_relay.pop_front() {
                if data.index > last_seen_hour {
                    new_relay_data.push_front(UsageHour {
                        up: data.up,
                        down: data.down,
                        price: data.price,
                        index: data.index,
                    });
                    break;
                }
            }
        }
        usage_tracker_data = Some(UsageTracker {
            last_save_hour: current_hour,
            client_bandwidth: new_client_data,
            relay_bandwidth: new_relay_data,
        });
    }

    let exit_con = Some(ExitConnection {
        cur_exit,
        client_pub_ipv6: get_client_pub_ipv6(),
    });

    let client = awc::Client::default();
    let response = client
        .post(url)
        .timeout(OPERATOR_UPDATE_TIMEOUT)
        .send_json(&OperatorCheckinMessage {
            id,
            operator_address,
            system_chain,
            exit_con,
            neighbor_info,
            contact_info,
            install_details,
            billing_details,
            hardware_info,
            user_bandwidth_limit,
            rita_uptime: RITA_UPTIME.elapsed(),
            user_bandwidth_usage: usage_tracker_data,
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
            return 0;
        }
    };

    let new_settings: OperatorUpdateMessage = match response {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to perform operator checkin with {:?}", e);
            return 0;
        }
    };

    let mut rita_client = rita_client;

    let update = check_contacts_update(
        rita_client.exit_client.contact_info.clone(),
        new_settings.contact_info.clone(),
    );
    if update {
        rita_client.exit_client.contact_info = option_convert(new_settings.contact_info.clone());
    }

    let mut operator = rita_client.operator.clone();
    if check_billing_update(
        rita_client.operator.billing_details.clone(),
        new_settings.billing_details.clone(),
    ) {
        operator.billing_details = new_settings.billing_details.clone();
    }

    let use_operator_price = operator.use_operator_price || operator.force_use_operator_price;
    let current_operator_fee = operator_settings.operator_fee;
    let new_operator_fee = Uint256::from(new_settings.operator_fee);
    if use_operator_price || new_operator_fee > current_operator_fee {
        operator.operator_fee = new_operator_fee;
    }
    operator.installation_details = None;
    rita_client.operator = operator;

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

    // merge the new settings into the local settings
    merge_settings_safely(&mut rita_client, new_settings.merge_json.clone());

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
    perform_operator_update(new_settings.clone(), rita_client, network);
    // update our count of ops last seen if we have confirmation ops is up to date on usage data
    if new_settings.ops_last_seen_usage_hour == current_hour {
        info!("Confirmed ops has taken usage update for hour {current_hour}");
        current_hour
    } else {
        new_settings.ops_last_seen_usage_hour
    }
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
        Some(OperatorAction::SoftReboot) => {
            let args = vec!["restart"];
            if let Err(e) = KI.run_command("/etc/init.d/rita", &args) {
                error!("Unable to restart rita after opkg update: {}", e)
            }
        }
        Some(OperatorAction::ResetRouterPassword) => {
            network.rita_dashboard_password = None;
        }
        Some(OperatorAction::ResetWiFiPassword) => {
            let _res = reset_wifi_pass();
        }
        Some(OperatorAction::SetWifi { token }) => {
            info!("Received an action to set wifi info! {:?}", token);
            let res = set_wifi_multi_internal(token);
            info!(
                "Set wifi multi returned with {:?} with message {:?}",
                res.status(),
                res.body()
            );
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
        Some(OperatorAction::UpdateAuthorizedKeys {
            add_list,
            drop_list,
        }) => {
            let key_file = DROPBEAR_AUTHORIZED_KEYS;
            info!("Updating auth_keys {:?}", key_file);
            let res = update_authorized_keys(add_list, drop_list, key_file);
            info!("Update auth_keys result is  {:?}", res);
        }
        None => {}
    }
    network.shaper_settings = new_settings.shaper_settings;
    rita_client.network = network;
    settings::set_rita_client(rita_client);
    trace!("Successfully completed OperatorUpdate");
}

// cycles in/out ssh pubkeys for recovery access
fn update_authorized_keys(
    add_list: Vec<String>,
    drop_list: Vec<String>,
    keys_file: &str,
) -> Result<(), std::io::Error> {
    info!("Authorized keys update starting");

    let mut existing = HashSet::new();
    let auth_keys_file = File::open(keys_file);
    let mut write_data: Vec<String> = vec![];
    let temp_key_file = String::from("temp_authorized_keys");

    info!(
        "Authorized keys updates add {} remove {} pubkeys",
        add_list.len(),
        drop_list.len()
    );
    // collect any keys managed by dropbear already on the router
    match auth_keys_file {
        Ok(key_file_open) => {
            let buf_reader = BufReader::new(key_file_open);

            for line in buf_reader.lines() {
                match line {
                    Ok(line) => {
                        if let Ok(pubkey) = openssh_keys::PublicKey::parse(&line) {
                            info!("Authorized keys parse keys");
                            existing.insert(AuthorizedKeys {
                                key: pubkey.to_string(),
                                managed: true,
                                flush: false,
                            });
                        }
                    }
                    Err(e) => {
                        let _create_keys_file = File::create(keys_file)?;
                        warn!(
                            "Authorized keys did not exist, creating the file {:?} {:?}",
                            &keys_file, e
                        )
                    }
                }
            }
        }
        Err(e) => {
            let _create_keys_file = File::create(keys_file)?;
            warn!(
                "Authorized keys did not exist, creating the file {:?} {:?}",
                &keys_file, e
            )
        }
    };
    // parse/validate keys before being added
    for pubkey in add_list {
        if let Ok(pubkey) = openssh_keys::PublicKey::parse(&pubkey) {
            existing.insert(AuthorizedKeys {
                key: pubkey.to_string(),
                managed: true,
                flush: false,
            });
        } else {
            info!("Authorized keys failed to parse key {:?}", pubkey);
        }
    }
    // parse list for keys to remove, setting flush = true
    for pubkey in drop_list {
        existing.remove(&AuthorizedKeys {
            key: pubkey,
            managed: false,
            flush: true,
        });
    }

    // create and write to temporary file. temp file to protect from a partial writes to _keys_file_
    let updated_key_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temp_key_file)?;

    let metadata = updated_key_file.metadata();
    match metadata {
        Ok(metadata) => {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            if let Err(e) = updated_key_file.set_permissions(perms) {
                warn!("Authorized keys unable to set permissions {:?}", e);
            }
        }
        Err(e) => {
            warn!("Authorized keys unable to set permissions {:?}", e);
            return Ok(());
        }
    }

    for key in &existing {
        if !key.flush {
            write_data.push(key.key.to_string());
        }
    }

    // create string block to use a single write to temp file
    match write!(&updated_key_file, "{}", &write_data.join("\n")) {
        Ok(()) => info!("Authorized keys write success {:#?}", write_data),
        Err(e) => info!("Authorized keys write failed with {:?}", e),
    };

    // rename temp file
    if let Err(e) = rename(&temp_key_file, keys_file) {
        info!("Authorized keys rename failed with {:?}", e);
        remove_file(&temp_key_file)?
    } else {
        info!("Authorized keys rename success")
    };

    Ok(())
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

fn check_billing_update(current: Option<BillingDetails>, incoming: Option<BillingDetails>) -> bool {
    let current_sequence = match current {
        Some(details) => details.sequence_number,
        None => 0,
    };
    if let Some(details) = incoming {
        let seq = details.sequence_number;
        if seq > current_sequence {
            return true;
        }
        // else the existing config is more recent, so do not update
        return false;
    }
    false
}

/// Merges an arbitrary settings string, after first filtering for several
/// forbidden values
fn merge_settings_safely(client_settings: &mut RitaClientSettings, new_settings: Value) {
    trace!("Got new settings from server {:?}", new_settings);
    // merge in arbitrary setting change string if it's not blank
    if new_settings != "" {
        if let Value::Object(map) = new_settings.clone() {
            let contains_forbidden_key = contains_forbidden_key(map, &FORBIDDEN_MERGE_VALUES);
            if !contains_forbidden_key {
                match client_settings.merge(new_settings.clone()) {
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
    use std::{fs, io::Error, path::Path};

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
    fn touch_temp_file(file_name: &str) -> &str {
        let test_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_name);
        let operator_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL+UBakquB9rJ7tA2H+U43H/xNmpJiHpOkHGpVfFUXgP OPERATOR";
        writeln!(test_file.unwrap(), "{operator_key}").expect("setup failed to create temp file");
        operator_key
    }
    fn remove_temp_file(file_name: &str) -> Result<(), Error> {
        fs::remove_file(file_name)
    }
    fn parse_keys(file_name: &str) -> Vec<String> {
        let mut temp = Vec::new();
        let expected = File::open(file_name).unwrap();
        let reader = BufReader::new(expected);
        for key in reader.lines() {
            temp.push(key.unwrap());
        }
        temp
    }

    #[test]
    fn test_update_auth_keys() {
        let added_keys = vec![String::from("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFgFrnSm9MFS1zpHHvwtfLohjqtsK13NyL41g/zyIhK test@hawk-net")];
        let removed_keys = vec![];
        let key_file: &str = "authorized_keys";
        let operator_key = touch_temp_file(key_file);

        let _update = update_authorized_keys(added_keys.clone(), removed_keys, key_file);
        let result = parse_keys(key_file);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&added_keys[0]));
        assert!(result.contains(&operator_key.to_string()));
        remove_temp_file(key_file).unwrap();
    }

    #[test]
    fn test_update_auth_multiple_keys() {
        let added_keys = vec![String::from("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFgFrnSm9MFS1zpHHvwtfLohjqtsK13NyL41g/zyIhK test@hawk-net"),
               String::from("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVF1POOko4/fTE/SowsURSmd+kAUFDX6VPNqICJjn8eQk8FZ15WsZKfBdrGXLhl2+pxM66VWMUVRQOq84iSRVSVPA3abz0H7JYIGzO8psTweSZfK1jwHfKDGQA1h1aPuspnPrX7dyS1qLZf3YeVUUi+BFsW2gSiMadbS4zal2c2F1AG5Ezr3zcRVA8y3D0bZxScPAEX74AeTFcimHpHFyzDtUsRpf0uSEXZcMFqX5j4ETKlIs28k1v8LlhHo91IQYHEtbyi/I1M0axbF4VCz5JlcbAs9LUEJg8Kx8LxzJSeSJbxVwyk5WiEDwVsCL2MAtaOcJ+/FhxLb0ZEELAHnXFNSqmY8QoHeSdHrGP7FmVCBjRb/AhVUHYvsG94rO3Ij4H5XsbsQbP3AHVKbvf387WB53Wga7VrBXvRC9aDisetdP9+4/seVIBbOIePotaiHoTyS1cJ+Jg0PkKy96enqwMt9T1Wt8jURB+s/A/bDGHkjB3dxomuGxux8dD6UNX54M= test-rsa@hawk-net"),
        ];
        let removed_keys = vec![];
        let key_file: &str = "add_keys";

        let operator_key = touch_temp_file(key_file);

        let _update = update_authorized_keys(added_keys.clone(), removed_keys, key_file);
        let result = parse_keys(key_file);
        assert!(result.contains(&added_keys[0]));
        assert!(result.contains(&added_keys[1]));
        assert!(result.contains(&operator_key.to_string()));
        assert_eq!(result.len(), 3);
        remove_temp_file(key_file).unwrap();
    }

    #[test]
    fn test_update_auth_remove_keys() {
        let added_keys = vec![];
        let removed_keys = vec![
            String::from("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFgFrnSm9MFS1zpHHvwtfLohjqtsK13NyL41g/zyIhK test@hawk-net"),
            String::from("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVF1POOko4/fTE/SowsURSmd+kAUFDX6VPNqICJjn8eQk8FZ15WsZKfBdrGXLhl2+pxM66VWMUVRQOq84iSRVSVPA3abz0H7JYIGzO8psTweSZfK1jwHfKDGQA1h1aPuspnPrX7dyS1qLZf3YeVUUi+BFsW2gSiMadbS4zal2c2F1AG5Ezr3zcRVA8y3D0bZxScPAEX74AeTFcimHpHFyzDtUsRpf0uSEXZcMFqX5j4ETKlIs28k1v8LlhHo91IQYHEtbyi/I1M0axbF4VCz5JlcbAs9LUEJg8Kx8LxzJSeSJbxVwyk5WiEDwVsCL2MAtaOcJ+/FhxLb0ZEELAHnXFNSqmY8QoHeSdHrGP7FmVCBjRb/AhVUHYvsG94rO3Ij4H5XsbsQbP3AHVKbvf387WB53Wga7VrBXvRC9aDisetdP9+4/seVIBbOIePotaiHoTyS1cJ+Jg0PkKy96enqwMt9T1Wt8jURB+s/A/bDGHkjB3dxomuGxux8dD6UNX54M= test-rsa@hawk-net"),
        ];
        let key_file: &str = "auth_remove_keys";

        let operator_key = touch_temp_file(key_file);

        let _update = update_authorized_keys(added_keys, removed_keys, key_file);
        let result = parse_keys(key_file);
        assert!(result.contains(&operator_key.to_string()));

        assert_eq!(result.len(), 1);

        remove_temp_file(key_file).unwrap();
    }
    #[test]
    fn test_removing_existing_key() {
        let added_keys = vec![];
        let key_file: &str = "remove_keys";

        let operator_key = touch_temp_file(key_file);
        let removed_keys = vec![String::from(operator_key)];
        let _update = update_authorized_keys(added_keys, removed_keys.clone(), key_file);

        let result = parse_keys(key_file);
        for item in result {
            assert_eq!(item, removed_keys[0].to_string());
        }

        remove_temp_file(key_file).unwrap();
    }
    #[test]
    fn test_authorized_keys_create_if_missing() {
        let added_keys = vec![
            String::from("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFgFrnSm9MFS1zpHHvwtfLohjqtsK13NyL41g/zyIhK test@hawk-net ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVF1POOko4/fTE/SowsURSmd+kAUFDX6VPNqICJjn8eQk8FZ15WsZKfBdrGXLhl2+pxM66VWMUVRQOq84iSRVSVPA3abz0H7JYIGzO8psTweSZfK1jwHfKDGQA1h1aPuspnPrX7dyS1qLZf3YeVUUi+BFsW2gSiMadbS4zal2c2F1AG5Ezr3zcRVA8y3D0bZxScPAEX74AeTFcimHpHFyzDtUsRpf0uSEXZcMFqX5j4ETKlIs28k1v8LlhHo91IQYHEtbyi/I1M0axbF4VCz5JlcbAs9LUEJg8Kx8LxzJSeSJbxVwyk5WiEDwVsCL2MAtaOcJ+/FhxLb0ZEELAHnXFNSqmY8QoHeSdHrGP7FmVCBjRb/AhVUHYvsG94rO3Ij4H5XsbsQbP3AHVKbvf387WB53Wga7VrBXvRC9aDisetdP9+4/seVIBbOIePotaiHoTyS1cJ+Jg0PkKy96enqwMt9T1Wt8jURB+s/A/bDGHkjB3dxomuGxux8dD6UNX54M= test-rsa@hawk-net"),
        ];
        let removed_keys: Vec<String> = vec![];
        let key_file: &str = "create_keys_file";
        let _update = update_authorized_keys(added_keys, removed_keys, key_file);
        assert!(Path::new(key_file).exists());
    }
}
