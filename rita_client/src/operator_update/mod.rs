//! This module is responsible for checking in with the operator server and getting updated local settings
pub mod tests;
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
use rita_common::usage_tracker::UsageHour as RCUsageHour;
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

lazy_static! {
    /// stores the startup time for Rita, used to compute uptime
    static ref RITA_UPTIME: Instant = Instant::now();
}

/// Operator update has a randomized exponential backoff, meaning if checkins fail
/// we will back off and try again after a longer interval
const TARGET_UPDATE_FREQUENCY: Duration = Duration::from_secs(5);
/// This is the cap for the exponential backoff, no matter how many consecutive checkins fail
/// we will not go above this amount of time
const UPDATE_FREQUENCY_CAP: Duration = Duration::from_secs(3600);

/// Checks in with the operator server
pub async fn operator_update(
    ops_last_seen_usage_hour: Option<u64>,
    timeout: Duration,
) -> Result<u64, ()> {
    let url: &str;
    if cfg!(feature = "dev_env") {
        url = "http://7.7.7.7:8080/checkin";
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
        // return ok as this is not an error case
        return Ok(ops_last_seen_usage_hour.unwrap_or_default());
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
            return Err(());
        }
    };
    let last_seen_hour = ops_last_seen_usage_hour.unwrap_or(0);
    // We check that the difference is >1 because we leave a 1 hour buffer to prevent from sending over an incomplete current hour
    let send_hours = current_hour - last_seen_hour > 1;
    let mut usage_tracker_data: Option<UsageTracker> = None;
    // if ops_last_seen_usage_hour is a None the thread has restarted and we are waiting for ops to tell us how much data we need to send,
    // which will be populated with the next checkin cycle. we only send 1 month at a time if ops is requesting the full usage history.
    if send_hours && ops_last_seen_usage_hour.is_some() {
        let usage_data_client = get_usage_data(Client);
        let usage_data_relay = get_usage_data(Relay);
        usage_tracker_data = process_usage_data(
            usage_data_client,
            usage_data_relay,
            last_seen_hour,
            current_hour,
        )
    }

    let exit_con = Some(ExitConnection {
        cur_exit,
        client_pub_ipv6: get_client_pub_ipv6(),
    });

    let client = awc::Client::default();
    let response = client
        .post(url)
        .timeout(timeout)
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
            return Err(());
        }
    };

    let new_settings: OperatorUpdateMessage = match response {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to perform operator checkin with {:?}", e);
            return Err(());
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
        Ok(current_hour)
    } else {
        Ok(new_settings.ops_last_seen_usage_hour)
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

/// Given a vecdeque of usage hours, add up to a month's worth of hours to a returned vecdeque
pub fn iterate_month_usage_data(mut data: VecDeque<RCUsageHour>) -> VecDeque<UsageHour> {
    // one month in hours
    let max_hour_iterations: u32 = 730;
    let mut client_iter = 0;
    let mut res = VecDeque::new();
    while let Some(hour) = data.pop_front() {
        // either we hit max iterations or we are on the second to last entry.
        res.push_back(UsageHour {
            up: hour.up,
            down: hour.down,
            price: hour.price,
            index: hour.index,
        });
        if client_iter >= max_hour_iterations || data.len() == 1 {
            break;
        }
        client_iter += 1;
    }
    res
}

/// Given our saved usage data and our last seen value, process the vecdeques so that we only
/// send to ops new data since last seen.
pub fn process_usage_data(
    mut usage_data_client: VecDeque<RCUsageHour>,
    mut usage_data_relay: VecDeque<RCUsageHour>,
    last_seen_hour: u64,
    current_hour: u64,
) -> Option<UsageTracker> {
    // sort client and relay data in case they have come out of order somehow. This sorts by index increasing so newest data at back
    usage_data_relay
        .make_contiguous()
        .sort_by(|a, b| a.index.cmp(&b.index));
    usage_data_client
        .make_contiguous()
        .sort_by(|a, b| a.index.cmp(&b.index));

    // so this spits out the index for where last seen is, or the index of the next highest hour(returned in an error).
    // we take the result -1 just in case, limit 0, since it's possible we might get back an index out of bounds at the back.
    let client_last_seen_index =
        match usage_data_client.binary_search_by(|x| x.index.cmp(&last_seen_hour)) {
            Ok(p) => p,
            Err(p) => p.saturating_sub(1),
        };
    let relay_last_seen_index =
        match usage_data_relay.binary_search_by(|x| x.index.cmp(&last_seen_hour)) {
            Ok(p) => p,
            Err(p) => p.saturating_sub(1),
        };
    // remove all data before the last seen index
    usage_data_client.drain(0..client_last_seen_index);
    usage_data_relay.drain(0..relay_last_seen_index);
    let new_client_data = iterate_month_usage_data(usage_data_client);
    let new_relay_data = iterate_month_usage_data(usage_data_relay);

    Some(UsageTracker {
        last_save_hour: current_hour,
        client_bandwidth: new_client_data,
        relay_bandwidth: new_relay_data,
    })
}
