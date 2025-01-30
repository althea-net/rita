//! This module contains all the tools and functions that integrate with the clients database
//! for the exit, which is most exit logic in general. Keep in mind database connections are remote
//! and therefore synchronous database requests are quite expensive (on the order of tens of milliseconds)
use crate::database::geoip::get_gateway_ip_bulk;
use crate::database::geoip::get_gateway_ip_single;
use crate::database::geoip::verify_ip;
use crate::database::ipddr_assignment::display_hashset;
use crate::rita_loop::RitaExitData;
use crate::rita_loop::EXIT_INTERFACE;
use crate::rita_loop::EXIT_LOOP_TIMEOUT;
use crate::setup_clients_snat;
use crate::ClientListAnIpAssignmentMap;
use crate::RitaExitError;
use althea_kernel_interface::exit_server_tunnel::set_exit_wg_config;
use althea_kernel_interface::exit_server_tunnel::teardown_snat;
use althea_kernel_interface::setup_wg_if::get_wg_exit_clients_offline;
use althea_kernel_interface::traffic_control::create_flow_by_ip;
use althea_kernel_interface::traffic_control::create_flow_by_ipv6;
use althea_kernel_interface::traffic_control::delete_class;
use althea_kernel_interface::traffic_control::has_class;
use althea_kernel_interface::traffic_control::has_flow;
use althea_kernel_interface::traffic_control::set_class_limit;
use althea_kernel_interface::ExitClient;
use althea_types::regions::Regions;
use althea_types::Identity;
use althea_types::WgKey;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitDetails, ExitState, ExitVerifMode};
use exit_trust_root::endpoints::RegisterRequest;
use exit_trust_root::endpoints::SubmitCodeRequest;
use ipnetwork::IpNetwork;
use phonenumber::PhoneNumber;
use rita_common::blockchain_oracle::calculate_close_thresh;
use rita_common::debt_keeper::get_debts_list;
use rita_common::debt_keeper::DebtAction;
use settings::exit::ExitIpv4RoutingSettings;
use settings::get_rita_exit;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

pub mod dualmap;
pub mod geoip;
pub mod ipddr_assignment;

/// one day in seconds
pub const ONE_DAY: i64 = 86400;

/// the time after which client tunnels will be torn down for inactivity in SNAT mdoe
/// (5 days in seconds)
pub const INACTIVE_CLIENT_THRESHOLD: u64 = 432000;

/// Timeout when requesting client registration
pub const CLIENT_REGISTER_TIMEOUT: Duration = Duration::from_secs(5);

pub fn get_exit_info() -> ExitDetails {
    let exit_settings = get_rita_exit();
    ExitDetails {
        server_internal_ip: exit_settings
            .exit_network
            .internal_ipv4
            .internal_ip()
            .into(),
        wg_exit_port: exit_settings.exit_network.wg_tunnel_port,
        exit_price: exit_settings.exit_network.exit_price,
        exit_currency: exit_settings.payment.system_chain,
        netmask: exit_settings.exit_network.internal_ipv4.prefix(),
        description: exit_settings.description,
        verif_mode: ExitVerifMode::Phone,
    }
}

/// Handles a new client registration api call. Performs a geoip lookup
/// on their registration ip to make sure that they are coming from a valid gateway
/// ip and then sends out an email of phone message
pub async fn signup_client(
    client: ExitClientIdentity,
    client_and_ip_info: Arc<Arc<RwLock<ClientListAnIpAssignmentMap>>>,
) -> Result<ExitState, Box<RitaExitError>> {
    let exit_settings = get_rita_exit();
    info!("got setup request {:?}", client);
    let gateway_ip = get_gateway_ip_single(client.global.mesh_ip)?;
    info!("got gateway ip {:?}", client);

    // dummy empty cache because signups don't happen often enough to bother using a locked unified cache
    // between the actix worker threads and the main thread. The main thread bulk checks all clients every
    // 5 seconds so caching goes a lot further there
    let mut cache = HashMap::new();
    let verify_status = verify_ip(&mut cache, gateway_ip).await?;
    info!("verified the ip country {:?}", client);

    // Is client requesting from a valid country? If so send registration request to ops
    if !verify_status {
        return Ok(ExitState::Denied {
            message: format!(
                "This exit only accepts connections from {}",
                display_hashset(&exit_settings.allowed_countries),
            ),
        });
    }

    let number = match client.clone().reg_details.phone {
        Some(n) => n,
        None => {
            return Err(Box::new(RitaExitError::MiscStringError(
                "Phone number is required for registration".to_string(),
            )));
        }
    };

    let phone_number: PhoneNumber = match number.parse() {
        Ok(p) => p,
        Err(e) => {
            return Err(Box::new(RitaExitError::MiscStringError(format!(
                "Failed to parse phone number with error {}",
                e
            ))));
        }
    };

    let exit_client = client_and_ip_info
        .write()
        .unwrap()
        .id_to_exit_client(client.global)?;
    // if there is a phone registration code, we should submit it for verification
    if let Some(code) = client.reg_details.phone_code.clone() {
        info!("Forwarding client verification request");
        forward_client_verify_request(client, phone_number, code).await?;
        Ok(ExitState::Registered {
            our_details: ExitClientDetails {
                client_internal_ip: exit_client.internal_ip,
                internet_ipv6_subnet: exit_client.internet_ipv6,
            },
            general_details: get_exit_info(),
            message: "Registration OK".to_string(),
            identity: Box::new(exit_settings.get_exit_identity()),
        })
    } else {
        info!("Forwarding client signup request");
        // if there is no phone registration code, we should submit the client for registration
        forward_client_signup_request(client, phone_number).await?;
        Ok(ExitState::Pending {
            message: "awaiting verification".to_string(),
        })
    }
}

pub async fn forward_client_verify_request(
    exit_client: ExitClientIdentity,
    phone_number: PhoneNumber,
    code: String,
) -> Result<(), RitaExitError> {
    let settings = get_rita_exit();
    let url = format!("{}/submit_code", settings.exit_root_url);

    info!(
        "About to submit client code {} with {}",
        exit_client.global, url
    );

    let client = awc::Client::default();
    let response = client
        .post(url)
        .timeout(CLIENT_REGISTER_TIMEOUT)
        .send_json(&SubmitCodeRequest {
            phone_number,
            identity: exit_client.global,
            code,
            contract: exit_client.reg_details.exit_database_contract,
        })
        .await;

    match response {
        Ok(v) => {
            trace!("Response is {:?}", v.status());
            trace!("Response is {:?}", v.headers());
            if v.status().is_success() {
                Ok(())
            } else {
                Err(RitaExitError::MiscStringError(v.status().to_string()))
            }
        }
        Err(e) => {
            error!("Failed to perform client registration with {:?}", e);
            Err(RitaExitError::MiscStringError(e.to_string()))
        }
    }
}

pub async fn forward_client_signup_request(
    exit_client: ExitClientIdentity,
    phone_number: PhoneNumber,
) -> Result<(), RitaExitError> {
    let settings = get_rita_exit();
    let url = format!("{}/register", settings.exit_root_url);

    info!(
        "About to request registration for client {} registration with {}",
        exit_client.global, url
    );

    let client = awc::Client::default();
    let response = client
        .post(url)
        .timeout(CLIENT_REGISTER_TIMEOUT)
        .send_json(&RegisterRequest { phone_number })
        .await;

    match response {
        Ok(v) => {
            trace!("Response is {:?}", v.status());
            trace!("Response is {:?}", v.headers());
            if v.status().is_success() {
                Ok(())
            } else {
                Err(RitaExitError::MiscStringError(v.status().to_string()))
            }
        }
        Err(e) => {
            error!("Failed to perform client registration with {:?}", e);
            Err(RitaExitError::MiscStringError(e.to_string()))
        }
    }
}

/// Every 5 seconds we validate all online clients to make sure that they are in the right region
/// we also do this in the client status requests but we want to handle the edge case of a modified
/// client that doesn't make status requests
pub async fn validate_clients_region(
    geoip_cache: &mut HashMap<IpAddr, Regions>,
    clients_list: Vec<Identity>,
) -> Result<Vec<Identity>, Box<RitaExitError>> {
    info!("Starting exit region validation");
    let start = Instant::now();

    let mut blacklist = Vec::new();

    trace!("Got clients list {:?}", clients_list);
    let mut ip_vec = Vec::new();
    let mut client_map = HashMap::new();
    for item in clients_list {
        client_map.insert(item.mesh_ip, item);
        ip_vec.push(item.mesh_ip);
    }
    let list = get_gateway_ip_bulk(ip_vec, EXIT_LOOP_TIMEOUT)?;
    for item in list.iter() {
        let res = verify_ip(geoip_cache, item.gateway_ip).await;
        match res {
            Ok(true) => trace!("{:?} is from an allowed ip", item),
            Ok(false) => {
                info!(
                    "Found unauthorized client already registered {}, removing",
                    client_map[&item.mesh_ip].wg_public_key
                );
                // get_gateway_ip_bulk can't add new entires to the list
                // therefore client_map is strictly a superset of ip_bulk results
                let client_to_deauth = &client_map[&item.mesh_ip];
                blacklist.push(*client_to_deauth);
            }
            Err(e) => warn!("Failed to verify ip with {:?}", e),
        }
    }

    info!(
        "Exit region validation completed in {}s {}ms",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis(),
    );
    Ok(blacklist)
}

#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct ExitClientSetupStates {
    // cache of clients from previous tick. Used to check if we need to
    // rerun some setup code
    pub old_clients: HashSet<ExitClient>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CurrentExitClientState {
    new: HashSet<WgKey>,
    all: HashSet<WgKey>,
}

/// Gets a complete list of clients from the database and transforms that list
/// into a single very long wg tunnel setup command which is then applied to the
/// wg_exit tunnel (or created if it's the first run). This is the offically supported
/// way to update live WireGuard tunnels and should not disrupt traffic
/// TODO: notes for teardown of geoip blacklisted clients- is that already happening?
pub fn setup_clients(client_data: &mut RitaExitData) -> Result<(), Box<RitaExitError>> {
    info!("Starting exit setup loop");
    let start = Instant::now();
    // Note, the data flow in this fuction is strage, we have getters and setters for all
    // data, but, some functions like id_to_exit_client will assign ip addresses to clients
    // thus modifying the internal state of the client_data object despite not obviously being
    // a setter. This is a holdover from the original design of the code and should be cleaned up with
    // more explicit ip allocation functions
    let clients_list = client_data.get_all_registered_clients();
    let mut client_states = client_data.get_setup_states();
    let geoip_blacklist = client_data.get_geoip_blacklist();

    // use hashset to ensure uniqueness and check for duplicate db entries
    let mut wg_clients = HashSet::new();
    let mut geoip_blacklist_map = HashSet::new();

    for c in clients_list.iter() {
        if !wg_clients.insert(*c) {
            error!("Duplicate database entry! {}", c.wg_public_key);
        }
    }

    for c in geoip_blacklist.iter() {
        if !geoip_blacklist_map.insert(*c) {
            error!("Duplicate database entry! {}", c.wg_public_key);
        }
    }

    trace!("converted clients {:?}", wg_clients);

    // remove geoip blacklisted clients from wg clients
    let wg_clients: HashSet<Identity> = wg_clients
        .difference(&geoip_blacklist_map)
        .copied()
        .collect();

    let mut wg_clients_exit = HashSet::new();
    // for each in wg_clients, try id_to_exit_client, if it fails, print an error and continue, else add to wg_clients_exit
    for c in wg_clients.iter() {
        match client_data.id_to_exit_client(*c) {
            Ok(c) => {
                wg_clients_exit.insert(c);
            }
            Err(e) => {
                error!(
                    "Unable to convert client to ExitClient! {} with error {}",
                    c.wg_public_key, e
                );
            }
        }
    }

    // now wg_clients contains the identities, and wg_clients_exit is the same list in ExitClient form

    // symmetric difference is an iterator of all items in A but not in B
    // or in B but not in A, in short if there's any difference between the two
    // it must be nonzero, since all entires must be unique there can not be duplicates
    if wg_clients_exit
        .symmetric_difference(&client_states.old_clients)
        .count()
        != 0
    {
        info!("Setting up configs for wg_exit");
        // setup all the tunnels
        let exit_status = set_exit_wg_config(
            &wg_clients_exit,
            settings::get_rita_exit().exit_network.wg_tunnel_port,
            &settings::get_rita_exit().network.wg_private_key_path,
            EXIT_INTERFACE,
        );

        // if we are in SNAT mode we need to setup iptables rules
        if let ExitIpv4RoutingSettings::SNAT { .. } = client_data.get_ipv4_nat_mode() {
            info!("Setting up rules for SNAT mode");
            setup_clients_snat(&wg_clients, client_data);
        }

        match exit_status {
            Ok(_a) => {
                trace!("Successfully setup Exit WG!");
            }
            Err(e) => warn!(
                "Error in Exit WG setup {:?}, 
                        this usually happens when a Rita service is 
                        trying to auto restart in the background",
                e
            ),
        }

        info!(
            "exit setup loop completed in {}s {}ms with {} clients and {} wg_clients",
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis(),
            clients_list.len(),
            wg_clients.len(),
        );
    }

    // set previous tick states to current clients on wg interfaces
    client_states.old_clients = wg_clients_exit;

    client_data.set_setup_states(client_states);
    Ok(())
}

/// Performs enforcement actions on clients by requesting a list of clients from debt keeper
/// if they are also a exit client they are limited to the free tier level of bandwidth by
/// setting the htb class they are assigned to to a maximum speed of the free tier value.
/// Unlike intermediary enforcement we do not need to subdivide the free tier to prevent
/// ourselves from exceeding the upstream free tier. As an exit we are the upstream.
pub fn enforce_exit_clients(client_data: &mut RitaExitData) -> Result<(), Box<RitaExitError>> {
    let start = Instant::now();
    let mut clients_by_id = HashMap::new();
    let free_tier_limit = settings::get_rita_exit().payment.free_tier_throughput;
    let close_threshold = calculate_close_thresh();
    for client_id in client_data.get_all_registered_clients() {
        if let Ok(exit_client) = client_data.id_to_exit_client(client_id) {
            clients_by_id.insert(client_id, exit_client);
        }
    }
    let list = get_debts_list();
    info!(
        "Exit enforcement finished grabbing data in {}s {}ms",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis(),
    );

    // build the new debt actions list and see if we need to do anything
    let old_debt_actions = client_data.get_debt_actions();
    let mut new_debt_actions = HashSet::new();
    for debt_entry in list.iter() {
        new_debt_actions.insert((
            debt_entry.identity,
            debt_entry.payment_details.action.clone(),
        ));
    }
    if new_debt_actions
        .symmetric_difference(&old_debt_actions)
        .count()
        == 0
    {
        info!("No change in enforcement list found, skipping tc calls");
        return Ok(());
    }

    for debt_entry in list.iter() {
        match clients_by_id.get(&debt_entry.identity) {
            Some(client) => {
                match client.internal_ip {
                    IpAddr::V4(ip) => {
                        if debt_entry.payment_details.action == DebtAction::SuspendTunnel {
                            info!("Exit is enforcing on {} because their debt of {} is greater than the limit of {}", client.public_key, debt_entry.payment_details.debt, close_threshold);
                            // setup flows this allows us to classify traffic we then limit the class, we delete the class as part of unenforcment but it's difficult to delete the flows
                            // so a user who has been enforced and unenforced while the exit has been online may already have them setup
                            let flow_setup_required = match has_flow(ip, EXIT_INTERFACE) {
                                Ok(true) => true,
                                Ok(false) => false,
                                Err(e) => {
                                    error!("Failed to get flow status with {:?}", e);
                                    false
                                }
                            };
                            if flow_setup_required {
                                // create ipv4 and ipv6 flows, which are used to classify traffic, we can then limit the class specifically
                                if let Err(e) = create_flow_by_ip(EXIT_INTERFACE, ip) {
                                    error!("Failed to setup flow for wg_exit_v2 {:?}", e);
                                }
                                // gets the client ipv6 flow for this exit specifically
                                let client_ipv6 =
                                    client_data.get_or_add_client_ipv6(debt_entry.identity);
                                if let Ok(Some(client_ipv6)) = client_ipv6 {
                                    if let Err(e) = create_flow_by_ipv6(
                                        EXIT_INTERFACE,
                                        IpNetwork::V6(client_ipv6),
                                        ip,
                                    ) {
                                        error!("Failed to setup ipv6 flow for wg_exit_v2 {:?}", e);
                                    }
                                }
                                info!(
                                    "Completed one time enforcement flow setup for {}",
                                    client.public_key
                                )
                            }

                            if let Err(e) = set_class_limit(
                                EXIT_INTERFACE,
                                free_tier_limit,
                                free_tier_limit,
                                ip,
                            ) {
                                error!("Unable to setup enforcement class on wg_exit_v2: {:?}", e);
                            }
                        } else {
                            let action_required = match has_class(ip, EXIT_INTERFACE) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("Failed to get qdisc class status from both exit interfaces {:?}", e);
                                    false
                                }
                            };
                            if action_required {
                                // Delete exisiting enforcement class, users who are not enforced are unclassifed becuase
                                // leaving the class in place reduces their speeds.
                                info!("Deleting enforcement classes for {}", client.public_key);
                                if let Err(e) = delete_class(EXIT_INTERFACE, ip) {
                                    error!("Unable to delete class on wg_exit_v2, is {} still enforced when they shouldnt be? {:?}", ip, e);
                                }
                            }
                        };
                    }
                    _ => warn!("Can't parse Ipv4Addr to create limit!"),
                };
            }
            None => {
                // this can happen when clients are connected but not registered
                // to this specific exit
                trace!(
                    "Could not find {} {} {} to suspend!",
                    debt_entry.identity.wg_public_key,
                    debt_entry.identity.eth_address,
                    debt_entry.identity.mesh_ip
                );
            }
        }
    }

    info!(
        "Exit enforcement completed in {}s {}ms",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis(),
    );
    client_data.set_debt_actions(new_debt_actions);
    Ok(())
}

/// Removes client ip assignments for clients that have not checked in for 1 hour
pub fn teardown_inactive_clients(client_data: &mut RitaExitData) {
    let inactive_list = client_data.get_inactive_list();
    // check for snat mode
    let ipv4_mode = client_data.get_ipv4_nat_mode();
    if let ExitIpv4RoutingSettings::SNAT { .. } = ipv4_mode {
    } else {
        return;
    }
    let ext_nic = &settings::get_rita_exit().network.external_nic.unwrap();
    let ext_assignments = client_data.get_external_ip_assignments();
    let int_assignments = client_data.get_internal_ip_assignments();
    // for each client in inactive, find their wg key from clientandipmap, then
    // remove their iptables rules if their last seen was over threshold
    for (client, last_seen) in inactive_list.iter() {
        if last_seen.elapsed().as_secs() > INACTIVE_CLIENT_THRESHOLD {
            try_teardown_client_snat(
                ext_assignments.clone(),
                int_assignments.clone(),
                *client,
                ext_nic,
            );
        }
    }
    let all_clients = client_data.get_all_registered_clients();
    // then, list any clients that have not had a wg handshake recently
    let wg_clients = get_wg_exit_clients_offline("wg_exit").unwrap();
    for wg_key in wg_clients.iter() {
        let client = all_clients
            .iter()
            .find(|c| *wg_key == c.wg_public_key)
            .expect("Client not found in database");
        try_teardown_client_snat(
            ext_assignments.clone(),
            int_assignments.clone(),
            *client,
            ext_nic,
        );
    }
}

fn try_teardown_client_snat(
    ext_assignments: HashMap<Ipv4Addr, HashSet<Identity>>,
    int_assignments: HashMap<Ipv4Addr, Identity>,
    client: Identity,
    ext_nic: &str,
) {
    // get this client's assigned external ip
    let external_ip: Vec<Ipv4Addr> = ext_assignments
        .iter()
        .filter(|(_k, v)| v.contains(&client))
        .map(|(&k, _v)| k)
        .collect();
    let internal_ip: Vec<Ipv4Addr> = int_assignments
        .iter()
        .filter(|(_k, v)| **v == client)
        .map(|(&k, _v)| k)
        .collect();
    match (external_ip.len().cmp(&1), internal_ip.len().cmp(&1)) {
        (std::cmp::Ordering::Greater, _) | (_, std::cmp::Ordering::Greater) => {
            error!(
            "Client {} has more than one internal or external ip assigned, this should not happen?",
            client
        );
        }
        (std::cmp::Ordering::Equal, std::cmp::Ordering::Equal) => {
            let external_ip = external_ip.first().unwrap();
            let internal_ip = internal_ip.first().unwrap();
            // remove the iptables rules for this client
            if let Err(e) = teardown_snat(*external_ip, *internal_ip, ext_nic) {
                error!(
                    "Failed to delete iptables rules for client {} with error {:?}",
                    client, e
                );
            }
        }
        (std::cmp::Ordering::Less, _) | (_, std::cmp::Ordering::Less) => {
            error!(
                "Client due for teardown {} has no external or internal ip assigned?",
                client
            );
        }
    }
}
