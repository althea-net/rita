//! This module contains all the tools and functions that integrate with the clients database
//! for the exit, which is most exit logic in general. Keep in mind database connections are remote
//! and therefore synchronous database requests are quite expensive (on the order of tens of milliseconds)
use crate::database::geoip::get_gateway_ip_bulk;
use crate::database::geoip::get_gateway_ip_single;
use crate::database::geoip::verify_ip;
use crate::database::ipddr_assignment::display_hashset;
use crate::database::ipddr_assignment::DEFAULT_CLIENT_SUBNET_SIZE;
use crate::rita_loop::RitaExitData;
use crate::rita_loop::EXIT_INTERFACE;
use crate::rita_loop::EXIT_LOOP_TIMEOUT;
use crate::rita_loop::LEGACY_INTERFACE;
use crate::ClientListAnIpAssignmentMap;
use crate::RitaExitError;
use althea_kernel_interface::exit_server_tunnel::set_exit_wg_config;
use althea_kernel_interface::exit_server_tunnel::setup_individual_client_routes;
use althea_kernel_interface::exit_server_tunnel::teardown_individual_client_routes;
use althea_kernel_interface::setup_wg_if::get_last_active_handshake_time;
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
use settings::get_rita_exit;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

pub mod geoip;
pub mod ipddr_assignment;

/// one day in seconds
pub const ONE_DAY: i64 = 86400;

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
    // List of clients we see on wg_exit from previous tick. Used to check for new clients on the
    // interface
    pub wg_exit_clients: HashSet<WgKey>,
    // List of clients on wg_exit_v2 from previous tick
    pub wg_exit_v2_clients: HashSet<WgKey>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CurrentExitClientState {
    new_v2: HashSet<WgKey>,
    new_v1: HashSet<WgKey>,
    all_v2: HashSet<WgKey>,
    all_v1: HashSet<WgKey>,
}

/// Gets a complete list of clients from the database and transforms that list
/// into a single very long wg tunnel setup command which is then applied to the
/// wg_exit tunnel (or created if it's the first run). This is the offically supported
/// way to update live WireGuard tunnels and should not disrupt traffic
pub fn setup_clients(client_data: &mut RitaExitData) -> Result<(), Box<RitaExitError>> {
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
    let key_to_client_map: HashMap<WgKey, Identity> = HashMap::new();

    trace!(
        "got clients from db {:?} {:?}",
        clients_list,
        client_states.old_clients
    );

    for c in clients_list.iter() {
        match client_data.id_to_exit_client(*c) {
            Ok(a) => {
                if !wg_clients.insert(a) {
                    error!("Duplicate database entry! {}", c.wg_public_key);
                }
            }
            Err(e) => {
                error!(
                    "Unable to convert client to ExitClient! {} with error {}",
                    c.wg_public_key, e
                );
            }
        }
    }

    for c in geoip_blacklist.iter() {
        match client_data.id_to_exit_client(*c) {
            Ok(a) => {
                if !geoip_blacklist_map.insert(a) {
                    error!("Duplicate database entry! {}", c.wg_public_key);
                }
            }
            Err(e) => {
                error!(
                    "Unable to convert client to ExitClient! {} with error {}",
                    c.wg_public_key, e
                );
            }
        }
    }

    trace!("converted clients {:?}", wg_clients);

    // remove geoip blacklisted clients from wg clients
    let wg_clients: HashSet<ExitClient> = wg_clients
        .difference(&geoip_blacklist_map)
        .copied()
        .collect();

    // symetric difference is an iterator of all items in A but not in B
    // or in B but not in A, in short if there's any difference between the two
    // it must be nonzero, since all entires must be unique there can not be duplicates
    if wg_clients
        .symmetric_difference(&client_states.old_clients)
        .count()
        != 0
    {
        info!("Setting up configs for wg_exit and wg_exit_v2");
        // setup all the tunnels
        let exit_status = set_exit_wg_config(
            &wg_clients,
            settings::get_rita_exit().exit_network.wg_tunnel_port,
            &settings::get_rita_exit().network.wg_private_key_path,
            LEGACY_INTERFACE,
        );

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

        // Setup new tunnels
        let exit_status_new = set_exit_wg_config(
            &wg_clients,
            settings::get_rita_exit().exit_network.wg_v2_tunnel_port,
            &settings::get_rita_exit().network.wg_private_key_path,
            EXIT_INTERFACE,
        );

        match exit_status_new {
            Ok(()) => {
                trace!("Successfully setup Exit wg_exit_v2!");
            }
            Err(e) => warn!(
                "Error in Exit wg_exit_v2 setup {:?}, 
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

    // Setup ipv6 and v4 routes and rules for clients
    // We optimise by setting up routes/rules only for those routers we see a latest handshake value with.
    // 1.) Find handshakes on both interfaces
    // 2.) From these timestamps, determine if client is wg exit v1 or v2
    // 3.) Compare this to our datastore of previous clients we set up routes for
    // 4.) Set up routes for v2 or v1 based on this
    let new_wg_exit_clients_timestamps: HashMap<WgKey, SystemTime> =
        get_last_active_handshake_time(EXIT_INTERFACE)
            .expect("There should be a new wg_exit interface")
            .into_iter()
            .collect();
    let wg_exit_clients_timestamps: HashMap<WgKey, SystemTime> =
        get_last_active_handshake_time(LEGACY_INTERFACE)
            .expect("There should be a wg_exit interface")
            .into_iter()
            .collect();

    let client_list_for_setup: Vec<Identity> = key_to_client_map
        .clone()
        .into_iter()
        .filter_map(|(k, v)| {
            if new_wg_exit_clients_timestamps.contains_key(&k)
                || wg_exit_clients_timestamps.contains_key(&k)
            {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    let exit_settings = settings::get_rita_exit();
    let internal_ip_v4 = exit_settings.exit_network.internal_ipv4.internal_ip();
    let internal_netmask = exit_settings.exit_network.internal_ipv4.prefix();

    // Get all new clients that need rule setup for wg_exit_v2 and wg_exit respectively
    let changed_clients_return = find_changed_clients(
        client_states.clone(),
        new_wg_exit_clients_timestamps,
        wg_exit_clients_timestamps,
        client_list_for_setup,
    );

    // set previous tick states to current clients on wg interfaces
    client_states.wg_exit_v2_clients = changed_clients_return.all_v2;
    client_states.wg_exit_clients = changed_clients_return.all_v1;

    // setup wg_exit routes (downgrade from b20 -> 19 and new b19 routers)
    // note these are spot routes for routers still on beta19 by default
    // all traffic will go over wg_exit_v2
    for c_key in changed_clients_return.new_v1 {
        if let Some(c) = key_to_client_map.get(&c_key) {
            setup_individual_client_routes(
                match client_data.get_or_add_client_internal_ip(
                    *c,
                    internal_netmask,
                    internal_ip_v4,
                ) {
                    Ok(a) => std::net::IpAddr::V4(a),
                    Err(e) => {
                        error!(
                            "Received error while trying to retrieve client internal ip {}",
                            e
                        );
                        continue;
                    }
                },
                internal_ip_v4.into(),
                LEGACY_INTERFACE,
            );
        }
    }
    for c_key in changed_clients_return.new_v2 {
        if let Some(c) = key_to_client_map.get(&c_key) {
            teardown_individual_client_routes(
                match client_data.get_or_add_client_internal_ip(
                    *c,
                    internal_netmask,
                    internal_ip_v4,
                ) {
                    Ok(a) => std::net::IpAddr::V4(a),
                    Err(e) => {
                        error!(
                            "Received error while trying to retrieve client internal ip {}",
                            e
                        );
                        continue;
                    }
                },
            );
        }
    }

    client_data.set_setup_states(client_states);
    Ok(())
}

/// Find all clients that underwent transition from b19 -> 20 or vice versa and need updated rules and routes
/// This function returns (v2_clients to setup, v1_clients to setup, all_v2 clients, all_v1 clients)
fn find_changed_clients(
    client_states: ExitClientSetupStates,
    all_v2: HashMap<WgKey, SystemTime>,
    all_v1: HashMap<WgKey, SystemTime>,
    clients_list: Vec<Identity>,
) -> CurrentExitClientState {
    let mut v1_clients = HashSet::new();

    let mut v2_clients = HashSet::new();

    // Look at handshakes of each client to determine if they are a V1 or V2 client
    for c in clients_list {
        match get_client_interface(c, all_v2.clone(), all_v1.clone()) {
            Ok(interface) => {
                if interface == ClientInterfaceType::LegacyInterface {
                    v1_clients.insert(c.wg_public_key);
                } else if interface == ClientInterfaceType::ExitInterface {
                    v2_clients.insert(c.wg_public_key);
                }
            }
            Err(_) => {
                // There is no handshake on either wg_exit or wg_exit_v2, which can happen during a restart
                // in this case the client will not have an ipv6 route until they initiate a handshake again
                continue;
            }
        };
    }

    // All new client (that need rules setup) are Set{clients on wg interface} - Set{clients from previous tick}
    let new_v2 = &v2_clients - &client_states.wg_exit_v2_clients;
    let new_v1 = &v1_clients - &client_states.wg_exit_clients;

    CurrentExitClientState {
        new_v2,
        new_v1,
        all_v2: v2_clients,
        all_v1: v1_clients,
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ClientInterfaceType {
    LegacyInterface,
    ExitInterface,
}

pub fn get_client_interface(
    c: Identity,
    new_wg_exit_clients: HashMap<WgKey, SystemTime>,
    wg_exit_clients: HashMap<WgKey, SystemTime>,
) -> Result<ClientInterfaceType, Box<RitaExitError>> {
    trace!(
        "New list is {:?} \n Old list is {:?}",
        new_wg_exit_clients,
        wg_exit_clients
    );
    match (
        new_wg_exit_clients.get(&c.wg_public_key),
        wg_exit_clients.get(&c.wg_public_key),
    ) {
        (Some(_), None) => Ok(ClientInterfaceType::ExitInterface),
        (None, Some(_)) => Ok(ClientInterfaceType::LegacyInterface),
        (Some(new), Some(old)) => {
            if new > old {
                Ok(ClientInterfaceType::ExitInterface)
            } else {
                Ok(ClientInterfaceType::LegacyInterface)
            }
        }
        _ => {
            error!(
                "WG EXIT SETUP: Client {}, does not have handshake with any wg exit interface. Setting up routes on wg_exit",
                c.wg_public_key
            );
            Ok(ClientInterfaceType::LegacyInterface)
        }
    }
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
                            let flow_setup_required = match (
                                has_flow(ip, EXIT_INTERFACE),
                                has_flow(ip, LEGACY_INTERFACE),
                            ) {
                                (Ok(true), Ok(true))
                                | (Ok(true), Ok(false))
                                | (Ok(false), Ok(true)) => true,
                                // skip repeat setup
                                (Ok(false), Ok(false)) => false,
                                // in case of error do nothing better for the user not be enforced if we have an issue
                                (_, Err(e)) => {
                                    error!("Failed to get flow status with {:?}", e);
                                    false
                                }
                                (Err(e), _) => {
                                    error!("Failed to get flow status with {:?}", e);
                                    false
                                }
                            };
                            if flow_setup_required {
                                // create ipv4 and ipv6 flows, which are used to classify traffic, we can then limit the class specifically
                                if let Err(e) = create_flow_by_ip(LEGACY_INTERFACE, ip) {
                                    error!("Failed to setup flow for wg_exit {:?}", e);
                                }
                                if let Err(e) = create_flow_by_ip(EXIT_INTERFACE, ip) {
                                    error!("Failed to setup flow for wg_exit_v2 {:?}", e);
                                }
                                // gets the client ipv6 flow for this exit specifically
                                let client_ipv6 = client_data.get_or_add_client_ipv6(
                                    debt_entry.identity,
                                    settings::get_rita_exit().exit_network.get_ipv6_subnet_alt(),
                                    settings::get_rita_exit()
                                        .get_client_subnet_size()
                                        .unwrap_or(DEFAULT_CLIENT_SUBNET_SIZE),
                                );
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
                                LEGACY_INTERFACE,
                                free_tier_limit,
                                free_tier_limit,
                                ip,
                            ) {
                                error!("Unable to setup enforcement class on wg_exit: {:?}", e);
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
                            let action_required = match (
                                has_class(ip, LEGACY_INTERFACE),
                                has_class(ip, EXIT_INTERFACE),
                            ) {
                                (Ok(a), Ok(b)) => a | b,
                                (Ok(a), Err(_)) => a,
                                (Err(_), Ok(a)) => a,
                                (Err(ea), Err(eb)) => {
                                    error!("Failed to get qdisc class status from both exit interfaces {:?} {:?}", ea, eb);
                                    false
                                }
                            };
                            if action_required {
                                // Delete exisiting enforcement class, users who are not enforced are unclassifed becuase
                                // leaving the class in place reduces their speeds.
                                info!("Deleting enforcement classes for {}", client.public_key);
                                if let Err(e) = delete_class(LEGACY_INTERFACE, ip) {
                                    error!("Unable to delete class on wg_exit, is {} still enforced when they shouldnt be? {:?}", ip, e);
                                }

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
