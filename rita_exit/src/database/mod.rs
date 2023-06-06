//! This module contains all the tools and functions that integrate with the clients database
//! for the exit, which is most exit logic in general. Keep in mind database connections are remote
//! and therefore synchronous database requests are quite expensive (on the order of tens of milliseconds)

use crate::create_or_update_user_record;
use crate::database::database_tools::client_conflict;
use crate::database::database_tools::delete_client;
use crate::database::database_tools::get_client;
use crate::database::database_tools::get_database_connection;
use crate::database::database_tools::set_client_timestamp;
use crate::database::database_tools::update_client;
use crate::database::database_tools::verify_client;
use crate::database::database_tools::verify_db_client;
use crate::database::email::handle_email_registration;
use crate::database::geoip::get_country;
use crate::database::geoip::get_gateway_ip_bulk;
use crate::database::geoip::get_gateway_ip_single;
use crate::database::geoip::verify_ip;
use crate::database::sms::handle_sms_registration;
use crate::database::struct_tools::display_hashset;
use crate::database::struct_tools::to_exit_client;
use crate::database::struct_tools::to_identity;
use crate::database::struct_tools::verif_done;
use crate::get_client_ipv6;
use crate::rita_loop::EXIT_LOOP_TIMEOUT;
use crate::RitaExitError;
use crate::EXIT_ALLOWED_COUNTRIES;
use crate::EXIT_DESCRIPTION;
use crate::EXIT_NETWORK_SETTINGS;
use crate::EXIT_PRICE;
use crate::EXIT_SYSTEM_CHAIN;
use crate::EXIT_VERIF_SETTINGS;
use althea_kernel_interface::ExitClient;
use althea_types::Identity;
use althea_types::WgKey;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitDetails, ExitState, ExitVerifMode};
use diesel::prelude::PgConnection;
use exit_db::models::Client;
use rita_common::blockchain_oracle::calculate_close_thresh;
use rita_common::debt_keeper::get_debts_list;
use rita_common::debt_keeper::DebtAction;
use rita_common::utils::secs_since_unix_epoch;
use rita_common::KI;
use settings::exit::ExitVerifSettings;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

pub mod database_tools;
pub mod db_client;
pub mod email;
pub mod geoip;
pub mod sms;
pub mod struct_tools;

pub const LEGACY_INTERFACE: &str = "wg_exit";
pub const EXIT_INTERFACE: &str = "wg_exit_v2";

/// one day in seconds
pub const ONE_DAY: i64 = 86400;

pub fn get_exit_info() -> ExitDetails {
    const UPDATE_INTERVAL: Duration = Duration::from_secs(60);
    let last_update = EXIT_PRICE.read().unwrap().1;
    if Instant::now() > last_update && ((Instant::now() - last_update) > UPDATE_INTERVAL) {
        let mut exit_price = EXIT_PRICE.write().unwrap();
        let old_exit_price = exit_price.0;
        exit_price.0 = settings::get_rita_exit().exit_network.exit_price;
        exit_price.1 = Instant::now();
        info!(
            "Updated exit price from settings {} -> {}",
            exit_price.0, old_exit_price
        );
    }

    let exit_network = &EXIT_NETWORK_SETTINGS;
    let payment = *EXIT_SYSTEM_CHAIN;
    ExitDetails {
        server_internal_ip: exit_network.own_internal_ip.into(),
        wg_exit_port: exit_network.wg_tunnel_port,
        exit_price: EXIT_PRICE.read().unwrap().0,
        exit_currency: payment,
        netmask: exit_network.netmask,
        description: EXIT_DESCRIPTION.clone(),
        verif_mode: match EXIT_VERIF_SETTINGS.clone() {
            Some(ExitVerifSettings::Email(_mailer_settings)) => ExitVerifMode::Email,
            Some(ExitVerifSettings::Phone(_phone_settings)) => ExitVerifMode::Phone,
            None => ExitVerifMode::Off,
        },
    }
}

/// Handles a new client registration api call. Performs a geoip lookup
/// on their registration ip to make sure that they are coming from a valid gateway
/// ip and then sends out an email of phone message
pub async fn signup_client(
    client: ExitClientIdentity,
    from_ops: bool,
) -> Result<ExitState, Box<RitaExitError>> {
    info!("got setup request {:?}", client);
    let gateway_ip = get_gateway_ip_single(client.global.mesh_ip)?;
    info!("got gateway ip {:?}", client);

    let verify_status = verify_ip(gateway_ip)?;
    info!("verified the ip country {:?}", client);

    let user_country = get_country(gateway_ip)?;
    info!("got the country  {:?}", client);

    let conn = get_database_connection()?;

    info!(
        "Doing database work for {:?} in country {} with verify_status {}",
        client, user_country, verify_status
    );
    // check if we have any users with conflicting details

    match client_conflict(&client, &conn) {
        Ok(true) => {
            return Ok(ExitState::Denied {
                message: format!(
                    "Partially changed registration details! Please reset your router and re-register with all new details. Backup your key first! {}",
                    display_hashset(&EXIT_ALLOWED_COUNTRIES),
                ),
            })
        },
        Ok(false) => {}
        Err(e) => return Err(e),
    }

    let their_record = create_or_update_user_record(&conn, &client, user_country)?;

    // either update and grab an existing entry or create one
    match (verify_status, EXIT_VERIF_SETTINGS.clone(), from_ops) {
        (true, _, true) => {
            verify_client(&client, true, &conn)?;
            let client_internal_ip = match their_record.internal_ip.parse() {
                Ok(ip) => ip,
                Err(e) => return Err(Box::new(RitaExitError::AddrParseError(e))),
            };
            let client_internet_ipv6_subnet = get_client_ipv6(&their_record)?;
            Ok(ExitState::Registered {
                our_details: ExitClientDetails {
                    client_internal_ip,
                    internet_ipv6_subnet: client_internet_ipv6_subnet,
                },
                general_details: get_exit_info(),
                message: "Registration OK".to_string(),
            })
        }

        (true, None, false) => {
            verify_client(&client, true, &conn)?;
            let client_internal_ip = match their_record.internal_ip.parse() {
                Ok(ip) => ip,
                Err(e) => return Err(Box::new(RitaExitError::AddrParseError(e))),
            };
            let client_internet_ipv6_subnet = get_client_ipv6(&their_record)?;
            Ok(ExitState::Registered {
                our_details: ExitClientDetails {
                    client_internal_ip,
                    internet_ipv6_subnet: client_internet_ipv6_subnet,
                },
                general_details: get_exit_info(),
                message: "Registration OK".to_string(),
            })
        }
        (true, Some(ExitVerifSettings::Email(mailer)), false) => {
            handle_email_registration(&client, &their_record, &conn, mailer.email_cooldown as i64)
        }
        (true, Some(ExitVerifSettings::Phone(phone)), false) => {
            handle_sms_registration(client, their_record, phone.auth_api_key).await
        }

        (false, _, _) => Ok(ExitState::Denied {
            message: format!(
                "This exit only accepts connections from {}",
                display_hashset(&EXIT_ALLOWED_COUNTRIES),
            ),
        }),
    }
}

/// Gets the status of a client and updates it in the database
pub fn client_status(
    client: ExitClientIdentity,
    conn: &PgConnection,
) -> Result<ExitState, Box<RitaExitError>> {
    trace!("Checking if record exists for {:?}", client.global.mesh_ip);

    if let Some(their_record) = get_client(&client, conn)? {
        trace!("record exists, updating");

        if !verif_done(&their_record) {
            return Ok(ExitState::Pending {
                general_details: get_exit_info(),
                message: "awaiting email verification".to_string(),
                email_code: None,
                phone_code: None,
            });
        }

        let current_ip: IpAddr = match their_record.internal_ip.parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        };

        let current_internet_ipv6 = get_client_ipv6(&their_record)?;

        update_client(&client, &their_record, conn)?;

        Ok(ExitState::Registered {
            our_details: ExitClientDetails {
                client_internal_ip: current_ip,
                internet_ipv6_subnet: current_internet_ipv6,
            },
            general_details: get_exit_info(),
            message: "Registration OK".to_string(),
        })
    } else {
        error!("De-registering client! {:?}", client);
        Err(Box::new(RitaExitError::MiscStringError(
            "Status request for a client that isnt present, please register first!".to_string(),
        )))
    }
}

/// Every 5 seconds we validate all online clients to make sure that they are in the right region
/// we also do this in the client status requests but we want to handle the edge case of a modified
/// client that doesn't make status requests
pub fn validate_clients_region(
    clients_list: Vec<exit_db::models::Client>,
    conn: &PgConnection,
) -> Result<(), Box<RitaExitError>> {
    info!("Starting exit region validation");
    let start = Instant::now();

    trace!("Got clients list {:?}", clients_list);
    let mut ip_vec = Vec::new();
    let mut client_map = HashMap::new();
    for item in clients_list {
        // there's no need to check clients that aren't verified
        // as they are never setup
        if !item.verified {
            continue;
        }
        match item.mesh_ip.parse() {
            Ok(ip) => {
                client_map.insert(ip, item);
                ip_vec.push(ip);
            }
            Err(_e) => error!("Database entry with invalid mesh ip! {:?}", item),
        }
    }
    let list = get_gateway_ip_bulk(ip_vec, EXIT_LOOP_TIMEOUT)?;
    for item in list.iter() {
        let res = verify_ip(item.gateway_ip);
        match res {
            Ok(true) => trace!("{:?} is from an allowed ip", item),
            Ok(false) => {
                info!(
                    "Found unauthorized client already registered {}, removing",
                    client_map[&item.mesh_ip].wg_pubkey
                );
                // get_gateway_ip_bulk can't add new entires to the list
                // therefore client_map is strictly a superset of ip_bulk results
                let client_to_deauth = &client_map[&item.mesh_ip];
                if verify_db_client(client_to_deauth, false, conn).is_err() {
                    error!("Failed to deauth client {:?}", client_to_deauth);
                }
            }
            Err(e) => warn!("Failed to verify ip with {:?}", e),
        }
    }

    info!(
        "Exit region validation completed in {}s {}ms",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis(),
    );
    Ok(())
}

/// Iterates over the the database of clients, if a client's last_seen value
/// is zero it is set to now if a clients last_seen value is older than
/// the client timeout it is deleted
pub fn cleanup_exit_clients(
    clients_list: &[exit_db::models::Client],
    conn: &PgConnection,
) -> Result<(), Box<RitaExitError>> {
    trace!("Running exit client cleanup");
    let start = Instant::now();

    for client in clients_list.iter() {
        trace!("Checking client {:?}", client);
        match to_exit_client(client.clone()) {
            Ok(client_id) => {
                let time_delta = secs_since_unix_epoch() - client.last_seen;
                let entry_timeout = i64::from(settings::get_rita_exit().exit_network.entry_timeout);
                // entry timeout can be disabled, or longer than a day, but not shorter
                assert!(entry_timeout == 0 || entry_timeout >= ONE_DAY);
                if client.last_seen == 0 {
                    info!(
                        "{} does not have a last seen timestamp, adding one now ",
                        client.wg_pubkey
                    );
                    let res = set_client_timestamp(client_id, conn);
                    if res.is_err() {
                        warn!(
                            "Unable to update the client timestamp for {} with {:?}",
                            client.wg_pubkey, res
                        );
                    }
                }
                // a entry_timeout value of 0 means the feature is disabled
                else if entry_timeout != 0 && time_delta > entry_timeout {
                    warn!(
                        "{} has been inactive for too long, deleting! ",
                        client.wg_pubkey
                    );
                    let res = delete_client(client_id, conn);
                    if res.is_err() {
                        error!(
                            "Unable to remove inactive client {:?} with {:?}",
                            client, res
                        )
                    }
                }
            }
            Err(e) => error!("Invalid database entry! {:?}", e),
        }
    }

    info!(
        "Exit cleanup completed in {}s {}ms",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis(),
    );
    Ok(())
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
pub fn setup_clients(
    clients_list: &[exit_db::models::Client],
    client_states: ExitClientSetupStates,
) -> Result<ExitClientSetupStates, Box<RitaExitError>> {
    let mut client_states = client_states;
    let start = Instant::now();

    // use hashset to ensure uniqueness and check for duplicate db entries
    let mut wg_clients = HashSet::new();
    let mut key_to_client_map: HashMap<WgKey, Client> = HashMap::new();

    trace!(
        "got clients from db {:?} {:?}",
        clients_list,
        client_states.old_clients
    );

    for c in clients_list.iter() {
        match (c.verified, to_exit_client(c.clone())) {
            (true, Ok(exit_client_c)) => {
                if !wg_clients.insert(exit_client_c.clone()) {
                    error!("Duplicate database entry! {}", c.wg_pubkey);
                }
                key_to_client_map.insert(exit_client_c.public_key, c.clone());
            }
            (true, Err(e)) => warn!("Error converting {:?} to exit client {:?}", c, e),
            (false, _) => trace!("{:?} is not verified, not adding to wg_exit", c),
        }
    }

    trace!("converted clients {:?}", wg_clients);
    // symetric difference is an iterator of all items in A but not in B
    // or in B but not in A, in short if there's any difference between the two
    // it must be nonzero, since all entires must be unique there can not be duplicates
    if wg_clients
        .symmetric_difference(&client_states.old_clients)
        .count()
        != 0
    {
        info!("Setting up configs for wg_exit and {}", EXIT_INTERFACE);
        // setup all the tunnels
        let exit_status = KI.set_exit_wg_config(
            &wg_clients,
            settings::get_rita_exit().exit_network.wg_tunnel_port,
            &settings::get_rita_exit().exit_network.wg_private_key_path,
            "wg_exit",
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
        let exit_status_new = KI.set_exit_wg_config(
            &wg_clients,
            settings::get_rita_exit().exit_network.wg_v2_tunnel_port,
            &settings::get_rita_exit().network.wg_private_key_path,
            EXIT_INTERFACE,
        );

        match exit_status_new {
            Ok(()) => {
                trace!("Successfully setup Exit {}!", EXIT_INTERFACE);
            }
            Err(e) => warn!(
                "Error in Exit {} setup {:?}, 
                        this usually happens when a Rita service is 
                        trying to auto restart in the background",
                EXIT_INTERFACE, e
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
    let new_wg_exit_clients_timestamps: HashMap<WgKey, SystemTime> = KI
        .get_last_active_handshake_time(EXIT_INTERFACE)
        .expect("There should be a new wg_exit interface")
        .into_iter()
        .collect();
    let wg_exit_clients_timestamps: HashMap<WgKey, SystemTime> = KI
        .get_last_active_handshake_time(LEGACY_INTERFACE)
        .expect("There should be a wg_exit interface")
        .into_iter()
        .collect();

    let client_list_for_setup: Vec<Client> = key_to_client_map
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
    let internal_ip_v4 = exit_settings.exit_network.own_internal_ip;

    // Get all new clients that need rule setup for wg_exit_v2 and wg_exit respectively
    let changed_clients_return = find_changed_clients(
        client_states.clone(),
        new_wg_exit_clients_timestamps,
        wg_exit_clients_timestamps,
        &client_list_for_setup,
    );

    // set previous tick states to current clients on wg interfaces
    client_states.wg_exit_v2_clients = changed_clients_return.all_v2;
    client_states.wg_exit_clients = changed_clients_return.all_v1;

    // setup wg_exit routes (downgrade from b20 -> 19 and new b19 routers)
    // note these are spot routes for routers still on beta19 by default
    // all traffic will go over wg_exit_v2
    for c_key in changed_clients_return.new_v1 {
        if let Some(c) = key_to_client_map.get(&c_key) {
            KI.setup_individual_client_routes(
                c.internal_ip.parse().expect("Invalid ipv4 in the db!"),
                internal_ip_v4.into(),
                LEGACY_INTERFACE,
            );
        }
    }
    for c_key in changed_clients_return.new_v2 {
        if let Some(c) = key_to_client_map.get(&c_key) {
            KI.teardown_individual_client_routes(
                c.internal_ip.parse().expect("Invalid ipv4 in the db!"),
            );
        }
    }

    Ok(client_states)
}

/// Find all clients that underwent transition from b19 -> 20 or vice versa and need updated rules and routes
/// This function returns (v2_clients to setup, v1_clients to setup, all_v2 clients, all_v1 clients)
fn find_changed_clients(
    client_states: ExitClientSetupStates,
    all_v2: HashMap<WgKey, SystemTime>,
    all_v1: HashMap<WgKey, SystemTime>,
    clients_list: &[exit_db::models::Client],
) -> CurrentExitClientState {
    let mut v1_clients = HashSet::new();

    let mut v2_clients = HashSet::new();

    // Look at handshakes of each client to determine if they are a V1 or V2 client
    for c in clients_list {
        match get_client_interface(c, all_v2.clone(), all_v1.clone()) {
            Ok(interface) => {
                if interface == ClientInterfaceType::LegacyInterface {
                    v1_clients.insert(match c.wg_pubkey.parse() {
                        Ok(a) => a,
                        Err(_) => continue,
                    });
                } else if interface == ClientInterfaceType::ExitInterface {
                    v2_clients.insert(match c.wg_pubkey.parse() {
                        Ok(a) => a,
                        Err(_) => continue,
                    });
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
    c: &exit_db::models::Client,
    new_wg_exit_clients: HashMap<WgKey, SystemTime>,
    wg_exit_clients: HashMap<WgKey, SystemTime>,
) -> Result<ClientInterfaceType, Box<RitaExitError>> {
    trace!(
        "New list is {:?} \n Old list is {:?}",
        new_wg_exit_clients,
        wg_exit_clients
    );
    match (
        new_wg_exit_clients.get(match &c.wg_pubkey.parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.clone().into())),
        }),
        wg_exit_clients.get(match &c.wg_pubkey.parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.clone().into())),
        }),
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
                c.wg_pubkey
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
pub fn enforce_exit_clients(
    clients_list: Vec<exit_db::models::Client>,
    old_debt_actions: &HashSet<(Identity, DebtAction)>,
) -> Result<HashSet<(Identity, DebtAction)>, Box<RitaExitError>> {
    let start = Instant::now();
    let mut clients_by_id = HashMap::new();
    let free_tier_limit = settings::get_rita_exit().payment.free_tier_throughput;
    let close_threshold = calculate_close_thresh();
    for client in clients_list.iter() {
        if let Ok(id) = to_identity(client) {
            clients_by_id.insert(id, client);
        }
    }
    let list = get_debts_list();
    info!(
        "Exit enforcement finished grabbing data in {}s {}ms",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis(),
    );

    // build the new debt actions list and see if we need to do anything
    let mut new_debt_actions = HashSet::new();
    for debt_entry in list.iter() {
        new_debt_actions.insert((
            debt_entry.identity,
            debt_entry.payment_details.action.clone(),
        ));
    }
    if new_debt_actions
        .symmetric_difference(old_debt_actions)
        .count()
        == 0
    {
        info!("No change in enforcement list found, skipping tc calls");
        return Ok(new_debt_actions);
    }

    for debt_entry in list.iter() {
        match clients_by_id.get(&debt_entry.identity) {
            Some(client) => {
                match client.internal_ip.parse() {
                    Ok(IpAddr::V4(ip)) => {
                        if debt_entry.payment_details.action == DebtAction::SuspendTunnel {
                            info!("Exit is enforcing on {} because their debt of {} is greater than the limit of {}", client.wg_pubkey, debt_entry.payment_details.debt, close_threshold);

                            // setup flows this allows us to classify traffic we then limit the class, we delete the class as part of unenforcment but it's difficult to delete the flows
                            // so a user who has been enforced and unenforced while the exit has been online may already have them setup
                            match (
                                KI.has_flow(ip, EXIT_INTERFACE),
                                KI.has_flow(ip, LEGACY_INTERFACE),
                            ) {
                                (Ok(true), Ok(true)) => {
                                    info!("Not repeating flow setup for {}", client.wg_pubkey)
                                }
                                // in any case of partial setup try again
                                (Ok(false), Ok(false))
                                | (Ok(true), Ok(false))
                                | (Ok(false), Ok(true)) => {
                                    // create ipv4 and ipv6 flows, which are used to classify traffic, we can then limit the class specifically
                                    if let Err(e) = KI.create_flow_by_ip(LEGACY_INTERFACE, ip) {
                                        error!(
                                            "Failed to setup flow for {} {:?}",
                                            LEGACY_INTERFACE, e
                                        );
                                    }
                                    if let Err(e) = KI.create_flow_by_ip(EXIT_INTERFACE, ip) {
                                        error!(
                                            "Failed to setup flow for {} {:?}",
                                            EXIT_INTERFACE, e
                                        );
                                    }
                                    // gets the client ipv6 flow for this exit specifically
                                    let client_ipv6 = get_client_ipv6(client);
                                    if let Ok(Some(client_ipv6)) = client_ipv6 {
                                        if let Err(e) =
                                            KI.create_flow_by_ipv6(EXIT_INTERFACE, client_ipv6, ip)
                                        {
                                            error!(
                                                "Failed to setup ipv6 flow for {} {:?}",
                                                EXIT_INTERFACE, e
                                            );
                                        }
                                    }
                                    info!(
                                        "Completed one time enforcement flow setup for {}",
                                        client.wg_pubkey
                                    );
                                }
                                (_, Err(e)) => error!("Failed to get flow status with {:?}", e),
                                (Err(e), _) => error!("Failed to get flow status with {:?}", e),
                            }
                            if let Err(e) =
                                KI.set_class_limit("wg_exit", free_tier_limit, free_tier_limit, ip)
                            {
                                error!(
                                    "Unable to setup enforcement class on {}: {:?}",
                                    LEGACY_INTERFACE, e
                                );
                            }
                            if let Err(e) = KI.set_class_limit(
                                EXIT_INTERFACE,
                                free_tier_limit,
                                free_tier_limit,
                                ip,
                            ) {
                                error!(
                                    "Unable to setup enforcement class on {}: {:?}",
                                    EXIT_INTERFACE, e
                                );
                            }
                        } else {
                            // Delete exisiting enforcement class, users who are not enforced are unclassifed becuase
                            // leaving the class in place reduces their speeds.
                            if let Ok(true) = KI.has_class(ip, LEGACY_INTERFACE) {
                                info!("Deleting enforcement classes for {}", client.wg_pubkey);
                                if let Err(e) = KI.delete_class(LEGACY_INTERFACE, ip) {
                                    error!("Unable to delete class on {}, is {} still enforced when they shouldnt be? {:?}", LEGACY_INTERFACE, ip, e);
                                }
                            }

                            if let Ok(true) = KI.has_class(ip, EXIT_INTERFACE) {
                                info!("Deleting enforcement classes for {}", client.wg_pubkey);
                                if let Err(e) = KI.delete_class(EXIT_INTERFACE, ip) {
                                    error!("Unable to delete class on {}, is {} still enforced when they shouldnt be? {:?}", EXIT_INTERFACE, ip, e);
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
    Ok(new_debt_actions)
}
