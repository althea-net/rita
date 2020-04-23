//! This module contains all the tools and functions that integrate with the clients database
//! for the exit, which is most exit logic in general. Keep in mind database connections are remote
//! and therefore synronous database requests are quite expensive (on the order of tens of milliseconds)

use crate::rita_common::debt_keeper::get_debts_list_sync;
use crate::rita_common::debt_keeper::DebtAction;
use crate::rita_exit::database::database_tools::client_conflict;
use crate::rita_exit::database::database_tools::create_or_update_user_record;
use crate::rita_exit::database::database_tools::delete_client;
use crate::rita_exit::database::database_tools::get_client;
use crate::rita_exit::database::database_tools::get_database_connection;
use crate::rita_exit::database::database_tools::get_database_connection_sync;
use crate::rita_exit::database::database_tools::set_client_timestamp;
use crate::rita_exit::database::database_tools::update_client;
use crate::rita_exit::database::database_tools::update_low_balance_notification_time;
use crate::rita_exit::database::database_tools::verify_client;
use crate::rita_exit::database::database_tools::verify_db_client;
use crate::rita_exit::database::email::handle_email_registration;
use crate::rita_exit::database::email::send_low_balance_email;
use crate::rita_exit::database::geoip::get_country_async;
use crate::rita_exit::database::geoip::get_gateway_ip_bulk;
use crate::rita_exit::database::geoip::get_gateway_ip_single;
use crate::rita_exit::database::geoip::verify_ip;
use crate::rita_exit::database::geoip::verify_ip_sync;
use crate::rita_exit::database::sms::handle_sms_registration;
use crate::rita_exit::database::sms::send_low_balance_sms;
use crate::rita_exit::database::struct_tools::display_hashset;
use crate::rita_exit::database::struct_tools::to_exit_client;
use crate::rita_exit::database::struct_tools::to_identity;
use crate::rita_exit::database::struct_tools::verif_done;
use crate::rita_exit::rita_loop::wait_timeout::wait_timeout;
use crate::rita_exit::rita_loop::wait_timeout::WaitResult;
use crate::rita_exit::rita_loop::EXIT_LOOP_TIMEOUT;
use crate::EXIT_ALLOWED_COUNTRIES;
use crate::EXIT_DESCRIPTION;
use crate::EXIT_NETWORK_SETTINGS;
use crate::EXIT_PRICE;
use crate::EXIT_SYSTEM_CHAIN;
use crate::EXIT_VERIF_SETTINGS;
use crate::KI;
use crate::SETTING;
use althea_kernel_interface::ExitClient;
use althea_types::Identity;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitDetails, ExitState, ExitVerifMode};
use diesel::prelude::PgConnection;
use failure::Error;
use futures01::future;
use futures01::Future;
use ipnetwork::IpNetwork;
use settings::exit::ExitVerifSettings;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod database_tools;
pub mod db_client;
mod email;
mod geoip;
mod sms;
pub mod struct_tools;

/// one day in seconds
pub const ONE_DAY: i64 = 86400;

pub fn get_exit_info() -> ExitDetails {
    const UPDATE_INTERVAL: Duration = Duration::from_secs(60);
    let last_update = EXIT_PRICE.read().unwrap().1;
    if Instant::now() > last_update && ((Instant::now() - last_update) > UPDATE_INTERVAL) {
        let mut exit_price = EXIT_PRICE.write().unwrap();
        let old_exit_price = exit_price.0;
        exit_price.0 = SETTING.get_exit_network().exit_price;
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

// lossy conversion, but it won't matter until 2.9 * 10^8 millenia from now
pub fn secs_since_unix_epoch() -> i64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() as i64
}

/// Handles a new client registration api call. Performs a geoip lookup
/// on their registration ip to make sure that they are coming from a valid gateway
/// ip and then sends out an email of phone message
pub fn signup_client(client: ExitClientIdentity) -> impl Future<Item = ExitState, Error = Error> {
    trace!("got setup request {:?}", client);
    get_gateway_ip_single(client.global.mesh_ip).and_then(move |gateway_ip| {
        trace!("got gateway ip {:?}", client);
        verify_ip(gateway_ip).and_then(move |verify_status| {
            trace!("verified the ip country {:?}", client);
            get_country_async(gateway_ip).and_then(move |user_country| {
                trace!("got the country country {:?}", client);
                get_database_connection().and_then(move |conn| {
                    trace!("Doing database work for {:?} in country {} with verify_status {}", client, user_country, verify_status);
                    // check if we have any users with conflicting details
                    match client_conflict(&client, &conn) {
                        Ok(true) => {
                            return Box::new(future::ok(ExitState::Denied {
                                message: format!(
                                    "Partially changed registration details! Please reset your router and re-register with all new details. Backup your key first! {}",
                                    display_hashset(&*EXIT_ALLOWED_COUNTRIES),
                                ),
                            }))
                                as Box<dyn Future<Item = ExitState, Error = Error>>
                        }
                        Ok(false) => {}
                        Err(e) => return Box::new(future::err(e)),
                    }

                    let their_record =
                        match create_or_update_user_record(&conn, &client, user_country) {
                            Ok(record) => record,
                            Err(e) => return Box::new(future::err(e)),
                        };

                    // either update and grab an existing entry or create one
                    match (verify_status, EXIT_VERIF_SETTINGS.clone()) {
                        (true, Some(ExitVerifSettings::Email(mailer))) => {
                            Box::new(handle_email_registration(
                                &client,
                                &their_record,
                                &conn,
                                mailer.email_cooldown as i64,
                            ))
                        }
                        (true, Some(ExitVerifSettings::Phone(phone))) => Box::new(
                            handle_sms_registration(client, their_record, phone.auth_api_key),
                        ),
                        (true, None) => {
                            match verify_client(&client, true, &conn) {
                                Ok(_) => (),
                                Err(e) => return Box::new(future::err(e)),
                            }
                            let client_internal_ip = match their_record.internal_ip.parse() {
                                Ok(ip) => ip,
                                Err(e) => return Box::new(future::err(format_err!("{:?}", e))),
                            };

                            Box::new(future::ok(ExitState::Registered {
                                our_details: ExitClientDetails { client_internal_ip },
                                general_details: get_exit_info(),
                                message: "Registration OK".to_string(),
                            }))
                        }
                        (false, _) => Box::new(future::ok(ExitState::Denied {
                            message: format!(
                                "This exit only accepts connections from {}",
                                display_hashset(&*EXIT_ALLOWED_COUNTRIES),
                            ),
                        })),
                    }
                })
            })
        })
    })
}

/// Gets the status of a client and updates it in the database
pub fn client_status(client: ExitClientIdentity, conn: &PgConnection) -> Result<ExitState, Error> {
    trace!("Checking if record exists for {:?}", client.global.mesh_ip);

    if let Some(their_record) = get_client(&client, &conn)? {
        trace!("record exists, updating");

        if !verif_done(&their_record) {
            return Ok(ExitState::Pending {
                general_details: get_exit_info(),
                message: "awaiting email verification".to_string(),
                email_code: None,
                phone_code: None,
            });
        }

        let current_ip = their_record.internal_ip.parse()?;

        let exit_network = &*EXIT_NETWORK_SETTINGS;
        let current_subnet =
            IpNetwork::new(exit_network.own_internal_ip.into(), exit_network.netmask)?;

        if !current_subnet.contains(current_ip) {
            return Ok(ExitState::Registering {
                general_details: get_exit_info(),
                message: "Registration reset because of IP range change".to_string(),
            });
        }

        update_client(&client, &their_record, &conn)?;

        low_balance_notification(client, &their_record, EXIT_VERIF_SETTINGS.clone(), &conn);

        Ok(ExitState::Registered {
            our_details: ExitClientDetails {
                client_internal_ip: current_ip,
            },
            general_details: get_exit_info(),
            message: "Registration OK".to_string(),
        })
    } else {
        Ok(ExitState::New)
    }
}

/// Handles the dispatching of low balance notifications based on what validation method the exit
/// is currently using and what the configured interval is. There are many many possible combinations
/// of state to handle so this is a bit of a mess. May be possible to clean up by making more things
/// mandatory?
fn low_balance_notification(
    client: ExitClientIdentity,
    their_record: &exit_db::models::Client,
    config: Option<ExitVerifSettings>,
    conn: &PgConnection,
) {
    trace!("Checking low balance nofication");

    // maybe this needs a trait 'enabled'?
    if let Some(ref config) = config {
        match config {
            ExitVerifSettings::Phone(ref val) => {
                if !val.notify_low_balance {
                    return;
                }
            }
            ExitVerifSettings::Email(ref val) => {
                if !val.notify_low_balance {
                    return;
                }
            }
        }
    }

    let time_since_last_notification =
        secs_since_unix_epoch() - their_record.last_balance_warning_time;

    match (client.low_balance, config) {
        (Some(true), Some(ExitVerifSettings::Phone(val))) => match (
            client.reg_details.phone.clone(),
            time_since_last_notification > i64::from(val.balance_notification_interval),
        ) {
            (Some(number), true) => {
                let res = send_low_balance_sms(&number, val);
                if let Err(e) = res {
                    warn!(
                        "Failed to notify {} of their low balance with {:?}",
                        number, e
                    );
                } else if let Err(e) = update_low_balance_notification_time(&client, conn) {
                    error!(
                        "Failed to find {:?} in the database to update notified time! {:?}",
                        client, e
                    );
                }
            }
            (Some(_), false) => {}
            (None, _) => error!(
                "Client {} is registered but has no phone number!",
                client.global.wg_public_key
            ),
        },
        (Some(true), Some(ExitVerifSettings::Email(val))) => match (
            client.reg_details.email.clone(),
            time_since_last_notification > i64::from(val.balance_notification_interval),
        ) {
            (Some(email), true) => {
                let res = send_low_balance_email(&email, val);
                if let Err(e) = res {
                    warn!(
                        "Failed to notify {} of their low balance with {:?}",
                        email, e
                    );
                } else if let Err(e) = update_low_balance_notification_time(&client, conn) {
                    error!(
                        "Failed to find {:?} in the database to update notified time! {:?}",
                        client, e
                    );
                }
            }
            (Some(_), false) => {}
            (None, _) => error!("No notification method to notify of low balance!"),
        },
        (_, _) => {}
    }
}

/// Every 5 seconds we vlaidate all online clients to make sure that they are in the right region
/// we also do this in the client status requests but we want to handle the edge case of a modified
/// client that doesn't make status requests
pub fn validate_clients_region(clients_list: Vec<exit_db::models::Client>) -> Result<(), Error> {
    info!("Starting exit region validation");
    let start = Instant::now();

    trace!("Got clients list {:?}", clients_list);
    let mut ip_vec = Vec::new();
    let mut client_map = HashMap::new();
    for item in clients_list {
        match item.mesh_ip.parse() {
            Ok(ip) => {
                client_map.insert(ip, item);
                ip_vec.push(ip);
            }
            Err(_e) => error!("Database entry with invalid mesh ip! {:?}", item),
        }
    }
    let conn = get_database_connection_sync()?;
    let list = match wait_timeout(get_gateway_ip_bulk(ip_vec), EXIT_LOOP_TIMEOUT) {
        WaitResult::Err(e) => return Err(e),
        WaitResult::Ok(val) => val,
        WaitResult::TimedOut(_) => return Err(format_err!("Timed out!")),
    };
    for item in list.iter() {
        let res = verify_ip_sync(item.gateway_ip);
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
                if verify_db_client(client_to_deauth, false, &conn).is_err() {
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
) -> Result<(), Error> {
    trace!("Running exit client cleanup");
    let start = Instant::now();

    for client in clients_list.iter() {
        trace!("Checking client {:?}", client);
        match to_exit_client(client.clone()) {
            Ok(client_id) => {
                let time_delta = secs_since_unix_epoch() - client.last_seen;
                let entry_timeout = i64::from(SETTING.get_exit_network().entry_timeout);
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

/// Gets a complete list of clients from the database and transforms that list
/// into a single very long wg tunnel setup command which is then applied to the
/// wg_exit tunnel (or created if it's the first run). This is the offically supported
/// way to update live WireGuard tunnels and should not disrupt traffic
pub fn setup_clients(
    clients_list: &[exit_db::models::Client],
    old_clients: &HashSet<ExitClient>,
) -> Result<HashSet<ExitClient>, Error> {
    let start = Instant::now();

    // use hashset to ensure uniqueness and check for duplicate db entries
    let mut wg_clients = HashSet::new();

    trace!("got clients from db {:?} {:?}", clients_list, old_clients);

    for c in clients_list.iter() {
        match (c.verified, to_exit_client(c.clone())) {
            (true, Ok(exit_client_c)) => {
                if !wg_clients.insert(exit_client_c) {
                    error!("Duplicate database entry! {}", c.wg_pubkey);
                }
            }
            (true, Err(e)) => warn!("Error converting {:?} to exit client {:?}", c, e),
            (false, _) => trace!("{:?} is not verified, not adding to wg_exit", c),
        }
    }

    trace!("converted clients {:?}", wg_clients);
    // symetric difference is an iterator of all items in A but not in B
    // or in B but not in A, in short if there's any difference between the two
    // it must be nonzero, since all entires must be unique there can not be duplicates
    if wg_clients.symmetric_difference(old_clients).count() == 0 {
        info!("No change in wg_exit, skipping setup for this round");
        return Ok(wg_clients);
    }

    // setup all the tunnels
    let exit_status = KI.set_exit_wg_config(
        &wg_clients,
        SETTING.get_exit_network().wg_tunnel_port,
        &SETTING.get_exit_network().wg_private_key_path,
    );

    match exit_status {
        Ok(_) => trace!("Successfully setup Exit WG!"),
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
    Ok(wg_clients)
}

/// Performs enforcement actions on clients by requesting a list of clients from debt keeper
/// if they are also a exit client they are limited to the free tier level of bandwidth by
/// setting the htb class they are assigned to to a maximum speed of the free tier value.
/// Unlike intermediary enforcement we do not need to subdivide the free tier to prevent
/// ourselves from exceeding the upstream free tier. As an exit we are the upstream.
pub fn enforce_exit_clients(
    clients_list: Vec<exit_db::models::Client>,
    old_debt_actions: &HashSet<(Identity, DebtAction)>,
) -> Result<HashSet<(Identity, DebtAction)>, Error> {
    let start = Instant::now();
    let mut clients_by_id = HashMap::new();
    let free_tier_limit = SETTING.get_payment().free_tier_throughput;
    let close_threshold = SETTING.get_payment().close_threshold.clone();
    for client in clients_list.iter() {
        if let Ok(id) = to_identity(client) {
            clients_by_id.insert(id, client);
        }
    }
    let list = get_debts_list_sync();
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
                        let res = if debt_entry.payment_details.action == DebtAction::SuspendTunnel
                        {
                            info!("Exit is enforcing on {} because their debt of {} is greater than the limit of {}", client.wg_pubkey, debt_entry.payment_details.debt, close_threshold);
                            KI.set_class_limit("wg_exit", free_tier_limit, free_tier_limit, &ip)
                        } else {
                            // set to 500mbps garunteed bandwidth and 1gbps
                            // absolute max
                            KI.set_class_limit("wg_exit", 500_000, 1_000_000, &ip)
                        };
                        if res.is_err() {
                            panic!("Failed to limit {} with {:?}", ip, res);
                        }
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

    // TODO this is a hacky emergency kill switch for when we detect that
    // the actix loop may be running too slowly, when that happens requests to
    // the full node timeout and transactions will not be processed resulting in
    // wallet drain, this is worse than the possiblity of the exit not coming back up
    // As a method of detection this is just a decent proxy not a 100% acurate method
    // as it seems that http requests and anything that touches shelling out slow down
    // the most in these situations. Hopefully we can figure out more about why the
    // futures loop starts acting stragely.
    const PANIC_TIME: u64 = 10;
    if start.elapsed().as_secs() > PANIC_TIME {
        let fail_mesg = format!("Exit enforcement took more than {} seconds!", PANIC_TIME);
        error!("{}", fail_mesg);
        panic!("{}", fail_mesg);
    }
    Ok(new_debt_actions)
}
