//! This module contains all the tools and functions that integrate with the clients database
//! for the exit, which is most exit logic in general. Keep in mind database connections are remote
//! and therefore synronous database requests are quite expensive (on the order of tens of milliseconds)

use crate::rita_common::debt_keeper::DebtAction;
use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::GetDebtsList;
use crate::rita_exit::database::database_tools::client_exists;
use crate::rita_exit::database::database_tools::delete_client;
use crate::rita_exit::database::database_tools::get_client;
use crate::rita_exit::database::database_tools::get_next_client_ip;
use crate::rita_exit::database::database_tools::set_client_timestamp;
use crate::rita_exit::database::database_tools::update_client;
use crate::rita_exit::database::database_tools::update_low_balance_notification_time;
use crate::rita_exit::database::database_tools::verify_client;
use crate::rita_exit::database::database_tools::verify_db_client;
use crate::rita_exit::database::email::handle_email_registration;
use crate::rita_exit::database::email::send_low_balance_email;
use crate::rita_exit::database::geoip::get_country;
use crate::rita_exit::database::geoip::get_gateway_ip_bulk;
use crate::rita_exit::database::geoip::get_gateway_ip_single;
use crate::rita_exit::database::geoip::verify_ip;
use crate::rita_exit::database::sms::handle_sms_registration;
use crate::rita_exit::database::sms::send_low_balance_sms;
use crate::rita_exit::database::struct_tools::display_hashset;
use crate::rita_exit::database::struct_tools::to_exit_client;
use crate::rita_exit::database::struct_tools::to_identity;
use crate::rita_exit::database::struct_tools::verif_done;
use crate::KI;
use crate::SETTING;
use ::actix::prelude::SystemService;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitDetails, ExitState, ExitVerifMode};
use diesel;
use diesel::prelude::{Connection, ConnectionError, PgConnection, RunQueryDsl};
use exit_db::{models, schema};
use failure::Error;
use futures::Future;
use ipnetwork::IpNetwork;
use rand;
use rand::Rng;
use settings::exit::ExitVerifSettings;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

mod database_tools;
pub mod db_client;
mod email;
mod geoip;
mod ip_increment;
mod sms;
pub mod struct_tools;

/// Gets the Postgres database connection
pub fn get_database_connection() -> Result<PgConnection, ConnectionError> {
    let db_uri = SETTING.get_db_uri();
    info!("Opening database connection {:?}", db_uri);
    if db_uri.contains("postgres://")
        || db_uri.contains("postgresql://")
        || db_uri.contains("psql://")
    {
        PgConnection::establish(&db_uri)
    } else {
        panic!("You must provide a valid postgressql database uri!");
    }
}

pub fn get_exit_info() -> ExitDetails {
    ExitDetails {
        server_internal_ip: SETTING.get_exit_network().own_internal_ip.into(),
        wg_exit_port: SETTING.get_exit_network().wg_tunnel_port,
        exit_price: SETTING.get_exit_network().exit_price,
        exit_currency: SETTING.get_payment().system_chain,
        netmask: SETTING.get_exit_network().netmask,
        description: SETTING.get_description(),
        verif_mode: match SETTING.get_verif_settings() {
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

fn client_to_new_db_client(
    client: &ExitClientIdentity,
    new_ip: IpAddr,
    country: String,
) -> models::Client {
    let mut rng = rand::thread_rng();
    let rand_code: u64 = rng.gen_range(0, 999_999);
    models::Client {
        wg_port: i32::from(client.wg_port),
        mesh_ip: client.global.mesh_ip.to_string(),
        wg_pubkey: client.global.wg_public_key.to_string(),
        eth_address: client.global.eth_address.to_string(),
        nickname: client.global.nickname.unwrap_or_default().to_string(),
        internal_ip: new_ip.to_string(),
        email: client.reg_details.email.clone().unwrap_or_default(),
        phone: client.reg_details.phone.clone().unwrap_or_default(),
        country,
        email_code: format!("{:06}", rand_code),
        text_sent: 0,
        verified: false,
        email_sent_time: 0,
        last_seen: 0,
        last_balance_warning_time: 0,
    }
}

/// Handles a new client registration api call. Performs a geoip lookup
/// on their registration ip to make sure that they are coming from a valid gateway
/// ip and then sends out an email of phone message
pub fn signup_client(client: ExitClientIdentity) -> Result<ExitState, Error> {
    use self::schema::clients::dsl::clients;
    let mut tmp_cache = HashMap::new();
    let conn = get_database_connection()?;
    let client_mesh_ip = client.global.mesh_ip;
    let gateway_ip = get_gateway_ip_single(client_mesh_ip)?;

    trace!("got setup request {:?}", client);

    // either update and grab an existing entry or create one
    let their_record = if client_exists(&client_mesh_ip, &conn)? {
        update_client(&client, &conn)?;
        get_client(client_mesh_ip, &conn)?
    } else {
        trace!("record does not exist, creating");

        let new_ip = get_next_client_ip(&conn)?;

        trace!("About to check country");
        let user_country = if SETTING.get_allowed_countries().is_empty() {
            String::new()
        } else {
            get_country(&gateway_ip, &mut tmp_cache)?
        };

        let c = client_to_new_db_client(&client, new_ip, user_country);

        trace!("Inserting new client");
        diesel::insert_into(clients).values(&c).execute(&conn)?;

        c
    };

    match (
        verify_ip(&gateway_ip, &mut tmp_cache),
        SETTING.get_verif_settings(),
    ) {
        (Ok(true), Some(ExitVerifSettings::Email(mailer))) => {
            handle_email_registration(&client, &their_record, &conn, mailer.email_cooldown as i64)
        }
        (Ok(true), Some(ExitVerifSettings::Phone(phone))) => {
            handle_sms_registration(&client, &their_record, phone.auth_api_key, &conn)
        }
        (Ok(true), None) => {
            verify_client(&client, true, &conn)?;
            Ok(ExitState::Registered {
                our_details: ExitClientDetails {
                    client_internal_ip: their_record.internal_ip.parse()?,
                },
                general_details: get_exit_info(),
                message: "Registration OK".to_string(),
            })
        }
        (Ok(false), _) => Ok(ExitState::Denied {
            message: format!(
                "This exit only accepts connections from {}",
                display_hashset(&SETTING.get_allowed_countries()),
            ),
        }),
        (Err(_e), _) => Ok(ExitState::Denied {
            message: "There was a problem signing up, please try again".to_string(),
        }),
    }
}

/// Gets the status of a client and updates it in the database
pub fn client_status(client: ExitClientIdentity) -> Result<ExitState, Error> {
    let conn = get_database_connection()?;
    let client_mesh_ip = client.global.mesh_ip;

    trace!("Checking if record exists for {:?}", client.global.mesh_ip);

    if client_exists(&client.global.mesh_ip, &conn)? {
        trace!("record exists, updating");

        let their_record = get_client(client_mesh_ip, &conn)?;

        if !verif_done(&their_record) {
            return Ok(ExitState::Pending {
                general_details: get_exit_info(),
                message: "awaiting email verification".to_string(),
                email_code: None,
                phone_code: None,
            });
        }

        let current_ip = their_record.internal_ip.parse()?;

        let current_subnet = IpNetwork::new(
            SETTING.get_exit_network().own_internal_ip.into(),
            SETTING.get_exit_network().netmask,
        )?;

        if !current_subnet.contains(current_ip) {
            return Ok(ExitState::Registering {
                general_details: get_exit_info(),
                message: "Registration reset because of IP range change".to_string(),
            });
        }

        update_client(&client, &conn)?;

        low_balance_notification(client, &their_record, SETTING.get_verif_settings(), &conn);

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
    info!("Checking low balance nofication");
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
            (None, _) => error!("Client is registered but has no phone number!"),
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
            (None, _) => error!("Client is registered but has no phone number!"),
        },
        (_, _) => {}
    }
}

/// Every 5 seconds we vlaidate all online clients to make sure that they are in the right region
/// we also do this in the client status requests but we want to handle the edge case of a modified
/// client that doesn't make status requests
pub fn validate_clients_region(
    mut geoip_cache: &mut HashMap<IpAddr, String>,
    clients_list: &[exit_db::models::Client],
    conn: &PgConnection,
) -> Result<(), Error> {
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

    let mesh_to_gateway_ip_list = get_gateway_ip_bulk(ip_vec);

    match mesh_to_gateway_ip_list {
        Ok(list) => {
            for item in list {
                match verify_ip(&item.gateway_ip, &mut geoip_cache) {
                    Ok(true) => trace!("{:?} is from an allowed ip", item),
                    Ok(false) => {
                        // get_gateway_ip_bulk can't add new entires to the list
                        // therefore client_map is strictly a superset of ip_bulk results
                        let client_to_deauth = &client_map[&item.mesh_ip];
                        if verify_db_client(client_to_deauth, false, conn).is_err() {
                            error!("Failed to deauth client {:?}", client_to_deauth);
                        }
                    }
                    Err(e) => error!("Failed to GeoIP {:?} to check region", e),
                }
            }
            info!(
                "Exit region validation completed in {}s {}ms",
                start.elapsed().as_secs(),
                start.elapsed().subsec_millis(),
            );
            Ok(())
        }
        Err(e) => {
            error!("Problem getting gateway ip's for clients! {:?}", e);
            bail!("Problem getting gateway ips for clients! {:?}", e)
        }
    }
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
                if client.last_seen == 0 {
                    info!(
                        "{} does not have a last seen timestamp, adding one now ",
                        client.mesh_ip
                    );
                    let res = set_client_timestamp(client_id, conn);
                    if res.is_err() {
                        warn!(
                            "Unable to update the client timestamp for {:?} with {:?}",
                            client, res
                        );
                    }
                }
                // a entry_timeout value of 0 means the feature is disabled
                else if entry_timeout != 0 && time_delta > entry_timeout {
                    warn!(
                        "{} has been inactive for too long, deleting! ",
                        client.mesh_ip
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
pub fn setup_clients(clients_list: &[exit_db::models::Client]) -> Result<(), Error> {
    use self::schema::clients::dsl::clients;

    let start = Instant::now();

    let mut wg_clients = Vec::new();

    trace!("got clients from db {:?}", clients);

    for c in clients_list.iter() {
        match (c.verified, to_exit_client(c.clone())) {
            (true, Ok(exit_client_c)) => wg_clients.push(exit_client_c),
            (true, Err(e)) => warn!("Error converting {:?} to exit client {:?}", c, e),
            (false, _) => trace!("{:?} is not verified, not adding to wg_exit", c),
        }
    }

    trace!("converted clients {:?}", wg_clients);

    // setup all the tunnels
    let exit_status = KI.set_exit_wg_config(
        wg_clients,
        SETTING.get_exit_network().wg_tunnel_port,
        &SETTING.get_exit_network().wg_private_key_path,
        &SETTING.get_exit_network().own_internal_ip.into(),
        SETTING.get_exit_network().netmask,
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
        "exit setup loop completed in {}s {}ms",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis()
    );
    Ok(())
}

/// Performs enforcement actions on clients by requesting a list of clients from debt keeper
/// if they are also a exit client they are limited to the free tier level of bandwidth by
/// setting the htb class they are assigned to to a maximum speed of the free tier value.
/// Unlike intermediary enforcement we do not need to subdivide the free tier to prevent
/// ourselves from exceeding the upstream free tier. As an exit we are the upstream.
pub fn enforce_exit_clients(
    clients_list: Vec<exit_db::models::Client>,
) -> Box<Future<Item = (), Error = ()>> {
    let start = Instant::now();
    Box::new(
        DebtKeeper::from_registry()
            .send(GetDebtsList)
            .and_then(move |debts_list| match debts_list {
                Ok(list) => {
                    let mut clients_by_id = HashMap::new();
                    let free_tier_limit = SETTING.get_payment().free_tier_throughput;
                    for client in clients_list.iter() {
                        if let Ok(id) = to_identity(client) {
                            clients_by_id.insert(id, client);
                        }
                    }

                    for debt_entry in list.iter() {
                        match clients_by_id.get(&debt_entry.identity) {
                            Some(client) => {
                                match client.internal_ip.parse() {
                                    Ok(IpAddr::V4(ip)) => {
                                        let res = if debt_entry.payment_details.action
                                            == DebtAction::SuspendTunnel
                                        {
                                            KI.set_class_limit(
                                                "wg_exit",
                                                free_tier_limit,
                                                free_tier_limit,
                                                &ip,
                                            )
                                        } else {
                                            // set to 100mbps garunteed bandwidth and 1gbps
                                            // absolute max
                                            KI.set_class_limit("wg_exit", 100_000, 1_000_000, &ip)
                                        };
                                        if res.is_err() {
                                            panic!("Failed to limit {} with {:?}", ip, res);
                                        }
                                    }
                                    _ => warn!("Can't parse Ipv4Addr to create limit!"),
                                };
                            }
                            None => {
                                warn!("Could not find {:?} to suspend!", debt_entry.identity);
                            }
                        }
                    }

                    info!(
                        "Exit enforcement completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis(),
                    );
                    Ok(())
                }
                Err(e) => {
                    warn!("Failed to get debts from DebtKeeper! {:?}", e);
                    Ok(())
                }
            })
            .then(|_| Ok(())),
    )
}
