use crate::database::secs_since_unix_epoch;
use crate::database::struct_tools::client_to_new_db_client;
use crate::database::ONE_DAY;
use rita_common::utils::ip_increment::increment;

use crate::{DB_POOL, RitaExitError};
use actix_web::Result;
use althea_kernel_interface::ExitClient;
use althea_types::ExitClientIdentity;
use diesel::dsl::{delete, exists};
use diesel::prelude::{ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl};
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::PooledConnection;
use diesel::select;
use exit_db::{models, schema};
use futures01::future;
use futures01::future::Future;
use std::net::IpAddr;
use std::net::Ipv4Addr;

/// Takes a list of clients and returns a sorted list of ip addresses spefically v4 since it
/// can implement comparison operators
fn get_internal_ips(clients: &[exit_db::models::Client]) -> Vec<Ipv4Addr> {
    let mut list = Vec::with_capacity(clients.len());
    for client in clients {
        let client_internal_ip = client.internal_ip.parse();
        match client_internal_ip {
            Ok(address) => list.push(address),
            Err(_e) => error!("Bad database entry! {:?}", client),
        }
    }
    // this list should come sorted from the database, this just double checks
    list.sort();
    list
}

/// Gets the next available client ip, takes about O(n) time, we could make it faster by
/// sorting on the database side but I've left that optimization on the vine for now
pub fn get_next_client_ip(conn: &PgConnection) -> Result<IpAddr, RitaExitError> {
    use self::schema::clients::dsl::clients;
    let rita_exit = settings::get_rita_exit();
    let exit_settings = rita_exit.exit_network;
    let netmask = exit_settings.netmask as u8;
    let start_ip = exit_settings.exit_start_ip;
    let gateway_ip = exit_settings.own_internal_ip;
    // drop here to free up the settings lock, this codepath runs in parallel
    drop(exit_settings);

    let clients_list = clients.load::<models::Client>(conn)?;
    let ips_list = get_internal_ips(&clients_list);
    let mut new_ip: IpAddr = start_ip.into();

    // iterate until we find an open spot, yes converting to string and back is quite awkward
    while ips_list.contains(&new_ip.to_string().parse()?) {
        new_ip = increment(new_ip, netmask)?;
        if new_ip == gateway_ip {
            new_ip = increment(new_ip, netmask)?;
        }
    }
    trace!(
        "The new client's ip is {} selected using {:?}",
        new_ip,
        ips_list
    );

    Ok(new_ip)
}

/// updates the last seen time
pub fn update_client(
    client: &ExitClientIdentity,
    their_record: &models::Client,
    conn: &PgConnection,
) -> Result<(), RitaExitError> {
    use self::schema::clients::dsl::{
        clients, email, eth_address, last_seen, mesh_ip, phone, wg_pubkey,
    };
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));

    if let Some(mail) = client.reg_details.email.clone() {
        if their_record.email != mail {
            info!(
                "Client {} email has changed from {} to {} updating",
                their_record.wg_pubkey, their_record.email, mail
            );
            diesel::update(filtered_list.clone())
                .set(email.eq(mail))
                .execute(&*conn)?;
        }
    }

    if let Some(number) = client.reg_details.phone.clone() {
        if their_record.phone != number {
            info!(
                "Client {} phonenumber has changed from {} to {} updating",
                their_record.wg_pubkey, their_record.phone, number
            );
            diesel::update(filtered_list.clone())
                .set(phone.eq(number))
                .execute(&*conn)?;
        }
    }

    let current_time = secs_since_unix_epoch();
    let time_since_last_update = current_time - their_record.last_seen;
    // update every 12 hours, no entry timeouts less than a day allowed
    if time_since_last_update > ONE_DAY / 2 {
        info!("Bumping client timestamp for {}", their_record.wg_pubkey);
        diesel::update(filtered_list)
            .set(last_seen.eq(secs_since_unix_epoch() as i64))
            .execute(&*conn)?;
    }

    Ok(())
}

pub fn get_client(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<Option<models::Client>, RitaExitError> {
    use self::schema::clients::dsl::{clients, eth_address, mesh_ip, wg_pubkey};
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        // TODO search for EIP-55 capitalized key string and add a fallback
        // to upgrade entires that are using the old all lowercase format. This should
        // simplify the code some and reduce calls to .to_lowercase and worst of all the chance
        // that we might forget a lowercase call, which type-checking can't protect us from.
        .filter(eth_address.eq(key.to_string().to_lowercase()));
    match filtered_list.load::<models::Client>(conn) {
        Ok(entry) => {
            if entry.len() > 1 {
                let err_msg = format!(
                    "More than one exact match with wg: {} eth: {} ip: {}",
                    wg, key, ip
                );
                error!("{}", err_msg);
                panic!("{}", err_msg);
            } else if entry.is_empty() {
                return Ok(None);
            }
            Ok(Some(entry[0].clone()))
        }
        Err(e) => {
            error!("We failed to lookup the client {:?} with{:?}", mesh_ip, e);
            return Err(RitaExitError::MiscStringError("We failed to lookup the client!".to_string()))
        }
    }
}

/// changes a clients verified value in the database
pub fn verify_client(
    client: &ExitClientIdentity,
    client_verified: bool,
    conn: &PgConnection,
) -> Result<(), RitaExitError> {
    use self::schema::clients::dsl::*;
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));

    diesel::update(filtered_list)
        .set(verified.eq(client_verified))
        .execute(&*conn)?;

    Ok(())
}

/// Marks a client as verified in the database
pub fn verify_db_client(
    client: &models::Client,
    client_verified: bool,
    conn: &PgConnection,
) -> Result<(), RitaExitError> {
    use self::schema::clients::dsl::*;
    let ip = &client.mesh_ip;
    let wg = &client.wg_pubkey;
    let key = &client.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));

    diesel::update(filtered_list)
        .set(verified.eq(client_verified))
        .execute(&*conn)?;

    Ok(())
}

/// Increments the text message sent count in the database
pub fn text_sent(client: &ExitClientIdentity, conn: &PgConnection, val: i32) -> Result<(), RitaExitError> {
    use self::schema::clients::dsl::*;
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));

    diesel::update(filtered_list)
        .set(text_sent.eq(val + 1))
        .execute(&*conn)?;

    Ok(())
}

fn client_exists(client: &ExitClientIdentity, conn: &PgConnection) -> Result<bool, RitaExitError> {
    use self::schema::clients::dsl::*;
    trace!("Checking if client exists");
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));
    Ok(select(exists(filtered_list)).get_result(&*conn)?)
}

/// True if there is any client with the same eth address, wg key, or ip address already registered
pub fn client_conflict(client: &ExitClientIdentity, conn: &PgConnection) -> Result<bool, RitaExitError> {
    use self::schema::clients::dsl::*;
    // we can't possibly have a conflict if we have exactly this client already
    // since client exists checks all major details this is safe and will return false
    // if it's not exactly the same client
    if client_exists(client, conn)? {
        return Ok(false);
    }
    trace!("Checking if client exists");
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let ip_match = clients.filter(mesh_ip.eq(ip.to_string()));
    let wg_key_match = clients.filter(wg_pubkey.eq(wg.to_string()));
    let eth_address_match = clients.filter(eth_address.eq(key.to_string().to_lowercase()));
    let ip_exists = select(exists(ip_match)).get_result(&*conn)?;
    let wg_exists = select(exists(wg_key_match)).get_result(&*conn)?;
    let eth_exists = select(exists(eth_address_match)).get_result(&*conn)?;
    info!(
        "Signup conflict ip {} eth {} wg {}",
        ip_exists, eth_exists, wg_exists
    );
    Ok(ip_exists || eth_exists || wg_exists)
}

pub fn delete_client(client: ExitClient, connection: &PgConnection) -> Result<(), RitaExitError> {
    use self::schema::clients::dsl::*;
    info!("Deleting clients {:?} in database", client);

    let mesh_ip_string = client.mesh_ip.to_string();
    let statement = clients.find(&mesh_ip_string);
    delete(statement).execute(connection)?;
    Ok(())
}

// for backwards compatibility with entires that do not have a timestamp
// new entires will be initialized and updated as part of the normal flow
pub fn set_client_timestamp(client: ExitClient, connection: &PgConnection) -> Result<(), RitaExitError> {
    use self::schema::clients::dsl::*;
    info!("Setting timestamp for client {:?}", client);

    diesel::update(clients.find(&client.mesh_ip.to_string()))
        .set(last_seen.eq(secs_since_unix_epoch()))
        .execute(connection)?;
    Ok(())
}

// we match on email not key? that has interesting implications for
// shared emails
pub fn update_mail_sent_time(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<(), RitaExitError> {
    use self::schema::clients::dsl::{clients, email, email_sent_time};
    let mail_addr = match client.clone().reg_details.email {
        Some(mail) => mail,
        None => return Err(RitaExitError::EmailNotFound(client.clone()))
    };

    diesel::update(clients.filter(email.eq(mail_addr)))
        .set(email_sent_time.eq(secs_since_unix_epoch()))
        .execute(&*conn)?;

    Ok(())
}

/// Gets the Postgres database connection from the threadpool, since there are dedicated
/// connections for each threadpool member error if non is available right away
pub fn get_database_connection(
) -> impl Future<Item = PooledConnection<ConnectionManager<PgConnection>>, Error = RitaExitError> {
    match DB_POOL.read().unwrap().try_get() {
        Some(connection) => Box::new(future::ok(connection))
            as Box<
                dyn Future<Item = PooledConnection<ConnectionManager<PgConnection>>, Error = RitaExitError>,
            >,
        None => {
            error!("No available db connection!");
            Box::new(future::err(RitaExitError::MiscStringError("No Database connection available!".to_string())))
        }
    }
}

pub fn get_database_connection_sync(
) -> Result<PooledConnection<ConnectionManager<PgConnection>>, RitaExitError> {
    match DB_POOL.read().unwrap().try_get() {
        Some(connection) => Ok(connection),
        None => return Err(RitaExitError::MiscStringError("No connection!".to_string()))
    }
}

pub fn create_or_update_user_record(
    conn: &PgConnection,
    client: &ExitClientIdentity,
    user_country: String,
) -> Result<models::Client, RitaExitError> {
    use self::schema::clients::dsl::clients;
    if let Some(val) = get_client(client, conn)? {
        update_client(client, &val, conn)?;
        Ok(val)
    } else {
        info!(
            "record for {} does not exist, creating",
            client.global.wg_public_key
        );

        let new_ip = get_next_client_ip(conn)?;

        let c = client_to_new_db_client(client, new_ip, user_country);

        info!("Inserting new client {}", client.global.wg_public_key);
        diesel::insert_into(clients).values(&c).execute(conn)?;

        Ok(c)
    }
}
