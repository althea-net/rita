use crate::database::secs_since_unix_epoch;
use crate::database::struct_tools::client_to_new_db_client;
use crate::database::ONE_DAY;
use exit_db::models::AssignedIps;
use exit_db::schema::clients::althea_address;
use ipnetwork::{IpNetwork, Ipv6Network, NetworkSize};
use rita_common::utils::ip_increment::increment;

use crate::{RitaExitError, DB_POOL};
use althea_kernel_interface::ExitClient;
use althea_types::ExitClientIdentity;
use diesel::dsl::{delete, exists};
use diesel::prelude::{ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl};
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::PooledConnection;
use diesel::select;
use exit_db::{models, schema};
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::net::{IpAddr, Ipv6Addr};

// Default Subnet size assigned to each client
const DEFAULT_CLIENT_SUBNET_SIZE: u8 = 56;

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
pub fn get_next_client_ip(conn: &PgConnection) -> Result<IpAddr, Box<RitaExitError>> {
    use self::schema::clients::dsl::clients;
    let rita_exit = settings::get_rita_exit();
    let exit_settings = rita_exit.exit_network;
    let netmask = exit_settings.netmask;
    let start_ip = exit_settings.exit_start_ip;
    let gateway_ip = exit_settings.own_internal_ip;
    // drop here to free up the settings lock, this codepath runs in parallel
    drop(exit_settings);

    let clients_list = match clients.load::<models::Client>(conn) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };
    let ips_list = get_internal_ips(&clients_list);
    let mut new_ip: IpAddr = start_ip.into();

    // iterate until we find an open spot, yes converting to string and back is quite awkward
    while ips_list.contains({
        match &new_ip.to_string().parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.clone().into())),
        }
    }) {
        new_ip = match increment(new_ip, netmask) {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        };
        if new_ip == gateway_ip {
            new_ip = match increment(new_ip, netmask) {
                Ok(a) => a,
                Err(e) => return Err(Box::new(e.into())),
            }
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
) -> Result<(), Box<RitaExitError>> {
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
            if let Err(e) = diesel::update(filtered_list.clone())
                .set(email.eq(mail))
                .execute(conn)
            {
                return Err(Box::new(e.into()));
            }
        }
    }

    if let Some(number) = client.reg_details.phone.clone() {
        if their_record.phone != number {
            info!(
                "Client {} phonenumber has changed from {} to {} updating",
                their_record.wg_pubkey, their_record.phone, number
            );
            if let Err(e) = diesel::update(filtered_list.clone())
                .set(phone.eq(number))
                .execute(conn)
            {
                return Err(Box::new(e.into()));
            }
        }
    }

    // check if althea address needs to be updated
    if their_record.althea_address.is_empty() && client.global.althea_address.is_some() {
        info!(
            "Updating althea address for client {} to {:?}",
            their_record.wg_pubkey, client.global.althea_address
        );
        if let Err(e) = diesel::update(filtered_list.clone())
            .set(
                althea_address.eq(client
                    .global
                    .althea_address
                    .unwrap()
                    .to_string()
                    .to_lowercase()),
            )
            .execute(conn)
        {
            return Err(Box::new(e.into()));
        }
    }

    let current_time = secs_since_unix_epoch();
    let time_since_last_update = current_time - their_record.last_seen;
    // update every 12 hours, no entry timeouts less than a day allowed
    if time_since_last_update > ONE_DAY / 2 {
        info!("Bumping client timestamp for {}", their_record.wg_pubkey);
        if let Err(e) = diesel::update(filtered_list)
            .set(last_seen.eq(secs_since_unix_epoch()))
            .execute(conn)
        {
            return Err(Box::new(e.into()));
        }
    }

    Ok(())
}

pub fn get_client(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<Option<models::Client>, Box<RitaExitError>> {
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
                let err_msg =
                    format!("More than one exact match with wg: {wg} eth: {key} ip: {ip}");
                error!("{}", err_msg);
                panic!("{}", err_msg);
            } else if entry.is_empty() {
                return Ok(None);
            }
            Ok(Some(entry[0].clone()))
        }
        Err(e) => {
            error!("We failed to lookup the client {:?} with{:?}", mesh_ip, e);
            Err(Box::new(RitaExitError::MiscStringError(
                "We failed to lookup the client!".to_string(),
            )))
        }
    }
}

/// changes a clients verified value in the database
pub fn verify_client(
    client: &ExitClientIdentity,
    client_verified: bool,
    conn: &PgConnection,
) -> Result<(), Box<RitaExitError>> {
    use self::schema::clients::dsl::*;
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));

    if let Err(e) = diesel::update(filtered_list)
        .set(verified.eq(client_verified))
        .execute(conn)
    {
        return Err(Box::new(e.into()));
    }

    Ok(())
}

/// Marks a client as verified in the database
pub fn verify_db_client(
    client: &models::Client,
    client_verified: bool,
    conn: &PgConnection,
) -> Result<(), Box<RitaExitError>> {
    use self::schema::clients::dsl::*;
    let ip = &client.mesh_ip;
    let wg = &client.wg_pubkey;
    let key = &client.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));

    if let Err(e) = diesel::update(filtered_list)
        .set(verified.eq(client_verified))
        .execute(conn)
    {
        return Err(Box::new(e.into()));
    }

    Ok(())
}

/// Increments the text message sent count in the database
pub fn text_sent(
    client: &ExitClientIdentity,
    conn: &PgConnection,
    val: i32,
) -> Result<(), Box<RitaExitError>> {
    use self::schema::clients::dsl::*;
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));

    if let Err(e) = diesel::update(filtered_list)
        .set(text_sent.eq(val + 1))
        .execute(conn)
    {
        return Err(Box::new(e.into()));
    }

    Ok(())
}

fn client_exists(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<bool, Box<RitaExitError>> {
    use self::schema::clients::dsl::*;
    trace!("Checking if client exists");
    let ip = client.global.mesh_ip;
    let wg = client.global.wg_public_key;
    let key = client.global.eth_address;
    let filtered_list = clients
        .filter(mesh_ip.eq(ip.to_string()))
        .filter(wg_pubkey.eq(wg.to_string()))
        .filter(eth_address.eq(key.to_string().to_lowercase()));
    Ok(match select(exists(filtered_list)).get_result(conn) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    })
}

/// True if there is any client with the same eth address, wg key, or ip address already registered
pub fn client_conflict(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<bool, Box<RitaExitError>> {
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
    let althea_key = client.global.althea_address;
    let ip_match = clients.filter(mesh_ip.eq(ip.to_string()));
    let wg_key_match = clients.filter(wg_pubkey.eq(wg.to_string()));
    let eth_address_match = clients.filter(eth_address.eq(key.to_string().to_lowercase()));

    let ip_exists = match select(exists(ip_match)).get_result(conn) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };
    let wg_exists = match select(exists(wg_key_match)).get_result(conn) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };
    let eth_exists = match select(exists(eth_address_match)).get_result(conn) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };

    let althea_exist = match althea_key {
        Some(a) => {
            let althea_address_match =
                clients.filter(althea_address.eq(a.to_string().to_lowercase()));
            match select(exists(althea_address_match)).get_result(conn) {
                Ok(b) => b,
                Err(e) => return Err(Box::new(e.into())),
            }
        }
        None => false,
    };

    info!(
        "Signup conflict ip {} eth {} wg {}",
        ip_exists, eth_exists, wg_exists
    );
    Ok(ip_exists || eth_exists || wg_exists || althea_exist)
}

/// Delete a client from the Clients database. Retrieve the reclaimed subnet index and add it to
/// available_subnets in assigned_ips database
pub fn delete_client(
    client: ExitClient,
    connection: &PgConnection,
) -> Result<(), Box<RitaExitError>> {
    use self::schema::assigned_ips::dsl::{assigned_ips, subnet};
    use self::schema::clients::dsl::*;
    info!("Deleting clients {:?} in database", client);

    let mesh_ip_string = client.mesh_ip.to_string();
    let statement = clients.find(&mesh_ip_string);

    // Add the reclaimed subnet to available subnets
    let filtered_list = clients
        .select(internet_ipv6)
        .filter(mesh_ip.eq(&mesh_ip_string));
    let mut client_sub = match filtered_list.load::<String>(connection) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };

    let filtered_list = assigned_ips.select(subnet);
    let exit_sub = match filtered_list.load::<String>(connection) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };

    if let Some(client_sub) = client_sub.pop() {
        if !client_sub.is_empty() {
            let client_sub: Vec<&str> = client_sub.split(',').collect();
            info!(
                "For reclaiming subnets, exit subs are: {:?} and client subs are {:?}",
                exit_sub, client_sub
            );
            reclaim_all_ip_subnets(client_sub, exit_sub, connection)?;
        }
    }

    if let Err(e) = delete(statement).execute(connection) {
        return Err(Box::new(e.into()));
    };
    Ok(())
}

/// Given a vector of client subnet and exit subnets, reclaim all client subnets into the given exit subnets
/// This relies on the fact that there are no overlapping subnets
/// For example, if client has Ip addrs : "fbad::1000/64,feee::1000/64"
/// The exit subnets in the cluster are fbad::/40, feee::/40, fd00::/40
/// Then fbad::/40 would gain the subnet fbad::1000/64 and feee::/40 would gain the subnet feee::1000/64 as available subnets
/// when the client get deleted from the database. View the unit test below for more examples
fn reclaim_all_ip_subnets(
    client_sub: Vec<&str>,
    exit_sub: Vec<String>,
    conn: &PgConnection,
) -> Result<(), Box<RitaExitError>> {
    use self::schema::assigned_ips::dsl::{assigned_ips, available_subnets, subnet};

    for client_ip in client_sub {
        for exit_ip in &exit_sub {
            let c_net: IpNetwork = client_ip.parse().expect("Unable to parse client subnet");
            let e_net: IpNetwork = exit_ip.parse().expect("Unable to parse exit subnet");
            if e_net.contains(c_net.ip()) {
                let index = generate_index_from_subnet(e_net, c_net)?;
                info!("Reclaimed index is: {:?}", index);

                let filtered_list = assigned_ips.filter(subnet.eq(exit_ip));
                let res = filtered_list.load::<models::AssignedIps>(conn);

                match res {
                    Ok(mut a) => {
                        if a.len() > 1 {
                            error!("Received multiple assigned ip entries for a singular subnet! Error");
                        }
                        let a_ip = match a.pop() {
                            Some(a) => a,
                            None => {
                                return Err(Box::new(RitaExitError::MiscStringError(
                                    "Unable to retrive assigned ip database".to_string(),
                                )))
                            }
                        };
                        let mut avail_ips = a_ip.available_subnets;
                        if avail_ips.is_empty() {
                            avail_ips.push_str(&index.to_string())
                        } else {
                            // if our index is '10', we need to append ",10" to the end
                            let mut new_str = ",".to_owned();
                            new_str.push_str(&index.to_string());
                            // If avail_ips does not contains '"," + "index"' and (avail ips has only one entry and does not contains 'index')
                            if !(avail_ips.contains(&new_str)
                                || (!avail_ips.contains(',')
                                    && avail_ips.contains(&index.to_string())))
                            {
                                avail_ips.push_str(&new_str);
                            } else {
                                error!("IPV6 ERROR: We tried adding {:?} to string {:?}, how did we get in this position?", index, avail_ips);
                            }
                        }
                        info!(
                            "We are updating database with reclaim string: {:?}",
                            avail_ips
                        );
                        if let Err(e) = diesel::update(assigned_ips.find(exit_ip))
                            .set(available_subnets.eq(avail_ips))
                            .execute(conn)
                        {
                            return Err(Box::new(e.into()));
                        };
                    }
                    Err(e) => {
                        error!(
                            "unable to add a reclaimed ip to database with error: {:?}",
                            e
                        );
                    }
                }

                // After we reclaim an index, we break from the loop. The prevents duplicate reclaiming when two instances have the same subnet
                break;
            }
        }
    }

    Ok(())
}

// for backwards compatibility with entires that do not have a timestamp
// new entires will be initialized and updated as part of the normal flow
pub fn set_client_timestamp(
    client: ExitClient,
    connection: &PgConnection,
) -> Result<(), Box<RitaExitError>> {
    use self::schema::clients::dsl::*;
    info!("Setting timestamp for client {:?}", client);

    if let Err(e) = diesel::update(clients.find(&client.mesh_ip.to_string()))
        .set(last_seen.eq(secs_since_unix_epoch()))
        .execute(connection)
    {
        return Err(Box::new(e.into()));
    };
    Ok(())
}

// we match on email not key? that has interesting implications for
// shared emails
pub fn update_mail_sent_time(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<(), Box<RitaExitError>> {
    use self::schema::clients::dsl::{clients, email, email_sent_time};
    let mail_addr = match client.clone().reg_details.email {
        Some(mail) => mail,
        None => {
            return Err(Box::new(RitaExitError::EmailNotFound(Box::new(
                client.clone(),
            ))))
        }
    };

    if let Err(e) = diesel::update(clients.filter(email.eq(mail_addr)))
        .set(email_sent_time.eq(secs_since_unix_epoch()))
        .execute(conn)
    {
        return Err(Box::new(e.into()));
    };

    Ok(())
}

/// Gets the Postgres database connection from the threadpool, since there are dedicated
/// connections for each threadpool member error if non is available right away
pub fn get_database_connection(
) -> Result<PooledConnection<ConnectionManager<PgConnection>>, Box<RitaExitError>> {
    match DB_POOL.read().unwrap().try_get() {
        Some(connection) => Ok(connection),
        None => {
            error!("No available db connection!");
            Err(Box::new(RitaExitError::MiscStringError(
                "No Database connection available!".to_string(),
            )))
        }
    }
}

pub fn create_or_update_user_record(
    conn: &PgConnection,
    client: &ExitClientIdentity,
    user_country: String,
) -> Result<models::Client, Box<RitaExitError>> {
    use self::schema::clients::dsl::clients;

    // Retrieve exit subnet
    let rita_exit = settings::get_rita_exit();
    let exit_settings = rita_exit.exit_network;
    let subnet = exit_settings.subnet;

    // If subnet isnt already present in database, create it
    let mut subnet_entry = None;
    if let Some(subnet) = subnet {
        subnet_entry = Some(initialize_subnet_datastore(subnet, conn)?);
        info!("Subnet Database entry: {:?}", subnet_entry);
    }

    if let Some(val) = get_client(client, conn)? {
        // Give ipv6 if not present
        if let Some(subnet) = subnet {
            assign_ip_to_client(val.mesh_ip.clone(), subnet, conn)?;
        }
        update_client(client, &val, conn)?;
        Ok(val)
    } else {
        info!(
            "record for {} does not exist, creating",
            client.global.wg_public_key
        );

        let new_ip = get_next_client_ip(conn)?;

        let internet_ip = if let (Some(subnet), Some(subnet_entry)) = (subnet, subnet_entry) {
            Some(get_client_subnet(subnet, subnet_entry, conn)?)
        } else {
            None
        };

        let c = client_to_new_db_client(client, new_ip, user_country, internet_ip);

        info!("Inserting new client {}", client.global.wg_public_key);
        if let Err(e) = diesel::insert_into(clients).values(&c).execute(conn) {
            return Err(Box::new(e.into()));
        }

        Ok(c)
    }
}

/// This function creates an entry for the given subnet in the assgined_ips table if doesnt exist
fn initialize_subnet_datastore(
    sub: IpNetwork,
    conn: &PgConnection,
) -> Result<models::AssignedIps, Box<RitaExitError>> {
    use self::schema::assigned_ips::dsl::{assigned_ips, subnet};
    let filtered_list = assigned_ips.filter(subnet.eq(sub.to_string()));
    match filtered_list.load::<models::AssignedIps>(conn) {
        Err(_) => {
            // When there is no entry create an entry in the database
            let record = AssignedIps {
                subnet: sub.to_string(),
                available_subnets: "".to_string(),
                iterative_index: 0,
            };
            if let Err(e) = diesel::insert_into(assigned_ips)
                .values(&record)
                .execute(conn)
            {
                return Err(Box::new(e.into()));
            };
            Ok(record)
        }
        Ok(mut a) => {
            // There is an entry in the database. If the entry is just an empty vector, create a new entry
            // else, pop the vector (should be only 1 entry) and return it
            if a.len() > 1 {
                error!("More than one entry for singular subnet in database, please fix");
            } else if a.is_empty() {
                let record = AssignedIps {
                    subnet: sub.to_string(),
                    available_subnets: "".to_string(),
                    iterative_index: 0,
                };
                info!("Received an empty vector, adding new subnet entry");
                if let Err(e) = diesel::insert_into(assigned_ips)
                    .values(&record)
                    .execute(conn)
                {
                    return Err(Box::new(e.into()));
                };
                return Ok(record);
            }
            Ok(a.pop().unwrap())
        }
    }
}

/// This function finds an available ipv6 subnet for a client that connects. It works as follows:
/// 1.) Take assigned subnet and client configured subnet length (currently hardcoded to CLIENT_SUBNET_LENGTH)
/// 2.) Retreive all active subnets from database
/// 3.) Retrieve assigned_ips struct from database table for given exit subnet. Check for any available subnet index
/// 4.) If not get the subnets next iterative index instead
/// 5.) Use this index to retrieve the 'ith' iterative subnet in the larger subnet
/// Max Iterative index should theoretically never be reached because we choose subnets from deleted clients before generating
/// an iterative subnet
pub fn get_client_subnet(
    sub: IpNetwork,
    ip_tracker: AssignedIps,
    conn: &PgConnection,
) -> Result<IpNetwork, Box<RitaExitError>> {
    use self::schema::assigned_ips::dsl::{assigned_ips, available_subnets, iterative_index};
    use self::schema::clients::dsl::{clients, internet_ipv6};
    // Get our assigned subnet
    info!("Received Exit assigned ipv6 subnet: {}", sub);

    // Make sql query to get list of all client subnets in use
    // SELECT internet_ipv6 FROM <TABLE>
    let filtered_list = clients.select(internet_ipv6);
    let ip_list = match filtered_list.load::<String>(conn) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };

    let mut index: Option<u64> = None;

    // First check for any available subnets to reclaim
    if !ip_tracker.available_subnets.is_empty() {
        // available ips are stored in the form of "1,2,5" etc
        if let Some((remaining, i)) = ip_tracker.available_subnets.rsplit_once(',') {
            // set database available subnets to remainging
            if let Err(e) = diesel::update(assigned_ips.find(sub.to_string()))
                .set(available_subnets.eq(remaining))
                .execute(conn)
            {
                return Err(Box::new(e.into()));
            };

            index = match i.parse() {
                Ok(a) => Some(a),
                Err(e) => {
                    return Err(Box::new(RitaExitError::MiscStringError(format!(
                        "Unable to assign user ipv6 subnet when parsing latest index: {e}"
                    ))));
                }
            }
        } else {
            // This is case of singular entry in, for exmaple "2"
            // set database available subnets to ""
            if let Err(e) = diesel::update(assigned_ips.find(sub.to_string()))
                .set(available_subnets.eq(""))
                .execute(conn)
            {
                return Err(Box::new(e.into()));
            };

            index = match ip_tracker.available_subnets.parse() {
                Ok(a) => Some(a),
                Err(e) => {
                    return Err(Box::new(RitaExitError::MiscStringError(format!(
                        "Unable to assign user ipv6 subnet: {e}"
                    ))));
                }
            }
        }
    }

    let mut used_iterative_index = false;
    // Next get iterative index to generate next subnet. If index is not already set from available subnets, set it here from database
    if index.is_none() {
        used_iterative_index = true;
        index = Some(match ip_tracker.iterative_index.try_into() {
            Ok(a) => a,
            Err(e) => {
                return Err(Box::new(RitaExitError::MiscStringError(format!(
                    "Unable to assign user ipv6 subnet when parsing iterative index: {e}"
                ))));
            }
        });
    }

    // Once we get the index, generate the subnet
    match generate_iterative_client_subnet(
        sub,
        index.unwrap(),
        settings::get_rita_exit()
            .get_client_subnet_size()
            .unwrap_or(DEFAULT_CLIENT_SUBNET_SIZE),
    ) {
        Ok(addr) => {
            // increment iterative index
            if used_iterative_index {
                let new_ind = (index.unwrap() + 1) as i64;
                if let Err(e) = diesel::update(assigned_ips.find(sub.to_string()))
                    .set(iterative_index.eq(new_ind))
                    .execute(conn)
                {
                    return Err(Box::new(e.into()));
                };
            }

            // ip_list is a vector of a list of ipaddrs, so we check each ipaddr to see if it is already used
            if !ip_list
                .iter()
                .any(|ipv6_list| ipv6_list.contains(&addr.to_string()))
            {
                Ok(addr)
            } else {
                error!("Chosen subnet: {:?} is in use! Race condition hit", addr);
                Err(Box::new(RitaExitError::MiscStringError(format!(
                    "Unable to assign user ipv6 subnet. Chosen subnet {addr:?} is in use"
                ))))
            }
        }
        Err(e) => {
            error!(
                "Unable to retrieve an available ipv6 subnet for client: {}",
                e
            );
            Err(e)
        }
    }
}

/// Take an index i, a larger subnet and a smaller subnet length and generate the ith smaller subnet in the larger subnet
/// For instance, if our larger subnet is fd00::1330/120, smaller sub len is 124, and index is 1, our generated subnet would be fd00::1310/124
fn generate_iterative_client_subnet(
    exit_sub: IpNetwork,
    ind: u64,
    subprefix: u8,
) -> Result<IpNetwork, Box<RitaExitError>> {
    let net;

    // Covert the subnet's ip address into a u128 integer to allow for easy iterative
    // addition operations. To this u128, we add (interative_index * client_subnet_size)
    // and convert this result into an ipv6 addr. This is the starting ip in the client subnet
    //
    // For example, if we have exit subnet: fbad::1000/120, client subnet size is 124, index is 1
    // we do (fbad::1000).to_int() + (16 * 1) = fbad::1010/124 is the client subnet
    let net_as_int: u128 = if let IpAddr::V6(addr) = exit_sub.network() {
        net = Ipv6Network::new(addr, subprefix).unwrap();
        addr.into()
    } else {
        return Err(Box::new(RitaExitError::MiscStringError(
            "Exit subnet expected to be ipv6!!".to_string(),
        )));
    };

    if subprefix < exit_sub.prefix() {
        return Err(Box::new(RitaExitError::MiscStringError(
            "Client subnet larger than exit subnet".to_string(),
        )));
    }

    // This bitshifting is the total number of client subnets available. We are checking that our iterative index
    // is lower than this number. For example, exit subnet: fd00:1000/120, client subnet /124, number of subnets will be
    // 2^(124 - 120) => 2^4 => 16
    if ind < (1 << (subprefix - exit_sub.prefix())) {
        let ret = net_as_int + (ind as u128 * net.size());
        let v6addr = Ipv6Addr::from(ret);
        let ret = IpNetwork::from(match Ipv6Network::new(v6addr, subprefix) {
            Ok(a) => a,
            Err(e) => {
                return Err(Box::new(RitaExitError::MiscStringError(format!(
                    "Unable to parse a valid client subnet: {e:?}"
                ))))
            }
        });

        Ok(ret)
    } else {
        error!(
            "Our index is larger than available subnets, either error in logic or no more subnets"
        );
        Err(Box::new(RitaExitError::MiscStringError(
            "Index larger than available subnets".to_string(),
        )))
    }
}

/// This function takes a larger subnet and a smaller subnet and generates an iterative index of the smaller
/// subnet within the larger subnet
/// For exmaple fd00::1020/124 is the 3rd subnet in fd00::1000/120, so it generates the index '2'
fn generate_index_from_subnet(
    exit_sub: IpNetwork,
    sub: IpNetwork,
) -> Result<u64, Box<RitaExitError>> {
    if exit_sub.size() < sub.size() {
        error!("Invalid subnet sizes");
        return Err(Box::new(RitaExitError::MiscStringError(
            "Invalid subnet sizes provided to generate_index_from_subnet".to_string(),
        )));
    }

    let size: u128 = if let NetworkSize::V6(a) = sub.size() {
        a
    } else {
        return Err(Box::new(RitaExitError::MiscStringError(
            "Exit Subnet needs to be ipv6!!".to_string(),
        )));
    };
    let exit_sub_int: u128 = if let IpAddr::V6(addr) = exit_sub.ip() {
        addr.into()
    } else {
        return Err(Box::new(RitaExitError::MiscStringError(
            "Exit Subnet needs to be ipv6!!".to_string(),
        )));
    };

    let sub_int: u128 = if let IpAddr::V6(addr) = sub.ip() {
        addr.into()
    } else {
        return Err(Box::new(RitaExitError::MiscStringError(
            "Exit Subnet needs to be ipv6!!".to_string(),
        )));
    };

    let ret: u128 = (sub_int - exit_sub_int) / size;

    Ok(ret as u64)
}

/// This function run on startup initializes databases and other missing fields from the previous database schema
/// for ipv6 support. Existing clients in the previous schema will not have an ipv6 addr assigned, so every client is
/// given one on startup
pub fn initialize_exisitng_clients_ipv6() -> Result<(), Box<RitaExitError>> {
    use self::schema::clients::dsl::{clients, mesh_ip};
    let conn = get_database_connection()?;

    // initialize the assigned_ips database
    let rita_exit = settings::get_rita_exit();
    let exit_settings = rita_exit.exit_network;
    let subnet = exit_settings.subnet;

    if let Some(subnet) = subnet {
        // If subnet isnt already present in database, create it
        let subnet_entry = initialize_subnet_datastore(subnet, &conn)?;
        info!("Subnet Database entry: {:?}", subnet_entry);

        // update all client entries to have an ipv6 addr
        // 1.) get list of mesh ips
        // 2.) for each ip, select ipv6 field, if empty set an ipv6, else continue
        let filtered_list = clients.select(mesh_ip);
        let ip_list = match filtered_list.load::<String>(&conn) {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        };

        for ip in ip_list {
            assign_ip_to_client(ip, subnet, &conn)?;
        }
    }

    Ok(())
}

/// This function updates the clients database with an added entry in the internet ipv6 field
/// that stores client ipv6 addrs. ipv6 addrs are stored in the form of "fd00:1330/64,fde0::1100/40" etc
/// with a comma being the delimiter
fn assign_ip_to_client(
    client_mesh_ip: String,
    exit_sub: IpNetwork,
    conn: &PgConnection,
) -> Result<IpNetwork, Box<RitaExitError>> {
    // check if ipv6 list already has an ip in its subnet
    use self::schema::clients::dsl::{clients, internet_ipv6, mesh_ip};

    let filtered_list = clients
        .select(internet_ipv6)
        .filter(mesh_ip.eq(&client_mesh_ip));
    let mut sub = match filtered_list.load::<String>(conn) {
        Ok(a) => a,
        Err(e) => return Err(Box::new(e.into())),
    };

    let client_ipv6_list = sub.pop();

    if let Some(mut list_str) = client_ipv6_list {
        if !list_str.is_empty() {
            let list: Vec<&str> = list_str.split(',').collect();
            for ipv6_str in list {
                let ipv6_sub: IpNetwork =
                    ipv6_str.parse().expect("Unable to parse ipnetwork subnet");
                // Since there are no overlapping subnets, If the ip is in the subnet, so is the ip subnet
                if exit_sub.contains(ipv6_sub.ip()) {
                    return Ok(ipv6_sub);
                }
            }
            // If code hasnt returned yet, we need to add the ip to the list
            let subnet_entry = initialize_subnet_datastore(exit_sub, conn)?;
            let internet_ip = get_client_subnet(exit_sub, subnet_entry.clone(), conn)?;
            let mut new_str = ",".to_owned();
            new_str.push_str(&internet_ip.to_string());
            list_str.push_str(&new_str);
            info!("Initializing ipv6 addrs for existing clients, IP: {}, is given ip {:?}, subnet entry is {:?}", client_mesh_ip, list_str.clone(), subnet_entry);
            if let Err(e) = diesel::update(clients.find(client_mesh_ip))
                .set(internet_ipv6.eq(list_str))
                .execute(conn)
            {
                return Err(Box::new(e.into()));
            };
            Ok(internet_ip)
        } else {
            // List is empty
            let subnet_entry = initialize_subnet_datastore(exit_sub, conn)?;
            let internet_ip = get_client_subnet(exit_sub, subnet_entry.clone(), conn)?;
            info!("Initializing ipv6 addrs for existing clients, IP: {}, is given ip {:?}, subnet entry is {:?}", client_mesh_ip, internet_ip.clone(), subnet_entry);
            if let Err(e) = diesel::update(clients.find(client_mesh_ip))
                .set(internet_ipv6.eq(internet_ip.to_string()))
                .execute(conn)
            {
                return Err(Box::new(e.into()));
            };
            Ok(internet_ip)
        }
    } else {
        // The client doesnt not have an appropriate ipv6 addr for our subnet, assign it one
        let subnet_entry = initialize_subnet_datastore(exit_sub, conn)?;
        let internet_ip = get_client_subnet(exit_sub, subnet_entry.clone(), conn)?;
        info!("Initializing ipv6 addrs for existing clients, IP: {}, is given ip {:?}, subnet entry is {:?}", client_mesh_ip, internet_ip.clone(), subnet_entry);
        if let Err(e) = diesel::update(clients.find(client_mesh_ip))
            .set(internet_ipv6.eq(internet_ip.to_string()))
            .execute(conn)
        {
            return Err(Box::new(e.into()));
        };
        Ok(internet_ip)
    }
}

/// Given a database client entry, get ipnetwork string ("fd00::1337,f100:1400") find the correct ipv6 address to send back to client corresponding to our exit instance
pub fn get_client_ipv6(
    their_record: &models::Client,
) -> Result<Option<IpNetwork>, Box<RitaExitError>> {
    let client_subs = &their_record.internet_ipv6;
    let client_mesh_ip = &their_record.mesh_ip;

    let rita_exit = settings::get_rita_exit();
    let exit_settings = rita_exit.exit_network;
    let exit_sub = exit_settings.subnet;

    if let Some(exit_sub) = exit_sub {
        if !client_subs.is_empty() {
            let c_sub: Vec<&str> = client_subs.split(',').collect();
            for sub in c_sub {
                let c_net: IpNetwork = sub.parse().expect("Unable to parse client subnet");
                if exit_sub.contains(c_net.ip()) {
                    return Ok(Some(c_net));
                }
            }
        }

        // If no ip has been returned, an ip has not been setup, so we assign an ip in the database
        let conn = get_database_connection()?;
        let ip_net = assign_ip_to_client(client_mesh_ip.to_string(), exit_sub, &conn)?;
        Ok(Some(ip_net))
    } else {
        // This exit doesnt support ipv6
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test iterative subnet generation
    #[test]
    fn test_generate_iterative_subnet() {
        // Complex subnet example
        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 64);
        assert_eq!("2602:FBAD::/64".parse::<IpNetwork>().unwrap(), ret.unwrap());

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 1, 64);
        assert_eq!(
            "2602:FBAD:0:1::/64".parse::<IpNetwork>().unwrap(),
            ret.unwrap()
        );

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 50, 64);
        assert_eq!(
            "2602:FBAD:0:32::/64".parse::<IpNetwork>().unwrap(),
            ret.unwrap()
        );

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 2_u64.pow(24), 64);
        assert!(ret.is_err());

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 30);
        assert!(ret.is_err());

        // Simple subnet example
        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 124);
        assert_eq!("fd00::1300/124".parse::<IpNetwork>().unwrap(), ret.unwrap());

        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 2, 124);
        assert_eq!("fd00::1320/124".parse::<IpNetwork>().unwrap(), ret.unwrap());

        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 15, 124);
        assert_eq!("fd00::13f0/124".parse::<IpNetwork>().unwrap(), ret.unwrap());

        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 16, 124);
        assert!(ret.is_err());
    }

    #[test]
    fn test_reclaiming_ips() {
        let str = "";
        let str2 = "2";
        let str3 = "1,2,5,10,92";
        let vec = str.rsplit_once(',');
        println!("{vec:?}");

        let vec = str2.rsplit_once(',');
        println!("{vec:?}");

        let vec = str3.rsplit_once(',');
        println!("{vec:?}");
    }

    #[test]
    fn test_subnet_to_index() {
        let sub: IpNetwork = "fd00::1000/124".parse().unwrap();

        let net = sub.network();
        println!("net: {net:?}");
        let size = sub.size();
        println!("size: {size:?}");

        let exit_sub: IpNetwork = "fd00::1000/120".parse().unwrap();
        let sub: IpNetwork = "fd00::1060/124".parse().unwrap();
        assert_eq!(generate_index_from_subnet(exit_sub, sub).unwrap(), 6);

        let exit_sub: IpNetwork = "fd00::1000/120".parse().unwrap();
        let sub: IpNetwork = "fd00::1060/128".parse().unwrap();
        assert_eq!(generate_index_from_subnet(exit_sub, sub).unwrap(), 96);

        let exit_sub: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let sub: IpNetwork = "2602:FBAD:0:32::/64".parse().unwrap();
        assert_eq!(generate_index_from_subnet(exit_sub, sub).unwrap(), 50);
    }

    #[test]
    fn test_assignment_ipv6_to_client_logic() {
        // TEST CASE 1
        // let client_ipv6_list = Some("fbad::1330/64,fedd::1000/64".to_string());
        // let exit_sub: IpNetwork = "fbad::1330/40".parse().unwrap();

        // TEST CASE 2
        let client_ipv6_list = Some("fbad::1330/64,fedd::1000/64".to_string());
        let exit_sub: IpNetwork = "feee::1330/40".parse().unwrap();

        // TEST CASE 3
        // let client_ipv6_list = Some("".to_string());
        // let exit_sub: IpNetwork = "fbad::1330/40".parse().unwrap();

        // TEST CASE 4
        // let client_ipv6_list: Option<String> = None;
        // let exit_sub: IpNetwork = "fbad::1330/40".parse().unwrap();

        if let Some(mut list_str) = client_ipv6_list {
            if !list_str.is_empty() {
                let list: Vec<&str> = list_str.split(',').collect();
                println!("List looks like: {list:?}");
                for ipv6_str in list {
                    let ipv6_sub: IpNetwork =
                        ipv6_str.parse().expect("Unable to parse ipnetwork subnet");
                    // Since there are no overlapping subnets, If the ip is in the subnet, so is the ip subnet
                    if exit_sub.contains(ipv6_sub.ip()) {
                        println!("Hit Test case 1");
                        return;
                    }
                }
                // If code hasnt returned yet, we need to add the ip to the list
                let internet_ip: IpNetwork = "feee::1000/64".parse().unwrap();
                let mut new_str = ",".to_owned();
                new_str.push_str(&internet_ip.to_string());
                list_str.push_str(&new_str);
                println!("list_str looks like: {list_str:?}");
                println!("hit test case 2");
            } else {
                // List is empty
                println!("Hit Test case 3");
            }
        } else {
            // The client doesnt not have an appropriate ipv6 addr for our subnet, assign it one
            println!("hit Test case 4");
        }
    }

    #[test]
    fn test_get_client_ipv6() {
        let client_subs = "fbad::1000/64";
        let exit_sub: Option<IpNetwork> = Some("fbad::1000/40".parse().unwrap());
        assert_eq!(
            get_client_ipv6_helper(client_subs.to_string(), exit_sub),
            Some(client_subs.parse().unwrap())
        );

        let client_subs = "";
        let exit_sub: Option<IpNetwork> = Some("fbad::1000/40".parse().unwrap());
        assert_eq!(
            get_client_ipv6_helper(client_subs.to_string(), exit_sub),
            Some("fbad::1000/64".parse().unwrap())
        );

        let client_subs = "feee::1000/64";
        let exit_sub: Option<IpNetwork> = Some("fbad::1000/40".parse().unwrap());
        assert_eq!(
            get_client_ipv6_helper(client_subs.to_string(), exit_sub),
            Some("fbad::1000/64".parse().unwrap())
        );

        let client_subs = "feee::1000/64,fbad::1000/64";
        let exit_sub: Option<IpNetwork> = Some("fbad::1000/40".parse().unwrap());
        assert_eq!(
            get_client_ipv6_helper(client_subs.to_string(), exit_sub),
            Some("fbad::1000/64".parse().unwrap())
        );
    }

    fn get_client_ipv6_helper(
        client_subs: String,
        exit_sub: Option<IpNetwork>,
    ) -> Option<IpNetwork> {
        if let Some(exit_sub) = exit_sub {
            if !client_subs.is_empty() {
                let c_sub: Vec<&str> = client_subs.split(',').collect();
                for sub in c_sub {
                    let c_net: IpNetwork = sub.parse().expect("Unable to parse client subnet");
                    if exit_sub.contains(c_net.ip()) {
                        return Some(c_net);
                    }
                }
            }
            // If no ip has been returned, an ip has not been setup, so we assign an ip in the database
            let ip_net: IpNetwork = "fbad::1000/64".parse().unwrap();
            Some(ip_net)
        } else {
            // This exit doesnt support ipv6
            None
        }
    }

    #[test]
    fn test_reclaim_all_subnets() {
        //Case 1: no ipv6 instances, should panic
        // let client_sub = vec![""];
        // let exit_sub = vec!["".to_string()];
        // reclaim_all_subnets_helper(client_sub, exit_sub);

        //Case 2: One ipv6 instance
        let client_sub = vec!["fbad::1000/64"];
        let exit_sub = vec!["fbad::1000/40".to_string()];
        reclaim_all_subnets_helper(client_sub, exit_sub);

        //Case 3: Two ipv6 instances, same subnet (invalid case, there shouldnt be two client subs for 1 exit sub)
        let client_sub = vec!["fbad::1000/64", "fbad::eeee/64"];
        let exit_sub = vec!["fbad::1000/40".to_string()];
        reclaim_all_subnets_helper(client_sub, exit_sub);

        //Case 3: Two ipv6 instances, same subnet (invalid case, no overlapping subnets)
        let client_sub = vec!["fbad::1000/64"];
        let exit_sub = vec!["fbad::1000/40".to_string(), "fbad::1000/50".to_string()];
        reclaim_all_subnets_helper(client_sub, exit_sub);

        //Case 4: Two ipv6 instances, different subnet
        let client_sub = vec!["fbad::1000/64", "feee::eeee/64"];
        let exit_sub = vec!["fbad::1000/40".to_string(), "feee::1000/40".to_string()];
        reclaim_all_subnets_helper(client_sub, exit_sub);
    }

    fn reclaim_all_subnets_helper(client_sub: Vec<&str>, exit_sub: Vec<String>) {
        for client_ip in client_sub {
            for exit_ip in &exit_sub {
                let c_net: IpNetwork = client_ip.parse().expect("Unable to parse client subnet");
                let e_net: IpNetwork = exit_ip.parse().expect("Unable to parse exit subnet");
                if e_net.contains(c_net.ip()) {
                    println!("reclaiming client {c_net:?} to exit sub {e_net:?}");

                    // After we reclaim an index, we break from the loop. The prevents duplicate reclaiming when two instances have the same subnet
                    break;
                }
            }
        }
    }

    #[test]
    fn test_playground() {
        let a = generate_index_from_subnet(
            "2000:fbad:10::/45".parse().unwrap(),
            "2000:fbad:10:1450::/60".parse().unwrap(),
        );

        println!("{a:?}");

        let client_ipv6 = "2602:fbad:0:2340::/60,2602:fbad:10:2500::/60";
        let client_sub: Vec<&str> = client_ipv6.split(',').collect();
        println!("{client_sub:?}");
        let exit_sub = vec![
            "2602:fbad:10::/45".to_string(),
            "2602:fbad::/45".to_string(),
        ];

        reclaim_all_subnets_helper(client_sub, exit_sub);
    }
}
