use crate::database::secs_since_unix_epoch;
use crate::database::struct_tools::client_to_new_db_client;
use crate::database::ONE_DAY;
use exit_db::models::AssignedIps;
use ipaddress::IPAddress;
use ipnetwork::IpNetwork;
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
use std::net::IpAddr;
use std::net::Ipv4Addr;

// Subnet size assigned to each client
const CLIENT_SUBNET_SIZE: u8 = 64;

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
            Err(RitaExitError::MiscStringError(
                "We failed to lookup the client!".to_string(),
            ))
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
pub fn text_sent(
    client: &ExitClientIdentity,
    conn: &PgConnection,
    val: i32,
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
pub fn client_conflict(
    client: &ExitClientIdentity,
    conn: &PgConnection,
) -> Result<bool, RitaExitError> {
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

/// Delete a client from the Clients database. Retrieve the reclaimed subnet index and add it to
/// available_subnets in assigned_ips database
pub fn delete_client(client: ExitClient, connection: &PgConnection) -> Result<(), RitaExitError> {
    use self::schema::assigned_ips::dsl::{assigned_ips, available_subnets, subnet};
    use self::schema::clients::dsl::*;
    info!("Deleting clients {:?} in database", client);

    let mesh_ip_string = client.mesh_ip.to_string();
    let statement = clients.find(&mesh_ip_string);

    // Add the reclaimed subnet to available subnets
    let filtered_list = clients
        .select(internet_ipv6)
        .filter(mesh_ip.eq(&mesh_ip_string));
    let mut sub = filtered_list.load::<String>(connection)?;
    if let Some(sub) = sub.pop() {
        let rita_exit = settings::get_rita_exit();
        let exit_settings = rita_exit.exit_network;
        let exit_sub = exit_settings.subnet;
        // This is a valid subnet in database so this unwrap should not panic
        let sub: IpNetwork = sub.parse().expect("Unable to parse subnet in database");
        let index = match generate_index_from_subnet(exit_sub, sub) {
            Ok(a) => a,
            Err(e) => {
                return Err(e);
            }
        };

        info!("Reclaimed index is: {:?}", index);

        let filtered_list = assigned_ips.filter(subnet.eq(sub.to_string()));
        let res = filtered_list.load::<models::AssignedIps>(connection);

        match res {
            Ok(mut a) => {
                if a.len() > 1 {
                    error!("Received multiple assigned ip entries for a singular subnet! Error");
                }
                let a_ip = match a.pop() {
                    Some(a) => a,
                    None => {
                        return Err(RitaExitError::MiscStringError(
                            "Unable to retrive assigned ip database".to_string(),
                        ))
                    }
                };
                let mut avail_ips = a_ip.available_subnets;
                if avail_ips.is_empty() {
                    avail_ips.push_str(&index.to_string())
                } else {
                    // if our index is '10', we need to append ",10" to the end
                    let mut new_str = ",".to_owned();
                    new_str.push_str(&index.to_string());
                    avail_ips.push_str(&new_str);
                }
                info!(
                    "We are updating database with reclaim string: {:?}",
                    avail_ips
                );
                diesel::update(assigned_ips.find(sub.to_string()))
                    .set(available_subnets.eq(avail_ips))
                    .execute(connection)?;
            }
            Err(e) => {
                error!(
                    "unable to add a reclaimed ip to database with error: {:?}",
                    e
                );
            }
        }
    }

    delete(statement).execute(connection)?;
    Ok(())
}

// for backwards compatibility with entires that do not have a timestamp
// new entires will be initialized and updated as part of the normal flow
pub fn set_client_timestamp(
    client: ExitClient,
    connection: &PgConnection,
) -> Result<(), RitaExitError> {
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
        None => return Err(RitaExitError::EmailNotFound(client.clone())),
    };

    diesel::update(clients.filter(email.eq(mail_addr)))
        .set(email_sent_time.eq(secs_since_unix_epoch()))
        .execute(&*conn)?;

    Ok(())
}

/// Gets the Postgres database connection from the threadpool, since there are dedicated
/// connections for each threadpool member error if non is available right away
pub fn get_database_connection(
) -> Result<PooledConnection<ConnectionManager<PgConnection>>, RitaExitError> {
    match DB_POOL.read().unwrap().try_get() {
        Some(connection) => Ok(connection),
        None => {
            error!("No available db connection!");
            Err(RitaExitError::MiscStringError(
                "No Database connection available!".to_string(),
            ))
        }
    }
}

pub fn create_or_update_user_record(
    conn: &PgConnection,
    client: &ExitClientIdentity,
    user_country: String,
) -> Result<models::Client, RitaExitError> {
    use self::schema::clients::dsl::clients;

    // Retrieve exit subnet
    let rita_exit = settings::get_rita_exit();
    let exit_settings = rita_exit.exit_network;
    let subnet = exit_settings.subnet;

    // If subnet isnt already present in database, create it
    let subnet_entry = initialize_subnet_datastore(subnet, conn)?;
    info!("Subnet Database entry: {:?}", subnet_entry);

    if let Some(val) = get_client(client, conn)? {
        update_client(client, &val, conn)?;
        Ok(val)
    } else {
        info!(
            "record for {} does not exist, creating",
            client.global.wg_public_key
        );

        let new_ip = get_next_client_ip(conn)?;

        let internet_ip = get_client_subnet(subnet, subnet_entry, conn)?;

        let c = client_to_new_db_client(client, new_ip, user_country, internet_ip);

        info!("Inserting new client {}", client.global.wg_public_key);
        diesel::insert_into(clients).values(&c).execute(conn)?;

        Ok(c)
    }
}

/// This function creates an entry for the given subnet in the assgined_ips table if doesnt exist
fn initialize_subnet_datastore(
    sub: IpNetwork,
    conn: &PgConnection,
) -> Result<models::AssignedIps, RitaExitError> {
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
            diesel::insert_into(assigned_ips)
                .values(&record)
                .execute(conn)?;
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
                diesel::insert_into(assigned_ips)
                    .values(&record)
                    .execute(conn)?;
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
) -> Result<IpNetwork, RitaExitError> {
    use self::schema::assigned_ips::dsl::{assigned_ips, available_subnets, iterative_index};
    use self::schema::clients::dsl::{clients, internet_ipv6};
    // Get our assigned subnet
    info!("Received Exit assigned ipv6 subnet: {}", sub);

    // Make sql query to get list of all client subnets in use
    // SELECT internet_ipv6 FROM <TABLE>
    let filtered_list = clients.select(internet_ipv6);
    let ip_list = filtered_list.load::<String>(conn)?;

    let mut index: Option<u64> = None;

    // First check for any available subnets to reclaim
    if !ip_tracker.available_subnets.is_empty() {
        // available ips are stored in the form of "1,2,5" etc
        if let Some((remaining, i)) = ip_tracker.available_subnets.rsplit_once(',') {
            // set database available subnets to remainging
            diesel::update(assigned_ips.find(sub.to_string()))
                .set(available_subnets.eq(remaining))
                .execute(conn)?;

            index = match i.parse() {
                Ok(a) => Some(a),
                Err(e) => {
                    return Err(RitaExitError::MiscStringError(format!(
                        "Unable to assign user ipv6 subnet when parsing latest index: {}",
                        e
                    )));
                }
            }
        } else {
            // This is case of singular entry in, for exmaple "2"
            // set database available subnets to ""
            diesel::update(assigned_ips.find(sub.to_string()))
                .set(available_subnets.eq(""))
                .execute(conn)?;

            index = match ip_tracker.available_subnets.parse() {
                Ok(a) => Some(a),
                Err(e) => {
                    return Err(RitaExitError::MiscStringError(format!(
                        "Unable to assign user ipv6 subnet: {}",
                        e
                    )));
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
                return Err(RitaExitError::MiscStringError(format!(
                    "Unable to assign user ipv6 subnet when parsing iterative index: {}",
                    e
                )));
            }
        });
    }

    // Once we get the index, generate the subnet
    match generate_iterative_client_subnet(sub, index.unwrap(), CLIENT_SUBNET_SIZE.into()) {
        Ok(addr) => {
            // increment iterative index
            if used_iterative_index {
                let new_ind = (index.unwrap() + 1) as i64;
                diesel::update(assigned_ips.find(sub.to_string()))
                    .set(iterative_index.eq(new_ind))
                    .execute(conn)?;
            }

            if !ip_list.contains(&addr.to_string()) {
                Ok(addr)
            } else {
                error!("Chosen subnet: {:?} is in use! Race condition hit", addr);
                return Err(RitaExitError::MiscStringError(format!(
                    "Unable to assign user ipv6 subnet. Chosen subnet {:?} is in use",
                    addr
                )));
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
    subprefix: usize,
) -> Result<IpNetwork, RitaExitError> {
    // Convert IpNetwork into IPAdress type
    let network: IPAddress = IPAddress::parse(exit_sub.to_string())
        .expect("Paniced while parsing the exit subnet: IpNetwork -> IPAddress");
    let mut net = network.network();
    net.prefix = net.prefix.from(subprefix).unwrap();

    if subprefix < network.prefix.num {
        return Err(RitaExitError::MiscStringError(
            "Client subnet larger than exit subnet".to_string(),
        ));
    }

    // This is the total number of client subnets available. We are checking that our iterative index
    // is lower than this number. For example, exit subnet: fd00:1000/120, client subnet /124, number of subnets will be
    // 2^(124 - 120) => 2^4 => 16
    if ind < (1 << (subprefix - network.prefix.num)) {
        net = net.from(&net.host_address, &net.prefix);
        let size = net.size();
        net.host_address += ind * size;
        let ret = net
            .to_string()
            .parse()
            .expect("Paniced while parsing exit subnet: IPAdress -> IpNetwork");
        Ok(ret)
    } else {
        error!(
            "Our index is larger than available subnets, either error in logic or no more subnets"
        );
        Err(RitaExitError::MiscStringError(
            "Index larger than available subnets".to_string(),
        ))
    }
}

/// This function takes a larger subnet and a smaller subnet and generates an iterative index of the smaller
/// subnet within the larger subnet
/// For exmaple fd00::1020/124 is the 3rd subnet in fd00::1000/120, so it generates the index '2'
fn generate_index_from_subnet(exit_sub: IpNetwork, sub: IpNetwork) -> Result<u64, RitaExitError> {
    let exit_sub_mig: IPAddress = IPAddress::parse(exit_sub.to_string())
        .expect("Paniced while migrating IpNetwork -> IPAddress");
    let sub_mig: IPAddress =
        IPAddress::parse(sub.to_string()).expect("Paniced while parsing IpNetwork -> IPAddress");

    if exit_sub_mig.size() < sub_mig.size() {
        error!("Invalid subnet sizes");
        return Err(RitaExitError::MiscStringError(
            "Invalid subnet sizes provided to generate_index_from_subnet".to_string(),
        ));
    }
    let size = sub_mig.size();
    let ret = (sub_mig.host_address - exit_sub_mig.host_address) / size;

    Ok(ret
        .to_string()
        .parse::<u64>()
        .expect("Unalbe to parse biguint into u64"))
}

/// This function run on startup initializes databases and other missing fields from the previous database schema
/// for ipv6 support. Existing clients in the previous schema will not have an ipv6 addr assigned, so every client is
/// given one on startup
pub fn initialize_exisitng_clients_ipv6() -> Result<(), RitaExitError> {
    use self::schema::clients::dsl::{clients, internet_ipv6, mesh_ip};
    let conn = get_database_connection()?;

    // initialize the assigned_ips database
    let rita_exit = settings::get_rita_exit();
    let exit_settings = rita_exit.exit_network;
    let subnet = exit_settings.subnet;

    // If subnet isnt already present in database, create it
    let subnet_entry = initialize_subnet_datastore(subnet, &conn)?;
    info!("Subnet Database entry: {:?}", subnet_entry);

    // update all client entries to have an ipv6 addr
    // 1.) get list of mesh ips
    // 2.) for each ip, select ipv6 field, if empty set an ipv6, else continue
    let filtered_list = clients.select(mesh_ip);
    let ip_list = filtered_list.load::<String>(&conn)?;

    for ip in ip_list {
        let filtered_list = clients.select(internet_ipv6).filter(mesh_ip.eq(&ip));
        let mut sub = filtered_list.load::<String>(&conn)?;

        if sub.len() > 1 {
            error!("More than one ipv6 for a given client");
        }

        let ipv6 = sub.pop();
        if ipv6.is_none() || ipv6.clone().unwrap().is_empty() {
            let subnet_entry = initialize_subnet_datastore(subnet, &conn)?;
            let internet_ip = get_client_subnet(subnet, subnet_entry.clone(), &conn)?;
            info!("Initializing ipv6 addrs for existing clients, IP: {}, is given ip {:?}, subnet entry is {:?}", ip, internet_ip.clone(), subnet_entry.clone());
            diesel::update(clients.find(ip))
                .set(internet_ipv6.eq(internet_ip.to_string()))
                .execute(&conn)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test to strings conversions and parsing from IpNetwork -> IPAdress -> IpNetwork
    #[test]
    fn test_ipnetwork_tostring() {
        let ip: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let to_str = ip.to_string();
        println!("network: {}", to_str);

        let ip_ad: IPAddress = IPAddress::parse(to_str).unwrap();
        println!("IPAdress network: {:?}", ip_ad);

        let to_str = ip_ad.to_string();
        println!("network: {}", to_str);

        let ip: IpNetwork = to_str.parse().unwrap();
        println!("IpNetwork network: {:?}", ip);
    }

    /// This checks the functionality of IPAddress 'subnet' function which divides a larger subnet
    /// into individual smaller ones. Source code of this function is used
    #[ignore]
    #[test]
    fn test_subnet_splitting() {
        let ip = IPAddress::parse("2602:FBAD::/40").unwrap();
        println!("we got: {:?}", ip);
        let subnets = ip.subnet(42);
        println!("subners: {:?}", subnets);

        println!("Subnets custom: {:?}", test_subnet_aggregate(ip, 42));
    }

    #[allow(dead_code)]
    fn test_subnet_aggregate(network: IPAddress, subprefix: usize) -> Vec<IPAddress> {
        let mut ret = Vec::new();
        let mut net = network.network();
        for _ in 0..(1 << (subprefix - network.prefix.num)) {
            ret.push(net.clone());
            net = net.from(&net.host_address, &net.prefix);
            let size = net.size();
            net.host_address += size;
        }

        ret
    }

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
        println!("{:?}", vec);

        let vec = str2.rsplit_once(',');
        println!("{:?}", vec);

        let vec = str3.rsplit_once(',');
        println!("{:?}", vec);
    }

    #[test]
    fn test_subnet_to_index() {
        let exit_sub: IpNetwork = "fd00::1000/120".parse().unwrap();
        let sub: IpNetwork = "fd00::1000/124".parse().unwrap();

        let exit_sub_mig: IPAddress = IPAddress::parse(exit_sub.to_string())
            .expect("Paniced while migrating IpNetwork -> IPAddress");
        let sub_mig: IPAddress = IPAddress::parse(sub.to_string())
            .expect("Paniced while parsing IpNetwork -> IPAddress");

        let net = sub_mig.network();
        println!("net: {:?}", net);
        let size = net.size();
        println!("size: {:?}", size);

        let test = (sub_mig.host_address - exit_sub_mig.host_address) / size;
        let a: u64 = test.to_string().parse().unwrap();
        println!("Res: {:?}", a);

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
}
