#[macro_use]
extern crate log;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate serde_derive;

pub mod error;
pub mod models;
pub mod schema;

use std::{collections::HashSet, time::Duration};

use crate::schema::clients::dsl::clients;
use althea_types::Identity;
use clarity::Address;
use diesel::{r2d2::ConnectionManager, PgConnection, RunQueryDsl};
use error::RitaDBMigrationError;
use models::Client;
use r2d2::PooledConnection;
use rita_client_registration::{add_client_to_reg_queue, client_db::get_all_regsitered_clients};
use web30::client::Web3;

const WEB3_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn start_db_migration(
    db_url: String,
    web3_url: String,
    requester_address: Address,
    db_addr: Address,
) -> Result<(), RitaDBMigrationError> {
    // Validate that db_url and contract_addr are valid
    if !(db_url.contains("postgres://")
        || db_url.contains("postgresql://")
        || db_url.contains("psql://"))
    {
        panic!("You must provide a valid postgressql database uri!");
    }

    let db_conn = get_database_connection(db_url)?;

    if let Ok(clients_list) = clients.load::<models::Client>(&db_conn) {
        info!(
            "Recieved a valid client list with {} entries",
            clients_list.len()
        );

        let contact = Web3::new(&web3_url, WEB3_TIMEOUT);
        add_clients_to_reg_queue(clients_list, &contact, requester_address, db_addr).await
    } else {
        return Err(RitaDBMigrationError::MiscStringError(
            "Unable to get db clients".to_string(),
        ));
    }

    Ok(())
}

async fn add_clients_to_reg_queue(
    client_list: Vec<Client>,
    contact: &Web3,
    requester_address: Address,
    contract: Address,
) {
    let existing_users: HashSet<Identity> =
        match get_all_regsitered_clients(contact, requester_address, contract).await {
            Ok(a) => HashSet::from_iter(a.iter().cloned()),
            Err(e) => {
                error!(
                    "Failed to get a list of existing users with {}!. Trying to add all users",
                    e
                );
                HashSet::new()
            }
        };

    for c in client_list {
        let id = Identity {
            mesh_ip: match c.mesh_ip.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!("Cannot parse client {:?} mesh ip! with {}", c, e);
                    continue;
                }
            },
            eth_address: match c.eth_address.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!("Cannot parse client {:?} eth addr! with {}", c, e);
                    continue;
                }
            },
            wg_public_key: match c.wg_pubkey.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!("Cannot parse client {:?} wg key! with {}", c, e);
                    continue;
                }
            },
            nickname: None,
        };

        if !existing_users.contains(&id) {
            info!("Adding user {}", id.mesh_ip);
            add_client_to_reg_queue(id);
        } else {
            warn!("User {} already exists!", id.mesh_ip);
        }
    }
}

pub fn get_database_connection(
    db_url: String,
) -> Result<PooledConnection<ConnectionManager<PgConnection>>, RitaDBMigrationError> {
    let manager = ConnectionManager::new(db_url);
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .build(manager)
        .expect("Failed to create pool.");

    match pool.try_get() {
        Some(connection) => Ok(connection),
        None => {
            error!("No available db connection!");
            Err(RitaDBMigrationError::MiscStringError(
                "No Database connection available!".to_string(),
            ))
        }
    }
}
