#[macro_use]
extern crate log;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate serde_derive;

pub mod error;
pub mod models;
pub mod schema;

use crate::schema::clients::dsl::clients;
use althea_types::Identity;
use diesel::{r2d2::ConnectionManager, PgConnection, RunQueryDsl};
use error::RitaDBMigrationError;
use models::Client;
use r2d2::PooledConnection;
use rita_client_registration::add_client_to_reg_batch;

pub fn start_db_migration(db_url: String) -> Result<(), RitaDBMigrationError> {
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

        add_clients_to_reg_queue(clients_list)
    } else {
        return Err(RitaDBMigrationError::MiscStringError(
            "Unable to get db clients".to_string(),
        ));
    }

    Ok(())
}

fn add_clients_to_reg_queue(client_list: Vec<Client>) {
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

        add_client_to_reg_batch(id);
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
