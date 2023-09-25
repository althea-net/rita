//! This binary is run to have access to a postgresql db, takes its client info and writes it into
//! smart contract. This is necessary setup to move existing registered clients from the previous
//! sql db format to a smart contract

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

use docopt::Docopt;
use log::{error, info};
use rita_client_registration::register_client_batch_loop::register_client_batch_loop;
use rita_db_migration::start_db_migration;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Args {
    pub sql_db_url: String,
    pub address: String,
    pub web3_url: String,
    pub private_key: String,
}

fn main() {
    let args: Args = Docopt::new(get_arg_usage())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let db_url = args.sql_db_url;
    let contract_addr = args
        .address
        .parse()
        .expect("Please provide a valid eth contract addr");
    let web3_url = args.web3_url;
    let private_key = args
        .private_key
        .parse()
        .expect("Please provide a valid eth private key with funds");

    let system = actix_async::System::new();

    // Start registration loop
    register_client_batch_loop(web3_url, contract_addr, private_key);

    match start_db_migration(db_url) {
        Ok(_) => println!("Successfully migrated all clients!"),
        Err(e) => println!("Failed to migrate clients with {}", e),
    }

    if let Err(e) = system.run() {
        error!("Starting Rita DB migration failed with {}", e);
    }
    info!("Started Rita DB migration!");
}

pub fn get_arg_usage() -> String {
    "Usage: rita_db_migration [--db_url=<db_url>] [--address=<address>] [--web3_url=<web3_url>] [--private_key=<private_key>]
Options:
    -u, --db_url=<db_url>           Postgresql db url
    -a, --address=<address>         Smart Contract address
    -w, --web3_url=<web3_url>       Web3 url
    -p, --private_key=<private_key> Our Private key
About: 
    Db migration binary".to_string()
}
