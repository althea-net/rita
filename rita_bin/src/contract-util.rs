//! This binary is a set of utilities for interacting with the Althea exit infrastructure contract. This contract contains a list of
//! all clients and exits and is used to perform key exchange between both sides. This binary contains a set of utilities for interacting
//! with this contract and performing a variety of tasks.

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

use althea_types::regions::Regions;
use althea_types::ExitIdentity;
use althea_types::Identity;
use althea_types::SystemChain;
use clarity::PrivateKey;
use diesel::RunQueryDsl;
use docopt::Docopt;
use exit_trust_root::client_db::add_exits_to_registration_list;
use exit_trust_root::client_db::add_users_to_registered_list;
use exit_trust_root::client_db::get_all_registered_clients;
use exit_trust_root::register_client_batch_loop::MAX_BATCH_SIZE;
use log::{error, info};
use rita_db_migration::{
    get_database_connection,
    models::{self, Client},
    schema::clients::dsl::clients,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::{process::exit, time::Duration};
use web30::{client::Web3, types::SendTxOption};

const WEB3_TIMEOUT: Duration = Duration::from_secs(15);
pub const TX_TIMEOUT: Duration = Duration::from_secs(60);
const EXIT_REGISTRATION_PORT: u16 = 4875;
const EXIT_WG_LISTEN_PORT: u16 = 59998;

#[derive(Debug, Deserialize)]
pub struct Args {
    pub cmd_migrate: bool,
    pub cmd_add_exit: bool,
    pub flag_dburl: String,
    pub flag_address: String,
    pub flag_web3url: String,
    pub flag_privatekey: String,
}

#[actix_rt::main]
async fn main() {
    env_logger::Builder::default()
        .filter(None, log::LevelFilter::Info)
        .init();

    let args: Args = Docopt::new(get_arg_usage())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let db_url = args.flag_dburl;
    let contract_addr = args
        .flag_address
        .parse()
        .expect("Please provide a valid eth contract addr");
    let private_key: PrivateKey = args
        .flag_privatekey
        .parse()
        .expect("Please provide a valid eth private key with funds");
    let address = private_key.to_address();

    let web3 = Web3::new(&args.flag_web3url, WEB3_TIMEOUT);

    if args.cmd_migrate {
        // get a copy of all existing clients, we do this in order to handle a potential future edgecase where more than one registration server
        // is operating at a time and the same user attempts to register to more than one before the transaction can be sent. Without this check
        // once a already registered user is in the queue all future transactions would fail and the server would no longer operate correctly
        let all_contract_clients =
            match get_all_registered_clients(&web3, address, contract_addr).await {
                Ok(all_clients) => all_clients,
                Err(e) => {
                    panic!("Failed to get list of already registered clients {:?}", e);
                }
            };

        let db_conn = get_database_connection(db_url).unwrap();

        let database_clients_list = clients.load::<models::Client>(&db_conn).unwrap();
        let database_clients_list = clients_to_ids(database_clients_list);

        let mut clients_to_register = Vec::new();
        for client in database_clients_list {
            if !all_contract_clients.contains(&client) {
                clients_to_register.push(client);
                if clients_to_register.len() > MAX_BATCH_SIZE {
                    break;
                }
            }
        }
        // if there is no one once we filter already registered users
        if clients_to_register.is_empty() {
            info!("No new clients to register! Successfully exiting");
            exit(0);
        }
        info!(
            "Starting registration of {} clients",
            clients_to_register.len()
        );

        while !clients_to_register.is_empty() {
            let mut register_batch = Vec::new();

            // build a small batch to register
            while register_batch.len() < MAX_BATCH_SIZE {
                if let Some(client) = clients_to_register.pop() {
                    register_batch.push(client);
                } else {
                    break;
                }
            }

            info!("Prepped user batch sending register tx");
            match add_users_to_registered_list(
                &web3,
                register_batch.clone(),
                contract_addr,
                private_key,
                Some(TX_TIMEOUT),
                vec![
                    SendTxOption::GasPriorityFee(100000000000u128.into()),
                    SendTxOption::GasMaxFee(400000000000u128.into()),
                ],
            )
            .await
            {
                Ok(_) => {
                    info!(
                        "Successfully registered {} clients!",
                        clients_to_register.len()
                    );
                }
                Err(e) => {
                    error!("Failed to register clients with {:?}, will try again!", e);
                    for client in register_batch {
                        clients_to_register.push(client);
                    }
                }
            }
        }
        info!("Successfully migrated all users!");
    } else if args.cmd_add_exit {
        let mut xdai = HashSet::new();
        xdai.insert(SystemChain::Xdai);
        let mut usa = HashSet::new();
        usa.insert(Regions::UnitedStates);

        // This command helps generate the bytes for registering a set of exits
        let exits_to_register = vec![
            ExitIdentity {
                mesh_ip: "fd00::2602:9000".parse().unwrap(),
                wg_key: "4PsEKlDEF8gcj9oXtt3Gi+ZmaGuxBwRMxNJ/ewCZpis="
                    .parse()
                    .unwrap(),
                eth_addr: "0xdE8236B129Ae270B75DED07101727fB03C39AA5F"
                    .parse()
                    .unwrap(),
                registration_port: EXIT_REGISTRATION_PORT,
                wg_exit_listen_port: EXIT_WG_LISTEN_PORT,
                allowed_regions: usa.clone(),
                payment_types: xdai.clone(),
            },
            ExitIdentity {
                mesh_ip: "fd00::2602:3000".parse().unwrap(),
                wg_key: "uNu3IMSgt3SY2+MvtEwjEpx45lOk7q/7sWC3ff80GXE="
                    .parse()
                    .unwrap(),
                eth_addr: "0x72d9E579f691D62aA7e0703840db6dd2fa9fAE21"
                    .parse()
                    .unwrap(),
                registration_port: EXIT_REGISTRATION_PORT,
                wg_exit_listen_port: EXIT_WG_LISTEN_PORT,
                allowed_regions: usa,
                payment_types: xdai,
            },
        ];
        match add_exits_to_registration_list(
            &web3,
            exits_to_register.clone(),
            contract_addr,
            private_key,
            Some(TX_TIMEOUT),
            vec![
                SendTxOption::GasPriorityFee(100000000000u128.into()),
                SendTxOption::GasMaxFee(400000000000u128.into()),
            ],
        )
        .await
        {
            Ok(_) => {
                info!("Successfully registered {} exits!", exits_to_register.len());
            }
            Err(e) => {
                error!("Failed to register exits with {:?}", e);
            }
        }
    }
}

pub fn get_arg_usage() -> String {
    "Usage: 
    contract-util migrate --dburl=<dburl> --address=<address> --web3url=<web3url> --privatekey=<privatekey>
    contract-util add-exit --address=<address> --web3url=<web3url> --privatekey=<privatekey>
    contract-util (-h | --help)

Options:
    -u, --dburl=<dburl>           Postgresql db url
    -a, --address=<address>         Smart Contract address
    -w, --web3url=<web3url>       Web3 url
    -p, --privatekey=<privatekey>     The contract state admin private key

About: 
    Utilities for interacting with the Althea exit database contract".to_string()
}

fn clients_to_ids(client_list: Vec<Client>) -> Vec<Identity> {
    let mut res = Vec::new();
    for c in client_list {
        res.push(Identity {
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
        });
    }
    res
}
