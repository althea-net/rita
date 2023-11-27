use std::{
    thread,
    time::{Duration, Instant},
};

use clarity::{Address, PrivateKey};
use diesel::{PgConnection, RunQueryDsl};
use rita_client_registration::{
    client_db::{check_and_add_user_admin, get_all_regsitered_clients},
    register_client_batch_loop::register_client_batch_loop,
};
use rita_common::usage_tracker::tests::test::random_identity;
use rita_db_migration::{
    get_database_connection, models::Client, schema::clients::dsl::clients, start_db_migration,
};
use web30::client::Web3;

use crate::{
    payments_eth::{get_eth_miner_key, WEB3_TIMEOUT},
    setup_utils::database::start_postgres,
    utils::{deploy_contracts, get_eth_node, MINER_PRIVATE_KEY},
};

pub const DB_URI: &str = "postgres://postgres@localhost/test";

/// This tests the rita_db_migration binary and veries that clients actually migrate from a postgresql db
/// to a smart contract
pub async fn run_db_migration_test() {
    info!("Starting db migration test");

    info!("Waiting to deploy contracts");
    let althea_db_addr = deploy_contracts().await;
    info!("DB addr is {}", althea_db_addr);

    info!("Starting postrgresql db");
    start_postgres();

    let conn = get_database_connection(DB_URI.to_string()).expect("Please fix db path");

    let num_clients = 10;
    // Add a bunch of dummy clients to the db to migrate
    add_dummy_clients_to_db(num_clients, &conn);

    thread::sleep(Duration::from_secs(10));

    info!("Run migration code");

    let miner_private_key: PrivateKey = get_eth_miner_key();
    // Start registration loop
    info!("Registering user admin");
    // This request needs to be made with the state admin's key
    check_and_add_user_admin(
        &Web3::new(&get_eth_node(), WEB3_TIMEOUT),
        althea_db_addr,
        MINER_PRIVATE_KEY.parse().unwrap(),
        miner_private_key,
        Some(WEB3_TIMEOUT),
        vec![],
    )
    .await
    .expect("Failed to add user admin!");

    thread::sleep(Duration::from_secs(5));

    info!("Starting registration loop");
    register_client_batch_loop(get_eth_node(), althea_db_addr, miner_private_key);

    info!("Running user migration");
    match start_db_migration(
        DB_URI.to_string(),
        get_eth_node(),
        miner_private_key.to_address(),
        althea_db_addr,
    )
    .await
    {
        Ok(_) => println!("Successfully migrated all clients!"),
        Err(e) => println!("Failed to migrate clients with {}", e),
    }

    info!("Waiting for register loop to migrate all clients");
    thread::sleep(Duration::from_secs(10));

    validate_db_migration(num_clients, althea_db_addr, miner_private_key).await;
}

fn add_dummy_clients_to_db(num_of_entries: usize, conn: &PgConnection) {
    for i in 0..num_of_entries {
        let new_client = random_db_client();
        info!("Inserting new client {}: {}", i, new_client.wg_pubkey);
        if let Err(e) = diesel::insert_into(clients)
            .values(&new_client)
            .execute(conn)
        {
            panic!("Why did a client {} insert fail? {}", i, e);
        }
    }
}

fn random_db_client() -> Client {
    let random_id = random_identity();
    Client {
        mesh_ip: random_id.mesh_ip.to_string(),
        wg_pubkey: random_id.wg_public_key.to_string(),
        wg_port: 0,
        eth_address: random_id.eth_address.to_string(),
        internal_ip: "".to_string(),
        internet_ipv6: "".to_string(),
        nickname: "".to_string(),
        email: "".to_string(),
        phone: "".to_string(),
        country: "".to_string(),
        email_code: "".to_string(),
        verified: true,
        email_sent_time: 0,
        text_sent: 0,
        last_balance_warning_time: 0,
        last_seen: 0,
    }
}

async fn validate_db_migration(
    num_clients: usize,
    althea_db_addr: Address,
    miner_private_key: PrivateKey,
) {
    let miner_pub_key = miner_private_key.to_address();
    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);

    let start = Instant::now();
    loop {
        let client_vec = get_all_regsitered_clients(&contact, miner_pub_key, althea_db_addr).await;
        if client_vec.is_err() {
            if Instant::now() - start > Duration::from_secs(300) {
                panic!("Failed to migrate clients after waiting for 5 mins");
            }
            error!("No clients have been registered so far, waiting..",);
            thread::sleep(Duration::from_secs(10));
        } else if let Ok(client_list) = client_vec {
            if client_list.len() == num_clients {
                info!(
                    "All clients have successuflly migrated from postgresql db to smart contract!"
                );
                info!("DB clients are :\n");
                for id in client_list {
                    info!("{}", id);
                }
                break;
            } else {
                if Instant::now() - start > Duration::from_secs(300) {
                    panic!(
                        "Failed to migrate {} clients after waiting for 5 mins. Only migrated {}",
                        num_clients,
                        client_list.len()
                    );
                }
                error!(
                    "{} clients have been registered so far, waiting..",
                    client_list.len()
                );
                thread::sleep(Duration::from_secs(10));
            }
        }
    }
}
