use crate::{
    payments_eth::{TRASACTION_TIMEOUT, WEB3_TIMEOUT},
    setup_utils::database::start_postgres,
    utils::{deploy_contracts, get_eth_node, REGISTRATION_SERVER_KEY},
};
use althea_types::random_identity;
use clarity::{Address, PrivateKey};
use crossbeam::queue::SegQueue;
use diesel::{PgConnection, RunQueryDsl};
use exit_trust_root::{
    client_db::{check_and_add_user_admin, get_all_registered_clients},
    register_client_batch_loop::register_client_batch_loop,
};
use futures::future::{select, Either};
use rita_db_migration::{
    get_database_connection, models::Client, schema::clients::dsl::clients, start_db_migration,
};
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use web30::client::Web3;

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

    let reg_server_key: PrivateKey = REGISTRATION_SERVER_KEY.parse().unwrap();
    // Start registration loop
    info!("Registering user admin");
    // This request needs to be made with the state admin's key
    check_and_add_user_admin(
        &Web3::new(&get_eth_node(), WEB3_TIMEOUT),
        althea_db_addr,
        reg_server_key.to_address(),
        reg_server_key,
        Some(TRASACTION_TIMEOUT),
        vec![],
    )
    .await
    .expect("Failed to add user admin!");

    thread::sleep(Duration::from_secs(5));

    let queue = Arc::new(SegQueue::new());

    info!("Starting registration loop");
    let reg_loop = register_client_batch_loop(get_eth_node(), reg_server_key, queue.clone());

    info!("Running user migration");
    start_db_migration(
        DB_URI.to_string(),
        get_eth_node(),
        reg_server_key.to_address(),
        althea_db_addr,
        queue.clone(),
    )
    .await
    .expect("Failed to start migration!");

    // wait for the timeout while also running the registration loop
    match select(
        Box::pin(validate_db_migration(
            num_clients,
            althea_db_addr,
            reg_server_key,
        )),
        Box::pin(reg_loop),
    )
    .await
    {
        Either::Left((_, _)) => info!("Successfully migrated all clients!"),
        Either::Right((_, _)) => panic!("Registration loop crashed!"),
    };
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
    reg_server_key: PrivateKey,
) {
    let miner_pub_key = reg_server_key.to_address();
    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);

    let start = Instant::now();
    loop {
        let client_vec = get_all_registered_clients(&contact, miner_pub_key, althea_db_addr).await;
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
