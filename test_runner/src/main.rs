use althea_types::Identity;
use deep_space::Contact;
use integration_tests::config::{
    generate_exit_config_file, generate_rita_config_file, CONFIG_FILE_PATH, EXIT_CONFIG_PATH,
};
use integration_tests::debts::run_debts_test;
/// Binary crate for actually running the integration tests
use integration_tests::five_nodes::run_five_node_test_scenario;
use integration_tests::mutli_exit::run_multi_exit_test;
use integration_tests::payments_eth::{ETH_MINER_KEY, WEB3_TIMEOUT};
use integration_tests::utils::{get_althea_grpc, get_eth_node, TOTAL_TIMEOUT};
use integration_tests::{
    payments_althea::run_althea_payments_test_scenario,
    payments_eth::run_eth_payments_test_scenario, utils::set_sigterm,
};
use log::info;
use rita_client_registration::client_db::{
    add_client_to_registered_list, get_all_regsitered_clients, get_registered_client_using_ethkey,
    get_registered_client_using_meship, get_registered_client_using_wgkey,
};
use std::process::Command;
use std::str::from_utf8;
use std::time::Duration;
use std::{env, thread};
use web30::client::Web3;

extern crate log;

pub const ALTHEA_CHAIN_PREFIX: &str = "althea";
pub const ALTHEA_CONTACT_TIMEOUT: Duration = Duration::from_secs(30);
pub const ETH_NODE: &str = "http://localhost:8545";
pub const MINER_PRIVATE_KEY: &str =
    "0x34d97aaf58b1a81d3ed3068a870d8093c6341cf5d1ef7e6efa03fe7f7fc2c3a8";

#[actix_rt::main]
async fn main() {
    println!("About to init env logger");
    // custom logger filter gives error logs for all modules but info for only the test_runner
    // if you want to see logs for the rita instances you can adjust this per module in Rita by level
    // note this will print logs for all rita instances since they are all in one thread
    env_logger::Builder::default()
        .filter(None, log::LevelFilter::Error)
        .filter(Some("integration_tests"), log::LevelFilter::Info)
        .init();
    set_sigterm();

    println!("Starting the Rita test runner");

    let conf = generate_rita_config_file(CONFIG_FILE_PATH.to_string());
    info!("Generating rita config file: {:?}", conf);
    let conf = generate_exit_config_file(EXIT_CONFIG_PATH.to_string());
    info!("Generating exit config file: {:?}", conf);

    println!("Waiting to deploy contracts");
    deploy_contracts().await;

    // Try adding a dummy entry and validating that we can retrive them
    validate_contract_functionality().await;

    let test_type = env::var("TEST_TYPE");
    info!("Starting tests with {:?}", test_type);
    if let Ok(test_type) = test_type {
        if test_type == "FIVE_NODES" {
            run_five_node_test_scenario().await;
        } else if test_type == "DEBTS_TEST" {
            run_debts_test().await;
        } else if test_type == "PAYMENTS_ETH" || test_type == "ETH_PAYMENTS" {
            run_eth_payments_test_scenario().await;
        } else if test_type == "PAYMENTS_ALTHEA" || test_type == "ALTHEA_PAYMENTS" {
            run_althea_payments_test_scenario().await
        } else if test_type == "MULTI_EXIT" {
            run_multi_exit_test().await
        } else {
            panic!("Error unknown test type {}!", test_type);
        }
    } else {
        panic!("Error test type not set!");
    }
}

pub async fn deploy_contracts() {
    let contact = Contact::new(
        &get_althea_grpc(),
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();
    // prevents the node deployer from failing (rarely) when the chain has not
    // yet produced the next block after submitting each eth address
    contact.wait_for_next_block(TOTAL_TIMEOUT).await.unwrap();

    let res = Command::new("npx")
        .args([
            "ts-node",
            "/althea_rs/solidity/contract-deployer.ts",
            &format!("--eth-privkey={}", MINER_PRIVATE_KEY),
            &format!("--eth-node={}", ETH_NODE),
        ])
        .output()
        .expect("Failed to deploy contracts!");

    println!("Contract deploy returned {:?}", from_utf8(&res.stdout));
}

pub async fn validate_contract_functionality() {
    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);

    // Define the users
    let user = Identity {
        mesh_ip: "fd00::1337".parse().unwrap(),
        eth_address: "0x02ad6b480DFeD806C63a0839C6f1f3136c5fD515"
            .parse()
            .unwrap(),
        wg_public_key: "sPtNGQbyPpCsqSKD6PbnflB1lIUCd259Vhd0mJfJeGo="
            .parse()
            .unwrap(),
        nickname: None,
    };

    let user_2 = Identity {
        mesh_ip: "fd00::1447:1447".parse().unwrap(),
        eth_address: "0x1994A73F79F9648d4a8064D9C0F221fB1007Fd2F"
            .parse()
            .unwrap(),
        wg_public_key: "Yhyj+CKZbyEKea/9hdIFje98yc5Cukt1Pbq0qWB4Aqw="
            .parse()
            .unwrap(),
        nickname: None,
    };

    let user_3 = Identity {
        mesh_ip: "fd00::3000:1117".parse().unwrap(),
        eth_address: "0x9c33D0dFdc9E3f7cC73bE3A575C31cfe3059C76a"
            .parse()
            .unwrap(),
        wg_public_key: "fzOUfEqYzRE0MwfR5o7XV+MKZKj/qEfELRzQTRTKAB8="
            .parse()
            .unwrap(),
        nickname: None,
    };

    // Try requests when there are no users present
    let res = get_all_regsitered_clients(
        &contact,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
    )
    .await
    .unwrap();

    assert!(res.is_empty());

    let res = get_registered_client_using_wgkey(
        user.wg_public_key,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
        &contact,
    )
    .await;

    assert!(res.is_err());

    // Add the first user
    let _res = add_client_to_registered_list(
        &contact,
        user,
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
        ETH_MINER_KEY.parse().unwrap(),
        None,
        vec![],
    )
    .await
    .unwrap();

    thread::sleep(Duration::from_secs(5));

    // Try requesting some info that doesnt exist
    let res = get_registered_client_using_ethkey(
        "0x3d261902a988d94599d7f0Bd4c2e4514D73BB329"
            .parse()
            .unwrap(),
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
        &contact,
    )
    .await;

    assert!(res.is_err());

    // Add the second user
    let _res = add_client_to_registered_list(
        &contact,
        user_2,
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
        ETH_MINER_KEY.parse().unwrap(),
        None,
        vec![],
    )
    .await
    .unwrap();

    thread::sleep(Duration::from_secs(5));

    // Add the third user
    let _res = add_client_to_registered_list(
        &contact,
        user_3,
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
        ETH_MINER_KEY.parse().unwrap(),
        None,
        vec![],
    )
    .await
    .unwrap();

    thread::sleep(Duration::from_secs(10));

    let res = get_all_regsitered_clients(
        &contact,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
    )
    .await;

    println!("All users are : {:?}", res);

    thread::sleep(Duration::from_secs(5));

    let res = get_registered_client_using_wgkey(
        user.wg_public_key,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
        &contact,
    )
    .await
    .unwrap();
    assert_eq!(res, user);

    let res = get_registered_client_using_ethkey(
        user_2.eth_address,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
        &contact,
    )
    .await
    .unwrap();
    assert_eq!(res, user_2);

    let res = get_registered_client_using_meship(
        user_3.mesh_ip,
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
        "0xb9b674D720F96995ca033ec347df080d500c2230"
            .parse()
            .unwrap(),
        &contact,
    )
    .await
    .unwrap();
    assert_eq!(res, user_3);
}
