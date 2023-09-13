use integration_tests::config::{
    generate_exit_config_file, generate_rita_config_file, CONFIG_FILE_PATH, EXIT_CONFIG_PATH,
};
use integration_tests::contract_test::run_altheadb_contract_test;
use integration_tests::debts::run_debts_test;
/// Binary crate for actually running the integration tests
use integration_tests::five_nodes::run_five_node_test_scenario;
use integration_tests::mutli_exit::run_multi_exit_test;
use integration_tests::registration_server::start_registration_server;
use integration_tests::utils::deploy_contracts;
use integration_tests::{
    payments_althea::run_althea_payments_test_scenario,
    payments_eth::run_eth_payments_test_scenario, utils::set_sigterm,
};
use log::info;

use std::env;

use std::time::Duration;

extern crate log;

pub const ALTHEA_CHAIN_PREFIX: &str = "althea";
pub const ALTHEA_CONTACT_TIMEOUT: Duration = Duration::from_secs(30);

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

    println!("Starting registration server");
    start_registration_server();

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
        } else if test_type == "CONTRACT_TEST" {
            run_altheadb_contract_test().await
        } else {
            panic!("Error unknown test type {}!", test_type);
        }
    } else {
        panic!("Error test type not set!");
    }
}
