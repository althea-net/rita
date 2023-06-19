/// Binary crate for actually running the integration tests
use integration_tests::five_nodes::run_five_node_test_scenario;
use integration_tests::{
    payments_althea::run_althea_payments_test_scenario,
    payments_eth::run_eth_payments_test_scenario, utils::set_sigterm,
};
use log::info;
use std::env;

extern crate log;

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

    info!("Starting the Rita test runner");
    println!("info above?");

    let test_type = env::var("TEST_TYPE");
    info!("Starting tests with {:?}", test_type);
    if let Ok(test_type) = test_type {
        if test_type == "FIVE_NODES" {
            run_five_node_test_scenario().await;
        } else if test_type == "PAYMENTS_ETH" {
            run_eth_payments_test_scenario()
        } else if test_type == "PAYMENTS_ALTHEA" {
            run_althea_payments_test_scenario().await;
        } else {
            panic!("Error unknown test type {}!", test_type);
        }
    } else {
        panic!("Error test type not set!");
    }
}
