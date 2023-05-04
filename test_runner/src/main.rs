use five_nodes::run_five_node_test_scenario;
use log::info;
use std::{env, time::Duration};

pub mod five_nodes;
pub mod setup_utils;
pub mod test_utils;
extern crate log;

/// The amount of time we wait for a network to stabalize before testing
pub const SETUP_WAIT: Duration = Duration::from_secs(60);

fn main() {
    println!("About to init env logger");
    // custom logger filter gives error logs for all modules but info for only the test_runner
    // if you want to see logs for the rita instances you can adjust this per module in Rita by level
    // note this will print logs for all rita instances since they are all in one thread
    env_logger::Builder::default()
        .filter(None, log::LevelFilter::Error)
        .filter(Some("tester"), log::LevelFilter::Info)
        .init();

    info!("Starting the Rita test runner");
    println!("info above?");

    let test_type = env::var("TEST_TYPE");
    info!("Starting tests with {:?}", test_type);
    if let Ok(test_type) = test_type {
        if test_type == "FIVE_NODES" {
            run_five_node_test_scenario();
        } else {
            panic!("Error unknown test type {}!", test_type);
        }
    } else {
        panic!("Error test type not set!");
    }
}
