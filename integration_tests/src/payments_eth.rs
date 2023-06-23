use crate::five_nodes::five_node_config;
use crate::setup_utils::namespaces::setup_ns;
use crate::setup_utils::rita::thread_spawner;
use crate::utils::{get_default_settings, test_reach_all, test_routes};
use crate::SETUP_WAIT;
use log::info;

use std::thread;

/// Runs a five node fixed network map test scenario
pub fn run_eth_payments_test_scenario() {
    info!("Starting eth payments test");
    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    let (rita_settings, rita_exit_settings) = get_default_settings();

    // no modifications to the default settings in this test case

    namespaces.validate();

    let res = setup_ns(namespaces.clone());
    info!("Namespaces setup: {res:?}");

    let _rita_identities = thread_spawner(namespaces.clone(), rita_settings, rita_exit_settings)
        .expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    // allow setup to finish before running tests
    thread::sleep(SETUP_WAIT);

    // this sleep is for debugging so that the container can be accessed to poke around in
    //thread::sleep(five_mins);

    test_reach_all(namespaces.clone());

    test_routes(namespaces, expected_routes);

    // start main test content
}
