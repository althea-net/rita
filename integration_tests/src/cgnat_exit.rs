use althea_kernel_interface::run_command;
use ipnetwork::Ipv4Network;
use settings::exit::ExitIpv4RoutingSettings;

use crate::five_nodes::five_node_config;
use crate::setup_utils::namespaces::*;
use crate::setup_utils::rita::{spawn_exit_root_of_trust, thread_spawner};
use crate::utils::{
    add_exits_contract_exit_list, deploy_contracts, get_default_settings, populate_routers_eth,
    register_all_namespaces_to_exit, test_all_internet_connectivity, test_reach_all, test_routes,
};
use std::net::Ipv4Addr;
use std::str::{from_utf8, FromStr};
use std::thread;
use std::time::Duration;

/// Runs a five node fixed network map test scenario, this does basic network setup and tests reachability to
/// all destinations
pub async fn run_cgnat_exit_test_scenario() {
    info!("Starting cgnat exit node test scenario");
    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    info!("Waiting to deploy contracts");
    let db_addr = deploy_contracts().await;

    let (client_settings, mut exit_settings, exit_root_addr) =
        get_default_settings(namespaces.clone(), db_addr);

    // using /29 allows us to test that multiple clients can use the same external IP if randomly assigned
    exit_settings.exit_network.ipv4_routing = ExitIpv4RoutingSettings::CGNAT {
        subnet: Ipv4Network::from_str("10.0.0.0/29").unwrap(),
        static_assignments: Vec::new(),
        gateway_ipv4: Ipv4Addr::new(10, 0, 0, 1),
        external_ipv4: Ipv4Addr::new(10, 0, 0, 2),
        broadcast_ipv4: Ipv4Addr::new(10, 0, 0, 255),
    };

    namespaces.validate();

    let res = setup_ns(namespaces.clone(), "cgnat");
    info!("Namespaces setup: {res:?}");

    info!("Starting root server!");
    spawn_exit_root_of_trust(db_addr).await;

    let rita_identities = thread_spawner(
        namespaces.clone(),
        client_settings,
        exit_settings.clone(),
        db_addr,
    )
    .expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    // Add exits to the contract exit list so clients get the propers exits they can migrate to
    add_exits_contract_exit_list(db_addr, exit_settings.exit_network, rita_identities.clone())
        .await;

    info!("About to populate routers with eth");
    populate_routers_eth(rita_identities, exit_root_addr).await;

    test_reach_all(namespaces.clone());

    test_routes(namespaces.clone(), expected_routes);

    info!("Registering routers to the exit");
    register_all_namespaces_to_exit(namespaces.clone()).await;

    info!("Checking for wg_exit tunnel setup");
    test_all_internet_connectivity(namespaces.clone());
    info!("All clients successfully registered!");

    info!("cgnat exit node test scenario complete");
}
