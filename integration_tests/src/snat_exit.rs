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
pub async fn run_snat_exit_test_scenario() {
    info!("Starting snat exit node test scenario");
    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    info!("Waiting to deploy contracts");
    let db_addr = deploy_contracts().await;

    let (client_settings, mut exit_settings, exit_root_addr) =
        get_default_settings(namespaces.clone(), db_addr);

    exit_settings.exit_network.ipv4_routing = ExitIpv4RoutingSettings::SNAT {
        subnet: Ipv4Network::from_str("10.0.0.0/24").unwrap(),
        static_assignments: Vec::new(),
        gateway_ipv4: Ipv4Addr::new(10, 0, 0, 1),
        external_ipv4: Ipv4Addr::new(10, 0, 0, 2),
        broadcast_ipv4: Ipv4Addr::new(10, 0, 0, 255),
    };

    namespaces.validate();

    let res = setup_ns(namespaces.clone(), "snat");
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

    // test teardown
    check_setup();
    info!("killing client 1");
    let client = namespaces.names.first().unwrap();
    kill_client(client.clone());
    // wg handshakes are by default every 2 mins, so in the integration test env the "inactive" threshold
    // is 140 seconds. we wait 150 to be sure
    thread::sleep(Duration::from_secs(150));
    // check our nftables rules
    check_teardown();
    info!("snat exit node test scenario complete");
}

fn kill_client(client: Namespace) {
    let out = run_command("ip", &["netns", "pids", &client.get_name()]).unwrap();
    let out = from_utf8(&out.stdout)
        .unwrap()
        .split('\n')
        .collect::<Vec<&str>>();
    for s in out {
        run_command("kill", &[s.trim()]).unwrap();
    }
}

// check that we have the correct nftables rules before tearing down
fn check_setup() {
    // get output of ip netns exec n-4 nft list table ip nat
    let out = run_command(
        "ip",
        &["netns", "exec", "n-4", "nft", "list", "table", "ip", "nat"],
    )
    .unwrap();
    // the test default network settings put the client internal ips at 172.16.0.{client namespace number}
    // we kill client 1, so search for 172.16.0.1 in the output
    assert!(from_utf8(&out.stdout).unwrap().contains("172.16.0.1"));

    // same goes for output of ip netns exec n-4 nft list table ip filter
    let out = run_command(
        "ip",
        &[
            "netns", "exec", "n-4", "nft", "list", "table", "ip", "filter",
        ],
    )
    .unwrap();
    assert!(from_utf8(&out.stdout).unwrap().contains("172.16.0.1"));
}

// check that the client is no longer in the exit's nftables rules
fn check_teardown() {
    // get output of ip netns exec n-4 nft list table ip nat
    let out = run_command(
        "ip",
        &["netns", "exec", "n-4", "nft", "list", "table", "ip", "nat"],
    )
    .unwrap();
    // the test default network settings put the client internal ips at 172.16.0.{client namespace number}
    // we kill client 1, so search for 172.16.0.1 in the output
    assert!(!from_utf8(&out.stdout).unwrap().contains("172.16.0.1"));

    // same goes for output of ip netns exec n-4 nft list table ip filter
    let out = run_command(
        "ip",
        &[
            "netns", "exec", "n-4", "nft", "list", "table", "ip", "filter",
        ],
    )
    .unwrap();
    assert!(!from_utf8(&out.stdout).unwrap().contains("172.16.0.1"));
}
