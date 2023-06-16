use crate::five_nodes::five_node_config;
use crate::setup_utils::namespaces::setup_ns;
use crate::setup_utils::rita::thread_spawner;
use crate::utils::{get_default_settings, send_eth_bulk, test_reach_all, test_routes};
use clarity::Address as EthAddress;
use clarity::{PrivateKey as EthPrivateKey, Uint256};
use log::info;
use std::thread;
use std::time::Duration;
use web30::client::Web3;

/// Key with funds in the EVM that can be sent to routers
pub const ETH_MINER_KEY: &str =
    "0xb1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7";

pub fn get_miner_key() -> EthPrivateKey {
    ETH_MINER_KEY.parse().unwrap()
}

pub fn get_miner_address() -> EthAddress {
    get_miner_key().to_address()
}

/// The chain id of the ethereum testnet
pub fn eth_chain_id() -> Uint256 {
    417834u64.into()
}

pub const WEB3_TIMEOUT: Duration = Duration::from_secs(1);
pub const ONE_ETH: u128 = 1000000000000000000;

/// Runs a five node fixed network map test scenario
pub async fn run_eth_payments_test_scenario() {
    info!("Starting eth payments test");
    let node_config = five_node_config();
    let namespaces = node_config.0;

    let (rita_settings, rita_exit_settings) = get_default_settings();

    // no modifications to the default settings in this test case

    namespaces.validate();

    let res = setup_ns(namespaces.clone());
    info!("Namespaces setup: {res:?}");

    let rita_identities = thread_spawner(namespaces.clone(), rita_settings, rita_exit_settings)
        .expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    test_reach_all(namespaces.clone());

    // start main test content
    let web3 = Web3::new("http://localhost:8545", WEB3_TIMEOUT);
    let mut to_top_up = Vec::new();
    for c in rita_identities.client_identities {
        to_top_up.push(c.eth_address);
    }
    for e in rita_identities.exit_identities {
        to_top_up.push(e.eth_address)
    }
    send_eth_bulk((ONE_ETH * 50).into(), &to_top_up, &web3).await;
    info!("Sent 10 eth to all routers")
}
