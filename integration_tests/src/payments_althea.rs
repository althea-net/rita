use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use crate::five_nodes::five_node_config;
use crate::registration_server::start_registration_server;
use crate::setup_utils::namespaces::*;
use crate::setup_utils::rita::thread_spawner;
use crate::utils::{
    deploy_contracts, generate_traffic, get_default_settings, populate_routers_eth,
    print_althea_balances, register_all_namespaces_to_exit, register_erc20_usdc_token,
    send_althea_tokens, test_all_internet_connectivity, test_reach_all, test_routes,
    validate_debt_entry, TEST_PAY_THRESH,
};
use althea_types::{Denom, SystemChain, ALTHEA_PREFIX};
use deep_space::Address as AltheaAddress;
use deep_space::{EthermintPrivateKey, PrivateKey};
use log::info;
use rita_common::debt_keeper::GetDebtsResult;
use settings::client::RitaClientSettings;
use settings::exit::RitaExitSettingsStruct;

const USDC_TO_WEI_DECIMAL: u64 = 1_000_000_000_000u64;

/// This is one of the validator private keys grabbed from setup-validators.sh
const ALTHEA_EVM_PRIV_BYTES: &str =
    "3b23c86080c9abc8870936b2eb17ecb808f5ad3b318018b3e23873013379e4d6";

pub fn get_althea_evm_priv() -> EthermintPrivateKey {
    ALTHEA_EVM_PRIV_BYTES
        .parse::<clarity::PrivateKey>()
        .unwrap()
        .into()
}

pub fn get_althea_evm_pub() -> AltheaAddress {
    get_althea_evm_priv().to_address(ALTHEA_PREFIX).unwrap()
}

pub async fn run_althea_payments_test_scenario() {
    info!("Starting althea payments test");

    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    info!("Waiting to deploy contracts");
    let db_addr = deploy_contracts().await;

    info!("Starting registration server");
    start_registration_server(db_addr);

    let (mut client_settings, mut exit_settings) =
        get_default_settings("test".to_string(), namespaces.clone());

    namespaces.validate();

    let res = setup_ns(namespaces.clone());
    info!("Namespaces setup: {res:?}");

    // Modify configs to use Althea chain
    let (client_settings, exit_settings) =
        althea_payments_map(&mut client_settings, &mut exit_settings);

    let rita_identities =
        thread_spawner(namespaces.clone(), client_settings, exit_settings, db_addr)
            .expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    populate_routers_eth(rita_identities.clone()).await;

    // Test for network convergence
    test_reach_all(namespaces.clone());

    test_routes(namespaces.clone(), expected_routes);

    info!("Registering routers to the exit");
    register_all_namespaces_to_exit(namespaces.clone()).await;

    thread::sleep(Duration::from_secs(10));

    test_all_internet_connectivity(namespaces.clone());
    info!("Successfully registered all clients");

    let from_node: Option<Namespace> = namespaces.get_namespace(1);
    let forward_node: Option<Namespace> = namespaces.get_namespace(3);
    let end_node: Option<Namespace> = namespaces.get_namespace(6);

    let mut to_topup = Vec::new();
    for ident in rita_identities.client_identities {
        to_topup.push(ident.get_althea_address());
    }

    info!("Registering USDC as ERC20");
    register_erc20_usdc_token().await;

    info!(
        "Sending aalthea to all nodes with address {:?}",
        to_topup.clone()
    );
    send_althea_tokens(to_topup.clone()).await;

    let balances = print_althea_balances(to_topup.clone(), "uUSDC".to_string()).await;
    info!("USDC Balances are {:?}", balances);
    let balances = print_althea_balances(to_topup, "aalthea".to_string()).await;
    info!("Althea Balances are {:?}", balances);

    info!("Trying to generate traffic");
    generate_traffic(
        from_node.clone().unwrap(),
        Some(end_node.clone().unwrap()),
        "1.2G".to_string(),
    );

    validate_debt_entry(
        from_node.unwrap(),
        forward_node.unwrap(),
        &althea_payment_conditions,
    )
    .await;
}

fn althea_payment_conditions(debts: GetDebtsResult) -> bool {
    let pay_sent = debts.payment_details.total_payment_sent;
    matches!(
        (
            pay_sent > USDC_TO_WEI_DECIMAL.into(),
            pay_sent < (2 * USDC_TO_WEI_DECIMAL).into(),
        ),
        (true, true)
    )
}

fn althea_payments_map(
    c_set: &mut RitaClientSettings,
    exit_set: &mut RitaExitSettingsStruct,
) -> (RitaClientSettings, RitaExitSettingsStruct) {
    let mut accept_de = HashMap::new();
    accept_de.insert(
        "usdc".to_string(),
        Denom {
            denom: "uUSDC".to_string(),
            decimal: 1_000_000u64,
        },
    );

    c_set.payment.system_chain = SystemChain::Althea;
    exit_set.payment.system_chain = SystemChain::Althea;
    // set pay thres to a smaller value
    c_set.payment.payment_threshold = TEST_PAY_THRESH.into();
    exit_set.payment.payment_threshold = TEST_PAY_THRESH.into();
    c_set.payment.accepted_denoms = Some(accept_de.clone());
    exit_set.payment.accepted_denoms = Some(accept_de.clone());

    (c_set.clone(), exit_set.clone())
}
