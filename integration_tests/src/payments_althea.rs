use std::thread;
use std::time::Duration;

use crate::five_nodes::five_node_config;
use crate::setup_utils::database::start_postgres;
use crate::setup_utils::namespaces::*;
use crate::setup_utils::rita::thread_spawner;
use crate::utils::{
    althea_system_chain_client, althea_system_chain_exit, generate_traffic, get_default_settings,
    print_althea_balances, register_erc20_usdc_token, register_to_exit, send_althea_tokens,
    test_reach_all, test_routes, validate_debt_entry,
};
use althea_types::ALTHEA_PREFIX;
use deep_space::Address as AltheaAddress;
use deep_space::{EthermintPrivateKey, PrivateKey};
use log::info;
use rita_common::debt_keeper::GetDebtsResult;

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

    let (rita_settings, rita_exit_settings) = get_default_settings();

    namespaces.validate();
    start_postgres();

    let res = setup_ns(namespaces.clone());
    info!("Namespaces setup: {res:?}");

    // Modify configs to use Althea chain
    let rita_exit_settings = althea_system_chain_exit(rita_exit_settings);
    let rita_settings = althea_system_chain_client(rita_settings);

    let rita_identities = thread_spawner(namespaces.clone(), rita_settings, rita_exit_settings)
        .expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    // Test for network convergence
    test_reach_all(namespaces.clone());

    test_routes(namespaces.clone(), expected_routes);

    info!("Registering routers to the exit");
    for r in namespaces.names.clone() {
        if let NodeType::Client = r.node_type {
            let res = register_to_exit(r.get_name()).await;
            if !res.is_success() {
                panic!("Failed to register {} to exit with {:?}", r.get_name(), res);
            } else {
                info!("{} registered to exit", r.get_name());
            }
        }
    }

    thread::sleep(Duration::from_secs(10));

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
