use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use crate::five_nodes::five_node_config;
use crate::setup_utils::database::start_postgres;
use crate::setup_utils::namespaces::*;
use crate::setup_utils::rita::thread_spawner;
use crate::utils::{
    generate_traffic, get_default_settings, get_ip_from_namespace, query_debts, register_to_exit,
    test_all_internet_connectivity, test_reach_all, test_routes, DEBT_ACCURACY_THRES,
};
use althea_types::Identity;
use log::info;
use num256::Int256;
use num_traits::Signed;
use rita_common::debt_keeper::GetDebtsResult;

type DebtsConfig<T> = (Vec<(T, T)>, HashMap<(T, T), Vec<T>>);

pub async fn run_debts_test() {
    info!("Starting althea debts test");

    /*
    These are connected as such with their node weights in paranthesis:
    1(25)---------2(500)
    |             |
    |             |
    |             |
    |             |
    |             |
    3(15)         4(10)---------7(15)
    | \           |
    |   \         |
    |     \       |
    |       \     |
    |         \   |
    |           \ |
    5(40)         6(20)
    */

    let (pairs, optimal_routes) = get_debts_test_config();
    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    let (rita_settings, rita_exit_settings) = get_default_settings();

    // The exit price is set to ns.cost during thread_spawner
    let exit_price = namespaces.get_namespace(4).unwrap().cost;

    namespaces.validate();
    start_postgres();

    let res = setup_ns(namespaces.clone());
    info!("Namespaces setup: {res:?}");

    let rita_identities = thread_spawner(namespaces.clone(), rita_settings, rita_exit_settings)
        .expect("Could not spawn Rita threads");
    // There should be only 1 exit identity
    let exit_identity = rita_identities
        .exit_identities
        .last()
        .cloned()
        .expect("Why is there no exit here");
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

    // Let network stabalize
    thread::sleep(Duration::from_secs(20));

    test_all_internet_connectivity(namespaces.clone());

    // For each node pair to test:
    // 1.) Get a debt screenshot of all nodes before generating traffic
    // 2.) Generate traffic between start and end node
    // 3.) Get another debt screentshot and validate that the increase in debt for each
    //     node is in accordance to its estimated value
    for pair in pairs {
        let from_node = namespaces
            .get_namespace(pair.0)
            .expect("From needs to be a valid node");
        let to_node = namespaces.get_namespace(pair.1);

        // Get vec of namespaces of all intermediate nodes
        let forwarding_nodes = optimal_routes.get(&pair).unwrap();
        let mut query_nodes = {
            let mut ret = vec![];
            for e in forwarding_nodes {
                ret.push(namespaces.get_namespace(*e).unwrap())
            }
            ret
        };

        // Before traffic debt screenshot
        let mut debts_nodes = vec![from_node.clone()];
        debts_nodes.append(&mut query_nodes.clone());
        let existing_debts_screenshot =
            query_debts(debts_nodes.clone(), Some(debts_nodes.clone())).await;

        info!(
            "Generating some traffic between {} and node {}",
            from_node.get_name(),
            pair.1
        );

        // Generate 1 GB traffic
        generate_traffic(from_node.clone(), to_node.clone(), "1G".to_string());

        // Give time for rita to update debtkeeper
        thread::sleep(Duration::from_secs(20));

        // Special case for when forwarding to internet, remove exit from query nodes as it debt is reflected
        // directly in the from_node's debt instaed of its neighbors debt
        let mut exit_node = None;
        // if to_node is none, we are querying the internet, so last node has to be an exit node
        if to_node.is_none() {
            exit_node = query_nodes.pop();
            if exit_node.clone().unwrap().node_type != NodeType::Exit {
                panic!("Why is last element not an exit?");
            }
        }

        // Get each neighbor pair to verify their debts are the same and of the correct amount
        let path_weight = get_total_path_weight(query_nodes.clone());
        let neigh_pairs = get_neigh_pairs(from_node.clone(), query_nodes.clone());

        // Get a debts screenshot after traffic generation
        let debts_screenshot = query_debts(debts_nodes.clone(), Some(debts_nodes)).await;

        // For each neighbor pair in path, validate their debts and make sure they are opposite
        // and close to each other
        let mut weight_left = path_weight;
        for (from_neigh, to_neigh) in neigh_pairs {
            validate_debt_increase(
                from_neigh.clone(),
                to_neigh.clone(),
                &debts_screenshot,
                &existing_debts_screenshot,
                1u32,
                weight_left,
                exit_identity,
            );

            weight_left -= to_neigh.cost
        }

        // special case for exit, validate from_node and exits debts are incremented accordingly
        if to_node.is_none() {
            validate_debt_increase(
                from_node,
                exit_node.unwrap(),
                &debts_screenshot,
                &existing_debts_screenshot,
                1u32,
                exit_price,
                exit_identity,
            );
        }
    }
}

fn get_debts_test_config() -> DebtsConfig<u16> {
    // Hardcoded debt pairs and optimal routes. 0 represents the internet
    let pairs: Vec<(u16, u16)> = vec![(7, 0), (3, 0), (7, 2), (5, 1), (1, 4), (2, 5), (7, 5)];

    // Hardcoded optimal paths for each node pair. Validation uses this to test debts for each node in path
    let mut optimal_routes: HashMap<(u16, u16), Vec<u16>> = HashMap::new();
    optimal_routes.insert((7, 0), vec![4]);
    optimal_routes.insert((3, 0), vec![6, 4]);
    optimal_routes.insert((7, 2), vec![4]);
    optimal_routes.insert((5, 1), vec![3]);
    optimal_routes.insert((1, 4), vec![3, 6]);
    optimal_routes.insert((2, 5), vec![1, 3]);
    optimal_routes.insert((7, 5), vec![4, 6, 3]);

    (pairs, optimal_routes)
}

/// Sum of all weights in a path
fn get_total_path_weight(query_nodes: Vec<Namespace>) -> u32 {
    let mut ret = 0;
    for e in query_nodes {
        ret += e.cost;
    }
    ret
}

/// Get all pair in a path so that we can validate each pair independently
/// For example, for a path A -> B -> C -> D, this function returns
/// Vec[(A,B), (B,C), (C,D)]
fn get_neigh_pairs(
    from_node: Namespace,
    query_nodes: Vec<Namespace>,
) -> Vec<(Namespace, Namespace)> {
    let mut ret = Vec::new();
    let mut prev: Option<Namespace> = None;
    for (i, e) in query_nodes.iter().enumerate() {
        if i == 0 {
            ret.push((from_node.clone(), e.clone()))
        } else {
            ret.push((prev.unwrap(), e.clone()))
        }
        prev = Some(e.clone());
    }
    ret
}

/// Data sent in GB
/// Given two nodes A and B get their debts before and after traffic generation.
/// Compare increse in debt to an estimated value and ensure it is within a threshold
/// Do this for A's debt for B as well as B's debt for A
/// Finally validate A debt and B debt are opposite in sign and close to each other
pub fn validate_debt_increase(
    from_node: Namespace,
    to_node: Namespace,
    debts_screenshot: &HashMap<Namespace, Vec<GetDebtsResult>>,
    existing_debts_screenshot: &HashMap<Namespace, Vec<GetDebtsResult>>,
    data_sent: u32,
    weight: u32,
    exit_identity: Identity,
) {
    let bytes_per_gb: Int256 = (1024u64 * 1024u64 * 1024u64).into();

    // Get from_node's debt for to_node
    let (debt_entry, existing_debt_entry) = get_relevant_debt_entries(
        debts_screenshot,
        existing_debts_screenshot,
        exit_identity,
        from_node.clone(),
        to_node.clone(),
    );

    // Calculate actual and expected debt
    let actual_debt_from =
        debt_entry.payment_details.debt - existing_debt_entry.payment_details.debt;
    info!(
        "debt now is {:?}, exiting is {:?}",
        debt_entry.payment_details.debt, existing_debt_entry.payment_details.debt
    );
    let expected_debt_from = bytes_per_gb * data_sent.into() * weight.into();

    // Expected and actual debt should be within 75% accurate
    info!(
        "Actual: {} and expected: {}",
        actual_debt_from, expected_debt_from
    );
    let margin = ((actual_debt_from - expected_debt_from) * 100u8.into()) / expected_debt_from;
    assert!(margin.abs() < DEBT_ACCURACY_THRES.into());

    // Get to_node's debt for from_node and repeat the process
    let (debt_entry, existing_debt_entry) = get_relevant_debt_entries(
        debts_screenshot,
        existing_debts_screenshot,
        exit_identity,
        to_node.clone(),
        from_node.clone(),
    );

    let actual_debt_to = debt_entry.payment_details.debt - existing_debt_entry.payment_details.debt;
    let expected_debt_to = bytes_per_gb * data_sent.into() * weight.into() * Int256::from(-1i32);

    // Expected and actual debt should be within 75% accurate
    let margin = ((actual_debt_to - expected_debt_to) * 100u8.into()) / expected_debt_to;
    assert!(margin.abs() < DEBT_ACCURACY_THRES.into());

    // For debugging
    info!(
        "\nNode {} debt for node {} is {} :::::::: {} % accurate ::::::: \nNode {} debt for node {} is {} :::::::: {}% accurate :::::::::",
        from_node.id,
        to_node.id,
        actual_debt_from,
        (actual_debt_from * 100u8.into()) / expected_debt_from,
        to_node.id,
        from_node.id,
        actual_debt_to,
        ((actual_debt_to * 100u8.into()) / expected_debt_to).abs()
    );

    // Both node debts should be opposite
    assert!(actual_debt_from * (actual_debt_to / actual_debt_to.abs()) < 0u8.into());
    let margin =
        ((actual_debt_from.abs() - actual_debt_to.abs()) * 100u8.into()) / actual_debt_to.abs();
    assert!(margin < DEBT_ACCURACY_THRES.into());
}

fn get_relevant_debt_entries(
    debts_screenshot: &HashMap<Namespace, Vec<GetDebtsResult>>,
    existing_debts_screenshot: &HashMap<Namespace, Vec<GetDebtsResult>>,
    exit_identity: Identity,
    debt_of_node: Namespace,
    querying_node: Namespace,
) -> (GetDebtsResult, GetDebtsResult) {
    let mut debt_entry: Vec<GetDebtsResult> = Vec::new();
    let mut existing_debt_entry: Vec<GetDebtsResult> = Vec::new();

    for entry in debts_screenshot
        .get(&debt_of_node)
        .expect("There needs to be an entry here")
    {
        if entry.identity.mesh_ip.to_string() == get_ip_from_namespace(querying_node.clone()) {
            debt_entry.push(entry.clone());
        }
    }

    for entry in existing_debts_screenshot
        .get(&debt_of_node)
        .expect("There needs to be an entry here")
    {
        if entry.identity.mesh_ip.to_string() == get_ip_from_namespace(querying_node.clone()) {
            existing_debt_entry.push(entry.clone());
        }
    }

    let debt_entry = {
        if debt_entry.len() == 1 {
            debt_entry.last().unwrap().clone()
        } else {
            // The gateway may have two entries for debt, if some other node, panic
            let mut ret = None;
            for e in debt_entry {
                if e.identity == exit_identity {
                    ret = Some(e)
                }
            }
            ret.expect("There needs to be a valid entry here")
        }
    };
    let existing_debt_entry = {
        if existing_debt_entry.len() == 1 {
            existing_debt_entry.last().unwrap().clone()
        } else {
            let mut ret = None;
            for e in existing_debt_entry {
                if e.identity == exit_identity {
                    ret = Some(e)
                }
            }
            ret.expect("There needs to be a valid existing debt entry here")
        }
    };

    (debt_entry, existing_debt_entry)
}
