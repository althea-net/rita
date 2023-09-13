use crate::payments_eth::{ONE_ETH, WEB3_TIMEOUT};
use crate::setup_utils::database::start_postgres;
use crate::setup_utils::namespaces::*;
use crate::setup_utils::rita::thread_spawner;
use crate::utils::{
    get_default_settings, register_all_namespaces_to_exit, send_eth_bulk,
    test_all_internet_connectivity, test_reach_all, test_routes,
};
use log::info;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use web30::client::Web3;

/// Runs a five node fixed network map test scenario, this does basic network setup and tests reachability to
/// all destinations
pub async fn run_five_node_test_scenario() {
    info!("Starting five node test scenario");
    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    let (client_settings, exit_settings) =
        get_default_settings("test".to_string(), namespaces.clone());

    namespaces.validate();

    start_postgres();
    let res = setup_ns(namespaces.clone());
    info!("Namespaces setup: {res:?}");

    let rita_identities = thread_spawner(namespaces.clone(), client_settings, exit_settings)
        .expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    // this sleep is for debugging so that the container can be accessed to poke around in
    //thread::sleep(SETUP_WAIT * 500);

    test_reach_all(namespaces.clone());

    test_routes(namespaces.clone(), expected_routes);

    // Exits need to have funds to request a registered client list, which is needed for proper setup
    info!("Topup exits with funds");
    let web3 = Web3::new("http://localhost:8545", WEB3_TIMEOUT);
    let mut to_top_up = Vec::new();
    for c in rita_identities.client_identities {
        to_top_up.push(c.eth_address);
    }
    for e in rita_identities.exit_identities {
        to_top_up.push(e.eth_address)
    }

    info!("Sending 50 eth to all routers");
    send_eth_bulk((ONE_ETH * 50).into(), &to_top_up, &web3).await;

    info!("Registering routers to the exit");
    register_all_namespaces_to_exit(namespaces.clone()).await;

    thread::sleep(Duration::from_secs(10));

    info!("Checking for wg_exit tunnel setup");
    test_all_internet_connectivity(namespaces.clone());
}

/// This defines the network map for a five node scenario
pub fn five_node_config() -> (NamespaceInfo, HashMap<Namespace, RouteHop>) {
    /*
    These are connected as such:
    1---------2
    |         |
    |         |
    |         |
    |         |
    |         |
    3         4---------7
    |\        |
    |  \      |
    |    \    |
    |      \  |
    |        \|
    5         6
    */
    let testa = Namespace {
        id: 1,
        cost: 25,
        node_type: NodeType::Client {
            cluster_name: "test".to_string(),
        },
    };
    let testb = Namespace {
        id: 2,
        cost: 500,
        node_type: NodeType::Client {
            cluster_name: "test".to_string(),
        },
    };
    let testc = Namespace {
        id: 3,
        cost: 15,
        node_type: NodeType::Client {
            cluster_name: "test".to_string(),
        },
    };
    let testd = Namespace {
        id: 4,
        cost: 10,
        node_type: NodeType::Exit {
            instance_name: "test_4".to_string(),
        },
    };
    let teste = Namespace {
        id: 5,
        cost: 40,
        node_type: NodeType::Client {
            cluster_name: "test".to_string(),
        },
    };
    let testf = Namespace {
        id: 6,
        cost: 20,
        node_type: NodeType::Client {
            cluster_name: "test".to_string(),
        },
    };
    let testg = Namespace {
        id: 7,
        cost: 15,
        node_type: NodeType::Client {
            cluster_name: "test".to_string(),
        },
    };

    let nsinfo = NamespaceInfo {
        names: vec![
            testa.clone(),
            testb.clone(),
            testc.clone(),
            testd.clone(),
            teste.clone(),
            testf.clone(),
            testg.clone(),
        ],
        linked: vec![
            // arbitrary connections
            (1, 2),
            (1, 3),
            (2, 4),
            (3, 5),
            (3, 6),
            (4, 6),
            (4, 7),
        ],
    };
    // This is a Hashmap that contains the key namespace, and how it connects to each node in the network as its values.
    // For each namespace in the outer hashmap(A), we have an inner hashmap holding the other namespace nodes(B), how
    // much the expected price from A -> B is, and what the next hop would be from A -> B.
    let mut expected_routes = HashMap::new();
    let testa_routes = RouteHop {
        destination: [
            (2, PriceId { price: 0, id: 2 }),
            (3, PriceId { price: 0, id: 3 }),
            (4, PriceId { price: 35, id: 3 }),
            (5, PriceId { price: 15, id: 3 }),
            (6, PriceId { price: 15, id: 3 }),
            (7, PriceId { price: 45, id: 3 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testb_routes = RouteHop {
        destination: [
            (1, PriceId { price: 0, id: 1 }),
            (3, PriceId { price: 25, id: 1 }),
            (4, PriceId { price: 0, id: 4 }),
            (5, PriceId { price: 40, id: 1 }),
            (6, PriceId { price: 10, id: 4 }),
            (7, PriceId { price: 10, id: 4 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testc_routes = RouteHop {
        destination: [
            (1, PriceId { price: 0, id: 1 }),
            (2, PriceId { price: 25, id: 1 }),
            (4, PriceId { price: 20, id: 6 }),
            (5, PriceId { price: 0, id: 5 }),
            (6, PriceId { price: 0, id: 6 }),
            (7, PriceId { price: 30, id: 6 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testd_routes = RouteHop {
        destination: [
            (1, PriceId { price: 35, id: 6 }),
            (2, PriceId { price: 0, id: 2 }),
            (3, PriceId { price: 20, id: 6 }),
            (5, PriceId { price: 35, id: 6 }),
            (6, PriceId { price: 0, id: 6 }),
            (7, PriceId { price: 0, id: 7 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let teste_routes = RouteHop {
        destination: [
            (1, PriceId { price: 15, id: 3 }),
            (2, PriceId { price: 40, id: 3 }),
            (3, PriceId { price: 0, id: 3 }),
            (4, PriceId { price: 35, id: 3 }),
            (6, PriceId { price: 15, id: 3 }),
            (7, PriceId { price: 45, id: 3 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testf_routes = RouteHop {
        destination: [
            (1, PriceId { price: 15, id: 3 }),
            (2, PriceId { price: 10, id: 4 }),
            (3, PriceId { price: 0, id: 3 }),
            (4, PriceId { price: 0, id: 4 }),
            (5, PriceId { price: 15, id: 3 }),
            (7, PriceId { price: 10, id: 4 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testg_routes = RouteHop {
        destination: [
            (1, PriceId { price: 45, id: 4 }),
            (2, PriceId { price: 10, id: 4 }),
            (3, PriceId { price: 30, id: 4 }),
            (4, PriceId { price: 0, id: 4 }),
            (5, PriceId { price: 45, id: 4 }),
            (6, PriceId { price: 10, id: 4 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };

    expected_routes.insert(testa, testa_routes);
    expected_routes.insert(testb, testb_routes);
    expected_routes.insert(testc, testc_routes);
    expected_routes.insert(testd, testd_routes);
    expected_routes.insert(teste, teste_routes);
    expected_routes.insert(testf, testf_routes);
    expected_routes.insert(testg, testg_routes);

    (nsinfo, expected_routes)
}
