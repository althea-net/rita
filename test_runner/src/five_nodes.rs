use crate::setup_utils::*;
use crate::utils::{
    get_default_client_settings, test_reach_all, test_routes, validate_connections,
};
use log::info;
use std::collections::HashMap;

/// Runs a five node fixed network map test scenario, this does basic network setup and tests reachability to
/// all destinations
pub fn run_five_node_test_scenario() {
    info!("Starting five node test scenario");
    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    let rita_settings = get_default_client_settings();

    validate_connections(namespaces.clone());

    let res = setup_ns(namespaces.clone());
    info!("Namespaces setup: {res:?}");

    let _ =
        thread_spawner(namespaces.clone(), rita_settings).expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    // this sleep is for debugging so that the container can be accessed to poke around in
    //thread::sleep(SETUP_WAIT * 500);

    test_reach_all(namespaces.clone());

    test_routes(namespaces, expected_routes);
}

/// This defines the network map for a five node scenario
pub fn five_node_config() -> (NamespaceInfo, HashMap<Namespace, RouteHop>) {
    /*
    These are connected as such:
    A---------B
    |         |
    |         |
    |         |
    |         |
    |         |
    C         D---------G
    |\        |
    |  \      |
    |    \    |
    |      \  |
    |        \|
    E         F
    */
    let testa = Namespace {
        name: "n-1".to_string(),
        id: 1,
        cost: 25,
    };
    let testb = Namespace {
        name: "n-2".to_string(),
        id: 2,
        cost: 500,
    };
    let testc = Namespace {
        name: "n-3".to_string(),
        id: 3,
        cost: 15,
    };
    let testd = Namespace {
        name: "n-4".to_string(),
        id: 4,
        cost: 10,
    };
    let teste = Namespace {
        name: "n-5".to_string(),
        id: 5,
        cost: 40,
    };
    let testf = Namespace {
        name: "n-6".to_string(),
        id: 6,
        cost: 20,
    };
    let testg = Namespace {
        name: "n-7".to_string(),
        id: 7,
        cost: 15,
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
            (testa.clone(), testb.clone()),
            (testa.clone(), testc.clone()),
            (testb.clone(), testd.clone()),
            (testc.clone(), teste.clone()),
            (testc.clone(), testf.clone()),
            (testd.clone(), testf.clone()),
            (testd.clone(), testg.clone()),
        ],
    };
    // This is a Hashmap that contains the key namespace, and how it connects to each node in the network as its values.
    // For each namespace in the outer hashmap(A), we have an inner hashmap holding the other namespace nodes(B), how
    // much the expected price from A -> B is, and what the next hop would be from A -> B.
    let mut expected_routes = HashMap::new();
    let testa_routes = RouteHop {
        destination: [
            (testb.clone(), (0, testb.clone())),
            (testc.clone(), (0, testc.clone())),
            (testd.clone(), (35, testc.clone())),
            (teste.clone(), (15, testc.clone())),
            (testf.clone(), (15, testc.clone())),
            (testg.clone(), (45, testc.clone())),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testb_routes = RouteHop {
        destination: [
            (testa.clone(), (0, testa.clone())),
            (testc.clone(), (25, testa.clone())),
            (testd.clone(), (0, testd.clone())),
            (teste.clone(), (40, testa.clone())),
            (testf.clone(), (10, testd.clone())),
            (testg.clone(), (10, testd.clone())),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testc_routes = RouteHop {
        destination: [
            (testa.clone(), (0, testa.clone())),
            (testb.clone(), (25, testa.clone())),
            (testd.clone(), (20, testf.clone())),
            (teste.clone(), (0, teste.clone())),
            (testf.clone(), (0, testf.clone())),
            (testg.clone(), (30, testf.clone())),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testd_routes = RouteHop {
        destination: [
            (testa.clone(), (35, testf.clone())),
            (testb.clone(), (0, testb.clone())),
            (testc.clone(), (20, testf.clone())),
            (teste.clone(), (35, testf.clone())),
            (testf.clone(), (0, testf.clone())),
            (testg.clone(), (0, testg.clone())),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let teste_routes = RouteHop {
        destination: [
            (testa.clone(), (15, testc.clone())),
            (testb.clone(), (40, testc.clone())),
            (testc.clone(), (0, testc.clone())),
            (testd.clone(), (35, testc.clone())),
            (testf.clone(), (15, testc.clone())),
            (testg.clone(), (45, testc.clone())),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testf_routes = RouteHop {
        destination: [
            (testa.clone(), (15, testc.clone())),
            (testb.clone(), (10, testd.clone())),
            (testc.clone(), (0, testc.clone())),
            (testd.clone(), (0, testd.clone())),
            (teste.clone(), (15, testc.clone())),
            (testg.clone(), (10, testd.clone())),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testg_routes = RouteHop {
        destination: [
            (testa.clone(), (45, testd.clone())),
            (testb.clone(), (10, testd.clone())),
            (testc.clone(), (30, testd.clone())),
            (testd.clone(), (0, testd.clone())),
            (teste.clone(), (45, testd.clone())),
            (testf.clone(), (10, testd.clone())),
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
