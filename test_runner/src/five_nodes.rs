use crate::test_utils::{test_reach_all, test_routes};
use crate::{setup_utils::*, SETUP_WAIT};
use log::info;
use std::collections::HashMap;
use std::thread;

/// Runs a five node fixed network map test scenario
pub fn run_five_node_test_scenario() {
    info!("Starting five node test scenario");
    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    validate_connections(namespaces.clone());

    let res = setup_ns(namespaces.clone());
    info!("Namespaces setup: {res:?}");

    let res = thread_spawner(namespaces.clone());
    info!("Thread Spawner: {res:?}");

    // allow setup to finish before running tests
    thread::sleep(SETUP_WAIT);

    // this sleep is for debugging so that the container can be accessed to poke around in
    //thread::sleep(five_mins);

    let res1 = test_reach_all(namespaces.clone()).expect("Could not reach all namespaces!");
    info!("Reachability Test: {res1}");

    let res2 = test_routes(namespaces, expected_routes);
    // this just returns a number at the moment, which must be 12 until more test instances are added
    info!("Routes Test: {res2}");

    if res1 != 49 || res2 != 42 {
        panic!("Failed to find the correct number of routes!");
    }
}

/// This defines the network map for a five node scenario
fn five_node_config() -> (NamespaceInfo, HashMap<Namespace, RouteHop>) {
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

/// Validate the list of linked namespaces
fn validate_connections(namespaces: NamespaceInfo) {
    for link in namespaces.linked {
        if !namespaces.names.contains(&link.0) || !namespaces.names.contains(&link.1) {
            panic!(
                "One or both of these names is not in the given namespace list: {}, {}",
                link.0.name, link.1.name
            )
        }
        if link.0.name.len() + link.1.name.len() > 8 {
            panic!(
                "Namespace names are too long(max 4 chars): {}, {}",
                link.0.name, link.1.name,
            )
        }
        if link.0.name.eq(&link.1.name) {
            panic!("Cannot link namespace to itself!")
        }
    }
}
