use std::{collections::HashMap, str::from_utf8, thread, time::Duration};

use crate::{
    registration_server::start_registration_server,
    setup_utils::{
        namespaces::{setup_ns, Namespace, NamespaceInfo, NodeType, PriceId, RouteHop},
        rita::thread_spawner,
    },
    utils::{
        deploy_contracts, get_default_settings, get_node_id_from_ip, populate_routers_eth,
        register_all_namespaces_to_exit, test_all_internet_connectivity, test_reach_all,
        test_routes,
    },
};
use althea_kernel_interface::KI;
use log::info;

/*
Nodes are connected as such, 4 and 5 are exit:
1---------2
|         |
|         |
|         |
|         4 ---------7
|
|
3---------5
|         |
|         |
|         |
8---------6
*/

pub async fn run_multi_exit_test() {
    info!("Starting mutli exit test");

    let node_configs = multi_exit_config();
    let namespaces = node_configs.0;
    let expected_routes = node_configs.1;

    info!("Waiting to deploy contracts");
    let db_addr = deploy_contracts().await;

    info!("Starting registration server");
    start_registration_server(db_addr);

    let (rita_client_settings, rita_exit_settings) =
        get_default_settings("test".to_string(), namespaces.clone());

    namespaces.validate();

    let res = setup_ns(namespaces.clone());

    let rita_identities = thread_spawner(
        namespaces.clone(),
        rita_client_settings,
        rita_exit_settings,
        db_addr,
    )
    .expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    populate_routers_eth(rita_identities).await;

    // Test for network convergence
    test_reach_all(namespaces.clone());

    test_routes(namespaces.clone(), expected_routes);

    info!("Registering routers to the exit");
    register_all_namespaces_to_exit(namespaces.clone()).await;

    thread::sleep(Duration::from_secs(10));

    test_all_internet_connectivity(namespaces.clone());

    info!("All clients successfully registered!");

    let current_exit = get_current_exit(namespaces.names[0].clone(), namespaces.clone());
    info!(
        "All nodes are set up correctly and are connected to exit {}",
        current_exit.get_name()
    );

    // Kill one of the exits
    kill_exit(current_exit.clone());
    info!(
        "Exit {} killed, verifing client migration",
        current_exit.get_name()
    );

    thread::sleep(Duration::from_secs(10));

    // Check that we migrated
    let new_exit = get_current_exit(namespaces.names[0].clone(), namespaces.clone());
    assert!(new_exit != current_exit);
    info!("Clients have migrated to exit {}", new_exit.get_name());

    // verfiy that we have internet connectivity. Special case where clients migrate from n-4 to n-5, n-7
    // wont have internet connection since it routes through n-4. So we remove it from namespace list before checking
    // for internet connectivity
    let namespaces_without_7 = NamespaceInfo {
        names: {
            let mut ret = namespaces.names.clone();
            let ns_7 = namespaces.get_namespace(7).clone().unwrap();
            let ind_to_remove = ret.iter().position(|x| *x == ns_7).unwrap();
            ret.remove(ind_to_remove);
            ret
        },
        linked: namespaces.linked,
    };
    test_all_internet_connectivity(namespaces_without_7);
}

fn kill_exit(exit: Namespace) {
    let out = KI
        .run_command("ip", &["netns", "pids", &exit.get_name()])
        .unwrap();
    let out = from_utf8(&out.stdout)
        .unwrap()
        .split('\n')
        .collect::<Vec<&str>>();
    for s in out {
        KI.run_command("kill", &[s.trim()]).unwrap();
    }
}

fn get_current_exit(ns: Namespace, namespaces: NamespaceInfo) -> Namespace {
    let out = KI
        .run_command(
            "ip",
            &["netns", "exec", &ns.get_name(), "wg", "show", "wg_exit"],
        )
        .unwrap();
    let out = from_utf8(&out.stdout).unwrap();
    let out = out.split('\n').collect::<Vec<&str>>();

    let mut out_str = None;
    for o in out {
        if o.contains("endpoint") {
            out_str = Some(o);
            break;
        }
    }
    let out = out_str.unwrap();
    let out = out.split(']').collect::<Vec<&str>>()[0];
    let out = out.split('[').last().unwrap();
    let ns = get_node_id_from_ip(out.parse().unwrap());
    namespaces.get_namespace(ns).expect("This should be valid")
}

/// This defines the network map for a multi exit scenario
pub fn multi_exit_config() -> (NamespaceInfo, HashMap<Namespace, RouteHop>) {
    /*
    Nodes are connected as such, 4 and 5 are exit:
    1---------2
    |         |
    |         |
    |         |
    |         4(Exit) ---------7
    |
    |
    3---------5(Exit)
    |         |
    |         |
    |         |
    8---------6
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
        cost: 50,
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
        cost: 20,
        node_type: NodeType::Exit {
            instance_name: "test_5".to_string(),
        },
    };
    let testf = Namespace {
        id: 6,
        cost: 60,
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
    let testh = Namespace {
        id: 8,
        cost: 10,
        node_type: NodeType::Client {
            cluster_name: "test".to_string(),
        },
    };

    let nsinfo_exit = NamespaceInfo {
        names: vec![
            testa.clone(),
            testb.clone(),
            testc.clone(),
            testd.clone(),
            teste.clone(),
            testf.clone(),
            testg.clone(),
            testh.clone(),
        ],
        linked: vec![
            // arbitrary connections
            (1, 2),
            (1, 3),
            (2, 4),
            (3, 8),
            (3, 5),
            (4, 7),
            (5, 6),
            (6, 8),
        ],
    };

    // For each namespace in the outer hashmap(A), we have an inner hashmap holding the other namespace nodes(B), how
    // much the expected price from A -> B is, and what the next hop would be from A -> B.
    let mut expected_routes = HashMap::new();

    let testa_routes = RouteHop {
        destination: [
            (2, PriceId { price: 0, id: 2 }),
            (3, PriceId { price: 0, id: 3 }),
            (4, PriceId { price: 50, id: 2 }),
            (5, PriceId { price: 15, id: 3 }),
            (6, PriceId { price: 25, id: 3 }),
            (7, PriceId { price: 60, id: 2 }),
            (8, PriceId { price: 15, id: 3 }),
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
            (6, PriceId { price: 50, id: 1 }),
            (7, PriceId { price: 10, id: 4 }),
            (8, PriceId { price: 40, id: 1 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testc_routes = RouteHop {
        destination: [
            (1, PriceId { price: 0, id: 1 }),
            (2, PriceId { price: 25, id: 1 }),
            (4, PriceId { price: 75, id: 1 }),
            (5, PriceId { price: 0, id: 5 }),
            (6, PriceId { price: 10, id: 8 }),
            (7, PriceId { price: 85, id: 1 }),
            (8, PriceId { price: 0, id: 8 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testd_routes = RouteHop {
        destination: [
            (1, PriceId { price: 50, id: 2 }),
            (2, PriceId { price: 0, id: 2 }),
            (3, PriceId { price: 75, id: 2 }),
            (5, PriceId { price: 90, id: 2 }),
            (6, PriceId { price: 100, id: 2 }),
            (7, PriceId { price: 0, id: 7 }),
            (8, PriceId { price: 90, id: 2 }),
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
            (4, PriceId { price: 90, id: 3 }),
            (6, PriceId { price: 0, id: 6 }),
            (7, PriceId { price: 100, id: 3 }),
            (8, PriceId { price: 15, id: 3 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testf_routes = RouteHop {
        destination: [
            (1, PriceId { price: 25, id: 8 }),
            (2, PriceId { price: 50, id: 8 }),
            (3, PriceId { price: 10, id: 8 }),
            (4, PriceId { price: 100, id: 8 }),
            (5, PriceId { price: 0, id: 5 }),
            (7, PriceId { price: 110, id: 8 }),
            (8, PriceId { price: 0, id: 8 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testg_routes = RouteHop {
        destination: [
            (1, PriceId { price: 60, id: 4 }),
            (2, PriceId { price: 10, id: 4 }),
            (3, PriceId { price: 85, id: 4 }),
            (4, PriceId { price: 0, id: 4 }),
            (5, PriceId { price: 100, id: 4 }),
            (6, PriceId { price: 110, id: 4 }),
            (8, PriceId { price: 100, id: 4 }),
        ]
        .iter()
        .cloned()
        .collect(),
    };
    let testh_routes = RouteHop {
        destination: [
            (1, PriceId { price: 15, id: 3 }),
            (2, PriceId { price: 40, id: 3 }),
            (3, PriceId { price: 0, id: 3 }),
            (4, PriceId { price: 90, id: 3 }),
            (5, PriceId { price: 15, id: 3 }),
            (6, PriceId { price: 0, id: 6 }),
            (7, PriceId { price: 100, id: 3 }),
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
    expected_routes.insert(testh, testh_routes);

    (nsinfo_exit, expected_routes)
}
