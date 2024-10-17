use std::{str::from_utf8, thread, time::Duration};

use crate::{
    mutli_exit::multi_exit_config, registration_server::start_registration_server, setup_utils::{
        namespaces::{setup_ns, Namespace, NamespaceInfo},
        rita::{spawn_exit_root, thread_spawner},
    }, utils::{
        add_exits_contract_exit_list, deploy_contracts, get_default_settings, get_node_id_from_ip, populate_routers_eth, register_all_namespaces_to_exit, test_all_internet_connectivity, test_reach_all, test_routes
    }
};
use althea_kernel_interface::KI;

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

pub async fn run_exit_server_test() {
    info!("Starting exit server test");

    let node_configs = multi_exit_config();
    let namespaces = node_configs.0;
    let expected_routes = node_configs.1;

    info!("Waiting to deploy contracts");
    let db_addr = deploy_contracts().await;

    info!("Starting registration server");
    start_registration_server(db_addr).await;

    let (rita_client_settings, rita_exit_settings) = get_default_settings(namespaces.clone());

    namespaces.validate();

    let res = setup_ns(namespaces.clone());

    info!("Starting root server!");
    spawn_exit_root();

    let rita_identities = thread_spawner(
        namespaces.clone(),
        rita_client_settings,
        rita_exit_settings,
        db_addr,
    )
    .expect("Could not spawn Rita threads");
    info!("Thread Spawner: {res:?}");

    // Add exits to the contract exit list so clients get the propers exits they can migrate to
    add_exits_contract_exit_list(db_addr, rita_identities.clone()).await;
    
    // now routers must find exits on their own!
    // they must run the get_exit_list fn and register to one of the exits...


    populate_routers_eth(rita_identities).await;

    // Test for network convergence
    test_reach_all(namespaces.clone());

    test_routes(namespaces.clone(), expected_routes);

    info!("Registering routers to the exit");
    register_all_namespaces_to_exit(namespaces.clone()).await;

    thread::sleep(Duration::from_secs(100));

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

    const MIGRATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
    let start = std::time::Instant::now();

    while start.elapsed() < MIGRATION_ATTEMPT_TIMEOUT {
        let new_exit = get_current_exit(namespaces.names[0].clone(), namespaces.clone());
        if new_exit != current_exit {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

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
