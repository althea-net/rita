use crate::utils::TEST_EXIT_DETAILS;

use super::babel::spawn_babel;
use super::namespaces::get_nsfd;
use super::namespaces::NamespaceInfo;
use super::namespaces::NodeType;
use actix_web::rt::System;
use actix_web::web;
use actix_web::App;
use actix_web::HttpServer;
use althea_kernel_interface::KernelInterfaceError;
use althea_types::Identity;
use althea_types::SignedExitServerList;
use clarity::Address;
use exit_trust_root;
use exit_trust_root::return_exit_contract_data;
use exit_trust_root::signature_update_loop;
use ipnetwork::IpNetwork;
use ipnetwork::Ipv6Network;
use log::info;
use nix::sched::{setns, CloneFlags};
use rita_client::{dashboard::start_client_dashboard, rita_loop::start_rita_client_loops};
use rita_common::rita_loop::{
    start_core_rita_endpoints, start_rita_common_loops,
    write_to_disk::{save_to_disk_loop, SettingsOnDisk},
};
use rita_exit::rita_loop::start_rita_exit_list_endpoint;
use rita_exit::{
    dashboard::start_rita_exit_dashboard,
    operator_update::update_loop::start_operator_update_loop,
    rita_loop::{start_rita_exit_endpoints, start_rita_exit_loop},
};
use settings::exit::EXIT_LIST_IP;
use settings::set_flag_config;
use settings::{client::RitaClientSettings, exit::RitaExitSettingsStruct};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    fs::{self},
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

/// This struct contains metadata about instances that the thread spanwer has spawned
/// if you need any data about an instance that can be had at startup use this to pass it
#[derive(Clone, Debug, Default)]
pub struct InstanceData {
    pub client_identities: Vec<Identity>,
    pub exit_identities: Vec<Identity>,
}

/// Spawn a rita and babel thread for each namespace, then assign those threads to said namespace
/// returns data about the spanwed instances that is used for coordination
pub fn thread_spawner(
    namespaces: NamespaceInfo,
    client_settings: RitaClientSettings,
    exit_settings: RitaExitSettingsStruct,
    db_addr: Address,
) -> Result<InstanceData, KernelInterfaceError> {
    let mut instance_data = InstanceData::default();
    let babeld_path = "/var/babeld/babeld".to_string();
    let babelconf_path = "/var/babeld/config".to_string();
    let babelconf_data = "default enable-timestamps true\ndefault update-interval 1";
    // pass the config arguments for babel to a config file as they cannot be successfully passed as arguments via run_command()
    fs::write(babelconf_path.clone(), babelconf_data).unwrap();
    for ns in namespaces.names.clone() {
        let veth_interfaces = get_veth_interfaces(namespaces.clone());
        let veth_interfaces = veth_interfaces.get(&ns.get_name()).unwrap().clone();

        spawn_babel(
            ns.clone().get_name(),
            babelconf_path.clone(),
            babeld_path.clone(),
        );

        // todo spawn exits first in order to pass data to the clients? Or configure via endpoints later?

        match ns.node_type.clone() {
            NodeType::Client { exit_name: _ } => {
                let instance_info = spawn_rita(
                    ns.get_name(),
                    veth_interfaces,
                    client_settings.clone(),
                    ns.cost,
                );
                instance_data.client_identities.push(instance_info);
            }
            NodeType::Exit { instance_name } => {
                let instance_info = spawn_rita_exit(
                    ns.get_name(),
                    instance_name,
                    veth_interfaces,
                    exit_settings.clone(),
                    ns.cost as u64,
                    ns.cost,
                    db_addr,
                );
                instance_data.exit_identities.push(instance_info);
            }
        }
    }
    Ok(instance_data)
}

/// get veth interfaces in a given namespace
pub fn get_veth_interfaces(nsinfo: NamespaceInfo) -> HashMap<String, HashSet<String>> {
    let mut res: HashMap<String, HashSet<String>> = HashMap::new();
    for name in nsinfo.names.iter() {
        res.insert(name.get_name(), HashSet::new());
    }
    for (a, b) in nsinfo.linked.iter() {
        let a_name = nsinfo.get_namespace(*a).unwrap().get_name();
        let b_name = nsinfo.get_namespace(*b).unwrap().get_name();
        let veth_ab = format!("veth-{}-{}", a_name, b_name);
        let veth_ba = format!("veth-{}-{}", b_name, a_name);
        res.entry(a_name).or_default().insert(veth_ab);
        res.entry(b_name).or_default().insert(veth_ba);
    }
    res
}

/// Spawn a thread for rita given a NamespaceInfo which will be assigned to the namespace given
pub fn spawn_rita(
    ns: String,
    veth_interfaces: HashSet<String>,
    mut rcsettings: RitaClientSettings,
    local_fee: u32,
) -> Identity {
    let ns_dup = ns.clone();
    let wg_keypath = format!("/var/tmp/{ns}");
    let config_path = format!("/var/tmp/settings-{ns}.toml");
    // thread safe lock that allows us to pass data between the router thread and this thread
    // one copy of the reference is sent into the closure and the other is kept in this scope.
    let router_identity_ref: Arc<RwLock<Option<Identity>>> = Arc::new(RwLock::new(None));
    let router_identity_ref_local = router_identity_ref.clone();

    let _rita_handler = thread::spawn(move || {
        // set the host of this thread to the ns
        let nsfd = get_nsfd(ns.clone());
        setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");

        // NOTE: this is why the names for the namespaces must include a number identifier, as it is used in
        // their mesh ip assignment
        let nameclone = ns.clone();
        let nsname: Vec<&str> = nameclone.split('-').collect();
        let id: u32 = nsname.get(1).unwrap().parse().unwrap();

        rcsettings.network.mesh_ip = Some(IpAddr::V6(Ipv6Addr::new(
            0xfd00,
            0,
            0,
            0,
            0,
            0,
            0,
            id.try_into().unwrap(),
        )));
        rcsettings.network.wg_private_key_path = wg_keypath;
        rcsettings.network.peer_interfaces = veth_interfaces;
        rcsettings.network.babeld_settings.local_fee = local_fee;

        // mirrored from rita_bin/src/client.rs
        let s = clu::init(rcsettings);
        set_flag_config(config_path.into());
        settings::set_rita_client(s.clone());

        // pass the data to the calling thread via thread safe lock
        *router_identity_ref.write().unwrap() = Some(s.get_identity().unwrap());

        let system = actix::System::new();

        start_rita_common_loops();
        start_rita_client_loops();
        save_to_disk_loop(SettingsOnDisk::RitaClientSettings(Box::new(
            settings::get_rita_client(),
        )));
        start_core_rita_endpoints(1);
        start_client_dashboard(s.network.rita_dashboard_port);

        if let Err(e) = system.run() {
            panic!("Starting client failed with {}", e);
        }
    });

    // wait for the child thread to finish initializing
    while router_identity_ref_local.read().unwrap().is_none() {
        info!("Waiting for Rita instance {} to generate keys", ns_dup);
        thread::sleep(Duration::from_millis(100));
    }
    let val = router_identity_ref_local.read().unwrap().unwrap();
    val
}

/// Spawn a thread for rita given a NamespaceInfo which will be assigned to the namespace given
pub fn spawn_rita_exit(
    ns: String,
    instance_name: String,
    veth_interfaces: HashSet<String>,
    mut resettings: RitaExitSettingsStruct,
    exit_fee: u64,
    local_fee: u32,
    db_addr: Address,
) -> Identity {
    let ns_dup = ns.clone();
    let wg_keypath = format!("/var/tmp/{ns}");
    let config_path = format!("/var/tmp/settings-{ns}.toml");
    // thread safe lock that allows us to pass data between the router thread and this thread
    // one copy of the reference is sent into the closure and the other is kept in this scope.
    let router_identity_ref: Arc<RwLock<Option<Identity>>> = Arc::new(RwLock::new(None));
    let router_identity_ref_local = router_identity_ref.clone();

    let instance = TEST_EXIT_DETAILS
        .get(&instance_name)
        .expect("Why is here no instance?");

    let _rita_handler = thread::spawn(move || {
        // set the host of this thread to the ns
        let nsfd = get_nsfd(ns.clone());
        setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");

        // NOTE: this is why the names for the namespaces must include a number identifier, as it is used in
        // their mesh ip assignment
        let nameclone = ns.clone();
        let nsname: Vec<&str> = nameclone.split('-').collect();
        let id: u32 = nsname.get(1).unwrap().parse().unwrap();

        resettings.network.mesh_ip = Some(IpAddr::V6(Ipv6Addr::new(
            0xfd00,
            0,
            0,
            0,
            0,
            0,
            0,
            id.try_into().unwrap(),
        )));
        resettings.network.alternate_mesh_ips = vec![EXIT_LIST_IP.into()];

        resettings.exit_network.subnet = Some(IpNetwork::V6(
            Ipv6Network::new(instance.subnet, 40).unwrap(),
        ));
        resettings.exit_network.registered_users_contract_addr = db_addr;
        resettings.network.wg_private_key = Some(instance.wg_priv_key);
        resettings.network.wg_public_key = Some(instance.exit_id.wg_public_key);
        resettings.network.wg_private_key_path = wg_keypath;
        resettings.network.peer_interfaces = veth_interfaces;
        resettings.network.babeld_settings.local_fee = local_fee;
        resettings.payment.eth_private_key = Some(instance.eth_private_key);
        resettings.exit_network.exit_price = exit_fee;
        let veth_exit_to_native = format!("vout-{}-o", ns);
        resettings.network.external_nic = Some(veth_exit_to_native);

        // mirrored from rita_bin/src/exit.rs
        let resettings = clu::exit_init(resettings);

        set_flag_config(config_path.into());
        settings::set_rita_exit(resettings.clone());

        // pass the data to the calling thread via thread safe lock
        *router_identity_ref.write().unwrap() = Some(resettings.get_identity().unwrap());

        start_rita_common_loops();
        start_operator_update_loop();
        save_to_disk_loop(SettingsOnDisk::RitaExitSettingsStruct(Box::new(
            settings::get_rita_exit(),
        )));

        let workers = 4;
        start_core_rita_endpoints(workers as usize);
        start_rita_exit_endpoints(workers as usize);
        start_rita_exit_list_endpoint(workers as usize);
        start_rita_exit_dashboard(Arc::new(RwLock::new(None)));

        // this one blocks
        start_rita_exit_loop(vec![]);
    });

    // wait for the child thread to finish initializing
    while router_identity_ref_local.read().unwrap().is_none() {
        info!("Waiting for Rita Exit instance {} to generate keys", ns_dup);
        thread::sleep(Duration::from_millis(100));
    }
    let val = router_identity_ref_local.read().unwrap().unwrap();
    val
}

/// Spawns the exit root server and waits for it to finish starting, panics if it does not finish starting
pub fn spawn_exit_root() {
    let successful_start: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let start_move = successful_start.clone();
    // the exit root server does not get its own namespace- instead it runs in the native namespace/host
    let exit_contract_data_cache: Arc<RwLock<HashMap<Address, SignedExitServerList>>> =
        Arc::new(RwLock::new(HashMap::new()));
    signature_update_loop(exit_contract_data_cache.clone());
    let web_data = web::Data::new(exit_contract_data_cache.clone());
    thread::spawn(move || {
        let successful_start = start_move.clone();
        let runner = System::new();
        runner.block_on(async move {
            let server = HttpServer::new(move || {
                App::new()
                    .service(return_exit_contract_data)
                    .app_data(web_data.clone())
            });
            info!("Starting exit trust root server on 10.0.0.1:4050");
            let server = server.bind("10.0.0.1:4050").unwrap();
            successful_start.store(true, Relaxed);
            let _ = server.run().await;
        });
    });

    const FAILURE_TIME: Duration = Duration::from_secs(10);
    let start = Instant::now();
    while start.elapsed() < FAILURE_TIME {
        if successful_start.clone().load(Relaxed) {
            break;
        }
    }
    if !successful_start.load(Relaxed) {
        panic!("Exit root server failed to start!");
    }
}
