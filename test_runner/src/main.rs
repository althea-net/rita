extern crate log;
// Uncomment for manual debugging
use core::time;
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    fs,
    net::{IpAddr, Ipv6Addr},
    thread,
};

use althea_kernel_interface::{KernelInterfaceError, KI};
use log::info;
use nix::{
    fcntl::{open, OFlag},
    sched::{setns, CloneFlags},
    sys::stat::Mode,
};
use rita_client::{
    dashboard::start_client_dashboard,
    rita_loop::{start_antenna_forwarder, start_rita_client_loops},
};
use rita_common::rita_loop::{
    start_core_rita_endpoints, start_rita_common_loops,
    write_to_disk::{save_to_disk_loop, SettingsOnDisk},
};
use settings::client::RitaClientSettings;

use crate::tests::{test_reach_all, test_routes};

pub mod tests;

/// This struct holds the format for a namespace info
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Namespace {
    /// Name assigned to the namespace
    pub name: String,
    /// ID number of the namespace
    pub id: u32,
    /// Local Fee of the rita instance in the namespace, used also to assign
    /// edge weight on the network graph
    pub cost: u32,
}

/// This struct holds the setup instructions for namespaces
#[derive(Clone, Eq, PartialEq)]
pub struct NamespaceInfo {
    /// Namespace names and corresponding numbers for ip assignment to avoid having to string
    /// parse every time we want its number for ips, last number is cost (local fee)
    pub names: Vec<Namespace>,
    /// Linked nodes written as tuple pairs
    /// The string is for the namespace name(NOTE: names must be <=4 characters as interfaces
    /// cannot be more than 15 char, and we input as veth-{}-{})
    /// The u32 is for the subnet on the 3rd octet
    pub linked: Vec<(Namespace, Namespace)>,
}

/// For each key in destination, the u32 value is the price we expect to see in its route,
/// and the namespace value is the next hop we take to reach the key. This struct is meant to
/// be used within an outer hashmap which holds the "from" namespace.
pub struct RouteHop {
    pub destination: HashMap<Namespace, (u32, Namespace)>,
}

fn main() {
    // uncomment these 2 lines for manual debugging 600
    //let five_mins = time::Duration::from_secs(300);
    //env_logger::init();

    let one_min = time::Duration::from_secs(60);

    let node_config = five_node_config();
    let namespaces = node_config.0;
    let expected_routes = node_config.1;

    validate_connections(namespaces.clone());

    let res = setup_ns(namespaces.clone());
    println!("Namespaces setup: {res:?}");

    let res = thread_spawner(namespaces.clone());
    println!("Thread Spawner: {res:?}");

    // allow setup to finish before running tests
    thread::sleep(one_min);

    // this sleep is for debugging so that the container can be accessed to poke around in
    //thread::sleep(five_mins);

    let res1 = test_reach_all(namespaces.clone()).expect("Could not reach all namespaces!");
    println!("Reachability Test: {res1}");

    let res2 = test_routes(namespaces, expected_routes);
    // this just returns a number at the moment, which must be 12 until more test instances are added
    println!("Routes Test: {res2}");

    if res1 != 49 || res2 != 42 {
        std::process::exit(1);
    }
}

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

fn setup_ns(spaces: NamespaceInfo) -> Result<(), KernelInterfaceError> {
    // arbitrary number for the IP assignment
    let mut counter = 6;
    // clear namespaces
    KI.run_command("ip", &["-all", "netns", "delete", "||", "true"])?;
    // add namespaces
    for ns in spaces.names {
        let res = KI.run_command("ip", &["netns", "add", &ns.name]);
        println!("{res:?}");
        // ip netns exec nB ip link set dev lo up
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &ns.name, "ip", "link", "set", "dev", "lo", "up",
            ],
        );
        println!("{res:?}");
    }
    for link in spaces.linked {
        let veth_ab = format!("veth-{}-{}", link.0.name, link.1.name);
        let veth_ba = format!("veth-{}-{}", link.1.name, link.0.name);
        let ip_ab = format!("192.168.{}.{}/24", link.0.id, counter);
        let ip_ba = format!("192.168.{}.{}/24", link.1.id, counter);
        let subnet_a = format!("192.168.{}.0/24", link.0.id);
        let subnet_b = format!("192.168.{}.0/24", link.1.id);

        counter += 1;
        // create veth to link them
        let res = KI.run_command(
            "ip",
            &[
                "link", "add", &veth_ab, "type", "veth", "peer", "name", &veth_ba,
            ],
        );
        println!("{res:?}");
        // assign each side of the veth to one of the nodes namespaces
        let res = KI.run_command("ip", &["link", "set", &veth_ab, "netns", &link.0.name]);
        println!("{res:?}");
        let res = KI.run_command("ip", &["link", "set", &veth_ba, "netns", &link.1.name]);
        println!("{res:?}");

        // add ip addresses on each side
        let res = KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &link.0.name,
                "ip",
                "addr",
                "add",
                &ip_ab,
                "dev",
                &veth_ab,
            ],
        );
        println!("{res:?}");

        let res = KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &link.1.name,
                "ip",
                "addr",
                "add",
                &ip_ba,
                "dev",
                &veth_ba,
            ],
        );
        println!("{res:?}");

        // bring the interfaces up
        let res = KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &link.0.name,
                "ip",
                "link",
                "set",
                "dev",
                &veth_ab,
                "up",
            ],
        );
        println!("{res:?}");

        let res = KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &link.1.name,
                "ip",
                "link",
                "set",
                "dev",
                &veth_ba,
                "up",
            ],
        );
        println!("{res:?}");

        //  ip netns exec nC ip route add 192.168.0.0/24 dev veth-nC-nA
        // add routes to each other's subnets
        let res = KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &link.0.name,
                "ip",
                "route",
                "add",
                &subnet_b,
                "dev",
                &veth_ab,
            ],
        );
        println!("{res:?}");
        let res = KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &link.1.name,
                "ip",
                "route",
                "add",
                &subnet_a,
                "dev",
                &veth_ba,
            ],
        );
        println!("{res:?}");
    }

    Ok(())
}

/// Spawn a rita and babel thread for each namespace, then assign those threads to said namespace
fn thread_spawner(namespaces: NamespaceInfo) -> Result<(), KernelInterfaceError> {
    let babeld_path = "/var/babeld/babeld/babeld".to_string();
    let babelconf_path = "/var/babeld/config".to_string();
    let ritasettings = RitaClientSettings::new("/althea_rs/scripts/rita-test.toml").unwrap();
    let babelconf_data = "default enable-timestamps true\ndefault update-interval 1";
    // pass the config arguments for babel to a config file as they cannot be successfully passed as arguments via run_command()
    fs::write(babelconf_path.clone(), babelconf_data).unwrap();
    for ns in namespaces.names.clone() {
        let veth_interfaces = get_veth_interfaces(namespaces.clone());
        let veth_interfaces = veth_interfaces.get(&ns.name).unwrap().clone();
        let rcsettings = ritasettings.clone();
        let nspath = format!("/var/run/netns/{}", ns.name);
        let nsfd = open(nspath.as_str(), OFlag::O_RDONLY, Mode::empty())
            .unwrap_or_else(|_| panic!("Could not open netns file: {}", nspath));
        let local_fee = ns.cost;

        spawn_rita(
            ns.clone().name,
            veth_interfaces,
            rcsettings,
            nsfd,
            local_fee,
        );

        spawn_babel(ns.name, babelconf_path.clone(), babeld_path.clone(), nsfd);
    }
    Ok(())
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

/// get veth interfaces in a given namespace
fn get_veth_interfaces(nsinfo: NamespaceInfo) -> HashMap<String, HashSet<String>> {
    let mut res: HashMap<String, HashSet<String>> = HashMap::new();
    for name in nsinfo.names {
        res.insert(name.name, HashSet::new());
    }
    for link in nsinfo.linked {
        let veth_ab = format!("veth-{}-{}", link.0.name, link.1.name);
        let veth_ba = format!("veth-{}-{}", link.1.name, link.0.name);
        res.entry(link.0.name).or_default().insert(veth_ab);
        res.entry(link.1.name).or_default().insert(veth_ba);
    }
    res
}

/// Spawn a thread for rita given a NamespaceInfo which will be assigned to the namespace given
fn spawn_rita(
    ns: String,
    veth_interfaces: HashSet<String>,
    mut rcsettings: RitaClientSettings,
    nsfd: i32,
    local_fee: u32,
) {
    let wg_keypath = format!("/var/tmp/{ns}");
    let _rita_handler = thread::spawn(move || {
        // set the host of this thread to the ns
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
        let s = clu::init("linux", rcsettings);
        settings::set_rita_client(s.clone());

        let system = actix_async::System::new();

        start_rita_common_loops();
        start_rita_client_loops();
        save_to_disk_loop(SettingsOnDisk::RitaClientSettings(
            settings::get_rita_client(),
        ));
        start_core_rita_endpoints(4);
        start_client_dashboard(s.network.rita_dashboard_port);
        start_antenna_forwarder(s);
        println!("Started rita loops");

        if let Err(e) = system.run() {
            panic!("Starting client failed with {}", e);
        }

        info!("Started Rita Client!");
    });
}

/// Spawn a thread for rita given a NamespaceInfo which will be assigned to the namespace given
fn spawn_babel(ns: String, babelconf_path: String, babeld_path: String, nsfd: i32) {
    let _babel_handler = thread::spawn(move || {
        let babeld_pid = format!("/var/run/babeld-{ns}.pid");
        let babeld_log = format!("/var/log/babeld-{ns}.log");
        // 1 here is for log
        let res = KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &ns,
                &babeld_path,
                "-I",
                &babeld_pid,
                "-d",
                "1",
                "-r",
                "-L",
                &babeld_log,
                "-H",
                "1",
                "-G",
                "6872",
                "-w",
                "lo",
                "-c",
                &babelconf_path,
                "-D",
            ],
        );
        println!("res of babel {res:?}");
        // set the host of this thread to the ns
        setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");
    });
}
