extern crate log;
// Uncomment for manual debugging
//use core::time;
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

use crate::tests::test_reach_all;

pub mod tests;

/// This struct holds the setup instructions for namespaces
#[derive(Clone, Eq, PartialEq)]
pub struct NamespaceInfo {
    /// Namespace names and corresponding numbers for ip assignment to avoid having to string
    /// parse every time we want its number for ips
    pub names: Vec<(String, u32)>,
    /// Linked nodes written as tuple pairs
    /// The string is for the namespace name(NOTE: names must be <=4 characters as interfaces
    /// cannot be more than 15 char, and we input as veth-{}-{})
    /// The u32 is for the subnet on the 3rd octet
    pub linked: Vec<((String, u32), (String, u32))>,
}

fn main() {
    // uncomment these 2 lines for manual debugging 600
    //let ten_mins = time::Duration::from_secs(300);
    //env_logger::init();

    let namespaces = five_node_config();

    validate_connections(namespaces.clone());

    let res = setup_ns(namespaces.clone());
    println!("Namespaces setup: {res:?}");

    let res = thread_spawner(namespaces.clone());
    println!("Thread Spawner: {:?}", res);

    // this sleep is for debugging so that the container can be accessed to poke around in
    //thread::sleep(ten_mins);

    let res = test_reach_all(namespaces).expect("Could not reach all namespaces!");
    println!("Reachability Test: {:?}", res);
}

fn five_node_config() -> NamespaceInfo {
    /*
    These are connected as such:
    A---------B
     \       /|
      \     / |
       \   /  |
        \ /   |
         X    |
        / \   |
       /   \  |
      /     \ |
     /       \|
    D---------C
    */
    let testa = ("n-1".to_string(), 1);
    let testb = ("n-2".to_string(), 2);
    let testc = ("n-3".to_string(), 3);
    let testd = ("n-4".to_string(), 4);

    NamespaceInfo {
        names: vec![testa.clone(), testb.clone(), testc.clone(), testd.clone()],
        linked: vec![
            // arbitrary connections
            (testa.clone(), testb.clone()),
            (testb.clone(), testc.clone()),
            (testa, testc.clone()),
            (testc, testd.clone()),
            (testb, testd),
        ],
    }
}

fn setup_ns(spaces: NamespaceInfo) -> Result<(), KernelInterfaceError> {
    // arbitrary number for the IP assignment
    let mut counter = 6;
    // clear namespaces
    KI.run_command("ip", &["-all", "netns", "delete", "||", "true"])?;
    // add namespaces
    for name in spaces.names {
        let res = KI.run_command("ip", &["netns", "add", &name.0]);
        println!("{:?}", res);
        // ip netns exec nB ip link set dev lo up
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &name.0, "ip", "link", "set", "dev", "lo", "up",
            ],
        );
        println!("{res:?}");
    }
    for link in spaces.linked {
        let veth_ab = format!("veth-{}-{}", link.0 .0, link.1 .0);
        let veth_ba = format!("veth-{}-{}", link.1 .0, link.0 .0);
        let ip_ab = format!("192.168.{}.{}/24", link.0 .1, counter);
        let ip_ba = format!("192.168.{}.{}/24", link.1 .1, counter);
        let subnet_a = format!("192.168.{}.0/24", link.0 .1);
        let subnet_b = format!("192.168.{}.0/24", link.1 .1);

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
        let res = KI.run_command("ip", &["link", "set", &veth_ab, "netns", &link.0 .0]);
        println!("{res:?}");
        let res = KI.run_command("ip", &["link", "set", &veth_ba, "netns", &link.1 .0]);
        println!("{res:?}");

        // add ip addresses on each side
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.0 .0, "ip", "addr", "add", &ip_ab, "dev", &veth_ab,
            ],
        );
        println!("{res:?}");

        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.1 .0, "ip", "addr", "add", &ip_ba, "dev", &veth_ba,
            ],
        );
        println!("{res:?}");

        // bring the interfaces up
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.0 .0, "ip", "link", "set", "dev", &veth_ab, "up",
            ],
        );
        println!("{res:?}");

        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.1 .0, "ip", "link", "set", "dev", &veth_ba, "up",
            ],
        );
        println!("{res:?}");

        //  ip netns exec nC ip route add 192.168.0.0/24 dev veth-nC-nA
        // add routes to each other's subnets
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.0 .0, "ip", "route", "add", &subnet_b, "dev", &veth_ab,
            ],
        );
        println!("{res:?}");
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.1 .0, "ip", "route", "add", &subnet_a, "dev", &veth_ba,
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
        let veth_interfaces = veth_interfaces.get(&ns.0).unwrap().clone();
        let rcsettings = ritasettings.clone();
        let nspath = format!("/var/run/netns/{}", ns.0);
        let nsfd = open(nspath.as_str(), OFlag::O_RDONLY, Mode::empty())
            .unwrap_or_else(|_| panic!("Could not open netns file: {}", nspath));

        spawn_rita(ns.clone().0, veth_interfaces, rcsettings, nsfd);

        spawn_babel(ns.0, babelconf_path.clone(), babeld_path.clone(), nsfd);
    }
    Ok(())
}

/// Validate the list of linked namespaces
fn validate_connections(namespaces: NamespaceInfo) {
    for link in namespaces.linked {
        if !namespaces.names.contains(&link.0) || !namespaces.names.contains(&link.1) {
            panic!(
                "One or both of these names is not in the given namespace list: {}, {}",
                link.0 .0, link.1 .0
            )
        }
        if link.0 .0.len() + link.1 .0.len() > 8 {
            panic!(
                "Namespace names are too long(max 4 chars): {}, {}",
                link.0 .0, link.1 .0,
            )
        }
        if link.0 .0.eq(&link.1 .0) {
            panic!("Cannot link namespace to itself!")
        }
    }
}

/// get veth interfaces in a given namespace
fn get_veth_interfaces(nsinfo: NamespaceInfo) -> HashMap<String, HashSet<String>> {
    let mut res: HashMap<String, HashSet<String>> = HashMap::new();
    for name in nsinfo.names {
        res.insert(name.0, HashSet::new());
    }
    for link in nsinfo.linked {
        let veth_ab = format!("veth-{}-{}", link.0 .0, link.1 .0);
        let veth_ba = format!("veth-{}-{}", link.1 .0, link.0 .0);
        res.entry(link.0 .0).or_default().insert(veth_ab);
        res.entry(link.1 .0).or_default().insert(veth_ba);
    }
    res
}

/// Spawn a thread for rita given a NamespaceInfo which will be assigned to the namespace given
fn spawn_rita(
    ns: String,
    veth_interfaces: HashSet<String>,
    mut rcsettings: RitaClientSettings,
    nsfd: i32,
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
        rcsettings.payment.local_fee = 10; //arbitrary for now

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
