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
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    fs,
    net::{IpAddr, Ipv6Addr},
    thread,
};

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

pub fn setup_ns(spaces: NamespaceInfo) -> Result<(), KernelInterfaceError> {
    // arbitrary number for the IP assignment
    let mut counter = 6;
    // clear namespaces
    KI.run_command("ip", &["-all", "netns", "delete", "||", "true"])?;
    // add namespaces
    for ns in spaces.names {
        KI.run_command("ip", &["netns", "add", &ns.name])?;
        // ip netns exec nB ip link set dev lo up
        KI.run_command(
            "ip",
            &[
                "netns", "exec", &ns.name, "ip", "link", "set", "dev", "lo", "up",
            ],
        )?;
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
        KI.run_command(
            "ip",
            &[
                "link", "add", &veth_ab, "type", "veth", "peer", "name", &veth_ba,
            ],
        )?;
        // assign each side of the veth to one of the nodes namespaces
        KI.run_command("ip", &["link", "set", &veth_ab, "netns", &link.0.name])?;
        KI.run_command("ip", &["link", "set", &veth_ba, "netns", &link.1.name])?;

        // add ip addresses on each side
        KI.run_command(
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
        )?;
        KI.run_command(
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
        )?;

        // bring the interfaces up
        KI.run_command(
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
        )?;

        KI.run_command(
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
        )?;

        //  ip netns exec nC ip route add 192.168.0.0/24 dev veth-nC-nA
        // add routes to each other's subnets
        KI.run_command(
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
        )?;
        KI.run_command(
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
        )?;
    }

    Ok(())
}

/// Spawn a rita and babel thread for each namespace, then assign those threads to said namespace
pub fn thread_spawner(namespaces: NamespaceInfo) -> Result<(), KernelInterfaceError> {
    let babeld_path = "/var/babeld/babeld/babeld".to_string();
    let babelconf_path = "/var/babeld/config".to_string();
    let ritasettings =
        RitaClientSettings::new("/althea_rs/scripts/legacy_integration_test/rita-test.toml")
            .unwrap();
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

/// get veth interfaces in a given namespace
pub fn get_veth_interfaces(nsinfo: NamespaceInfo) -> HashMap<String, HashSet<String>> {
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
pub fn spawn_rita(
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
        rcsettings.payment.local_fee = local_fee;

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
        info!("Started rita loops");

        if let Err(e) = system.run() {
            panic!("Starting client failed with {}", e);
        }

        info!("Started Rita Client!");
    });
}

/// Spawn a thread for rita given a NamespaceInfo which will be assigned to the namespace given
pub fn spawn_babel(ns: String, babelconf_path: String, babeld_path: String, nsfd: i32) {
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
        info!("res of babel {res:?}");
        // set the host of this thread to the ns
        setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");
    });
}
