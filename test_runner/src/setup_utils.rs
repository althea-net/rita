use althea_kernel_interface::{KernelInterfaceError, KI};
use althea_types::Identity;
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
    fs::{self, remove_file},
    net::{IpAddr, Ipv6Addr},
    path::Path,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

/// This struct holds the format for a namespace info
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Namespace {
    /// ID number of the namespace, limited to u16 for ip reasons, also having
    /// more than u16 max instances would be a little crazy
    pub id: u16,
    /// Local Fee of the rita instance in the namespace, used also to assign
    /// edge weight on the network graph
    pub cost: u32,
}

impl Namespace {
    /// Gets the string format name for this namespace
    pub fn get_name(&self) -> String {
        format!("n-{}", self.id)
    }
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
    pub linked: Vec<(u16, u16)>,
}

impl NamespaceInfo {
    /// Validate the list of linked namespaces
    pub fn validate(&self) {
        // list of seen IDs for duplicate detection
        let mut seen_id = HashSet::new();
        for space in self.names.iter() {
            // HashSets return false if they already contain a specific entry
            if !seen_id.insert(space.id) {
                panic!("Duplicate id in namespace definition {}", space.id)
            }
        }

        for (a, b) in self.linked.iter() {
            if a == b {
                panic!("Cannot link namespace to itself!")
            }
            match (self.get_namespace(*a), self.get_namespace(*b)) {
                (Some(a), Some(b)) => {
                    if a.get_name().len() + b.get_name().len() > 8 {
                        panic!(
                            "Namespace names are too long(max 4 chars): {}, {}",
                            a.get_name(),
                            b.get_name(),
                        )
                    }
                }
                (_, _) => panic!(
                    "One or both of these names is not in the given namespace list: {}, {}",
                    a, b
                ),
            }
        }
    }

    pub fn get_namespace(&self, id: u16) -> Option<Namespace> {
        for space in self.names.iter() {
            if space.id == id {
                return Some(space.clone());
            }
        }
        None
    }
}

/// For each key in destination, the u32 value is the price we expect to see in its route,
/// and the namespace value is the next hop we take to reach the key. This struct is meant to
/// be used within an outer hashmap which holds the "from" namespace.
#[derive(Clone, Eq, PartialEq)]
pub struct RouteHop {
    pub destination: HashMap<u16, PriceId>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PriceId {
    pub price: u32,
    pub id: u16,
}

pub fn setup_ns(spaces: NamespaceInfo) -> Result<(), KernelInterfaceError> {
    // arbitrary number for the IP assignment
    let mut counter = 6;
    // clear namespaces
    KI.run_command("ip", &["-all", "netns", "delete", "||", "true"])?;
    // add namespaces
    for ns in spaces.names.iter() {
        KI.run_command("ip", &["netns", "add", &ns.get_name()])?;
        // ip netns exec nB ip link set dev lo up
        KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &ns.get_name(),
                "ip",
                "link",
                "set",
                "dev",
                "lo",
                "up",
            ],
        )?;
        // nft create table inet fw4
        KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &ns.get_name(),
                "nft",
                "create",
                "table",
                "inet",
                "fw4",
            ],
        )?;
        // nft add chain inet fw4 input { type filter hook input priority filter; policy accept; }
        // nft add chain inet fw4 output { type filter hook output priority filter; policy accept; }
        // nft add chain inet fw4 forward { type filter hook forward priority filter; policy accept; }
        KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &ns.get_name(),
                "nft",
                "add",
                "chain",
                "inet",
                "fw4",
                "input",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "filter;",
                "policy",
                "accept;",
                "}",
            ],
        )?;
        KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &ns.get_name(),
                "nft",
                "add",
                "chain",
                "inet",
                "fw4",
                "output",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "filter;",
                "policy",
                "accept;",
                "}",
            ],
        )?;
        KI.run_command(
            "ip",
            &[
                "netns",
                "exec",
                &ns.get_name(),
                "nft",
                "add",
                "chain",
                "inet",
                "fw4",
                "forward",
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "filter;",
                "policy",
                "accept;",
                "}",
            ],
        )?;
    }
    for (a, b) in spaces.linked.iter() {
        let a_name = spaces.get_namespace(*a).unwrap().get_name();
        let b_name = spaces.get_namespace(*b).unwrap().get_name();
        let veth_ab = format!("veth-{}-{}", a_name, b_name);
        let veth_ba = format!("veth-{}-{}", b_name, a_name);
        let ip_ab = format!("192.168.{}.{}/24", a, counter);
        let ip_ba = format!("192.168.{}.{}/24", b, counter);
        let subnet_a = format!("192.168.{}.0/24", a);
        let subnet_b = format!("192.168.{}.0/24", b);

        counter += 1;
        // create veth to link them
        KI.run_command(
            "ip",
            &[
                "link", "add", &veth_ab, "type", "veth", "peer", "name", &veth_ba,
            ],
        )?;
        // assign each side of the veth to one of the nodes namespaces
        KI.run_command("ip", &["link", "set", &veth_ab, "netns", &a_name])?;
        KI.run_command("ip", &["link", "set", &veth_ba, "netns", &b_name])?;

        // add ip addresses on each side
        KI.run_command(
            "ip",
            &[
                "netns", "exec", &a_name, "ip", "addr", "add", &ip_ab, "dev", &veth_ab,
            ],
        )?;
        KI.run_command(
            "ip",
            &[
                "netns", "exec", &b_name, "ip", "addr", "add", &ip_ba, "dev", &veth_ba,
            ],
        )?;

        // bring the interfaces up
        KI.run_command(
            "ip",
            &[
                "netns", "exec", &a_name, "ip", "link", "set", "dev", &veth_ab, "up",
            ],
        )?;

        KI.run_command(
            "ip",
            &[
                "netns", "exec", &b_name, "ip", "link", "set", "dev", &veth_ba, "up",
            ],
        )?;

        //  ip netns exec nC ip route add 192.168.0.0/24 dev veth-nC-nA
        // add routes to each other's subnets
        KI.run_command(
            "ip",
            &[
                "netns", "exec", &a_name, "ip", "route", "add", &subnet_b, "dev", &veth_ab,
            ],
        )?;
        KI.run_command(
            "ip",
            &[
                "netns", "exec", &b_name, "ip", "route", "add", &subnet_a, "dev", &veth_ba,
            ],
        )?;
    }

    Ok(())
}

/// Spawn a rita and babel thread for each namespace, then assign those threads to said namespace
/// returns data about the spanwed instances that is used for coordination
pub fn thread_spawner(
    namespaces: NamespaceInfo,
    rita_settings: RitaClientSettings,
) -> Result<Vec<Identity>, KernelInterfaceError> {
    let mut instance_data = Vec::new();
    let babeld_path = "/var/babeld/babeld/babeld".to_string();
    let babelconf_path = "/var/babeld/config".to_string();
    let babelconf_data = "default enable-timestamps true\ndefault update-interval 1";
    // pass the config arguments for babel to a config file as they cannot be successfully passed as arguments via run_command()
    fs::write(babelconf_path.clone(), babelconf_data).unwrap();
    for ns in namespaces.names.clone() {
        let veth_interfaces = get_veth_interfaces(namespaces.clone());
        let veth_interfaces = veth_interfaces.get(&ns.get_name()).unwrap().clone();
        let rcsettings = rita_settings.clone();
        let nspath = format!("/var/run/netns/{}", ns.get_name());
        let nsfd = open(nspath.as_str(), OFlag::O_RDONLY, Mode::empty())
            .unwrap_or_else(|_| panic!("Could not open netns file: {}", nspath));
        let local_fee = ns.cost;

        spawn_babel(
            ns.clone().get_name(),
            babelconf_path.clone(),
            babeld_path.clone(),
        );

        let instance_info = spawn_rita(ns.get_name(), veth_interfaces, rcsettings, nsfd, local_fee);
        instance_data.push(instance_info);
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
    nsfd: i32,
    local_fee: u32,
) -> Identity {
    let ns_dup = ns.clone();
    let wg_keypath = format!("/var/tmp/{ns}");
    // thread safe lock that allows us to pass data between the router thread and this thread
    // one copy of the reference is sent into the closure and the other is kept in this scope.
    let router_identity_ref: Arc<RwLock<Option<Identity>>> = Arc::new(RwLock::new(None));
    let router_identity_ref_local = router_identity_ref.clone();

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

        // pass the data to the calling thread via thread safe lock
        *router_identity_ref.write().unwrap() = Some(s.get_identity().unwrap());

        let system = actix_async::System::new();

        start_rita_common_loops();
        start_rita_client_loops();
        save_to_disk_loop(SettingsOnDisk::RitaClientSettings(
            settings::get_rita_client(),
        ));
        start_core_rita_endpoints(4);
        start_client_dashboard(s.network.rita_dashboard_port);
        start_antenna_forwarder(s);

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
pub fn spawn_babel(ns: String, babelconf_path: String, babeld_path: String) {
    // create a thread, set the namespace of that thread, spawn babel, then join the thread
    // so that we don't move on until babel is started
    let _babel_handler = thread::spawn(move || {
        let pid_path = format!("/var/run/babeld-{ns}.pid");
        // if babel has previously been running in this container it won't start
        // unless the pid file is deleted since that will indicate another instance
        // of babel is running
        let _ = remove_file(pid_path.clone());
        let babeld_pid = pid_path.clone();
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
        // waits for babel to finish starting up and create it's pid file
        while !Path::new(&pid_path).exists() {
            thread::sleep(Duration::from_millis(100));
        }
    })
    .join();
}
