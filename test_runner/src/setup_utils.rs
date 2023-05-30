use althea_kernel_interface::{KernelInterfaceError, KI};
use althea_types::Identity;
use diesel::{Connection, PgConnection};
use log::{error, info, warn};
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
use rita_exit::{
    operator_update::update_loop::start_operator_update_loop,
    rita_loop::{start_rita_exit_endpoints, start_rita_exit_loop},
    start_rita_exit_dashboard,
};
use settings::{client::RitaClientSettings, exit::RitaExitSettingsStruct};
use std::io::Write;
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    fs::{self, remove_file, File},
    io::stdout,
    net::{IpAddr, Ipv6Addr},
    path::Path,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
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
    /// Identifies if this node is a client or an exit
    pub node_type: NodeType,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum NodeType {
    Client,
    Exit,
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

            if let NodeType::Exit = space.node_type {
                if space.id == 1 {
                    // this would conflict with ip requirements for the internal
                    // bridge
                    panic!("Exits can not have id 1!");
                }
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

    const BRIDGE_NAME: &str = "br0";
    const BRIDGE_IP: &str = "10.0.0.1";
    const BRIDGE_IP_PREFIX: &str = "10.0.0.1/24";
    // the name of the external nic in the containers default namespace
    const EXTERNAL_NIC: &str = "eth0";

    // setup link for exits to the native namespace, providing them 'backhaul' interent
    // and the ability to reach the postgresql database in the native namespace
    let mut links_to_native_namespace = Vec::new();
    for name in spaces.names.iter() {
        if let NodeType::Exit = name.node_type {
            let veth_native_to_exit = format!("vout-o-{}", name.get_name());
            let veth_exit_to_native = format!("vout-{}-o", name.get_name());
            let exit_ip = format!(
                "10.0.{}.{}/24",
                name.id.to_be_bytes()[0],
                name.id.to_be_bytes()[1]
            );
            // collect these to attach to the virtual switch later
            links_to_native_namespace.push(veth_native_to_exit.clone());

            // delete the old native namespace veth for repeated runs
            // this veth should go away on it's own when the veths are cleared but that
            // can take long enough to cause a race condition
            KI.run_command("ip", &["link", "del", &veth_native_to_exit])?;

            // create link between exit and native namespace
            KI.run_command(
                "ip",
                &[
                    "link",
                    "add",
                    &veth_exit_to_native,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &veth_native_to_exit,
                ],
            )?;
            // set the exit side of the link to the correct namespace the other side is native
            KI.run_command(
                "ip",
                &[
                    "link",
                    "set",
                    &veth_exit_to_native,
                    "netns",
                    &name.get_name(),
                ],
            )?;
            KI.run_command("ip", &["link", "set", "up", &veth_native_to_exit])?;
            KI.run_command(
                "ip",
                &[
                    "netns",
                    "exec",
                    &name.get_name(),
                    "ip",
                    "link",
                    "set",
                    "up",
                    &veth_exit_to_native,
                ],
            )?;
            // add ip address for the exit
            KI.run_command(
                "ip",
                &[
                    "netns",
                    "exec",
                    &name.get_name(),
                    "ip",
                    "addr",
                    "add",
                    &exit_ip,
                    "dev",
                    &veth_exit_to_native,
                ],
            )?;
            // set default route
            KI.run_command(
                "ip",
                &[
                    "netns",
                    "exec",
                    &name.get_name(),
                    "ip",
                    "route",
                    "add",
                    "default",
                    "via",
                    BRIDGE_IP,
                    "dev",
                    &veth_exit_to_native,
                ],
            )?;
        }
    }

    // now we need to loop the interfaces we created and build a single bridge interface
    // this will make our job of forwarding their traffic to the internet much easier
    KI.run_command("ip", &["link", "add", BRIDGE_NAME, "type", "bridge"])?;
    for iface in links_to_native_namespace {
        KI.run_command("ip", &["link", "set", &iface, "master", BRIDGE_NAME])?;
    }
    KI.run_command("ip", &["link", "set", "up", BRIDGE_NAME])?;
    KI.run_command("ip", &["addr", "add", BRIDGE_IP_PREFIX, "dev", BRIDGE_NAME])?;
    // finally we setup a nat between this bridge and the native namespace, allowing traffic to exit
    KI.run_command(
        "iptables",
        &[
            "-A",
            "FORWARD",
            "-o",
            EXTERNAL_NIC,
            "-i",
            BRIDGE_NAME,
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-j",
            "ACCEPT",
        ],
    )?;
    KI.run_command(
        "iptables",
        &[
            "-A",
            "FORWARD",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )?;
    KI.run_command(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            EXTERNAL_NIC,
            "-j",
            "MASQUERADE",
        ],
    )?;

    // link individual namespaces
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

/// This struct contains metadata about instances that the thread spanwer has spawned
/// if you need any data about an instance that can be had at startup use this to pass it
#[derive(Clone, Debug, Default)]
pub struct InstanceData {
    client_identities: Vec<Identity>,
    exit_identities: Vec<Identity>,
}

/// Spawn a rita and babel thread for each namespace, then assign those threads to said namespace
/// returns data about the spanwed instances that is used for coordination
pub fn thread_spawner(
    namespaces: NamespaceInfo,
    rita_settings: RitaClientSettings,
    rita_exit_settings: RitaExitSettingsStruct,
) -> Result<InstanceData, KernelInterfaceError> {
    let mut instance_data = InstanceData::default();
    let babeld_path = "/var/babeld/babeld/babeld".to_string();
    let babelconf_path = "/var/babeld/config".to_string();
    let babelconf_data = "default enable-timestamps true\ndefault update-interval 1";
    // pass the config arguments for babel to a config file as they cannot be successfully passed as arguments via run_command()
    fs::write(babelconf_path.clone(), babelconf_data).unwrap();
    for ns in namespaces.names.clone() {
        let veth_interfaces = get_veth_interfaces(namespaces.clone());
        let veth_interfaces = veth_interfaces.get(&ns.get_name()).unwrap().clone();
        let nspath = format!("/var/run/netns/{}", ns.get_name());
        let nsfd = open(nspath.as_str(), OFlag::O_RDONLY, Mode::empty())
            .unwrap_or_else(|_| panic!("Could not open netns file: {}", nspath));

        spawn_babel(
            ns.clone().get_name(),
            babelconf_path.clone(),
            babeld_path.clone(),
        );

        // todo spawn exits first in order to pass data to the clients? Or configure via endpoints later?

        match ns.node_type {
            NodeType::Client => {
                let instance_info = spawn_rita(
                    ns.get_name(),
                    veth_interfaces,
                    rita_settings.clone(),
                    nsfd,
                    ns.cost,
                );
                instance_data.client_identities.push(instance_info);
            }
            NodeType::Exit => {
                let instance_info = spawn_rita_exit(
                    ns.get_name(),
                    veth_interfaces,
                    rita_exit_settings.clone(),
                    nsfd,
                    ns.cost as u64,
                    ns.cost,
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
pub fn spawn_rita_exit(
    ns: String,
    veth_interfaces: HashSet<String>,
    mut resettings: RitaExitSettingsStruct,
    nsfd: i32,
    exit_fee: u64,
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
        resettings.network.wg_private_key_path = wg_keypath;
        resettings.network.peer_interfaces = veth_interfaces;
        resettings.payment.local_fee = local_fee;
        resettings.exit_network.exit_price = exit_fee;
        // each exit instance connects to one database in the default net namespace
        resettings.db_uri = "postgresql://postgres@10.0.0.1/test".to_string();

        // mirrored from rita_bin/src/exit.rs
        let resettings = clu::exit_init("linux", resettings);
        settings::set_rita_exit(resettings.clone());

        // pass the data to the calling thread via thread safe lock
        *router_identity_ref.write().unwrap() = Some(resettings.get_identity().unwrap());

        let system = actix_async::System::new();

        start_rita_common_loops();
        start_rita_exit_loop();
        start_operator_update_loop();
        save_to_disk_loop(SettingsOnDisk::RitaExitSettingsStruct(
            settings::get_rita_exit(),
        ));

        let workers = 4;
        start_core_rita_endpoints(workers as usize);
        start_rita_exit_endpoints(workers as usize);
        start_rita_exit_dashboard();

        if let Err(e) = system.run() {
            panic!("Starting exit failed with {}", e);
        }
    });

    // wait for the child thread to finish initializing
    while router_identity_ref_local.read().unwrap().is_none() {
        info!("Waiting for Rita Exit instance {} to generate keys", ns_dup);
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

/// Starts the exit postgres instance in the native system namespace, TODO insert plumbing so that exits can reach it
pub fn start_postgres() {
    const POSTGRES_USER: &str = "postgres";
    const POSTGRES_BIN: &str = "/usr/lib/postgresql/15/bin/postgres";
    const INITDB_BIN: &str = "/usr/lib/postgresql/15/bin/initdb";
    // for this test script
    const DB_URL_LOCAL: &str = "postgres://postgres@localhost/test";
    // for the rita exit instances
    const POSTGRES_DATABASE_LOCATION: &str = "/var/lib/postgresql/data";
    let migration_directory = Path::new("/althea_rs/exit_db/migrations/");
    let postgres_pid_path: String = format!("{}/postmaster.pid", POSTGRES_DATABASE_LOCATION);

    // only init and launch if postgres has not already been started
    if !Path::new(&postgres_pid_path).exists() {
        // initialize the db datadir
        KI.run_command(
            "sudo",
            &[
                "-u",
                POSTGRES_USER,
                INITDB_BIN,
                "-D",
                POSTGRES_DATABASE_LOCATION,
            ],
        )
        .unwrap();

        // create the pg_hba.conf with auth for the 10.0.0.1 routers
        let pg_hba_path = format!("{}/pg_hba.conf", POSTGRES_DATABASE_LOCATION);
        let mut pg_hba = File::create(pg_hba_path).unwrap();
        let pb_hba_lines: [&str; 3] = [
            "local   all all trust",
            "host   all all 10.0.0.1/16 trust",
            "host   all all 127.0.0.1/32 trust",
        ];
        for line in pb_hba_lines {
            writeln!(pg_hba, "{}", line).unwrap()
        }
    }
    // start postgres in it's own thread, we kill it every time we startup
    // so it's spawned in this context
    thread::spawn(move || {
        let res = KI
            .run_command(
                "sudo",
                &[
                    "-u",
                    POSTGRES_USER,
                    POSTGRES_BIN,
                    "-D",
                    POSTGRES_DATABASE_LOCATION,
                ],
            )
            .unwrap();
        error!("Postgres has crashed {:?}", res);
    });

    // create connection to the now started database
    let mut conn = PgConnection::establish(DB_URL_LOCAL);
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
    let start = Instant::now();
    while let Err(e) = conn {
        warn!("Waiting for db to start {:?}", e);
        if Instant::now() - start > STARTUP_TIMEOUT {
            panic!("Postgres did not start! {:?}", e);
        }

        // reset database contents for every run, this is in the loop becuase it too must wait until the db has started
        KI.run_command("psql", &["-c", "drop database test;", "-U", POSTGRES_USER])
            .unwrap();
        KI.run_command(
            "psql",
            &["-c", "create database test;", "-U", POSTGRES_USER],
        )
        .unwrap();

        conn = PgConnection::establish(DB_URL_LOCAL);
        thread::sleep(Duration::from_millis(1000));
    }
    let conn = conn.unwrap();

    // run diesel migrations
    diesel_migrations::run_pending_migrations_in_directory(
        &conn,
        &migration_directory,
        &mut stdout(),
    )
    .unwrap();
}
