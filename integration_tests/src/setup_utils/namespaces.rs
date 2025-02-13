use althea_kernel_interface::{run_command, KernelInterfaceError};
use nix::{
    fcntl::{open, OFlag},
    sys::stat::Mode,
};
use settings::exit::EXIT_LIST_IP;
use std::collections::{HashMap, HashSet};

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
    Client {
        // The exit this client should be connected to at network init
        exit_name: String,
    },
    Exit {
        instance_name: String,
    },
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

            if let NodeType::Exit { .. } = space.node_type {
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
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RouteHop {
    pub destination: HashMap<u16, PriceId>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PriceId {
    pub price: u32,
    pub id: u16,
}

pub fn setup_ns(spaces: NamespaceInfo, exit_mode: &str) -> Result<(), KernelInterfaceError> {
    // arbitrary number for the IP assignment
    let mut counter = 6;
    // clear namespaces
    run_command("ip", &["-all", "netns", "delete", "||", "true"])?;
    // add namespaces
    for ns in spaces.names.iter() {
        run_command("ip", &["netns", "add", &ns.get_name()])?;
        // ip netns exec nB ip link set dev lo up
        run_command(
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
        run_command(
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
        run_command(
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
        run_command(
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
        run_command(
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
        if let NodeType::Exit { .. } = name.node_type {
            let veth_native_to_exit = format!("vout-o-{}", name.get_name());
            let veth_exit_to_native = format!("vout-{}-o", name.get_name());
            let exit_ip = match exit_mode {
                "snat" => "10.0.0.2/24".to_string(),
                "cgnat" => "10.0.0.2/24".to_string(),
                _ => format!(
                    "10.0.{}.{}/24",
                    name.id.to_be_bytes()[0],
                    name.id.to_be_bytes()[1]
                ),
            };
            // collect these to attach to the virtual switch later
            links_to_native_namespace.push(veth_native_to_exit.clone());

            // delete the old native namespace veth for repeated runs
            // this veth should go away on it's own when the veths are cleared but that
            // can take long enough to cause a race condition
            run_command("ip", &["link", "del", &veth_native_to_exit])?;

            // create link between exit and native namespace
            run_command(
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
            run_command(
                "ip",
                &[
                    "link",
                    "set",
                    &veth_exit_to_native,
                    "netns",
                    &name.get_name(),
                ],
            )?;
            run_command("ip", &["link", "set", "up", &veth_native_to_exit])?;
            run_command(
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
            run_command(
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
            // add ip address for the exit list endpoint
            run_command(
                "ip",
                &[
                    "netns",
                    "exec",
                    &name.get_name(),
                    "ip",
                    "addr",
                    "add",
                    &EXIT_LIST_IP.to_string(),
                    "dev",
                    &veth_exit_to_native,
                ],
            )?;
            // set default route
            run_command(
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
    run_command("ip", &["link", "add", BRIDGE_NAME, "type", "bridge"])?;
    for iface in links_to_native_namespace {
        run_command("ip", &["link", "set", &iface, "master", BRIDGE_NAME])?;
    }
    run_command("ip", &["link", "set", "up", BRIDGE_NAME])?;
    run_command("ip", &["addr", "add", BRIDGE_IP_PREFIX, "dev", BRIDGE_NAME])?;
    // finally we setup a nat between this bridge and the native namespace, allowing traffic to exit
    run_command(
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
    run_command(
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
    run_command(
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
        run_command(
            "ip",
            &[
                "link", "add", &veth_ab, "type", "veth", "peer", "name", &veth_ba,
            ],
        )?;
        // assign each side of the veth to one of the nodes namespaces
        run_command("ip", &["link", "set", &veth_ab, "netns", &a_name])?;
        run_command("ip", &["link", "set", &veth_ba, "netns", &b_name])?;

        // add ip addresses on each side
        run_command(
            "ip",
            &[
                "netns", "exec", &a_name, "ip", "addr", "add", &ip_ab, "dev", &veth_ab,
            ],
        )?;
        run_command(
            "ip",
            &[
                "netns", "exec", &b_name, "ip", "addr", "add", &ip_ba, "dev", &veth_ba,
            ],
        )?;

        // bring the interfaces up
        run_command(
            "ip",
            &[
                "netns", "exec", &a_name, "ip", "link", "set", "dev", &veth_ab, "up",
            ],
        )?;

        run_command(
            "ip",
            &[
                "netns", "exec", &b_name, "ip", "link", "set", "dev", &veth_ba, "up",
            ],
        )?;

        //  ip netns exec nC ip route add 192.168.0.0/24 dev veth-nC-nA
        // add routes to each other's subnets
        run_command(
            "ip",
            &[
                "netns", "exec", &a_name, "ip", "route", "add", &subnet_b, "dev", &veth_ab,
            ],
        )?;
        run_command(
            "ip",
            &[
                "netns", "exec", &b_name, "ip", "route", "add", &subnet_a, "dev", &veth_ba,
            ],
        )?;
    }

    Ok(())
}

/// Translates a namespace ID to a filedescriptor
pub fn get_nsfd(namespace_name: String) -> i32 {
    let nspath = format!("/var/run/netns/{}", namespace_name);
    open(nspath.as_str(), OFlag::O_RDONLY, Mode::empty())
        .unwrap_or_else(|_| panic!("Could not open netns file: {}", nspath))
}
