//use core::time;
//use std::thread;

use althea_kernel_interface::{KernelInterfaceError, KI};

/// This struct holds the setup instructions for namespaces
#[derive(Clone, Eq, PartialEq)]
pub struct NamespaceInfo {
    /// the names of the namespaces
    pub names: Vec<String>,
    /// Linked nodes written as tuple pairs
    /// The string is for the namespace name(NOTE: names must be <=4 characters as interfaces
    /// cannot be more than 15 char, and we input as veth-{}-{})
    /// The u32 is for the subnet on the 3rd octet
    pub linked: Vec<((String, u32), (String, u32))>,
}

fn main() {
    // uncomment this for manual debugging
    // let ten_mins = time::Duration::from_secs(600);

    let namespaces = five_node_config();

    validate_connections(namespaces.clone());

    let res = setup_ns(namespaces);
    println!("Namespaces setup: {:?}", res);
    // this sleep is for debugging so that the container can be accessed to poke around in
    // thread::sleep(ten_mins);
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
    let testa = ("nA".to_string(), 0);
    let testb = ("nB".to_string(), 1);
    let testc = ("nC".to_string(), 2);
    let testd = ("nD".to_string(), 3);

    NamespaceInfo {
        names: vec![
            testa.clone().0,
            testb.clone().0,
            testc.clone().0,
            testd.clone().0,
        ],
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
        let res = KI.run_command("ip", &["netns", "add", &name]);
        println!("{:?}", res);
        // ip netns exec nB ip link set dev lo up
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &name, "ip", "link", "set", "dev", "lo", "up",
            ],
        );
        println!("{:?}", res);
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
        println!("{:?}", res);
        // assign each side of the veth to one of the nodes namespaces
        let res = KI.run_command("ip", &["link", "set", &veth_ab, "netns", &link.0 .0]);
        println!("{:?}", res);
        let res = KI.run_command("ip", &["link", "set", &veth_ba, "netns", &link.1 .0]);
        println!("{:?}", res);

        // add ip addresses on each side
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.0 .0, "ip", "addr", "add", &ip_ab, "dev", &veth_ab,
            ],
        );
        println!("{:?}", res);

        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.1 .0, "ip", "addr", "add", &ip_ba, "dev", &veth_ba,
            ],
        );
        println!("{:?}", res);

        // bring the interfaces up
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.0 .0, "ip", "link", "set", "dev", &veth_ab, "up",
            ],
        );
        println!("{:?}", res);

        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.1 .0, "ip", "link", "set", "dev", &veth_ba, "up",
            ],
        );
        println!("{:?}", res);

        //  ip netns exec nC ip route add 192.168.0.0/24 dev veth-nC-nA
        // add routes to each other's subnets
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.0 .0, "ip", "route", "add", &subnet_b, "dev", &veth_ab,
            ],
        );
        println!("{:?}", res);
        let res = KI.run_command(
            "ip",
            &[
                "netns", "exec", &link.1 .0, "ip", "route", "add", &subnet_a, "dev", &veth_ba,
            ],
        );
        println!("{:?}", res);
    }

    Ok(())
}

/// Validate the list of linked namespaces
fn validate_connections(namespaces: NamespaceInfo) {
    for link in namespaces.linked {
        if !namespaces.names.contains(&link.0 .0) || !namespaces.names.contains(&link.1 .0) {
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
