use core::time;
use std::{
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, Ipv6Addr},
    str::from_utf8,
    thread,
    time::Duration,
};

use althea_kernel_interface::{KernelInterfaceError, KI};
use babel_monitor::{open_babel_stream, parse_routes, structs::Route};
use ipnetwork::IpNetwork;
use nix::{
    fcntl::{open, OFlag},
    sched::{setns, CloneFlags},
    sys::stat::Mode,
};

use crate::{Namespace, NamespaceInfo, RouteHop};

/// test pingability between namespaces on babel routes
pub fn test_reach_all(nsinfo: NamespaceInfo) -> Result<u16, KernelInterfaceError> {
    let mut count: u16 = 0;
    for i in nsinfo.clone().names {
        for j in nsinfo.clone().names {
            if test_reach(i.clone(), j) {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn test_reach(from: Namespace, to: Namespace) -> bool {
    // ip netns exec n-1 ping6 fd00::2
    let ip = format!("fd00::{}", to.id);
    let errormsg = format!("Could not run ping6 from {} to {}", from.name, to.name);
    let output = KI
        .run_command(
            "ip",
            &["netns", "exec", &from.name, "ping6", &ip, "-c", "1"],
        )
        .expect(&errormsg);
    let output = from_utf8(&output.stdout).expect("could not get output for ping6!");
    println!("ping output: {output:?} end");
    output.contains("1 packets transmitted, 1 received, 0% packet loss")
}

/// check the presence of all optimal routes
pub fn test_routes(nsinfo: NamespaceInfo, expected: HashMap<Namespace, RouteHop>) -> u32 {
    // add ALL routes for each namespace into a map to search through for the next portion
    let mut routesmap = HashMap::new();
    for ns in nsinfo.clone().names {
        let rita_handler = thread::spawn(move || {
            let nspath = format!("/var/run/netns/{}", ns.name);
            let nsfd = open(nspath.as_str(), OFlag::O_RDONLY, Mode::empty())
                .unwrap_or_else(|_| panic!("Could not open netns file: {}", nspath));
            setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");
            let babel_port = settings::get_rita_common().network.babel_port;

            if let Ok(mut stream) = open_babel_stream(babel_port, Duration::from_secs(4)) {
                if let Ok(babel_routes) = parse_routes(&mut stream) {
                    routesmap.insert(ns.name, babel_routes);
                    routesmap
                } else {
                    routesmap
                }
            } else {
                routesmap
            }
        });
        routesmap = rita_handler.join().unwrap();
    }
    let mut count = 0;
    let mut not_found: Vec<(Namespace, Namespace)> = Vec::new();
    for ns1 in nsinfo.clone().names {
        'neighs: for ns2 in &nsinfo.names {
            if &ns1 == ns2 {
                continue;
            }

            let routes = routesmap.get(&ns1.name).unwrap();
            //within routes there must be a route that matches the expected price between the dest (fd00::id) and the expected next hop (fe80::id)

            if try_route(&expected, routes, ns1.clone(), ns2.clone()) {
                println!("We found route for {:?}, {:?}", ns1.name, ns2.name);
                count += 1;
                continue 'neighs;
            } else {
                println!(
                    "No route found for {:?}, {:?}, retrying...",
                    ns1.name, ns2.name
                );
                not_found.insert(0, (ns1.clone(), ns2.clone()));
            }
        }
    }

    while !not_found.is_empty() {
        let mut minutes_passed = 0;
        let one_min = time::Duration::from_secs(60);
        println!("Retrying failed routes");
        let namespaces = not_found.pop().unwrap();
        let ns1 = namespaces.clone().0;
        let ns2 = namespaces.clone().1;
        let routes = routesmap.get(&ns1.name).unwrap();

        while minutes_passed < 10 {
            thread::sleep(one_min);
            minutes_passed += 1;
            match try_route(&expected, routes, ns1.clone(), ns2.clone()) {
                true => {
                    println!("We found route for {:?}, {:?}", ns1.name, ns2.name);
                    count += 1;
                    break;
                }
                false => {
                    println!(
                        "No route found for {:?}, {:?}, retrying...",
                        ns1.name, ns2.name
                    );
                }
            }
        }
        if minutes_passed > 10 {
            println!(
                "Could not find missing routes after 10 minutes: {:?}, {:?}",
                namespaces, not_found
            );
            return count;
        }
    }

    count
}

/// Look for an installed route given our expected list between ns1 and ns2
fn try_route(
    expected: &HashMap<Namespace, RouteHop>,
    routes: &Vec<Route>,
    ns1: Namespace,
    ns2: Namespace,
) -> bool {
    let expected_data = expected.get(&ns1).unwrap().destination.get(&ns2).unwrap();
    let expected_cost = expected_data.clone().0;
    let expected_hop_id: u16 = expected_data.clone().1.id.try_into().unwrap();
    let ns2_id: u16 = ns2.id.try_into().unwrap();
    let neigh_ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, expected_hop_id));
    let dest_ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, ns2_id));
    for r in routes {
        if let IpNetwork::V6(ref ip) = r.prefix {
            if ip.ip() == dest_ip
                && r.price == expected_cost
                && r.fee == ns1.cost
                && r.neigh_ip == neigh_ip
            {
                return true;
            } else {
                continue;
            }
        }
    }

    false
}
