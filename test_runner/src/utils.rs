use crate::setup_utils::{Namespace, NamespaceInfo, RouteHop};
use althea_kernel_interface::KI;
use babel_monitor::{open_babel_stream, parse_routes, structs::Route};
use ipnetwork::IpNetwork;
use log::{info, trace, warn};
use nix::{
    fcntl::{open, OFlag},
    sched::{setns, CloneFlags},
    sys::stat::Mode,
};
use settings::client::RitaClientSettings;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    str::from_utf8,
    thread,
    time::{Duration, Instant},
};

/// Wait this long for network convergence
const REACHABILITY_TEST_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the reacability test should wait in between tests
const REACHABILITY_TEST_CHECK_SPEED: Duration = Duration::from_secs(5);

/// Test pingability waiting and failing if it is not successful
pub fn test_reach_all(nsinfo: NamespaceInfo) {
    let start = Instant::now();
    while !test_reach_all_async(nsinfo.clone()) {
        if Instant::now() - start > REACHABILITY_TEST_TIMEOUT {
            panic!("Failed to ping all destinations! Did not converge")
        }
        thread::sleep(REACHABILITY_TEST_CHECK_SPEED)
    }
    info!("All nodes are rechable via ping!");
}

/// test pingability between namespaces on babel routes
pub fn test_reach_all_async(nsinfo: NamespaceInfo) -> bool {
    for i in nsinfo.clone().names {
        for j in nsinfo.clone().names {
            if test_reach(i.clone(), j) {
                // ping failed
                return false;
            }
        }
    }
    true
}

fn test_reach(from: Namespace, to: Namespace) -> bool {
    // todo replace with oping
    // ip netns exec n-1 ping6 fd00::2
    let ip = format!("fd00::{}", to.id);
    let errormsg = format!(
        "Could not run ping6 from {} to {}",
        from.get_name(),
        to.get_name()
    );
    let output = KI
        .run_command(
            "ip",
            &["netns", "exec", &from.get_name(), "ping6", &ip, "-c", "1"],
        )
        .expect(&errormsg);
    let output = from_utf8(&output.stdout).expect("could not get output for ping6!");
    trace!("ping output: {output:?} end");
    output.contains("1 packets transmitted, 1 received, 0% packet loss")
}

/// Tests routes, waiting until they are all found and panicing if that does not happen
pub fn test_routes(nsinfo: NamespaceInfo, expected: HashMap<Namespace, RouteHop>) {
    let start = Instant::now();
    while !test_routes_async(nsinfo.clone(), expected.clone()) {
        if Instant::now() - start > REACHABILITY_TEST_TIMEOUT {
            panic!("Failed to locate all Babel routes, network did not converge!")
        }
        thread::sleep(REACHABILITY_TEST_CHECK_SPEED)
    }
    info!("All routes found, network converged!");
}

/// check the presence of all optimal routes, returns false if there is a route missing
pub fn test_routes_async(nsinfo: NamespaceInfo, expected: HashMap<Namespace, RouteHop>) -> bool {
    // add ALL routes for each namespace into a map to search through for the next portion
    let mut routesmap = HashMap::new();
    for ns in nsinfo.clone().names {
        // create a thread in the babel namespace, ask it about routes, then join to bring that
        // data back to this thread in the default namespace
        let rita_handler = thread::spawn(move || {
            let nspath = format!("/var/run/netns/{}", ns.get_name());
            let nsfd = open(nspath.as_str(), OFlag::O_RDONLY, Mode::empty())
                .unwrap_or_else(|_| panic!("Could not open netns file: {}", nspath));
            setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");
            let babel_port = settings::get_rita_common().network.babel_port;

            if let Ok(mut stream) = open_babel_stream(babel_port, Duration::from_secs(4)) {
                if let Ok(babel_routes) = parse_routes(&mut stream) {
                    routesmap.insert(ns.get_name(), babel_routes);
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
    for ns1 in nsinfo.clone().names {
        for ns2 in &nsinfo.names {
            if &ns1 == ns2 {
                continue;
            }

            let routes = routesmap.get(&ns1.get_name()).unwrap();
            //within routes there must be a route that matches the expected price between the dest (fd00::id) and the expected next hop (fe80::id)

            if !try_route(&expected, routes, ns1.clone(), ns2.clone()) {
                warn!(
                    "No route found for {:?}, {:?}, retrying...",
                    ns1.get_name(),
                    ns2.get_name()
                );
                return false;
            }
        }
    }
    true
}

/// Look for an installed route given our expected list between ns1 and ns2
fn try_route(
    expected: &HashMap<Namespace, RouteHop>,
    routes: &Vec<Route>,
    ns1: Namespace,
    ns2: Namespace,
) -> bool {
    let expected_data = expected
        .get(&ns1)
        .unwrap()
        .destination
        .get(&ns2.id)
        .unwrap();
    let expected_cost = expected_data.clone().price;
    let expected_hop_id: u16 = expected_data.clone().id;
    let ns2_id: u16 = ns2.id;
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

/// Gets the default client settings, configured to connected to the EVM of the Althea chain as a standin EVM environment
pub fn get_default_client_settings() -> RitaClientSettings {
    RitaClientSettings::new("/althea_rs/scripts/legacy_integration_test/rita-test.toml").unwrap()
}

/// Same as get_default_client_settings but directed at the Althea node by default
pub fn get_default_client_settings_althea() -> RitaClientSettings {
    RitaClientSettings::new("/althea_rs/scripts/legacy_integration_test/rita-test.toml").unwrap()
}

/// This allows the tester to exit cleanly then it gets a ctrl-c message
/// allowing you to reuse a test env and save a lot of setup
pub fn set_sigterm() {
    //Setup a SIGTERM hadler
    ctrlc::set_handler(move || {
        info!("received Ctrl+C!");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");
}
