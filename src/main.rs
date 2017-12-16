#![feature(getpid)]
extern crate althea_kernel_interface;
extern crate babel_monitor;

use std::process;

extern crate docopt;

#[macro_use]
extern crate log;

extern crate ip_network;
extern crate simple_logger;

use std::{thread, time};
use std::collections::HashMap;
use babel_monitor::Babel;
use althea_kernel_interface::KernelInterface;
use std::net::IpAddr;
use ip_network::IpNetwork;
use std::net::SocketAddr;
use docopt::Docopt;

use std::fs::File;
use std::io::prelude::*;
use std::env;

const USAGE: &'static str = "
Usage: rita [--pid <pid file>]

Options:
    --pid  Which file to write the PID to. 
";

fn main() {
    simple_logger::init().unwrap();
    let args = Docopt::new(USAGE)
        .and_then(|d| d.parse())
        .unwrap_or_else(|e| e.exit());

    if args.get_bool("--pid") {
        let mut file = File::create(args.get_str("<pid file>")).unwrap();
        file.write_all(format!("{}", process::id()).as_bytes()).unwrap();
    }

    trace!("Starting");
    let mut ki = KernelInterface::new();

    let mut babel = Babel::new(&"[::1]:8080".parse::<SocketAddr>().unwrap());
    trace!("Connected to babel at {}", "[::1]:8080");

    let mut neigh_debts = HashMap::new();

    loop {
        trace!("Getting neighbors");
        let neighbors = ki.get_neighbors().unwrap();
        info!("Got neighbors: {:?}", neighbors);

        trace!("Getting routes");
        let routes = babel.parse_routes().unwrap();
        info!("Got routes: {:?}", routes);

        let mut destinations = HashMap::new();

        for route in &routes {
            // Only ip6
            if let IpNetwork::V6(ref ip) = route.prefix {
                // Only host addresses
                if ip.get_netmask() == 128 {
                    destinations.insert(ip.get_network_address().to_string(), route.price);
                    for &(neigh_mac, _) in &neighbors {
                        ki.start_flow_counter(neigh_mac, IpAddr::V6(ip.get_network_address()))
                            .unwrap();
                    }
                }
            }
        }

        info!("Destinations: {:?}", destinations);

        trace!("Going to sleep");
        thread::sleep(time::Duration::from_secs(5));

        trace!("Getting flow counters");
        let counters = ki.read_flow_counters().unwrap();
        info!("Got flow counters: {:?}", counters);

        for (neigh_mac, dest_ip, bytes) in counters {
            let kb = bytes / 1000;
            let price = destinations.get(&dest_ip.to_string()).unwrap();
            let debt = *price as u64 * kb;

            *neigh_debts.entry(neigh_mac.to_string()).or_insert(0) += debt;
        }
    }
}
