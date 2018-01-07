#![feature(getpid)]

use std::ops::Mul;

#[macro_use]
extern crate log;

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate babel_monitor;
use babel_monitor::Babel;

extern crate num256;
use num256::Int256;

use std::net::IpAddr;
use std::collections::HashMap;

extern crate ip_network;
use ip_network::IpNetwork;

use std::{thread, time};

extern crate debt_keeper;
use debt_keeper::{Identity, Key};

extern crate eui48;
use eui48::MacAddress;

/// This traffic watcher watches how much traffic each neighbor sends to each destination
/// during the next `duration` seconds (this blocks the thread).
/// It also gathers the price to each destination from Babel and uses this information
/// to calculate how much each neighbor owes. After `duration` it returns a map of how much
/// each neighbor owes.
pub fn watch(
    neighbors: Vec<Identity>,
    duration: u64,
    ki: &mut KernelInterface,
    babel: &mut Babel,
) -> Vec<(Identity, Int256)> {
    // trace!("Getting neighbors");
    // let neighbors: HashMap<_, _> = ki.get_neighbors().unwrap().into_iter().collect();
    // info!("Got neighbors: {:?}", neighbors);

    trace!("Getting routes");
    let routes = babel.parse_routes().unwrap();
    info!("Got routes: {:?}", routes);

    let mut identities: HashMap<MacAddress, Identity> = HashMap::new();
    for ident in &neighbors {
        identities.insert(ident.mac_address, *ident);
    }

    let mut destinations = HashMap::new();
    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses
            if ip.get_netmask() == 128 {
                destinations.insert(
                    ip.get_network_address().to_string(),
                    Int256::from(route.price as i64),
                );
                for ident in &neighbors {
                    ki.start_flow_counter(ident.mac_address, IpAddr::V6(ip.get_network_address()))
                        .unwrap();
                }
            }
        }
    }

    info!("Destinations: {:?}", destinations);

    trace!("Going to sleep");
    thread::sleep(time::Duration::from_secs(duration));

    trace!("Getting flow counters");
    let counters = ki.read_flow_counters().unwrap();
    info!("Got flow counters: {:?}", counters);

    // let mut neigh_debts = HashMap::new();
    counters
        .iter()
        .map(|&(neigh_mac, dest_ip, bytes)| {
            trace!(
                "Calculating neighbor debt: mac: {:?}, destination: {:?}, bytes: {:?}",
                neigh_mac,
                dest_ip,
                bytes
            );
            let price = destinations.get(&dest_ip.to_string()).unwrap();
            let debt = price.clone().mul(Int256::from(bytes as i64));
            trace!(
                "Calculated neighbor debt. price: {:?}, debt: {:?}",
                price,
                debt
            );



            (identities.get(&neigh_mac).unwrap().clone(), debt)
            // let neigh_ip = neighbors[&neigh_mac];
            // *neigh_debts.entry(neigh_ip).or_insert(0) += debt;
        })
        .collect::<Vec<(Identity, Int256)>>()

    // info!("Current neighbor debts: {:?}", neigh_debts);
    // neigh_debts
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
