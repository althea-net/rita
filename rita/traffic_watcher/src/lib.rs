#![feature(getpid)]

use std::ops::Mul;

#[macro_use]
extern crate log;

#[macro_use]
extern crate derive_error;

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
use debt_keeper::{Identity};

extern crate eui48;
use eui48::MacAddress;

#[derive(Debug, Error)]
pub enum Error {
    BabelMonitorError(babel_monitor::Error),
    KernelInterfaceError(althea_kernel_interface::Error),
    #[error(msg_embedded, no_from, non_std)]
    TrafficWatcherError(String),
}

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
) -> Result<Vec<(Identity, Int256)>, Error> {
    trace!("Getting routes");
    let routes = babel.parse_routes()?;
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
                    ki.start_flow_counter(ident.mac_address, IpAddr::V6(ip.get_network_address()))?;
                }
            }
        }
    }

    info!("Destinations: {:?}", destinations);

    trace!("Going to sleep");
    thread::sleep(time::Duration::from_secs(duration));

    trace!("Getting flow counters");
    let counters = ki.read_flow_counters()?;
    info!("Got flow counters: {:?}", counters);

    counters
        .iter()
        .map(|&(neigh_mac, dest_ip, bytes)| {
            trace!(
                "Calculating neighbor debt: mac: {:?}, destination: {:?}, bytes: {:?}",
                neigh_mac,
                dest_ip,
                bytes
            );

            let price = &destinations[&dest_ip.to_string()];
            let debt = price.clone().mul(Int256::from(bytes as i64));

            trace!(
                "Calculated neighbor debt. price: {:?}, debt: {:?}",
                price,
                debt
            );

            Ok((identities[&neigh_mac].clone(), debt))
        })
        .collect::<Result<Vec<(Identity, Int256)>, Error>>()
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
