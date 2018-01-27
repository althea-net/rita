use std::ops::Mul;

#[macro_use]
extern crate log;

#[macro_use]
extern crate derive_error;

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate althea_types;
use althea_types::Identity;

extern crate babel_monitor;
use babel_monitor::Babel;

extern crate num256;
use num256::Int256;
use std::ops::{Add, Sub};

use std::net::IpAddr;
use std::collections::HashMap;

extern crate ip_network;
use ip_network::IpNetwork;

use std::{thread, time};

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
                    ki.start_destination_counter(ident.mac_address, IpAddr::V6(ip.get_network_address()))?;
                }
            }
        }
    }

    info!("Destinations: {:?}", destinations);

    trace!("Going to sleep");
    thread::sleep(time::Duration::from_secs(duration));

    trace!("Getting flow counters");
    let flow_counters = ki.read_flow_counters()?;
    info!("Got flow counters: {:?}", flow_counters);

    trace!("Getting destination counters");
    let des_counters = ki.read_destination_counters()?;
    info!("Got destination counters: {:?}", des_counters);

    // Flow counters should debit your neighbour which you received the packet from
    // Destination counters should credit your neighbour which you sent the packet to

    let mut debts = HashMap::new();

    // Setup the debts table
    for (mac, ident) in identities.clone() {
        debts.insert(ident, Int256::from(0));
    }

    for (mac, ip, bytes) in flow_counters {
        let id = identities[&mac];
        *debts.get_mut(&id).unwrap() = debts[&id].clone().sub(
            // get price
            destinations[
                // get ip from mac
                &identities[&mac].ip_address.to_string().clone()]
                // multiply my bytes used
                .clone().mul(Int256::from(bytes as i64)));
    }

    trace!("Collated flow debts: {:?}", debts);

    for (mac, ip, bytes) in des_counters {
        let id = identities[&mac];
        *debts.get_mut(&id).unwrap() = debts[&id].clone().add(
            // get price
            destinations[
                // get ip from mac
                &identities[&mac].ip_address.to_string().clone()]
            // multiply my bytes used
            .clone().mul(Int256::from(bytes as i64)));
    }

    trace!("Collated total debts: {:?}", debts);


    Ok(debts.into_iter().collect())
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
