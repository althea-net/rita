use althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

use althea_types::Identity;

use babel_monitor;
use babel_monitor::Babel;

use num256::Int256;

use eui48::MacAddress;

use std::net::{IpAddr, Ipv6Addr};
use std::collections::HashMap;

use ip_network::IpNetwork;

use std::{thread, time};

use settings::SETTING;

#[derive(Debug, Error)]
pub enum Error {
    BabelMonitorError(babel_monitor::Error),
    KernelInterfaceError(althea_kernel_interface::Error),
    #[error(msg_embedded, no_from, non_std)]
    TrafficWatcherError(String),
}

/*
/// This traffic watcher watches how much traffic each neighbor sends to each destination
/// between the last time watch was run, (This does _not_ block the thread)
/// It also gathers the price to each destination from Babel and uses this information
/// to calculate how much each neighbor owes. It returns a list of how much each neighbor owes.
///
/// This first time this is run, it will create the rules and then immediately read and zero them.
/// (should return 0)
pub fn watch(neighbors: Vec<Identity>, ki: &mut KernelInterface, babel: &mut Babel)
    -> Result<Vec<(Identity, Int256)>, Error> {
    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    let mut identities: HashMap<String, Identity> = HashMap::new();
    for ident in &neighbors {
        identities.insert(ident.wg_public_key, *ident);
    }

    let mut destinations = HashMap::new();
    destinations.insert(SETTING.network.own_ip, Int256::from(babel.local_price().unwrap() as i64));

    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.get_netmask() == 128 && route.installed {
                destinations.insert(
                    IpAddr::V6(ip.get_network_address()),
                    Int256::from(route.price),
                );
                for ident in &neighbors {
                    ki.start_flow_counter(ident.wg_public_key, IpAddr::V6(ip.get_network_address()))?;
                    ki.start_destination_counter(ident.wg_public_key, IpAddr::V6(ip.get_network_address()))?;
                }
            }
        }
    }

    for ident in &neighbors {
        ki.start_flow_counter(ident.wg_public_key, SETTING.network.own_ip)?;
    }
    trace!("Getting flow counters");
    let flow_counters = ki.read_flow_counters(true)?;
    info!("Got flow counters: {:?}", flow_counters);

    trace!("Getting destination counters");
    let des_counters = ki.read_destination_counters(true)?;
    info!("Got destination counters: {:?}", des_counters);

    // Flow counters should debit your neighbor which you received the packet from
    // Destination counters should credit your neighbor which you sent the packet to

    let mut debts = HashMap::new();

    // Setup the debts table
    for (mac, ident) in identities.clone() {
        debts.insert(ident, Int256::from(0));
    }

    // Flow counters should charge the "full price"
    for (mac, ip, bytes) in flow_counters {
        if destinations.contains_key(&ip) {
            let id = identities[&mac];
            *debts.get_mut(&id).unwrap() -= destinations[&ip].clone() * bytes;
        } else {
            warn!("flow destination not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated flow debts: {:?}", debts);

    // Destination counters should not give your cost to your neighbor
    for (mac, ip, bytes) in des_counters {
        if destinations.contains_key(&ip) {
            let id = identities[&mac];
            *debts.get_mut(&id).unwrap() += (destinations[&ip].clone() - babel.local_price().unwrap()) * bytes;
        } else {
            warn!("destination not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated total debts: {:?}", debts);


    Ok(debts.into_iter().collect())
}
*/

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
