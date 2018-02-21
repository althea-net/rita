use actix::prelude::*;

use althea_kernel_interface;
use althea_kernel_interface::KernelInterface;
use althea_kernel_interface::FilterTarget;

use althea_types::LocalIdentity;

use babel_monitor;
use babel_monitor::Babel;

use debt_keeper;
use debt_keeper::DebtKeeper;

use futures::{future, Future};

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

pub struct TrafficWatcher;

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}
impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, ctx: &mut Context<Self>) {
        info!("Traffic Watcher started");
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher{}
    }
}

#[derive(Message)]
pub struct Watch(pub Vec<(LocalIdentity, String)>);

impl Handler<Watch> for TrafficWatcher {
    type Result = ();

    fn handle(&mut self, msg: Watch, _: &mut Context<Self>) -> Self::Result {
        watch(msg.0);
    }
}

/// This traffic watcher watches how much traffic each neighbor sends to each destination
/// between the last time watch was run, (This does _not_ block the thread)
/// It also gathers the price to each destination from Babel and uses this information
/// to calculate how much each neighbor owes. It returns a list of how much each neighbor owes.
///
/// This first time this is run, it will create the rules and then immediately read and zero them.
/// (should return 0)
pub fn watch(neighbors: Vec<(LocalIdentity, String)>) -> Result<(), Error> {
    let mut ki = KernelInterface{};
    let mut babel = Babel::new(&format!("[::1]:{}", SETTING.network.babel_port).parse().unwrap());

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    let mut identities: HashMap<IpAddr, LocalIdentity> = HashMap::new();
    for ident in &neighbors {
        identities.insert(ident.0.global.mesh_ip, ident.0.clone());
    }

    let mut if_to_ip: HashMap<String, IpAddr> = HashMap::new();
    for ident in &neighbors {
        if_to_ip.insert(ident.clone().1, ident.0.global.mesh_ip);
    }

    let mut ip_to_if: HashMap<IpAddr, String> = HashMap::new();
    for ident in &neighbors {
        ip_to_if.insert( ident.0.global.mesh_ip, ident.clone().1);
    }

    let mut destinations = HashMap::new();
    destinations.insert(SETTING.network.own_ip, Int256::from(babel.local_price().unwrap() as i64));

    let old_input_counters = ki.read_counters(false, &FilterTarget::Input)?;
    let old_output_counters = ki.read_counters(false, &FilterTarget::Output)?;
    let old_fwd_input_counters = ki.read_counters(false, &FilterTarget::ForwardInput)?;
    let old_fwd_output_counters = ki.read_counters(false, &FilterTarget::ForwardOutput)?;

    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.get_netmask() == 128 && route.installed {
                destinations.insert(
                    IpAddr::V6(ip.get_network_address()),
                    Int256::from(route.price),
                );
                for &(ref ident, ref dev) in &neighbors {
                    ki.start_counter(dev.to_string(), IpAddr::V6(ip.get_network_address()), &FilterTarget::Input, &old_input_counters)?;
                    ki.start_counter(dev.to_string(), IpAddr::V6(ip.get_network_address()), &FilterTarget::ForwardInput, &old_fwd_input_counters)?;
                    ki.start_counter(dev.to_string(), IpAddr::V6(ip.get_network_address()), &FilterTarget::Output, &old_output_counters)?;
                    ki.start_counter(dev.to_string(), IpAddr::V6(ip.get_network_address()), &FilterTarget::ForwardOutput, &old_fwd_output_counters)?;
                }
            }
        }
    }

    for &(ref ident, ref dev) in &neighbors {
        ki.start_counter(dev.to_string(), SETTING.network.own_ip, &FilterTarget::Input, &old_input_counters)?;
        ki.start_counter(dev.to_string(), SETTING.network.own_ip, &FilterTarget::Output, &old_output_counters)?;
        ki.start_counter(dev.to_string(), SETTING.network.own_ip, &FilterTarget::ForwardInput, &old_fwd_input_counters)?;
        ki.start_counter(dev.to_string(), SETTING.network.own_ip, &FilterTarget::ForwardOutput, &old_fwd_output_counters)?;
    }
    trace!("Getting input counters");
    let mut input_counters = ki.read_counters(true, &FilterTarget::Input)?;
    info!("Got output counters: {:?}", input_counters);


    trace!("Getting destination counters");
    let mut output_counters = ki.read_counters(true, &FilterTarget::Output)?;
    info!("Got destination counters: {:?}", output_counters);

    trace!("Getting fwd counters");
    let (fwd_input_counters, fwd_output_counters) = ki.read_fwd_counters(true)?;
    info!("Got fwd counters: {:?}", (&fwd_input_counters, &fwd_output_counters));

    for (k, v) in &mut output_counters {
        *v += fwd_output_counters[k]
    }

    for (k, v) in &mut input_counters {
        *v += fwd_input_counters[k]
    }

    info!("Got final input counters: {:?}", input_counters);
    info!("Got final output counters: {:?}", output_counters);


    // Flow counters should debit your neighbor which you received the packet from
    // Destination counters should credit your neighbor which you sent the packet to

    let mut debts = HashMap::new();

    // Setup the debts table
    for (mac, ident) in identities.clone() {
        debts.insert(ident, Int256::from(0));
    }

    // Flow counters should charge the "full price"
    for ((ip, interface), bytes) in input_counters {
        if destinations.contains_key(&ip) {
            let id = identities[&if_to_ip[&interface]].clone();
            *debts.get_mut(&id).unwrap() -= destinations[&ip].clone() * bytes;
        } else {
            warn!("flow destination not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated flow debts: {:?}", debts);

    // Destination counters should not give your cost to your neighbor
    for ((ip, interface), bytes) in output_counters {
        if destinations.contains_key(&ip) {
            let id = identities[&if_to_ip[&interface]].clone();
            *debts.get_mut(&id).unwrap() += (destinations[&ip].clone() - babel.local_price().unwrap()) * bytes;
        } else {
            warn!("destination not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated total debts: {:?}", debts);

    for (from, amount) in debts {
        let update = debt_keeper::TrafficUpdate { from: from.global.clone(), amount };
        let adjustment = debt_keeper::SendUpdate { from: from.global };

        Arbiter::handle().spawn(
            DebtKeeper::from_registry().send(update).then(
                move |_| {
                    DebtKeeper::from_registry().do_send(adjustment);
                    future::result(Ok(()))
                }));
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
