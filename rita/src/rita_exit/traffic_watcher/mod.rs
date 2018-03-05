use actix::prelude::*;

use althea_kernel_interface;
use althea_kernel_interface::KernelInterface;
use althea_kernel_interface::ExitFilterTarget;

use althea_types::Identity;

use babel_monitor;
use babel_monitor::Babel;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;

use futures::{future, Future};

use num256::Int256;

use eui48::MacAddress;

use std::net::{IpAddr, Ipv6Addr};
use std::collections::HashMap;

use ip_network::IpNetwork;

use std::{thread, time};

use SETTING;

use failure::Error;

pub struct TrafficWatcher;

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}
impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, ctx: &mut Context<Self>) {
        let ki = KernelInterface {};

        ki.init_exit_counter(&ExitFilterTarget::Input).unwrap();
        ki.init_exit_counter(&ExitFilterTarget::Output).unwrap();

        info!("Traffic Watcher started");
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {}
    }
}

#[derive(Message)]
pub struct Watch(pub Vec<Identity>);

impl Handler<Watch> for TrafficWatcher {
    type Result = ();

    fn handle(&mut self, msg: Watch, _: &mut Context<Self>) -> Self::Result {
        watch(msg.0);
    }
}

/// This traffic watcher watches how much traffic each we send and receive from each client.
pub fn watch(clients: Vec<Identity>) -> Result<(), Error> {
    let ki = KernelInterface {};
    let mut babel = Babel::new(&format!("[::1]:{}", SETTING.read().unwrap().network.babel_port)
        .parse()
        .unwrap());

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    let mut destinations = HashMap::new();
    destinations.insert(
        SETTING.read().unwrap().network.own_ip,
        Int256::from(babel.local_price().unwrap() as i64),
    );

    let mut identities: HashMap<IpAddr, Identity> = HashMap::new();
    for ident in &clients {
        identities.insert(ident.mesh_ip, ident.clone());
    }

    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.get_netmask() == 128 && route.installed {
                destinations.insert(
                    IpAddr::V6(ip.get_network_address()),
                    Int256::from(route.price),
                );
            }
        }
    }

    let input_counters = ki.read_exit_counters(&ExitFilterTarget::Input)?;
    let output_counters = ki.read_exit_counters(&ExitFilterTarget::Output)?;

    let mut debts = HashMap::new();

    // Setup the debts table
    for (mac, ident) in identities.clone() {
        debts.insert(ident, Int256::from(0));
    }

    for (ip, bytes) in input_counters {
        if destinations.contains_key(&ip) {
            let id = identities[&ip].clone();
            *debts.get_mut(&id).unwrap() -= destinations[&ip].clone() * bytes;
        } else {
            warn!("input sender not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated flow debts: {:?}", debts);

    for (ip, bytes) in output_counters {
        if destinations.contains_key(&ip) {
            let id = identities[&ip].clone();
            *debts.get_mut(&id).unwrap() -= destinations[&ip].clone() * bytes;
        } else {
            warn!("input sender not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated total debts: {:?}", debts);

    for (from, amount) in debts {
        let update = debt_keeper::TrafficUpdate {
            from: from.clone(),
            amount,
        };
        let adjustment = debt_keeper::SendUpdate { from };

        Arbiter::handle().spawn(DebtKeeper::from_registry().send(update).then(move |_| {
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

