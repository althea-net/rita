use actix::prelude::*;

use althea_kernel_interface::KernelInterface;

use althea_types::Identity;

use babel_monitor::Babel;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;

use num256::Int256;

use std::net::IpAddr;
use std::collections::HashMap;

use ip_network::IpNetwork;

use SETTING;

use failure::Error;

pub struct TrafficWatcher;

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}
impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        let ki = KernelInterface {};

        info!("Client traffic watcher started");

        ki.init_exit_client_counters().unwrap();
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {}
    }
}

#[derive(Message)]
pub struct Watch(pub Identity, pub u64);

impl Handler<Watch> for TrafficWatcher {
    type Result = ();

    fn handle(&mut self, msg: Watch, _: &mut Context<Self>) -> Self::Result {
        watch(msg.0, msg.1).unwrap();
    }
}

/// This traffic watcher watches how much traffic we send to the exit, and how much the exit sends
/// back to us.
pub fn watch(exit: Identity, exit_price: u64) -> Result<(), Error> {
    let ki = KernelInterface {};
    let mut babel = Babel::new(
        &format!("[::1]:{}", SETTING.read().unwrap().network.babel_port)
            .parse()
            .unwrap(),
    );

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    let mut destinations = HashMap::new();

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

    let input = ki.read_exit_client_counters_input();
    let output = ki.read_exit_client_counters_output();

    trace!("got {:?} from client exit counters", (&input, &output));

    let input = input?;
    let output = output?;

    let mut owes: Int256 = Int256::from(0);

    trace!("exit price {}", exit_price);
    trace!(
        "exit destination price {}",
        destinations[&exit.mesh_ip].clone() + exit_price
    );

    if destinations.contains_key(&exit.mesh_ip) {
        owes += Int256::from(exit_price * output);

        owes += (destinations[&exit.mesh_ip].clone() + exit_price) * input;

        let update = debt_keeper::TrafficUpdate {
            from: exit.clone(),
            amount: owes,
        };

        DebtKeeper::from_registry().do_send(update);
    } else {
        warn!("not yet have route to exit at {:?}, ignoring payment", &exit.mesh_ip)
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
