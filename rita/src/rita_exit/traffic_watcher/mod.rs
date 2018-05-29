use actix::prelude::*;

use althea_kernel_interface::ExitFilterTarget;
use althea_kernel_interface::KI;

use althea_types::Identity;

use babel_monitor::Babel;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;

use num256::Int256;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};

use ip_network::IpNetwork;

use settings::{RitaCommonSettings, RitaExitSettings};
use SETTING;

use failure::Error;

pub struct TrafficWatcher;

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}
impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        KI.init_exit_counter(&ExitFilterTarget::Input).unwrap();
        KI.init_exit_counter(&ExitFilterTarget::Output).unwrap();

        match KI.setup_wg_if_named("wg_exit") {
            Err(e) => warn!("exit setup returned {}", e),
            _ => {}
        }
        KI.setup_nat(&SETTING.get_network().external_nic.clone().unwrap())
            .unwrap();

        info!("Traffic Watcher started");
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {}
    }
}

pub struct Watch(pub Vec<Identity>);

impl Message for Watch {
    type Result = Result<(), Error>;
}

impl Handler<Watch> for TrafficWatcher {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: Watch, _: &mut Context<Self>) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;

        watch(Babel::new(stream), msg.0)
    }
}

/// This traffic watcher watches how much traffic each we send and receive from each client.
pub fn watch<T: Read + Write>(mut babel: Babel<T>, clients: Vec<Identity>) -> Result<(), Error> {
    babel.start_connection()?;

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    let mut destinations = HashMap::new();
    destinations.insert(
        SETTING.get_network().own_ip,
        Int256::from(babel.local_fee().unwrap()),
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

    let input_counters = KI.read_exit_server_counters(&ExitFilterTarget::Input)?;
    let output_counters = KI.read_exit_server_counters(&ExitFilterTarget::Output)?;

    trace!("input exit counters: {:?}", input_counters);
    trace!("output exit counters: {:?}", output_counters);

    let mut debts = HashMap::new();

    // Setup the debts table
    for (_, ident) in identities.clone() {
        debts.insert(ident, Int256::from(0));
    }

    let price = SETTING.get_exit_network().exit_price;

    for (ip, bytes) in input_counters {
        if identities.contains_key(&ip) && destinations.contains_key(&ip) {
            let id = identities[&ip].clone();
            *debts.get_mut(&id).unwrap() -= price * bytes;
        } else {
            warn!("input sender not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated input exit debts: {:?}", debts);

    for (ip, bytes) in output_counters {
        if identities.contains_key(&ip) && destinations.contains_key(&ip) {
            let id = identities[&ip].clone();
            *debts.get_mut(&id).unwrap() -= (destinations[&ip].clone() + price) * bytes;
        } else {
            warn!("input sender not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated total exit debts: {:?}", debts);

    for (from, amount) in debts {
        let update = debt_keeper::TrafficUpdate {
            from: from.clone(),
            amount,
        };

        DebtKeeper::from_registry().do_send(update);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::*;

    #[test]
    #[ignore]
    fn debug_babel_socket_client() {
        env_logger::init();
        let bm_stream = TcpStream::connect::<SocketAddr>("[::1]:9001".parse().unwrap()).unwrap();
        watch(Babel::new(bm_stream), Vec::new()).unwrap();
    }
}
