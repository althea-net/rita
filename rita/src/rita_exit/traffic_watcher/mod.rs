//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ipset counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.
//!
//! This is the exit specific billing code used to determine how exits should be compensted. Which is
//! different in that mesh nodes are paid by forwarding traffic, but exits have to return traffic and
//! must get paid for doing so.

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

use ipnetwork::IpNetwork;

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
        match SETTING.get_network().mesh_ip {
            Some(ip) => ip,
            None => bail!("No mesh IP configured yet"),
        },
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
            if ip.prefix() == 128 && route.installed {
                destinations.insert(IpAddr::V6(ip.ip()), Int256::from(route.price));
            }
        }
    }

    let input_counters = match KI.read_exit_server_counters(&ExitFilterTarget::Input) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };
    let output_counters = match KI.read_exit_server_counters(&ExitFilterTarget::Output) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting output counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };

    trace!("input exit counters: {:?}", input_counters);
    let mut total_in: u64 = 0;
    for entry in input_counters.iter() {
        let input = entry.1;
        total_in += input;
    }
    info!("Total Exit input of {} bytes this round", total_in);
    trace!("output exit counters: {:?}", output_counters);
    let mut total_out: u64 = 0;
    for entry in output_counters.iter() {
        let output = entry.1;
        total_out += output;
    }
    info!("Total Exit output of {} bytes this round", total_out);

    let mut debts = HashMap::new();

    // Setup the debts table
    for (_, ident) in identities.clone() {
        debts.insert(ident, Int256::from(0));
    }

    let price = SETTING.get_exit_network().exit_price;

    for (ip, bytes) in input_counters {
        let state = (identities.get(&ip), destinations.get(&ip));
        match state {
            (Some(id), Some(_dest)) => match debts.get_mut(&id) {
                Some(debt) => {
                    *debt -= price * bytes;
                }
                // debts is generated from identities, this should be impossible
                None => warn!("No debts entry for input entry id {:?}", id),
            },
            // this can be caused by a peer that has not yet formed a babel route
            (Some(id), None) => warn!("We have an id {:?} but not destination", id),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (None, Some(dest)) => warn!("We have a destination {:?} but no id", dest),
            // dead entry?
            (None, None) => warn!("We have no id or dest for an input counter on {:?}", ip),
        }
    }

    trace!("Collated input exit debts: {:?}", debts);

    for (ip, bytes) in output_counters {
        let state = (identities.get(&ip), destinations.get(&ip));
        match state {
            (Some(id), Some(dest)) => match debts.get_mut(&id) {
                Some(debt) => {
                    *debt -= (dest.clone() + price) * bytes;
                }
                // debts is generated from identities, this should be impossible
                None => warn!("No debts entry for input entry id {:?}", id),
            },
            // this can be caused by a peer that has not yet formed a babel route
            (Some(id), None) => warn!("We have an id {:?} but not destination", id),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (None, Some(dest)) => warn!("We have a destination {:?} but no id", dest),
            // dead entry?
            (None, None) => warn!("We have no id or dest for an input counter on {:?}", ip),
        }
    }

    trace!("Collated total exit debts: {:?}", debts);

    info!("Computed exit debts for {:?} clients", debts.len());
    let mut total_income = Int256::zero();
    for entry in debts.iter() {
        let income = entry.1;
        total_income += income;
    }
    info!("Total exit income of {:?} Wei this round", total_income);

    match KI.get_wg_exit_clients_online() {
        Ok(users) => info!("Total of {} users online", users),
        Err(e) => warn!("Getting clients failed with {:?}", e),
    }

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
