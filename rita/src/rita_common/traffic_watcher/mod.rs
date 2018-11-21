//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ipset counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.

use actix::prelude::*;
use rita_common::tunnel_manager::Neighbor;

use althea_kernel_interface::FilterTarget;
use KI;

use althea_types::Identity;

use babel_monitor::Babel;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;

use num256::Int256;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};

use ipnetwork::IpNetwork;

use settings::RitaCommonSettings;
use SETTING;

use failure::Error;

pub struct TrafficWatcher;

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}

impl Supervised for TrafficWatcher {}

impl SystemService for TrafficWatcher {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        KI.init_counter(&FilterTarget::Input).unwrap();
        KI.init_counter(&FilterTarget::Output).unwrap();
        KI.init_counter(&FilterTarget::ForwardInput).unwrap();
        KI.init_counter(&FilterTarget::ForwardOutput).unwrap();

        info!("Traffic Watcher started");
    }
}

impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {}
    }
}

pub struct Watch {
    /// List of neighbors to watch
    pub neighbors: Vec<Neighbor>,
}

impl Watch {
    pub fn new(neighbors: Vec<Neighbor>) -> Watch {
        Watch { neighbors }
    }
}

impl Message for Watch {
    type Result = Result<(), Error>;
}

impl Handler<Watch> for TrafficWatcher {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: Watch, _: &mut Context<Self>) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;

        watch(Babel::new(stream), &msg.neighbors)
    }
}

/// This traffic watcher watches how much traffic each neighbor sends to each destination
/// between the last time watch was run, (This does _not_ block the thread)
/// It also gathers the price to each destination from Babel and uses this information
/// to calculate how much each neighbor owes. It returns a list of how much each neighbor owes.
///
/// This first time this is run, it will create the rules and then immediately read and zero them.
/// (should return 0)
pub fn watch<T: Read + Write>(mut babel: Babel<T>, neighbors: &Vec<Neighbor>) -> Result<(), Error> {
    babel.start_connection()?;

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    let mut identities: HashMap<IpAddr, Identity> = HashMap::new();
    let mut if_to_id: HashMap<String, Identity> = HashMap::new();
    let mut ip_to_if: HashMap<IpAddr, String> = HashMap::new();

    for neigh in neighbors {
        // provides a lookup from mesh ip to identity
        identities.insert(neigh.identity.global.mesh_ip, neigh.identity.global.clone());
        // provides a lookup from wireguard interface to mesh ip
        if_to_id.insert(neigh.iface_name.clone(), neigh.identity.global.clone());
        // provides a lookup from mesh ip to wireguard interface
        ip_to_if.insert(neigh.identity.global.mesh_ip, neigh.iface_name.clone());
    }

    let mut destinations = HashMap::new();
    let local_fee = babel.get_local_fee().unwrap();

    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed {
                destinations.insert(IpAddr::V6(ip.ip()), Int256::from(route.price + local_fee));
            }
        }
    }

    destinations.insert(
        match SETTING.get_network().mesh_ip {
            Some(ip) => ip,
            None => bail!("No mesh IP configured yet"),
        },
        Int256::from(0),
    );

    trace!("Getting input counters");
    let input_counters = match KI.read_counters(&FilterTarget::Input) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };
    trace!("Got input counters: {:?}", input_counters);

    trace!("Getting ouput counters");
    let output_counters = match KI.read_counters(&FilterTarget::Output) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting output counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };
    trace!("Got output counters: {:?}", output_counters);

    trace!("Getting fwd counters");
    let fwd_input_counters = match KI.read_counters(&FilterTarget::ForwardInput) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };
    let fwd_output_counters = match KI.read_counters(&FilterTarget::ForwardOutput) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };

    info!(
        "Got fwd counters: {:?}",
        (&fwd_input_counters, &fwd_output_counters)
    );

    let mut total_input_counters = HashMap::new();
    let mut total_output_counters = HashMap::new();

    for (k, v) in input_counters {
        *total_input_counters.entry(k).or_insert(0) += v
    }

    for (k, v) in fwd_input_counters {
        *total_input_counters.entry(k).or_insert(0) += v
    }

    for (k, v) in output_counters {
        *total_output_counters.entry(k).or_insert(0) += v
    }

    for (k, v) in fwd_output_counters {
        *total_output_counters.entry(k).or_insert(0) += v
    }

    info!("Got final input counters: {:?}", total_input_counters);
    info!("Got final output counters: {:?}", total_output_counters);

    let mut total_in: u64 = 0;
    for entry in total_input_counters.iter() {
        let input = entry.1;
        total_in += input;
    }
    info!("Total input of {} bytes this round", total_in);
    let mut total_out: u64 = 0;
    for entry in total_output_counters.iter() {
        let output = entry.1;
        total_out += output;
    }
    info!("Total output of {} bytes this round", total_out);

    // Flow counters should debit your neighbor which you received the packet from
    // Destination counters should credit your neighbor which you sent the packet to

    let mut debts = HashMap::new();

    // Setup the debts table
    for (_, ident) in identities.clone() {
        debts.insert(ident, Int256::from(0));
    }

    // We take the destination ip and input interface and then look up what local neighbor
    // to credit that debt to using the interface (since tunnel interfaces are unique to a neighbor)
    // we also look up the destination cost from babel using the destination ip
    for ((ip, interface), bytes) in total_input_counters {
        let state = (destinations.get(&ip), if_to_id.get(&interface));
        match state {
            (Some(dest), Some(id_from_if)) => {
                match debts.get_mut(&id_from_if) {
                    Some(debt) => {
                        *debt -= (dest.clone()) * bytes;
                    }
                    // debts is generated from identities, this should be impossible
                    None => warn!("No debts entry for input entry id {:?}", id_from_if),
                }
            }
            // this can be caused by a peer that has not yet formed a babel route
            // we use _ because ip_to_if is created from identites, if one fails the other must
            (None, Some(id)) => warn!("We have an id {:?} but not destination", id),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (Some(dest), None) => warn!("We have a destination {:?} but no id", dest),
            // dead entry?
            (None, None) => warn!("We have a counter but nothing else on {:?}", ip),
        }
    }

    trace!("Collated flow debts: {:?}", debts);

    // We take the destination ip and output interface and then look up what local neighbor
    // to credit that debt from us using the interface (since tunnel interfaces are unique to a neighbor)
    // we also look up the destination cost from babel using the destination ip
    for ((ip, interface), bytes) in total_output_counters {
        let state = (destinations.get(&ip), if_to_id.get(&interface));
        match state {
            (Some(dest), Some(id_from_if)) => match debts.get_mut(&id_from_if) {
                Some(debt) => {
                    *debt += (dest.clone() - local_fee) * bytes;
                }
                // debts is generated from identities, this should be impossible
                None => warn!("No debts entry for input entry id {:?}", id_from_if),
            },
            // this can be caused by a peer that has not yet formed a babel route
            // we use _ because ip_to_if is created from identites, if one fails the other must
            (None, Some(id_from_if)) => warn!("We have an id {:?} but not destination", id_from_if),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (Some(dest), None) => warn!("We have a destination {:?} but no id", dest),
            // dead entry?
            (None, None) => warn!("We have a counter but nothing else on {:?}", ip),
        }
    }

    trace!("Collated total Intermediary debts: {:?}", debts);
    info!("Computed Intermediary debts for {:?} peers", debts.len());
    let mut total_income = Int256::zero();
    for entry in debts.iter() {
        let income = entry.1;
        total_income += income;
    }
    info!(
        "Total intermediary debts of {:?} Wei this round",
        total_income
    );

    for (from, amount) in debts {
        trace!("collated debt for {} is {}", from.mesh_ip, amount);

        let update = debt_keeper::TrafficUpdate {
            from: from.clone(),
            amount,
        };

        DebtKeeper::from_registry().do_send(update);
    }

    // check if we are a gateway
    let gateway = match SETTING.get_network().external_nic {
        Some(ref external_nic) => match KI.is_iface_up(external_nic) {
            Some(val) => val,
            None => false,
        },
        None => false,
    };

    trace!("We are a Gateway: {}", gateway);
    SETTING.get_network_mut().is_gateway = gateway;

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::*;

    #[test]
    #[ignore]
    fn debug_babel_socket_common() {
        env_logger::init();
        let bm_stream = TcpStream::connect::<SocketAddr>("[::1]:9001".parse().unwrap()).unwrap();
        watch(Babel::new(bm_stream), &Vec::new()).unwrap();
    }
}
