use actix::prelude::*;

use althea_kernel_interface::FilterTarget;
use KI;

use althea_types::LocalIdentity;

use babel_monitor::Babel;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;

use num256::Int256;

use std::collections::HashMap;
use std::net::IpAddr;

use ip_network::IpNetwork;

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

#[derive(Message)]
pub struct Watch(pub Vec<(LocalIdentity, String)>);

impl Handler<Watch> for TrafficWatcher {
    type Result = ();

    fn handle(&mut self, msg: Watch, _: &mut Context<Self>) -> Self::Result {
        watch(&msg.0).unwrap();
    }
}

/// This traffic watcher watches how much traffic each neighbor sends to each destination
/// between the last time watch was run, (This does _not_ block the thread)
/// It also gathers the price to each destination from Babel and uses this information
/// to calculate how much each neighbor owes. It returns a list of how much each neighbor owes.
///
/// This first time this is run, it will create the rules and then immediately read and zero them.
/// (should return 0)
pub fn watch(neighbors: &[(LocalIdentity, String)]) -> Result<(), Error> {
    let mut babel = Babel::new(&format!("[::1]:{}", SETTING.get_network().babel_port)
        .parse()
        .unwrap());

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    let mut identities: HashMap<IpAddr, LocalIdentity> = HashMap::new();
    for ident in neighbors {
        identities.insert(ident.0.global.mesh_ip, ident.0.clone());
    }

    let mut if_to_ip: HashMap<String, IpAddr> = HashMap::new();
    for ident in neighbors {
        if_to_ip.insert(ident.clone().1, ident.0.global.mesh_ip);
    }

    let mut ip_to_if: HashMap<IpAddr, String> = HashMap::new();
    for ident in neighbors {
        ip_to_if.insert(ident.0.global.mesh_ip, ident.clone().1);
    }

    let mut destinations = HashMap::new();
    let local_price = babel.local_fee().unwrap();

    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.get_netmask() == 128 && route.installed {
                destinations.insert(
                    IpAddr::V6(ip.get_network_address()),
                    Int256::from(route.price + local_price),
                );
            }
        }
    }

    destinations.insert(SETTING.get_network().own_ip, Int256::from(0));

    trace!("Getting input counters");
    let input_counters = KI.read_counters(&FilterTarget::Input)?;
    info!("Got output counters: {:?}", input_counters);

    trace!("Getting destination counters");
    let output_counters = KI.read_counters(&FilterTarget::Output)?;
    info!("Got destination counters: {:?}", output_counters);

    trace!("Getting fwd counters");
    let fwd_input_counters = KI.read_counters(&FilterTarget::ForwardInput)?;
    let fwd_output_counters = KI.read_counters(&FilterTarget::ForwardOutput)?;

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

    // Flow counters should debit your neighbor which you received the packet from
    // Destination counters should credit your neighbor which you sent the packet to

    let mut debts = HashMap::new();

    // Setup the debts table
    for (_, ident) in identities.clone() {
        debts.insert(ident, Int256::from(0));
    }

    for ((ip, interface), bytes) in total_input_counters {
        if destinations.contains_key(&ip) && if_to_ip.contains_key(&interface)
            && identities.contains_key(&if_to_ip[&interface])
        {
            let id = identities[&if_to_ip[&interface]].clone();
            *debts.get_mut(&id).unwrap() -= (destinations[&ip].clone()) * bytes;
        } else {
            warn!("flow destination not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated flow debts: {:?}", debts);

    for ((ip, interface), bytes) in total_output_counters {
        if destinations.contains_key(&ip) && if_to_ip.contains_key(&interface)
            && identities.contains_key(&if_to_ip[&interface])
        {
            let id = identities[&if_to_ip[&interface]].clone();
            *debts.get_mut(&id).unwrap() += (destinations[&ip].clone() - local_price) * bytes;
        } else {
            warn!("destination not found {}, {}", ip, bytes);
        }
    }

    trace!("Collated total debts: {:?}", debts);

    for (k, v) in &debts {
        trace!("collated debt for {} is {}", k.global.mesh_ip, v);
    }

    for (from, amount) in debts {
        let update = debt_keeper::TrafficUpdate {
            from: from.global.clone(),
            amount,
        };

        DebtKeeper::from_registry().do_send(update);
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
