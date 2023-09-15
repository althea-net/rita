//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ipset counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.

use crate::debt_keeper::traffic_update;
use crate::debt_keeper::Traffic;
use crate::tunnel_manager::Neighbor;
use crate::usage_tracker::structs::UsageType;
use crate::usage_tracker::update_usage_data;
use crate::usage_tracker::UpdateUsage;
use crate::RitaCommonError;
use crate::KI;
use althea_kernel_interface::open_tunnel::is_link_local;
use althea_kernel_interface::FilterTarget;
use althea_types::Identity;
use babel_monitor::structs::Route;
use ipnetwork::IpNetwork;

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default)]
pub struct TrafficWatcher;

pub struct Watch {
    /// List of neighbors to watch
    pub neighbors: Vec<Neighbor>,
    pub routes: Vec<Route>,
}

impl Watch {
    pub fn new(neighbors: Vec<Neighbor>, routes: Vec<Route>) -> Watch {
        Watch { neighbors, routes }
    }
}

pub fn init_traffic_watcher() {
    KI.init_counter(&FilterTarget::Input)
        .expect("Is ipset installed?");
    KI.init_counter(&FilterTarget::Output)
        .expect("Is ipset installed?");
    KI.init_counter(&FilterTarget::ForwardInput)
        .expect("Is ipset installed?");
    KI.init_counter(&FilterTarget::ForwardOutput)
        .expect("Is ipset installed?");

    info!("Traffic Watcher started");
}

pub fn prepare_helper_maps(
    neighbors: &[Neighbor],
) -> (HashMap<IpAddr, Identity>, HashMap<String, Identity>) {
    let mut identities: HashMap<IpAddr, Identity> = HashMap::new();
    let mut if_to_id: HashMap<String, Identity> = HashMap::new();

    for neigh in neighbors {
        // provides a lookup from mesh ip to identity
        identities.insert(neigh.identity.global.mesh_ip, neigh.identity.global);
        // provides a lookup from wireguard interface to mesh ip
        if_to_id.insert(neigh.iface_name.clone(), neigh.identity.global);
    }
    (identities, if_to_id)
}

pub fn get_babel_info(routes: Vec<Route>) -> Result<(HashMap<IpAddr, i128>, u32), RitaCommonError> {
    trace!("Got {} routes: {:?}", routes.len(), routes);
    let mut destinations = HashMap::new();
    let common = settings::get_rita_common();
    // we assume this matches what is actually set it babel because we
    // panic on startup if it does not get set correctly
    let local_fee = common.payment.local_fee;
    let max_fee = common.payment.max_fee;
    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed {
                let price = if route.price > max_fee {
                    max_fee
                } else {
                    route.price
                };

                trace!(
                    "Inserting {} into the destinations map",
                    IpAddr::V6(ip.ip())
                );
                destinations.insert(IpAddr::V6(ip.ip()), i128::from(price + local_fee));
            }
        }
    }

    destinations.insert(
        match common.network.mesh_ip {
            Some(ip) => ip,
            None => {
                return Err(RitaCommonError::MiscStringError(
                    "No mesh IP configured yet".to_string(),
                ))
            }
        },
        i128::from(0),
    );

    trace!("{} destinations setup", destinations.len());

    Ok((destinations, local_fee))
}

pub fn get_input_counters() -> Result<HashMap<(IpAddr, String), u64>, RitaCommonError> {
    let mut total_input_counters = HashMap::new();
    trace!("Getting input counters");
    let input_counters = match KI.read_counters(&FilterTarget::Input) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e.into());
        }
    };
    trace!("Got input counters: {:?}", input_counters);
    trace!("Getting fwd counters");
    let fwd_input_counters = match KI.read_counters(&FilterTarget::ForwardInput) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e.into());
        }
    };

    for (k, v) in input_counters {
        let ip = k.0;
        // our counters have captured packets that are either multicast
        // or ipv6 link local, these are peer to peer comms and not billable
        // since they are not forwarded, ignore them
        if is_link_local(ip) || ip.is_multicast() {
            trace!("Discarding packets that can't be forwarded");
            continue;
        }

        *total_input_counters.entry(k).or_insert(0) += v
    }

    for (k, v) in fwd_input_counters {
        *total_input_counters.entry(k).or_insert(0) += v
    }
    info!("Got final input counters: {:?}", total_input_counters);

    let mut total_in: u64 = 0;
    for entry in total_input_counters.iter() {
        let input = entry.1;
        total_in += input;
    }
    info!("Total input of {} bytes this round", total_in);

    Ok(total_input_counters)
}

pub fn get_output_counters() -> Result<HashMap<(IpAddr, String), u64>, RitaCommonError> {
    let mut total_output_counters = HashMap::new();
    trace!("Getting ouput counters");
    let output_counters = match KI.read_counters(&FilterTarget::Output) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting output counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e.into());
        }
    };
    trace!("Got output counters: {:?}", output_counters);

    let fwd_output_counters = match KI.read_counters(&FilterTarget::ForwardOutput) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e.into());
        }
    };

    for (k, v) in output_counters {
        let ip = k.0;
        // our counters have captured packets that are either multicast
        // or ipv6 link local, these are peer to peer comms and not billable
        // since they are not forwarded, ignore them
        if is_link_local(ip) || ip.is_multicast() {
            trace!("Discarding packets that can't be forwarded");
            continue;
        }

        *total_output_counters.entry(k).or_insert(0) += v
    }

    for (k, v) in fwd_output_counters {
        *total_output_counters.entry(k).or_insert(0) += v
    }
    info!("Got final output counters: {:?}", total_output_counters);

    let mut total_out: u64 = 0;
    for entry in total_output_counters.iter() {
        let output = entry.1;
        total_out += output;
    }
    info!("Total output of {} bytes this round", total_out);

    Ok(total_output_counters)
}

/// Takes and sums the input and output counters for logging
fn update_usage(
    input: &HashMap<(IpAddr, String), u64>,
    output: &HashMap<(IpAddr, String), u64>,
    our_fee: u32,
) {
    let mut total_in = 0;
    let mut total_out = 0;
    for (_, count) in input.iter() {
        total_in += count;
    }
    for (_, count) in output.iter() {
        total_out += count;
    }
    info!(
        "Total of {} bytes relay upload and {} bytes relay download",
        total_out, total_in
    );

    // update the usage tracker with the details of this round's usage

    update_usage_data(UpdateUsage {
        kind: UsageType::Relay,
        up: total_out,
        down: total_in,
        price: our_fee,
    });
}

/// This traffic watcher watches how much traffic each neighbor sends to each destination
/// between the last time watch was run, (This does _not_ block the thread)
/// It also gathers the price to each destination from Babel and uses this information
/// to calculate how much each neighbor owes. It returns a list of how much each neighbor owes.
///
/// This first time this is run, it will create the rules and then immediately read and zero them.
/// (should return 0)
pub fn watch(routes: Vec<Route>, neighbors: &[Neighbor]) -> Result<(), RitaCommonError> {
    let (identities, if_to_id) = prepare_helper_maps(neighbors);

    let (destinations, local_fee) = get_babel_info(routes)?;

    let total_input_counters = get_input_counters()?;
    let total_output_counters = get_output_counters()?;
    update_usage(&total_input_counters, &total_output_counters, local_fee);

    // Flow counters should debit your neighbor which you received the packet from
    // Destination counters should credit your neighbor which you sent the packet to

    let mut debts = HashMap::new();

    // Setup the debts table
    for (_, ident) in identities {
        debts.insert(ident, 0i128);
    }

    // We take the destination ip and input interface and then look up what local neighbor
    // to credit that debt to using the interface (since tunnel interfaces are unique to a neighbor)
    // we also look up the destination cost from babel using the destination ip
    for ((ip, interface), bytes) in total_input_counters {
        let state = (destinations.get(&ip), if_to_id.get(&interface));
        match state {
            (Some(dest), Some(id_from_if)) => {
                match debts.get_mut(id_from_if) {
                    Some(debt) => {
                        *debt -= dest * i128::from(bytes);
                    }
                    // debts is generated from identities, this should be impossible
                    None => warn!("No debts entry for input entry id {:?}", id_from_if),
                }
            }
            // this can be caused by a peer that has not yet formed a babel route
            // we use _ because ip_to_if is created from identities, if one fails the other must
            (None, Some(if_to_id)) => warn!(
                "We have an id {:?} but not destination for {}",
                if_to_id.mesh_ip, ip
            ),
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
            (Some(dest), Some(id_from_if)) => match debts.get_mut(id_from_if) {
                Some(debt) => {
                    *debt += (dest - i128::from(local_fee)) * i128::from(bytes);
                }
                // debts is generated from identities, this should be impossible
                None => warn!("No debts entry for input entry id {:?}", id_from_if),
            },
            // this can be caused by a peer that has not yet formed a babel route
            // we use _ because ip_to_if is created from identities, if one fails the other must
            (None, Some(id_from_if)) => warn!(
                "We have an id {:?} but not destination for {}",
                id_from_if.mesh_ip, ip
            ),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (Some(dest), None) => warn!("We have a destination {:?} but no id", dest),
            // dead entry?
            (None, None) => warn!("We have a counter but nothing else on {:?}", ip),
        }
    }

    trace!("Collated total Intermediary debts: {:?}", debts);
    info!("Computed Intermediary debts for {:?} peers", debts.len());
    let mut total_income = 0i128;
    for entry in debts.iter() {
        let income = entry.1;
        total_income += income;
    }
    info!(
        "Total intermediary debts of {:?} Wei this round",
        total_income
    );

    let mut traffic_vec = Vec::new();
    for (from, amount) in debts {
        trace!("collated debt for {} is {}", from.mesh_ip, amount);
        traffic_vec.push(Traffic {
            from,
            amount: amount.into(),
        });
    }
    traffic_update(traffic_vec);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::net::Ipv6Addr;
    #[test]
    fn test_ip_lookup() {
        let ip_a: IpAddr = "fd00::1337:e8f".parse().unwrap();
        let ip_b: Ipv6Addr = "fd00::1337:e8f".parse().unwrap();
        let ip_b = IpAddr::V6(ip_b);
        assert_eq!(ip_a, ip_b);
        let mut map = HashMap::new();
        map.insert(ip_b, "test");
        assert!(map.get(&ip_a).is_some());
    }
}
