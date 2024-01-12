//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ipset counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.
//!
//! This is the exit specific billing code used to determine how exits should be compensted. Which is
//! different in that mesh nodes are paid by forwarding traffic, but exits have to return traffic and
//! must get paid for doing so.
//!
//! Also handles enforcement of nonpayment, since there's no need for a complicated TunnelManager for exits

use rita_common::debt_keeper::traffic_update;
use rita_common::debt_keeper::Traffic;
use rita_common::usage_tracker::update_usage_data;
use rita_common::usage_tracker::UpdateUsage;
use rita_common::usage_tracker::UsageType;

use althea_kernel_interface::wg_iface_counter::prepare_usage_history;
use althea_kernel_interface::wg_iface_counter::WgUsage;
use althea_kernel_interface::KI;
use althea_types::Identity;
use althea_types::WgKey;
use babel_monitor::structs::Route;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::RwLock;

use crate::database::EXIT_INTERFACE;
use crate::database::LEGACY_INTERFACE;
use crate::RitaExitError;

lazy_static! {
    static ref TRAFFIC_WATCHER: Arc<RwLock<TrafficWatcher>> =
        Arc::new(RwLock::new(TrafficWatcher::default()));
}

#[derive(Default)]
pub struct TrafficWatcher {
    last_seen_bytes: HashMap<WgKey, WgUsage>,
}

pub struct Watch {
    pub users: Vec<Identity>,
    pub routes: Vec<Route>,
}

pub fn watch_exit_traffic(msg: Watch) -> Result<(), Box<RitaExitError>> {
    let traffic_watcher = &mut *TRAFFIC_WATCHER.write().unwrap();
    watch(
        &mut traffic_watcher.last_seen_bytes,
        &msg.routes,
        &msg.users,
    )
}

fn get_babel_info(
    routes: &[Route],
    our_id: Identity,
    id_from_ip: HashMap<IpAddr, Identity>,
) -> HashMap<WgKey, u64> {
    // we assume this matches what is actually set it babel becuase we
    // panic on startup if it does not get set correctly
    let local_fee = settings::get_rita_exit().network.babeld_settings.local_fee;

    // insert ourselves as a destination, don't think this is actually needed
    let mut destinations = HashMap::new();
    destinations.insert(our_id.wg_public_key, u64::from(local_fee));

    let max_fee = settings::get_rita_exit().payment.max_fee;
    for route in routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed {
                match id_from_ip.get(&IpAddr::V6(ip.ip())) {
                    Some(id) => {
                        let price = if route.price > max_fee {
                            max_fee
                        } else {
                            route.price
                        };

                        destinations.insert(id.wg_public_key, u64::from(price));
                    }
                    None => trace!("Can't find destination for client {:?}", ip.ip()),
                }
            }
        }
    }
    destinations
}

struct HelperMapReturn {
    wg_to_id: HashMap<WgKey, Identity>,
    ip_to_id: HashMap<IpAddr, Identity>,
}

fn generate_helper_maps(our_id: &Identity, clients: &[Identity]) -> HelperMapReturn {
    let mut identities: HashMap<WgKey, Identity> = HashMap::new();
    let mut id_from_ip: HashMap<IpAddr, Identity> = HashMap::new();
    let rita_exit = settings::get_rita_exit();
    let our_settings = rita_exit.network;
    id_from_ip.insert(our_settings.mesh_ip.unwrap(), *our_id);

    for ident in clients.iter() {
        identities.insert(ident.wg_public_key, *ident);
        id_from_ip.insert(ident.mesh_ip, *ident);
    }

    HelperMapReturn {
        wg_to_id: identities,
        ip_to_id: id_from_ip,
    }
}

fn counters_logging(
    counters: &HashMap<WgKey, WgUsage>,
    history: &HashMap<WgKey, WgUsage>,
    exit_fee: u32,
) {
    trace!("wg counters: {:?}", counters);

    let mut total_in: u64 = 0;
    for entry in counters.iter() {
        let key = entry.0;
        let val = entry.1;
        if let Some(history_val) = history.get(key) {
            let moved_bytes = val.download - history_val.download;
            trace!("wg accounted {} uploaded {} bytes", key, moved_bytes,);
            total_in += moved_bytes;
        }
    }

    info!("Total Exit input of {} bytes this round", total_in);

    let mut total_out: u64 = 0;
    for entry in counters.iter() {
        let key = entry.0;
        let val = entry.1;
        if let Some(history_val) = history.get(key) {
            let moved_bytes = val.upload - history_val.upload;
            trace!("wg accounted {} downloaded {} bytes", key, moved_bytes);
            total_out += moved_bytes;
        }
    }

    update_usage_data(UpdateUsage {
        kind: UsageType::Exit,
        up: total_out,
        down: total_in,
        price: exit_fee,
    });

    info!("Total Exit output of {} bytes this round", total_out);
}

fn debts_logging(debts: &HashMap<Identity, i128>) {
    trace!("Collated total exit debts: {:?}", debts);

    info!("Computed exit debts for {:?} clients", debts.len());
    let mut total_income = 0i128;
    for (_identity, income) in debts.iter() {
        total_income += income;
    }
    info!("Total exit income of {:?} Wei this round", total_income);

    match KI.get_wg_exit_clients_online(LEGACY_INTERFACE) {
        Ok(users) => info!("Total of {} {} users online", users, LEGACY_INTERFACE),
        Err(e) => warn!("Getting clients failed with {:?}", e),
    }
    match KI.get_wg_exit_clients_online(EXIT_INTERFACE) {
        Ok(users) => info!("Total of {} {} users online", users, EXIT_INTERFACE),
        Err(e) => warn!("Getting clients failed with {:?}", e),
    }
}

/// This traffic watcher watches how much traffic each we send and receive from each client.
pub fn watch(
    usage_history: &mut HashMap<WgKey, WgUsage>,
    routes: &[Route],
    clients: &[Identity],
) -> Result<(), Box<RitaExitError>> {
    // Since Althea is a pay per forward network we must add a surcharge for transaction fees
    // to our own price. In the case Exit -> A -> B -> C the exit pays A a lump sum for it's own
    // fees as well as B's fees. This means the exit pays the transaction fee (a percentage) for
    // that entire series of hops, we use the percentage number to ensure the exit recovers that amount
    let our_price = settings::get_rita_exit().exit_network.exit_price;
    let tx_fee_percentage = settings::get_rita_common()
        .payment
        .simulated_transaction_fee;

    let our_id = match settings::get_rita_exit().get_identity() {
        Some(id) => id,
        None => {
            warn!("Our identity is not ready!");
            return Err(Box::new(RitaExitError::MiscStringError(
                "Identity is not ready".to_string(),
            )));
        }
    };

    let ret = generate_helper_maps(&our_id, clients);
    let identities = ret.wg_to_id;
    let id_from_ip = ret.ip_to_id;
    let destinations = get_babel_info(routes, our_id, id_from_ip);

    let counters = match KI.read_wg_counters(LEGACY_INTERFACE) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(Box::new(e.into()));
        }
    };

    let new_counters = match KI.read_wg_counters(EXIT_INTERFACE) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(Box::new(e.into()));
        }
    };

    let mut debts = HashMap::new();

    // Setup the debts table
    for (_, ident) in identities.clone() {
        debts.insert(ident, 0i128);
    }

    trace!("Old counters are: {:?}", counters);
    trace!("New counters are: {:?}", new_counters);
    let counters: HashMap<WgKey, WgUsage> = merge_counters(&counters, &new_counters);
    trace!("merged counters are : {:?}", counters);

    // creates new usage entires does not actualy update the values
    prepare_usage_history(&counters, usage_history);

    counters_logging(&counters, usage_history, our_price as u32);

    // accounting for 'input'
    for (wg_key, bytes) in counters.clone() {
        let state = (
            identities.get(&wg_key),
            destinations.get(&wg_key),
            usage_history.get_mut(&wg_key),
        );
        match state {
            (Some(id), Some(_dest), Some(history)) => match debts.get_mut(id) {
                Some(debt) => {
                    let used = bytes.download - history.download;
                    let value = i128::from(our_price) * i128::from(used);
                    trace!("We are billing for {} bytes input (client output) times a exit price of {} for a total of -{}", used, our_price, value);
                    *debt -= value;
                    // update history so that we know what was used from previous cycles
                    history.download = bytes.download;
                }
                // debts is generated from identities, this should be impossible
                None => warn!("No debts entry for input entry id {}", id),
            },
            (Some(id), Some(_dest), None) => warn!("Entry for {} should have been created", id),
            // this can be caused by a peer that has not yet formed a babel route
            (Some(id), None, _) => trace!("We have an id {} but not destination", id),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (None, Some(dest), _) => trace!("We have a destination {} but no id", dest),
            // dead entry?
            (None, None, _) => warn!("We have no id or dest for an input counter on {}", wg_key),
        }
    }

    // accounting for 'output'
    for (wg_key, bytes) in counters {
        let state = (
            identities.get(&wg_key),
            destinations.get(&wg_key),
            usage_history.get_mut(&wg_key),
        );
        match state {
            (Some(id), Some(dest), Some(history)) => match debts.get_mut(id) {
                Some(debt) => {
                    let used = bytes.upload - history.upload;
                    // ensure the exit recovers the percentage fee see explanation where tx_fee_percentage is declared
                    // surchage is based only on the price paid forward, since the exit keeps it's share without making
                    // an additional pyament
                    let tx_fee_surcharge =
                        (i128::from(*dest) * i128::from(used)) / i128::from(tx_fee_percentage);
                    let value =
                        (i128::from(dest + our_price) * i128::from(used)) + tx_fee_surcharge;
                    trace!("We are billing for {} bytes output (client input) times a exit dest price of {} for a total of -{}", used, dest + our_price, value);
                    *debt -= value;
                    history.upload = bytes.upload;
                }
                // debts is generated from identities, this should be impossible
                None => warn!("No debts entry for input entry id {}", id),
            },
            (Some(id), Some(_dest), None) => warn!("Entry for {} should have been created", id),
            // this can be caused by a peer that has not yet formed a babel route
            (Some(id), None, _) => trace!("We have an id {} but not destination", id),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (None, Some(dest), _) => warn!("We have a destination {} but no id", dest),
            // dead entry?
            (None, None, _) => warn!("We have no id or dest for an input counter on {}", wg_key),
        }
    }

    debts_logging(&debts);

    let mut traffic_vec = Vec::new();
    for (from, amount) in debts {
        traffic_vec.push(Traffic {
            from,
            amount: amount.into(),
        })
    }
    traffic_update(traffic_vec);

    Ok(())
}

/// This function merges two counter maps for wg_exit and wg_exit_v2 for combined accounting
fn merge_counters(
    old_counters: &HashMap<WgKey, WgUsage>,
    new_counters: &HashMap<WgKey, WgUsage>,
) -> HashMap<WgKey, WgUsage> {
    let mut ret: HashMap<WgKey, WgUsage> = HashMap::new();
    ret.extend(old_counters);
    for (k, e) in new_counters {
        if ret.contains_key(k) {
            let mut usage = *ret.get(k).unwrap();
            usage.upload += e.upload;
            usage.download += e.download;
            ret.insert(*k, usage);
        } else {
            ret.insert(*k, *e);
        }
    }
    ret
}

#[test]
fn test_merge_counters() {
    let mut ret = HashMap::new();
    let mut map1: HashMap<&str, &str> = HashMap::new();
    map1.insert("a", "asdf");

    let mut map2: HashMap<&str, &str> = HashMap::new();
    map2.insert("b", "asdfasdf");

    ret.extend(map1);
    ret.extend(map2);

    println!("{ret:?}");
}
