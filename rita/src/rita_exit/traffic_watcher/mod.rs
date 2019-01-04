//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ipset counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.
//!
//! This is the exit specific billing code used to determine how exits should be compensted. Which is
//! different in that mesh nodes are paid by forwarding traffic, but exits have to return traffic and
//! must get paid for doing so.
//!
//! Also handles enforcement of nonpayment, since there's no need for a complicated TunnelManager for exits

use ::actix::prelude::*;
use althea_types::WgKey;

use althea_kernel_interface::wg_iface_counter::WgUsage;
use althea_kernel_interface::KI;

use althea_types::Identity;

use babel_monitor::Babel;

use crate::rita_common::debt_keeper;
use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::Traffic;

use crate::rita_exit::rita_loop::EXIT_LOOP_SPEED;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};

use ipnetwork::IpNetwork;

use crate::SETTING;
use settings::{RitaCommonSettings, RitaExitSettings};

use failure::Error;

pub struct TrafficWatcher {
    last_seen_bytes: HashMap<WgKey, WgUsage>,
}

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}

impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        if let Err(e) = KI.setup_wg_if_named("wg_exit") {
            warn!("exit setup returned {}", e)
        }
        KI.setup_nat(&SETTING.get_network().external_nic.clone().unwrap())
            .unwrap();

        info!("Traffic Watcher started");
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {
            last_seen_bytes: HashMap::new(),
        }
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

        watch(&mut self.last_seen_bytes, Babel::new(stream), &msg.0)
    }
}

fn get_babel_info<T: Read + Write>(
    mut babel: Babel<T>,
    our_id: Identity,
    id_from_ip: HashMap<IpAddr, Identity>,
) -> Result<HashMap<WgKey, u64>, Error> {
    babel.start_connection()?;

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    // insert ourselves as a destination, don't think this is actually needed
    let mut destinations = HashMap::new();
    destinations.insert(
        our_id.wg_public_key,
        u64::from(babel.get_local_fee().unwrap()),
    );

    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed {
                match id_from_ip.get(&IpAddr::V6(ip.ip())) {
                    Some(id) => {
                        destinations.insert(id.wg_public_key.clone(), u64::from(route.price));
                    }
                    None => warn!("Can't find destinatoin for client {:?}", ip.ip()),
                }
            }
        }
    }
    Ok(destinations)
}

fn generate_helper_maps(
    our_id: &Identity,
    clients: &[Identity],
) -> Result<(HashMap<WgKey, Identity>, HashMap<IpAddr, Identity>), Error> {
    let mut identities: HashMap<WgKey, Identity> = HashMap::new();
    let mut id_from_ip: HashMap<IpAddr, Identity> = HashMap::new();
    let our_settings = SETTING.get_network();
    id_from_ip.insert(our_settings.mesh_ip.unwrap(), our_id.clone());

    for ident in clients.iter() {
        identities.insert(ident.wg_public_key.clone(), ident.clone());
        id_from_ip.insert(ident.mesh_ip, ident.clone());
    }

    Ok((identities, id_from_ip))
}

fn counters_logging(counters: &HashMap<WgKey, WgUsage>) {
    trace!("exit counters: {:?}", counters);

    let mut total_in: u64 = 0;
    for entry in counters.iter() {
        info!(
            "Exit accounted {} uploaded {} bytes",
            entry.0, entry.1.download
        );
        let input = entry.1;
        total_in += input.download;
    }
    info!("Total Exit input of {} bytes this round", total_in);
    let mut total_out: u64 = 0;
    for entry in counters.iter() {
        info!(
            "Exit accounted {} downloaded {} bytes",
            entry.0, entry.1.upload
        );
        let output = entry.1;
        total_out += output.upload;
    }
    info!("Total Exit output of {} bytes this round", total_out);
}

fn debts_logging(debts: &HashMap<Identity, i128>) {
    info!("Collated total exit debts: {:?}", debts);

    info!("Computed exit debts for {:?} clients", debts.len());
    let mut total_income = 0i128;
    for (_identity, income) in debts.iter() {
        total_income += income;
    }
    info!("Total exit income of {:?} Wei this round", total_income);

    match KI.get_wg_exit_clients_online() {
        Ok(users) => info!("Total of {} users online", users),
        Err(e) => warn!("Getting clients failed with {:?}", e),
    }
}

pub fn update_usage_history(
    counters: &HashMap<WgKey, WgUsage>,
    usage_history: &mut HashMap<WgKey, WgUsage>,
) {
    for (wg_key, bytes) in counters.iter() {
        match usage_history.get_mut(&wg_key) {
            Some(history) => {
                // tunnel has been reset somehow, reset usage
                if history.download > bytes.download {
                    history.download = 0;
                }
                if history.upload > bytes.upload {
                    history.download = 0;
                }
            }
            None => {
                trace!(
                    "We have not seen {:?} before, starting counter off at {:?}",
                    wg_key,
                    bytes
                );
                usage_history.insert(wg_key.clone(), bytes.clone());
            }
        }
    }
}

/// This traffic watcher watches how much traffic each we send and receive from each client.
pub fn watch<T: Read + Write>(
    usage_history: &mut HashMap<WgKey, WgUsage>,
    babel: Babel<T>,
    clients: &[Identity],
) -> Result<(), Error> {
    // the number of bytes provided under the free tier, (kbps * seconds) * 125 = bytes
    let free_tier_threshold: u64 =
        u64::from(SETTING.get_payment().free_tier_throughput) * EXIT_LOOP_SPEED * 125u64;

    let our_price = SETTING.get_exit_network().exit_price;
    let our_id = match SETTING.get_identity() {
        Some(id) => id,
        None => {
            warn!("Our identity is not ready!");
            bail!("Identity is not ready");
        }
    };

    let (identities, id_from_ip) = generate_helper_maps(&our_id, clients)?;
    let destinations = get_babel_info(babel, our_id.clone(), id_from_ip)?;

    let counters = match KI.read_wg_counters("wg_exit") {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };
    counters_logging(&counters);

    // creates new usage entires does not actualy update the values
    update_usage_history(&counters, usage_history);

    let mut debts = HashMap::new();

    // Setup the debts table
    for (_, ident) in identities.clone() {
        debts.insert(ident, 0 as i128);
    }

    // accounting for 'input'
    for (wg_key, bytes) in counters.clone() {
        let state = (
            identities.get(&wg_key),
            destinations.get(&wg_key),
            usage_history.get_mut(&wg_key),
        );
        match state {
            (Some(id), Some(_dest), Some(history)) => match debts.get_mut(&id) {
                Some(debt) => {
                    let used = bytes.download - history.download;
                    if free_tier_threshold < used {
                        let value = i128::from(our_price) * i128::from(used - free_tier_threshold);
                        trace!("We are billing for {} bytes input (client output) subtracted from {} byte free tier times a exit price of {} for a total of -{}", used, free_tier_threshold, our_price, value);
                        *debt -= value;
                    } else {
                        trace!("{:?} not billed under free tier rules", id);
                    }
                    // update history so that we know what was used from previous cycles
                    history.download = bytes.download;
                }
                // debts is generated from identities, this should be impossible
                None => warn!("No debts entry for input entry id {:?}", id),
            },
            (Some(id), Some(_dest), None) => warn!("Entry for {:?} should have been created", id),
            // this can be caused by a peer that has not yet formed a babel route
            (Some(id), None, _) => warn!("We have an id {:?} but not destination", id),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (None, Some(dest), _) => warn!("We have a destination {:?} but no id", dest),
            // dead entry?
            (None, None, _) => warn!("We have no id or dest for an input counter on {:?}", wg_key),
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
            (Some(id), Some(dest), Some(history)) => match debts.get_mut(&id) {
                Some(debt) => {
                    let used = bytes.upload - history.upload;
                    if free_tier_threshold < used {
                        let value =
                            i128::from(dest + our_price) * i128::from(used - free_tier_threshold);
                        trace!("We are billing for {} bytes output (client input) subtracted from {} byte free tier times a exit dest price of {} for a total of -{}", used, free_tier_threshold, dest + our_price, value);
                        *debt -= value;
                    } else {
                        trace!("{:?} not billed under free tier rules", id);
                    }
                    history.upload = bytes.upload;
                }
                // debts is generated from identities, this should be impossible
                None => warn!("No debts entry for input entry id {:?}", id),
            },
            (Some(id), Some(_dest), None) => warn!("Entry for {:?} should have been created", id),
            // this can be caused by a peer that has not yet formed a babel route
            (Some(id), None, _) => warn!("We have an id {:?} but not destination", id),
            // if we have a babel route we should have a peer it's possible we have a mesh client sneaking in?
            (None, Some(dest), _) => warn!("We have a destination {:?} but no id", dest),
            // dead entry?
            (None, None, _) => warn!("We have no id or dest for an input counter on {:?}", wg_key),
        }
    }

    debts_logging(&debts);

    let mut traffic_vec = Vec::new();
    for (from, amount) in debts {
        // Provides a 10% discount to encourage convergence
        let discounted_amount = ((amount as f64) * 0.95 ) as i128;
        trace!("discounted {} to {}", amount, discounted_amount);
        traffic_vec.push(Traffic {
            from: from,
            amount: discounted_amount.into(),
        })
    }
    let update = debt_keeper::TrafficUpdate {
        traffic: traffic_vec,
    };
    DebtKeeper::from_registry().do_send(update);

    Ok(())
}

#[cfg(test)]
mod tests {
    use env_logger;

    use super::*;

    #[test]
    #[ignore]
    fn debug_babel_socket_client() {
        env_logger::init();
        let bm_stream = TcpStream::connect::<SocketAddr>("[::1]:9001".parse().unwrap()).unwrap();
        watch(&mut HashMap::new(), Babel::new(bm_stream), &[]).unwrap();
    }
}
