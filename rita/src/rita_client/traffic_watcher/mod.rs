//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ip counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.
//!
//! This is the client specific billing code used to determine how exits should be compensted. Which is
//! different in that mesh nodes are paid by forwarding traffic, but exits have to return traffic and
//! must get paid for doing so.

use ::actix::prelude::*;
use failure::Error;
use ipnetwork::IpNetwork;
use reqwest;

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};

use crate::rita_client::rita_loop::CLIENT_LOOP_SPEED;
use crate::rita_common::debt_keeper::{DebtKeeper, Traffic, TrafficUpdate};
use crate::KI;
use crate::SETTING;
use althea_types::{Identity, RTTimestamps};
use babel_monitor::Babel;
use settings::{RitaClientSettings, RitaCommonSettings};

pub struct TrafficWatcher {
    last_read_input: u64,
    last_read_output: u64,
}

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}
impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Client traffic watcher started");
        self.last_read_input = 0;
        self.last_read_output = 0;
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {
            last_read_input: 0,
            last_read_output: 0,
        }
    }
}

pub struct Watch {
    pub exit_id: Identity,
    pub exit_price: u64,
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

        watch(self, Babel::new(stream), msg.exit_id, msg.exit_price)
    }
}

/// This traffic watcher watches how much traffic we send to the exit, and how much the exit sends
/// back to us.
pub fn watch<T: Read + Write>(
    history: &mut TrafficWatcher,
    mut babel: Babel<T>,
    exit: Identity,
    exit_price: u64,
) -> Result<(), Error> {
    // the number of bytes provided under the free tier, (kbps * seconds) * (1000/8) = bytes
    let free_tier_threshold: u64 =
        u64::from(SETTING.get_payment().free_tier_throughput) * CLIENT_LOOP_SPEED * 125u64;

    babel.start_connection()?;

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    trace!("Got routes: {:?}", routes);
    let babel_neighs = babel.parse_neighs()?;
    trace!("Got neighs: {:?}", babel_neighs);

    let mut exit_route = None;
    for route in routes.iter() {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed && IpAddr::V6(ip.ip()) == exit.mesh_ip {
                exit_route = Some(route);
                break;
            }
        }
    }
    if exit_route.is_none() {
        bail!("No route to exit, therefore we can't be sending traffic to it");
    }
    let exit_route = exit_route.unwrap();

    let counter = match KI.read_wg_counters("wg_exit") {
        Ok(res) => {
            if res.len() > 1 {
                warn!("wg_exit client tunnel has multiple peers!");
            } else if res.is_empty() {
                warn!("No peers on wg_exit why is client traffic watcher running?");
                return Err(format_err!("No peers on wg_exit"));
            }
            // unwrap is safe because we check that len is not equal to zero
            // then we toss the exit's wg key as we don't need it
            res.iter().last().unwrap().1.clone()
        }
        Err(e) => {
            warn!(
                "Error getting router client input output counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };

    // bandwidth usage should always increase if it doesn't the interface has been
    // deleted and recreated and we need to reset our usage, also protects from negatives
    if history.last_read_input > counter.download || history.last_read_output > counter.upload {
        warn!("Exit tunnel reset resetting counters");
        history.last_read_input = 0;
        history.last_read_output = 0;
    }

    let input = counter.download - history.last_read_input;
    let output = counter.upload - history.last_read_output;

    history.last_read_input = counter.download;
    history.last_read_output = counter.upload;

    info!("{:?} bytes downloaded from exit this round", &input);
    info!("{:?} bytes uploaded to exit this round", &output);

    // the price we pay to send traffic through the exit
    info!("exit price {}", exit_price);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // price to get traffic to the exit as a u64 to make the type rules for math easy
    let exit_route_price: i128 = exit_route.price.into();
    // the total price for the exit returning traffic to us, in the future we should ask
    // the exit for this because TODO assumes symetric route
    let exit_dest_price: i128 = exit_route_price + i128::from(exit_price);
    let client_tx = SystemTime::now();
    let RTTimestamps { exit_rx, exit_tx } = client
        .get(&format!(
            "http://[{}]:{}/rtt",
            exit.mesh_ip,
            match SETTING.get_exit_client().get_current_exit() {
                Some(current_exit) => current_exit.registration_port,
                None => {
                    return Err(format_err!(
                        "No current exit even though an exit route is present"
                    ));
                }
            }
        ))
        .send()?
        .json()?;
    let client_rx = SystemTime::now();

    let inner_rtt = client_rx.duration_since(client_tx)? - exit_tx.duration_since(exit_rx)?;
    let inner_rtt_millis =
        inner_rtt.as_secs() as f32 * 1000.0 + inner_rtt.subsec_nanos() as f32 / 1_000_000.0;
    //                        secs -> millis                            nanos -> millis

    info!(
        "RTTs: per-hop {}ms, inner {}ms",
        exit_route.full_path_rtt, inner_rtt_millis
    );

    info!("Exit destination price {}", exit_dest_price);
    trace!("Exit ip: {:?}", exit.mesh_ip);
    trace!("Exit destination:\n{:#?}", exit_route);

    // accounts for what we owe the exit for return data and sent data
    // we have to pay our neighbor for what we send over them
    // remember pay per *forward* so we pay our neighbor for what we
    // send to the exit while we pay the exit to pay it's neighbor to eventually
    // pay our neighbor to send data back to us.
    let mut owes_exit = 0i128;
    if input > free_tier_threshold {
        owes_exit += i128::from(input - free_tier_threshold) * exit_dest_price;
    }
    if output > free_tier_threshold {
        owes_exit += i128::from(exit_price * (output - free_tier_threshold));
    }

    if owes_exit > 0 {
        info!("Total client debt of {} this round", owes_exit);

        let exit_update = TrafficUpdate {
            traffic: vec![Traffic {
                from: exit.clone(),
                amount: owes_exit.into(),
            }],
        };

        DebtKeeper::from_registry().do_send(exit_update);
    } else {
        trace!("Exit bandwidth did not exceed free tier, no bill");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use env_logger;

    use super::*;
    use althea_types::WgKey;
    use clarity::Address;
    use std::str::FromStr;

    #[test]
    #[ignore]
    fn debug_babel_socket_client() {
        env_logger::init();
        let bm_stream = TcpStream::connect::<SocketAddr>("[::1]:9001".parse().unwrap()).unwrap();
        watch(
            &mut TrafficWatcher {
                last_read_input: 0u64,
                last_read_output: 0u64,
            },
            Babel::new(bm_stream),
            Identity::new(
                "0.0.0.0".parse().unwrap(),
                Address::from_str("abababababababababab").unwrap(),
                WgKey::from_str("abc0abc1abc2abc3abc4abc5abc6abc7abc8abc=").unwrap(),
            ),
            5,
        )
        .unwrap();
    }
}
