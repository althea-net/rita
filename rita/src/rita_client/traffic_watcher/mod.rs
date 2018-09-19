//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ip counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.
//!
//! This is the client specific billing code used to determine how exits should be compensted. Which is
//! different in that mesh nodes are paid by forwarding traffic, but exits have to return traffic and
//! must get paid for doing so.

use actix::prelude::*;
use failure::Error;
use ipnetwork::IpNetwork;
use reqwest;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};

use althea_types::{Identity, RTTimestamps};
use babel_monitor::Babel;
use num256::Int256;
use rita_common::debt_keeper::{DebtKeeper, TrafficUpdate};
use settings::{RitaClientSettings, RitaCommonSettings};
use KI;
use SETTING;

pub struct TrafficWatcher;

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}
impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Client traffic watcher started");

        KI.init_iface_counters("wg_exit").unwrap();
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {}
    }
}

pub struct Watch(pub Identity, pub u64);

impl Message for Watch {
    type Result = Result<(), Error>;
}

impl Handler<Watch> for TrafficWatcher {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: Watch, _: &mut Context<Self>) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;

        watch(Babel::new(stream), msg.0, msg.1)
    }
}

/// This traffic watcher watches how much traffic we send to the exit, and how much the exit sends
/// back to us.
pub fn watch<T: Read + Write>(
    mut babel: Babel<T>,
    exit: Identity,
    exit_price: u64,
) -> Result<(), Error> {
    babel.start_connection()?;

    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    info!("Got routes: {:?}", routes);

    let mut destinations = HashMap::new();

    for route in &routes {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed {
                destinations.insert(IpAddr::V6(ip.ip()), route);
            }
        }
    }

    let (input, output) = match KI.read_iface_counters("wg_exit") {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "Error getting input output counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };

    // account for wg packet overhead
    let input = input.total_bytes();
    let output = output.total_bytes();

    trace!("got {:?} from client exit counters", (&input, &output));

    let mut owes: Int256 = Int256::from(0);

    trace!("exit price {}", exit_price);

    if destinations.contains_key(&exit.mesh_ip) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        let target_route = destinations[&exit.mesh_ip];
        let exit_dest_price: Int256 = Int256::from(target_route.price) + exit_price;
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
            )).send()?
            .json()?;
        let client_rx = SystemTime::now();

        let inner_rtt = client_rx.duration_since(client_tx)? - exit_tx.duration_since(exit_rx)?;
        let inner_rtt_millis =
            inner_rtt.as_secs() as f32 * 1000.0 + inner_rtt.subsec_nanos() as f32 / 1_000_000.0;
        //                        secs -> millis                            nanos -> millis

        trace!(
            "RTTs: per-hop {}ms, inner {}ms",
            target_route.full_path_rtt,
            inner_rtt_millis
        );

        trace!("exit destination price {}", exit_dest_price);
        trace!("Exit ip: {:?}", exit.mesh_ip);
        trace!("Exit destination:\n{:#?}", target_route);

        owes += Int256::from(exit_price * output) + exit_dest_price * input;

        let update = TrafficUpdate {
            from: exit.clone(),
            amount: owes,
        };

        DebtKeeper::from_registry().do_send(update);
    } else {
        warn!(
            "not yet have route to exit at {:?}, ignoring payment",
            &exit.mesh_ip
        )
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::*;
    use althea_types::EthAddress;
    use std::str::FromStr;

    #[test]
    #[ignore]
    fn debug_babel_socket_client() {
        env_logger::init();
        let bm_stream = TcpStream::connect::<SocketAddr>("[::1]:9001".parse().unwrap()).unwrap();
        watch(
            Babel::new(bm_stream),
            Identity::new(
                "0.0.0.0".parse().unwrap(),
                EthAddress::from_str("abababababababababab").unwrap(),
                String::from("abc0abc1abc2abc3abc4abc5abc6abc7abc8abc9"),
            ),
            5,
        ).unwrap();
    }
}
