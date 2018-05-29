use actix::prelude::*;

use KI;

use althea_types::Identity;

use babel_monitor::Babel;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;

use num256::Int256;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};

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
        info!("Client traffic watcher started");

        KI.init_exit_client_counters().unwrap();
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
            if ip.get_netmask() == 128 && route.installed {
                destinations.insert(
                    IpAddr::V6(ip.get_network_address()),
                    Int256::from(route.price),
                );
            }
        }
    }

    let input = KI.read_exit_client_counters_input();
    let output = KI.read_exit_client_counters_output();

    trace!("got {:?} from client exit counters", (&input, &output));

    let input = input?;
    let output = output?;

    let mut owes: Int256 = Int256::from(0);

    trace!("exit price {}", exit_price);

    if destinations.contains_key(&exit.mesh_ip) {
        trace!(
            "exit destination price {}",
            destinations[&exit.mesh_ip].clone() + exit_price
        );

        owes += Int256::from(exit_price * output);

        owes += (destinations[&exit.mesh_ip].clone() + exit_price) * input;

        let update = debt_keeper::TrafficUpdate {
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
    use althea_types::eth_address::EthAddress;
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
