//! Because of the nature of pay per forward billing download traffic (the most common form of end user traffic)
//! requires an exception, in which the Exit and Client have special billing rules that allow for download traffic
//! to be paid for. This is still a net gain to system design simplicity because the general case of an arbitrary number
//! of nodes forwarding an arbitrary amount of traffic can follow the simple pay per forward rules and we only need to
//! account for exceptions on the endpoints of what may be an arbitrarily long, complicated, and changing path.
//!
//! The big advantage of pay per forward is that it reaches a passive consensus state even when there is packet loss.
//! If packets are lost then the next node only sees a slight overpayment. This isn't the case for download traffic, if
//! the client where to keep track of it's download usage all on it's own it would never be able to account for packet
//! loss that the exit may see.
//!
//! So this module contains two major components.
//!
//! TrafficWatcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ip counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute the usage amounts displayed to the user.
//!
//! QueryExitDebts asks the exit what it thinks this particular client owes (over the secure channel of the exit tunnel)
//! validating if this number is correct is difficult, because the exit is serving us with a total debt while our local
//! billing implementation is only producing a delta change. Knowing if the update is fraudulent or not requires heuristics
//! in debt keeper more than anything that can be done here. What we can do here is take action if several requests fail, falling
//! back to local debt computation rather than running blind.

use crate::rita_loop::is_gateway_client;
use babel_monitor::get_installed_route;
use rita_common::debt_keeper::{
    traffic_replace, traffic_update, wgkey_insensitive_traffic_update, Traffic,
};

use actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use actix_web::client;
use actix_web::client::Connection;
use actix_web::HttpMessage;
use althea_types::Identity;
use babel_monitor::Route as RouteLegacy;
use failure::Error;
use futures01::future::ok as future_ok;
use futures01::future::Future;
use num256::Int256;
use num_traits::identities::Zero;
use rita_common::usage_tracker::update_usage_data;
use rita_common::usage_tracker::UpdateUsage;
use rita_common::usage_tracker::UsageType;
use rita_common::KI;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream as TokioTcpStream;

pub struct TrafficWatcher {
    // last read download
    last_read_input: u64,
    // last read upload
    last_read_output: u64,
    /// cached exit destination price value
    last_exit_dest_price: u128,
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
        self.last_exit_dest_price = 0;
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {
            last_read_input: 0,
            last_read_output: 0,
            last_exit_dest_price: 0,
        }
    }
}

/// Used to request what the exits thinks this clients debts are. We will compare
/// this value to our own computation and alert to any large discrepencies, but in
/// general we have to trust the exit. In a pay per forward system nodes within the
/// network have either of two states, properly paid, or in the face of packet loss and
/// network issues, overpaid. Because packet loss presents as the sending node having
/// a higher total packets sent count than the receiving node. Resulting in what looks
/// like overpayment on the receiving end. For client traffic though this does not apply
/// the client is paying for the exit to send it download traffic. So if packets are lost
/// on the way the client will never know the full price the exit has to pay. This breaks
/// the key assumption that allows us to compute bills without any direct communication beyond
/// packets and payments. To resolve this impossiblity we must communicate with the exit
///
/// This request is made against the exits internal ip address to ensure that upstream
/// nodes can't spoof it.
pub struct QueryExitDebts {
    pub exit_internal_addr: IpAddr,
    pub exit_port: u16,
    pub exit_id: Identity,
    pub exit_price: u64,
    pub routes: Vec<RouteLegacy>,
}

impl Message for QueryExitDebts {
    type Result = Result<(), Error>;
}

impl Handler<QueryExitDebts> for TrafficWatcher {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: QueryExitDebts, _: &mut Context<Self>) -> Self::Result {
        trace!("About to query the exit for client debts");

        // we could exit the function if this fails, but doing so would remove the chance
        // that we can get debts from the exit and continue anyways
        let local_debt =
            match local_traffic_calculation(self, &msg.exit_id, msg.exit_price, msg.routes) {
                Ok(val) => Some(Int256::from(val)),
                Err(_e) => None,
            };

        let gateway_exit_client = is_gateway_client();
        let start = Instant::now();
        let exit_addr = msg.exit_internal_addr;
        let exit_id = msg.exit_id;
        let exit_port = msg.exit_port;
        // actix client behaves badly if you build a request the default way but don't give it
        // a domain name, so in order to do peer to peer requests we use with_connection and our own
        // socket specification
        let our_id = settings::get_rita_client().get_identity();
        let request = format!("http://{}:{}/client_debt", exit_addr, exit_port);
        // it's an ipaddr appended to a u16, there's no real way for this to fail
        // unless of course it's an ipv6 address and you don't do the []
        let socket: SocketAddr = format!("{}:{}", exit_addr, exit_port).parse().unwrap();

        let stream_future = TokioTcpStream::connect(&socket);

        let s = stream_future.then(move |active_stream| match active_stream {
            Ok(stream) => Box::new(
                client::post(request.clone())
                    .with_connection(Connection::from_stream(stream))
                    .json(our_id)
                    .unwrap()
                    .send()
                    .timeout(Duration::from_secs(5))
                    .then(move |response| match response {
                        Ok(response) => Box::new(response.json().then(move |debt_value| {
                            match debt_value {
                                Ok(debt) => {
                                    info!(
                                        "Successfully got debt from the exit {:?} Rita Client TrafficWatcher completed in {}s {}ms",
                                        debt,
                                        start.elapsed().as_secs(),
                                        start.elapsed().subsec_millis()
                                    );
                                    let we_are_not_a_gateway = !gateway_exit_client;
                                    let we_owe_exit = debt >= Int256::zero();
                                    match (we_are_not_a_gateway, we_owe_exit) {
                                        (true, true) => {
                                        traffic_replace(
                                   Traffic {
                                                from: exit_id,
                                                amount: debt,
                                            }
                                        )
                                        },
                                        // the exit should never tell us it owes us, that doesn't make sense outside of the gateway
                                        // client corner case
                                        (true, false) => warn!("We're probably a gateway but haven't detected it yet"),
                                        (false, _) => {
                                            info!("We are a gateway!, Acting accordingly");
                                            if let Some(val) = local_debt {
                                                wgkey_insensitive_traffic_update(
                                       Traffic {
                                                    from: exit_id,
                                                    amount: val,
                                                    }

                                                )
                                            }
                                        },
                                    }
                                }
                                Err(e) => {
                                    error!("Failed deserializing exit debts update with {:?}", e);
                                    if let Some(val) = local_debt {
                                        traffic_update(
                                   vec![Traffic {
                                            from: exit_id,
                                            amount: val,
                                            }]

                                        )
                                    }
                                }
                            }
                            Ok(()) as Result<(), ()>
                        })),
                        Err(e) => {
                            error!("Exit debts request to {} failed with {:?}", request, e);
                            if let Some(val) = local_debt {
                                traffic_update(
                                   vec![Traffic {
                                            from: exit_id,
                                            amount: val,
                                            }]

                                        )
                            }
                            Box::new(future_ok(())) as Box<dyn Future<Item = (), Error = ()>>
                        }
                    }),
            ),

            Err(e) => {
                error!(
                    "Failed to open stream to exit for debts update! with {:?}",
                    e
                );
                if let Some(val) = local_debt {
                                traffic_update(
                                   vec![Traffic {
                                            from: exit_id,
                                            amount: val,
                                            }]

                                        )


                }
                Box::new(future_ok(())) as Box<dyn Future<Item = (), Error = ()>>
            }
        });
        Arbiter::spawn(s);
        Ok(())
    }
}

/// Returns the babel route to a given mesh ip with the properly capped price
fn find_exit_route_capped(
    exit_mesh_ip: IpAddr,
    routes: Vec<RouteLegacy>,
) -> Result<RouteLegacy, Error> {
    let max_fee = settings::get_rita_client().payment.max_fee;
    let mut exit_route = get_installed_route(&exit_mesh_ip, &routes)?;
    if exit_route.price > max_fee {
        let mut capped_route = exit_route.clone();
        capped_route.price = max_fee;
        exit_route = capped_route;
    }
    Ok(exit_route)
}

pub fn local_traffic_calculation(
    history: &mut TrafficWatcher,
    exit: &Identity,
    exit_price: u64,
    routes: Vec<RouteLegacy>,
) -> Result<i128, Error> {
    let exit_route = find_exit_route_capped(exit.mesh_ip, routes)?;
    info!("Exit metric: {}", exit_route.metric);

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
            // create an iterator, take the last (and only) value, then grab the
            // counter and not the key from the hashmap entry
            *res.iter().last().unwrap().1
        }
        Err(e) => {
            warn!(
                "Error getting router client input output counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e.into());
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

    // price to get traffic to the exit as a u64 to make the type rules for math easy
    let exit_route_price: i128 = exit_route.price.into();
    // the total price for the exit returning traffic to us, in the future we should ask
    // the exit for this because TODO assumes symetric route
    let exit_dest_price: i128 = exit_route_price + i128::from(exit_price);

    // send the exit dest price over to the light client manager for consumption there
    history.last_exit_dest_price = exit_dest_price as u128;

    info!("Exit destination price {}", exit_dest_price);
    trace!("Exit ip: {:?}", exit.mesh_ip);
    trace!("Exit destination:\n{:#?}", exit_route);

    // accounts for what we owe the exit for return data and sent data
    // we have to pay our neighbor for what we send over them
    // remember pay per *forward* so we pay our neighbor for what we
    // send to the exit while we pay the exit to pay it's neighbor to eventually
    // pay our neighbor to send data back to us. Here we only pay the exit the exit
    // fee for traffic we send to it since our neighbors billing should be handled in
    // rita_common but we do pay for return traffic here since it doesn't make sense
    // to handle in the general case
    let mut owes_exit = 0i128;
    let value = i128::from(input) * exit_dest_price;
    trace!(
        "We are billing for {} bytes input times a exit dest price of {} for a total of {}",
        input,
        exit_dest_price,
        value
    );
    owes_exit += value;
    let value = i128::from(exit_price * (output));
    trace!(
        "We are billing for {} bytes output times a exit price of {} for a total of {}",
        output,
        exit_price,
        value
    );
    owes_exit += value;

    if owes_exit > 0 {
        info!("Total client debt of {} this round", owes_exit);
        // update the usage tracker with the details of this round's usage

        update_usage_data(UpdateUsage {
            kind: UsageType::Client,
            up: output,
            down: input,
            price: exit_dest_price as u32,
        });
    } else {
        error!("no Exit bandwidth, no bill!");
    }

    assert!(owes_exit >= 0);
    Ok(owes_exit)
}

/// Grabs the exit destination price cached in the TrafficWatcher object
/// this allows users to avoid the rather complicated procedure of computing it
/// themselves
pub struct GetExitDestPrice;

impl Message for GetExitDestPrice {
    type Result = Result<u128, Error>;
}

impl Handler<GetExitDestPrice> for TrafficWatcher {
    type Result = Result<u128, Error>;

    fn handle(&mut self, _msg: GetExitDestPrice, _: &mut Context<Self>) -> Self::Result {
        Ok(self.last_exit_dest_price)
    }
}
