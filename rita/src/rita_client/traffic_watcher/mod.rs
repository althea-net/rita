//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ip counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.
//!
//! This is the client specific billing code used to determine how exits should be compensted. Which is
//! different in that mesh nodes are paid by forwarding traffic, but exits have to return traffic and
//! must get paid for doing so.

use crate::rita_common::debt_keeper::{DebtKeeper, Traffic, TrafficReplace};
use crate::SETTING;
use ::actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use actix_web::client;
use actix_web::client::Connection;
use actix_web::HttpMessage;
use althea_types::Identity;
use failure::Error;
use futures::future::ok as future_ok;
use futures::future::Future;
use num256::Int256;
use settings::RitaCommonSettings;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream as TokioTcpStream;

pub struct TrafficWatcher {}

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}
impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Client traffic watcher started");
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {}
    }
}

/// Used to request what the exits thinks this clients debts are. We will compare
/// this value to our own computation and alert to any large discrepencies, but in
/// general we have to trust the exit. In a pay per forward system nodes within the
/// network have either two states, properly paid, or in the face of packet loss or
/// network issues, overpaid. Because packet loss presents as the sending node having
/// a higher total packets sent count than the receiving node. Resulting in what looks
/// like overpayment on the receiving end. For client traffic though this does not apply
/// the client is paying for the exit to send it download traffic. So if packets are lost
/// on the way the client will never know the full price the exit has to pay. This call
/// resolves that issue by communicating about debts with the exit.
///
/// This request is made against the exits internal ip address to ensure that upstream
/// nodes can't spoof it.
pub struct QueryExitDebts {
    pub exit_internal_addr: IpAddr,
    pub exit_port: u16,
    pub exit_id: Identity,
}

impl Message for QueryExitDebts {
    type Result = Result<(), Error>;
}

impl Handler<QueryExitDebts> for TrafficWatcher {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: QueryExitDebts, _: &mut Context<Self>) -> Self::Result {
        trace!("About to query the exit for client debts");

        let start = Instant::now();
        let exit_addr = msg.exit_internal_addr;
        let exit_id = msg.exit_id;
        let exit_port = msg.exit_port;
        // actix client behaves badly if you build a request the default way but don't give it
        // a domain name, so in order to do peer to peer requests we use with_connection and our own
        // socket speficification
        let our_id = SETTING.get_identity();
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
                                    if debt >= Int256::from(0) {
                                        let exit_replace = TrafficReplace {
                                            traffic: Traffic {
                                                from: exit_id,
                                                amount: debt,
                                            },
                                        };

                                        DebtKeeper::from_registry().do_send(exit_replace);
                                    } else {
                                        error!("The exit owes us? That shouldn't be possible!");
                                    }
                                }
                                Err(e) => {
                                    error!("Failed deserializing exit debts update with {:?}", e)
                                }
                            }
                            Ok(()) as Result<(), ()>
                        })),
                        Err(e) => {
                            trace!("Exit debts request to {} failed with {:?}", request, e);
                            Box::new(future_ok(())) as Box<dyn Future<Item = (), Error = ()>>
                        }
                    }),
            ),

            Err(e) => {
                error!(
                    "Failed to open stream to exit for debts update! with {:?}",
                    e
                );
                Box::new(future_ok(())) as Box<dyn Future<Item = (), Error = ()>>
            }
        });
        Arbiter::spawn(s);
        Ok(())
    }
}
