//! Network endptoints for common Rita functionality (such as exchanging hello messages)

use althea_types::{LocalIdentity, PaymentTx};

use actix::registry::SystemService;
use actix_web::http::StatusCode;
use actix_web::*;

use futures::{future, Future};

use futures::future::Either;

use failure::Error;

use settings::RitaCommonSettings;
use SETTING;

use std::net::SocketAddr;

use rita_common;
use rita_common::payment_controller::PaymentController;
use rita_common::peer_listener::Peer;
use rita_common::rita_loop::get_web3_server;
use rita_common::tunnel_manager::{IdentityCallback, TunnelManager};

use guac_core::web3::client::{Web3, Web3Client};

use std::boxed::Box;

#[derive(Serialize)]
pub struct JsonStatusResponse {
    response: String,
}

impl JsonStatusResponse {
    pub fn new(ret_val: Result<String, Error>) -> Result<Json<JsonStatusResponse>, Error> {
        let res_string = match ret_val {
            Ok(msg) => msg.clone(),
            Err(e) => format!("{}", e),
        };

        Ok(Json(JsonStatusResponse {
            response: res_string,
        }))
    }
}

/// The recieve side of the make payments call
pub fn make_payments(
    pmt: (Json<PaymentTx>, HttpRequest),
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    info!(
        "Got Payment from {:?} for {} with txid {:?}",
        pmt.1.connection_info().remote(),
        pmt.0.amount,
        pmt.0.txid
    );
    let full_node = get_web3_server();
    let web3 = Web3Client::new(&full_node);

    // we didn't get a txid, probably an old client.
    // why don't we need an Either up here? Because the types ultimately match?
    if pmt.0.txid.is_none() {
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::from_u16(400u16).unwrap())
                .into_builder()
                .json(format!("txid not provided! Invalid payment!")),
        ));
    }

    // check the blockchain for the hash and let the neighbor know if
    // we where able to verify the payment or if it has gone unaccounted
    // once things have gone unaccounted it will become a delta in debts
    // that will remain until both nodes are rebooted since there's no
    // convergence system yet.
    let res = web3
        .eth_get_transaction_by_hash(pmt.0.txid.clone().unwrap())
        .then(move |tx_status| match tx_status {
            // first level is our success/failure at talking to the full node
            Ok(status) => match status {
                // this level handles the actual response about the transaction
                // and checking if it's good.
                Some(transaction) => {
                    if transaction.from == pmt.0.from.eth_address
                        && transaction.value == pmt.0.amount
                        && transaction.to == SETTING.get_payment().eth_address
                    {
                        Either::A(
                            PaymentController::from_registry()
                                .send(rita_common::payment_controller::PaymentReceived(
                                    pmt.0.clone(),
                                )).from_err()
                                .and_then(|_| {
                                    Ok(HttpResponse::Ok().json("Payment Successful!").into())
                                }).responder(),
                        )
                    } else {
                        Either::B(future::ok(
                            HttpResponse::new(StatusCode::from_u16(400u16).unwrap())
                                .into_builder()
                                .json(format!("Transaction parameters invalid!")),
                        ))
                    }
                }
                None => Either::B(future::ok(
                    HttpResponse::new(StatusCode::from_u16(400u16).unwrap())
                        .into_builder()
                        .json(format!("Could not find txid on the blockchain!")),
                )),
            },
            Err(e) => {
                // full node failure, we don't actually know anything about the transaction
                warn!(
                    "Failed to validate {:?} transaction with {:?}",
                    pmt.0.from, e
                );
                Either::B(future::ok(
                    HttpResponse::new(StatusCode::from_u16(504u16).unwrap())
                        .into_builder()
                        .json(format!("Could not talk to our fullnode!")),
                ))
            }
        });
    Box::new(res)
}

pub fn hello_response(
    req: (Json<LocalIdentity>, HttpRequest),
) -> Box<Future<Item = Json<LocalIdentity>, Error = Error>> {
    let their_id = req.0.clone();

    let socket = req
        .1
        .connection_info()
        .remote()
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap();

    trace!("Got Hello from {:?}", req.1.connection_info().remote());
    trace!("opening tunnel in hello_response for {:?}", their_id);

    let peer = Peer {
        contact_socket: socket,
        ifidx: 0, // only works because we lookup ifname in kernel interface
    };

    // We send the callback, which can safely allocate a port because it already successfully
    // contacted a neighbor. The exception to this is when the TCP session fails at exactly
    // the wrong time.
    Box::new(
        TunnelManager::from_registry()
            .send(IdentityCallback::new(their_id, peer, None))
            .from_err()
            .and_then(|tunnel| {
                let tunnel = tunnel.unwrap();
                Ok(Json(LocalIdentity {
                    global: match SETTING.get_identity() {
                        Some(id) => id,
                        None => return Err(format_err!("Identity has no mesh IP ready yet").into()),
                    },
                    wg_port: tunnel.0.listen_port,
                    have_tunnel: Some(tunnel.1),
                }))
            }).responder(),
    )
}

pub fn version(_req: HttpRequest) -> String {
    format!(
        "crate ver {}\ngit hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    )
}
