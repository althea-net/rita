//! Placehodler payment manager, handles single transaction payments as well as
//! managing the retry flow for failed payment attempts. We will retry a payment
//! so long as we have not published it to a full node, once the payment is on
//! the blockchain it's up to the reciever to validate that it's correct

use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::PaymentFailed;
use crate::rita_common::oracle::trigger_update_nonce;
use crate::rita_common::payment_validator::{PaymentValidator, ToValidate, ValidateLater};
use crate::rita_common::rita_loop::get_web3_server;
use crate::SETTING;
use actix::prelude::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use actix_web::client;
use actix_web::client::Connection;
use althea_types::PaymentTx;
use clarity::Transaction;
use failure::Error;
use futures01::future::Either;
use futures01::{future, Future};
use num256::Uint256;
use settings::RitaCommonSettings;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream as TokioTcpStream;
use web30::client::Web3;

pub const TRANSACTION_SUBMISSON_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_TXID_RETRIES: u8 = 15u8;

pub struct PaymentController();

impl Actor for PaymentController {
    type Context = Context<Self>;
}
impl Supervised for PaymentController {}
impl SystemService for PaymentController {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Payment Controller started");
    }
}

#[derive(Message)]
pub struct MakePayment(pub PaymentTx);

impl Handler<MakePayment> for PaymentController {
    type Result = ();

    fn handle(&mut self, msg: MakePayment, _ctx: &mut Context<Self>) -> Self::Result {
        let res = make_payment(msg.0.clone());
        if res.is_err() {
            DebtKeeper::from_registry().do_send(PaymentFailed { to: msg.0.to });
        }
    }
}

impl Default for PaymentController {
    fn default() -> PaymentController {
        PaymentController::new()
    }
}

impl PaymentController {
    pub fn new() -> Self {
        PaymentController {}
    }
}
/// This is called by debt_keeper to make payments. It sends a
/// PaymentTx to the `mesh_ip` in its `to` field.
fn make_payment(mut pmt: PaymentTx) -> Result<(), Error> {
    let payment_settings = SETTING.get_payment();
    let balance = payment_settings.balance.clone();
    let nonce = payment_settings.nonce.clone();
    let gas_price = payment_settings.gas_price.clone();
    let our_address = payment_settings.eth_address.unwrap();
    info!(
        "current balance: {:?}, payment of {:?}, from address {} to address {} with nonce {}",
        balance, pmt.amount, our_address, pmt.to.eth_address, nonce
    );
    if balance < pmt.amount {
        warn!("Not enough money to pay debts! Cutoff immenient");
        bail!("Not enough money!")
    } else if pmt.amount == 0u32.into() {
        error!("Trying to pay nothing!");
        bail!("Zero payment!");
    }

    let contact_socket: SocketAddr = match format!(
        "[{}]:{}",
        pmt.to.mesh_ip,
        SETTING.get_network().rita_contact_port
    )
    .parse()
    {
        Ok(socket) => socket,
        Err(e) => {
            bail!("Failed to make socket for payment message! {:?}", e);
        }
    };
    let stream = TokioTcpStream::connect(&contact_socket);

    // testing hack
    let neighbor_url = if cfg!(not(test)) {
        format!(
            "http://[{}]:{}/make_payment",
            contact_socket.ip(),
            contact_socket.port(),
        )
    } else {
        String::from("http://127.0.0.1:1234/make_payment")
    };

    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSON_TIMEOUT);

    let tx = Transaction {
        nonce,
        gas_price,
        gas_limit: "21000".parse().unwrap(),
        to: pmt.to.eth_address,
        value: pmt.amount.clone(),
        data: Vec::new(),
        signature: None,
    };
    let transaction_signed = tx.sign(
        &payment_settings
            .eth_private_key
            .expect("No private key configured!"),
        payment_settings.net_version,
    );

    let transaction_bytes = match transaction_signed.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => bail!("Failed to generate transaction, {:?}", e),
    };

    let transaction_status = web3.eth_send_raw_transaction(transaction_bytes);

    let futures_chain = Box::new(stream.then(move |open_stream| match open_stream {
            Ok(open_stream) => Either::A(transaction_status.then(move |transaction_outcome| {
                match transaction_outcome {
                    Ok(tx_id) => {
                        info!("Sending bw payment with txid: {:#066x}", tx_id);
                        // add published txid to submission
                        pmt.txid = Some(tx_id.clone());
                        Either::A(
                            client::post(&neighbor_url)
                                .with_connection(Connection::from_stream(open_stream))
                                .json(&pmt)
                                .expect("Failed to serialize payment!")
                                .send()
                                .timeout(TRANSACTION_SUBMISSON_TIMEOUT)
                                .then(move |neigh_ack| match neigh_ack {
                                    Ok(msg) => {
                                        info!(
                                            "Payment with txid: {:#066x} is in the mempool with {}, using full node {} and amount {:?}",
                                            tx_id, msg.status(), full_node, pmt.amount
                                        );

                                        if !msg.status().is_success() {
                                            error!("We published txid: {:#066x} but failed to notify our neighbor, will retry", tx_id);
                                            PaymentController::from_registry().do_send(ResendTxid(ResendInfo{
                                                txid: tx_id,
                                                contact_socket,
                                                neigh_url: neighbor_url,
                                                pmt: pmt.clone(),
                                                attempt: 0u8,
                                            }));
                                        }
                                        SETTING.get_payment_mut().nonce += 1u64.into();


                                        let ts = ToValidate {
                                            payment: pmt,
                                            recieved: Instant::now(),
                                            checked: false
                                       };

                                      PaymentValidator::from_registry().do_send(ValidateLater(ts));

                                        Ok(()) as Result<(), ()>
                                    }
                                    Err(e) => {
                                        warn!("Failed to notify our neighbor of payment {:?}", e);
                                        PaymentController::from_registry().do_send(ResendTxid(ResendInfo{
                                            txid: tx_id,
                                            contact_socket,
                                            neigh_url: neighbor_url,
                                            pmt: pmt.clone(),
                                            attempt: 0u8,
                                        }));
                                        Ok(())
                                    }
                                }),
                        )
                    }

                    Err(e) => {
                        warn!(
                            "Failed to send bandwidth payment {:?}, using full node {}",
                            e, full_node
                        );

                        // triggering a nonce update may help us if the oracle modules updates
                        // are slow for some reason
                        trigger_update_nonce(our_address, &web3, full_node);

                        // we have not yet published the tx (at least hopefully)
                        // so it's safe to add this debt back to our balances
                        DebtKeeper::from_registry().do_send(PaymentFailed {
                            to: pmt.to,
                        });
                        Either::B(future::ok(()))
                    }
                }
            })),
            Err(e) => {
                // if we don't notify the neighbor they can't validate our payment
                // so if we can't talk to them we abort our payment to retry later
                warn!(
                    "Failed to connect to neighbor for bandwidth payment {:?}",
                    e
                );
                DebtKeeper::from_registry().do_send(PaymentFailed {
                    to: pmt.to,
                });
                Either::B(future::ok(()))
            }
        }));

    Arbiter::spawn(futures_chain);
    Ok(())
}

struct ResendInfo {
    txid: Uint256,
    contact_socket: SocketAddr,
    neigh_url: String,
    pmt: PaymentTx,
    attempt: u8,
}

#[derive(Message)]
struct ResendTxid(ResendInfo);

impl Handler<ResendTxid> for PaymentController {
    type Result = ();

    fn handle(&mut self, msg: ResendTxid, _ctx: &mut Context<Self>) -> Self::Result {
        resend_txid(msg.0);
    }
}

/// For some reason we have sent a payment and managed not to notify our neighbor, this routine will
/// retry up to MAX_TXID_RETIRES times
fn resend_txid(input: ResendInfo) {
    let txid = input.txid;
    let contact_socket = input.contact_socket;
    let neigh_url = input.neigh_url;
    let pmt = input.pmt;
    let attempt = input.attempt + 1;

    // at this point the chance of success is too tiny to be worth it
    if attempt > MAX_TXID_RETRIES {
        return;
    }

    let stream = TokioTcpStream::connect(&contact_socket);

    let futures_chain = Box::new(stream.then(move |open_stream| {
        match open_stream {
            Ok(open_stream) => Either::A(
                client::post(&neigh_url)
                    .with_connection(Connection::from_stream(open_stream))
                    .json(&pmt)
                    .expect("Failed to serialize payment!")
                    .send()
                    .timeout(TRANSACTION_SUBMISSON_TIMEOUT)
                    .then(move |neigh_ack| match neigh_ack {
                        Ok(msg) => {
                            if !msg.status().is_success() {
                                error!("retry failed with published txid: {:#066x}", txid);
                                PaymentController::from_registry().do_send(ResendTxid(
                                    ResendInfo {
                                        txid,
                                        contact_socket,
                                        neigh_url,
                                        pmt: pmt.clone(),
                                        attempt,
                                    },
                                ));
                            }

                            Ok(()) as Result<(), ()>
                        }
                        Err(e) => {
                            warn!("Failed to notify our neighbor of payment {:?}", e);

                            PaymentController::from_registry().do_send(ResendTxid(ResendInfo {
                                txid,
                                contact_socket,
                                neigh_url,
                                pmt: pmt.clone(),
                                attempt,
                            }));
                            Ok(())
                        }
                    }),
            ),
            Err(e) => {
                warn!(
                    "Failed to connect to neighbor for bandwidth payment {:?}",
                    e
                );

                PaymentController::from_registry().do_send(ResendTxid(ResendInfo {
                    txid,
                    contact_socket,
                    neigh_url,
                    pmt: pmt.clone(),
                    attempt,
                }));
                Either::B(future::ok(()))
            }
        }
    }));
    Arbiter::spawn(futures_chain);
}
