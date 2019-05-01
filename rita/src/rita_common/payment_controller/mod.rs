//! Placehodler payment manager, handles single transaction payments as well as
//! managing the retry flow for failed payment attempts. We will retry a payment
//! so long as we have not published it to a full node, once the payment is on
//! the blockchain it's up to the reciever to validate that it's correct

use crate::rita_common::debt_keeper;
use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::PaymentFailed;
use crate::rita_common::oracle::update_nonce;
use crate::rita_common::rita_loop::get_web3_server;
use crate::SETTING;
use ::actix::prelude::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use ::actix_web::client;
use ::actix_web::client::Connection;
use althea_types::PaymentTx;
use clarity::Transaction;
use failure::Error;
use futures::future::Either;
use futures::{future, Future};
use settings::RitaCommonSettings;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;
use web3::client::Web3;

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
pub struct PaymentReceived(pub PaymentTx);

impl Handler<PaymentReceived> for PaymentController {
    type Result = ();

    fn handle(&mut self, msg: PaymentReceived, _: &mut Context<Self>) -> Self::Result {
        DebtKeeper::from_registry().do_send(self.payment_received(msg.0).unwrap());
    }
}

#[derive(Message)]
pub struct MakePayment(pub PaymentTx);

impl Handler<MakePayment> for PaymentController {
    type Result = ();

    fn handle(&mut self, msg: MakePayment, _ctx: &mut Context<Self>) -> Self::Result {
        let res = self.make_payment(msg.0.clone());
        if res.is_err() {
            DebtKeeper::from_registry().do_send(PaymentFailed {
                to: msg.0.to,
                amount: msg.0.amount,
            });
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

    /// This gets called when a payment from a counterparty has arrived, and updates
    /// the balance in memory and sends an update to the "bounty hunter".
    pub fn payment_received(
        &mut self,
        pmt: PaymentTx,
    ) -> Result<debt_keeper::PaymentReceived, Error> {
        trace!(
            "payment of {:?} received from {:?}: {:?}",
            pmt.amount,
            pmt.from.mesh_ip,
            pmt
        );

        Ok(debt_keeper::PaymentReceived {
            from: pmt.from,
            amount: pmt.amount.clone(),
        })
    }

    /// This is called by the other modules in Rita to make payments. It sends a
    /// PaymentTx to the `mesh_ip` in its `to` field.
    pub fn make_payment(&mut self, mut pmt: PaymentTx) -> Result<(), Error> {
        let payment_settings = SETTING.get_payment();
        let balance = payment_settings.balance.clone();
        let nonce = payment_settings.nonce.clone();
        let gas_price = payment_settings.gas_price.clone();
        let our_address = payment_settings.eth_address.unwrap();
        info!(
            "current balance: {:?}, payment of {:?}, from address {:#x} to address {:#x} with nonce {}",
            balance,
            pmt.amount,
            our_address,
            pmt.to.eth_address,
            nonce
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
        let web3 = Web3::new(&full_node);

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
                                .timeout(Duration::from_secs(4))
                                .then(move |neigh_ack| match neigh_ack {
                                    // return emtpy result, we're using messages anyways
                                    Ok(msg) => {
                                        info!(
                                            "Payment with txid: {:#066x} successful with {:?}, using full node {} and amount {:?}",
                                            tx_id, msg, full_node, pmt.amount
                                        );
                                        SETTING.get_payment_mut().nonce += 1u64.into();
                                        Ok(()) as Result<(), ()>
                                    }
                                    Err(e) => {
                                        warn!("Failed to notify our neighbor of payment {:?}", e);
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

                        // Previously we updated our nonce constantly, but this lead to issues
                        // where rapid payments would often happen and always fail due to nonce
                        // issues, you can't just check the error message and try incrementing
                        // because by the time you're back here it's been reset by the oracle 
                        // so now we only update nonces when we get an error, otherwise it should
                        // remain internally consistent and correct
                        update_nonce(our_address, &web3);

                        DebtKeeper::from_registry().do_send(PaymentFailed {
                            to: pmt.to,
                            amount: pmt.amount,
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
                    amount: pmt.amount,
                });
                Either::B(future::ok(()))
            }
        }));

        Arbiter::spawn(futures_chain);
        Ok(())
    }
}
