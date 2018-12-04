//! Placehodler payment manager, to be removed with Gauc integration

use actix::prelude::*;
use actix_web::client;

use futures::future::Either;
use futures::{future, Future};

use althea_types::PaymentTx;

use clarity::Transaction;

use settings::RitaCommonSettings;
use SETTING;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;
use rita_common::debt_keeper::PaymentFailed;
use rita_common::rita_loop::get_web3_server;

use guac_core::web3::client::{Web3, Web3Client};

use failure::Error;

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

#[cfg(test)]
extern crate mockito;

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
    pub fn make_payment(&mut self, pmt: PaymentTx) -> Result<(), Error> {
        let payment_settings = SETTING.get_payment();
        let balance = payment_settings.balance.clone();
        let nonce = payment_settings.nonce.clone();
        let gas_price = payment_settings.gas_price.clone();
        info!(
            "current balance: {:?}, payment of {:?}, from address {:#x} to address {:#x}",
            balance,
            pmt.amount,
            payment_settings.eth_address,
            pmt.to.eth_address.clone()
        );
        if balance < pmt.amount {
            warn!("Not enough money to pay debts! Cutoff immenient");
            bail!("Not enough money!")
        }

        // testing hack
        let neighbor_url = if cfg!(not(test)) {
            format!(
                "http://[{}]:{}/make_payment",
                pmt.to.mesh_ip,
                SETTING.get_network().rita_contact_port
            )
        } else {
            String::from("http://127.0.0.1:1234/make_payment")
        };

        let full_node = get_web3_server();
        let web3 = Web3Client::new(&full_node);

        let tx = Transaction {
            nonce: nonce,
            gas_price: gas_price,
            gas_limit: "21000".parse().unwrap(),
            to: pmt.to.eth_address.clone(),
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

        let futures_chain = Box::new(transaction_status.then(move |outcome| {
            match outcome {
                Ok(_tx_id) => {
                    Either::A(
                        client::post(&neighbor_url)
                            .json(&pmt)
                            .expect("Failed to serialize payment!")
                            .send()
                            .then(|neigh_ack| match neigh_ack {
                                // return emtpy result, we're using messages anyways
                                Ok(_) => {
                                    SETTING.get_payment_mut().nonce += 1;
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
                    warn!("Failed to send bandwidth payment {:?}", e);
                    DebtKeeper::from_registry().do_send(PaymentFailed {
                        to: pmt.to,
                        amount: pmt.amount,
                    });
                    Either::B(future::ok(()))
                }
            }
        }));
        Arbiter::spawn(futures_chain);
        Ok(())
    }
}
