//! Placehodler payment manager, to be removed with Gauc integration

use actix::prelude::*;

use althea_types::{Identity, PaymentTx};

use num256::{Int256, Uint256};

use reqwest::{Client, StatusCode};

use std::time::Duration;

use settings::RitaCommonSettings;
use SETTING;

use reqwest;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;
use rita_common::rita_loop::get_web3_server;

use serde_json;

use failure::Error;

#[derive(Debug, Fail)]
pub enum PaymentControllerError {
    #[fail(display = "Payment Sending Error: {:?}", _0)]
    PaymentSendingError(String),
    #[fail(display = "Bounty Error: {:?}", _0)]
    BountyError(String),
}

pub struct PaymentController {
    pub reqwest_client: Client,
    pub balance: Uint256,
}

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

#[derive(Message, Clone)]
pub struct MakePayment(pub PaymentTx);

impl Handler<MakePayment> for PaymentController {
    type Result = ();

    fn handle(&mut self, msg: MakePayment, _ctx: &mut Context<Self>) -> Self::Result {
        match self.make_payment(msg.clone().0) {
            Ok(()) => {}
            Err(err) => {
                warn!("got error from make payment {:?}, retrying", err);
                // ctx.notify_later(msg, Duration::from_secs(5));
            }
        }
    }
}

pub struct UpdateBalance {
    pub balance: Uint256,
}

impl Message for UpdateBalance {
    type Result = ();
}

impl Handler<UpdateBalance> for PaymentController {
    type Result = ();
    fn handle(&mut self, msg: UpdateBalance, _: &mut Context<Self>) -> Self::Result {
        self.balance = msg.balance;
    }
}

pub struct GetOwnBalance;

impl Message for GetOwnBalance {
    type Result = Result<Uint256, Error>;
}

impl Handler<GetOwnBalance> for PaymentController {
    type Result = Result<Uint256, Error>;
    fn handle(&mut self, _msg: GetOwnBalance, _: &mut Context<Self>) -> Self::Result {
        Ok(self.balance.clone())
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
        PaymentController {
            reqwest_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            balance: Uint256::from(0u64),
        }
    }

    /// This gets called when a payment from a counterparty has arrived, and updates
    /// the balance in memory and sends an update to the "bounty hunter".
    pub fn payment_received(
        &mut self,
        pmt: PaymentTx,
    ) -> Result<debt_keeper::PaymentReceived, Error> {
        trace!("current balance: {:?}", self.balance);
        trace!(
            "payment of {:?} received from {:?}: {:?}",
            pmt.amount,
            pmt.from.mesh_ip,
            pmt
        );

        self.balance = self.balance.clone() + Int256::from(pmt.amount.clone());

        trace!("current balance: {:?}", self.balance);

        Ok(debt_keeper::PaymentReceived {
            from: pmt.from,
            amount: pmt.amount.clone(),
        })
    }

    /// This is called by the other modules in Rita to make payments. It sends a
    /// PaymentTx to the `mesh_ip` in its `to` field.
    pub fn make_payment(&mut self, pmt: PaymentTx) -> Result<(), Error> {
        trace!("current balance: {:?}", self.balance);

        trace!(
            "sending payment of {:?} to {:?}: {:?}",
            pmt.amount,
            pmt.to.mesh_ip,
            pmt
        );

        let neighbor_url = if cfg!(not(test)) {
            format!(
                "http://[{}]:{}/make_payment",
                pmt.to.mesh_ip,
                SETTING.get_network().rita_contact_port
            )
        } else {
            String::from("http://127.0.0.1:1234/make_payment")
        };

        trace!("current balance: {:?}", self.balance);

        let mut r = self.reqwest_client.post(&neighbor_url).json(&pmt).send()?;

        if r.status() == StatusCode::OK {
            let payment_amount = Uint256::from(pmt.amount.clone());
            if payment_amount < self.balance {
                self.balance = self.balance.clone() - payment_amount;
            } else {
                warn!("We're spending more money than we have!");
                self.balance = Uint256::from(0u32);
            }
            Ok(())
        } else {
            trace!("Unsuccessfully paid");
            trace!(
                "Received error from payee: {:?}",
                r.text().unwrap_or(String::from("No message received"))
            );
            Err(Error::from(PaymentControllerError::PaymentSendingError(
                String::from(format!(
                    "Received error from payee: {:?}",
                    r.text().unwrap_or(String::from("No message received"))
                )),
            )))
        }
    }
}
