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

#[derive(Message)]
pub struct PaymentControllerUpdate;

impl Handler<PaymentControllerUpdate> for PaymentController {
    type Result = ();

    fn handle(&mut self, _msg: PaymentControllerUpdate, _ctx: &mut Context<Self>) -> Self::Result {
        match self.update() {
            Ok(()) => {}
            Err(err) => {
                warn!("got error from update {:?}, retrying", err);
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

/// This updates a "bounty hunter" with the current balance and the last `PaymentTx`.
/// Bounty hunters are servers which store and possibly enforce the current state of
/// a channel. Currently they are actually just showing a completely insecure
/// "fake" balance as a stand-in for the real thing.
#[derive(Serialize, Deserialize, Debug)]
pub struct BountyUpdate {
    pub from: Identity,
    pub balance: Int256,
    pub tx: PaymentTx,
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

    fn update_bounty_actual(&self, update: BountyUpdate) -> Result<(), Error> {
        trace!("Sending bounty hunter update: {:?}", update);
        let bounty_url = if cfg!(not(test)) {
            format!(
                "http://[{}]:{}/update",
                SETTING.get_network().bounty_ip,
                SETTING.get_network().bounty_port
            )
        } else {
            String::from("http://127.0.0.1:1234/update") //TODO: This is mockito::SERVER_URL, but don't want to include the crate in a non-test build just for that string
        };

        let mut r = self
            .reqwest_client
            .post(&bounty_url)
            .body(serde_json::to_string(&update)?)
            .send()?;

        if r.status() == StatusCode::OK {
            Ok(())
        } else {
            trace!("Unsuccessfully in sending update to bounty hunter");
            trace!(
                "Received error from bounty hunter: {:?}",
                r.text().unwrap_or(String::from("No message received"))
            );
            Err(Error::from(PaymentControllerError::BountyError(
                String::from(format!(
                    "Received error from bounty hunter: {:?}",
                    r.text().unwrap_or(String::from("No message received"))
                )),
            )))
        }
    }

    fn update_bounty(&self, update: BountyUpdate) -> Result<(), Error> {
        match self.update_bounty_actual(update) {
            Ok(()) => {}
            Err(err) => warn!("Bounty hunter returned error {:?}, ignoring", err),
        };
        Ok(())
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

        self.update_bounty(BountyUpdate {
            from: SETTING
                .get_identity()
                .ok_or(format_err!("No mesh IP available for Identity yet"))?,
            tx: pmt.clone(),
            balance: self.balance.clone().into(),
        })?;
        Ok(debt_keeper::PaymentReceived {
            from: pmt.from,
            amount: pmt.amount.clone(),
        })
    }

    /// This should be called on a regular interval to update the bounty hunter of a node's current
    /// balance as well as to log the current balance
    pub fn update(&mut self) -> Result<(), Error> {
        let our_id = SETTING
            .get_identity()
            .ok_or(format_err!("No mesh IP available for Identity yet"))?;
        self.update_bounty(BountyUpdate {
            from: our_id.clone(),
            tx: PaymentTx {
                from: our_id.clone(),
                to: our_id.clone(),
                amount: Uint256::from(0u32),
            },
            balance: self.balance.clone().into(),
        })?;
        info!("Balance update: {:?}", self.balance);
        Ok(())
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

            self.update_bounty(BountyUpdate {
                from: SETTING
                    .get_identity()
                    .ok_or(format_err!("No mesh IP available for Identity yet"))?,
                tx: pmt,
                balance: self.balance.clone().into(),
            })?;
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
