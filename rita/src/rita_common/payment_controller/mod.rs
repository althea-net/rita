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
    pub client: Client,
    pub identity: Identity,
    pub balance: Int256,
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

    fn handle(&mut self, msg: MakePayment, ctx: &mut Context<Self>) -> Self::Result {
        match self.make_payment(msg.clone().0) {
            Ok(()) => {}
            Err(err) => {
                warn!("got error from make payment {:?}, retrying", err);
                ctx.notify_later(msg, Duration::from_secs(5));
            }
        }
    }
}

#[derive(Message)]
pub struct PaymentControllerUpdate;

impl Handler<PaymentControllerUpdate> for PaymentController {
    type Result = ();

    fn handle(&mut self, msg: PaymentControllerUpdate, ctx: &mut Context<Self>) -> Self::Result {
        match self.update() {
            Ok(()) => {}
            Err(err) => {
                warn!("got error from update {:?}, retrying", err);
                ctx.notify_later(msg, Duration::from_secs(5));
            }
        }
    }
}

pub struct GetOwnBalance;

impl Message for GetOwnBalance {
    type Result = Result<i64, Error>;
}

impl Handler<GetOwnBalance> for PaymentController {
    type Result = Result<i64, Error>;
    fn handle(&mut self, _msg: GetOwnBalance, _: &mut Context<Self>) -> Self::Result {
        Ok(self.balance.clone().into())
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
        PaymentController::new(&SETTING.get_identity())
    }
}

impl PaymentController {
    pub fn new(id: &Identity) -> Self {
        PaymentController {
            identity: id.clone(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            balance: Int256::from(0i64),
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
            .client
            .post(&bounty_url)
            .body(serde_json::to_string(&update)?)
            .send()?;

        if r.status() == StatusCode::Ok {
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
            from: self.identity.clone(),
            tx: pmt.clone(),
            balance: self.balance.clone(),
        })?;
        Ok(debt_keeper::PaymentReceived {
            from: pmt.from,
            amount: pmt.amount.clone(),
        })
    }

    /// This should be called on a regular interval to update the bounty hunter of a node's current
    /// balance as well as to log the current balance
    pub fn update(&mut self) -> Result<(), Error> {
        self.update_bounty(BountyUpdate {
            from: self.identity.clone(),
            tx: PaymentTx {
                from: self.identity.clone(),
                to: self.identity.clone(),
                amount: Uint256::from(0u32),
            },
            balance: self.balance.clone(),
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
                SETTING.get_network().rita_hello_port
            )
        } else {
            String::from("http://127.0.0.1:1234/make_payment")
        };

        trace!("current balance: {:?}", self.balance);

        let mut r = self.client.post(&neighbor_url).json(&pmt).send()?;

        if r.status() == StatusCode::Ok {
            self.balance = self.balance.clone() - Int256::from(pmt.amount.clone());
            self.update_bounty(BountyUpdate {
                from: self.identity.clone(),
                tx: pmt,
                balance: self.balance.clone(),
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

#[cfg(test)]
mod tests {
    extern crate eui48;
    extern crate mockito;

    use self::mockito::mock;

    use super::*;

    use num256::Uint256;
    use std::net::IpAddr;
    use std::net::Ipv6Addr;

    use althea_types::{EthAddress, Identity, PaymentTx};

    fn new_addr(x: u8) -> EthAddress {
        EthAddress([x; 20])
    }

    fn new_payment(x: u8) -> PaymentTx {
        PaymentTx {
            to: new_identity(x),
            from: new_identity(x),
            amount: Uint256::from(x),
        }
    }

    fn new_identity(x: u8) -> Identity {
        let y = x as u16;
        Identity {
            mesh_ip: IpAddr::V6(Ipv6Addr::new(y, y, y, y, y, y, y, y)),
            wg_public_key: String::from("AAAAAAAAAAAAAAAAAAAA"),
            eth_address: new_addr(x),
        }
    }

    #[test]
    fn test_make_payments() {
        // mock neighbor
        let _m = mock("POST", "/make_payment")
            .with_status(200)
            .with_body("payment OK")
            .match_body("{\"to\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"from\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"amount\":\"1\"}")
            .create();

        // mock bounty hunter
        let __m = mock("POST", "/update")
            .with_status(200)
            .with_body("bounty OK")
            .match_body("{\"from\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\
            \"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"balance\":\"-1\",\"tx\":{\"to\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"from\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"amount\":\"1\"}}")
            .create();

        let mut pc = PaymentController::new(&new_identity(1));

        let _ = pc.make_payment(new_payment(1));

        assert_eq!(pc.balance, Int256::from(-1));

        _m.assert();
        __m.assert();
    }

    #[test]
    fn test_multi_make_payments() {
        // mock neighbor
        let _m = mock("POST", "/make_payment")
            .with_status(200)
            .with_body("payment OK")
            .match_body("{\"to\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"from\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"amount\":\"1\"}")
            .expect(100)
            .create();

        // mock bounty hunter
        let __m = mock("POST", "/update")
            .with_status(200)
            .with_body("bounty OK")
            .expect(100)
            .create();

        let mut pc = PaymentController::new(&new_identity(1));

        for _ in 0..100 {
            pc.make_payment(new_payment(1)).unwrap();
        }

        assert_eq!(pc.balance, Int256::from(-100));

        _m.assert();
        __m.assert();
    }

    #[test]
    fn test_single_payment_received() {
        // mock bounty hunter
        let _m = mock("POST", "/update")
            .with_status(200)
            .with_body("bounty OK")
            .match_body("{\"from\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"balance\":\"1\",\"tx\":{\"to\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"from\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"amount\":\"1\"}}")
            .create();

        let mut pc = PaymentController::new(&new_identity(1));

        let out = pc.payment_received(new_payment(1)).unwrap();

        assert_eq!(pc.balance, Int256::from(1));

        assert_eq!(
            out,
            debt_keeper::PaymentReceived {
                from: new_identity(1),
                amount: Uint256::from(1),
            }
        );

        _m.assert();
    }

    #[test]
    fn test_multi_payment_received() {
        // mock bounty hunter
        let _m = mock("POST", "/update")
            .with_status(200)
            .with_body("bounty OK")
            .expect(100)
            .create();

        let mut pc = PaymentController::new(&new_identity(1));

        for i in 0..100 {
            let out = pc.payment_received(new_payment(1)).unwrap();
            assert_eq!(pc.balance, Int256::from(i + 1));
            assert_eq!(
                out,
                debt_keeper::PaymentReceived {
                    from: new_identity(1),
                    amount: Uint256::from(1),
                }
            );
        }

        _m.assert();
    }
}
