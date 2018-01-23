#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

#[macro_use] extern crate log;

// use std::sync::mpsc::{Receiver, Sender};

extern crate serde;
extern crate serde_json;

extern crate althea_types;
use althea_types::{PaymentTx, Identity};

extern crate debt_keeper;
use debt_keeper::DebtAdjustment;

extern crate num256;
use num256::Int256;

extern crate reqwest;

use reqwest::{Client, StatusCode};

use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc::{Sender, channel};

use std::net::Ipv6Addr;

#[derive(Debug, Error)]
pub enum Error {
    HttpError(reqwest::Error),
    SerdeError(serde_json::Error),
    #[error(msg_embedded, no_from, non_std)] PaymentControllerError(String),
    #[error(msg_embedded, no_from, non_std)] PaymentSendingError(String),
    #[error(msg_embedded, no_from, non_std)] BountyError(String),
}


pub struct PaymentController {
    pub client: Client,
    pub identity: Identity,
    pub balance: Int256,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct BountyUpdate {
    pub from: Identity,
    pub balance: Int256,
    pub tx: PaymentTx,
}

pub enum PaymentControllerMsg {
    PaymentReceived(PaymentTx),
    MakePayment(PaymentTx),
    StopThread
}

#[cfg(test)]
extern crate mockito;

impl PaymentController {
    pub fn start(id: &Identity, m_tx: Arc<Mutex<Sender<DebtAdjustment>>>) -> Sender<PaymentControllerMsg> {
        let mut controller = PaymentController::new(id);
        let (tx, rx) = channel();

        thread::spawn(move || {
            for msg in rx {
                match msg {
                    PaymentControllerMsg::PaymentReceived(pmt) => controller.payment_received(pmt, m_tx.clone()).unwrap(),
                    PaymentControllerMsg::MakePayment(pmt) => controller.make_payment(pmt).unwrap(),
                    PaymentControllerMsg::StopThread => return
                };
            }
        });
        tx
    }

    pub fn new(id: &Identity) -> Self {
        PaymentController {
            identity: id.clone(),
            client: Client::new(),
            balance: Int256::from(10000000000000000i64)
        }
    }

    fn update_bounty(&self, update: BountyUpdate) -> Result<(), Error> {
        let bounty_url = if cfg!(not(test)) {
            format!("http://[{}]:8888/update", "2001::3".parse::<Ipv6Addr>().unwrap())
        } else {
            String::from(mockito::SERVER_URL)
        };

        let mut r = self.client
            .post(&bounty_url) //TODO: what port do we use?, how do we get the IP for the bounty hunter?
            .body(serde_json::to_string(&update)?)
            .send()?;

        if r.status() == StatusCode::Ok {
            trace!("Successfully sent bounty hunter update");
            Ok(())
        } else {
            trace!("Unsuccessfully in sending update to bounty hunter");
            trace!("Received error from bounty hunter: {:?}", r.text().unwrap_or(String::from("No message received")));
            Err(Error::BountyError(
                String::from(format!("Received error from bounty hunter: {:?}",
                                     r.text().unwrap_or(String::from("No message received"))
                ))
            ))
        }
    }

    /// This is exposed to the Guac light client, or whatever else is
    /// being used for payments. It gets called when a payment from a counterparty
    /// has arrived, and will return if it is valid.
    pub fn payment_received(&mut self, pmt: PaymentTx, m_tx: Arc<Mutex<Sender<DebtAdjustment>>>) -> Result<(), Error> {
        trace!("Sending payment to Guac: {:?}", pmt);
        trace!("Received payment, Balance: {:?}", self.balance);
        // TODO: Pass the paymentTx to guac, get a channel summary back, reject if incorrect
        self.balance = self.balance.clone() + Int256::from(pmt.clone().amount);

        m_tx.lock().unwrap().send(
            DebtAdjustment {
                ident: pmt.from,
                amount: Int256::from(pmt.amount.clone())
            }
        ).unwrap();

        self.update_bounty(BountyUpdate{from: self.identity, tx: pmt, balance: self.balance.clone()})?;
        Ok(())
    }

    /// This is called by the other modules in Rita to make payments.
    pub fn make_payment(&mut self, pmt: PaymentTx) -> Result<(), Error> {
        trace!("Making payments to {:?}", pmt);
        trace!("Sent payment, Balance: {:?}", self.balance);
        trace!("Sending payments to http://[{}]:4876/make_payment", pmt.to.ip_address);

        let neighbour_url = if cfg!(not(test)) {
            format!("http://[{}]:4876/make_payment", pmt.to.ip_address)
        } else {
            String::from(mockito::SERVER_URL)
        };

        self.balance = self.balance.clone() - Int256::from(pmt.clone().amount);
        let mut r = self.client
            .post(&neighbour_url)
            .body(serde_json::to_string(&pmt)?)
            .send()?;

        if r.status() == StatusCode::Ok {
            trace!("Successfully paid");
            trace!("Received success from payee: {:?}", r.text().unwrap_or(String::from("No message received")));
            Ok(())
        } else {
            trace!("Unsuccessfully paid");
            trace!("Received error from payee: {:?}", r.text().unwrap_or(String::from("No message received")));
            Err(Error::PaymentSendingError(
                String::from(format!("Received error from payee: {:?}",
                                     r.text().unwrap_or(String::from("No message received"))
                ))
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate eui48;
    extern crate mockito;

    use mockito::mock;

    use super::*;

    use std::time;

    use std::collections::hash_map::DefaultHasher;
    use std::net::IpAddr;
    use std::net::Ipv6Addr;
    use std::sync::mpsc;
    use num256::Uint256;

    use althea_types::{EthAddress, PaymentTx, Identity};

    fn new_addr(x: u8) -> EthAddress {
        EthAddress([x; 20])
    }

    fn new_payment(x: u8) -> PaymentTx {
        PaymentTx{
            to: new_identity(x),
            from: new_identity(x),
            amount: Uint256::from(x)
        }
    }

    fn new_identity(x: u8) -> Identity {
        let y = x as u16;
        Identity{
            ip_address: IpAddr::V6(Ipv6Addr::new(y, y, y, y, y, y, y, y)),
            mac_address: eui48::MacAddress::new([x; 6]),
            eth_address: new_addr(x)
        }
    }

    #[test]
    fn test_thread_stop() {
        let (rita_rx, rita_tx) = mpsc::channel();

        let id = new_identity(1);
        let pc_tx = PaymentController::start(&id, Arc::new(Mutex::new(rita_rx)));

        assert!(pc_tx.send(PaymentControllerMsg::StopThread).is_ok());

        thread::sleep(time::Duration::from_millis(100));

        assert!(pc_tx.send(PaymentControllerMsg::StopThread).is_err());
    }

    #[test]
    fn test_thread_make_payment() {
        // mock neighbours
        let _m = mock("POST", "/")
            .with_status(200)
            .with_body("payment OK")
            .match_body("{\"to\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"amount\":\"1\"}")
            .create();

        let (rita_rx, rita_tx) = mpsc::channel();

        let id = new_identity(1);
        let pc_tx = PaymentController::start(&id, Arc::new(Mutex::new(rita_rx)));

        assert!(pc_tx.send(PaymentControllerMsg::MakePayment(new_payment(1))).is_ok());

        thread::sleep(time::Duration::from_millis(100));

        assert!(pc_tx.send(PaymentControllerMsg::StopThread).is_ok());

        _m.assert();
    }

    #[test]
    fn test_thread_payment_received() {
        // mock bounty hunter
        let _m = mock("POST", "/")
            .with_status(200)
            .with_body("bounty OK")
            .match_body("{\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"balance\":\"10000000000000001\",\"tx\":{\"to\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"amount\":\"1\"}}")
            .create();

        let (rita_tx, rita_rx) = mpsc::channel();

        let id = new_identity(1);
        let pc_tx = PaymentController::start(&id, Arc::new(Mutex::new(rita_tx)));

        assert!(pc_tx.send(PaymentControllerMsg::PaymentReceived(new_payment(1))).is_ok());

        thread::sleep(time::Duration::from_millis(100));

        let out = rita_rx.try_recv().unwrap();

        assert_eq!(out, DebtAdjustment {
            ident: new_identity(1),
            amount: Int256::from(1)
        });

        assert!(pc_tx.send(PaymentControllerMsg::StopThread).is_ok());
        _m.assert();
    }
}
