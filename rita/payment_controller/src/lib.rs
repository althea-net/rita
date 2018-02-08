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
use debt_keeper::DebtKeeperMsg;

extern crate num256;
use num256::{Uint256, Int256};

extern crate reqwest;

use reqwest::{Client, StatusCode};

use std::thread;
use std::time::Duration;
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

/// This updates a "bounty hunter" with the current balance and the last PaymentTx. 
/// Bounty hunters are servers which store and possibly enforce the current state of
/// a channel. Currently they are actually just showing a completely insecure 
/// "fake" balance as a stand-in for the real thing.
#[derive(Serialize, Deserialize, Debug)]
pub struct BountyUpdate {
    pub from: Identity,
    pub balance: Int256,
    pub tx: PaymentTx,
}

/// The actions that a `PaymentController` can take. 
pub enum PaymentControllerMsg {
    PaymentReceived(PaymentTx),
    MakePayment(PaymentTx),
    Update,
    StopThread
}

#[cfg(test)]
extern crate mockito;

impl PaymentController {
    pub fn start(id: &Identity, m_tx: Arc<Mutex<Sender<DebtKeeperMsg>>>) -> Sender<PaymentControllerMsg> {
        let mut controller = PaymentController::new(id);
        let (tx, rx) = channel();

        thread::spawn(move || {
            for msg in rx {
                match msg {
                    PaymentControllerMsg::PaymentReceived(pmt) => controller.payment_received(pmt, m_tx.clone()).unwrap(),
                    PaymentControllerMsg::MakePayment(pmt) => controller.make_payment(pmt).unwrap(),
                    PaymentControllerMsg::Update => controller.update(),
                    PaymentControllerMsg::StopThread => return
                };
            }
        });
        tx
    }

    pub fn new(id: &Identity) -> Self {
        PaymentController {
            identity: id.clone(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build().unwrap(),
            balance: Int256::from(0i64)
        }
    }

    fn update_bounty(&self, update: BountyUpdate) -> Result<(), Error> {
        trace!("Sending bounty hunter update: {:?}", update);
        let bounty_url = if cfg!(not(test)) {
            format!("http://[{}]:8888/update", "2001::3".parse::<Ipv6Addr>().unwrap())
        } else {
            String::from("http://127.0.0.1:1234/update") //TODO: This is mockito::SERVER_URL, but don't want to include the crate in a non-test build just for that string
        };

        let mut r = self.client
            .post(&bounty_url) //TODO: what port do we use?, how do we get the IP for the bounty hunter?
            .body(serde_json::to_string(&update)?)
            .send()?;

        if r.status() == StatusCode::Ok {
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

    /// This gets called when a payment from a counterparty has arrived, and updates
    /// the balance in memory and sends an update to the "bounty hunter".
    pub fn payment_received(&mut self, pmt: PaymentTx, m_tx: Arc<Mutex<Sender<DebtKeeperMsg>>>) -> Result<(), Error> {
        trace!("current balance: {:?}", self.balance);
        trace!("payment of {:?} received from {:?}: {:?}", pmt.amount, pmt.from.ip_address, pmt);

        self.balance = self.balance.clone() + Int256::from(pmt.amount.clone());

        trace!("current balance: {:?}", self.balance);

        m_tx.lock().unwrap().send(
            DebtKeeperMsg::PaymentReceived {
                from: pmt.from,
                amount: Int256::from(pmt.amount.clone())
            }
        ).unwrap();

        self.update_bounty(BountyUpdate{from: self.identity, tx: pmt, balance: self.balance.clone()})?;
        Ok(())
    }

    /// This should be called on a regular interval to update the bounty hunter of a node's current
    /// balance as well as to log the current balance
    pub fn update(&mut self) {
        self.update_bounty(BountyUpdate{
            from: self.identity, tx:
            PaymentTx{from: self.identity,
                      to: self.identity,
                      amount: Uint256::from(0u32)
            },
            balance: self.balance.clone()
        });
        info!("Balance update: {:?}", self.balance);
    }

    /// This is called by the other modules in Rita to make payments. It sends a 
    /// PaymentTx to the `ip_address` in its `to` field.
    pub fn make_payment(&mut self, pmt: PaymentTx) -> Result<(), Error> {
        trace!("current balance: {:?}", self.balance);

        trace!("sending payment of {:?} to {:?}: {:?}", pmt.amount, pmt.to.ip_address, pmt);

        let neighbor_url = if cfg!(not(test)) {
            format!("http://[{}]:4876/make_payment", pmt.to.ip_address)
        } else {
            String::from("http://127.0.0.1:1234/make_payment")
        };

        self.balance = self.balance.clone() - Int256::from(pmt.amount.clone());
        
        trace!("current balance: {:?}", self.balance);

        let mut r = self.client
            .post(&neighbor_url)
            .body(serde_json::to_string(&pmt)?)
            .send()?;

        if r.status() == StatusCode::Ok {
            self.update_bounty(BountyUpdate{from: self.identity, tx: pmt, balance: self.balance.clone()});
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
        let _m = mock("POST", "/make_payment")
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
        let _m = mock("POST", "/update")
            .with_status(200)
            .with_body("bounty OK")
            .match_body("{\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"balance\":\"1\",\"tx\":{\"to\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"amount\":\"1\"}}")
            .create();

        let (rita_tx, rita_rx) = mpsc::channel();

        let id = new_identity(1);
        let pc_tx = PaymentController::start(&id, Arc::new(Mutex::new(rita_tx)));

        assert!(pc_tx.send(PaymentControllerMsg::PaymentReceived(new_payment(1))).is_ok());

        thread::sleep(time::Duration::from_millis(100));

        let out = rita_rx.try_recv().unwrap();

        assert_eq!(out, DebtKeeperMsg::PaymentReceived {
            from: new_identity(1),
            amount: Int256::from(1)
        });

        assert!(pc_tx.send(PaymentControllerMsg::StopThread).is_ok());
        _m.assert();
    }

    #[test]
    fn test_make_payments() {
        // mock neighbor
        let _m = mock("POST", "/make_payment")
            .with_status(200)
            .with_body("payment OK")
            .match_body("{\"to\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"amount\":\"1\"}")
            .create();

        let mut pc = PaymentController::new(&new_identity(1));

        pc.make_payment(new_payment(1)).unwrap();

        assert_eq!(pc.balance, Int256::from(-1));

        _m.assert();
    }

    #[test]
    fn test_multi_make_payments() {
        // mock neighbor
        let _m = mock("POST", "/make_payment")
            .with_status(200)
            .with_body("payment OK")
            .match_body("{\"to\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"amount\":\"1\"}")
            .expect(100)
            .create();

        let mut pc = PaymentController::new(&new_identity(1));

        for _ in 0..100 {
            pc.make_payment(new_payment(1)).unwrap();
        }

        assert_eq!(pc.balance, Int256::from(-100));

        _m.assert();
    }

    #[test]
    fn test_single_payment_received() {
        // mock bounty hunter
        let _m = mock("POST", "/update")
            .with_status(200)
            .with_body("bounty OK")
            .match_body("{\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"balance\":\"1\",\"tx\":{\"to\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"from\":{\"ip_address\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0101010101010101010101010101010101010101\",\"mac_address\":\"01-01-01-01-01-01\"},\"amount\":\"1\"}}")
            .create();

        let (rita_tx, rita_rx) = mpsc::channel();

        let mut pc = PaymentController::new(&new_identity(1));

        pc.payment_received(new_payment(1), Arc::new(Mutex::new(rita_tx))).unwrap();

        assert_eq!(pc.balance, Int256::from(1));

        let out = rita_rx.try_recv().unwrap();

        assert_eq!(out, DebtKeeperMsg::PaymentReceived {
            from: new_identity(1),
            amount: Int256::from(1)
        });

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

        let (rita_tx, rita_rx) = mpsc::channel();

        let mut pc = PaymentController::new(&new_identity(1));

        for _ in 0..100 {
            pc.payment_received(new_payment(1), Arc::new(Mutex::new(rita_tx.clone()))).unwrap();
        }

        assert_eq!(pc.balance, Int256::from(100));

        for _ in 0..100 {
            let out = rita_rx.try_recv().unwrap();

            assert_eq!(out, DebtKeeperMsg::PaymentReceived {
                from: new_identity(1),
                amount: Int256::from(1)
            });
        }

        _m.assert();
    }
}
