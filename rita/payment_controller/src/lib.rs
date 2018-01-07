#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

use std::sync::mpsc::{Receiver, Sender};

extern crate serde;
extern crate serde_json;

extern crate althea_types;
use althea_types::EthAddress;

extern crate debt_keeper;
use debt_keeper::{Identity};

extern crate num256;
use num256::{Int256, Uint256};

extern crate reqwest;
use reqwest::Client;

#[derive(Debug, Error)]
pub enum Error {
    HttpError(reqwest::Error),
    SerdeError(serde_json::Error),
    #[error(msg_embedded, no_from, non_std)]
    PaymentControllerError(String),
}


pub struct PaymentController {
    pub client: Client,
}

#[derive(Serialize, Deserialize)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}

impl PaymentController {
    pub fn new() -> Self {
        PaymentController {
            client: Client::new(),
        }
    }
    /// This is exposed to the Guac light client, or whatever else is
    /// being used for payments. It gets called when a payment from a counterparty
    /// has arrived.
    pub fn payment_received(&self, pmt: PaymentTx) {}

    /// This is called by the other modules in Rita to make payments.
    pub fn make_payment(&self, pmt: PaymentTx) -> Result<(), Error> {
        self.client
            .get(&format!("http://{}/payments", pmt.to.ip_address))
            .body(serde_json::to_string(&pmt)?)
            .send()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
