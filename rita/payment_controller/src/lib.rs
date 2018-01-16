#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

#[macro_use] extern crate log;

// use std::sync::mpsc::{Receiver, Sender};

extern crate serde;
extern crate serde_json;

// extern crate althea_types;
// use althea_types::EthAddress;

extern crate debt_keeper;
use debt_keeper::Identity;

extern crate num256;
use num256::Uint256;

extern crate reqwest;
use reqwest::{Client, Response, StatusCode};

#[derive(Debug, Error)]
pub enum Error {
    HttpError(reqwest::Error),
    SerdeError(serde_json::Error),
    #[error(msg_embedded, no_from, non_std)] PaymentControllerError(String),
    #[error(msg_embedded, no_from, non_std)] PaymentSendingError(String),
}


pub struct PaymentController {
    pub client: Client,
}

#[derive(Serialize, Deserialize, Debug)]
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
    // pub fn payment_received(&self, pmt: PaymentTx) {}

    /// This is called by the other modules in Rita to make payments.
    pub fn make_payment(&self, pmt: PaymentTx) -> Result<(), Error> {
        trace!("Making payments to {:?}", pmt);
        trace!("Sending payments to http://[{}]:4876/make_payment", pmt.to.ip_address);

        let mut r = self.client
            .post(&format!("http://[{}]:4876/make_payment", pmt.to.ip_address))
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
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
