#[macro_use]
extern crate serde_derive;

extern crate althea_types;
extern crate debt_keeper;
use debt_keeper::Identity;

extern crate num256;
extern crate reqwest;

extern crate serde;
extern crate serde_json;

use std::sync::mpsc::{Receiver, Sender};
use num256::{Int256, Uint256};
use debt_keeper::Key;
use althea_types::EthAddress;
use reqwest::Client;

pub struct PaymentController {
    pub debt_keeper_input: Sender<(Key, Int256)>,
    pub client: Client,
}

#[derive(Serialize, Deserialize)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}

impl PaymentController {
    /// This is exposed to the Guac light client, or whatever else is
    /// being used for payments. It gets called when a payment from a counterparty
    /// has arrived.
    fn payment_received(&self, pmt: Payment) {}

    /// This is called by the other modules in Rita to make payments.
    fn make_payment(&self, pmt: PaymentTx) {
        self.client
            .get(pmt)
            .body(serde_json::to_string(&pmt).unwrap())
            .send()
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
