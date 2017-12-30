extern crate althea_types;
extern crate num256;

use std::sync::mpsc::Sender;
use num256::{Int256, Uint256};
use althea_types::EthAddress;

pub struct PaymentController {
    sender: Sender<(EthAddress, Uint256)>,
}

impl PaymentController {
    /// This is exposed to the Guac light client, or whatever else is
    /// being used for payments. It gets called when a payment from a counterparty
    /// has arrived.
    fn payment_received(from: EthAddress, amt: Uint256) {}

    /// This is called by the other modules in Rita to make payments.
    fn make_payment(to: EthAddress, amt: Uint256) {}
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
