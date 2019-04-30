//! This module stores txid's and other payment infromation for later validation
//! while in theory we should be able to get the transaction from a txid within a few
//! seconds experience shows that up to a minute is not unusual for a txid to spread to
//! the whole network. During times of congestion may be even worse.
//! A series of payment amounts and txid's are stored in the actor which is triggered to
//! attempt to validate these payments every 5 seconds, if successful the payment is sent
//! off to debt keeper to be removed from the owed balance. Payments may time out after a
//! configured period.

use ::actix::prelude::*;

use althea_types::PaymentTx;

use std::time::{Duration, Instant};

use web3::client::Web3;

use settings::RitaCommonSettings;

use crate::rita_common;
use crate::rita_common::payment_controller::PaymentController;
use crate::rita_common::rita_loop::get_web3_server;

use std::collections::HashSet;

use futures::Future;

use crate::SETTING;

// Discard payments after 30 minutes of failing to find txid
const PAYMENT_TIMEOUT: Duration = Duration::from_secs(1800u64);

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct ToValidate {
    pub payment: PaymentTx,
    pub recieved: Instant,
}

pub struct PaymentValidator {
    unvalidated_transactions: HashSet<ToValidate>,
}

impl Actor for PaymentValidator {
    type Context = Context<Self>;
}

impl Supervised for PaymentValidator {}
impl SystemService for PaymentValidator {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Payment Validator started");
    }
}

impl PaymentValidator {
    pub fn new() -> Self {
        PaymentValidator {
            unvalidated_transactions: HashSet::new(),
        }
    }
}

impl Default for PaymentValidator {
    fn default() -> PaymentValidator {
        PaymentValidator::new()
    }
}

#[derive(Message)]
pub struct ValidateLater(pub ToValidate);

impl Handler<ValidateLater> for PaymentValidator {
    type Result = ();

    fn handle(&mut self, msg: ValidateLater, _ctx: &mut Context<Self>) -> Self::Result {
        self.unvalidated_transactions.insert(msg.0);
    }
}

#[derive(Message)]
pub struct Remove(pub ToValidate);

impl Handler<Remove> for PaymentValidator {
    type Result = ();

    fn handle(&mut self, msg: Remove, _ctx: &mut Context<Self>) -> Self::Result {
        self.unvalidated_transactions.remove(&msg.0);
    }
}

#[derive(Message)]
pub struct Validate();

impl Handler<Validate> for PaymentValidator {
    type Result = ();

    fn handle(&mut self, _msg: Validate, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(
            "Attempting to validate {} transactions",
            self.unvalidated_transactions.len()
        );
        let mut to_delete = Vec::new();
        for item in self.unvalidated_transactions.iter() {
            if item.recieved.elapsed() > PAYMENT_TIMEOUT {
                trace!("Transaction {:?} has timed out, payment failed!", item);
                to_delete.push(item.clone());
            } else {
                validate_transaction(item);
            }
        }

        for item in to_delete.iter() {
            self.unvalidated_transactions.remove(item);
        }
    }
}

pub fn validate_transaction(ts: &ToValidate) {
    trace!("validating transaction");
    // we validate that a txid is present before adding to the validation list
    let txid = ts.payment.clone().txid.unwrap();
    let from_address = ts.payment.from.eth_address;
    let amount = ts.payment.amount.clone();
    let pmt = ts.payment.clone();
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node);
    let our_address = SETTING.get_payment().eth_address.expect("No Address!");

    let long_life_ts = ts.clone();

    let res =
        web3.eth_get_transaction_by_hash(txid.clone())
            .then(move |tx_status| match tx_status {
                // first level is our success/failure at talking to the full node
                Ok(status) => match status {
                    // this level handles the actual response about the transaction
                    // and checking if it's good.
                    Some(transaction) => {
                        if transaction.from == from_address
                            && transaction.value == amount
                            && transaction.to == our_address
                        {
                            if transaction.block_number.is_some() {
                                info!(
                                    "payment {:#066x}  from {} successfully validated!",
                                    txid, from_address
                                );
                                PaymentController::from_registry()
                                    .do_send(rita_common::payment_controller::PaymentReceived(pmt));
                                PaymentValidator::from_registry().do_send(Remove(long_life_ts));
                            } else {
                                trace!("transaction is vaild but not in a block yet");
                            }
                            Ok(())
                        } else {
                            trace!("payment failed, transaction invalid");
                            PaymentValidator::from_registry().do_send(Remove(long_life_ts));
                            Ok(())
                        }
                    }
                    None => Ok(()),
                },
                Err(e) => {
                    // full node failure, we don't actually know anything about the transaction
                    warn!("Failed to validate {:?} transaction with {:?}", pmt.from, e);
                    Ok(())
                }
            });
    Arbiter::spawn(res);
}
