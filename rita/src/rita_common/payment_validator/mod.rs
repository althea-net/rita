//! This module stores txid's and other payment infromation for later validation
//! while in theory we should be able to get the transaction from a txid within a few
//! seconds experience shows that up to a minute is not unusual for a txid to spread to
//! the whole network. During times of congestion may be even worse.
//! A series of payment amounts and txid's are stored in the actor which is triggered to
//! attempt to validate these payments every 5 seconds, if successful the payment is sent
//! off to debt keeper to be removed from the owed balance. Payments may time out after a
//! configured period.

use crate::rita_common;
use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::PaymentSucceeded;
use crate::rita_common::rita_loop::get_web3_server;
use crate::rita_common::usage_tracker::UpdatePayments;
use crate::rita_common::usage_tracker::UsageTracker;
use crate::SETTING;
use ::actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use althea_types::PaymentTx;
use futures::future::Either;
use futures::{future, Future};
use num256::Uint256;
use rita_common::debt_keeper::PaymentReceived;
use settings::RitaCommonSettings;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use web3::client::Web3;
use web3::types::TransactionResponse;

// Discard payments after 15 minutes of failing to find txid
pub const PAYMENT_TIMEOUT: Duration = Duration::from_secs(900u64);
// How many blocks before we assume finality
const BLOCKS_TO_CONFIRM: u32 = 4;

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
                error!("Transaction {:?} has timed out, payment failed!", item);
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

/// Attempt to validate that a given transaction has been accepeted into the blockchain and
/// is at least some configurable number of blocks behind the head.
pub fn validate_transaction(ts: &ToValidate) {
    trace!("validating transaction");
    // we validate that a txid is present before adding to the validation list
    let txid = ts.payment.clone().txid.unwrap();
    let pmt = ts.payment.clone();
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node);

    let long_life_ts = ts.clone();

    let res = web3.eth_block_number().then(move |block| {
        match block {
            Ok(block_num) => {
                Either::A(
                    web3.eth_get_transaction_by_hash(txid.clone())
                        .then(move |tx_status| match tx_status {
                            Ok(status) => match status {
                                Some(transaction) => {
                                    handle_tx_messaging(txid, transaction, long_life_ts, block_num);
                                    Ok(())
                                }
                                None => Ok(()),
                            },
                            Err(e) => {
                                // full node failure, we don't actually know anything about the transaction
                                warn!("Failed to validate {:?} transaction with {:?}", pmt.from, e);
                                Ok(())
                            }
                        }),
                )
            }
            Err(e) => {
                // full node failure, we don't actually know anything about the transaction
                warn!("Failed to validate {:?} transaction with {:?}", pmt.from, e);
                Either::B(future::ok(()))
            }
        }
    });
    Arbiter::spawn(res);
}

/// Handles the tx response from the full node and it's various cases
/// pulled out of validate_transaction purely for cosmetic reasons
fn handle_tx_messaging(
    txid: Uint256,
    transaction: TransactionResponse,
    ts: ToValidate,
    current_block: Uint256,
) {
    let from_address = ts.payment.from.eth_address;
    let amount = ts.payment.amount.clone();
    let pmt = ts.payment.clone();
    let our_address = SETTING.get_payment().eth_address.expect("No Address!");

    let to_us = transaction.to == our_address;
    let from_us = transaction.from == our_address;
    let value_correct = transaction.value == amount;
    let is_in_chain = payment_in_chain(current_block, transaction.block_number);

    match (to_us, from_us, value_correct, is_in_chain) {
        // we where successfully paid
        (true, false, true, true) => {
            info!(
                "payment {:#066x}  from {} successfully validated!",
                txid, from_address
            );
            DebtKeeper::from_registry().do_send(PaymentReceived {
                from: pmt.from,
                amount: pmt.amount.clone(),
            });
            PaymentValidator::from_registry().do_send(Remove(ts));

            // update the usage tracker with the details of this payment
            UsageTracker::from_registry().do_send(UpdatePayments { payment: pmt });
        }
        // we suceessfully paid someone
        (false, true, true, true) => {
            info!(
                "payment {:#066x}  from {} successfully sent!",
                txid, from_address
            );
            DebtKeeper::from_registry().do_send(PaymentSucceeded {
                to: pmt.to,
                amount: pmt.amount.clone(),
            });
            PaymentValidator::from_registry().do_send(Remove(ts));

            // update the usage tracker with the details of this payment
            UsageTracker::from_registry().do_send(UpdatePayments { payment: pmt });
        }
        (true, false, false, _) => {
            error!("Transaction with invalid amount!");
            PaymentValidator::from_registry().do_send(Remove(ts));
        }
        (false, true, false, _) => {
            error!("Transaction with invalid amount!");
            PaymentValidator::from_registry().do_send(Remove(ts));
        }
        (true, true, _, _) => {
            error!("Transaction to ourselves!");
            PaymentValidator::from_registry().do_send(Remove(ts));
        }
        (false, false, _, _) => {
            error!("Transaction has nothing to do with us?");
            PaymentValidator::from_registry().do_send(Remove(ts));
        }
        (_, _, _, false) => {
            //transaction waiting for validation, do nothing
        }
    }
}

/// Determine if a given payment satisfies our criteria for being in the blockchain
fn payment_in_chain(chain_height: Uint256, tx_height: Option<Uint256>) -> bool {
    match tx_height {
        Some(tx_block) => {
            // somehow the block is newer than our block height request, wait until later
            if tx_block > chain_height {
                false
            } else {
                chain_height - tx_block >= Uint256::from(BLOCKS_TO_CONFIRM)
            }
        }
        None => false,
    }
}
