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
use futures01::future::Either;
use futures01::{future, Future};
use num256::Uint256;
use rita_common::debt_keeper::PaymentReceived;
use settings::RitaCommonSettings;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use web30::client::Web3;
use web30::types::TransactionResponse;

// How long we will wait for full node responses, set to a much more conservative
// value on the client to prevent memory usage growth, but on the server we experience
// far less dynamic network conditions and it's far more important that we validate payments
// even at the cost of memory or the risk of an emergency restart if we slow down too much
#[cfg(not(feature = "server"))]
const TRANSACTION_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(4);
#[cfg(feature = "server")]
const TRANSACTION_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(60);

// Discard payments after 15 minutes of failing to find txid
pub const PAYMENT_TIMEOUT: Duration = Duration::from_secs(900u64);
// How many blocks before we assume finality
const BLOCKS_TO_CONFIRM: u32 = 4;
// How old does a txid need to be before we don't accept it?
// this is 12 hours
const BLOCKS_TO_OLD: u32 = 1440;

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct ToValidate {
    pub payment: PaymentTx,
    pub recieved: Instant,
}

pub struct PaymentValidator {
    unvalidated_transactions: HashSet<ToValidate>,
    successful_transactions: HashSet<Uint256>,
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
            successful_transactions: HashSet::new(),
        }
    }
}

impl Default for PaymentValidator {
    fn default() -> PaymentValidator {
        PaymentValidator::new()
    }
}

/// Message to insert transactions into payment validator, once inserted they will remain
/// until they are validated, dropped for validity issues, or time out without being inserted
/// into the blockchain. Transactions that are too old are prevented from being played back
/// by using a history of successful transactions.
/// This endpoint specifically (and only this one) is fully imdepotent so that we can retry
/// txid transmissions
#[derive(Message)]
pub struct ValidateLater(pub ToValidate);

impl Handler<ValidateLater> for PaymentValidator {
    type Result = ();

    fn handle(&mut self, msg: ValidateLater, _ctx: &mut Context<Self>) -> Self::Result {
        let ts = msg.0;
        if let Some(txid) = ts.payment.txid.clone() {
            if !self.successful_transactions.contains(&txid) {
                // insert is safe to run multiple times just so long as we check successful tx's for duplicates
                self.unvalidated_transactions.insert(ts);
            }
        } else {
            error!(
                "Someone tried to insert an unpublished transaction to validate!? {:?}",
                ts
            );
        }
    }
}

#[derive(Message)]
pub struct Remove {
    tx: ToValidate,
    success: bool,
}

impl Handler<Remove> for PaymentValidator {
    type Result = ();

    fn handle(&mut self, msg: Remove, _ctx: &mut Context<Self>) -> Self::Result {
        self.unvalidated_transactions.remove(&msg.tx);
        // store successful transactions so that they can't be played back to us, at least
        // during this session
        if msg.success {
            self.successful_transactions
                .insert(msg.tx.payment.txid.unwrap());
        }
    }
}

#[derive(Message)]
pub struct Validate();

impl Handler<Validate> for PaymentValidator {
    type Result = ();

    fn handle(&mut self, _msg: Validate, _ctx: &mut Context<Self>) -> Self::Result {
        info!(
            "Attempting to validate {} transactions",
            self.unvalidated_transactions.len()
        );
        let mut to_delete = Vec::new();
        for item in self.unvalidated_transactions.iter() {
            if item.recieved.elapsed() > PAYMENT_TIMEOUT {
                error!(
                    "Transaction {:#066x} has timed out, payment failed!",
                    item.payment.txid.clone().unwrap()
                );
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
    let web3 = Web3::new(&full_node, TRANSACTION_VERIFICATION_TIMEOUT);

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
                                warn!(
                                    "Failed to validate {:#066x} transaction with {:?}",
                                    pmt.txid.unwrap(),
                                    e
                                );
                                Ok(())
                            }
                        }),
                )
            }
            Err(e) => {
                // full node failure, we don't actually know anything about the transaction
                warn!(
                    "Failed to get blocknum to validate {:#066x} transaction with {:?}",
                    pmt.txid.unwrap(),
                    e
                );
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
    let is_in_chain = payment_in_chain(current_block.clone(), transaction.block_number.clone());
    let is_old = payment_is_old(current_block, transaction.block_number);

    if !value_correct {
        error!("Transaction with invalid amount!");
        PaymentValidator::from_registry().do_send(Remove {
            tx: ts,
            success: false,
        });
        return;
    }

    if is_old {
        error!("Transaction is more than 6 hours old! {:#066x}", txid);
        PaymentValidator::from_registry().do_send(Remove {
            tx: ts,
            success: false,
        });
        return;
    }

    match (to_us, from_us, is_in_chain) {
        // we where successfully paid
        (true, false, true) => {
            info!(
                "payment {:#066x}  from {} successfully validated!",
                txid, from_address
            );
            DebtKeeper::from_registry().do_send(PaymentReceived {
                from: pmt.from,
                amount: pmt.amount.clone(),
            });
            PaymentValidator::from_registry().do_send(Remove {
                tx: ts,
                success: true,
            });

            // update the usage tracker with the details of this payment
            UsageTracker::from_registry().do_send(UpdatePayments { payment: pmt });
        }
        // we suceessfully paid someone
        (false, true, true) => {
            info!(
                "payment {:#066x}  from {} successfully sent!",
                txid, from_address
            );
            DebtKeeper::from_registry().do_send(PaymentSucceeded {
                to: pmt.to,
                amount: pmt.amount.clone(),
            });
            PaymentValidator::from_registry().do_send(Remove {
                tx: ts,
                success: true,
            });

            // update the usage tracker with the details of this payment
            UsageTracker::from_registry().do_send(UpdatePayments { payment: pmt });
        }
        (true, true, _) => {
            error!("Transaction to ourselves!");
            PaymentValidator::from_registry().do_send(Remove {
                tx: ts,
                success: false,
            });
        }
        (false, false, _) => {
            error!("Transaction has nothing to do with us?");
            PaymentValidator::from_registry().do_send(Remove {
                tx: ts,
                success: false,
            });
        }
        (_, _, false) => {
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

/// Determine if a given payment is older than what we shoul accept
fn payment_is_old(chain_height: Uint256, tx_height: Option<Uint256>) -> bool {
    match tx_height {
        Some(tx_block) => {
            // somehow the block is newer than our block height request, wait until later
            if tx_block > chain_height {
                false
            } else {
                chain_height - tx_block > Uint256::from(BLOCKS_TO_OLD)
            }
        }
        None => false,
    }
}
