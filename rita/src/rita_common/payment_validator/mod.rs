//! This module stores txid's and other payment infromation for later validation
//! while in theory we should be able to get the transaction from a txid within a few
//! seconds experience shows that up to a minute is not unusual for a txid to spread to
//! the whole network. During times of congestion may be even worse.
//! A series of payment amounts and txid's are stored in the actor which is triggered to
//! attempt to validate these payments every 5 seconds, if successful the payment is sent
//! off to debt keeper to be removed from the owed balance. Payments may time out after a
//! configured period.

use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::PaymentReceived;
use crate::rita_common::debt_keeper::PaymentSucceeded;
use crate::rita_common::rita_loop::fast_loop::FAST_LOOP_TIMEOUT;
use crate::rita_common::rita_loop::get_web3_server;
use crate::rita_common::usage_tracker::UpdatePayments;
use crate::rita_common::usage_tracker::UsageTracker;
use crate::SETTING;
use actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use althea_types::PaymentTx;
use failure::Error;
use futures01::Future;
use num256::Uint256;
use settings::RitaCommonSettings;
use std::collections::HashSet;
use std::fmt;
use std::time::{Duration, Instant};
use tokio::util::FutureExt;
use web30::client::Web3;
use web30::types::TransactionResponse;

pub const TRANSACTION_VERIFICATION_TIMEOUT: Duration = FAST_LOOP_TIMEOUT;

// Discard payments after 15 minutes of failing to find txid
pub const PAYMENT_TIMEOUT: Duration = Duration::from_secs(900u64);
// How many blocks before we assume finality
const BLOCKS_TO_CONFIRM: u32 = 4;
// How old does a txid need to be before we don't accept it?
// this is 12 hours
const BLOCKS_TO_OLD: u32 = 1440;

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct ToValidate {
    /// details of the payment from the user in the format they where sent
    pub payment: PaymentTx,
    /// When we got this tx
    pub recieved: Instant,
    /// if we have managed to talk to a full node about this
    /// transaction ever
    pub checked: bool,
}

impl fmt::Display for ToValidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.payment.txid {
            Some(txid) => write!(
                f,
                "(txid: {:#066x}, from: {}",
                txid, self.payment.from.wg_public_key
            ),
            None => write!(f, "(txid: None, from: {}", self.payment.from.wg_public_key),
        }
    }
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

/// Removes a transaction from the pending validation queue, it may either
/// have been discovered to be invalid or have been succesfully accepted
struct Remove {
    tx: ToValidate,
    success: bool,
}

impl Message for Remove {
    type Result = Result<(), Error>;
}

impl Handler<Remove> for PaymentValidator {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: Remove, _ctx: &mut Context<Self>) -> Self::Result {
        let was_present = self.unvalidated_transactions.remove(&msg.tx);
        // store successful transactions so that they can't be played back to us, at least
        // during this session
        if msg.success && was_present {
            self.successful_transactions
                .insert(msg.tx.payment.clone().txid.unwrap());
        }
        if was_present {
            info!("Transaction {} was removed", msg.tx);
            Ok(())
        } else {
            error!("Transaction {} was double removed", msg.tx);
            Err(format_err!("No such transaction present!"))
        }
    }
}

/// Marks a transaction as 'checked' in that we have talked to a full node about it
/// if we fail to talk to a full node about a transaction for the full duration of
/// the timeout we will panic and restart.
#[derive(Message)]
struct Checked {
    tx: ToValidate,
}

impl Handler<Checked> for PaymentValidator {
    type Result = ();

    fn handle(&mut self, msg: Checked, _ctx: &mut Context<Self>) -> Self::Result {
        if self.unvalidated_transactions.take(&msg.tx).is_some() {
            let mut checked_tx = msg.tx;
            checked_tx.checked = true;
            info!("We successfully checked tx {:?}", checked_tx);
            self.unvalidated_transactions.insert(checked_tx);
        } else {
            error!("Tried to mark a tx {:?} we don't have as checked!", msg.tx);
        }
    }
}

#[derive(Message)]
pub struct Validate();

impl Handler<Validate> for PaymentValidator {
    type Result = ();

    fn handle(&mut self, _msg: Validate, _ctx: &mut Context<Self>) -> Self::Result {
        info!(
            "Attempting to validate {} transactions {}",
            self.unvalidated_transactions.len(),
            print_txids(&self.unvalidated_transactions)
        );
        let mut to_delete = Vec::new();
        for item in self.unvalidated_transactions.iter() {
            if item.recieved.elapsed() > PAYMENT_TIMEOUT {
                error!(
                    "Transaction {:#066x} has timed out, payment failed!",
                    item.payment.txid.clone().unwrap()
                );

                if !item.checked {
                    let msg = "We failed to check txid {:#066x} against full nodes for the full duration of it's timeout period, please check full nodes";
                    error!("{}", msg);
                    panic!(msg)
                }

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

    let res = web3
        .eth_block_number()
        .join(web3.eth_get_transaction_by_hash(txid.clone()))
        // even though we sepcify the timeout above don't remove this, we need it to 100% ensure that operations time out
        // for example Actix may run slowly, web3 timeouts only care about actual request time
        .timeout(TRANSACTION_VERIFICATION_TIMEOUT)
        .and_then(move |(block_num, tx_status)| {
            if !long_life_ts.checked {
                PaymentValidator::from_registry().do_send(Checked {
                    tx: long_life_ts.clone(),
                });
            }

            if let Some(transaction) = tx_status {
                handle_tx_messaging(txid, transaction, long_life_ts, block_num);
            }
            Ok(())
        })
        .then(|res| {
            if let Err(e) = res {
                warn!(
                    "Failed to validate {:#066x} transaction with {:?}",
                    pmt.txid.unwrap(),
                    e
                );
            }
            Ok(())
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
            let res = PaymentValidator::from_registry()
                .send(Remove {
                    tx: ts,
                    success: true,
                })
                .and_then(move |res| {
                    if res.is_ok() {
                        info!(
                            "payment {:#066x} from {} for {} wei successfully validated!",
                            txid, from_address, amount
                        );
                        DebtKeeper::from_registry().do_send(PaymentReceived {
                            from: pmt.from,
                            amount: pmt.amount.clone(),
                        });

                        // update the usage tracker with the details of this payment
                        UsageTracker::from_registry().do_send(UpdatePayments { payment: pmt });
                    } else {
                        info!(
                            "payment {:#066x} from {} for {} wei duplicate validation attempt!",
                            txid, from_address, amount
                        );
                    }
                    Ok(())
                })
                .then(|_| Ok(()));
            Arbiter::spawn(res);
        }
        // we suceessfully paid someone
        (false, true, true) => {
            let res = PaymentValidator::from_registry()
                .send(Remove {
                    tx: ts,
                    success: true,
                })
                .and_then(move |res| {
                    info!(
                        "payment {:#066x} from {} for {} wei successfully sent!",
                        txid, from_address, amount
                    );
                    if res.is_ok() {
                        DebtKeeper::from_registry().do_send(PaymentSucceeded {
                            to: pmt.to,
                            amount: pmt.amount.clone(),
                        });
                        // update the usage tracker with the details of this payment
                        UsageTracker::from_registry().do_send(UpdatePayments { payment: pmt });
                    }
                    Ok(())
                })
                .then(|_| Ok(()));
            Arbiter::spawn(res);
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

fn print_txids(list: &HashSet<ToValidate>) -> String {
    let mut output = String::new();
    for item in list.iter() {
        output += &format!("{} ,", item);
    }
    output
}
