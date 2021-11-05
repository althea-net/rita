//! This module stores txid's and other payment information for later validation
//! while in theory we should be able to get the transaction from a txid within a few
//! seconds experience shows that up to a minute is not unusual for a txid to spread to
//! the whole network. During times of congestion may be even worse.
//! A series of payment amounts and txid's are stored in the actor which is triggered to
//! attempt to validate these payments every 5 seconds, if successful the payment is sent
//! off to debt keeper to be removed from the owed balance. Payments may time out after a
//! configured period.

use crate::debt_keeper::payment_received;
use crate::debt_keeper::payment_succeeded;
use crate::rita_loop::fast_loop::FAST_LOOP_TIMEOUT;
use crate::rita_loop::get_web3_server;
use crate::usage_tracker::update_payments;

use actix::System;
use althea_types::PaymentTx;
use num256::Uint256;
use web30::client::Web3;
use web30::types::TransactionResponse;

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub const TRANSACTION_VERIFICATION_TIMEOUT: Duration = FAST_LOOP_TIMEOUT;

/// Discard payments after 15 minutes of failing to find txid, this is very generous
/// because attempting to validate an incoming payment for longer does nothing to harm
/// us, we can still send and receive other payments to all other nodes while waiting
/// So it make sense to give the maximum benefit of the doubt. Or time to resubmit
pub const PAYMENT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(900u64);
/// Retry payments after a much shorter period, this is because other nodes may
/// enforce upon us if we miss a payment and due to the implementation of DebtKeeper
/// we will not send another payment while one is in flight. On Xdai the block time is
/// once every 5 seconds, meaning a minimum of 20 seconds is required to ensure 4 confirms
pub const PAYMENT_SEND_TIMEOUT: Duration = Duration::from_secs(60u64);
/// How many blocks before we assume finality
const BLOCKS_TO_CONFIRM: u32 = 4;
/// How old does a txid need to be before we don't accept it?
/// this is 12 hours
const BLOCKS_TO_OLD: u32 = 1440;

lazy_static! {
    static ref HISTORY: Arc<RwLock<PaymentValidator>> =
        Arc::new(RwLock::new(PaymentValidator::new()));
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct ToValidate {
    /// details of the payment from the user in the format they where sent
    pub payment: PaymentTx,
    /// When we got this tx
    pub received: Instant,
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
/// This endpoint specifically (and only this one) is fully idempotent so that we can retry
/// txid transmissions
pub fn validate_later(ts: ToValidate) {
    let mut history = HISTORY.write().unwrap();
    if let Some(txid) = ts.payment.txid.clone() {
        if !history.successful_transactions.contains(&txid) {
            // insert is safe to run multiple times just so long as we check successful tx's for duplicates
            history.unvalidated_transactions.insert(ts);
        }
    } else {
        error!(
            "Someone tried to insert an unpublished transaction to validate!? {:?}",
            ts
        );
        // in a development env we want to draw attention to this case
        #[cfg(feature = "development")]
        panic!(
            "Someone tried to insert an unpublished transaction to validate!? {:?}",
            ts
        )
    }
}

struct Remove {
    tx: ToValidate,
    success: bool,
}

/// Removes a transaction from the pending validation queue, it may either
/// have been discovered to be invalid or have been successfully accepted
fn remove(msg: Remove, history: &mut PaymentValidator) {
    let was_present = history.unvalidated_transactions.remove(&msg.tx);
    // store successful transactions so that they can't be played back to us, at least
    // during this session
    if msg.success && was_present {
        history
            .successful_transactions
            .insert(msg.tx.payment.clone().txid.unwrap());
    }
    if was_present {
        info!("Transaction {} was removed", msg.tx);
    } else {
        error!("Transaction {} was double removed", msg.tx);
        // in a development env we want to draw attention to this case
        #[cfg(feature = "development")]
        panic!("Transaction double removed!");
    }
}

/// Marks a transaction as 'checked' in that we have talked to a full node about it
/// if we fail to talk to a full node about a transaction for the full duration of
/// the timeout we attempt to restart our node.
fn checked(msg: ToValidate, history: &mut PaymentValidator) {
    if history.unvalidated_transactions.take(&msg).is_some() {
        let mut checked_tx = msg;
        checked_tx.checked = true;
        info!("We successfully checked tx {:?}", checked_tx);
        history.unvalidated_transactions.insert(checked_tx);
    } else {
        error!("Tried to mark a tx {:?} we don't have as checked!", msg);

        #[cfg(feature = "development")]
        panic!("Tried to mark a tx {:?} we don't have as checked!", msg);
    }
}

#[allow(clippy::await_holding_lock)]
pub async fn validate() {
    // we panic on a failed receive so it should always be longer than the minimum
    // time we expect payments to take to enter the blockchain (the send timeout)
    assert!(PAYMENT_RECEIVE_TIMEOUT > PAYMENT_SEND_TIMEOUT);

    let our_address = settings::get_rita_common().payment.eth_address.unwrap();

    let mut history = HISTORY.write().unwrap();

    let mut to_delete = Vec::new();

    info!(
        "Attempting to validate {} transactions {}",
        history.unvalidated_transactions.len(),
        print_txids(&history.unvalidated_transactions)
    );

    for item in history.unvalidated_transactions.clone().iter() {
        let elapsed = Instant::now().checked_duration_since(item.received);
        let from_us = item.payment.from.eth_address == our_address;

        if elapsed.is_some() && elapsed.unwrap() > PAYMENT_RECEIVE_TIMEOUT {
            error!(
                "Incoming transaction {:#066x} has timed out, payment failed!",
                item.payment.txid.clone().unwrap()
            );

            // if we fail to so much as get a block height for the full duration of a payment timeout, we have problems and probably we are not counting payments correctly potentially leading to wallet
            // drain and other bad outcomes. So we should restart with the hope that the system will be restored to a working state by this last resort action
            if !item.checked {
                let msg = format!("We failed to check txid {:#066x} against full nodes for the full duration of it's timeout period, please check full nodes", item.payment.txid.clone().unwrap());
                error!("{}", msg);
                // drop the lock to prevent poisoning if we don't manage to crash
                drop(history);
                // get the non-async actix system and try to shut down the whole process
                let system = System::current();
                system.stop_with_code(121);
                // this satisfies the borrow checker to let us drop history so that if we
                // fail to get the current actix system we don't poison the lock fatally
                return;
            }

            to_delete.push(item.clone());
        }
        // no penalties for failure here, we expect to overpay one out of every few hundred
        // transactions
        else if elapsed.is_some() && from_us && elapsed.unwrap() > PAYMENT_SEND_TIMEOUT {
            error!(
                "Outgoing transaction {:#066x} has timed out, payment failed!",
                item.payment.txid.clone().unwrap()
            );
            to_delete.push(item.clone());
        } else {
            validate_transaction(item, &mut history).await;
        }
    }

    for item in to_delete.iter() {
        history.unvalidated_transactions.remove(item);
    }
}

/// Attempt to validate that a given transaction has been accepted into the blockchain and
/// is at least some configurable number of blocks behind the head.
pub async fn validate_transaction(ts: &ToValidate, history: &mut PaymentValidator) {
    trace!("validating transaction");
    // we validate that a txid is present before adding to the validation list
    let txid = ts.payment.clone().txid.unwrap();
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_VERIFICATION_TIMEOUT);

    let block_num = web3.eth_block_number().await;
    let transaction = web3.eth_get_transaction_by_hash(txid.clone()).await;

    match (transaction, block_num) {
        (Ok(Some(transaction)), Ok(block_num)) => {
            if !ts.checked {
                checked(ts.clone(), history);
            }
            handle_tx_messaging(txid, transaction, ts.clone(), block_num, history);
        }
        (Ok(None), _) => {
            // we have a response back from the full node that this tx is not in the mempool this
            // satisfies our checked requirement
            if !ts.checked {
                checked(ts.clone(), history);
            }
        }
        (Err(_), Ok(_)) => {
            // we get an error from the full node but a successful block request, clearly we can contact
            // the full node so the transaction check has been attempted
            if !ts.checked {
                checked(ts.clone(), history);
            }
        }
        (Ok(Some(_)), Err(_)) => trace!("Failed to check transaction {:#066x}", txid),
        (Err(_), Err(_)) => trace!("Failed to check transaction {:#066x}", txid),
    }
}

/// Handles the tx response from the full node and it's various cases
/// pulled out of validate_transaction purely for cosmetic reasons
fn handle_tx_messaging(
    txid: Uint256,
    transaction: TransactionResponse,
    ts: ToValidate,
    current_block: Uint256,
    history: &mut PaymentValidator,
) {
    let from_address = ts.payment.from.eth_address;
    let amount = ts.payment.amount.clone();
    let pmt = ts.payment.clone();
    let our_address = settings::get_rita_common()
        .payment
        .eth_address
        .expect("No Address!");
    let to = match transaction.to {
        Some(val) => val,
        None => {
            error!("Invalid TX! No destination!");
            remove(
                Remove {
                    tx: ts,
                    success: false,
                },
                history,
            );
            return;
        }
    };

    // notice we get these values from the blockchain using 'transaction' not ts which may be a lie since we don't
    // actually cryptographically validate the txhash locally. Instead we just compare the value we get from the full
    // node
    let to_us = to == our_address;
    let from_us = transaction.from == our_address;
    let value_correct = transaction.value == amount;
    let is_in_chain = payment_in_chain(current_block.clone(), transaction.block_number.clone());
    let is_old = payment_is_old(current_block, transaction.block_number);

    if !value_correct {
        error!("Transaction with invalid amount!");
        remove(
            Remove {
                tx: ts,
                success: false,
            },
            history,
        );
        return;
    }

    if is_old {
        error!("Transaction is more than 6 hours old! {:#066x}", txid);
        remove(
            Remove {
                tx: ts,
                success: false,
            },
            history,
        );
        return;
    }

    match (to_us, from_us, is_in_chain) {
        // we where successfully paid
        (true, false, true) => {
            // remove this transaction from our storage
            remove(
                Remove {
                    tx: ts,
                    success: true,
                },
                history,
            );
            info!(
                "payment {:#066x} from {} for {} wei successfully validated!",
                txid, from_address, amount
            );
            // update debt keeper with the details of this payment
            let _ = payment_received(pmt.from, pmt.amount.clone());

            // update the usage tracker with the details of this payment
            update_payments(pmt);
        }
        // we successfully paid someone
        (false, true, true) => {
            info!(
                "payment {:#066x} from {} for {} wei successfully sent!",
                txid, from_address, amount
            );
            // remove this transaction from our storage
            remove(
                Remove {
                    tx: ts,
                    success: true,
                },
                history,
            );
            // update debt keeper with the details of this payment
            let _ = payment_succeeded(pmt.to, pmt.amount.clone());

            // update the usage tracker with the details of this payment
            update_payments(pmt);
        }
        (true, true, _) => {
            error!("Transaction to ourselves!");
            remove(
                Remove {
                    tx: ts,
                    success: false,
                },
                history,
            );
        }
        (false, false, _) => {
            error!("Transaction has nothing to do with us?");
            remove(
                Remove {
                    tx: ts,
                    success: false,
                },
                history,
            );
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
