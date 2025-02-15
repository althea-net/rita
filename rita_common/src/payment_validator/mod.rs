//! This module stores txid's and other payment information for later validation
//! while in theory we should be able to get the transaction from a txid within a few
//! seconds experience shows that up to a minute is not unusual for a txid to spread to
//! the whole network. During times of congestion may be even worse.
//! A series of payment amounts and txid's are stored in the actor which is triggered to
//! attempt to validate these payments every 5 seconds, if successful the payment is sent
//! off to debt keeper to be removed from the owed balance. Payments may time out after a
//! configured period.

use crate::debt_keeper::payment_failed;
use crate::debt_keeper::payment_received;
use crate::debt_keeper::payment_succeeded;
use crate::rita_loop::fast_loop::FAST_LOOP_TIMEOUT;
use crate::rita_loop::get_web3_server;
use crate::usage_tracker::update_payments;
use crate::RitaCommonError;
use althea_types::Identity;
use althea_types::PaymentTx;
use clarity::Address;
use crossbeam::queue::SegQueue;
use futures::future::join_all;
use num256::Uint256;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Write as _;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Arc;
use std::time::{Duration, Instant};
use web30::client::Web3;
use web30::types::TransactionResponse;

pub const TRANSACTION_VERIFICATION_TIMEOUT: Duration = FAST_LOOP_TIMEOUT;

/// Discard payments after 72 hours of failing to find txid, this is very generous
/// because attempting to validate an incoming payment for longer does nothing to harm
/// us, we can still send and receive other payments to all other nodes while waiting
/// So it make sense to give the maximum benefit of the doubt. Or time to resubmit
pub const PAYMENT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(259200u64);
/// Retry payments after a much shorter period, this is because other nodes may
/// enforce upon us if we miss a payment and due to the implementation of DebtKeeper
/// we will not send another payment while one is in flight. On Xdai the block time is
/// once every 5 seconds, meaning a minimum of 20 seconds is required to ensure 4 confirms
/// This only applies to ETH based chains as Althea chain transactions will be impossible to
/// submit after ALTHEA_L1_MICROTX_TIMEOUT blocks have elapsed, so there's no need to guess
pub const ETH_PAYMENT_SEND_TIMEOUT: Duration = Duration::from_secs(600u64);
/// How many blocks before we assume finality
const BLOCKS_TO_CONFIRM: u32 = 4;
/// How old does a txid need to be before we don't accept it?
/// this is 12 hours
const BLOCKS_TO_OLD: u32 = 1440;

// This is a global queue of incoming transactions that need to be validated
// the u32 here is the net namespace used to allow multiple instances to be run
// in the same process without interfering with each other. The SegQueue is a
// lock free queue that allows us to push transactions on from the make_payment_v1 and v2
// endpoints, potentially several in parallel and then pop them off in the tick_payment_validator
lazy_static! {
    static ref INCOMING_TRANSACTIONS: Arc<SegQueue<ToValidate>> = Arc::new(SegQueue::new());
}

pub fn add_to_incoming_transaction_queue(tx: ToValidate) {
    INCOMING_TRANSACTIONS.push(tx);
}

/// Returns the global incoming transaction queue
pub fn get_incoming_transaction_queue() -> Vec<ToValidate> {
    let mut ret = Vec::new();
    while let Some(ts) = INCOMING_TRANSACTIONS.pop() {
        ret.push(ts);
    }
    ret
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ToValidate {
    /// details of the payment from the user in the format they where sent
    pub payment: PaymentTx,
    /// When we got this tx
    pub received: Instant,
    /// The timeout block for this transaction, only set on transactions we send
    /// this is used as a more reliable timeout than the recieved field since it is
    /// actually not possible for the transaction to be included once this timeout has passed
    /// versus the recieved field which is just a guess
    pub timeout_block: Option<u64>,
}

// Ensure that duplicate txid are always treated as the same object
impl Hash for ToValidate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.payment.txid.hash(state);
    }
}

impl fmt::Display for ToValidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(txid: {:#066x}, from: {:?}",
            self.payment.txid, self.payment.from
        )?;
        Ok(())
    }
}

/// This struct stores the state of the payment validator module and is used to keep track of all payments
/// that are in the process of being validated. It also stores all successful transactions that have been sent
/// or received by this router.
#[derive(Clone, Debug)]
pub struct PaymentValidator {
    unvalidated_transactions: HashSet<ToValidate>,
    /// All successful transactions sent FROM this router, mapped To Address-> list of PaymentTx
    previously_sent_payments: HashMap<Identity, HashSet<PaymentTx>>,
    /// All successful txids TO this router that have been verified, used to check for duplicate payments
    successful_transactions: HashSet<PaymentTx>,
}

impl PaymentValidator {
    pub fn new() -> Self {
        PaymentValidator {
            unvalidated_transactions: HashSet::new(),
            previously_sent_payments: HashMap::new(),
            successful_transactions: HashSet::new(),
        }
    }
}

impl Default for PaymentValidator {
    fn default() -> PaymentValidator {
        PaymentValidator::new()
    }
}

impl PaymentValidator {
    /// Performs a sanity check of the Payment validator struct
    /// this checks that we do not have duplicate data anywhere in the struct
    /// returns true if the struct contains no duplicate data, false otherwise
    fn is_consistent(&self) -> bool {
        let mut txids = HashSet::new();
        for tx in self.unvalidated_transactions.iter() {
            if txids.contains(&tx.payment.txid) {
                return false;
            }
            txids.insert(tx.payment.txid.clone());
        }

        for (_, txs) in self.previously_sent_payments.iter() {
            for tx in txs.iter() {
                if txids.contains(&tx.txid) {
                    return false;
                }
                txids.insert(tx.txid.clone());
            }
        }

        for tx in self.successful_transactions.iter() {
            if txids.contains(&tx.txid) {
                return false;
            }
            txids.insert(tx.txid.clone());
        }

        true
    }

    /// Checks if a transaction is a duplicate of any transaction we have already seen
    fn check_for_duplicates(&self, tx: &ToValidate) -> bool {
        let mut txids = HashSet::new();
        for tx in self.unvalidated_transactions.iter() {
            txids.insert(tx.payment.txid.clone());
        }
        for (_, txs) in self.previously_sent_payments.iter() {
            for tx in txs.iter() {
                txids.insert(tx.txid.clone());
            }
        }
        for tx in self.successful_transactions.iter() {
            txids.insert(tx.txid.clone());
        }
        txids.contains(&tx.payment.txid)
    }

    /// Removes a transaction from the pending validation queue, it may either
    /// have been discovered to be invalid or have been successfully accepted
    /// This function handles updating debt keeper and usage tracker with the details
    /// messaging to external modules should happen only in this function
    fn remove_and_update_debt_keeper(&mut self, tx: ToValidate, success: TxValidationStatus) {
        let was_present = self.unvalidated_transactions.remove(&tx);

        match success {
            TxValidationStatus::FromUsSuccess => {
                let txs = self
                    .previously_sent_payments
                    .entry(tx.payment.to)
                    .or_default();

                // update debt keeper with details of this payment
                let _ = payment_succeeded(tx.payment.to.clone(), tx.payment.amount.clone());

                // update the usage tracker with the details of this payment
                update_payments(tx.payment.clone());

                txs.insert(tx.payment.clone());
            }
            TxValidationStatus::FromUsFailure => {
                // notify debt keeper that the payment has failed
                payment_failed(tx.payment.to);
            }
            // store successful transactions to us so that they can't be played back to us, at least
            // during this session
            TxValidationStatus::ToUsSuccess => {
                self.successful_transactions.insert(tx.payment.clone());

                // update debt keeper with the details of this payment
                let _ = payment_received(tx.payment.from, tx.payment.amount.clone());

                // update the usage tracker with the details of this payment
                update_payments(tx.payment.clone());
            }
            // if a payment to us fails we don't need to do anything
            TxValidationStatus::ToUsFailure => {}
            // Log and hopefully resolve the errors
            TxValidationStatus::FailureException => {}
        }

        // integrity checks unrelated to the rest of the processing
        if was_present && self.is_consistent() {
            info!("Transaction {} {:?} was removed", tx.clone(), success);
        } else {
            warn!(
                "Transaction {} was double removed or state became inconsistent",
                tx.clone()
            );
            // in a development env we want to draw attention to this case
            if cfg!(feature = "integration_test") || cfg!(test) {
                panic!("Transaction double removed!");
            }
        }
    }

    /// Message to insert transactions into payment validator, once inserted they will remain
    /// until they are validated, dropped for validity issues, or time out without being inserted
    /// into the blockchain. Transactions that are too old are prevented from being played back
    /// by using a history of successful transactions.
    /// This endpoint specifically (and only this one) is fully idempotent so that we can retry
    /// txid transmissions
    fn add_to_validation_queue(&mut self, ts: ToValidate) -> Result<(), RitaCommonError> {
        if !self.check_for_duplicates(&ts) {
            // insert is safe to run multiple times just so long as we check successful tx's for duplicates
            self.unvalidated_transactions.insert(ts);
            Ok(())
        } else {
            Err(RitaCommonError::DuplicatePayment)
        }
    }

    /// Iterates the payment validator state, checking transactions for validity. If a transaction to this router
    /// is found to be valid it is removed from the unvalidated_transactions list and the debt keeper is updated
    /// if a transaction from this router is found to be valid it is removed from the unvalidated_transactions list
    /// if a transaction from this router is found to be invalid it is removed from the unvalidated_transactions list
    /// and a retry is scheduled with payment_sender
    pub async fn tick_payment_validator(
        &mut self,
        // outgoing payments coming in from payment_controller
        outgoing_payments: Vec<ToValidate>,
    ) -> HashMap<Identity, HashSet<PaymentTx>> {
        // we panic on a failed receive so it should always be longer than the minimum
        // time we expect payments to take to enter the blockchain (the send timeout)
        assert!(PAYMENT_RECEIVE_TIMEOUT > ETH_PAYMENT_SEND_TIMEOUT);
        if !self.is_consistent() {
            warn!("Inconsistent payment validator! {:?}", self);
            // in a development env we want to draw attention to this case
            if cfg!(feature = "integration_test") || cfg!(test) {
                panic!("Inconsistent payment validator!");
            }
        }

        let mut payments = Vec::new();
        payments.extend(outgoing_payments.into_iter());
        payments.extend(get_incoming_transaction_queue().into_iter());
        for pmt in payments {
            let _ = self.add_to_validation_queue(pmt);
        }

        let our_address = settings::get_rita_common().payment.eth_address.unwrap();
        let mut to_delete = Vec::new();

        // there's nothing to do, exit early
        if self.unvalidated_transactions.is_empty() {
            return self.previously_sent_payments.clone();
        }

        info!(
            "Attempting to validate {} transactions {}",
            self.unvalidated_transactions.len(),
            print_txids(&self.unvalidated_transactions)
        );

        // Payment validation logic, broken up into three parts first we handle the basic timeouts
        // for sending and recieving payments, this can be easily handles entierly within this scope
        // then we handle the more complex validation logic which requires a network request by creating
        // a future for each transaction and then executing them in parallel.
        let mut futs = Vec::new();
        for item in self.unvalidated_transactions.iter() {
            let elapsed = Instant::now().checked_duration_since(item.received);
            let from_us = item.payment.from.eth_address == our_address;

            if elapsed.is_some() && elapsed.unwrap() > PAYMENT_RECEIVE_TIMEOUT {
                error!(
                    "Incoming transaction {} has timed out, payment failed!",
                    format!("{:#066x}", item.payment.txid)
                );

                to_delete.push((item.clone(), TxValidationStatus::ToUsFailure));
            }
            // timeout eth based transactions after the timeout time has passed, in this case it's possible that our tx will be included
            // after the timeout and we will overpay
            else if elapsed.is_some() && from_us && elapsed.unwrap() > ETH_PAYMENT_SEND_TIMEOUT {
                error!(
                    "Outgoing transaction {:#066x} has timed out, payment failed!",
                    item.payment.txid
                );
                to_delete.push((item.clone(), TxValidationStatus::FromUsFailure));
            } else {
                // we take all these futures and put them onto an array that we will execute
                // in parallel, this is essential on the exit where in the worst case scenario
                // we could have a thousand or more payments in the queue
                let fut = validate_transaction(item.clone());
                futs.push(fut);
            }
        }

        // Run all parallel validation tasks, there may be many hundreds of tx here
        // becuase make_payments_v2 plays back the entire payment history of a node
        // in order to resync. This is batched to avoid issues with making too many
        // requests at once
        const VALIDATE_BATCH_SIZE: usize = 10;
        let mut validation_results = Vec::new();
        let mut buf = Vec::new();
        for f in futs.into_iter() {
            if buf.len() < VALIDATE_BATCH_SIZE {
                buf.push(f)
            } else {
                // execute all of the above verification operations in parallel
                validation_results.extend(join_all(buf).await);
                buf = Vec::new();
            }
        }
        // check the last leftover futures in the array
        validation_results.extend(join_all(buf).await);

        // take all validation results and add them to the to_delete list from the
        // timeout checking, so that we can process everything in one go
        for (tx, success) in validation_results.into_iter().flatten() {
            // transactions that have finished being procssed return a Some()
            // value and are removed from the queue.
            to_delete.push((tx, success));
        }

        // This is the final stage of payment validation, we remove all transactions
        // that have been processed from the unvalidated_transactions list
        // Messaging to debt keeper and usage tracker must only be done here
        // keeping it in one location makes it easier to keep track of and prevent
        // duplicate checks which can cause duplicate payments or panics in debt keeper
        for (tx, success) in to_delete.iter() {
            self.remove_and_update_debt_keeper(tx.clone(), *success)
        }

        // we return our list of sent payments this is passed to payment_controller
        // so that it can be played back to other nodes as part of make_payment_v2
        // where we replay payment history to resync with other nodes and form a sort
        // of distributed memory of payments that survives reboots
        self.previously_sent_payments.clone()
    }
}

/// This function validates transactions on the xDai chain, making a series of requests
/// and then checking the results to determine if the transaction is valid. If the transaction
/// is valid or invalid Some(true) or Some(false) respectively is returned. If the transaction
/// is still pending None is returned.
async fn validate_transaction(ts: ToValidate) -> Option<(ToValidate, TxValidationStatus)> {
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_VERIFICATION_TIMEOUT);

    let txid = ts.payment.txid.clone();

    let eth_block_num = web3.eth_block_number().await;
    let eth_transaction = web3.eth_get_transaction_by_hash(txid.clone()).await;
    match (eth_transaction, eth_block_num) {
        (Ok(Some(transaction)), Ok(block_num)) => {
            handle_tx_messaging_xdai(ts.payment.txid.clone(), transaction, ts.clone(), block_num)
        }
        (_, _) => {
            trace!("Failed to check transaction {:#066x}", txid);
            None
        }
    }
}

fn get_xdai_transaction_details(
    transaction: TransactionResponse,
) -> (Option<Address>, Address, Uint256, Option<Uint256>) {
    (
        transaction.to,
        transaction.from,
        transaction.value,
        transaction.block_number,
    )
}

/// A quick internal enum to encode the status of a transaction validation
/// rather than a boolean which would leave the direction of the transaction
/// ambiguous
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxValidationStatus {
    FromUsSuccess,
    FromUsFailure,
    ToUsSuccess,
    ToUsFailure,
    /// a case for failures that don't require any messaging about success or failure
    /// to debt keeper and is used for cases we really shouldn't ever seen in production
    /// but we don't panic for because a hostile actor could cause them by submitting strange tx
    /// for validation
    FailureException,
}

/// This function is used to validate transactions both incoming and outgoing, it must reject any payment
/// that is not correct and returns the payment and a boolean indicating if it was successful, if we do not
/// yet know if the payment was successful we return None
fn handle_tx_messaging_xdai(
    txid: Uint256,
    transaction: TransactionResponse,
    ts: ToValidate,
    current_block: Uint256,
) -> Option<(ToValidate, TxValidationStatus)> {
    let from_address = ts.payment.from.eth_address;
    let amount = ts.payment.amount.clone();
    let our_address = settings::get_rita_common()
        .payment
        .eth_address
        .expect("No Address!");

    let (tx_to, tx_from, tx_value, tx_block_number) = get_xdai_transaction_details(transaction);

    let to = match tx_to {
        Some(val) => val,
        None => {
            // this is only possible for contract creation transactions
            error!("Invalid TX! No destination!");
            return Some((ts, TxValidationStatus::FailureException));
        }
    };

    // notice we get these values from the blockchain using 'transaction' not ts which may be a lie since we don't
    // actually cryptographically validate the txhash locally. Instead we just compare the value we get from the full
    // node
    let to_us = to == our_address;
    let from_us = tx_from == our_address;
    let value_correct = tx_value == amount;
    let is_in_chain = payment_in_chain_xdai(current_block.clone(), tx_block_number.clone());
    let is_old = payment_is_old(current_block, tx_block_number);

    if !value_correct {
        error!("Transaction with invalid amount!");
        return Some((ts, TxValidationStatus::FailureException));
    }

    if is_old {
        error!("Transaction is more than 6 hours old! {:#066x}", txid);
        return Some((ts, TxValidationStatus::FailureException));
    }

    match (to_us, from_us, is_in_chain) {
        // we were successfully paid
        (true, false, true) => {
            info!(
                "payment {:#066x} from {} for {} wei successfully validated!",
                txid, from_address, amount
            );
            Some((ts, TxValidationStatus::ToUsSuccess))
        }
        // we successfully paid someone
        (false, true, true) => {
            info!(
                "payment {:#066x} from {} for {} wei successfully sent!",
                txid, from_address, amount
            );
            Some((ts, TxValidationStatus::FromUsSuccess))
        }
        (true, true, _) => {
            error!("Transaction to ourselves!");
            Some((ts, TxValidationStatus::FailureException))
        }
        (false, false, _) => {
            error!("Transaction has nothing to do with us?");
            Some((ts, TxValidationStatus::FailureException))
        }
        (_, _, false) => {
            //transaction waiting for validation, do nothing
            None
        }
    }
}

/// Determine if a given payment satisfies our criteria for being in the blockchain
/// this is not required or valid for althea L1 as payments there have instant finality
fn payment_in_chain_xdai(chain_height: Uint256, tx_height: Option<Uint256>) -> bool {
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
        write!(output, "{item} ,").unwrap();
    }
    output
}

/// Uses the correct format string to convert a Uint256 to a hex string
/// for Alhtea L1 txids
pub fn althea_l1_txid_to_string(txid: Uint256) -> String {
    format!("{:64X}", txid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debt_keeper::reset_debt_keeper;
    use crate::{
        blockchain_oracle::get_pay_thresh,
        debt_keeper::{send_debt_update, traffic_update, Traffic},
        usage_tracker::tests::test::random_identity,
    };
    use num256::Int256;
    use settings::client::RitaClientSettings;

    fn generate_fake_payment(from_id: Identity) -> ToValidate {
        let mut amount: u64 = rand::random();
        // we have to make sure this value is hgih enough to trigger a payment
        while Int256::from(amount) <= get_pay_thresh() {
            amount = rand::random();
        }
        let txid: u128 = rand::random();
        let tx = PaymentTx {
            to: random_identity(),
            from: from_id,
            amount: amount.into(),
            txid: txid.into(),
        };
        ToValidate {
            payment: tx,
            received: Instant::now(),
            timeout_block: None,
        }
    }

    /// tests the remove behaivor of payment validator, ensuring that transactions
    /// are successfully removed, and that they are moved to the correct list
    #[test]
    fn test_remove() {
        let mut validator = PaymentValidator::new();
        let our_id = random_identity();
        // setup settings in test env
        RitaClientSettings::setup_test(our_id);
        // setup settings in test env
        reset_debt_keeper();

        // add a payment to carry through the test to demonstrate we don't
        // remove the wrong one
        let payment = generate_fake_payment(our_id);
        validator.add_to_validation_queue(payment.clone()).unwrap();

        // test that we remove a transaction and put it into the successful list
        let payment = generate_fake_payment(our_id);
        validator.add_to_validation_queue(payment.clone()).unwrap();
        validator.remove_and_update_debt_keeper(
            payment.clone(),
            // the random payment doesn't specify who it's from
            TxValidationStatus::ToUsSuccess,
        );
        assert_eq!(validator.unvalidated_transactions.len(), 1);
        assert_eq!(validator.successful_transactions.len(), 1);
        assert_eq!(validator.previously_sent_payments.len(), 0);

        // unsuccessful transactions should not be saved

        // we generate a payment, and enqueue it for validation, while also
        // messaging debt keeper that a payment needs to be made this is required
        // so that the cross validation works while also bypassing payment_controller
        // since we're not actually sending a payment in this test
        let payment = generate_fake_payment(our_id);
        let amount: i128 = payment.payment.amount.clone().to_string().parse().unwrap();
        traffic_update(vec![Traffic {
            // not a typo, the debt is from this peer
            from: payment.payment.to,
            amount: amount.into(),
        }]);
        validator.add_to_validation_queue(payment.clone()).unwrap();
        // debt update should return one payment to be made (which we've already added to the queue)
        // skipping the part where paymetn_controller would send hte payment then enqueue it
        assert!(send_debt_update().unwrap().len() == 1);

        validator.remove_and_update_debt_keeper(payment.clone(), TxValidationStatus::FromUsFailure);
        assert_eq!(validator.unvalidated_transactions.len(), 1);
        assert_eq!(validator.successful_transactions.len(), 1);
        assert_eq!(validator.previously_sent_payments.len(), 0);

        // make sure the payments sent from us are stored in the correct list
        // run this again to have debt_keeper trigger a payment retry
        assert!(send_debt_update().unwrap().len() == 1);
        validator.add_to_validation_queue(payment.clone()).unwrap();
        validator.remove_and_update_debt_keeper(payment.clone(), TxValidationStatus::FromUsSuccess);
        assert_eq!(validator.unvalidated_transactions.len(), 1);
        assert_eq!(validator.successful_transactions.len(), 1);
        assert_eq!(validator.previously_sent_payments.len(), 1);

        // payments that do not succeed should not be added
        let payment = generate_fake_payment(our_id);
        let amount: i128 = payment.payment.amount.clone().to_string().parse().unwrap();
        traffic_update(vec![Traffic {
            // not a typo, the debt is from this peer
            from: payment.payment.to,
            amount: amount.into(),
        }]);
        validator.add_to_validation_queue(payment.clone()).unwrap();
        // debt update should return one payment to be made (which we've already added to the queue)
        // skipping the part where paymetn_controller would send hte payment then enqueue it
        assert!(send_debt_update().unwrap().len() == 1);
        assert_eq!(validator.unvalidated_transactions.len(), 2);
        validator.remove_and_update_debt_keeper(payment.clone(), TxValidationStatus::FromUsFailure);
        assert_eq!(validator.unvalidated_transactions.len(), 1);
        assert_eq!(validator.successful_transactions.len(), 1);
        assert_eq!(validator.previously_sent_payments.len(), 1);
    }

    // this test has to be ignored by default becuase it panics and poisons the DebtKeeper lazy static
    // this can be removed once we (hopefuly) move away from a global variable situation
    #[ignore]
    #[test]
    #[should_panic]
    fn test_double_remove() {
        let mut validator = PaymentValidator::new();
        let our_id = random_identity();
        // setup settings in test env
        RitaClientSettings::setup_test(our_id);
        reset_debt_keeper();

        let payment = generate_fake_payment(our_id);
        validator.add_to_validation_queue(payment.clone()).unwrap();
        validator.remove_and_update_debt_keeper(payment.clone(), TxValidationStatus::FromUsFailure);
        validator.remove_and_update_debt_keeper(payment.clone(), TxValidationStatus::FromUsFailure);
    }

    #[test]
    /// Attempts to insert a duplicate tx into the to_validate list
    fn test_duplicate_tx() {
        // check that we can't put duplicates in add_to_validation_queue
        let mut validator = PaymentValidator::new();
        let our_id = random_identity();
        // setup settings in test env
        RitaClientSettings::setup_test(our_id);
        reset_debt_keeper();

        let payment = generate_fake_payment(our_id);
        assert!(validator.add_to_validation_queue(payment.clone()).is_ok());
        assert!(validator.add_to_validation_queue(payment).is_err());
        // check that we can't put dupliates in that we have already validated
        let payment = generate_fake_payment(our_id);
        validator
            .successful_transactions
            .insert(payment.payment.clone());
        assert!(validator.add_to_validation_queue(payment).is_err());
    }

    // ensures that payment validator crashes when presented with an invalid state
    #[test]
    fn test_invalid_payment_validator_state() {
        let mut validator = PaymentValidator::new();
        let our_id = random_identity();
        // setup settings in test env
        RitaClientSettings::setup_test(our_id);
        reset_debt_keeper();

        // duplicate between unvalidated and previously sent
        let payment = generate_fake_payment(our_id);
        let mut set = HashSet::new();
        set.insert(payment.clone().payment);
        validator.unvalidated_transactions.insert(payment.clone());
        validator
            .previously_sent_payments
            .insert(payment.payment.to, set);

        assert!(!validator.is_consistent());

        // duplicate between unvalidated and successful
        let mut validator = PaymentValidator::new();
        let payment = generate_fake_payment(our_id);
        validator.unvalidated_transactions.insert(payment.clone());
        validator.successful_transactions.insert(payment.payment);

        assert!(!validator.is_consistent());

        // duplicate between sent and recieved
        let mut validator = PaymentValidator::new();
        let payment = generate_fake_payment(our_id);
        let mut set = HashSet::new();
        set.insert(payment.clone().payment);
        validator
            .successful_transactions
            .insert(payment.payment.clone());
        validator
            .previously_sent_payments
            .insert(payment.payment.to, set);

        assert!(!validator.is_consistent());

        // Consistent with 3 different payments, happy path
        let mut validator = PaymentValidator::new();
        let mut set = HashSet::new();
        set.insert(generate_fake_payment(our_id).payment);
        validator.unvalidated_transactions.insert(payment.clone());
        validator
            .successful_transactions
            .insert(generate_fake_payment(our_id).payment);
        validator
            .previously_sent_payments
            .insert(payment.payment.to, set);

        assert!(validator.is_consistent());
    }
}
