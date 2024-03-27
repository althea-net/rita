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
use crate::RitaCommonError;
use althea_proto::microtx::v1::MsgMicrotx;
use althea_types::Denom;
use althea_types::Identity;
use althea_types::PaymentTx;
use althea_types::SystemChain;
use clarity::Address;
use cosmos_sdk_proto_althea::cosmos::tx::v1beta1::GetTxResponse;
use cosmos_sdk_proto_althea::cosmos::tx::v1beta1::{TxBody, TxRaw};
use deep_space::client::type_urls::MSG_MICROTX_TYPE_URL;
use deep_space::client::ChainStatus;
use deep_space::utils::decode_any;
use deep_space::Address as AltheaAddress;
use deep_space::Coin;
use deep_space::Contact;
use futures::future::join_all;
use num256::Uint256;
use settings::get_rita_common;
use settings::DEBT_KEEPER_DENOM;
use settings::DEBT_KEEPER_DENOM_DECIMAL;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Write as _;
use std::hash::Hash;
use std::hash::Hasher;
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
pub const PAYMENT_SEND_TIMEOUT: Duration = Duration::from_secs(600u64);
/// How many blocks before we assume finality
const BLOCKS_TO_CONFIRM: u32 = 4;
/// How old does a txid need to be before we don't accept it?
/// this is 12 hours
const BLOCKS_TO_OLD: u32 = 1440;

// These parameters are used to set up a contact with althea chain
pub const ALTHEA_CHAIN_PREFIX: &str = "althea";
pub const ALTHEA_CONTACT_TIMEOUT: Duration = Duration::from_secs(30);

/// Details we pass into handle_tx_handling while validating a transaction
/// These are made options in case althea chain parsing fails
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct TransactionDetails {
    pub to: AltheaAddress,
    pub from: AltheaAddress,
    pub amount: Uint256,
    pub denom: String,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ToValidate {
    /// details of the payment from the user in the format they where sent
    pub payment: PaymentTx,
    /// When we got this tx
    pub received: Instant,
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
            "(txid: {:#066x}, from: {}",
            self.payment.txid, self.payment.from.wg_public_key
        )?;
        Ok(())
    }
}

/// This struct stores the state of the payment validator module and is used to keep track of all payments
/// that are in the process of being validated. It also stores all successful transactions that have been sent
/// or received by this router.
#[derive(Clone)]
pub struct PaymentValidator {
    unvalidated_transactions: HashSet<ToValidate>,
    /// All successful transactions sent FROM this router, mapped To Address-> list of PaymentTx
    successful_transactions_sent: HashMap<Identity, HashSet<PaymentTx>>,
    /// All successful txids this router has verified, used to check for duplicate payments
    successful_transactions: HashSet<PaymentTx>,
}

impl PaymentValidator {
    pub fn new() -> Self {
        PaymentValidator {
            unvalidated_transactions: HashSet::new(),
            successful_transactions_sent: HashMap::new(),
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
            txids.insert(tx.payment.txid);
        }

        for (_, txs) in self.successful_transactions_sent.iter() {
            for tx in txs.iter() {
                if txids.contains(&tx.txid) {
                    return false;
                }
                txids.insert(tx.txid);
            }
        }

        for tx in self.successful_transactions.iter() {
            if txids.contains(&tx.txid) {
                return false;
            }
            txids.insert(tx.txid);
        }

        true
    }

    /// Removes a transaction from the pending validation queue, it may either
    /// have been discovered to be invalid or have been successfully accepted
    fn remove(&mut self, tx: ToValidate, success: bool) {
        let was_present = self.unvalidated_transactions.remove(&tx);
        // store successful transactions so that they can't be played back to us, at least
        // during this session
        if success {
            self.successful_transactions.insert(tx.payment.clone());
        }
        if was_present {
            info!("Transaction {} {} was removed", tx, success);
        } else {
            warn!("Transaction {} was double removed", tx);
            // in a development env we want to draw attention to this case
            if cfg!(feature = "development") || cfg!(feature = "integration_test") {
                panic!("Transaction double removed!");
            }
        }
    }

    /// This stores the txid of all payments we have made so that they can be played
    /// back to other nodes, allowing them to rebuild their payment states
    fn store_payment(&mut self, pmt: PaymentTx) {
        let neighbor = pmt.to;

        if let Some(e) = self.successful_transactions_sent.get_mut(&neighbor) {
            e.insert(pmt);
        } else {
            let mut set = HashSet::new();
            set.insert(pmt);
            self.successful_transactions_sent.insert(neighbor, set);
        }
    }

    /// Given an id, get all payments made to that id
    fn get_payment_txids(&self, id: Identity) -> HashSet<PaymentTx> {
        let data: HashSet<PaymentTx> = HashSet::new();
        self.successful_transactions_sent
            .get(&id)
            .unwrap_or(&data)
            .clone()
    }

    /// Function to compute the total amount of all unverified payments
    /// Input: takes in an identity which represents the router we are
    /// going to exclude from the total amount of all unverified payments.
    fn calculate_unverified_payments(&self, router: Identity) -> Uint256 {
        let mut total_unverified_payment: Uint256 = Uint256::from(0u32);
        for iterate in self.unvalidated_transactions.iter() {
            if iterate.payment.from == router && iterate.payment.to != router {
                total_unverified_payment += iterate.payment.amount;
            }
        }
        total_unverified_payment
    }

    /// Checks if we already have a given txid in our to_validate list
    /// true if we have it false if we do not
    fn check_for_unvalidated_tx(&self, ts: &ToValidate) -> bool {
        for tx in self.unvalidated_transactions.iter() {
            if tx.payment.txid == ts.payment.txid {
                return true;
            }
        }
        false
    }

    /// Message to insert transactions into payment validator, once inserted they will remain
    /// until they are validated, dropped for validity issues, or time out without being inserted
    /// into the blockchain. Transactions that are too old are prevented from being played back
    /// by using a history of successful transactions.
    /// This endpoint specifically (and only this one) is fully idempotent so that we can retry
    /// txid transmissions
    fn validate_later(&mut self, ts: ToValidate) -> Result<(), RitaCommonError> {
        if !self.successful_transactions.contains(&ts.payment)
            && !self.check_for_unvalidated_tx(&ts)
        {
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
    async fn tick_payment_validator(&mut self, chain: SystemChain) {
        // we panic on a failed receive so it should always be longer than the minimum
        // time we expect payments to take to enter the blockchain (the send timeout)
        assert!(PAYMENT_RECEIVE_TIMEOUT > PAYMENT_SEND_TIMEOUT);
        if !self.is_consistent() {
            warn!("Inconsistent payment validator!");
            // in a development env we want to draw attention to this case
            if cfg!(feature = "development") || cfg!(feature = "integration_test") {
                panic!("Inconsistent payment validator!");
            }
        }

        let our_address = settings::get_rita_common().payment.eth_address.unwrap();
        let mut to_delete = Vec::new();

        info!(
            "Attempting to validate {} transactions {}",
            self.unvalidated_transactions.len(),
            print_txids(&self.unvalidated_transactions)
        );

        let mut futs = Vec::new();
        for item in self.unvalidated_transactions.iter() {
            let elapsed = Instant::now().checked_duration_since(item.received);
            let from_us = item.payment.from.eth_address == our_address;

            if elapsed.is_some() && elapsed.unwrap() > PAYMENT_RECEIVE_TIMEOUT {
                error!(
                    "Incoming transaction {} has timed out, payment failed!",
                    format!("{:#066x}", item.payment.txid)
                );

                to_delete.push((item.clone(), false));
            }
            // no penalties for failure here, we expect to overpay one out of every few hundred
            // transactions
            else if elapsed.is_some() && from_us && elapsed.unwrap() > PAYMENT_SEND_TIMEOUT {
                error!(
                    "Outgoing transaction {:#066x} has timed out, payment failed!",
                    item.payment.txid
                );
                to_delete.push((item.clone(), false));
            } else {
                // we take all these futures and put them onto an array that we will execute
                // in parallel, this is essential on the exit where in the worst case scenario
                // we could have a thousand or more payments in the queue
                let fut = validate_transaction(item.clone(), chain);
                futs.push(fut);
            }
        }

        /// This is the number of tx we validate in a single join operation
        /// doing too many at once can cause system problems by opening many connections
        /// and spamming full nodes.
        const VALIDATE_BATCH_SIZE: usize = 10;
        let mut buf = Vec::new();
        for f in futs.into_iter() {
            if buf.len() < VALIDATE_BATCH_SIZE {
                buf.push(f)
            } else {
                // execute all of the above verification operations in parallel
                join_all(buf).await;
                buf = Vec::new();
            }
        }
        // check the last leftover futures in the array
        join_all(buf).await;

        for (tx, success) in to_delete.iter() {
            self.remove(*tx, *success)
        }
    }
}

/// Message to insert transactions into payment validator from another thread, once inserted they will remain
/// until they are validated, dropped for validity issues, or time out without being inserted
/// into the blockchain. Transactions that are too old are prevented from being played back
/// by using a history of successful transactions.
/// This endpoint specifically (and only this one) is fully idempotent so that we can retry
/// txid transmissions
pub fn validate_later(ts: ToValidate) -> Result<(), RitaCommonError> {
    // We hold the lock to prevent race condition between make_payment_v1 and make_payment_v2
    let successful_txs = get_all_successful_tx();
    let lock = &mut *HISTORY.write().unwrap();
    let payment_validator = get_payment_validator_write_ref(lock);
    if !successful_txs.contains(&ts.payment) && !check_for_unvalidated_tx(&ts, payment_validator) {
        // insert is safe to run multiple times just so long as we check successful tx's for duplicates
        payment_validator.unvalidated_transactions.insert(ts);
        Ok(())
    } else {
        Err(RitaCommonError::DuplicatePayment)
    }
}

/// This wrapper function handles validating a transaction on either Althea or Xdai based on the system chain
async fn validate_transaction(ts: ToValidate, chain: SystemChain) -> Option<(ToValidate, bool)> {
    match chain {
        SystemChain::Althea => handle_althea_tx_checking(ts.clone()).await,
        SystemChain::Xdai | SystemChain::Ethereum | SystemChain::Rinkeby => {
            handle_xdai_tx_checking(ts.clone()).await
        }
    }
}

async fn handle_althea_tx_checking(ts: ToValidate) -> Option<(ToValidate, bool)> {
    let cosmos_node_grpc = get_rita_common().payment.althea_grpc_list[0].clone();
    let althea_contact = Contact::new(
        &cosmos_node_grpc,
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();
    // convert to hex string
    let txhash = ts.payment.txid.to_str_radix(16);

    let althea_status = althea_contact.get_chain_status().await;
    let althea_transaction = althea_contact.get_tx_by_hash(txhash.clone()).await;

    match (althea_transaction, althea_status) {
        (Ok(transaction), Ok(ChainStatus::Moving { block_height })) => {
            let txs = decode_althea_microtx(transaction);
            handle_tx_messaging_althea(txs, ts.clone(), block_height)
        }
        (Ok(_), Ok(status)) => {
            error!(
                "Failed to check transaction due to chain status! {:?} {:?}",
                txhash, status
            );
            if cfg!(feature = "development") || cfg!(feature = "integration_test") {
                panic!(
                    "Failed to check transaction due to chain status! {:?} {:?}",
                    txhash, status
                );
            }
            None
        }
        _ => {
            trace!("Failed to check transaction {:?}", txhash);
            None
        }
    }
}

/// This function is used to validate transactions both incoming and outgoing, it must reject any payment
/// that is not correct and returns the payment and a boolean indicating if it was successful, if we do not
/// yet know if the payment was successful we return None
/// This function must handle the unique case of multiple message MicroTx being part of a single message
/// in this case only the first will be checked and the rest will be ignored. We could try to handle this
/// more gracefully but the only reason this would happen is in some sort of attack scenario otherwise
/// there's no reason not to aggregate the payments into a single message anyway
fn handle_tx_messaging_althea(
    transactions: Vec<MsgMicrotx>,
    ts: ToValidate,
    current_block: u64,
) -> Option<(ToValidate, bool)> {
    if transactions.is_empty() {
        error!("Microtx payment with no transactions!");
        if cfg!(feature = "development") || cfg!(feature = "integration_test") {
            panic!("Microtx payment with no transactions!");
        }
        return Some((ts, false));
    }
    let transaction = transactions[0];

    let amount: Coin = if let Some(amount) = transaction.amount {
        amount.into()
    } else {
        error!("Transaction with no amount!");
        if cfg!(feature = "development") || cfg!(feature = "integration_test") {
            panic!("Transaction with no amount!");
        }
        return Some((ts, false));
    };

    let reciver_address: AltheaAddress = match transaction.receiver.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Invalid receiver address! {}", e);
            if cfg!(feature = "development") || cfg!(feature = "integration_test") {
                panic!("Invalid reciever address!");
            }
            return Some((ts, false));
        }
    };

    let sender_address: AltheaAddress = match transaction.sender.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Invalid sender address! {}", e);
            if cfg!(feature = "development") || cfg!(feature = "integration_test") {
                panic!("Invalid sender address!");
            }
            return Some((ts, false));
        }
    };

    // Verify that denom is valid
    let mut denom: Option<Denom> = None;
    for d in get_rita_common()
        .payment
        .accepted_denoms
        .unwrap_or_default()
    {
        if amount.denom == d.1.denom {
            denom = Some(d.1);
        }
    }
    if denom.is_none() {
        error!(
            "Invalid Denom! We do not currently support {}!",
            amount.denom
        );
        return Some((ts, false));
    }

    let our_id = settings::get_rita_common().get_identity().unwrap();
    let our_address_althea = our_id.get_althea_address();

    // notice we get these values from the blockchain using 'transaction' not ts which may be a lie since we don't
    // actually cryptographically validate the txhash locally. Instead we just compare the value we get from the full
    // node
    let to_us = reciver_address == our_address_althea;
    let from_us = sender_address == our_address_althea;
    let value_correct = amount.amount == ts.payment.amount;

    if !value_correct {
        error!("Transaction with invalid amount!");
        return Some((ts, false));
    }

    match (to_us, from_us) {
        // we were successfully paid
        (true, false) => {
            info!(
                "payment {:#066x} from {} for {} {} successfully validated!",
                ts.payment.txid,
                reciver_address,
                amount,
                denom.clone().expect("Already verified existance").denom
            );

            // update debt keeper with the details of this payment
            let _ = payment_received(
                ts.payment.from,
                ts.payment.amount,
                denom.expect("How did this happen when we already verified existence"),
            );
            // update the usage tracker with the details of this payment
            update_payments(ts.payment);
            Some((ts, false))
        }
        // we successfully paid someone
        (false, true) => {
            info!(
                "payment {:#066x} from {} for {} {} successfully sent!",
                ts.payment.txid,
                reciver_address,
                amount,
                denom.clone().expect("Already verified existance").denom
            );

            // update debt keeper with the details of this payment
            payment_succeeded(
                ts.payment.to,
                ts.payment.amount,
                denom.expect("How did this happen when we already verified existence"),
            )
            .unwrap();
            // update the usage tracker with the details of this payment
            update_payments(ts.payment);

            Some((ts, true))
        }
        (true, true) => {
            error!("Transaction to ourselves!");
            Some((ts, false))
        }
        (false, false) => {
            error!("Transaction has nothing to do with us?");
            Some((ts, true))
        }
    }
}

/// Handles decoding of an Althea MicroTx type from the transaction response query
/// since CommosSdk allows for multiple messages in a single transaction, we need to
/// handle that possibility. Any messages that are not of type MsgMicroTx are ignored
fn decode_althea_microtx(response: GetTxResponse) -> Vec<MsgMicrotx> {
    if let Some(tx_resp) = response.tx_response {
        let tx = match tx_resp.tx {
            Some(a) => a.value,
            None => {
                // this exists to handle a pointer in go, it should never happen
                // unless the server has a go error where this value is nil on return
                error!("Althea chain tx {:?} has no tx field?", tx_resp);
                if cfg!(feature = "development")
                    || cfg!(feature = "integration_test")
                    || cfg!(feature = "test")
                {
                    panic!("Althea chain tx {:?} has no tx field?", tx_resp);
                }
                return Vec::new();
            }
        };

        // Decode TxRaw
        let raw_tx_any = prost_types::Any {
            type_url: "/cosmos.tx.v1beta1.Tx".to_string(),
            value: tx,
        };
        let tx_raw: TxRaw = match decode_any(raw_tx_any) {
            Ok(a) => a,
            Err(e) => {
                error!("Unable to decode raw_tx with {}", e);
                if cfg!(feature = "development")
                    || cfg!(feature = "integration_test")
                    || cfg!(feature = "test")
                {
                    panic!("Unable to decode raw_tx with {}", e);
                }
                return Vec::new();
            }
        };

        // Decode TxBody
        let body_any = prost_types::Any {
            type_url: "/cosmos.tx.v1beta1.TxBody".to_string(),
            value: tx_raw.body_bytes,
        };
        let tx_body: TxBody = match decode_any(body_any) {
            Ok(a) => a,
            Err(e) => {
                error!("Unable to decode body_any with {}", e);
                if cfg!(feature = "development")
                    || cfg!(feature = "integration_test")
                    || cfg!(feature = "test")
                {
                    panic!("Unable to decode body_any with {}", e);
                }
                return Vec::new();
            }
        };

        let mut ret = Vec::new();

        // Decode MsgMicroTx and send each one to validator
        for message in tx_body.messages {
            let msg_send = prost_types::Any {
                type_url: MSG_MICROTX_TYPE_URL.to_owned(),
                value: message.value.clone(),
            };
            let msg_send: Result<MsgMicrotx, _> = decode_any(msg_send);
            if let Ok(msg) = msg_send {
                ret.push(msg);
            }
        }
        ret
    } else {
        error!("Althea chain tx {:?} has no tx_response field?", response);
        if cfg!(feature = "development")
            || cfg!(feature = "integration_test")
            || cfg!(feature = "test")
        {
            panic!("Althea chain tx {:?} has no tx_response field?", response);
        }
        Vec::new()
    }
}

/// This function validates transactions on the xDai chain, making a series of requests
/// and then checking the results to determine if the transaction is valid. If the transaction
/// is valid or invalid Some(true) or Some(false) respectively is returned. If the transaction
/// is still pending None is returned.
async fn handle_xdai_tx_checking(ts: ToValidate) -> Option<(ToValidate, bool)> {
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_VERIFICATION_TIMEOUT);

    let txid = ts.payment.txid;

    let eth_block_num = web3.eth_block_number().await;
    let eth_transaction = web3.eth_get_transaction_by_hash(txid).await;
    match (eth_transaction, eth_block_num) {
        (Ok(Some(transaction)), Ok(block_num)) => {
            handle_tx_messaging_xdai(ts.payment.txid, transaction, ts.clone(), block_num)
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
    match transaction {
        TransactionResponse::Eip1559 {
            to,
            from,
            value,
            block_number,
            ..
        } => (to, from, value, block_number),
        TransactionResponse::Eip2930 {
            to,
            from,
            value,
            block_number,
            ..
        } => (to, from, value, block_number),
        TransactionResponse::Legacy {
            to,
            from,
            value,
            block_number,
            ..
        } => (to, from, value, block_number),
    }
}

/// This function is used to validate transactions both incoming and outgoing, it must reject any payment
/// that is not correct and returns the payment and a boolean indicating if it was successful, if we do not
/// yet know if the payment was successful we return None
fn handle_tx_messaging_xdai(
    txid: Uint256,
    transaction: TransactionResponse,
    ts: ToValidate,
    current_block: Uint256,
) -> Option<(ToValidate, bool)> {
    let from_address = ts.payment.from.eth_address;
    let amount = ts.payment.amount;
    let pmt = ts.payment;
    let our_address = settings::get_rita_common()
        .payment
        .eth_address
        .expect("No Address!");

    let (tx_to, tx_from, tx_value, tx_block_number) = get_xdai_transaction_details(transaction);

    let to = match tx_to {
        Some(val) => val,
        None => {
            error!("Invalid TX! No destination!");
            return Some((ts, false));
        }
    };

    // notice we get these values from the blockchain using 'transaction' not ts which may be a lie since we don't
    // actually cryptographically validate the txhash locally. Instead we just compare the value we get from the full
    // node
    let to_us = to == our_address;
    let from_us = tx_from == our_address;
    let value_correct = tx_value == amount;
    let is_in_chain = payment_in_chain_xdai(current_block, tx_block_number);
    let is_old = payment_is_old(current_block, tx_block_number);

    if !value_correct {
        error!("Transaction with invalid amount!");
        return Some((ts, false));
    }

    if is_old {
        error!("Transaction is more than 6 hours old! {:#066x}", txid);
        return Some((ts, false));
    }

    match (to_us, from_us, is_in_chain) {
        // we were successfully paid
        (true, false, true) => {
            info!(
                "payment {:#066x} from {} for {} wei successfully validated!",
                txid, from_address, amount
            );
            // update debt keeper with the details of this payment
            let _ = payment_received(
                pmt.from,
                pmt.amount,
                Denom {
                    denom: DEBT_KEEPER_DENOM.to_string(),
                    decimal: DEBT_KEEPER_DENOM_DECIMAL,
                },
            );

            // update the usage tracker with the details of this payment
            update_payments(pmt);

            Some((ts, true))
        }
        // we successfully paid someone
        (false, true, true) => {
            info!(
                "payment {:#066x} from {} for {} wei successfully sent!",
                txid, from_address, amount
            );
            // update debt keeper with the details of this payment
            let _ = payment_succeeded(
                pmt.to,
                pmt.amount,
                Denom {
                    denom: DEBT_KEEPER_DENOM.to_string(),
                    decimal: DEBT_KEEPER_DENOM_DECIMAL,
                },
            );

            // update the usage tracker with the details of this payment
            update_payments(pmt);

            Some((ts, true))
        }
        (true, true, _) => {
            error!("Transaction to ourselves!");
            Some((ts, false))
        }
        (false, false, _) => {
            error!("Transaction has nothing to do with us?");
            Some((ts, false))
        }
        (_, _, false) => {
            //transaction waiting for validation, do nothingi
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

#[cfg(test)]
mod tests {
    use actix_async::System;
    use crate::usage_tracker::tests::test::random_identity;
    use super::*;

    fn generate_fake_payment() -> ToValidate {
        let amount: u128 = rand::random();
        let txid: u128 = rand::random();
        let tx = PaymentTx {
            to: random_identity(),
            from: random_identity(),
            amount: amount.into(),
            txid: txid.into(),
        };
        ToValidate {
            payment: tx,
            received: Instant::now(),
        }
    }

    #[test]
    /// Attempts to insert a duplicate tx into the to_validate list
    fn test_duplicate_tx() {
        // check that we can't put duplicates in to_validate
        let payment = generate_fake_payment();
        assert!(validate_later(payment.clone()).is_ok());
        assert!(validate_later(payment).is_err());
        // check that we can't put dupliates in that we have already validated
        let payment = generate_fake_payment();
        add_successful_tx(payment.clone().payment);
        assert!(validate_later(payment).is_err());
    }

    #[test]
    fn test_payment_txid_datastore() {
        let client_id = Identity {
            mesh_ip: "fd00::1".parse().unwrap(),
            eth_address: "0xE39bDB2e345ACf7B0C7B1A28dFA26288C3094A6A"
                .parse()
                .unwrap(),
            wg_public_key: "NZnbEv9w5lC3JG3hacwh5cq8C5NnsAUJLrNKYL91fS0="
                .parse()
                .unwrap(),
            nickname: None,
        };

        let exit_id = Identity {
            mesh_ip: "fd00::1337".parse().unwrap(),
            eth_address: "0xE39bDB2e345ACf7B0C7B1A28dFA26288C3094A6A"
                .parse()
                .unwrap(),
            wg_public_key: "PiMD6fCsgyNKwz9AVqP/GRT3+o6h6e9Y0KPEdFct/yw="
                .parse()
                .unwrap(),
            nickname: None,
        };

        let mut sent_hashset = HashSet::new();

        let pmt1 = PaymentTx {
            to: exit_id,
            from: client_id,
            amount: 10u8.into(),
            txid: 1u8.into(),
        };

        store_payment(pmt1);
        sent_hashset.insert(pmt1);
        assert_eq!(get_payment_txids(pmt1.to), sent_hashset);

        let pmt2 = PaymentTx {
            to: exit_id,
            from: client_id,
            amount: 100u8.into(),
            txid: 2u8.into(),
        };
        store_payment(pmt2);

        sent_hashset.insert(pmt2);
        assert_eq!(get_payment_txids(pmt2.to), sent_hashset);

        let pmt3 = PaymentTx {
            to: exit_id,
            from: client_id,
            amount: 100u8.into(),
            txid: 2u8.into(),
        };

        store_payment(pmt3);

        assert_eq!(get_payment_txids(pmt3.to), sent_hashset);
    }

    #[ignore]
    #[test]
    fn test_althea_chain_response() {
        let runner = System::new();
        runner.block_on(async move {
            let contact = Contact::new(
                "http://rpc.althea.zone:9090",
                ALTHEA_CONTACT_TIMEOUT,
                "althea",
            )
            .unwrap();

            let tx = contact
                .get_tx_by_hash(
                    "B0943ECCC5565A39D021EE815A82006B01FC87A9BED4EBDD0A448AC161007FF0".to_string(),
                )
                .await
                .expect("Unable to get tx by hash");
            let tx = decode_althea_microtx(tx);
        });
    }
}
