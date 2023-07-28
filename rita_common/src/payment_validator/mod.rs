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
use crate::KI;
use althea_types::Denom;
use althea_types::Identity;
use althea_types::PaymentTx;
use clarity::Address;
use cosmos_sdk_proto_althea::cosmos::bank::v1beta1::MsgSend;
use cosmos_sdk_proto_althea::cosmos::tx::v1beta1::{TxBody, TxRaw};
use deep_space::client::ChainStatus;
use deep_space::utils::decode_any;
use deep_space::Address as AltheaAddress;
use deep_space::Contact;
use futures::future::join;
use futures::future::join_all;
use num256::Uint256;
use num_traits::Num;
use settings::get_rita_common;
use settings::DEBT_KEEPER_DENOM;
use settings::DEBT_KEEPER_DENOM_DECIMAL;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Write as _;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Arc;
use std::sync::RwLock;
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
pub const PAYMENT_SEND_TIMEOUT: Duration = Duration::from_secs(60u64);
/// How many blocks before we assume finality
const BLOCKS_TO_CONFIRM: u32 = 4;
/// How old does a txid need to be before we don't accept it?
/// this is 12 hours
const BLOCKS_TO_OLD: u32 = 1440;

// These parameters are used to set up a contact with althea chain
pub const ALTHEA_CHAIN_PREFIX: &str = "althea";
pub const ALTHEA_CONTACT_TIMEOUT: Duration = Duration::from_secs(30);

lazy_static! {
    static ref HISTORY: Arc<RwLock<HashMap<u32, PaymentValidator>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Gets Payment validator copy from the static ref, or default if no value has been set
pub fn get_payment_validator() -> PaymentValidator {
    let netns = KI.check_integration_test_netns();
    HISTORY
        .read()
        .unwrap()
        .clone()
        .get(&netns)
        .cloned()
        .unwrap_or_default()
}

/// Gets a write ref for the payment validator lock, since this is a mutable reference
/// the lock will be held until you drop the return value, this lets the caller abstract the namespace handling
/// but still hold the lock in the local thread to prevent parallel modification
pub fn get_payment_validator_write_ref(
    input: &mut HashMap<u32, PaymentValidator>,
) -> &mut PaymentValidator {
    let netns = KI.check_integration_test_netns();
    input.entry(netns).or_insert_with(PaymentValidator::default);
    input.get_mut(&netns).unwrap()
}

/// Details we pass into handle_tx_handling while validating a transaction
/// These are made options in case althea chain parsing fails
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct TransactionDetails {
    pub to: AltheaAddress,
    pub from: AltheaAddress,
    pub amount: Uint256,
    pub denom: String,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum PaymentAddress {
    Xdai(Address),
    Althea(AltheaAddress),
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ToValidate {
    /// details of the payment from the user in the format they where sent
    pub payment: PaymentTx,
    /// When we got this tx
    pub received: Instant,
    /// if we have managed to talk to a full node about this
    /// transaction ever
    pub checked: bool,
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

#[derive(Clone)]
pub struct PaymentValidator {
    unvalidated_transactions: HashSet<ToValidate>,
    /// All successful transactions sent FROM this router, mapped To Address-> list of PaymentTx
    successful_transactions_sent: HashMap<Identity, HashSet<PaymentTx>>,
    /// All successful txids this router has verified, used to check for duplicate payments
    successful_transactions: HashSet<PaymentTx>,
}

// Setters and getters HISTORY lazy static
pub fn add_unvalidated_transaction(tx: ToValidate) {
    let writer = &mut *HISTORY.write().unwrap();
    get_payment_validator_write_ref(writer)
        .unvalidated_transactions
        .insert(tx);
}

pub fn remove_unvalidated_transaction(tx: ToValidate) -> bool {
    let writer = &mut *HISTORY.write().unwrap();
    get_payment_validator_write_ref(writer)
        .unvalidated_transactions
        .remove(&tx)
}

pub fn get_unvalidated_transactions() -> HashSet<ToValidate> {
    get_payment_validator().unvalidated_transactions
}

pub fn get_successful_tx_sent() -> HashMap<Identity, HashSet<PaymentTx>> {
    get_payment_validator().successful_transactions_sent
}

pub fn set_successful_tx_sent(v: HashMap<Identity, HashSet<PaymentTx>>) {
    let writer = &mut *HISTORY.write().unwrap();
    get_payment_validator_write_ref(writer).successful_transactions_sent = v;
}

pub fn get_all_successful_tx() -> HashSet<PaymentTx> {
    get_payment_validator().successful_transactions
}

pub fn add_successful_tx(v: PaymentTx) {
    let writer = &mut *HISTORY.write().unwrap();
    get_payment_validator_write_ref(writer)
        .successful_transactions
        .insert(v);
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

/// This stores payments of all tx that we sent to different nodes.
pub fn store_payment(pmt: PaymentTx) {
    let mut data = get_successful_tx_sent();
    let neighbor = pmt.to;

    if let Some(e) = data.get_mut(&neighbor) {
        e.insert(pmt);
    } else {
        let mut set = HashSet::new();
        set.insert(pmt);
        data.insert(neighbor, set);
    }

    set_successful_tx_sent(data);
}

/// Given an id, get all payments made to that id
pub fn get_payment_txids(id: Identity) -> HashSet<PaymentTx> {
    let data: HashSet<PaymentTx> = HashSet::new();
    get_payment_validator()
        .successful_transactions_sent
        .get(&id)
        .unwrap_or(&data)
        .clone()
}

/// Function to compute the total amount of all unverified payments
/// Input: takes in an identity which represents the router we are
/// going to exclude from the total amount of all unverified payments.
pub fn calculate_unverified_payments(router: Identity) -> Uint256 {
    let payments_to_process = get_unvalidated_transactions();
    let mut total_unverified_payment: Uint256 = Uint256::from(0u32);
    for iterate in payments_to_process.iter() {
        if iterate.payment.from == router && iterate.payment.to != router {
            total_unverified_payment += iterate.payment.amount;
        }
    }
    total_unverified_payment
}

/// Checks if we already have a given txid in our to_validate list
/// true if we have it false if we do not
fn check_for_unvalidated_tx(ts: &ToValidate, payment_validator: &mut PaymentValidator) -> bool {
    for tx in &payment_validator.unvalidated_transactions {
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

#[derive(Clone)]
struct Remove {
    tx: ToValidate,
    success: bool,
}

/// Removes a transaction from the pending validation queue, it may either
/// have been discovered to be invalid or have been successfully accepted
fn remove(msg: Remove) {
    // Try removing both check and uncheked versions of txs
    let mut msg_checked = msg.clone();
    msg_checked.tx.checked = true;
    let was_present = remove_unvalidated_transaction(msg.tx.clone())
        | remove_unvalidated_transaction(msg_checked.tx);
    // store successful transactions so that they can't be played back to us, at least
    // during this session
    if msg.success {
        add_successful_tx(msg.tx.payment.clone());
    }
    if was_present {
        info!("Transaction {} was removed", msg.tx);
    } else {
        warn!("Transaction {} was double removed", msg.tx);
        // in a development env we want to draw attention to this case
        #[cfg(feature = "development")]
        panic!("Transaction double removed!");
    }
}

/// Marks a transaction as 'checked' in that we have talked to a full node about it
/// if we fail to talk to a full node about a transaction for the full duration of
/// the timeout we attempt to restart our node.
fn checked(msg: ToValidate) {
    if remove_unvalidated_transaction(msg.clone()) {
        let mut checked_tx = msg;
        checked_tx.checked = true;
        info!("We successfully checked tx {:?}", checked_tx);
        add_unvalidated_transaction(checked_tx);
    } else {
        error!("Tried to mark a tx {:?} we don't have as checked!", msg);
        #[cfg(feature = "development")]
        panic!("Tried to mark a tx {:?} we don't have as checked!", msg);
    }
}

pub async fn validate() {
    // we panic on a failed receive so it should always be longer than the minimum
    // time we expect payments to take to enter the blockchain (the send timeout)
    assert!(PAYMENT_RECEIVE_TIMEOUT > PAYMENT_SEND_TIMEOUT);

    let our_address = settings::get_rita_common().payment.eth_address.unwrap();
    let mut to_delete = Vec::new();

    let unvalidated_transactions = get_unvalidated_transactions();
    info!(
        "Attempting to validate {} transactions {}",
        unvalidated_transactions.len(),
        print_txids(&unvalidated_transactions)
    );

    let mut futs = Vec::new();
    for item in unvalidated_transactions {
        let elapsed = Instant::now().checked_duration_since(item.received);
        let from_us = item.payment.from.eth_address == our_address;

        if elapsed.is_some() && elapsed.unwrap() > PAYMENT_RECEIVE_TIMEOUT {
            error!(
                "Incoming transaction {} has timed out, payment failed!",
                format!("{:#066x}", item.payment.txid)
            );

            // if we fail to so much as get a block height for the full duration of a payment timeout, we have problems and probably we are not counting payments correctly potentially leading to wallet
            // drain and other bad outcomes. So we should restart with the hope that the system will be restored to a working state by this last resort action
            if !item.checked {
                let msg = format!("We failed to check txid {:#066x} against full nodes for the full duration of it's timeout period, please check full nodes", item.payment.txid);
                error!("{}", msg);

                let sys = actix_async::System::current();
                sys.stop_with_code(121);
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
                item.payment.txid
            );
            to_delete.push(item.clone());
        } else {
            // we take all these futures and put them onto an array that we will execute
            // in parallel, this is essential on the exit where in the worst case scenario
            // we could have a thousand or more payments in the queue
            let fut = validate_transaction(item);
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

    for item in to_delete.iter() {
        remove_unvalidated_transaction(item.clone());
    }
}

/// Attempt to validate that a given transaction has been accepted into the blockchain and
/// is at least some configurable number of blocks behind the head.
pub async fn validate_transaction(ts: ToValidate) {
    trace!("validating transaction");
    // check both in parallel since we don't know what chain this is on
    join(
        handle_althea_tx_checking(ts.clone()),
        handle_xdai_tx_checking(ts),
    )
    .await;
}

async fn handle_xdai_tx_checking(ts: ToValidate) {
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_VERIFICATION_TIMEOUT);

    let txid = ts.payment.txid;

    let eth_block_num = web3.eth_block_number().await;
    let eth_transaction = web3.eth_get_transaction_by_hash(txid).await;
    match (eth_transaction, eth_block_num) {
        (Ok(Some(transaction)), Ok(block_num)) => {
            if !ts.checked {
                checked(ts.clone());
            }
            handle_tx_messaging_xdai(ts.payment.txid, transaction, ts.clone(), block_num);
        }
        (Ok(None), _) => {
            // we have a response back from the full node that this tx is not in the mempool this
            // satisfies our checked requirement
            if !ts.checked {
                checked(ts.clone());
            }
        }
        (Err(_), Ok(_)) => {
            // we get an error from the full node but a successful block request, clearly we can contact
            // the full node so the transaction check has been attempted
            if !ts.checked {
                checked(ts.clone());
            }
        }
        (Ok(Some(_)), Err(_)) => trace!("Failed to check transaction {:#066x}", txid),
        (Err(_), Err(_)) => trace!("Failed to check transaction {:#066x}", txid),
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

async fn handle_althea_tx_checking(ts: ToValidate) {
    let cosmos_node_grpc = get_rita_common().payment.althea_grpc_list[0].clone();
    let althea_contact = Contact::new(
        &cosmos_node_grpc,
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();
    // convert to hex string
    let txhash = ts.payment.txid.to_str_radix(16);

    let althea_transaction = althea_contact.get_tx_by_hash(txhash.clone()).await;
    let althea_chain_status = althea_contact.get_chain_status().await;

    match (althea_transaction, althea_chain_status) {
        (Ok(transaction), Ok(chain_status)) => {
            if let Some(tx_resp) = transaction.tx_response {
                if !ts.checked {
                    checked(ts.clone());
                }

                let tx = match tx_resp.tx {
                    Some(a) => a.value,
                    None => {
                        error!("Althea chain tx {:?} has no tx field?", tx_resp);
                        return;
                    }
                };

                if let ChainStatus::Moving { block_height: _ } = chain_status {
                    // Decode TxRaw
                    let raw_tx_any = prost_types::Any {
                        type_url: "/cosmos.tx.v1beta1.Tx".to_string(),
                        value: tx,
                    };
                    let tx_raw: TxRaw = match decode_any(raw_tx_any) {
                        Ok(a) => a,
                        Err(e) => {
                            error!("Unable to decode raw_tx with {}", e);
                            return;
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
                            return;
                        }
                    };

                    // Decode MsgSend and send each one to validator
                    for message in tx_body.messages {
                        let msg_send = prost_types::Any {
                            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                            value: message.value.clone(),
                        };
                        let msg_send: Result<MsgSend, _> = decode_any(msg_send);
                        if let Ok(msg) = msg_send {
                            for coin_tx in msg.amount {
                                let transaction_details = TransactionDetails {
                                    to: match msg.to_address.parse() {
                                        Ok(a) => a,
                                        Err(e) => {
                                            error!(
                                                    "Unable to parse send address {}f for tx {} with {}",
                                                    msg.to_address,
                                                    ts.clone(),
                                                    e
                                                );
                                            continue;
                                        }
                                    },
                                    from: match msg.from_address.parse() {
                                        Ok(a) => a,
                                        Err(e) => {
                                            error!(
                                                "Unable to parse send address {} for tx {} with {}",
                                                msg.to_address,
                                                ts.clone(),
                                                e
                                            );
                                            continue;
                                        }
                                    },
                                    amount: match Uint256::from_str_radix(&coin_tx.amount, 10) {
                                        Ok(a) => a,
                                        Err(e) => {
                                            error!(
                                                "Unable to parse amount : {:?} for tx {:?} with {}",
                                                coin_tx.amount,
                                                ts.clone(),
                                                e
                                            );
                                            continue;
                                        }
                                    },
                                    denom: coin_tx.denom,
                                };
                                handle_tx_messaging_althea(transaction_details, ts.clone());
                            }
                        }
                    }
                } else {
                    error!(
                        "Unable to check transaction id {} because of chain status {:?}",
                        txhash.clone(),
                        chain_status
                    )
                }
            }
        }
        (Ok(transaction), _) => {
            // we have a response back from the full node that this tx is not in the mempool this
            // satisfies our checked requirement
            if transaction.tx_response.is_some() && !ts.checked {
                checked(ts.clone());
            }
        }
        (Err(_), Ok(_)) => {
            // we get an error from the full node but a successful block request, clearly we can contact
            // the full node so the transaction check has been attempted
            if !ts.checked {
                checked(ts.clone());
            }
        }
        _ => trace!("Failed to check transaction {:?}", txhash),
    }
}

fn handle_tx_messaging_xdai(
    txid: Uint256,
    transaction: TransactionResponse,
    ts: ToValidate,
    current_block: Uint256,
) {
    let from_address = ts.payment.from.eth_address;
    let amount = ts.payment.amount;
    let pmt = ts.payment.clone();
    let our_address = settings::get_rita_common()
        .payment
        .eth_address
        .expect("No Address!");

    let (tx_to, tx_from, tx_value, tx_block_number) = get_xdai_transaction_details(transaction);

    let to = match tx_to {
        Some(val) => val,
        None => {
            error!("Invalid TX! No destination!");
            remove(Remove {
                tx: ts,
                success: false,
            });
            return;
        }
    };

    // notice we get these values from the blockchain using 'transaction' not ts which may be a lie since we don't
    // actually cryptographically validate the txhash locally. Instead we just compare the value we get from the full
    // node
    let to_us = to == our_address;
    let from_us = tx_from == our_address;
    let value_correct = tx_value == amount;
    let is_in_chain = payment_in_chain(current_block, tx_block_number);
    let is_old = payment_is_old(current_block, tx_block_number);

    if !value_correct {
        error!("Transaction with invalid amount!");
        remove(Remove {
            tx: ts,
            success: false,
        });
        return;
    }

    if is_old {
        error!("Transaction is more than 6 hours old! {:#066x}", txid);
        remove(Remove {
            tx: ts,
            success: false,
        });
        return;
    }

    match (to_us, from_us, is_in_chain) {
        // we were successfully paid
        (true, false, true) => {
            // remove this transaction from our storage
            remove(Remove {
                tx: ts,
                success: true,
            });
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
        }
        // we successfully paid someone
        (false, true, true) => {
            info!(
                "payment {:#066x} from {} for {} wei successfully sent!",
                txid, from_address, amount
            );
            // remove this transaction from our storage
            remove(Remove {
                tx: ts,
                success: true,
            });
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
            update_payments(pmt.clone());

            // Store this payment as a receipt to send in the future if this receiver doesnt see the payment
            store_payment(pmt);
        }
        (true, true, _) => {
            error!("Transaction to ourselves!");
            remove(Remove {
                tx: ts,
                success: false,
            });
        }
        (false, false, _) => {
            error!("Transaction has nothing to do with us?");
            remove(Remove {
                tx: ts,
                success: false,
            });
        }
        (_, _, false) => {
            //transaction waiting for validation, do nothing
        }
    }
}

/// Handles the tx response from the full node and it's various cases
/// pulled out of validate_transaction purely for cosmetic reasons
fn handle_tx_messaging_althea(transaction: TransactionDetails, ts: ToValidate) {
    let pmt = ts.payment.clone();

    // txid is for eth chain and txhash is for althea chain, only one of these should be
    // Some(..). This was verified before
    let txid = ts.payment.txid;

    // Verify that denom is valid
    let mut denom: Option<Denom> = None;
    for d in get_rita_common()
        .payment
        .accepted_denoms
        .unwrap_or(HashMap::new())
    {
        if transaction.denom == d.1.denom {
            denom = Some(d.1);
        }
    }
    if denom.is_none() {
        error!(
            "Invalid Denom! We do not currently support {}!",
            transaction.denom
        );
        remove(Remove {
            tx: ts,
            success: false,
        });
        return;
    }

    let amount = ts.payment.amount;

    let our_id = settings::get_rita_common().get_identity().unwrap();
    let our_address_althea = our_id.get_althea_address();

    let to = transaction.to;
    let from = transaction.from;

    // notice we get these values from the blockchain using 'transaction' not ts which may be a lie since we don't
    // actually cryptographically validate the txhash locally. Instead we just compare the value we get from the full
    // node
    let to_us = to == our_address_althea;
    let from_us = from == our_address_althea;
    let value_correct = transaction.amount == amount;

    if !value_correct {
        error!("Transaction with invalid amount!");
        remove(Remove {
            tx: ts,
            success: false,
        });
        return;
    }

    match (to_us, from_us) {
        // we were successfully paid
        (true, false) => {
            // remove this transaction from our storage
            remove(Remove {
                tx: ts,
                success: true,
            });
            info!(
                "payment {:#066x} from {} for {} {} successfully validated!",
                txid,
                from,
                amount,
                denom.clone().expect("Already verified existance").denom
            );

            // update debt keeper with the details of this payment
            let _ = payment_received(
                pmt.from,
                pmt.amount,
                denom.expect("How did this happen when we already verified existence"),
            );
            // update the usage tracker with the details of this payment
            update_payments(pmt);
        }
        // we successfully paid someone
        (false, true) => {
            info!(
                "payment {:#066x} from {} for {} {} successfully sent!",
                txid,
                from,
                amount,
                denom.clone().expect("Already verified existance").denom
            );

            // remove this transaction from our storage
            remove(Remove {
                tx: ts,
                success: true,
            });

            // update debt keeper with the details of this payment
            let _ = payment_succeeded(
                pmt.to,
                pmt.amount,
                denom.expect("How did this happen when we already verified existence"),
            );
            // update the usage tracker with the details of this payment
            update_payments(pmt.clone());

            // Store this payment as a receipt to send in the future if this receiver doesnt see the payment
            store_payment(pmt);
        }
        (true, true) => {
            error!("Transaction to ourselves!");
            remove(Remove {
                tx: ts,
                success: false,
            });
        }
        (false, false) => {
            error!("Transaction has nothing to do with us?");
            remove(Remove {
                tx: ts,
                success: false,
            });
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
        write!(output, "{item} ,").unwrap();
    }
    output
}

#[cfg(test)]
mod tests {
    use actix_async::System;
    use cosmos_sdk_proto_althea::cosmos::bank::v1beta1::MsgSend;
    use deep_space::utils::decode_any;

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
            checked: false,
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

        store_payment(pmt1.clone());
        sent_hashset.insert(pmt1.clone());
        assert_eq!(get_payment_txids(pmt1.to), sent_hashset);

        let pmt2 = PaymentTx {
            to: exit_id,
            from: client_id,
            amount: 100u8.into(),
            txid: 2u8.into(),
        };
        store_payment(pmt2.clone());

        sent_hashset.insert(pmt2.clone());
        assert_eq!(get_payment_txids(pmt2.to), sent_hashset);

        let pmt3 = PaymentTx {
            to: exit_id,
            from: client_id,
            amount: 100u8.into(),
            txid: 2u8.into(),
        };

        store_payment(pmt3.clone());

        assert_eq!(get_payment_txids(pmt3.to), sent_hashset);
    }

    #[ignore]
    #[test]
    fn test_althea_chain_response() {
        let runner = System::new();
        runner.block_on(async move {
            let contact =
                Contact::new("http://althea.zone:9090", ALTHEA_CONTACT_TIMEOUT, "althea").unwrap();

            let tx = contact
                .get_tx_by_hash(
                    "B0943ECCC5565A39D021EE815A82006B01FC87A9BED4EBDD0A448AC161007FF0".to_string(),
                )
                .await
                .expect("Unable to get tx by hash");
            println!("{:?}", tx.tx_response.clone().unwrap().tx);

            let raw_tx_any = prost_types::Any {
                type_url: "/cosmos.tx.v1beta1.Tx".to_string(),
                value: tx.tx_response.unwrap().tx.unwrap().value,
            };
            let tx_raw: TxRaw = decode_any(raw_tx_any).unwrap();

            println!("{:?}", tx_raw);

            let body_any = prost_types::Any {
                type_url: "/cosmos.tx.v1beta1.TxBody".to_string(),
                value: tx_raw.body_bytes,
            };
            let tx_body: TxBody = decode_any(body_any).unwrap();

            println!("{:?}", tx_body);

            for message in tx_body.messages {
                let msg_send = prost_types::Any {
                    type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                    value: message.value.clone(),
                };
                let msg_send: Result<MsgSend, _> = decode_any(msg_send);

                println!("\n\n{:?}", msg_send);
            }
        });
    }
}
