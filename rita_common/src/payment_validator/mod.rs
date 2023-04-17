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
use futures::future::join_all;
use num256::Uint256;
use num_traits::Num;
use settings::get_rita_common;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Write as _;
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
    static ref HISTORY: Arc<RwLock<PaymentValidator>> =
        Arc::new(RwLock::new(PaymentValidator::new()));
}

/// Details we pass into handle_tx_handling while validating a transaction
/// These are made options in case althea chain parsing fails
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct TransactionDetails {
    pub to: Option<PaymentAddress>,
    pub from: Option<PaymentAddress>,
    pub amount: Option<Uint256>,
    pub denom: String,
    pub block_num: Option<Uint256>,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum PaymentAddress {
    Xdai(Address),
    Althea(AltheaAddress),
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
    /// All successful transactions sent FROM this router, mapped To Address-> list of PaymentTx
    successful_transactions_sent: HashMap<Identity, HashSet<PaymentTx>>,
    /// All successful txids this router has verified, used to check for duplicate payments
    successful_transactions: HashSet<PaymentTx>,
}

// Setters and getters HISTORY lazy static
pub fn add_unvalidated_transaction(tx: ToValidate) {
    HISTORY.write().unwrap().unvalidated_transactions.insert(tx);
}

pub fn remove_unvalidated_transaction(tx: ToValidate) -> bool {
    HISTORY
        .write()
        .unwrap()
        .unvalidated_transactions
        .remove(&tx)
}

pub fn get_unvalidated_transactions() -> HashSet<ToValidate> {
    HISTORY.read().unwrap().unvalidated_transactions.clone()
}

pub fn get_successful_tx_sent() -> HashMap<Identity, HashSet<PaymentTx>> {
    HISTORY
        .write()
        .unwrap()
        .successful_transactions_sent
        .clone()
}

pub fn set_successful_tx_sent(v: HashMap<Identity, HashSet<PaymentTx>>) {
    HISTORY.write().unwrap().successful_transactions_sent = v;
}

pub fn get_all_successful_tx() -> HashSet<PaymentTx> {
    HISTORY.read().unwrap().successful_transactions.clone()
}

pub fn add_successful_tx(v: PaymentTx) {
    HISTORY.write().unwrap().successful_transactions.insert(v);
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

    if let std::collections::hash_map::Entry::Vacant(e) = data.entry(neighbor) {
        let mut set = HashSet::new();
        set.insert(pmt);
        e.insert(set);
    } else {
        let set = data
            .get_mut(&neighbor)
            .expect("This key should have an initialized set");
        set.insert(pmt);
    }

    set_successful_tx_sent(data);
}

/// Given an id, get all payments made to that id
pub fn get_payment_txids(id: Identity) -> HashSet<PaymentTx> {
    let data: HashSet<PaymentTx> = HashSet::new();
    HISTORY
        .read()
        .unwrap()
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

/// Message to insert transactions into payment validator, once inserted they will remain
/// until they are validated, dropped for validity issues, or time out without being inserted
/// into the blockchain. Transactions that are too old are prevented from being played back
/// by using a history of successful transactions.
/// This endpoint specifically (and only this one) is fully idempotent so that we can retry
/// txid transmissions
pub fn validate_later(ts: ToValidate) -> Result<(), RitaCommonError> {
    if !get_all_successful_tx().contains(&ts.payment) {
        // insert is safe to run multiple times just so long as we check successful tx's for duplicates
        add_unvalidated_transaction(ts);
    }
    Ok(())
}

struct Remove {
    tx: ToValidate,
    success: bool,
}

/// Removes a transaction from the pending validation queue, it may either
/// have been discovered to be invalid or have been successfully accepted
fn remove(msg: Remove) {
    let was_present = remove_unvalidated_transaction(msg.tx.clone());
    // store successful transactions so that they can't be played back to us, at least
    // during this session
    if msg.success && was_present {
        add_successful_tx(msg.tx.payment.clone());
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
fn checked(msg: ToValidate) {
    if remove_unvalidated_transaction(msg.clone()) {
        let mut checked_tx = msg.clone();
        checked_tx.checked = true;
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
                if let Some(txid) = item.payment.txid {
                    format!("{:#066x}", txid)
                } else {
                    item.payment.tx_hash.clone().unwrap()
                }
            );

            // if we fail to so much as get a block height for the full duration of a payment timeout, we have problems and probably we are not counting payments correctly potentially leading to wallet
            // drain and other bad outcomes. So we should restart with the hope that the system will be restored to a working state by this last resort action
            if !item.checked {
                let msg = format!("We failed to check txid {} against full nodes for the full duration of it's timeout period, please check full nodes",if let Some(txid) = item.payment.txid {
                    format!("{:#066x}", txid)
                } else {
                    item.payment.tx_hash.clone().unwrap()
                });
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
                "Outgoing transaction {} has timed out, payment failed!",
                if let Some(txid) = item.payment.txid {
                    format!("{:#066x}", txid)
                } else {
                    item.payment.tx_hash.clone().unwrap()
                }
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
    // we validate that a txid is present before adding to the validation list
    let txid = ts.payment.clone().txid;
    let txhash = ts.payment.clone().tx_hash;

    match (txid, txhash) {
        (Some(_), Some(_)) => {
            error!("We recieved both an eth and althea chain receipt for a payment! Trying to verify only althea chain");
            handle_althea_tx_checking(ts).await;
        }
        // Received a payment on eth chain
        (Some(_), None) => {
            handle_xdai_tx_checking(ts).await;
        }
        // Recieved payment on althea chain
        (None, Some(_)) => {
            handle_althea_tx_checking(ts).await;
        }
        // Recieved a receipt with no txid or txhash??
        (None, None) => {
            error!(
                "Someone tried to insert an unpublished transaction to validate!? {:?}",
                ts
            );
            // in a development env we want to draw attention to this case
            #[cfg(feature = "development")]
            panic!(
                "Someone tried to insert an unpublished transaction to validate!? {:?}",
                ts
            );
            remove(Remove {
                tx: ts,
                success: false,
            })
        }
    }
}

async fn handle_xdai_tx_checking(ts: ToValidate) {
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_VERIFICATION_TIMEOUT);

    // already verfied that it exists
    let txid = ts.payment.txid.unwrap();

    let eth_block_num = web3.eth_block_number().await;
    let eth_transaction = web3.eth_get_transaction_by_hash(txid).await;
    match (eth_transaction, eth_block_num) {
        (Ok(Some(transaction)), Ok(block_num)) => {
            if !ts.checked {
                checked(ts.clone());
            }
            let transaction = get_xdai_transaction_details(transaction);

            handle_tx_messaging(transaction, ts.clone(), block_num);
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

fn get_xdai_transaction_details(transaction: TransactionResponse) -> TransactionDetails {
    match transaction {
        TransactionResponse::Eip1559 {
            to,
            from,
            value,
            block_number,
            ..
        } => TransactionDetails {
            to: to.map(PaymentAddress::Xdai),
            from: Some(PaymentAddress::Xdai(from)),
            amount: Some(value),
            denom: "wei".to_string(),
            block_num: block_number,
        },
        TransactionResponse::Eip2930 {
            to,
            from,
            value,
            block_number,
            ..
        } => TransactionDetails {
            to: to.map(PaymentAddress::Xdai),
            from: Some(PaymentAddress::Xdai(from)),
            amount: Some(value),
            denom: "wei".to_string(),
            block_num: block_number,
        },
        TransactionResponse::Legacy {
            to,
            from,
            value,
            block_number,
            ..
        } => TransactionDetails {
            to: to.map(PaymentAddress::Xdai),
            from: Some(PaymentAddress::Xdai(from)),
            amount: Some(value),
            denom: "wei".to_string(),
            block_num: block_number,
        },
    }
}

async fn handle_althea_tx_checking(ts: ToValidate) {
    let cosmos_node_grpc = match get_rita_common().payment.cosmos_node_grpc {
        Some(a) => a,
        None => {
            error!("Did we forget to configure a cosmos_node_grpc in config? None found!");
            return;
        }
    };
    let althea_contact = Contact::new(
        &cosmos_node_grpc,
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();
    // already verfied that it exists
    let txhash = ts.payment.tx_hash.clone().unwrap();

    let althea_chain_status = althea_contact.get_chain_status().await;
    let althea_transaction = althea_contact.get_tx_by_hash(txhash.clone()).await;

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

                if let ChainStatus::Moving { block_height } = chain_status {
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
                                    to: Some(PaymentAddress::Althea(
                                        match msg.to_address.parse() {
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
                                    )),
                                    from: Some(PaymentAddress::Althea(
                                        match msg.from_address.parse() {
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
                                    )),
                                    amount: Some(
                                        match Uint256::from_str_radix(&coin_tx.amount, 10) {
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
                                    ),
                                    denom: coin_tx.denom,
                                    // this should never be negative
                                    block_num: Some((tx_resp.height as u32).into()),
                                };
                                handle_tx_messaging(
                                    transaction_details,
                                    ts.clone(),
                                    block_height.into(),
                                );
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
            if transaction.tx_response.is_some() {
                if !ts.checked {
                    checked(ts.clone());
                }
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

/// Handles the tx response from the full node and it's various cases
/// pulled out of validate_transaction purely for cosmetic reasons
fn handle_tx_messaging(transaction: TransactionDetails, ts: ToValidate, current_block: Uint256) {
    let pmt = ts.payment.clone();

    // txid is for eth chain and txhash is for althea chain, only one of these should be
    // Some(..). This was verified before
    let txid = ts.payment.txid;
    let txhash = ts.payment.tx_hash.clone();

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

    let from_address_eth = ts.payment.from.eth_address.clone();
    let from_address_althea = ts.payment.from.althea_address.clone();

    let amount = ts.payment.amount;

    let our_address_eth = settings::get_rita_common()
        .payment
        .eth_address
        .expect("No Address!");
    let our_address_althea = settings::get_rita_common()
        .payment
        .althea_address
        .expect("Althea address should be initialized");

    let to = match transaction.to {
        Some(a) => a,
        None => {
            error!("Invalid TX! No destination!");
            remove(Remove {
                tx: ts,
                success: false,
            });
            return;
        }
    };

    let from = match transaction.from {
        Some(a) => a,
        None => {
            error!("Invalid TX! No Source!");
            remove(Remove {
                tx: ts,
                success: false,
            });
            return;
        }
    };

    // Sanity check that to and from address are on the same chain
    // We check enum types are the same here, ie Althea == Althea or Xdai == Xdai
    if std::mem::discriminant(&to) != std::mem::discriminant(&from) {
        error!("Source and Destination on TX need to be on the same chain!");
        remove(Remove {
            tx: ts,
            success: false,
        });
        return;
    }

    // notice we get these values from the blockchain using 'transaction' not ts which may be a lie since we don't
    // actually cryptographically validate the txhash locally. Instead we just compare the value we get from the full
    // node
    let to_us = match to {
        PaymentAddress::Althea(a) => a == our_address_althea,
        PaymentAddress::Xdai(a) => a == our_address_eth,
    };
    let from_us = match from {
        PaymentAddress::Althea(a) => a == our_address_althea,
        PaymentAddress::Xdai(a) => a == our_address_eth,
    };
    let value_correct = match transaction.amount {
        Some(a) => a == amount,
        None => {
            error!("No amount specified in TX!");
            remove(Remove {
                tx: ts,
                success: false,
            });
            return;
        }
    };
    let is_in_chain = payment_in_chain(current_block, transaction.block_num);
    let is_old = payment_is_old(current_block, transaction.block_num);

    if !value_correct {
        error!("Transaction with invalid amount!");
        remove(Remove {
            tx: ts,
            success: false,
        });
        return;
    }

    if is_old {
        if txid.is_some() {
            error!(
                "Transaction is more than 6 hours old! {:#066x}",
                txid.unwrap()
            );
        } else {
            error!(
                "Transaction is more than 6 hours old! {:?}",
                txhash.unwrap()
            );
        }
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
            if txid.is_some() {
                info!(
                    "payment {:#066x} from {} for {} wei successfully validated!",
                    txid.unwrap(),
                    from_address_eth,
                    amount
                );
            } else {
                info!(
                    "payment {:?} from {:?} for {} wei successfully validated!",
                    txhash.unwrap(),
                    from_address_althea,
                    amount
                );
            }

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
        (false, true, true) => {
            if txid.is_some() {
                info!(
                    "payment {:#066x} from {} for {} wei successfully sent!",
                    txid.unwrap(),
                    from_address_eth,
                    amount
                );
            } else {
                info!(
                    "payment {:?} from {:?} for {} wei successfully sent!",
                    txhash, from_address_althea, amount
                );
            }

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

    use super::*;

    #[test]
    fn test_payment_txid_datastore() {
        let client_id = Identity {
            mesh_ip: "fd00::1".parse().unwrap(),
            eth_address: "0xE39bDB2e345ACf7B0C7B1A28dFA26288C3094A6A"
                .parse()
                .unwrap(),
            althea_address: Some(
                "althea11lrsu892mqx2mndyvjufrh2ux56tyfxl2e3eht3"
                    .parse()
                    .unwrap(),
            ),
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
            althea_address: Some(
                "althea11lrsu892mqx2mndyvjufrh2ux56tyfxl2e3eht3"
                    .parse()
                    .unwrap(),
            ),
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
            txid: Some(1u8.into()),
            tx_hash: None,
        };

        store_payment(pmt1.clone());
        sent_hashset.insert(pmt1.clone());
        assert_eq!(get_payment_txids(pmt1.to), sent_hashset);

        let pmt2 = PaymentTx {
            to: exit_id,
            from: client_id,
            amount: 100u8.into(),
            txid: Some(2u8.into()),
            tx_hash: None,
        };
        store_payment(pmt2.clone());

        sent_hashset.insert(pmt2.clone());
        assert_eq!(get_payment_txids(pmt2.to), sent_hashset);

        let pmt3 = PaymentTx {
            to: exit_id,
            from: client_id,
            amount: 100u8.into(),
            txid: Some(2u8.into()),
            tx_hash: None,
        };

        store_payment(pmt3.clone());

        assert_eq!(get_payment_txids(pmt3.to), sent_hashset);
    }

    #[test]
    fn test_althea_chain_response() {
        let runner = System::new();
        runner.block_on(async move {
            let contact = Contact::new(
                "http://chainripper-2.althea.net:3290",
                ALTHEA_CONTACT_TIMEOUT,
                "althea",
            )
            .unwrap();

            let tx = contact
                .get_tx_by_hash(
                    "B855DE0BE8158EFBD0E97754DB4BCA7FFF9CFCAFE314B370845D959710D10CE1".to_string(),
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
