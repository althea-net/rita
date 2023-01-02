//! This modules handles single transaction payments as well as
//! managing the retry flow for failed payment attempts. We will retry a payment
//! until it is successfully in a block, see payment_validator, once the payment is on
//! the blockchain it's up to the reciever to validate that it's correct

use althea_types::{Identity, PaymentTx};
use awc;
use futures::future::join_all;
use num256::Uint256;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Result as DisplayResult;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::Instant;
use web30::client::Web3;
use web30::types::SendTxOption;

use crate::blockchain_oracle::{
    get_oracle_balance, get_oracle_latest_gas_price, get_oracle_nonce, set_oracle_nonce,
};
use crate::debt_keeper::payment_failed;
use crate::payment_validator::{validate_later, ToValidate};
use crate::rita_loop::get_web3_server;

pub const TRANSACTION_SUBMISSION_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_TXID_RETRIES: u8 = 15u8;

lazy_static! {
    static ref PAYMENT_DATA: Arc<RwLock<PaymentController>> =
        Arc::new(RwLock::new(PaymentController::new()));
}

#[derive(Default)]
pub struct PaymentController {
    /// this is a vec of outgoing transactions for the payment
    /// controller loop to pick up next time it runs
    outgoing_queue: Vec<PaymentTx>,
    /// this queue tracks payments that we have failed to send to our
    /// neighbor this is where we have sent the actual funds on the chain
    /// but have failed to notify the neighbor we did so. In this edge case
    /// we don't to re-send the blockchain transaction, only attempt to get this
    /// info over to our neighbor. Even if we fail to do so we should still consider
    /// this debt as paid
    resend_queue: Vec<ResendInfo>,
    /// This datastore saves the payment receipts made from the start of rita
    /// This can be used to send to exits and neighbors when making a payment
    /// and can be used to synchronize transaction data in the cases of erroneous
    /// payments
    /// This is stored in the form of a hashmap key: recepient id -> value: list of payment tx
    payment_sent_datastore: HashMap<Identity, HashSet<PaymentTx>>,
    /// Same as above, stored as key: sender id -> value: list of payment tx
    payment_received_datastore: HashMap<Identity, HashSet<PaymentTx>>,
    /// A copy of Rita Client's exit list. This stays empty in the case of an exit
    exit_list: Vec<Identity>,
}

/// Pushes a payment tx onto the payment controller queue, to be processed
/// on the next payment controller loop run
pub fn queue_payment(payment: PaymentTx) {
    info!("Payment of {:?} queued!", payment);
    let mut data = PAYMENT_DATA.write().unwrap();
    data.outgoing_queue.push(payment);
}

/// Pushes a resend onto the payment controller queue, to be processed
/// on the next payment controller loop run
fn queue_resend(resend_info: ResendInfo) {
    info!("Resend of {:?} queued!", resend_info);
    let mut data = PAYMENT_DATA.write().unwrap();
    data.resend_queue.push(resend_info);
}

///This function stores an outgoing payment in payment datastore. We store both sent and received payments
pub fn store_payment(pmt: PaymentTx, sent: bool) {
    let mut lock = PAYMENT_DATA.write().unwrap();
    let neighbor;
    let data = if sent {
        neighbor = pmt.to;
        &mut lock.payment_sent_datastore
    } else {
        neighbor = pmt.from;
        &mut lock.payment_received_datastore
    };

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
}

/// Incase payment validator invalidates a transaction, we remove it from our list
pub fn remove_invalid_payment(pmt: PaymentTx) {
    let data = &mut PAYMENT_DATA.write().unwrap().payment_sent_datastore;
    let to = pmt.to;

    if let Some(list) = data.get_mut(&to) {
        list.remove(&pmt);
    }
}

/// Given a payment identity, get either all payments sent to that identity or all payments received from that
/// id
pub fn get_all_payment_txids(addr: Identity, sent: bool) -> HashSet<PaymentTx> {
    let lock = PAYMENT_DATA.read().unwrap();
    let data = if sent {
        lock.payment_sent_datastore.get(&addr)
    } else {
        lock.payment_received_datastore.get(&addr)
    };

    match data {
        Some(set) => set.clone(),
        None => {
            error!(
                "No hashset for the payment address {:?}, returning empty set",
                addr
            );
            HashSet::new()
        }
    }
}

pub fn set_payment_exit_list(list: Vec<Identity>) {
    PAYMENT_DATA.write().unwrap().exit_list = list;
}

pub fn get_payment_exit_list() -> Vec<Identity> {
    PAYMENT_DATA.read().unwrap().exit_list.clone()
}

impl PaymentController {
    pub fn new() -> Self {
        PaymentController {
            outgoing_queue: Vec::new(),
            resend_queue: Vec::new(),
            payment_sent_datastore: HashMap::new(),
            payment_received_datastore: HashMap::new(),
            exit_list: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum PaymentControllerError {
    /// a txid resend failed after the maximum number of attempts
    /// we have paid and our neighbor will not know
    ResendFailed,
    InsufficientFunds {
        amount: Uint256,
        balance: Uint256,
    },
    ZeroPayment,
    FailedToSendPayment,
}

impl Display for PaymentControllerError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Self::ResendFailed => write!(f, "Failed to resend txid after all attempts!"),
            Self::InsufficientFunds { amount, balance } => {
                write!(f, "Can not send amount {} with balance {}", amount, balance)
            }
            Self::ZeroPayment => write!(f, "Attempted to send zero value payment!"),
            Self::FailedToSendPayment => write!(f, "Failed to send payment!"),
        }
    }
}

impl Error for PaymentControllerError {}

/// This function is called by the async loop in order to perform payment
/// controller actions
pub async fn tick_payment_controller() {
    let outgoing_payments: Vec<PaymentTx>;
    let resend_queue: Vec<ResendInfo>;

    {
        let mut data = PAYMENT_DATA.write().unwrap();

        // we fully empty both queues every run, and replace them with empty
        // vectors this helps deal with logic issues around outgoing payments
        // needing to queue retries which would cause a deadlock if we needed
        // a write lock to iterate.
        outgoing_payments = data.outgoing_queue.clone();
        resend_queue = data.resend_queue.clone();

        info!(
            "Ticking payment controller with {} payments and {} resends",
            outgoing_payments.len(),
            resend_queue.len()
        );

        data.outgoing_queue = Vec::new();
        data.resend_queue = Vec::new();
    }

    // this creates a series of futures that we can use to perform
    // retires in parallel, this is helpful because retries may take
    // a long time to timeout, payments are done in series to reduce
    // nonce races
    let mut retry_futures = Vec::new();
    for pmt in outgoing_payments {
        let _ = make_payment(pmt).await;
    }
    for resend in resend_queue {
        let fut = resend_txid(resend);
        retry_futures.push(fut);
    }
    // we log all errors in the functions themselves, we could print errors here
    // instead, but right now no action is needed either way.
    let _ = join_all(retry_futures).await;
}

/// This is called by debt_keeper to make payments. It sends a
/// PaymentTx to the `mesh_ip` in its `to` field.
async fn make_payment(mut pmt: PaymentTx) -> Result<(), PaymentControllerError> {
    let common = settings::get_rita_common();
    let payment_settings = common.payment;
    let balance = get_oracle_balance();
    let nonce = get_oracle_nonce();
    let gas_price = get_oracle_latest_gas_price();
    let our_private_key = &payment_settings
        .eth_private_key
        .expect("No private key configured!");
    let our_address = our_private_key.to_address();

    info!(
        "current balance: {:?}, payment of {:?}, from address {} to address {} with nonce {}",
        balance, pmt.amount, our_address, pmt.to.eth_address, nonce
    );
    match balance.clone() {
        Some(value) => {
            if value < pmt.amount {
                warn!("Not enough money to pay debts! Cutoff imminent");
                // having this here really doesn't matter much, either we
                // tell debt keeper the payment failed and it enqueues another
                // that also won't succeed right away, or it waits for the timeout
                // and does the same thing.
                payment_failed(pmt.to);
                return Err(PaymentControllerError::InsufficientFunds {
                    amount: pmt.amount,
                    balance: balance.unwrap_or_else(|| 0u64.into()),
                });
            } else if pmt.amount == 0u32.into() {
                // in this case we just drop the tx, no retry no other messages
                error!("Trying to pay nothing!");
                return Err(PaymentControllerError::ZeroPayment);
            }
        }
        None => {
            warn!("Balance is none");
            return Err(PaymentControllerError::InsufficientFunds {
                amount: pmt.amount,
                balance: balance.unwrap_or_else(|| 0u64.into()),
            });
        }
    }

    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSION_TIMEOUT);

    let transaction_status = web3
        .send_transaction(
            pmt.to.eth_address,
            Vec::new(),
            pmt.amount.clone(),
            our_address,
            *our_private_key,
            vec![
                SendTxOption::Nonce(nonce.clone()),
                SendTxOption::GasPrice(gas_price),
            ],
        )
        .await;

    if transaction_status.is_err() {
        error!(
            "Failed to send payment {:?} to {:?} with {:?}",
            pmt, pmt.to, transaction_status
        );
        // we have not yet published the tx (at least hopefully)
        // so it's safe to add this debt back to our balances
        payment_failed(pmt.to);
        return Err(PaymentControllerError::FailedToSendPayment);
    }
    let tx_id = transaction_status.unwrap();

    // increment our nonce, this allows us to send another transaction
    // right away before this one that we just sent out gets into the chain
    {
        set_oracle_nonce(get_oracle_nonce() + 1u64.into());
    }

    info!("Sending bw payment with txid {:#066x} current balance: {:?}, payment of {:?}, from address {} to address {} with nonce {}",
                            tx_id, balance, pmt.amount, our_address, pmt.to.eth_address, nonce);

    // add published txid to submission
    pmt.txid = Some(tx_id.clone());

    // Add new payment to Hashmap of transactions
    store_payment(pmt.clone(), true);

    // special case when paying exit, we sent our transaction to all exits
    // This is important in the case of exit switching, since we have only one entry
    // of exit in debt keeper, but all exits in a cluster have an entry for us
    // Payment validator on the exit will make sure the right exit accepts the transaction
    // The client may be credited more than it should, this will be fixed once exits have their own
    // eth payment addresses
    if are_we_paying_exit(pmt.clone()) {
        info!(
            "Sending bw payment with txid {:#066x} to all exits in \n{:?}",
            tx_id,
            get_payment_exit_list()
        );
        for exit in get_payment_exit_list() {
            // Call endpoint make_payment_v2, which should validate all payments made since restart. If this fails,
            // the node we are paying is b19 and we call make_payment
            if let Err(e) =
                send_make_payment_endpoint_v2(pmt.clone(), full_node.clone(), exit.mesh_ip).await
            {
                warn!(
                    "Cannot hit make_payment_v2 endpoint for pmt transaction {:?} with error {}",
                    pmt.clone(),
                    e
                );
                send_make_payment_endpoint(pmt.clone(), full_node.clone(), exit.mesh_ip).await;
            }
        }
    } else {
        // We are paying a neighbor
        if let Err(e) =
            send_make_payment_endpoint_v2(pmt.clone(), full_node.clone(), pmt.to.mesh_ip).await
        {
            warn!(
                "Cannot hit make_payment_v2 endpoint for pmt transaction {:?} with error {}",
                pmt.clone(),
                e
            );
            send_make_payment_endpoint(pmt.clone(), full_node, pmt.to.mesh_ip).await;
        }
    }

    // place this payment in the validation queue to handle later.
    let ts = ToValidate {
        payment: pmt,
        received: Instant::now(),
        checked: false,
    };

    validate_later(ts);

    Ok(())
}

/// This function check if payment.to.mesh_ip is a mesh ip in our exit list
fn are_we_paying_exit(pmt: PaymentTx) -> bool {
    let list = get_payment_exit_list();
    let to = pmt.to;

    for exit in list {
        if exit.mesh_ip == to.mesh_ip {
            return true;
        }
    }
    false
}

async fn send_make_payment_endpoint_v2(
    pmt: PaymentTx,
    full_node: String,
    mesh_ip: IpAddr,
) -> Result<(), PaymentControllerError> {
    let common = settings::get_rita_common();
    let network_settings = common.network;
    let latest_txid = pmt.txid.expect("Why did we fail to setup txid");
    let neighbor_url_v2 = if cfg!(not(test)) {
        format!(
            "http://[{}]:{}/make_payment_v2",
            mesh_ip, network_settings.rita_contact_port,
        )
    } else {
        String::from("http://127.0.0.1:1234/make_payment_v2")
    };

    let actix_client = awc::Client::new();
    let neigh_ack_v2 = actix_client
        .post(neighbor_url_v2.clone())
        .timeout(TRANSACTION_SUBMISSION_TIMEOUT)
        .send_json(&get_all_payment_txids(pmt.to, true))
        .await;

    match neigh_ack_v2 {
        Ok(mut val) => {
            if val.status().is_success() {
                info!(
                    "Payment pmt with latest txid: {:#066x} is sent to our neighbor with status {:?} and body {:?} via url {}, using full node {} and amount {:?}",
                    latest_txid,
                    val.status(),
                    val.body().await,
                    neighbor_url_v2,
                    full_node,
                    pmt.amount
                );
                Ok(())
            } else {
                error!(
            "We published latest txid: {:#066x} but our neighbor responded with status {:?} and body {:?}",
            latest_txid, val.status(), val.body().await);
                Err(PaymentControllerError::FailedToSendPayment)
            }
        }
        Err(e) => {
            error!(
                "We published latest txid: {:#066x} but failed to notify our neighbor with {:?}",
                latest_txid, e
            );
            Err(PaymentControllerError::FailedToSendPayment)
        }
    }
}

async fn send_make_payment_endpoint(pmt: PaymentTx, full_node: String, mesh_ip: IpAddr) {
    let pmt_clone = pmt.clone();
    let common = settings::get_rita_common();
    let network_settings = common.network;
    let tx_id = pmt_clone
        .txid
        .expect("Why did this fail when we set this to Some(val)");

    let neighbor_url = if cfg!(not(test)) {
        format!(
            "http://[{}]:{}/make_payment",
            mesh_ip, network_settings.rita_contact_port,
        )
    } else {
        String::from("http://127.0.0.1:1234/make_payment")
    };

    let actix_client = awc::Client::new();
    let neigh_ack = actix_client
        .post(neighbor_url.clone())
        .timeout(TRANSACTION_SUBMISSION_TIMEOUT)
        .send_json(&pmt)
        .await;

    let resend_info = ResendInfo {
        txid: tx_id.clone(),
        neigh_url: neighbor_url.clone(),
        pmt: pmt.clone(),
        attempt: 0u8,
    };

    match neigh_ack {
        Ok(mut val) => {
            if val.status().is_success() {
                info!(
                    "Payment pmt with txid: {:#066x} is sent to our neighbor with status {:?} and body {:?} via url {}, using full node {} and amount {:?}",
                    tx_id,
                    val.status(),
                    val.body().await,
                    neighbor_url,
                    full_node,
                    pmt.amount
                );
            } else {
                error!(
            "We published txid: {:#066x} but our neighbor responded with status {:?} and body {:?}, will retry",
            tx_id, val.status(), val.body().await);
                queue_resend(resend_info);
            }
        }
        Err(e) => {
            error!(
            "We published txid: {:#066x} but failed to notify our neighbor with {:?}, will retry",
            tx_id, e
        );
            queue_resend(resend_info)
        }
    }
}

#[derive(Debug, Clone)]
struct ResendInfo {
    txid: Uint256,
    neigh_url: String,
    pmt: PaymentTx,
    attempt: u8,
}

/// For some reason we have sent a payment and managed not to notify our neighbor, this routine will
/// retry up to MAX_TXID_RETIRES times
async fn resend_txid(input: ResendInfo) -> Result<(), PaymentControllerError> {
    let mut input = input;
    input.attempt += 1;

    // at this point the chance of success is too tiny to be worth it
    if input.attempt > MAX_TXID_RETRIES {
        error!(
            "We have failed to send txid {:#066x} this payment will remain uncredited!",
            input.txid
        );
        return Err(PaymentControllerError::ResendFailed);
    }

    let actix_client = awc::Client::new();
    let neigh_ack = actix_client
        .post(&input.neigh_url)
        .timeout(TRANSACTION_SUBMISSION_TIMEOUT)
        .send_json(&input.pmt)
        .await;

    if neigh_ack.is_err() || !neigh_ack.unwrap().status().is_success() {
        error!("retry failed with published txid: {:#066x}", input.txid);
        queue_resend(input);
    }

    Ok(())
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
    let mut rec_hashset: HashSet<PaymentTx> = HashSet::new();

    let pmt1 = PaymentTx {
        to: exit_id,
        from: client_id,
        amount: 10u8.into(),
        txid: Some(1u8.into()),
    };
    store_payment(pmt1.clone(), true);
    sent_hashset.insert(pmt1.clone());
    assert_eq!(get_all_payment_txids(pmt1.to, true), sent_hashset);
    assert_eq!(get_all_payment_txids(pmt1.to, false), HashSet::new());

    let pmt2 = PaymentTx {
        to: exit_id,
        from: client_id,
        amount: 100u8.into(),
        txid: Some(2u8.into()),
    };
    store_payment(pmt2.clone(), true);
    sent_hashset.insert(pmt2.clone());
    assert_eq!(get_all_payment_txids(pmt2.to, true), sent_hashset);
    assert_eq!(get_all_payment_txids(pmt2.to, false), HashSet::new());

    let pmt3 = PaymentTx {
        to: client_id,
        from: exit_id,
        amount: 80u8.into(),
        txid: Some(3u8.into()),
    };
    store_payment(pmt3.clone(), false);
    rec_hashset.insert(pmt3.clone());
    assert_eq!(get_all_payment_txids(pmt3.from, true), sent_hashset);
    assert_eq!(get_all_payment_txids(pmt3.from, false), rec_hashset);

    let pmt4 = PaymentTx {
        to: client_id,
        from: exit_id,
        amount: 30u8.into(),
        txid: Some(4u8.into()),
    };
    store_payment(pmt4.clone(), false);
    rec_hashset.insert(pmt4.clone());
    assert_eq!(get_all_payment_txids(pmt4.from, true), sent_hashset);
    assert_eq!(get_all_payment_txids(pmt4.from, false), rec_hashset);

    remove_invalid_payment(pmt1.clone());
    sent_hashset.remove(&pmt1);
    assert_eq!(get_all_payment_txids(pmt1.to, true), sent_hashset);
    assert_eq!(get_all_payment_txids(pmt1.to, false), rec_hashset);

    remove_invalid_payment(pmt2.clone());
    sent_hashset.remove(&pmt2);
    assert_eq!(get_all_payment_txids(pmt2.to, true), sent_hashset);
    assert_eq!(get_all_payment_txids(pmt2.to, false), rec_hashset);
}
