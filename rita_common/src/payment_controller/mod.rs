//! This modules handles single transaction payments as well as
//! managing the retry flow for failed payment attempts. We will retry a payment
//! until it is successfully in a block, see payment_validator, once the payment is on
//! the blockchain it's up to the reciever to validate that it's correct

use althea_types::PaymentTx;
use awc;
use futures::future::{join, join_all};
use num256::Uint256;
use std::error::Error;
use std::fmt::Result as DisplayResult;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::Instant;
use web30::client::Web3;
use web30::types::SendTxOption;

use crate::blockchain_oracle::{
    get_oracle_balance, get_oracle_latest_gas_price, get_oracle_nonce, set_oracle_nonce,
};
use crate::debt_keeper::payment_failed;
use crate::payment_validator::{get_payment_txids, validate_later, ToValidate};
use crate::rita_loop::get_web3_server;
use crate::RitaCommonError;

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

impl PaymentController {
    pub fn new() -> Self {
        PaymentController {
            outgoing_queue: Vec::new(),
            resend_queue: Vec::new(),
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
                write!(f, "Can not send amount {amount} with balance {balance}")
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
    let network_settings = common.network;
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

    // testing hack
    let neighbor_url = if cfg!(not(test)) {
        format!(
            "http://[{}]:{}/make_payment",
            pmt.to.mesh_ip, network_settings.rita_contact_port,
        )
    } else {
        String::from("http://127.0.0.1:1234/make_payment")
    };

    // v2 version, this takes a list of pmts instead of one
    let neighbor_url_v2 = if cfg!(not(test)) {
        format!(
            "http://[{}]:{}/make_payment_v2",
            pmt.to.mesh_ip, network_settings.rita_contact_port,
        )
    } else {
        String::from("http://127.0.0.1:1234/make_payment_v2")
    };

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

    // Get all txids to this client. Temporary add new payment to a copy of a list to send up to endpoint
    // this pmt is actually recorded in memory after validator confirms it
    let mut txid_history = get_payment_txids(pmt.to);
    txid_history.insert(pmt.clone());

    let actix_client = awc::Client::new();
    let neigh_ack = actix_client
        .post(neighbor_url.clone())
        .timeout(TRANSACTION_SUBMISSION_TIMEOUT)
        .send_json(&pmt);

    let neigh_ack_v2 = actix_client
        .post(neighbor_url_v2.clone())
        .timeout(TRANSACTION_SUBMISSION_TIMEOUT)
        .send_json(&txid_history);

    let resend_info = ResendInfo {
        txid: tx_id.clone(),
        neigh_url: neighbor_url.clone(),
        pmt: pmt.clone(),
        attempt: 0u8,
    };

    // Hit both endpoints, in the case of a node having both endpoints, validator will simply get a duplicate transaction txid and discard it.
    let (neigh_ack_v2, neigh_ack) = join(neigh_ack_v2, neigh_ack).await;

    match (neigh_ack_v2, neigh_ack) {
        (Ok(mut val2), Ok(mut val)) => {
            // THis is probably a b20 router
            match (val2.status().is_success(), val.status().is_success()) {
                (true, _) => {
                    info!(
                        "Payment pmt with txid: {:#066x} is sent to our neighbor with status {:?} and body {:?} via url {}, using full node {} and amount {}",
                        tx_id,
                        val2.status(),
                        val2.body().await,
                        neighbor_url_v2,
                        full_node,
                        pmt.amount
                    );
                }
                (false, true) => {
                    error!(
                        "Make_payment_v2 with txid {:#066x} failed with status {:?} and body {:?}",
                        tx_id,
                        val2.status(),
                        val2.body().await
                    );
                    info!(
                        "Payment pmt with txid: {:#066x} is sent to our neighbor with status {:?} and body {:?} via url {}, using full node {} and amount {}",
                        tx_id,
                        val.status(),
                        val.body().await,
                        neighbor_url,
                        full_node,
                        pmt.amount
                    );
                }
                _ => {
                    error!(
                        "We published txid: {:#066x} to url {} but our neighbor responded with status {:?} and body {:?}, will retry",
                        tx_id, neighbor_url, val.status(), val.body().await);
                    queue_resend(resend_info);
                }
            }
        }
        (Err(_), Ok(mut val)) => {
            // probably a b19 router
            if val.status().is_success() {
                info!(
                    "Payment pmt with txid: {:#066x} is sent to our neighbor with status {:?} and body {:?} via url {}, using full node {} and amount {}",
                    tx_id,
                    val.status(),
                    val.body().await,
                    neighbor_url,
                    full_node,
                    pmt.amount
                );
            } else {
                error!(
                    "Make_payment with txid {:#066x} failed with status {:?} and body {:?}",
                    tx_id,
                    val.status(),
                    val.body().await
                );
            }
        }
        (Ok(mut val2), Err(_)) => {
            // We shouldnt reach this case unless some network error or make_payment has been removed. If make_payment
            // has been removed, all this legacy code can be removed also
            if val2.status().is_success() {
                info!(
                    "Payment pmt with txid: {:#066x} is sent to our neighbor with status {:?} and body {:?} via url {}, using full node {} and amount {}",
                    tx_id,
                    val2.status(),
                    val2.body().await,
                    neighbor_url_v2,
                    full_node,
                    pmt.amount
                );
            } else {
                error!(
                    "Make_payment_v2 with txid {:#066x} failed with status {:?} and body {:?}",
                    tx_id,
                    val2.status(),
                    val2.body().await
                );
            }
        }
        (Err(_), Err(e)) => {
            // Why is make payment failing here? Call a resend
            error!(
                "We published txid: {:#066x} but failed to notify our neighbor with {:?}, will retry",
                tx_id, e
            );
            queue_resend(resend_info)
        }
    }

    // place this payment in the validation queue to handle later.
    let ts = ToValidate {
        payment: pmt,
        received: Instant::now(),
        checked: false,
    };

    match validate_later(ts.clone()) {
        Ok(()) | Err(RitaCommonError::DuplicatePayment) => {}
        Err(e) => {
            error!("Received error trying to validate {:?} Error: {:?}", ts, e);
        }
    }

    Ok(())
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
