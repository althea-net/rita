//! This modules handles single transaction payments as well as
//! managing the retry flow for failed payment attempts. We will retry a payment
//! until it is successfully in a block, see payment_validator, once the payment is on
//! the blockchain it's up to the reciever to validate that it's correct

use althea_types::PaymentTx;
use async_web30::client::Web3;
use awc;
use clarity::Transaction;
use futures::future::join_all;
use num256::Uint256;
use std::error::Error;
use std::fmt::Result as DisplayResult;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::Instant;

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
    FailedToGenerateTransaction(clarity::Error),
}

impl Display for PaymentControllerError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Self::ResendFailed => write!(f, "Failed to resend txid after all attempts!"),
            Self::InsufficientFunds { amount, balance } => {
                write!(f, "Can not send amount {} with balance {}", amount, balance)
            }
            Self::ZeroPayment => write!(f, "Attempted to send zero value payment!"),
            Self::FailedToGenerateTransaction(e) => {
                write!(f, "Failed to generate transaction! {:?}", e)
            }
            Self::FailedToSendPayment => write!(f, "Failed to send payment!"),
        }
    }
}

impl Error for PaymentControllerError {}

/// This function is called by the async loop in order to perform payment
/// controller actions
pub async fn tick_payment_controller() {
    let mut data = PAYMENT_DATA.write().unwrap();

    // we fully empty both queues every run, and replace them with empty
    // vectors this helps deal with logic issues around outgoing payments
    // needing to queue retries which would cause a deadlock if we needed
    // a write lock to iterate.
    let outgoing_payments = data.outgoing_queue.clone();
    let resend_queue = data.resend_queue.clone();

    info!(
        "Ticking payment controller with {} payments and {} resends",
        outgoing_payments.len(),
        resend_queue.len()
    );

    data.outgoing_queue = Vec::new();
    data.resend_queue = Vec::new();
    drop(data);

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
    let balance = payment_settings.balance.clone();
    let nonce = payment_settings.nonce.clone();
    let gas_price = payment_settings.gas_price.clone();
    let our_private_key = &payment_settings
        .eth_private_key
        .expect("No private key configured!");
    let our_address = our_private_key.to_public_key().unwrap();

    info!(
        "current balance: {:?}, payment of {:?}, from address {} to address {} with nonce {}",
        balance, pmt.amount, our_address, pmt.to.eth_address, nonce
    );
    if balance < pmt.amount {
        warn!("Not enough money to pay debts! Cutoff imminent");
        // having this here really doesn't matter much, either we
        // tell debt keeper the payment failed and it enqueues another
        // that also won't succeed right away, or it waits for the timeout
        // and does the same thing.
        payment_failed(pmt.to);
        return Err(PaymentControllerError::InsufficientFunds {
            amount: pmt.amount,
            balance,
        });
    } else if pmt.amount == 0u32.into() {
        // in this case we just drop the tx, no retry no other messages
        error!("Trying to pay nothing!");
        return Err(PaymentControllerError::ZeroPayment);
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

    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSION_TIMEOUT);

    let tx = Transaction {
        nonce: nonce.clone(),
        gas_price,
        gas_limit: "21000".parse().unwrap(),
        to: pmt.to.eth_address,
        value: pmt.amount.clone(),
        data: Vec::new(),
        signature: None,
    };
    let transaction_signed = tx.sign(
        &payment_settings
            .eth_private_key
            .expect("No private key configured!"),
        payment_settings.net_version,
    );

    let transaction_bytes = match transaction_signed.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => return Err(PaymentControllerError::FailedToGenerateTransaction(e)),
    };

    let transaction_status = web3.eth_send_raw_transaction(transaction_bytes).await;
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
        let mut common = settings::get_rita_common();
        common.payment.nonce += 1u64.into();
        settings::set_rita_common(common);
    }

    info!("Sending bw payment with txid {:#066x} current balance: {:?}, payment of {:?}, from address {} to address {} with nonce {}",
                            tx_id, balance, pmt.amount, our_address, pmt.to.eth_address, nonce);

    // add published txid to submission
    pmt.txid = Some(tx_id.clone());

    let actix_client = awc::Client::new();
    let neigh_ack = actix_client
        .post(neighbor_url.clone())
        .timeout(TRANSACTION_SUBMISSION_TIMEOUT)
        .send_json(&pmt)
        .await;

    let resend_info = ResendInfo {
        txid: tx_id.clone(),
        neigh_url: neighbor_url,
        pmt: pmt.clone(),
        attempt: 0u8,
    };

    match neigh_ack {
        Ok(val) => {
            if val.status().is_success() {
                info!(
                "Payment with txid: {:#066x} is sent to our neighbor with {:?}, using full node {} and amount {:?}",
                tx_id,
                val,
                full_node,
                pmt.amount
            );
            } else {
                error!(
            "We published txid: {:#066x} but our neighbor responded with an error {:?}, will retry",
            tx_id, val
        );
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

    // place this payment in the validation queue to handle later.
    let ts = ToValidate {
        payment: pmt,
        received: Instant::now(),
        checked: false,
    };

    validate_later(ts);

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
