//! This modules handles single transaction payments as well as
//! managing the retry flow for failed payment attempts. We will retry a payment
//! until it is successfully in a block, see payment_validator, once the payment is on
//! the blockchain it's up to the reciever to validate that it's correct

use crate::blockchain_oracle::get_oracle_balance;
use crate::debt_keeper::payment_failed;
use crate::payment_validator::ToValidate;
use crate::rita_loop::get_web3_server;
use althea_types::interop::UnpublishedPaymentTx;
use althea_types::{Identity, PaymentTx};
use awc;
use futures::future::{join, join_all};
use num256::Uint256;
use settings::network::NetworkSettings;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Result as DisplayResult;
use std::fmt::{Display, Formatter};
use std::time::Duration;
use std::time::Instant;
use web30::client::Web3;

pub const TRANSACTION_SUBMISSION_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_TXID_RETRIES: u8 = 15u8;
/// How many blocks after submission a MicroTX will be valid for. If we wait this many blocks after submitting the
/// tx we can be sure that it will not be included in a block and we can safely retry it
pub const ALTHEA_L1_MICROTX_TIMEOUT: u64 = 25;

#[derive(Default, Clone)]
pub struct PaymentController {
    /// this is a vec of outgoing transactions for the payment
    /// controller loop to pick up next time it runs
    outgoing_queue: Vec<UnpublishedPaymentTx>,
    /// this queue tracks payments that we have failed to send to our
    /// neighbor this is where we have sent the actual funds on the chain
    /// but have failed to notify the neighbor we did so. In this edge case
    /// we don't to re-send the blockchain transaction, only attempt to get this
    /// info over to our neighbor. Even if we fail to do so we should still consider
    /// this debt as paid
    resend_queue: Vec<ResendInfo>,
}

impl PaymentController {
    pub fn new() -> Self {
        PaymentController {
            outgoing_queue: Vec::new(),
            resend_queue: Vec::new(),
        }
    }

    /// This function is called by the async loop in order to perform payment
    /// controller actions
    pub async fn tick_payment_controller(
        &mut self,
        new_outgoing_payments: Vec<UnpublishedPaymentTx>,
        previously_sent_payments: HashMap<Identity, HashSet<PaymentTx>>,
    ) -> Vec<ToValidate> {
        // move these new payments into the outgoing queue
        self.outgoing_queue.extend(new_outgoing_payments);

        // nothing to do this round
        if self.outgoing_queue.is_empty() && self.resend_queue.is_empty() {
            return Vec::new();
        }

        info!(
            "Ticking payment controller with {} payments and {} resends",
            self.outgoing_queue.len(),
            self.resend_queue.len()
        );

        let mut payments_sent_this_round = Vec::new();

        // if payments fail they are passed back to debt keeper to handle retrying
        // or passed onto payment_validator becuase they might be published
        while let Some(pmt) = self.outgoing_queue.pop() {
            match make_payment(pmt.clone(), &previously_sent_payments).await {
                Ok((pmt, resend)) => {
                    // resend info contains info required to notify our neighbor that the payment
                    // has been made. Since we have already sent the payment on the blockchain
                    // and the neighbor is not watching their account but instead needs to be notified
                    // we must make all possible efforts to get this info to them otherwise the payment
                    // doesn't do anything for us
                    payments_sent_this_round.push(pmt);
                    if let Some(retry) = resend {
                        self.resend_queue.push(retry)
                    }
                }
                Err(e) => {
                    // this must be the only reference to this function in this file!
                    // anything that is definately not publsihed needs to go back to debt keeper
                    // anything that might be published must go to payment validator
                    payment_failed(pmt.to.clone());
                    warn!("Failed to send payment with {:?}!", e);
                }
            }
        }

        // this creates a series of futures that we can use to perform
        // retires in parallel, this is helpful because retries may take
        // a long time to timeout, payments are done in series to reduce
        // nonce races
        let mut retry_futures = Vec::new();
        let network_settings = settings::get_rita_common().network;
        while let Some(resend) = self.resend_queue.pop() {
            if resend.attempt >= MAX_TXID_RETRIES {
                error!(
                    "Failed to resend txid {} after all attempts!",
                    resend.pmt.txid
                );
            } else {
                let fut = send_make_payment_endpoints(
                    resend.pmt,
                    network_settings.clone(),
                    resend.full_node.clone(),
                    &previously_sent_payments,
                    resend.attempt,
                );
                retry_futures.push(fut);
            }
        }
        // if yet another retry is needed we'll get Some(ResendInfo) back and requeue
        for resend in join_all(retry_futures).await.into_iter().flatten() {
            self.resend_queue.push(resend);
        }

        payments_sent_this_round
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

/// Sends a payment on ETH based chains, this is a basic send transaction with no payload
/// returns a payment to validate and optionally a retry if we have to send details to the neighbor again
async fn make_payment(
    pmt: UnpublishedPaymentTx,
    previously_sent_payments: &HashMap<Identity, HashSet<PaymentTx>>,
) -> Result<(ToValidate, Option<ResendInfo>), PaymentControllerError> {
    let common = settings::get_rita_common();
    let network_settings = common.network;
    let payment_settings = common.payment;

    let balance = get_oracle_balance();
    let our_private_key = &payment_settings
        .eth_private_key
        .expect("No private key configured!");
    let our_address = our_private_key.to_address();

    match sanity_check_balance(balance.clone(), &pmt) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    info!(
        "current xdai balance: {:?}, payment of {:?}, from address {} to address {}",
        balance, pmt.amount, our_address, pmt.to.eth_address
    );

    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSION_TIMEOUT);

    let tx = web3
        .send_transaction(
            pmt.to.eth_address,
            Vec::new(),
            pmt.amount.clone(),
            our_private_key.to_address(),
            *our_private_key,
            vec![],
        )
        .await;

    match tx {
        Ok(tx_id) => {
            info!("Sending bw payment with txid {:#066x} current balance: {:?}, payment of {:?}, from address {} to address {}",
                            tx_id, balance, pmt.amount, our_address, pmt.to.eth_address);

            // add published txid to submission
            let pmt = pmt.publish(tx_id);

            let resend = send_make_payment_endpoints(
                pmt.clone(),
                network_settings,
                full_node,
                previously_sent_payments,
                0,
            )
            .await;

            // place this payment in the validation queue to handle later.
            let ts = ToValidate {
                payment: pmt,
                received: Instant::now(),
                timeout_block: None,
            };

            Ok((ts, resend))
        }
        Err(e) => {
            error!(
                "Failed to send payment {:?} to {:?} with {:?}",
                pmt, pmt.to, e
            );
            // we have not yet published the tx
            // so it's safe to add this debt back to our balances
            Err(PaymentControllerError::FailedToSendPayment)
        }
    }
}

fn sanity_check_balance(
    balance: Option<Uint256>,
    pmt: &UnpublishedPaymentTx,
) -> Result<(), PaymentControllerError> {
    match balance {
        Some(value) => {
            if value < pmt.amount.clone() {
                warn!("Not enough money to pay debts! Cutoff imminent");
                // having this here really doesn't matter much, either we
                // tell debt keeper the payment failed and it enqueues another
                // that also won't succeed right away, or it waits for the timeout
                // and does the same thing.
                Err(PaymentControllerError::InsufficientFunds {
                    amount: pmt.amount.clone(),
                    balance: value,
                })
            } else if pmt.amount == 0u32.into() {
                // in this case we just drop the tx, no retry no other messages
                error!("Trying to pay nothing!");
                return Err(PaymentControllerError::ZeroPayment);
            } else {
                Ok(())
            }
        }
        None => {
            warn!("Balance is none");
            Err(PaymentControllerError::InsufficientFunds {
                amount: pmt.amount.clone(),
                balance: 0u32.into(),
            })
        }
    }
}

/// This function handles sending a payment to a neighbor, at this point the payment has
/// already been sent on the blockchain and we are simply notifying the neighbor of the txid
/// the complexity here is due to the fact that we have two different versions of the make_payment
/// endpoint one of which expects a single txid and the other accepts multiple txids
async fn send_make_payment_endpoints(
    pmt: PaymentTx,
    network_settings: NetworkSettings,
    full_node: String,
    previously_sent_payments: &HashMap<Identity, HashSet<PaymentTx>>,
    attempt: u8,
) -> Option<ResendInfo> {
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

    let mut txid_history = previously_sent_payments
        .get(&pmt.to)
        .cloned()
        .unwrap_or_default();

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
        full_node: full_node.clone(),
        pmt: pmt.clone(),
        attempt: attempt + 1,
    };

    // Hit both endpoints, in the case of a node having both endpoints, validator will simply get a duplicate transaction txid and discard it.
    let (neigh_ack_v2, neigh_ack) = join(neigh_ack_v2, neigh_ack).await;

    let tx_id = pmt.txid;
    match (neigh_ack_v2, neigh_ack) {
        // In this case both HTTP requests have responded, but they may return an error, an Err here is a network error
        (Ok(make_payments_v2_ack), Ok(mut make_payments_v1_ack)) => {
            // THis is probably a b20 router
            match (
                make_payments_v2_ack.status().is_success(),
                make_payments_v1_ack.status().is_success(),
            ) {
                (true, _) | (_, true) => {
                    // log the correct status for the success
                    let (mut status, url) = if make_payments_v2_ack.status().is_success() {
                        (make_payments_v2_ack, neighbor_url_v2)
                    } else {
                        (make_payments_v1_ack, neighbor_url)
                    };
                    info!(
                        "Payment pmt with tx identifier: {} is sent to our neighbor with status {:?} and body {:?} via url {}, using node {:?} and amount {}",
                        format!("{:#066x}", tx_id),
                        status.status(),
                        status.body().await,
                        url,
                        full_node,
                        pmt.amount.clone()
                    );
                    None
                }
                (false, false) => {
                    error!(
                        "We published txid: {} to url {} but our neighbor responded with status {:?} and body {:?}, will retry",
                                format!("{:#066x}", tx_id), neighbor_url, make_payments_v1_ack.status(), make_payments_v1_ack.body().await);
                    Some(resend_info)
                }
            }
        }
        (Err(_), Ok(mut make_payments_v1_ack)) => {
            // probably a b19 router
            if make_payments_v1_ack.status().is_success() {
                info!(
                    "Payment pmt with txid: {} is sent to our neighbor with status {:?} and body {:?} via url {}, using node {:?} and amount {}",
                    format!("{:#066x}", tx_id),
                    make_payments_v1_ack.status(),
                    make_payments_v1_ack.body().await,
                    neighbor_url,
                    full_node,
                    pmt.amount
                );
                None
            } else {
                error!(
                    "Make_payment with tx identifier {} failed with status {:?} and body {:?}",
                    format!("{:#066x}", tx_id),
                    make_payments_v1_ack.status(),
                    make_payments_v1_ack.body().await
                );
                Some(resend_info)
            }
        }
        (Ok(mut make_payments_v2_ack), Err(_)) => {
            // We shouldnt reach this case unless some network error or make_payment has been removed. If make_payment
            // has been removed, all this legacy code can be removed also
            if make_payments_v2_ack.status().is_success() {
                info!(
                    "Payment pmt with txid: {} is sent to our neighbor with status {:?} and body {:?} via url {}, using node {:?} and amount {}",
                    format!("{:#066x}", tx_id),
                    make_payments_v2_ack.status(),
                    make_payments_v2_ack.body().await,
                    neighbor_url_v2,
                    full_node,
                    pmt.amount
                );
                None
            } else {
                error!(
                    "Make_payment_v2 with txid {} failed with status {:?} and body {:?}",
                    format!("{:#066x}", tx_id),
                    make_payments_v2_ack.status(),
                    make_payments_v2_ack.body().await
                );
                Some(resend_info)
            }
        }
        (Err(_), Err(e)) => {
            // Why is make payment failing here? Call a resend
            error!(
                "We published txid: {} but failed to notify our neighbor with {:?}, will retry",
                format!("{:#066x}", tx_id),
                e
            );
            Some(resend_info)
        }
    }
}

/// Represents a failed payment that we want to retry sending to our neighbor
/// this is now the first line of defense in a multi part system where make_payments_v2
/// will replay our entire payment history to the neighbor so they can validate it
#[derive(Debug, Clone)]
struct ResendInfo {
    full_node: String,
    pmt: PaymentTx,
    attempt: u8,
}
