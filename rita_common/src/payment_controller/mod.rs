//! This modules handles single transaction payments as well as
//! managing the retry flow for failed payment attempts. We will retry a payment
//! until it is successfully in a block, see payment_validator, once the payment is on
//! the blockchain it's up to the reciever to validate that it's correct

use crate::blockchain_oracle::{
    get_oracle_balance, get_oracle_latest_gas_price, get_oracle_nonce, set_oracle_nonce,
};
use crate::debt_keeper::normalize_payment_amount;
use crate::debt_keeper::payment_failed;
use crate::payment_validator::ToValidate;
use crate::payment_validator::{ALTHEA_CHAIN_PREFIX, ALTHEA_CONTACT_TIMEOUT};
use crate::rita_loop::get_web3_server;
use althea_types::interop::UnpublishedPaymentTx;
use althea_types::{Denom, PaymentTx};
use althea_types::{Identity, SystemChain};
use awc;
use deep_space::{Coin, Contact, EthermintPrivateKey};
use futures::future::{join, join_all};
use num256::Uint256;
use num_traits::Num;
use settings::network::NetworkSettings;
use settings::payment::PaymentSettings;
use settings::{DEBT_KEEPER_DENOM, DEBT_KEEPER_DENOM_DECIMAL};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Result as DisplayResult;
use std::fmt::{Display, Formatter};
use std::time::Duration;
use std::time::Instant;
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;
use web30::types::SendTxOption;

pub const TRANSACTION_SUBMISSION_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_TXID_RETRIES: u8 = 15u8;

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
        info!(
            "Ticking payment controller with {} payments and {} resends",
            self.outgoing_queue.len(),
            self.resend_queue.len()
        );

        // move these new payments into the outgoing queue
        self.outgoing_queue.extend(new_outgoing_payments);

        let mut payments_sent_this_round = Vec::new();

        // Send each payment from the outgoing queue, if it fails we will requeue it
        // if make_payment fails, that means the transaction never made it to the full node
        // if the transaction never made it to the neighbor then we return Ok() but Some(RetryInfo)
        // is populated
        let mut requeue = Vec::new();
        while let Some(pmt) = self.outgoing_queue.pop() {
            match make_payment(pmt, &previously_sent_payments).await {
                Ok((pmt, resend)) => {
                    payments_sent_this_round.push(pmt);
                    if let Some(retry) = resend {
                        self.resend_queue.push(retry)
                    }
                }
                Err(e) => {
                    warn!("Failed to send payment with {:?}!", e);
                    requeue.push(pmt)
                }
            }
        }
        self.outgoing_queue.extend(requeue);

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

/// This is called by debt_keeper to make payments. It sends a
/// PaymentTx to the `mesh_ip` in its `to` field. It returns a payment to validate
async fn make_payment(
    pmt: UnpublishedPaymentTx,
    previously_sent_payments: &HashMap<Identity, HashSet<PaymentTx>>,
) -> Result<(ToValidate, Option<ResendInfo>), PaymentControllerError> {
    let common = settings::get_rita_common();
    let network_settings = common.network;
    let payment_settings = common.payment;
    let system_chain = payment_settings.system_chain;

    match system_chain {
        SystemChain::Althea => {
            make_althea_payment(
                pmt,
                payment_settings,
                network_settings,
                previously_sent_payments,
            )
            .await
        }
        SystemChain::Xdai | SystemChain::Rinkeby | SystemChain::Ethereum => {
            make_xdai_payment(
                pmt,
                payment_settings,
                network_settings,
                previously_sent_payments,
            )
            .await
        }
    }
}

/// Makes an Althea L1 payment, sends payment using the MicroTx transaction type
/// which is prioritized on chain. Returns a payment to validate and a potential retry
/// if we have to send details to the neighbor again
async fn make_althea_payment(
    mut pmt: UnpublishedPaymentTx,
    payment_settings: PaymentSettings,
    network_settings: NetworkSettings,
    previously_sent_payments: &HashMap<Identity, HashSet<PaymentTx>>,
) -> Result<(ToValidate, Option<ResendInfo>), PaymentControllerError> {
    // On althea chain, we default to paying with usdc, config must specify this as an accepted denom
    let usdc_denom = match payment_settings
        .accepted_denoms
        .unwrap_or_default()
        .get("usdc")
    {
        Some(a) => a.clone(),
        None => {
            error!("No USDC denom found");
            return Err(PaymentControllerError::FailedToSendPayment);
        }
    };

    let our_address = pmt.from.get_althea_address();

    // our althea private key is generated from our eth private key
    let our_private_key: EthermintPrivateKey = match payment_settings.eth_private_key {
        Some(a) => a.into(),
        None => {
            error!("How are we making an althea payment with no private key??");
            return Err(PaymentControllerError::FailedToSendPayment);
        }
    };

    let to_address = pmt.to.get_althea_address();

    let cosmos_node_grpc = payment_settings.althea_grpc_list[0].clone();

    // Convert Debt keeper denom to USDC
    pmt.amount = normalize_payment_amount(
        pmt.amount,
        Denom {
            denom: DEBT_KEEPER_DENOM.to_string(),
            decimal: DEBT_KEEPER_DENOM_DECIMAL,
        },
        usdc_denom.clone(),
    );

    // Create a contact object and get our balance
    let althea_contact = Contact::new(
        &cosmos_node_grpc,
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();

    let balance = match althea_contact
        .get_balance(our_address, usdc_denom.denom.clone())
        .await
    {
        Ok(a) => match a {
            Some(a) => a,
            None => {
                error!("Unable to get balance for wallet {:?}", our_address);
                return Err(PaymentControllerError::FailedToSendPayment);
            }
        },
        Err(e) => {
            error!(
                "Unable to get balance for wallet {:?} with {:?}",
                our_address, e
            );
            return Err(PaymentControllerError::FailedToSendPayment);
        }
    };

    match sanity_check_balance(Some(balance.amount), &pmt) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    info!(
        "current USDC balance on Althea Chain: {:?}, payment of {:?}, from address {} to address {}",
        balance, pmt.amount, our_address, to_address
    );

    let coin = Coin {
        amount: pmt.amount,
        denom: usdc_denom.denom.clone(),
    };
    // Make microtx transaction.
    let transaction = match althea_contact
        .send_microtx(
            coin,
            None,
            to_address,
            Some(Duration::from_secs(30)),
            our_private_key,
        )
        .await
    {
        Ok(a) => a,
        Err(e) => {
            error!(
                "Failed to send payment {:?} to {:?} with {:?}",
                pmt, pmt.to, e
            );
            payment_failed(pmt.to);
            return Err(PaymentControllerError::FailedToSendPayment);
        }
    };

    // setup tx hash
    let pmt = pmt.publish(Uint256::from_str_radix(&transaction.txhash, 16).unwrap());

    let retry = send_make_payment_endpoints(
        pmt,
        network_settings,
        cosmos_node_grpc,
        previously_sent_payments,
        0,
    )
    .await;

    // place this payment in the validation queue to handle later.
    let ts = ToValidate {
        payment: pmt,
        received: Instant::now(),
    };

    Ok((ts, retry))
}

/// Sends a payment on ETH based chains, this is a basic send transaction with no payload
/// returns a payment to validate and optionally a retry if we have to send details to the neighbor again
async fn make_xdai_payment(
    pmt: UnpublishedPaymentTx,
    payment_settings: PaymentSettings,
    network_settings: NetworkSettings,
    previously_sent_payments: &HashMap<Identity, HashSet<PaymentTx>>,
) -> Result<(ToValidate, Option<ResendInfo>), PaymentControllerError> {
    let balance = get_oracle_balance();
    let nonce = get_oracle_nonce();
    let gas_price = get_oracle_latest_gas_price();
    let our_private_key = &payment_settings
        .eth_private_key
        .expect("No private key configured!");
    let our_address = our_private_key.to_address();

    match sanity_check_balance(balance, &pmt) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    info!(
        "current xdai balance: {:?}, payment of {:?}, from address {} to address {} with nonce {}",
        balance, pmt.amount, our_address, pmt.to.eth_address, nonce
    );

    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSION_TIMEOUT);

    let tx = web3
        .prepare_legacy_transaction(
            pmt.to.eth_address,
            Vec::new(),
            pmt.amount,
            our_private_key.to_address(),
            *our_private_key,
            vec![
                SendTxOption::Nonce(nonce),
                SendTxOption::GasPrice(gas_price),
            ],
        )
        .await;

    match tx {
        Ok(tx) => {
            let transaction_status = web3.send_prepared_transaction(tx.clone()).await;
            let tx_id = match transaction_status {
                Ok(tx_id) => tx_id,
                Err(e) => {
                    error!(
                        "Failed to send payment {:?} to {:?} with {:?}",
                        pmt, pmt.to, e
                    );
                    // it is now possible that this transaction has been published
                    // so we have to try and determine what happened
                    if let Web3Error::JsonRpcError { .. } = e {
                        // in this case, we got a response from the full node that it did not like our
                        // tx, no chance that it is published (unless they start lying to us in a new way)
                        payment_failed(pmt.to);
                        return Err(PaymentControllerError::FailedToSendPayment);
                    } else {
                        // the published state of the tx is ambiguous, now we have to pretend like we sent it.
                        tx.txid()
                    }
                }
            };

            // increment our nonce, this allows us to send another transaction
            // right away before this one that we just sent out gets into the chain
            set_oracle_nonce(get_oracle_nonce() + 1u64.into());

            info!("Sending bw payment with txid {:#066x} current balance: {:?}, payment of {:?}, from address {} to address {} with nonce {}",
                            tx_id, balance, pmt.amount, our_address, pmt.to.eth_address, nonce);

            // add published txid to submission
            let pmt = pmt.publish(tx_id);

            let resend = send_make_payment_endpoints(
                pmt,
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
            payment_failed(pmt.to);
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
            if value < pmt.amount {
                warn!("Not enough money to pay debts! Cutoff imminent");
                // having this here really doesn't matter much, either we
                // tell debt keeper the payment failed and it enqueues another
                // that also won't succeed right away, or it waits for the timeout
                // and does the same thing.
                payment_failed(pmt.to);
                Err(PaymentControllerError::InsufficientFunds {
                    amount: pmt.amount,
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
                amount: pmt.amount,
                balance: balance.unwrap_or_else(|| 0u64.into()),
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

    txid_history.insert(pmt);

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
        pmt,
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
                        pmt.amount
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

#[test]
fn parse_althea_txhash() {
    let hash = "2B8884553F72CB4C313B2169B29F2279CCD6968A5512EFABAB1C6FE78ED86B57";
    let parsed: Uint256 = Uint256::from_str_radix(hash, 16).unwrap();
    println!("Parsed: {:?}", parsed);
    println!("{:?}", parsed.to_str_radix(16));
}
