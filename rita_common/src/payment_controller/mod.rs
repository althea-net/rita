//! This modules handles single transaction payments as well as
//! managing the retry flow for failed payment attempts. We will retry a payment
//! until it is successfully in a block, see payment_validator, once the payment is on
//! the blockchain it's up to the reciever to validate that it's correct

use crate::blockchain_oracle::{
    get_oracle_balance, get_oracle_latest_gas_price, get_oracle_nonce, set_oracle_nonce,
};
use crate::debt_keeper::normalize_payment_amount;
use crate::debt_keeper::payment_failed;
use crate::payment_validator::{get_payment_txids, validate_later, ToValidate};
use crate::payment_validator::{ALTHEA_CHAIN_PREFIX, ALTHEA_CONTACT_TIMEOUT};
use crate::rita_loop::get_web3_server;
use crate::KI;
use althea_types::interop::UnpublishedPaymentTx;
use althea_types::SystemChain;
use althea_types::{Denom, PaymentTx};
use awc;
use deep_space::{Coin, Contact, EthermintPrivateKey};
use futures::future::{join, join_all};
use num256::Uint256;
use num_traits::Num;
use settings::network::NetworkSettings;
use settings::payment::PaymentSettings;
use settings::{DEBT_KEEPER_DENOM, DEBT_KEEPER_DENOM_DECIMAL};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Result as DisplayResult;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::Instant;
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;
use web30::types::SendTxOption;

pub const TRANSACTION_SUBMISSION_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_TXID_RETRIES: u8 = 15u8;

lazy_static! {
    static ref PAYMENT_DATA: Arc<RwLock<HashMap<u32, PaymentController>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Gets Payment COntoller copy from the static ref, or default if no value has been set
pub fn get_payment_contoller() -> PaymentController {
    let netns = KI.check_integration_test_netns();
    PAYMENT_DATA
        .read()
        .unwrap()
        .clone()
        .get(&netns)
        .cloned()
        .unwrap_or_default()
}

/// Gets a write ref for the payment controller lock, since this is a mutable reference
/// the lock will be held until you drop the return value, this lets the caller abstract the namespace handling
/// but still hold the lock in the local thread to prevent parallel modification
pub fn get_payment_controller_write_ref(
    input: &mut HashMap<u32, PaymentController>,
) -> &mut PaymentController {
    let netns = KI.check_integration_test_netns();
    input
        .entry(netns)
        .or_insert_with(PaymentController::default);
    input.get_mut(&netns).unwrap()
}

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

/// Pushes a payment tx onto the payment controller queue, to be processed
/// on the next payment controller loop run
pub fn queue_payment(payment: UnpublishedPaymentTx) {
    info!("Payment of {:?} queued!", payment);
    let data = &mut *PAYMENT_DATA.write().unwrap();
    let data = get_payment_controller_write_ref(data);
    data.outgoing_queue.push(payment);
}

/// Pushes a resend onto the payment controller queue, to be processed
/// on the next payment controller loop run
fn queue_resend(resend_info: ResendInfo) {
    info!("Resend of {:?} queued!", resend_info);
    let data = &mut *PAYMENT_DATA.write().unwrap();
    let data = get_payment_controller_write_ref(data);
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
    let outgoing_payments: Vec<UnpublishedPaymentTx>;
    let resend_queue: Vec<ResendInfo>;

    {
        let data = &mut *PAYMENT_DATA.write().unwrap();
        let data = get_payment_controller_write_ref(data);

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
async fn make_payment(pmt: UnpublishedPaymentTx) -> Result<(), PaymentControllerError> {
    let common = settings::get_rita_common();
    let network_settings = common.network;
    let payment_settings = common.payment;
    let system_chain = payment_settings.system_chain;

    match system_chain {
        SystemChain::Althea => make_althea_payment(pmt, payment_settings, network_settings).await,
        SystemChain::Xdai => make_xdai_payment(pmt, payment_settings, network_settings).await,
        SystemChain::Rinkeby => {
            warn!("Payments on Rinkeby not currently supported!");
            Ok(())
        }
        SystemChain::Ethereum => {
            warn!("Payments on Ethereum not currently supported!");
            Ok(())
        }
    }
}

async fn make_althea_payment(
    mut pmt: UnpublishedPaymentTx,
    payment_settings: PaymentSettings,
    network_settings: NetworkSettings,
) -> Result<(), PaymentControllerError> {
    // On althea chain, we default to paying with usdc, config must specify this as an accepted denom
    let usdc_denom = match payment_settings
        .accepted_denoms
        .unwrap_or(HashMap::new())
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

    send_make_payment_endpoints(pmt, network_settings, None, Some(cosmos_node_grpc)).await;

    // place this payment in the validation queue to handle later.
    let ts = ToValidate {
        payment: pmt,
        received: Instant::now(),
        checked: false,
    };

    if let Err(e) = validate_later(ts.clone()) {
        error!("Received error trying to validate {:?} Error: {:?}", ts, e);
    }

    Ok(())
}

async fn make_xdai_payment(
    pmt: UnpublishedPaymentTx,
    payment_settings: PaymentSettings,
    network_settings: NetworkSettings,
) -> Result<(), PaymentControllerError> {
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

            send_make_payment_endpoints(pmt.clone(), network_settings, Some(full_node), None).await;

            // place this payment in the validation queue to handle later.
            let ts = ToValidate {
                payment: pmt,
                received: Instant::now(),
                checked: false,
            };

            if let Err(e) = validate_later(ts.clone()) {
                error!("Received error trying to validate {:?} Error: {:?}", ts, e);
            }

            Ok(())
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

async fn send_make_payment_endpoints(
    pmt: PaymentTx,
    network_settings: NetworkSettings,
    full_node: Option<String>,
    cosmos_node_grpc: Option<String>,
) {
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

    // Get all txids to this client. Temporary add new payment to a copy of a list to send up to endpoint
    // this pmt is actually recorded in memory after validator confirms it
    let mut txid_history = get_payment_txids(pmt.to);
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
        neigh_url: neighbor_url.clone(),
        pmt,
        attempt: 0u8,
    };

    // Hit both endpoints, in the case of a node having both endpoints, validator will simply get a duplicate transaction txid and discard it.
    let (neigh_ack_v2, neigh_ack) = join(neigh_ack_v2, neigh_ack).await;

    let tx_id = pmt.txid;
    match (neigh_ack_v2, neigh_ack) {
        (Ok(mut val2), Ok(mut val)) => {
            // THis is probably a b20 router
            match (val2.status().is_success(), val.status().is_success()) {
                (true, _) => {
                    info!(
                        "Payment pmt with tx identifier: {} is sent to our neighbor with status {:?} and body {:?} via url {}, using node {:?} and amount {}",
                        format!("{:#066x}", tx_id),
                        val2.status(),
                        val2.body().await,
                        neighbor_url_v2,
                        {
                            if full_node.is_some() {
                                full_node
                            } else {
                                cosmos_node_grpc
                            }
                        },
                        pmt.amount
                    );
                }
                (false, true) => {
                    error!(
                        "Make_payment_v2 with tx identifier {} failed with status {:?} and body {:?}",
                        format!("{:#066x}", tx_id),
                        val2.status(),
                        val2.body().await
                    );
                    info!(
                        "Payment pmt with tx identifier: {} is sent to our neighbor with status {:?} and body {:?} via url {}, using node {:?} and amount {}",
                        format!("{:#066x}", tx_id),
                        val.status(),
                        val.body().await,
                        neighbor_url,
                        {
                            if full_node.is_some() {
                                full_node
                            } else {
                                cosmos_node_grpc
                            }
                        },
                        pmt.amount
                    );
                }
                _ => {
                    error!(
                        "We published txid: {} to url {} but our neighbor responded with status {:?} and body {:?}, will retry",
                                format!("{:#066x}", tx_id), neighbor_url, val.status(), val.body().await);
                    queue_resend(resend_info);
                }
            }
        }
        (Err(_), Ok(mut val)) => {
            // probably a b19 router
            if val.status().is_success() {
                info!(
                    "Payment pmt with txid: {} is sent to our neighbor with status {:?} and body {:?} via url {}, using node {:?} and amount {}",
                    format!("{:#066x}", tx_id),
                    val.status(),
                    val.body().await,
                    neighbor_url,
                    {
                        if full_node.is_some() {
                            full_node
                        } else {
                            cosmos_node_grpc
                        }
                    },
                    pmt.amount
                );
            } else {
                error!(
                    "Make_payment with tx identifier {} failed with status {:?} and body {:?}",
                    format!("{:#066x}", tx_id),
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
                    "Payment pmt with txid: {} is sent to our neighbor with status {:?} and body {:?} via url {}, using node {:?} and amount {}",
                    format!("{:#066x}", tx_id),
                    val2.status(),
                    val2.body().await,
                    neighbor_url_v2,
                    {
                        if full_node.is_some() {
                            full_node
                        } else {
                            cosmos_node_grpc
                        }
                    },
                    pmt.amount
                );
            } else {
                error!(
                    "Make_payment_v2 with txid {} failed with status {:?} and body {:?}",
                    format!("{:#066x}", tx_id),
                    val2.status(),
                    val2.body().await
                );
            }
        }
        (Err(_), Err(e)) => {
            // Why is make payment failing here? Call a resend
            error!(
                "We published txid: {} but failed to notify our neighbor with {:?}, will retry",
                format!("{:#066x}", tx_id),
                e
            );
            queue_resend(resend_info)
        }
    }
}

#[derive(Debug, Clone)]
struct ResendInfo {
    neigh_url: String,
    pmt: PaymentTx,
    attempt: u8,
}

/// For some reason we have sent a payment and managed not to notify our neighbor, this routine will
/// retry up to MAX_TXID_RETIRES times
async fn resend_txid(input: ResendInfo) -> Result<(), PaymentControllerError> {
    let tx_id = input.pmt.txid;

    let mut input = input;
    input.attempt += 1;

    // at this point the chance of success is too tiny to be worth it
    if input.attempt > MAX_TXID_RETRIES {
        error!(
            "We have failed to send txid {} this payment will remain uncredited!",
            { format!("{:#066x}", tx_id) },
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
        error!("retry failed with published txid: {}", {
            format!("{:#066x}", tx_id)
        },);
        queue_resend(input);
    }

    Ok(())
}

#[test]
fn parse_althea_txhash() {
    let hash = "2B8884553F72CB4C313B2169B29F2279CCD6968A5512EFABAB1C6FE78ED86B57";
    let parsed: Uint256 = Uint256::from_str_radix(hash, 16).unwrap();
    println!("Parsed: {:?}", parsed);
    println!("{:?}", parsed.to_str_radix(16));
}
