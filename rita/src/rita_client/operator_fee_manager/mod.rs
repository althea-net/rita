//! In the longer term this is supposed to manage SubnetDAO membership, for the time being
//! it simply manages payments to a multisig walllet address without any of the other indtended
//! features of the subnet DAO system.
//! The multisig payments are performed much like the bandwidth payments, using a target fee amount
//! to compute the amount it should pay at a time, these micropayments have the effect of pro-rating
//! the DAO fee amount and preventing the router from drastically making a large payment

use crate::rita_common::payment_controller::TRANSACTION_SUBMISSON_TIMEOUT;
use crate::rita_common::rita_loop::get_web3_server;
use crate::rita_common::simulated_txfee_manager::AddTxToTotal;
use crate::rita_common::simulated_txfee_manager::SimulatedTxFeeManager;
use crate::rita_common::usage_tracker::UpdatePayments;
use crate::rita_common::usage_tracker::UsageTracker;
use crate::SETTING;
use ::actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use althea_types::Identity;
use althea_types::PaymentTx;
use clarity::Transaction;
use futures01::future::Future;
use num256::Int256;
use num256::Uint256;
use settings::client::RitaClientSettings;
use settings::RitaCommonSettings;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use web30::client::Web3;

lazy_static! {
    static ref OPERATOR_FEE_DEBT: Arc<RwLock<Uint256>> = Arc::new(RwLock::new(Uint256::from(0u8)));
}

pub fn get_operator_fee_debt() -> Uint256 {
    OPERATOR_FEE_DEBT.read().unwrap().clone()
}

pub struct OperatorFeeManager {
    last_payment_time: Instant,
}

impl Actor for OperatorFeeManager {
    type Context = Context<Self>;
}
impl Supervised for OperatorFeeManager {}
impl SystemService for OperatorFeeManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("OperatorFee manager started");
    }
}

impl Default for OperatorFeeManager {
    fn default() -> OperatorFeeManager {
        OperatorFeeManager::new()
    }
}

impl OperatorFeeManager {
    fn new() -> OperatorFeeManager {
        OperatorFeeManager {
            last_payment_time: Instant::now(),
        }
    }
}

pub struct SuccessfulPayment {
    timestamp: Instant,
}
impl Message for SuccessfulPayment {
    type Result = ();
}

impl Handler<SuccessfulPayment> for OperatorFeeManager {
    type Result = ();

    fn handle(&mut self, msg: SuccessfulPayment, _: &mut Context<Self>) -> Self::Result {
        self.last_payment_time = msg.timestamp;
    }
}

/// Very basic loop for Operator payments
pub struct Tick;
impl Message for Tick {
    type Result = ();
}

impl Handler<Tick> for OperatorFeeManager {
    type Result = ();

    fn handle(&mut self, _msg: Tick, _: &mut Context<Self>) -> Self::Result {
        let payment_send_time = Instant::now();
        let operator_settings = SETTING.get_operator();
        let payment_settings = SETTING.get_payment();
        let eth_private_key = payment_settings.eth_private_key;
        let our_id = match SETTING.get_identity() {
            Some(id) => id,
            None => return,
        };
        let our_balance = payment_settings.balance.clone();
        let gas_price = payment_settings.gas_price.clone();
        let nonce = payment_settings.nonce.clone();
        let pay_threshold = payment_settings.pay_threshold.clone();
        let operator_address = match operator_settings.operator_address {
            Some(val) => val,
            None => return,
        };
        let operator_fee = operator_settings.operator_fee.clone();
        let amount_to_pay =
            Uint256::from(self.last_payment_time.elapsed().as_secs()) * operator_fee;
        let net_version = payment_settings.net_version;

        // we should pay if the amount is greater than the pay threshold and if we have the
        // balance to do so. If we don't have the balance then we'll do all the signing and
        // network request for nothing
        let should_pay = amount_to_pay.to_int256().unwrap_or_else(|| Int256::from(0))
            > pay_threshold
            && amount_to_pay <= our_balance;
        drop(payment_settings);
        trace!("We should pay our operator {}", should_pay);

        *OPERATOR_FEE_DEBT.write().unwrap() = amount_to_pay.clone();

        if should_pay {
            trace!("Paying subnet operator fee to {}", operator_address);

            let operator_identity = Identity {
                eth_address: operator_address,
                // this key has no meaning, it's here so that we don't have to change
                // the identity indexing
                wg_public_key: "YJhxFPv+NVeU5e+eBmwIXFd/pVdgk61jUHojuSt8IU0="
                    .parse()
                    .unwrap(),
                mesh_ip: "::1".parse().unwrap(),
                nickname: None,
            };

            let full_node = get_web3_server();
            let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSON_TIMEOUT);

            let tx = Transaction {
                nonce,
                gas_price,
                gas_limit: "21000".parse().unwrap(),
                to: operator_address,
                value: amount_to_pay.clone(),
                data: Vec::new(),
                signature: None,
            };
            let transaction_signed = tx.sign(
                &eth_private_key.expect("No private key configured!"),
                net_version,
            );

            let transaction_bytes = match transaction_signed.to_bytes() {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to generate operator fee transaction, {:?}", e);
                    return;
                }
            };

            let transaction_status = web3.eth_send_raw_transaction(transaction_bytes);

            // in theory this may fail to get into a block, for now there is no handler and
            // we will just underpay when that occurs. Failure to successfully submit the tx
            // will be properly retried
            Arbiter::spawn(transaction_status.then(move |res| match res {
                Ok(txid) => {
                    info!(
                        "Successfully paid the operator {} wei with txid: {:#066x}!",
                        amount_to_pay, txid
                    );
                    UsageTracker::from_registry().do_send(UpdatePayments {
                        payment: PaymentTx {
                            to: operator_identity,
                            from: our_id,
                            amount: amount_to_pay.clone(),
                            txid: Some(txid),
                        },
                    });
                    SimulatedTxFeeManager::from_registry().do_send(AddTxToTotal(amount_to_pay));
                    OperatorFeeManager::from_registry().do_send(SuccessfulPayment {
                        timestamp: payment_send_time,
                    });
                    Ok(())
                }
                Err(e) => {
                    warn!("Failed to pay the operator! {:?}", e);
                    Ok(())
                }
            }));
        }
    }
}
