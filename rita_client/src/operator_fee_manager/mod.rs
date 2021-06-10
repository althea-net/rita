//! The operator fee is a fixed fee for service paid to an organizer address
//! The organizer address is also used as the index for all live Althea networks
//! in operator tools, any router with any new operator address will simply poof
//! a network into existence in operator tools.
//!
//! This file contains the logic for the 'operator fee' a pro-rated fixed fee paid
//! out over time by the router automatically, the operator fee can be configured in
//! operator tools or locally on the router.
//!
//! In order to compute the fee a timer is used. So a $100/mo fee equates to 30 microcents
//! a second. The reason we pay out this way is because users really don't like it when their
//! balance changes suddenly, so if they deposit $125 and the router instantly takes $100 to
//! pay their fee it's not a great situation. All that being said it's probable that this
//! will need to be re-written to better reflect a normal billing system at some point, perhaps
//! querying an API for an individual bill. As this is not designed to be a trustless payment

use rita_common::payment_controller::TRANSACTION_SUBMISSION_TIMEOUT;
use rita_common::rita_loop::get_web3_server;
use rita_common::simulated_txfee_manager::add_tx_to_total;
use rita_common::usage_tracker::handle_payment_data;
use rita_common::usage_tracker::UpdatePayments;

use ::actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use althea_types::Identity;
use althea_types::PaymentTx;
use clarity::Transaction;
use futures01::future::Future;
use num256::Int256;
use num256::Uint256;
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
    /// the operator fee is denominated in wei per second, so every time this routine runs
    /// we take the number of seconds since the last time it ran and multiply that by the
    /// operator fee and add to operator_fee_debt which we eventually pay
    last_updated: Instant,
    /// the amount in operator fees we owe to the operator address
    operator_fee_debt: Uint256,
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
            last_updated: Instant::now(),
            operator_fee_debt: 0u8.into(),
        }
    }
}

pub struct SuccessfulPayment {
    amount: Uint256,
}
impl Message for SuccessfulPayment {
    type Result = ();
}

impl Handler<SuccessfulPayment> for OperatorFeeManager {
    type Result = ();

    fn handle(&mut self, msg: SuccessfulPayment, _: &mut Context<Self>) -> Self::Result {
        if msg.amount > self.operator_fee_debt {
            self.operator_fee_debt = 0u8.into();
            // this should never happen, in theory the amount might go up (routine gets run again
            // before this call back is run) but there's no way I can think of for the counter to
            // run backwards, nonetheless we should handle it.
            error!(
                "Payment is greater than op debt? Should be impossible! {} > {}",
                msg.amount, self.operator_fee_debt
            )
        } else {
            self.operator_fee_debt -= msg.amount;
        }
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
        // get variables
        let mut rita_client = settings::get_rita_client();
        let operator_settings = rita_client.operator;
        let payment_settings = rita_client.payment;
        let eth_private_key = payment_settings.eth_private_key;
        let our_id = match settings::get_rita_client().get_identity() {
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
        let net_version = payment_settings.net_version;

        // accumulate what we owe
        self.operator_fee_debt +=
            Uint256::from(self.last_updated.elapsed().as_secs()) * operator_fee;
        self.last_updated = Instant::now();

        // reassign to immutable variable to avoid accidents
        let amount_to_pay = self.operator_fee_debt.clone();

        // update globally accessible lock value, will be removed when this module goes async
        *OPERATOR_FEE_DEBT.write().unwrap() = amount_to_pay.clone();

        // we should pay if the amount is greater than the pay threshold and if we have the
        // balance to do so. If we don't have the balance then we'll do all the signing and
        // network request for nothing
        let should_pay = amount_to_pay.to_int256().unwrap_or_else(|| Int256::from(0))
            > pay_threshold
            && amount_to_pay <= our_balance;
        trace!("We should pay our operator {}", should_pay);

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
            let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSION_TIMEOUT);

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

                    handle_payment_data(UpdatePayments {
                        payment: PaymentTx {
                            to: operator_identity,
                            from: our_id,
                            amount: amount_to_pay.clone(),
                            txid: Some(txid),
                        },
                    });

                    add_tx_to_total(amount_to_pay.clone());
                    OperatorFeeManager::from_registry().do_send(SuccessfulPayment {
                        amount: amount_to_pay,
                    });
                    Ok(())
                }
                Err(e) => {
                    warn!("Failed to pay the operator! {:?}", e);
                    Ok(())
                }
            }));
        }
        rita_client.operator = operator_settings;
        rita_client.payment = payment_settings;
        settings::set_rita_client(rita_client);
    }
}
