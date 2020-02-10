//! The maintainer fee is a fraction of all payments that is sent to the firmware maintainer

use crate::rita_common::payment_controller::TRANSACTION_SUBMISSON_TIMEOUT;
use crate::rita_common::rita_loop::get_web3_server;
use crate::rita_common::usage_tracker::UpdatePayments;
use crate::rita_common::usage_tracker::UsageTracker;
use crate::SETTING;
use actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use althea_types::Identity;
use althea_types::PaymentTx;
use clarity::Transaction;
use futures01::future::Future;
use num256::Uint256;
use num_traits::Signed;
use num_traits::Zero;
use settings::RitaCommonSettings;
use web30::client::Web3;

pub struct SimulatedTxFeeManager {
    amount_owed: Uint256,
}

impl Actor for SimulatedTxFeeManager {
    type Context = Context<Self>;
}
impl Supervised for SimulatedTxFeeManager {}
impl SystemService for SimulatedTxFeeManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("SimulatedTxFeeManager started");
    }
}

impl Default for SimulatedTxFeeManager {
    fn default() -> SimulatedTxFeeManager {
        SimulatedTxFeeManager::new()
    }
}

impl SimulatedTxFeeManager {
    fn new() -> SimulatedTxFeeManager {
        SimulatedTxFeeManager {
            amount_owed: Uint256::zero(),
        }
    }
}

struct SuccessfulPayment(Uint256);
impl Message for SuccessfulPayment {
    type Result = ();
}

impl Handler<SuccessfulPayment> for SimulatedTxFeeManager {
    type Result = ();

    fn handle(&mut self, msg: SuccessfulPayment, _: &mut Context<Self>) -> Self::Result {
        let payment_amount = msg.0;
        if payment_amount <= self.amount_owed {
            self.amount_owed = self.amount_owed.clone() - payment_amount;
        } else {
            // I don't think this can ever happen unless successful
            // payment gets called outside of this actor, or more than one
            // instance of this actor exists, System service prevents the later
            // and the lack of 'pub' prevents the former
            error!("Maintainer fee overpayment!")
        }
    }
}

// this is sent when a transaction is successful in another module and it registers
// some amount to be paid as part of the fee
pub struct AddTxToTotal(pub Uint256);
impl Message for AddTxToTotal {
    type Result = ();
}

impl Handler<AddTxToTotal> for SimulatedTxFeeManager {
    type Result = ();

    fn handle(&mut self, msg: AddTxToTotal, _: &mut Context<Self>) -> Self::Result {
        let to_add = msg.0 / SETTING.get_payment().simulated_transaction_fee.into();
        info!(
            "Simulated txfee total is {} with {} to add",
            self.amount_owed, to_add
        );
        self.amount_owed += to_add;
    }
}

/// Very basic loop for simulated txfee payments
pub struct Tick;
impl Message for Tick {
    type Result = ();
}

impl Handler<Tick> for SimulatedTxFeeManager {
    type Result = ();

    fn handle(&mut self, _msg: Tick, _: &mut Context<Self>) -> Self::Result {
        let payment_settings = SETTING.get_payment();
        let eth_private_key = payment_settings.eth_private_key;
        let our_id = match SETTING.get_identity() {
            Some(id) => id,
            None => return,
        };
        let gas_price = payment_settings.gas_price.clone();
        let nonce = payment_settings.nonce.clone();
        let pay_threshold = payment_settings.pay_threshold.clone();
        let simulated_transaction_fee_address = payment_settings.simulated_transaction_fee_address;
        let simulated_transaction_fee = payment_settings.simulated_transaction_fee;
        let amount_to_pay = self.amount_owed.clone();
        let should_pay = amount_to_pay > pay_threshold.abs().to_uint256().unwrap();
        let net_version = payment_settings.net_version;
        drop(payment_settings);
        trace!(
            "We should pay the simulated tx fee {} of 1/{} % to {}",
            should_pay,
            simulated_transaction_fee,
            simulated_transaction_fee_address
        );
        if !should_pay {
            return;
        }

        let txfee_identity = Identity {
            eth_address: simulated_transaction_fee_address,
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
            to: simulated_transaction_fee_address,
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
                error!("Failed to generate simulated txfee transaction, {:?}", e);
                return;
            }
        };

        let transaction_status = web3.eth_send_raw_transaction(transaction_bytes);

        // in theory this may fail, for now there is no handler and
        // we will just underpay when that occurs
        Arbiter::spawn(transaction_status.then(move |res| match res {
            Ok(txid) => {
                info!("Successfully paid the simulated txfee {:#066x}!", txid);
                UsageTracker::from_registry().do_send(UpdatePayments {
                    payment: PaymentTx {
                        to: txfee_identity,
                        from: our_id,
                        amount: amount_to_pay.clone(),
                        txid: Some(txid),
                    },
                });
                SimulatedTxFeeManager::from_registry().do_send(SuccessfulPayment(amount_to_pay));
                Ok(())
            }
            Err(e) => {
                warn!("Failed to pay simulated txfee! {:?}", e);
                Ok(())
            }
        }));
    }
}
