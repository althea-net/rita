//! The maintainer fee is a fraction of all payments that is sent to the firmware maintainer

use crate::rita_common::payment_controller::TRANSACTION_SUBMISSION_TIMEOUT;
use crate::rita_common::rita_loop::get_web3_server;
use crate::rita_common::usage_tracker::update_payments;
use crate::SETTING;
use althea_types::Identity;
use althea_types::PaymentTx;
use async_web30::client::Web3;
use clarity::Transaction;
use num256::Uint256;
use num_traits::Signed;
use num_traits::Zero;
use settings::RitaCommonSettings;
use std::sync::Arc;
use std::sync::RwLock;

lazy_static! {
    static ref AMOUNT_OWED: Arc<RwLock<Uint256>> = Arc::new(RwLock::new(Uint256::zero()));
}

// this is sent when a transaction is successful in another module and it registers
// some amount to be paid as part of the fee
pub fn add_tx_to_total(amount: Uint256) {
    let to_add = amount / SETTING.get_payment().simulated_transaction_fee.into();
    let mut amount_owed = AMOUNT_OWED.write().unwrap();
    info!(
        "Simulated txfee total is {} with {} to add",
        amount_owed, to_add
    );
    *amount_owed += to_add;
}

pub async fn tick_simulated_tx() {
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
    let amount_to_pay = AMOUNT_OWED.read().unwrap().clone();
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
    let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSION_TIMEOUT);

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
    match transaction_status.await {
        Ok(txid) => {
            info!("Successfully paid the simulated txfee {:#066x}!", txid);
            update_payments(PaymentTx {
                to: txfee_identity,
                from: our_id,
                amount: amount_to_pay.clone(),
                txid: Some(txid),
            });

            // update the billing now that the payment has gone through
            let mut amount_owed = AMOUNT_OWED.write().unwrap();
            let payment_amount = amount_to_pay;
            if payment_amount <= *amount_owed {
                *amount_owed = amount_owed.clone() - payment_amount;
            } else {
                // I don't think this can ever happen unless successful
                // payment gets called outside of this actor, or more than one
                // instance of this actor exists, System service prevents the later
                // and the lack of 'pub' prevents the former
                error!("Maintainer fee overpayment!")
            }
        }
        Err(e) => {
            warn!("Failed to pay simulated txfee! {:?}", e);
        }
    };
}
