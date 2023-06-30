//! The maintainer fee is a fraction of all payments that is sent to the firmware maintainer

use crate::blockchain_oracle::get_oracle_latest_gas_price;
use crate::blockchain_oracle::get_oracle_nonce;
use crate::blockchain_oracle::get_pay_thresh;
use crate::payment_controller::TRANSACTION_SUBMISSION_TIMEOUT;
use crate::rita_loop::get_web3_server;
use crate::usage_tracker::update_payments;
use crate::KI;
use althea_types::Identity;
use althea_types::PaymentTx;
use num256::Uint256;
use num_traits::{Signed, Zero};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use web30::client::Web3;
use web30::types::SendTxOption;

lazy_static! {
    static ref AMOUNT_OWED: Arc<RwLock<HashMap<u32, Uint256>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Gets Amount owed copy from the static ref, or default if no value has been set
pub fn get_amount_owed() -> Uint256 {
    let netns = KI.check_integration_test_netns();
    AMOUNT_OWED
        .read()
        .unwrap()
        .clone()
        .get(&netns)
        .cloned()
        .unwrap_or(Uint256::zero())
}

/// Gets a write ref for the amount owed lock, since this is a mutable reference
/// the lock will be held until you drop the return value, this lets the caller abstract the namespace handling
/// but still hold the lock in the local thread to prevent parallel modification
pub fn get_amount_owed_write_ref(input: &mut HashMap<u32, Uint256>) -> &mut Uint256 {
    let netns = KI.check_integration_test_netns();
    input.entry(netns).or_insert_with(Uint256::zero);
    input.get_mut(&netns).unwrap()
}

// this is sent when a transaction is successful in another module and it registers
// some amount to be paid as part of the fee
pub fn add_tx_to_total(amount: Uint256) {
    let simulated_transaction_fee = settings::get_rita_common()
        .payment
        .simulated_transaction_fee;
    let to_add = amount / simulated_transaction_fee.into();
    let amount_owed = &mut *AMOUNT_OWED.write().unwrap();
    let amount_owed = get_amount_owed_write_ref(amount_owed);
    info!(
        "Simulated txfee total is {} with {} to add",
        amount_owed, to_add
    );
    *amount_owed += to_add;
}

pub async fn tick_simulated_tx() {
    let payment_settings = settings::get_rita_common().payment;
    let eth_private_key = payment_settings.eth_private_key.unwrap();
    let our_id = match settings::get_rita_common().get_identity() {
        Some(id) => id,
        None => return,
    };
    let gas_price = get_oracle_latest_gas_price();
    let nonce = get_oracle_nonce();
    let pay_threshold = get_pay_thresh();
    let simulated_transaction_fee_address = payment_settings.simulated_transaction_fee_address;
    let simulated_transaction_fee = payment_settings.simulated_transaction_fee;
    let amount_to_pay = get_amount_owed();
    let should_pay = amount_to_pay > pay_threshold.abs().to_uint256().unwrap();
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

    let transaction_status = web3.send_transaction(
        simulated_transaction_fee_address,
        Vec::new(),
        amount_to_pay,
        eth_private_key,
        vec![
            SendTxOption::Nonce(nonce),
            SendTxOption::GasPrice(gas_price),
        ],
    );

    // in theory this may fail, for now there is no handler and
    // we will just underpay when that occurs
    match transaction_status.await {
        Ok(txid) => {
            info!("Successfully paid the simulated txfee {:#066x}!", txid);
            update_payments(PaymentTx {
                to: txfee_identity,
                from: our_id,
                amount: amount_to_pay,
                txid,
            });

            // update the billing now that the payment has gone through
            let amount_owed = &mut *AMOUNT_OWED.write().unwrap();
            let amount_owed = get_amount_owed_write_ref(amount_owed);
            let payment_amount = amount_to_pay;
            if payment_amount <= *amount_owed {
                *amount_owed -= payment_amount;
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
