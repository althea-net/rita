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

use althea_types::Identity;
use althea_types::PaymentTx;
use num256::Uint256;
use rita_common::blockchain_oracle::get_oracle_balance;
use rita_common::blockchain_oracle::get_oracle_latest_gas_price;
use rita_common::blockchain_oracle::get_oracle_nonce;
use rita_common::blockchain_oracle::get_pay_thresh;
use rita_common::payment_controller::TRANSACTION_SUBMISSION_TIMEOUT;
use rita_common::rita_loop::get_web3_server;
use rita_common::simulated_txfee_manager::add_tx_to_total;
use rita_common::usage_tracker::update_payments;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use web30::client::Web3;
use web30::types::SendTxOption;

lazy_static! {
    static ref OPERATOR_FEE_DATA: Arc<RwLock<OperatorFeeManager>> =
        Arc::new(RwLock::new(OperatorFeeManager::new()));
}

pub fn get_operator_fee_debt() -> Uint256 {
    let state = OPERATOR_FEE_DATA.read().unwrap();
    state.operator_debt
}

#[derive(Clone)]
struct OperatorFeeManager {
    /// the operator fee is denominated in wei per second, so every time this routine runs
    /// we take the number of seconds since the last time it ran and multiply that by the
    /// operator fee and add to operator_fee_debt which we eventually pay
    last_updated: Instant,
    /// How much we owe the operator, note this *CAN NOT* be safely eliminated and replaced
    /// by just computing off of the last updated time, if the operator fee is changed while
    /// the node is live it will result in a large back-payment
    operator_debt: Uint256,
}

impl OperatorFeeManager {
    fn new() -> OperatorFeeManager {
        OperatorFeeManager {
            last_updated: Instant::now(),
            operator_debt: 0u8.into(),
        }
    }
}

fn get_operator_fee_data() -> OperatorFeeManager {
    OPERATOR_FEE_DATA.write().unwrap().clone()
}

fn set_operator_fee_data(set: OperatorFeeManager) {
    *OPERATOR_FEE_DATA.write().unwrap() = set;
}

/// Very basic loop for async operator payments
pub async fn tick_operator_payments() {
    // get variables
    let common = settings::get_rita_common();
    let client = settings::get_rita_client();
    let our_id = match common.get_identity() {
        Some(id) => id,
        None => return,
    };
    let operator_settings = client.operator;
    let payment_settings = common.payment;
    let eth_private_key = payment_settings.eth_private_key.unwrap();
    let our_balance = get_oracle_balance();
    let gas_price = get_oracle_latest_gas_price();
    let nonce = get_oracle_nonce();
    let pay_threshold = get_pay_thresh();
    let operator_address = match operator_settings.operator_address {
        Some(val) => val,
        None => return,
    };
    let operator_fee = operator_settings.operator_fee;

    let mut state = get_operator_fee_data();

    // accumulate, if we don't pay this will count up, if we do pay we will pay the full amount
    let last_updated = state.last_updated.elapsed().as_secs();
    state.operator_debt += Uint256::from(last_updated) * operator_fee;
    state.last_updated = Instant::now();
    set_operator_fee_data(state.clone());

    // reassign to an immutable variable to prevent mistakes
    let amount_to_pay = state.operator_debt;

    // we should pay if the amount is greater than the pay threshold and if we have the
    // balance to do so.
    let should_pay = amount_to_pay.to_int256().unwrap_or_else(|| 0u64.into()) > pay_threshold
        && amount_to_pay <= our_balance.unwrap_or_else(|| 0u64.into());
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

        let transaction_status = web3
            .send_transaction(
                operator_address,
                Vec::new(),
                amount_to_pay,
                eth_private_key,
                vec![
                    SendTxOption::Nonce(nonce),
                    SendTxOption::GasPrice(gas_price),
                ],
            )
            .await;

        // in theory this may fail to get into a block, for now there is no handler and
        // we will just underpay when that occurs. Failure to successfully submit the tx
        // will be properly retried
        match transaction_status {
            Ok(txid) => {
                info!(
                    "Successfully paid the operator {} wei with txid: {:#066x}!",
                    amount_to_pay, txid
                );
                update_payments(PaymentTx {
                    to: operator_identity,
                    from: our_id,
                    amount: amount_to_pay,
                    txid,
                });
                add_tx_to_total(amount_to_pay);
                state.operator_debt -= amount_to_pay;
                set_operator_fee_data(state);
            }
            Err(e) => {
                warn!("Failed to pay the operator! {:?}", e);
            }
        }
    }
}
