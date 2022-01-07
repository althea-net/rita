//! This module is dedicated to updating local state with various pieces of information
//! relating to the blockchain being used. First and foremost is maintaining an updated
//! balance and nonce as well as computing more complicated things like the closing and
//! payment threshold based on gas prices.

use crate::rita_loop::fast_loop::FAST_LOOP_TIMEOUT;
use crate::rita_loop::get_web3_server;
use clarity::Address;
use futures::future::join4;
use num256::Int256;
use num256::Uint256;
use settings::payment::PaymentSettings;
use web30::client::Web3;

use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

lazy_static! {
    static ref ORACLE: Arc<RwLock<BlockchainOracle>> =
        Arc::new(RwLock::new(BlockchainOracle::new()));
}

pub struct BlockchainOracle {}

impl BlockchainOracle {
    pub fn new() -> Self {
        BlockchainOracle {}
    }
}

impl Default for BlockchainOracle {
    fn default() -> BlockchainOracle {
        BlockchainOracle::new()
    }
}

/// How long we wait for a response from the full node
/// this value must be less than or equal to the FAST_LOOP_SPEED
/// in the rita_common fast loop
pub const ORACLE_TIMEOUT: Duration = FAST_LOOP_TIMEOUT;

pub async fn update() {
    let payment_settings = settings::get_rita_common().payment;
    let our_address = payment_settings.eth_address.expect("No address!");

    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, ORACLE_TIMEOUT);

    info!("About to make web3 requests to {}", full_node);
    update_blockchain_info(our_address, web3, full_node).await;
}

async fn update_blockchain_info(our_address: Address, web3: Web3, full_node: String) {
    let balance = web3.eth_get_balance(our_address);
    let nonce = web3.eth_get_transaction_count(our_address);
    let net_version = web3.net_version();
    let gas_price = web3.eth_gas_price();
    let (balance, nonce, net_version, gas_price) =
        join4(balance, nonce, net_version, gas_price).await;
    let mut settings = settings::get_rita_common();
    match balance {
        Ok(balance) => update_balance(&full_node, &mut settings.payment.balance, balance),
        Err(e) => warn!("Failed to update balance with {:?}", e),
    }
    match gas_price {
        Ok(gas_price) => update_gas_price(&full_node, gas_price, &mut settings.payment),
        Err(e) => warn!("Failed to update gas price with {:?}", e),
    }
    match net_version {
        Ok(net_version) => {
            update_net_version(&full_node, &mut settings.payment.net_version, net_version)
        }
        Err(e) => warn!("Failed to update net_version with {:?}", e),
    }
    match nonce {
        Ok(nonce) => update_nonce(&full_node, nonce, &mut settings.payment.nonce),
        Err(e) => warn!("Failed to update nonce with {:?}", e),
    }
    settings::set_rita_common(settings);
}

/// Gets the balance for the provided eth address and updates it
/// in the global SETTING variable, do not use this function as a generic
/// balance getter.
fn update_balance(full_node: &str, our_balance: &mut Uint256, new_balance: Uint256) {
    let value = new_balance;
    info!(
        "Got response from {} balance request {:?}",
        full_node, value
    );

    *our_balance = value;
}

/// Updates the net_version in our global setting variable, this function
/// specifically runs into some security issues, a hostile node could provide
/// us with the wrong net_version, hoping to get a signed transaction good for
/// a different network than the one we are actually using. For example an address
/// that contains both real eth and test eth may be tricked into singing a transaction
/// for real eth while operating on the testnet. Because of this we have warnings behavior
fn update_net_version(full_node: &str, net_version: &mut Option<u64>, new_net_version: u64) {
    info!(
        "Got response from {} for net_version request {:?}",
        full_node, new_net_version
    );
    // we could just take the first value and kept it but for now
    // lets check that all nodes always agree on net version constantly
    if net_version.is_some() && net_version.unwrap() != new_net_version {
        error!("GOT A DIFFERENT NETWORK ID VALUE, IT IS CRITICAL THAT YOU REVIEW YOUR NODE LIST FOR HOSTILE/MISCONFIGURED NODES");
    } else if net_version.is_none() {
        *net_version = Some(new_net_version);
    }
}

/// Updates the nonce in global SETTING storage. The nonce of our next transaction
/// must always be greater than the nonce of our last transaction, since it's possible that other
/// programs are using the same private key and/or the router may be reset we need to get the nonce
/// from the blockchain at least once. We stick to incrementing it locally once we have it.
///
/// A potential attack here would be providing a lower nonce to cause you to replace an earlier transaction
/// that is still unconfirmed. That's a bit of a streach, more realistiically this would be spoofed in conjunction
/// with net_version
fn update_nonce(full_node: &str, transaction_count: Uint256, nonce: &mut Uint256) {
    info!(
        "Got response from {} for nonce request {:?}",
        full_node, transaction_count
    );
    *nonce = transaction_count;
}

/// This function updates the gas price and in the process adjusts our payment threshold
/// The average gas price over the last hour are averaged by the web3 call we then adjust our
/// expected payment amount and grace period so that every transaction pays 5% in transaction fees
/// (or whatever they care to configure as dyanmic_fee_factor). This also handles dramatic spikes in
/// gas prices by increasing the maximum debt before a drop to the free tier occurs. So if the blockchain
/// is simply to busy to use for some period of time payments will simply wait.
fn update_gas_price(
    full_node: &str,
    new_gas_price: Uint256,
    payment_settings: &mut PaymentSettings,
) {
    let mut value = new_gas_price;
    info!(
        "Got response from {} for gas price request {:?}",
        full_node, value
    );
    // Dynamic fee computation

    // use 105% of the gas price provided by the full node, this is designed
    // to keep us above the median price provided by the full node.
    // This should ensure that we maintain a higher-than-median priority even
    // if the network is being spammed with transactions
    value = value.clone() + (value / 20u32.into());

    // enforce minimum and maximum gas price rules
    // TODO This can be removed post xdai EIP1559 as it resolves the issues that
    // require this
    let min_gas: Uint256 = payment_settings.min_gas.into();
    payment_settings.gas_price = if value < min_gas {
        info!("gas price is low setting to! {}", min_gas);
        min_gas
    } else {
        value
    };

    let dynamic_fee_factor: Int256 = payment_settings.dynamic_fee_multiplier.into();
    let transaction_gas: Int256 = 21000.into();
    let neg_one = -1i32;
    let sign_flip: Int256 = neg_one.into();

    if let Some(gas_price) = payment_settings.gas_price.to_int256() {
        payment_settings.pay_threshold = transaction_gas * gas_price * dynamic_fee_factor;
    }
    trace!(
        "Dynamically set pay threshold to {:?}",
        payment_settings.pay_threshold
    );

    payment_settings.close_threshold =
        sign_flip * 4u32.into() * payment_settings.pay_threshold.clone();
    trace!(
        "Dynamically set close threshold to {:?}",
        payment_settings.close_threshold
    );
}

/// A very simple function placed here for convinence that indicates
/// if the system should go into low balance mode
pub fn low_balance() -> bool {
    let payment_settings = settings::get_rita_common().payment;
    let balance = payment_settings.balance.clone();
    let balance_warning_level = payment_settings.balance_warning_level;

    balance < balance_warning_level
}
