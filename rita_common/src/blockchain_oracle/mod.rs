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
use std::time::Instant;

/// This is the value pay_threshold is multiplied by to determine the close threshold
/// the close pay_threshold is when one router will pay another, the close_threshold is when
/// one router will throttle the connection of a peer that has not paid. A higher value here
/// indicates more 'debt' being allowed before enforcement. It's important this value be long enough
/// to allow for the payment to be made before enforcement, but short enough to prevent a router from
/// running up a large debt.
const CLOSE_THRESH_MULT: i32 = 10;

/// How long we wait for a response from the full node
/// this value must be less than or equal to the FAST_LOOP_SPEED
/// in the rita_common fast loop
pub const ORACLE_TIMEOUT: Duration = FAST_LOOP_TIMEOUT;

lazy_static! {
    /// This lazy static hold info about gas, thresholds and payment info for the router
    static ref ORACLE: Arc<RwLock<BlockchainOracle>> =
        Arc::new(RwLock::new(BlockchainOracle::new()));
}

pub struct BlockchainOracle {
    pub nonce: Uint256,
    pub net_version: u64,
    /// latest gas price value. Note that due to routers taking different times to run a loop, different routers
    ///  may have different values for this field. Post EIP1559, the max price change per block is 12.5% of the previous block
    pub gas_price: Uint256,
    /// The latest balance for this router, none if not yet set
    pub balance: Option<Uint256>,
    /// The last seen block, if this goes backwards we will
    /// ignore the update, none if not yet set
    pub last_seen_block: Option<Uint256>,
    pub last_updated: Option<Instant>,
}

// Set Xdai default
fn default_net_version() -> u64 {
    if cfg!(feature = "integration_test") {
        417834u64
    } else {
        100u64
    }
}

/// payment_threshold : This is the amount at which a router will make a payment. Below this value, the router will not may a payment since
/// a large portion of the payment will be eaten in fees which is not desirable. This is calculated by a constant
/// in the config, currently the default value is set to 0.3 * 1eth constant (1 dollar), which is 30 cents. When this is larger, the router pays less often and
/// vice versa.
pub fn get_pay_thresh() -> Int256 {
    let payment = settings::get_rita_common().payment;
    payment.payment_threshold
}

/// close_threshold : This is a multiple of payment_threshold and determines how many payments a router can miss before enforcing it.
/// For ex. if close_thres is 3 * pay_thres, another router may miss upto 3 payments before it gets enforced upon. Another way to think of this
/// is if a router owes more than the close_thresh, it will get enforced upon.
/// Since this depends on pay_thresh, pay_thresh needs to be reasonably stable to ensure router that need to be enforced, stay enforced
pub fn calculate_close_thresh() -> Int256 {
    let pay_thresh = get_pay_thresh();

    // A negative debt value indicates that a neighbor owes us, and vice versa
    let neg_one = -1i32;
    let sign_flip: Int256 = neg_one.into();
    sign_flip * CLOSE_THRESH_MULT.into() * pay_thresh
}

impl BlockchainOracle {
    pub fn new() -> Self {
        BlockchainOracle {
            nonce: 0u64.into(),
            //xdai by default
            net_version: default_net_version(),
            gas_price: 0u32.into(),
            balance: None,
            last_seen_block: None,
            last_updated: None,
        }
    }
}

impl Default for BlockchainOracle {
    fn default() -> BlockchainOracle {
        BlockchainOracle::new()
    }
}

// Oracle Getters
pub fn get_oracle_latest_gas_price() -> Uint256 {
    ORACLE.read().unwrap().gas_price
}

pub fn get_oracle_nonce() -> Uint256 {
    ORACLE.read().unwrap().nonce
}

pub fn get_oracle_net_version() -> u64 {
    ORACLE.read().unwrap().net_version
}

pub fn get_oracle_balance() -> Option<Uint256> {
    ORACLE.read().unwrap().balance
}

pub fn get_oracle_last_seen_block() -> Option<Uint256> {
    ORACLE.read().unwrap().last_seen_block
}

pub fn get_oracle_last_updated() -> Option<Instant> {
    ORACLE.read().unwrap().last_updated
}

// Oracle setters
pub fn set_oracle_gas_price(price: Uint256) {
    ORACLE.write().unwrap().gas_price = price;
}

pub fn set_oracle_nonce(n: Uint256) {
    ORACLE.write().unwrap().nonce = n;
}

pub fn set_oracle_net_version(net_v: u64) {
    ORACLE.write().unwrap().net_version = net_v;
}
pub fn set_oracle_balance(new_balance: Option<Uint256>) {
    ORACLE.write().unwrap().balance = new_balance
}
fn set_oracle_last_seen_block(block: Uint256) {
    ORACLE.write().unwrap().last_seen_block = Some(block)
}

pub fn set_oracle_last_updated(update: Instant) {
    ORACLE.write().unwrap().last_updated = Some(update)
}

pub async fn update() {
    let payment_settings = settings::get_rita_common().payment;
    let our_address = payment_settings.eth_address.expect("No address!");

    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, ORACLE_TIMEOUT);

    info!("About to make web3 requests to {}", full_node);
    update_blockchain_info(our_address, web3, full_node).await;
}

/// The current amount of time before we consider that the blockchain oracle
/// is too outdated and that we could have issues with payments.
const OUTDATED_TIME: Duration = Duration::new(300, 0);
/// This function is used to detect possible payment issues since we want to prevent
/// node failures in the future. Currently, it only checks to make sure the blockchain
/// oracle is semi-recent.
pub fn potential_payment_issues_detected() -> bool {
    // disable this feature if we're in development mode
    if cfg!(feature = "legacy_integration_test") {
        return false;
    }

    match ORACLE.read().unwrap().last_updated {
        Some(time) => {
            if time.elapsed() > OUTDATED_TIME {
                return true;
            }
        }
        None => return true,
    }
    false
}

async fn update_blockchain_info(our_address: Address, web3: Web3, full_node: String) {
    // all web30 functions check if the node is syncing, but sometimes the nodes lie about
    // syncing, this block checks the actual block number we've last seen and if we get a lower
    // value returns early, refusing to update our state with stale data.
    let latest_block = web3.eth_block_number().await;
    match latest_block {
        Ok(latest_block) => {
            if let Some(last_seen_block) = get_oracle_last_seen_block() {
                if latest_block < last_seen_block {
                    warn!(
                        "Got stale blockchain oracle data! {} < {}",
                        latest_block, last_seen_block
                    );
                    return;
                }
            }
            set_oracle_last_seen_block(latest_block);
            set_oracle_last_updated(Instant::now());
        }
        Err(e) => {
            warn!("Failed to get latest block number with {:?}", e);
            return;
        }
    }

    let balance = web3.eth_get_balance(our_address);
    let nonce = web3.eth_get_transaction_count(our_address);
    let net_version = web3.net_version();
    let gas_price = web3.eth_gas_price();
    let (balance, nonce, net_version, gas_price) =
        join4(balance, nonce, net_version, gas_price).await;

    let mut settings = settings::get_rita_common();

    match balance {
        Ok(balance) => update_balance(&full_node, balance),
        Err(e) => warn!("Failed to update balance with {:?}", e),
    }
    match gas_price {
        Ok(gas_price) => update_gas_price(&full_node, gas_price, &mut settings.payment),
        Err(e) => warn!("Failed to update gas price with {:?}", e),
    }
    match net_version {
        Ok(net_version) => {
            check_net_version(&full_node, ORACLE.read().unwrap().net_version, net_version)
        }
        Err(e) => warn!("Failed to update net_version with {:?}", e),
    }
    match nonce {
        Ok(nonce) => update_nonce(&full_node, nonce, &mut ORACLE.write().unwrap().nonce),
        Err(e) => warn!("Failed to update nonce with {:?}", e),
    }
    settings::set_rita_common(settings);
}

/// Gets the balance for the provided eth address and updates it
/// in the global SETTING variable, do not use this function as a generic
/// balance getter.
fn update_balance(full_node: &str, new_balance: Uint256) {
    let value = new_balance;

    info!(
        "Got response from {} balance request {:?}",
        full_node, value
    );
    set_oracle_balance(Some(value));
}

/// Updates the net_version in our global setting variable, this function
/// specifically runs into some security issues, a hostile node could provide
/// us with the wrong net_version, hoping to get a signed transaction good for
/// a different network than the one we are actually using. For example an address
/// that contains both real eth and test eth may be tricked into singing a transaction
/// for real eth while operating on the testnet. Because of this we have warnings behavior
fn check_net_version(full_node: &str, net_version: u64, new_net_version: u64) {
    info!(
        "Got response from {} for net_version request {:?}",
        full_node, new_net_version
    );
    // we could just take the first value and kept it but for now
    // lets check that all nodes always agree on net version constantly
    if net_version != new_net_version {
        error!("GOT A DIFFERENT NETWORK ID VALUE, IT IS CRITICAL THAT YOU REVIEW YOUR NODE LIST FOR HOSTILE/MISCONFIGURED NODES");
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
    // Minimum gas price. When gas is below this, we set gasprice to this value, which is then used to
    // calculate pay and close thresh
    let min_gas = payment_settings.min_gas;

    let value = new_gas_price;
    info!(
        "Got response from {} for gas price request {:?}",
        full_node, value
    );

    // taking the latest gas value for pay_thres and close_thres calculation does better
    // in the worst case compared to averaging
    let oracle_gas_price = value;

    let oracle_gas_price = if oracle_gas_price < min_gas {
        info!("gas price is low setting to! {}", min_gas);
        min_gas
    } else {
        oracle_gas_price
    };

    //set local values in lazy static
    set_oracle_gas_price(oracle_gas_price)
}

/// A very simple function placed here for convinence that indicates
/// if the system should go into low balance mode
pub fn low_balance() -> bool {
    let payment_settings = settings::get_rita_common().payment;
    let balance = get_oracle_balance();
    let balance_warning_level = payment_settings.balance_warning_level;

    match balance {
        Some(val) => val < balance_warning_level,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to prevent race conditions when running these test due to parallel test environment
    fn clear_gas_oracle() {
        set_oracle_gas_price(0u32.into());
    }

    #[test]
    fn test_oracle_get_set() {
        clear_gas_oracle();

        let or = ORACLE.read().unwrap();
        assert_eq!(or.gas_price, 0u128.into());
        drop(or);

        set_oracle_gas_price(10u128.into());

        let or = ORACLE.read().unwrap();
        assert_eq!(or.gas_price, 10u128.into());
        drop(or);
        clear_gas_oracle();
    }

    #[test]
    fn test_set_network_and_nonce() {
        clear_gas_oracle();

        let or = ORACLE.read().unwrap();
        assert_eq!(or.nonce, 0u128.into());
        assert_eq!(or.net_version, 417834);
        drop(or);

        check_net_version("Some node", ORACLE.read().unwrap().net_version, 17u64);
        let or = ORACLE.read().unwrap();
        drop(or);

        update_nonce(
            "Some Node",
            21u128.into(),
            &mut ORACLE.write().unwrap().nonce,
        );
        let or = ORACLE.read().unwrap();
        assert_eq!(or.nonce, 21u128.into());
        drop(or);

        set_oracle_nonce(30u64.into());
        set_oracle_net_version(78u64);
        let or = ORACLE.read().unwrap();
        assert_eq!(or.nonce, 30u128.into());
        assert_eq!(or.net_version, 78u64);
        drop(or);

        clear_gas_oracle();
    }
}
