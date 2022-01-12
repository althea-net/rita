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

/// This is the value pay_threshold is multiplied by to determine the close threshold
/// This value is determined as follows
///
/// In the new averaging scheme, consider these constraints and assumptions:
/// 1.) The largest time difference between two routers running is 10x
/// Ex. We have two routers a fast router running every 5sec and a slow running every 50 sec
/// 2.) After EIP1559, the max gas can increase each block is 12.5% of previous block (we take 15% for simplicity)
/// 3.) The total number of entries in our circular array is M  = 100
/// 4.) Let the starting gas that the two nodes are synced on is s
///
/// We need to find the maximum value of CLOSE_THRESH_MULT in the worse case such that the slow router
/// does not enforce the fast router because of disagreeing gas prices. Consdier these cases:
///
/// (I) Right on startup, the array is not filled, only the first 9 blocks have been registered. Lets look at the respective arrays
/// FastRouter: [s, 1.15s, (1.15^2)s, ...., (1.15^9)s]. The average gas here would be = ~20s/10 ~ 2s
/// SlowRouter: [s]. The average here would be s
///
/// Pay_thres for fast = D*T*(2s) (Where D is dynamic fee mult and T is average gas for a transaction)
/// Pay_thres for slow = D*T*s
/// To prevent enforcement, Close_thres of slow > pay_thres of fast
/// D*T*s * CLOSE_THRES_MULT > D*T*(2s) => CLOSE_THRES_MULT > 2
///
/// Without averaging
/// CLOSE_THRES_MULT > (1.15^9) > 3
///
/// (II) Gas price is relatively stable, but sudden jump in price (More realistic)
/// FastRouter: [s, s, s, ... 1.15s, ... (1.15^9)s]. Average is 110s/100 = ~s
/// SlowRouter: [s, s, s, .... s]. Average is s
/// CLOSE_THRES_MULT > 1
///
/// Without Averaging
/// CLOSE_THRES_MULT > (1.15)^9 > 3
///
/// (III) Gas price continues to increase non stop over the course of 50 * M seconds (absolute worst case):
/// FastRouter: [(1.15^9M)s, (1.15^(9M+1))s, .... (1.15^10M)s].
///     Average here would be: s * (1.15^9M) * (1.15^M  -  1)/(1.15  -  1). For M = 100, average = ~3.3s * 10^59
/// SlowRouter: [s, (1.15^10)s, (1.15^20)s ... (1.15^M)s ... (1.15^10M)s].
///     Average here would be s * (1.15^10M  -  1)/(1.15^10  -  1) for M = 100, average = ~1.66s * 10^58
/// So in this case CLOSE_THRES_MULT > 33/1.66 > 20
///
/// Without Averaging
/// CLOSE_THRES_MULT > (1.15^(999))/(1.15^(990)) > 1.15^9 > 3
///
/// In the worst cases, No averaging does better. To conservative we set this Multiplier higher than 3
const CLOSE_THRESH_MULT: i32 = 10;

/// How long we wait for a response from the full node
/// this value must be less than or equal to the FAST_LOOP_SPEED
/// in the rita_common fast loop
pub const ORACLE_TIMEOUT: Duration = FAST_LOOP_TIMEOUT;

/// Minimum gas price. When gas is below this, we set gasprice to this value, which is then used to
/// calculate pay and close thresh
pub const MIN_GAS: u32 = 1_000_000_000;

lazy_static! {
    /// This lazy static hold info about gas, thresholds and payment info for the router
    static ref ORACLE: Arc<RwLock<BlockchainOracle>> =
        Arc::new(RwLock::new(BlockchainOracle::new()));
}

pub struct BlockchainOracle {
    pub nonce: Uint256,
    pub net_version: u64,
    pub gas_info: GasInfo,
}

/// This struct contains important information to determine when a router should be paying and when it should be enforcing on
/// other routers
///
/// 1.) gas_price : latest gas price value. Note that due to routers taking different times to run a loop, different routers
///     may have different values for this field. Post EIP1559, the max price change per block is 12.5% of the previous block
///
/// 2.) payment_threshold : This is the ammount at which a router will make a payment. Below this value, the router will not may a payment since
///     a large portion of the payment will be eaten in fees which is not desirable. This is caluculated by
///     gas_price * gas_required * dynamic_fee_multiplier, where dynamic fee multiplier determines how much larger the payment is
///     compared to the fees (fees are essentially gas_price * gas_required). When this is larger, the router pays less often and
///     vice versa
///
/// 3.) close_threshold : This is a multiple of payment_threshold and determines how many payments a router can miss before enforcing it.
///     For ex. if close_thres is 3 * pay_thres, another router may miss upto 3 payments before it gets enforced upon. Another way to think of this
///     is if a router owes more than the close_thresh, it will get enforced upon.
#[derive(Debug, Clone)]
pub struct GasInfo {
    pub payment_threshold: Int256,
    pub close_threshold: Int256,
    pub gas_price: Uint256,
}

fn default_close_threshold() -> Int256 {
    Int256::from(-1) * default_pay_threshold() * CLOSE_THRESH_MULT.into()
}

fn default_pay_threshold() -> Int256 {
    500_000_000_000_000_000i64.into()
}

// Set Xdai default
fn default_net_version() -> u64 {
    100u64
}

impl BlockchainOracle {
    pub fn new() -> Self {
        BlockchainOracle {
            nonce: 0u64.into(),
            //xdai by default
            net_version: default_net_version(),
            gas_info: GasInfo::default(),
        }
    }
}

impl Default for GasInfo {
    fn default() -> Self {
        GasInfo {
            payment_threshold: default_pay_threshold(),
            close_threshold: default_close_threshold(),
            gas_price: 0u32.into(),
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
    ORACLE.read().unwrap().gas_info.gas_price.clone()
}

pub fn get_oracle_pay_thresh() -> Int256 {
    ORACLE.read().unwrap().gas_info.payment_threshold.clone()
}

pub fn get_oracle_close_thresh() -> Int256 {
    ORACLE.read().unwrap().gas_info.close_threshold.clone()
}

pub fn get_oracle_nonce() -> Uint256 {
    ORACLE.read().unwrap().nonce.clone()
}

pub fn get_oracle_net_version() -> u64 {
    ORACLE.read().unwrap().net_version
}

// Oracle setters
pub fn set_oracle_gas_info(info: GasInfo) {
    ORACLE.write().unwrap().gas_info = info;
}

pub fn set_oracle_nonce(n: Uint256) {
    ORACLE.write().unwrap().nonce = n;
}

pub fn set_oracle_net_version(net_v: u64) {
    ORACLE.write().unwrap().net_version = net_v;
}

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
    //local variables to be set
    let oracle_gas_price: Uint256;
    let mut oracle_pay_thresh: Int256 = 0u128.into();
    let oracle_close_thresh: Int256;

    let value = new_gas_price;
    info!(
        "Got response from {} for gas price request {:?}",
        full_node, value
    );

    // taking the latest gas value for pay_thres and close_thres calculation does better
    // in the worst case compared to averaging
    oracle_gas_price = value;

    let min_gas: Uint256 = MIN_GAS.into();
    let oracle_gas_price = if oracle_gas_price < min_gas {
        info!("gas price is low setting to! {}", min_gas);
        min_gas
    } else {
        oracle_gas_price
    };

    let dynamic_fee_factor: Int256 = payment_settings.dynamic_fee_multiplier.into();
    let transaction_gas: Int256 = 21000.into();
    let neg_one = -1i32;
    let sign_flip: Int256 = neg_one.into();

    if let Some(gas_price) = oracle_gas_price.to_int256() {
        oracle_pay_thresh = transaction_gas * gas_price * dynamic_fee_factor;
    }
    trace!("Dynamically set pay threshold to {:?}", oracle_pay_thresh);

    oracle_close_thresh = sign_flip * CLOSE_THRESH_MULT.into() * oracle_pay_thresh.clone();
    trace!(
        "Dynamically set close threshold to {:?}",
        oracle_close_thresh
    );

    //set local values in lazy static
    set_oracle_gas_info(GasInfo {
        gas_price: oracle_gas_price,
        payment_threshold: oracle_pay_thresh,
        close_threshold: oracle_close_thresh,
    })
}

/// A very simple function placed here for convinence that indicates
/// if the system should go into low balance mode
pub fn low_balance() -> bool {
    let payment_settings = settings::get_rita_common().payment;
    let balance = payment_settings.balance.clone();
    let balance_warning_level = payment_settings.balance_warning_level;

    balance < balance_warning_level
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to prevent race conditions when running these test due to parallel test environment
    fn clear_gas_oracle() {
        set_oracle_gas_info(GasInfo {
            payment_threshold: default_pay_threshold(),
            close_threshold: default_close_threshold(),
            gas_price: 0u32.into(),
        });
    }

    #[test]
    fn test_oracle_get_set() {
        clear_gas_oracle();

        let or = ORACLE.read().unwrap();
        assert_eq!(or.gas_info.gas_price, 0u128.into());
        assert_eq!(or.gas_info.payment_threshold, default_pay_threshold());
        assert_eq!(or.gas_info.close_threshold, default_close_threshold());
        drop(or);

        set_oracle_gas_info(GasInfo {
            gas_price: 10u128.into(),
            payment_threshold: 100u128.into(),
            close_threshold: Int256::from(-130),
        });

        let or = ORACLE.read().unwrap();
        assert_eq!(or.gas_info.gas_price, 10u128.into());
        assert_eq!(or.gas_info.payment_threshold, 100u128.into());
        assert_eq!(or.gas_info.close_threshold, Int256::from(-130));
        drop(or);
        clear_gas_oracle();
    }

    #[test]
    fn test_set_network_and_nonce() {
        clear_gas_oracle();

        let or = ORACLE.read().unwrap();
        assert_eq!(or.nonce, 0u128.into());
        assert_eq!(or.net_version, 100);
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
