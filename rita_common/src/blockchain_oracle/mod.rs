//! This module is dedicated to updating local state with various pieces of information
//! relating to the blockchain being used. First and foremost is maintaining an updated
//! balance and nonce as well as computing more complicated things like the closing and
//! payment threshold based on gas prices.

use crate::debt_keeper::normalize_payment_amount;
use crate::rita_loop::fast_loop::FAST_LOOP_TIMEOUT;
use crate::rita_loop::get_altheal1_server;
use crate::rita_loop::get_web3_server;
use althea_types::Denom;
use althea_types::SystemChain;
use althea_types::ALTHEA_PREFIX;
use clarity::Address;
use deep_space::Address as CosmosAddress;
use deep_space::Contact;
use num256::Int256;
use num256::Uint256;
use settings::DEBT_KEEPER_DENOM;
use settings::DEBT_KEEPER_DENOM_DECIMAL;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;
use web30::client::Web3;

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
    /// The latest balance for this router, none if not yet set
    pub balance: Option<Uint256>,
    /// The last seen block, if this goes backwards we will
    /// ignore the update, none if not yet set
    pub last_seen_block: Option<Uint256>,
    pub last_updated: Option<Instant>,
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

pub fn get_oracle_balance() -> Option<Uint256> {
    ORACLE.read().unwrap().balance
}

pub fn get_oracle_last_seen_block() -> Option<Uint256> {
    ORACLE.read().unwrap().last_seen_block
}

pub fn get_oracle_last_updated() -> Option<Instant> {
    ORACLE.read().unwrap().last_updated
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
    let our_althea_address = settings::get_rita_common()
        .get_identity()
        .unwrap()
        .get_althea_address();
    // on ETH based chains we are always using the native token ETH or XDAI, but on Althea L1
    // any one of many tokens can be used so we must specify the token that represents our
    // 'router balance'. This should maybe be a sum of all accepted denoms to better handle cases
    // where routers have balances in multiple stables
    let althea_denom = payment_settings.althea_l1_payment_denom;

    match payment_settings.system_chain {
        SystemChain::Ethereum | SystemChain::Sepolia | SystemChain::Xdai => {
            let full_node = get_web3_server();
            info!("About to make web3 requests to {}", full_node);
            let web3 = Web3::new(&full_node, ORACLE_TIMEOUT);
            update_blockchain_info_gnosis(our_address, web3, full_node).await;
        }
        SystemChain::AltheaL1 => {
            let full_node = get_altheal1_server();
            let contact = Contact::new(&full_node, ORACLE_TIMEOUT, ALTHEA_PREFIX).unwrap();
            update_blockchain_info_althea(our_althea_address, contact, althea_denom, full_node)
                .await;
        }
    }
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

async fn update_blockchain_info_althea(
    our_address: CosmosAddress,
    contact: Contact,
    denom: Denom,
    full_node: String,
) {
    let latest_block = contact.get_chain_status().await;
    match latest_block {
        Ok(deep_space::client::ChainStatus::Moving { block_height }) => {
            let latest_block = block_height.into();
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
        Ok(_) => {
            warn!("Failed to get latest block number and balance for Althea L1");
            return;
        }
        Err(e) => {
            warn!("Failed to get latest block number with {:?}", e);
            return;
        }
    }

    let balance = contact.get_balance(our_address, denom.denom.clone()).await;
    match balance {
        Ok(Some(balance)) => update_balance(
            &full_node,
            normalize_payment_amount(
                balance.amount,
                denom,
                Denom {
                    denom: DEBT_KEEPER_DENOM.to_string(),
                    decimal: DEBT_KEEPER_DENOM_DECIMAL,
                },
            ),
        ),
        Ok(None) => update_balance(&full_node, 0u32.into()),
        Err(e) => warn!("Failed to update balance with {:?}", e),
    }
}

async fn update_blockchain_info_gnosis(our_address: Address, web3: Web3, full_node: String) {
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

    let balance = web3.eth_get_balance(our_address).await;
    match balance {
        Ok(balance) => update_balance(&full_node, balance),
        Err(e) => warn!("Failed to update balance with {:?}", e),
    }
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

    #[test]
    fn test_update_blockchain_info() {
        let runner = actix_async::System::new();
        let contact = Contact::new(
            "https://rpc.althea.zone:9090",
            Duration::from_secs(30),
            "althea",
        )
        .unwrap();
        runner.block_on(async move {
            update_blockchain_info_althea(
                "althea19983m402agvayhr8eg9d7wtyf30935ysucqqax"
                    .parse()
                    .unwrap(),
                contact,
                Denom {
                    denom: "aalthea".to_string(),
                    decimal: 18,
                },
                "https://rpc.althea.zone:9090".to_string(),
            ).await;
        });
    }
}
