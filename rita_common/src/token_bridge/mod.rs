// This module is designed to allow easy deposits for some supported chains using Ethereum. The idea
// is pretty simple, the user deposits money into their routers Ethereum address, this is then exchanged
// through uniswap into DAI and then from there it is bridged over to the Xdai proof of authority chains.
// Support for Cosmos chains using a DAI-pegged native currency is next on the list.

// Essentially the goal is to allow users to deposit a popular and easy to acquire coin on Ethereum and then
// actually transact in a stablecoin on a fast blockchain, eg not Ethereum.

// Currently this flow supports USDC, USDT, and DAI itself (v2 specifically)

// This entire module works on the premise we call the conveyor belt model. It's difficult to track
// money through this entire process exactly, in fact there are some edge cases where it's simply not
// possible to reliably say if a task has completed or not. With that in mind we simply always progress
// the the process for Source coin -> DAI -> XDAI.

// For the withdraw process we update a lazy static variable every time a withdraw is invoked.
// Every tick, we check for updated withdraw information in the lazy static and use this to
// initiate a withdrawal. From there, we loop to check for events related to the withdraws,
// simulate these, and those that pass are unlocked on the eth side. Funds are sent to their final
// destination in dai

#[cfg(test)]
mod tests;
pub mod xdai_bridge;

use crate::rita_loop::slow_loop::SLOW_LOOP_TIMEOUT;
use crate::token_bridge::xdai_bridge::*;
use crate::RitaCommonError;
use althea_types::SystemChain;
use auto_bridge::encode_relaytokens;
use auto_bridge::TokenBridge as TokenBridgeCore;
use clarity::Address;
use num256::Uint256;
use settings::payment::PaymentSettings;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

lazy_static! {
    static ref BRIDGE: Arc<RwLock<TokenBridgeState>> =
        Arc::new(RwLock::new(TokenBridgeState::default()));
}

pub const ETH_TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000_u128;
const SIGNATURES_TIMEOUT: Duration = ETH_TRANSFER_TIMEOUT;
const BLOCKS: u64 = 40_032;

pub fn eth_to_wei(eth: u64) -> Uint256 {
    let wei = eth as u128 * WEI_PER_ETH;
    wei.into()
}

/// This struct contains the state of the bridge. TokenBridgeAmounts contains the
/// amounts we commonly reference for the operation in this file and TokenBridgeCore
/// contains details fo the various inner workings of the actual contract and bridge calls
/// rather than the logic. This struct was previously combined with TokenBridgeAmounts but
/// we want to reload the amounts regularly without interfering with the state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenBridgeState {
    /// This variable is used as a lock to ensure that our sending of money from our wallet to
    /// to xdai contract on xdai is an atomic process. If we reboot, we would have already completed this
    /// or not have succeeded, so false value is correct. This allows us to initiate only one withdrawal
    /// at a time, however funds can be unlocked on ethereum side in parallel.
    withdraw_in_progress: bool,
    withdraw_details: Option<Withdraw>,
    detailed_state: DetailedBridgeState,
}

/// The last values used for reserve and minimum to exchange
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct LastAmounts {
    minimum_to_exchange: u32,
    reserve_amount: u32,
}

pub async fn tick_token_bridge() {
    info!("Token bridge tick");
    let payment_settings = settings::get_rita_common().payment;
    let system_chain = payment_settings.system_chain;

    if !payment_settings.bridge_enabled {
        return;
    }
    let core = token_bridge_core_from_settings(&payment_settings);

    match system_chain {
        SystemChain::Xdai => xdai_bridge(core).await,
        SystemChain::Ethereum => {}
        SystemChain::Rinkeby => {}
    }
}

fn token_bridge_core_from_settings(payment_settings: &PaymentSettings) -> TokenBridgeCore {
    let addresses = payment_settings.bridge_addresses.clone();
    TokenBridgeCore::new(
        addresses.clone(),
        payment_settings.eth_address.unwrap(),
        payment_settings.eth_private_key.unwrap(),
        addresses.eth_full_node_url,
        addresses.xdai_full_node_url,
        SLOW_LOOP_TIMEOUT,
    )
}

impl Default for TokenBridgeState {
    fn default() -> TokenBridgeState {
        TokenBridgeState {
            withdraw_in_progress: false,
            withdraw_details: None,
            detailed_state: DetailedBridgeState::NoOp,
        }
    }
}

/// Withdraw state struct for the bridge, if withdraw_all is true, the eth will be
/// cleaned up on the way out as well
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Withdraw {
    pub to: Address,
    pub amount: Uint256,
}

/// Since our withdraw function is async and cannot be called from the previous sync context
/// we use this function to setup information about the withdrawal in the sync cUint256::from_bytes_be(&[12_u8])ontext. We setup
/// a bool and Withdraw struct inside a lazy static variable that we can read from later when
/// we initiate the withdrawal from an async context.
pub fn setup_withdraw(msg: Withdraw) -> Result<(), RitaCommonError> {
    let mut writer = BRIDGE.write().unwrap();

    // If there is already a withdrawal that needs to be executed, return
    if writer.withdraw_in_progress {
        return Err(RitaCommonError::MiscStringError(
            "There is currently a withdraw in progress!".to_string(),
        ));
    }

    // Setup withdraw information so we can execute it during next tick
    writer.withdraw_in_progress = true;
    writer.withdraw_details = Some(Withdraw {
        to: msg.to,
        amount: msg.amount,
    });

    Ok(())
}

fn get_bridge_state() -> TokenBridgeState {
    BRIDGE.write().unwrap().clone()
}

fn set_bridge_state(set: TokenBridgeState) {
    *BRIDGE.write().unwrap() = set;
}

/// This function initiates the withdrawal by calling the relayTokens function when there is no
/// other withdrawal currently in progress. It receives the information from the lazy static varaible,
/// which was setup by the function setup_withdrawal, and runs every loop to see if this lazy static has
/// been populated with new information to initialize a withdrawal.
pub async fn withdraw(msg: Withdraw) -> Result<(), RitaCommonError> {
    let payment_settings = settings::get_rita_common().payment;
    let system_chain = payment_settings.system_chain;
    let token_bridge = token_bridge_core_from_settings(&payment_settings);

    let to = msg.to;
    let amount = msg.amount;

    info!("bridge withdraw handler amount {}", amount);

    if let SystemChain::Xdai = system_chain {
        //check if a wtihdrawal is in progress, if not set bool to true
        let mut writer = get_bridge_state();
        if !writer.withdraw_in_progress {
            writer.withdraw_in_progress = true;
            set_bridge_state(writer.clone());
            let _res = encode_relaytokens(token_bridge, to, amount, Duration::from_secs(600)).await;

            detailed_state_change(DetailedBridgeState::XdaiToDai { amount });
            // Reset the lock
            writer.withdraw_in_progress = false;
            set_bridge_state(writer);
            Ok(())
        } else {
            Err(RitaCommonError::MiscStringError(
                "There is currently a withdraw in progress!".to_string(),
            ))
        }
    } else {
        Err(RitaCommonError::MiscStringError(
            "Not on Xdai chain!".to_string(),
        ))
    }
}

fn detailed_state_change(msg: DetailedBridgeState) {
    trace!("Changing detailed state to {:?}", msg);
    let mut bridge = BRIDGE.write().unwrap();
    trace!("Finished changing detailed state {:?}", msg);
    let new_state = msg;
    bridge.detailed_state = new_state;
}

/// Used to display the state of the bridge to the user, has a higher
/// resolution than the actual bridge state object in exchange for possibly
/// being inaccurate or going backwards
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub enum DetailedBridgeState {
    /// Swapping any input token for dai
    Swap,
    /// Converting Dai to Xdai
    DaiToXdai { amount: Uint256 },
    /// Converting Xdai to Dai
    XdaiToDai { amount: Uint256 },
    DaiToDest {
        amount_of_dai: Uint256,
        dest_address: Address,
    },
    /// Nothing is happening
    NoOp,
}

/// Contains everything a user facing application would need to help a user
/// interact with the bridge
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub struct BridgeStatus {
    withdraw_chain: SystemChain,
    state: DetailedBridgeState,
}

pub fn get_bridge_status() -> BridgeStatus {
    let payment_settings = settings::get_rita_common().payment;
    let withdraw_chain = payment_settings.withdraw_chain;
    drop(payment_settings);
    let bridge = BRIDGE.read().unwrap().clone();
    BridgeStatus {
        withdraw_chain,
        state: bridge.detailed_state,
    }
}
