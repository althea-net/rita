// This module is designed to allow easy deposits for some supported chains using Ethereum. The idea
// is pretty simple, the user deposits money into their routers Ethereum address, this is then exchanged
// through uniswap into DAI and then from there it is bridged over to the Xdai proof of authority chains.
// Support for Cosmos chains using a DAI-pegged native currency is next on the list.

// Essentially the goal is to allow users to deposit a popular and easy to acquire coin like Ethereum and then
// actually transact in a stablecoin on a fast blockchain, eg not Ethereum.

// This entire module works on the premise we call the conveyor belt model. It's difficult to track
// money through this entire process exactly, in fact there are some edge cases where it's simply not
// possible to reliably say if a task has completed or not. With that in mind we simply always progress
// the the process for Eth -> DAI -> XDAI. So if we find
// some DAI in our address it will always be converted to XDAI even if we didn't convert that DAI from Eth
// in the first place.

// For the withdraw process we update a lazy static variable every time a withdraw is invoked.
// Every tick, we check for updated withdraw information in the lazy static and use this to
// initiate a withdrawal. From there, we loop to check for events related to the withdraws,
// simulate these, and those that pass are unlocked on the eth side.

use crate::rita_loop::slow_loop::SLOW_LOOP_TIMEOUT;
use althea_types::SystemChain;
use async_web30::jsonrpc::error::Web3Error;
use auto_bridge::check_relayed_message;
use auto_bridge::get_payload_for_funds_unlock;
use auto_bridge::HelperWithdrawInfo;
use auto_bridge::ERC20_GAS_LIMIT;
use auto_bridge::UNISWAP_GAS_LIMIT;
use auto_bridge::XDAI_FUNDS_UNLOCK_GAS;
use auto_bridge::{check_withdrawals, encode_relaytokens, get_relay_message_hash};
use auto_bridge::{TokenBridge as TokenBridgeCore, TokenBridgeError};
use clarity::utils::display_uint256_as_address;
use clarity::Address;
use failure::{bail, Error};
use num256::Uint256;
use num_traits::identities::Zero;
use rand::{thread_rng, Rng};
use settings::payment::PaymentSettings;

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::iter::FromIterator;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

lazy_static! {
    static ref BRIDGE: Arc<RwLock<TokenBridgeState>> =
        Arc::new(RwLock::new(TokenBridgeState::default()));
    static ref AMOUNTS: Arc<RwLock<LastAmounts>> = Arc::new(RwLock::new(LastAmounts::default()));
    /// This variable pushes gas prices every minute over the last 24 hours. New entries are pushed to the front
    /// and older entries are popped from the back. The number of entries here is limited by the constant GAS_PRICE_ENTRIES
    static ref GAS_PRICES: Arc<RwLock<VecDeque<Uint256>>> = Arc::new(RwLock::new(VecDeque::with_capacity(GAS_PRICE_ENTRIES)));
}

pub const ETH_TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);
const UNISWAP_TIMEOUT: Duration = ETH_TRANSFER_TIMEOUT;

const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000_u128;
const SIGNATURES_TIMEOUT: Duration = ETH_TRANSFER_TIMEOUT;
const BLOCKS: u64 = 40_032;
/// This is the number of minutes in a day. We use this since we run the xdai_bridge every minute, therefore
/// entering an entry every minute
const GAS_PRICE_ENTRIES: usize = 1440;

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
    let payment_settings = settings::get_rita_common().payment;
    let system_chain = payment_settings.system_chain;

    if !payment_settings.bridge_enabled {
        return;
    }
    drop(payment_settings);

    match system_chain {
        SystemChain::Xdai => xdai_bridge().await,
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
            detailed_state: DetailedBridgeState::NoOp {
                eth_balance: Uint256::zero(),
                wei_per_dollar: Uint256::zero(),
            },
        }
    }
}

/// Transfers dai present in eth address from previous xdai_bridge iterations to the xdai chain.
/// This also assists in rescuing any stranded dai balance because of failures in depositing flow.
async fn transfer_dai(
    bridge: TokenBridgeCore,
    our_address: Address,
    minimum_stranded_dai_transfer: Uint256,
) -> Result<(), TokenBridgeError> {
    let dai_balance = bridge.get_dai_balance(our_address).await?;
    info!("Our DAI balance is {}", dai_balance);
    if dai_balance > minimum_stranded_dai_transfer {
        info!("rescuing dais, failure to wait for event");
        detailed_state_change(DetailedBridgeState::DaiToXdai {
            amount: dai_balance.clone(),
        });

        // Remove up to U16_MAX wei from this transaction, this is well under a cent.
        // what this does is randomly change the tx hash and help prevent 'stuck' transactions
        // thanks to anti-spam mechanisms. Payments get this 'for free' thanks to changing debts
        // numbers. And other tx's here do thanks to changing exchange rates and other external factors
        // this is the only transaction that will be exactly the same for a very long period.
        let mut rng = thread_rng();
        let some_wei: u16 = rng.gen();
        let amount = dai_balance - Uint256::from(some_wei);

        // Over the bridge into xDai
        bridge
            .dai_to_xdai_bridge(amount, ETH_TRANSFER_TIMEOUT)
            .await?;
        Ok(())
    } else {
        // we don't have a lot of dai, we shouldn't do anything
        Ok(())
    }
}

/// The logic for the Eth -> Xdai bridge operation that runs every tick that also handles withdrawals.
/// We start by checking the lazy static lock to check for any new withdrawals that were requested.
/// If we find one, we initiate this withdrawal and reset the lock. Next we loop through events
/// on the xdai blockchain to find any withdrawals related to us, and if so we unlock these funds.
/// We then rescue any stuck dai and send any eth that we have over to the xdai chain.
async fn xdai_bridge() {
    let bridge = get_core();
    let eth_gas_price = match bridge.eth_web3.eth_gas_price().await {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get eth gas price with {}", e);
            return;
        }
    };
    let wei_per_dollar = match bridge.dai_to_eth_price(eth_to_wei(1u8.into())).await {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get eth price with {}", e);
            return;
        }
    };
    let wei_per_cent = wei_per_dollar.clone() / 100u32.into();
    let our_eth_balance = match bridge.eth_web3.eth_get_balance(bridge.own_address).await {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get eth balance {}", e);
            return;
        }
    };

    // Add gas price entry to lazy static
    let writer = &mut *GAS_PRICES.write().unwrap();
    update_gas_price_store(eth_gas_price.clone(), writer);

    // Get max acceptable gas price (within 20%)
    let max_gas_price = match get_acceptable_gas_price(eth_gas_price.clone(), writer) {
        Ok(a) => a,
        Err(_) => {
            error!("Not enough entries in gas price datastore, or error in datastore entry logic");
            return;
        }
    };

    // the amount of Eth to retain in WEI. This is the cost of our transfer from the
    // xdai chain to the destination address.
    let reserve_amount = get_reserve_amount(eth_gas_price.clone());
    let minimum_to_exchange = reserve_amount.clone()
        + (eth_gas_price.clone() * (UNISWAP_GAS_LIMIT + ERC20_GAS_LIMIT).into());
    set_last_amounts(
        lossy_u32(minimum_to_exchange.clone() / wei_per_cent.clone()),
        lossy_u32(reserve_amount.clone() / wei_per_cent.clone()),
    );
    // the minimum amount to transfer, this is in DAI wei,
    let minimum_stranded_dai_transfer = minimum_to_exchange.clone();

    // initiate withdrawals if any
    let mut writer = BRIDGE.write().unwrap();
    if writer.withdraw_in_progress {
        let withdraw_details = match &writer.withdraw_details {
            Some(a) => a.clone(),
            None => {
                error!("No withdraw information present");
                writer.withdraw_in_progress = false;
                return;
            }
        };
        let amount = withdraw_details.amount.clone();
        let address = withdraw_details.to;
        match withdraw(withdraw_details).await {
            Ok(_) => {
                info!(
                    "Initiating withdrawal of amount {} to address {}",
                    amount, address
                );
            }
            Err(e) => error!("Received an error when initiating a withdrawal: {}", e),
        };

        //reset the withdraw lock
        writer.withdraw_in_progress = false;
        writer.withdraw_details = None;
    }

    // check for withdrawal events and execute them
    match simulated_withdrawal_on_eth(&bridge, wei_per_dollar.clone()).await {
        Ok(()) => {
            info!(
                "Checking for withdraw events related to us (address: {})",
                bridge.own_address
            );
        }
        Err(e) => {
            info!("Received error when trying to unlock funds: {}", e);
        }
    }

    //run these deposit steps only if gas price is low
    if max_gas_price < eth_gas_price {
        warn!("Gas prices too high this iteration");
        return;
    }

    // transfer dai exchanged from eth during previous iterations
    let res = transfer_dai(
        bridge.clone(),
        bridge.own_address,
        minimum_stranded_dai_transfer,
    )
    .await;
    if res.is_err() {
        warn!("Failed to transfer dai with {:?}", res);
    }
    trace!("Transfered dai");

    // run the conveyor belt eth -> xdai
    if our_eth_balance >= minimum_to_exchange {
        // Leave a reserve in the account to use for gas in the future
        let swap_amount = our_eth_balance - reserve_amount;

        detailed_state_change(DetailedBridgeState::EthToDai {
            amount_of_eth: swap_amount.clone(),
            wei_per_dollar,
        });

        info!("Converting to Dai");
        let _dai_bought = match bridge.eth_to_dai_swap(swap_amount, UNISWAP_TIMEOUT).await {
            Ok(val) => val,
            Err(e) => {
                warn!("Failed to swap dai with {:?}", e);
                return;
            }
        };
    } else {
        detailed_state_change(DetailedBridgeState::NoOp {
            eth_balance: our_eth_balance,
            wei_per_dollar,
        });
    }
}

/// This helper function adds a gas price entry to the GAS_PRICES data store.
fn update_gas_price_store(gp: Uint256, datastore: &mut VecDeque<Uint256>) {
    match datastore.len().cmp(&GAS_PRICE_ENTRIES) {
        Ordering::Less => datastore.push_front(gp),
        Ordering::Equal => {
            //vec is full, remove oldest entry
            datastore.pop_back();
            datastore.push_front(gp);
        }
        Ordering::Greater => {
            panic!("Vec size greater than max size, error in GAS_PRICES vecDeque logic")
        }
    }
}

/// Look thorugh all the gas prices in the last 24 hours and determine the highest
/// acceptabe price to pay (bottom 20% of gas prices in last 24 hours)
fn get_acceptable_gas_price(
    eth_gas_price: Uint256,
    datastore: &VecDeque<Uint256>,
) -> Result<Uint256, Error> {
    // if there are no entries, return current gas price as acceptable
    // We should not reach this condition since we alway call update_gas_price_store
    // before calling this function
    if datastore.is_empty() {
        return Ok(eth_gas_price);
    }

    let vector = datastore.clone();
    let mut vector: Vec<Uint256> = Vec::from_iter(vector);
    vector.sort();

    //find gas price in lowest 20%
    let lowest_20: usize = (0.2_f32 * vector.len() as f32).ceil() as usize;
    let value = match vector.get(lowest_20 - 1) {
        Some(a) => a.clone(),
        None => {
            bail!("There is no entry at index {}, should not reach this condition, error with GAS_PRICES vecDeque logic", lowest_20 - 1);
        }
    };
    Ok(value)
}

/// This function is called inside the bridge loop. It retrieves the 'n' most recent blocks
/// (where 'n' is the const 'BLOCKS' that is currently set to 40,032, which represents 1 week of blocks on xdai chain) that
/// have withdraw events related to our address. It then simulates these events and submits
/// the signatures needed to unlock the funds.
async fn simulated_withdrawal_on_eth(
    bridge: &TokenBridgeCore,
    wei_per_dollar: Uint256,
) -> Result<(), TokenBridgeError> {
    let client = bridge.xdai_web3.clone();

    let events = check_withdrawals(
        BLOCKS,
        bridge.xdai_bridge_on_xdai,
        client,
        vec![bridge.own_address],
    )
    .await?;

    for event in events.iter() {
        let txid = event.txid.clone();
        let amount = event.amount.clone();
        let w_p_dollar = wei_per_dollar.clone();

        let withdraw_info = get_relay_message_hash(
            bridge.own_address,
            bridge.xdai_web3.clone(),
            bridge.helper_on_xdai,
            event.receiver,
            txid.clone(),
            amount.clone(),
        )
        .await?;

        // check if the event has already unlocked the funds or not
        let res = match check_relayed_message(
            event.txid.clone(),
            bridge.eth_web3.clone(),
            bridge.own_address,
            bridge.xdai_bridge_on_eth,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "Received Error when checking for signature 'relayedMessages': {}, skipping",
                    e
                );
                continue;
            }
        };

        if res {
            trace!(
                "Transaction with Id: {} has already been unlocked, skipping",
                display_uint256_as_address(txid.clone())
            );
            continue;
        } else {
            //unlock this transaction
            trace!(
                "Tx Hash is {} with the amount of {} for a withdraw event",
                display_uint256_as_address(txid.clone()),
                amount
            );
            let _res = bridge
                .submit_signatures_to_unlock_funds(withdraw_info, SIGNATURES_TIMEOUT)
                .await?;
            detailed_state_change(DetailedBridgeState::DaiToDest {
                amount_of_dai: amount,
                wei_per_dollar: w_p_dollar,
                dest_address: event.receiver,
            });
        }
    }

    Ok(())
}

/// This function simulates the withdraw event given to it. Based on this information, we can decide if we want to
/// process this transaction by using real money. This allows us to unlock the funds on the 'eth' side. This function is currently not in use
/// and we use check_relayed_message() instead for simplicity.
#[allow(dead_code)]
async fn simulate_signature_submission(
    bridge: &TokenBridgeCore,
    data: &HelperWithdrawInfo,
) -> Result<Vec<u8>, Web3Error> {
    let payload = get_payload_for_funds_unlock(data);
    bridge
        .eth_web3
        .simulate_transaction(
            bridge.xdai_bridge_on_eth,
            0_u32.into(),
            payload,
            bridge.own_address,
            None,
        )
        .await
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
pub fn setup_withdraw(msg: Withdraw) -> Result<(), Error> {
    let mut writer = BRIDGE.write().unwrap();

    // If there is already a withdrawal that needs to be executed, return
    if writer.withdraw_in_progress {
        bail!("There is currently a withdraw in progress!");
    }

    // Setup withdraw information so we can execute it during next tick
    writer.withdraw_in_progress = true;
    writer.withdraw_details = Some(Withdraw {
        to: msg.to,
        amount: msg.amount,
    });

    Ok(())
}

/// This function initiates the withdrawal by calling the relayTokens function when there is no
/// other withdrawal currently in progress. It receives the information from the lazy static varaible,
/// which was setup by the function setup_withdrawal, and runs every loop to see if this lazy static has
/// been populated with new information to initialize a withdrawal.
pub async fn withdraw(msg: Withdraw) -> Result<(), Error> {
    let payment_settings = settings::get_rita_common().payment;
    let system_chain = payment_settings.system_chain;
    drop(payment_settings);

    let to = msg.to;
    let amount = msg.amount.clone();

    info!("bridge withdraw handler amount {}", amount);

    if let SystemChain::Xdai = system_chain {
        //check if a wtihdrawal is in progress, if not set bool to true
        let mut writer = BRIDGE.write().unwrap();
        if !writer.withdraw_in_progress {
            writer.withdraw_in_progress = true;
            let token_bridge = get_core();
            let _res =
                encode_relaytokens(token_bridge, to, amount.clone(), Duration::from_secs(600))
                    .await;

            detailed_state_change(DetailedBridgeState::XdaiToDai { amount });
            // Reset the lock
            writer.withdraw_in_progress = false;
            Ok(())
        } else {
            bail!("There is currently a withdraw in progress!");
        }
    } else {
        bail!("Not on Xdai chain!");
    }
}

fn detailed_state_change(msg: DetailedBridgeState) {
    trace!("Changing detailed state to {:?}", msg);
    let mut bridge = BRIDGE.write().unwrap();
    let new_state = msg;
    bridge.detailed_state = new_state;
}

fn set_last_amounts(minimum_to_exchange: u32, reserve_amount: u32) {
    let mut amounts = AMOUNTS.write().unwrap();
    *amounts = LastAmounts {
        minimum_to_exchange,
        reserve_amount,
    };
}

/// Used to display the state of the bridge to the user, has a higher
/// resolution than the actual bridge state object in exchange for possibly
/// being inaccurate or going backwards
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub enum DetailedBridgeState {
    /// Converting Eth to Dai
    EthToDai {
        amount_of_eth: Uint256,
        wei_per_dollar: Uint256,
    },
    /// Converting Dai to Xdai
    DaiToXdai { amount: Uint256 },
    /// Converting Xdai to Dai
    XdaiToDai { amount: Uint256 },
    /// Converting Dai to Eth
    DaiToEth {
        amount_of_dai: Uint256,
        wei_per_dollar: Uint256,
    },
    DaiToDest {
        amount_of_dai: Uint256,
        wei_per_dollar: Uint256,
        dest_address: Address,
    },
    /// Nothing is happening
    NoOp {
        eth_balance: Uint256,
        wei_per_dollar: Uint256,
    },
}

/// Contains everything a user facing application would need to help a user
/// interact with the bridge
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub struct BridgeStatus {
    reserve_amount: u32,
    minimum_deposit: u32,
    withdraw_chain: SystemChain,
    state: DetailedBridgeState,
}

pub fn get_bridge_status() -> BridgeStatus {
    let payment_settings = settings::get_rita_common().payment;
    let withdraw_chain = payment_settings.withdraw_chain;
    drop(payment_settings);
    let bridge = BRIDGE.read().unwrap().clone();
    // amounts is in cents, we need to convert to dollars for the dashboard display
    let amounts = AMOUNTS.read().unwrap().clone();
    let reserve_amount = amounts.reserve_amount / 100;
    let minimum_to_exchange = amounts.minimum_to_exchange / 100;
    BridgeStatus {
        reserve_amount,
        minimum_deposit: minimum_to_exchange,
        withdraw_chain,
        state: bridge.detailed_state,
    }
}

/// Grab state parameters from settings
fn get_core() -> TokenBridgeCore {
    let payment_settings = settings::get_rita_common().payment;
    token_bridge_core_from_settings(&payment_settings)
}

/// the amount of Eth to retain in WEI. This is the cost of our Uniswap exchange an ERC20 transfer
/// and one ETH transfer. To pay for Uniswap -> send to bridge and keep enough around for a withdraw
/// which involves a Uniswap exchange -> Eth send (since the ERC20 send is paid by the bridge)
/// this ensures that a withdraw is always possible. Currently we have reduced this to only ensure
/// that the deposit goes through. Because reserving enough funds is too expensive.
fn get_reserve_amount(eth_gas_price: Uint256) -> Uint256 {
    // eth_gas_price * (ERC20_GAS_LIMIT + (UNISWAP_GAS_LIMIT * 2) + ETH_TRANSACTION_GAS_LIMIT).into()
    eth_gas_price * (XDAI_FUNDS_UNLOCK_GAS).into()
}

fn lossy_u32(input: Uint256) -> u32 {
    match input.to_string().parse() {
        Ok(val) => val,
        // the only possible error the number being too large, both are unsigned. String formatting
        // won't change etc.
        Err(_e) => u32::MAX,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use auto_bridge::default_bridge_addresses;
    use auto_bridge::TokenBridge;
    use clarity::PrivateKey;
    use std::str::FromStr;

    const TIMEOUT: Duration = Duration::from_secs(600);

    /// This simply test that the lazy static lock is being updated correctly after calling the function setup_withdrawal.
    /// We call the function with the 'Withdraw' struct and check if the information is being updated correctly. This is necessary
    /// that the correct information about the withdrawal is being processed.
    #[test]
    fn test_xdai_setup_withdraw() {
        let pk = PrivateKey::from_str(&format!(
            "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
            "632c1e54099", "51b0281"
        ))
        .unwrap();

        let _bridge = TokenBridge::new(
            default_bridge_addresses(),
            pk.to_public_key().unwrap(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
            TIMEOUT,
        );

        let address = "0x9CAFD25b8b5982F1edA0691DEF8997C55a4d8188";
        let address = Address::parse_and_validate(address);
        if address.is_err() {
            panic!("withdraw address is wrong");
        }
        let withdraw = Withdraw {
            to: address.unwrap(),
            amount: 11646660293665450_u64.into(),
        };

        println!("ready for setup");
        let res = setup_withdraw(withdraw.clone());
        if res.is_err() {
            panic!("Error with setup withdrawal");
        }

        println!("setup done");

        let reader = BRIDGE.read().unwrap();
        let withdraw_setup = match &reader.withdraw_details {
            Some(a) => a.clone(),
            None => panic!("No value set in withdraw setup"),
        };

        //check lazy static
        assert!(reader.withdraw_in_progress);
        assert_eq!(withdraw_setup, withdraw);
    }

    /// Calls the encode_relaytokens and initiates the withdrawal process from xdai chain to an external address. Does not however unlock the funds on the eth side.
    /// Refer to test_xdai_unlock_withdraw() to check unlocking funds
    #[test]
    #[ignore]
    fn test_xdai_transfer_withdraw() {
        let pk = PrivateKey::from_str(&format!(
            "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
            "632c1e54099", "51b0281"
        ))
        .unwrap();

        let bridge = TokenBridge::new(
            default_bridge_addresses(),
            pk.to_public_key().unwrap(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
            TIMEOUT,
        );

        let address = "0x9CAFD25b8b5982F1edA0691DEF8997C55a4d8188";
        let address = Address::parse_and_validate(address);
        if address.is_err() {
            panic!("withdraw address is wrong");
        }
        let to = address.unwrap();
        //10 xdai
        let amount = 10000000000000000000_u128;

        //Run the withdrawal process
        let runner = actix_async::System::new();
        runner.block_on(async move {
            //do encode relay token call with our token bridge
            let res = encode_relaytokens(bridge, to, amount.into(), Duration::from_secs(600)).await;
            match res {
                Ok(_) => println!("withdraw successful to address {}", to),
                Err(e) => panic!("Error during withdraw: {}", e),
            }
        })
    }

    /// This tests the the funds that were initially transfered by test_xdai_transfer_withdraw can we unlocked, Note that the event you are trying to unlock
    /// needs to be within 40k blocks of the current xdai chain block height, or the withdraw event will not be found.
    #[test]
    #[ignore]
    fn test_xdai_unlock_withdraw() {
        let pk = PrivateKey::from_str(&format!(
            "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
            "632c1e54099", "51b0281"
        ))
        .unwrap();

        let bridge = TokenBridge::new(
            default_bridge_addresses(),
            pk.to_public_key().unwrap(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
            TIMEOUT,
        );

        let runner = actix_async::System::new();

        runner.block_on(async move {
            let wei_per_dollar = match bridge.dai_to_eth_price(eth_to_wei(1u8.into())).await {
                Ok(val) => val,
                Err(e) => {
                    warn!("Failed to get eth price with {}", e);
                    return;
                }
            };

            match simulated_withdrawal_on_eth(&bridge, wei_per_dollar.clone()).await {
                Ok(()) => {
                    println!(
                        "Checking for withdraw events related to us (address: {})",
                        bridge.own_address
                    );
                }
                Err(e) => {
                    println!("Received error when trying to unlock funds: {}", e);
                }
            }
        })
    }

    /// This tests the function simulate_signature_submission(), which is used to tests if a transaction needs to be unlocked on eth side or not.
    /// This function not currently in use and we instead use check_relayed_message because of simplicity, but simulate_signature_submission() is also functional and
    /// checks the same thing as check_relayed_message() does.
    #[test]
    fn test_simulate_unlock_funds() {
        let pk = PrivateKey::from_str(&format!(
            "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
            "632c1e54099", "51b0281"
        ))
        .unwrap();

        let bridge = TokenBridge::new(
            default_bridge_addresses(),
            pk.to_public_key().unwrap(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
            TIMEOUT,
        );

        let address = "0x9CAFD25b8b5982F1edA0691DEF8997C55a4d8188";
        let address = Address::parse_and_validate(address).unwrap();

        let tx_hash = "0xf75cd74e3643bb0d17780589e0f18840c89ff77532f5ac38fbff885468091620";
        let tx_hash = Uint256::from_str(tx_hash).unwrap();

        let amount = 10000000000000000000_u128;

        let runner = actix_async::System::new();

        runner.block_on(async move {
            let withdraw_info = get_relay_message_hash(
                bridge.own_address,
                bridge.xdai_web3.clone(),
                bridge.helper_on_xdai,
                address,
                tx_hash,
                amount.into(),
            )
            .await
            .unwrap();

            match simulate_signature_submission(&bridge, &withdraw_info).await {
                Ok(_) => println!("Successful simulation"),
                Err(e) => println!("Simulation failed {}", e),
            }
        })
    }

    /// Tests the deposit flow of funds from eth to dai on xdai chain. First converts eth to dai, reserving an amount
    /// to pay for withdrawal. Then transfer this amount over to the xdai chain.
    #[test]
    #[ignore]
    fn test_deposit_flow() {
        let pk = PrivateKey::from_str(&format!(
            "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
            "632c1e54099", "51b0281"
        ))
        .unwrap();

        let bridge = TokenBridge::new(
            default_bridge_addresses(),
            pk.to_public_key().unwrap(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
            TIMEOUT,
        );

        let runner = actix_async::System::new();
        runner.block_on(async move {
            let eth_gas_price = match bridge.eth_web3.eth_gas_price().await {
                Ok(val) => val,
                Err(e) => {
                    panic!("Failed to get eth gas price with {}", e);
                }
            };

            let reserve_amount = get_reserve_amount(eth_gas_price.clone());
            println!("reserve amount is {}", reserve_amount);
            let minimum_to_exchange = reserve_amount.clone()
                + (eth_gas_price.clone() * (UNISWAP_GAS_LIMIT + ERC20_GAS_LIMIT).into());
            println!("Mnimum to exchnage is {}", minimum_to_exchange);

            let our_eth_balance = match bridge.eth_web3.eth_get_balance(bridge.own_address).await {
                Ok(val) => val,
                Err(e) => {
                    panic!("Failed to get eth balance {}", e);
                }
            };
            println!("Our eth balance is {}", our_eth_balance);

            // run the conveyor belt eth -> xdai
            if our_eth_balance >= minimum_to_exchange {
                // Leave a reserve in the account to use for gas in the future
                let swap_amount = our_eth_balance - reserve_amount;

                let dai_bought = match bridge.eth_to_dai_swap(swap_amount, UNISWAP_TIMEOUT).await {
                    Ok(val) => val,
                    Err(e) => {
                        panic!("Failed to swap dai with {:?}", e);
                    }
                };
                println!("received dai: {}", dai_bought);

                // And over the bridge into xDai
                let _res = bridge
                    .dai_to_xdai_bridge(dai_bought, ETH_TRANSFER_TIMEOUT)
                    .await;
            } else {
                println!("ETH BALANCE IS NOT GREATER THAN MIN");
            }
        })
    }

    /// Tests that funds in dai are being transfered over to the xdai blockchain as long as dai funds are greater than
    /// minimum amount to exchange (cost of a withdrawal + cost of swap to dai + cost of transfer)
    #[test]
    #[ignore]
    fn test_transfer_dai() {
        let pk = PrivateKey::from_str(&format!(
            "983aa7cb3e22b5aa8425facb9703a{}e04bd829e675b{}e5df",
            "632c1e54099", "51b0281"
        ))
        .unwrap();

        let bridge = TokenBridge::new(
            default_bridge_addresses(),
            pk.to_public_key().unwrap(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
            TIMEOUT,
        );

        let runner = actix_async::System::new();
        runner.block_on(async move {
            let eth_gas_price = match bridge.eth_web3.eth_gas_price().await {
                Ok(val) => val,
                Err(e) => {
                    panic!("Failed to get eth gas price with {}", e);
                }
            };
            let reserve_amount = get_reserve_amount(eth_gas_price.clone());

            let minimum_to_exchange = reserve_amount.clone()
                + (eth_gas_price.clone() * (UNISWAP_GAS_LIMIT + ERC20_GAS_LIMIT).into());

            let res = transfer_dai(bridge.clone(), bridge.own_address, minimum_to_exchange).await;
            if res.is_err() {
                panic!("Failed to rescue dai with {:?}", res);
            }
        })
    }

    /// This test the function update_gas_price_store to check if the lazy static would be updated
    /// correctly, both for when the queue size is less that max capacity and for when it is at max
    /// capacity
    #[test]
    fn test_update_gas_price_store() {
        let mut vec: VecDeque<Uint256> = VecDeque::with_capacity(GAS_PRICE_ENTRIES);
        assert_eq!(vec.len(), 0);

        update_gas_price_store(12_u32.into(), &mut vec);

        assert_eq!(vec.len(), 1);
        assert_eq!(
            vec.get(0).unwrap().clone(),
            Uint256::from_bytes_be(&[12_u8])
        );

        let append_vec = vec![Uint256::from_bytes_be(&[12_u8]); 1439];

        vec.append(&mut VecDeque::from(append_vec));

        assert_eq!(vec.len(), GAS_PRICE_ENTRIES);

        update_gas_price_store(11_u32.into(), &mut vec);

        // Vec size should not exceed GAS_PRICE_ENTRIES and eariliest elemtn should match what we just added.
        assert_eq!(vec.len(), GAS_PRICE_ENTRIES);
        assert_eq!(
            vec.get(0).unwrap().clone(),
            Uint256::from_bytes_be(&[11_u8])
        );
    }

    /// Test the function get_acceptable_gas_price, which contains logic for getting the max threshold
    /// for the bottom 20% of prices in datastore. Tests various scenarios such as empty queue and odd
    /// number of elements in datastore
    #[test]
    fn test_get_acceptable_gas_price() {
        let mut vec: VecDeque<Uint256> = VecDeque::with_capacity(GAS_PRICE_ENTRIES);
        let eth_gas_price = Uint256::from_bytes_be(&[12_u8]);

        // when datastore is empty, return current gas price
        let res = get_acceptable_gas_price(eth_gas_price.clone(), &vec).unwrap();
        assert_eq!(eth_gas_price, res);

        // when datastore has one element, return it
        vec.push_front(12_u32.into());
        let res = get_acceptable_gas_price(eth_gas_price.clone(), &vec).unwrap();
        assert_eq!(res, eth_gas_price);
        vec.pop_front();

        // when datastore has multiple elements, calculate bottom 20% and return threshold value
        let append_vec: Vec<Uint256> = vec![
            1_u32.into(),
            2_u32.into(),
            3_u32.into(),
            4_u32.into(),
            5_u32.into(),
            6_u32.into(),
            7_u32.into(),
            8_u32.into(),
            9_u32.into(),
            10_u32.into(),
        ];
        assert_eq!(vec.len(), 0);
        vec.append(&mut VecDeque::from(append_vec));
        assert_eq!(vec.len(), 10);
        let res = get_acceptable_gas_price(eth_gas_price.clone(), &vec).unwrap();
        assert_eq!(res, Uint256::from_bytes_be(&[2_u8]));

        //test for random order in datastore
        vec.clear();
        assert_eq!(vec.len(), 0);
        let append_vec: Vec<Uint256> = vec![
            10_u32.into(),
            5_u32.into(),
            3_u32.into(),
            7_u32.into(),
            8_u32.into(),
            6_u32.into(),
            2_u32.into(),
            1_u32.into(),
            9_u32.into(),
            4_u32.into(),
        ];
        vec.append(&mut VecDeque::from(append_vec));
        assert_eq!(vec.len(), 10);
        let res = get_acceptable_gas_price(eth_gas_price.clone(), &vec).unwrap();
        assert_eq!(res, Uint256::from_bytes_be(&[2_u8]));

        //test for odd nubmer of elements in datastore
        vec.push_front(0_u32.into());
        assert_eq!(vec.len(), 11);
        let res = get_acceptable_gas_price(eth_gas_price, &vec).unwrap();
        assert_eq!(res, Uint256::from_bytes_be(&[2_u8]));
    }
}
