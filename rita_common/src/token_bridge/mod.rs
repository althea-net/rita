// This module is designed to allow easy deposits for some supported chains using Ethereum. The idea
// is pretty simple, the user deposits money into their routers Ethereum address, this is then exchanged
// through uniswap into USDS (or another configured stablecoin) and then from there it is bridged over
// to the Gnosis chain or via Gravity Bridge to Althea L1.

// Essentially the goal is to allow users to deposit a popular and easy to acquire coin on Ethereum and then
// actually transact in a stablecoin on a fast blockchain, eg not Ethereum.

// Currently this flow supports USDC, USDT, DAI, WETH, USDS, and sUSDS as input tokens.

// This entire module works on the premise we call the conveyor belt model. It's difficult to track
// money through this entire process exactly, in fact there are some edge cases where it's simply not
// possible to reliably say if a task has completed or not. With that in mind we simply always progress
// the process for Source coin -> USDS -> Gnosis/Althea L1.

// For the withdraw process we update a lazy static variable every time a withdraw is invoked.
// Every tick, we check for updated withdraw information in the lazy static and use this to
// initiate a withdrawal. From there, we loop to check for events related to the withdraws,
// simulate these, and those that pass are unlocked on the eth side. Funds are sent to their final
// destination in USDS

pub mod althea_bridge;
#[cfg(test)]
mod tests;
pub mod xdai_bridge;

use crate::rita_loop::slow_loop::SLOW_LOOP_TIMEOUT;
use crate::token_bridge::althea_bridge::althea_bridge as run_althea_bridge;
use crate::token_bridge::xdai_bridge::*;
use crate::RitaCommonError;
use althea_types::SystemChain;
use clarity::Address;
use deep_space::private_key::PrivateKey as PrivateKeyTrait;
use gnosis_bridge::encode_relaytokens;
use gnosis_bridge::TokenBridge as TokenBridgeCore;
use gravity_bridge::GravityBridge;
use num256::Uint256;
use settings::payment::PaymentSettings;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use web30::jsonrpc::error::Web3Error;
use web30::types::SendTxOption;

/// Default Althea L1 EVM address used for simulated balance queries.
/// The Althea EVM requires a 'from' address even for read-only calls.
fn default_bootstrap_query_addr() -> Address {
    "0xd263DC98dEc57828e26F69bA8687281BA5D052E0"
        .parse()
        .unwrap()
}

lazy_static! {
    static ref BRIDGE: Arc<RwLock<TokenBridgeState>> =
        Arc::new(RwLock::new(TokenBridgeState::default()));
}

pub const ETH_TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000_u128;
const SIGNATURES_TIMEOUT: Duration = ETH_TRANSFER_TIMEOUT;
/// How many blocks we search for on the Gnosis side for required bridge out events
/// if this number is too large requests will fail, if it is too small we may miss a withdraw
/// fortunately with the newer highly optmized event query flow this can be up to 100k before we
/// start seeing issues.
const EVENT_SEARCH_BLOCKS: u64 = 100_000;

pub fn eth_to_wei(eth: u64) -> Uint256 {
    let wei = eth as u128 * WEI_PER_ETH;
    wei.into()
}

/// This struct contains the state of the bridge. TokenBridgeAmounts contains the
/// amounts we commonly reference for the operation in this file and TokenBridgeCore
/// contains details fo the various inner workings of the actual contract and bridge calls
/// rather than the logic. This struct was previously combined with TokenBridgeAmounts but
/// we want to reload the amounts regularly without interfering with the state.
#[derive(Clone, Debug)]
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

    match system_chain {
        SystemChain::Xdai => {
            let core = token_bridge_core_from_settings(&payment_settings);
            xdai_bridge(core).await;
        }
        SystemChain::AltheaL1 => {
            // Construct both cores together — if gravity fails, skip the whole tick
            let gravity_core = gravity_bridge_core_from_settings(&payment_settings);
            match gravity_core {
                Ok(gravity_core) => {
                    let gnosis_core = token_bridge_core_from_settings(&payment_settings);
                    run_althea_bridge(gravity_core, gnosis_core).await;
                }
                Err(e) => {
                    error!("Error initializing Gravity Bridge core for Althea L1 bridge: {e}");
                }
            }
        }
        SystemChain::Ethereum => {}
        SystemChain::Sepolia => {}
    }
}

fn token_bridge_core_from_settings(payment_settings: &PaymentSettings) -> TokenBridgeCore {
    let addresses = payment_settings.bridge_rpcs.clone();
    TokenBridgeCore::new(
        addresses.clone(),
        payment_settings.get_eth_address().unwrap(),
        payment_settings.eth_private_key.unwrap(),
        SLOW_LOOP_TIMEOUT,
    )
}

/// Construct a GravityBridge instance from PaymentSettings.
/// ETH and Althea node URLs come from the existing payment settings fields.
fn gravity_bridge_core_from_settings(
    payment_settings: &PaymentSettings,
) -> Result<GravityBridge, RitaCommonError> {
    // address is already generated
    let eth_private_key = payment_settings.eth_private_key.unwrap();
    // Derive Cosmos key from the same ETH private key (ethermint compatible).
    // Log the derived addresses so any key derivation mismatch is visible on startup.
    let cosmos_key: deep_space::EthermintPrivateKey = eth_private_key.into();
    let derived_eth_addr = cosmos_key.as_ethereum_key().to_address();
    let derived_cosmos_addr = cosmos_key
        .to_address(gravity_bridge::ALTHEA_CHAIN_PREFIX)
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "DERIVATION_FAILED".to_string());
    info!(
        "Gravity bridge initialized: ETH address={derived_eth_addr}, Cosmos address={derived_cosmos_addr}"
    );
    let eth_url = payment_settings.bridge_rpcs.eth_full_node_url.clone();
    // these are not in the bridge rpc section but we need them for the althea bridge, so we pull them from the general payment settings
    let (althea_grpc, althea_evm_url) = match (
        payment_settings.althea_grpc_list.first().cloned(),
        payment_settings.eth_node_list.first().cloned(),
    ) {
        (Some(grpc), Some(evm)) => (grpc, evm),
        _ => {
            return Err(RitaCommonError::NoAltheaChainRPCs);
        }
    };

    // Gravity Bridge gRPC URL (hardcoded default for now)
    let gravity_grpc_url = payment_settings.bridge_rpcs.gravity_grpc_url.clone();

    // Convert Denom to deep_space::Coin for target stablecoin
    let target_stablecoin = deep_space::Coin {
        denom: payment_settings.althea_l1_payment_denom.denom.clone(),
        amount: 0u64.into(), // amount doesn't matter for configuration
    };

    Ok(GravityBridge::new(
        cosmos_key,
        &eth_url,
        &althea_evm_url,
        &gravity_grpc_url,
        &althea_grpc,
        target_stablecoin,
        default_bootstrap_query_addr(),
        SLOW_LOOP_TIMEOUT,
    ))
}

impl TokenBridgeState {
    /// Reset both withdraw fields together. Splitting these into two assignments
    /// at every cleanup site repeatedly invites the bug where one is forgotten,
    /// leaving `withdraw_in_progress = true` with no details and wedging future
    /// withdraws.
    fn clear_withdraw(&mut self) {
        self.withdraw_in_progress = false;
        self.withdraw_details = None;
    }
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
/// we use this function to setup information about the withdrawal in the sync context. We setup
/// a bool and Withdraw struct inside a lazy static variable that we can read from later when
/// we initiate the withdrawal from an async context.
pub fn setup_withdraw(msg: Withdraw) -> Result<(), RitaCommonError> {
    // Reject zero-amount up front. A zero withdraw can't make progress
    // (Stage 2 fee guard would skip it forever) but it would still occupy the
    // withdraw slot, so callers would get "withdraw in progress" until restart.
    if msg.amount == 0u8.into() {
        return Err(RitaCommonError::MiscStringError(
            "Cannot withdraw a zero amount".to_string(),
        ));
    }

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

    info!("bridge withdraw handler amount {amount}");

    if let SystemChain::Xdai = system_chain {
        //check if a wtihdrawal is in progress, if not set bool to true
        let mut writer = get_bridge_state();
        if !writer.withdraw_in_progress {
            writer.withdraw_in_progress = true;
            set_bridge_state(writer.clone());
            // Log the relayTokens result rather than discarding it - silent failure
            // here means the user's funds are still on this side of the bridge but
            // we've already moved the state machine on.
            match encode_relaytokens(
                token_bridge,
                to,
                amount,
                Duration::from_secs(600),
                None,
                None,
            )
            .await
            {
                Ok(()) => info!("relayTokens submitted for withdraw of {amount} to {to}"),
                Err(e) => error!("relayTokens failed for withdraw of {amount} to {to}: {e}"),
            }

            detailed_state_change(DetailedBridgeState::XdaiToDai { amount });
            // Reset the lock
            writer.clear_withdraw();
            set_bridge_state(writer);
            Ok(())
        } else {
            Err(RitaCommonError::MiscStringError(
                "There is currently a withdraw in progress!".to_string(),
            ))
        }
    } else if let SystemChain::AltheaL1 = system_chain {
        // For AltheaL1, set up the withdraw state for the conveyor belt to pick up
        let mut writer = get_bridge_state();
        if !writer.withdraw_in_progress {
            writer.withdraw_in_progress = true;
            writer.withdraw_details = Some(Withdraw { to, amount });
            set_bridge_state(writer);
            Ok(())
        } else {
            Err(RitaCommonError::MiscStringError(
                "There is currently a withdraw in progress!".to_string(),
            ))
        }
    } else {
        Err(RitaCommonError::MiscStringError(
            "Unsupported chain for withdraw!".to_string(),
        ))
    }
}

fn detailed_state_change(msg: DetailedBridgeState) {
    trace!("Changing detailed state to {msg:?}");
    let mut bridge = BRIDGE.write().unwrap();
    trace!("Finished changing detailed state {msg:?}");
    let new_state = msg;
    bridge.detailed_state = new_state;
}

/// A typed token amount that carries denomination and decimal metadata,
/// preventing accidental mixing of 6-decimal and 18-decimal token values.
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub struct TokenAmount {
    pub value: Uint256,
    /// Number of decimal places for this token (e.g. 6 for USDC, 18 for DAI)
    pub decimals: u8,
    /// Human-readable token name (e.g. "USDC", "DAI")
    pub token_name: String,
}

impl TokenAmount {
    pub fn new(value: Uint256, decimals: u8, token_name: &str) -> Self {
        Self {
            value,
            decimals,
            token_name: token_name.to_string(),
        }
    }

    /// Shorthand for amounts where we don't have token metadata (e.g. native ETH or xDai)
    pub fn untyped(value: Uint256) -> Self {
        Self {
            value,
            decimals: 18,
            token_name: "unknown".to_string(),
        }
    }
}

/// Used to display the state of the bridge to the user, has a higher
/// resolution than the actual bridge state object in exchange for possibly
/// being inaccurate or going backwards
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub enum DetailedBridgeState {
    /// Swapping any input token for DAI
    Swap,
    /// Converting DAI to xDai (Gnosis bridge-in)
    DaiToXdai { amount: Uint256 },
    /// Converting xDai to DAI (Gnosis bridge-out)
    XdaiToDai { amount: Uint256 },
    DaiToDest {
        amount_of_dai: Uint256,
        dest_address: Address,
    },
    /// Nothing is happening
    NoOp,
    // --- Gravity/Althea L1 bridge-in ---
    /// Sending tokens to Gravity Bridge contract on Ethereum
    TokenToGravity { amount: TokenAmount },
    /// Unwrapping gravity ERC20 to Cosmos coin on Althea L1
    UnwrappingErc20 { amount: TokenAmount },
    // --- Gravity/Althea L1 bridge-out ---
    /// IBC transfer from Althea L1 to Gravity chain sent, waiting for arrival
    AltheaToGravityIbc { amount: TokenAmount },
    /// Tokens on Gravity chain, about to submit MsgSendToEth
    WaitingOnGravity { amount: TokenAmount },
    /// MsgSendToEth submitted, waiting for relayer to batch
    GravityToEthPending { amount: TokenAmount },
    // --- Gnosis migration ---
    /// Migrating funds from Gnosis chain to ETH (native xDai, 18 decimals)
    GnosisMigration { amount: Uint256 },
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

// ---- Shared Swap logic ----

#[derive(Debug)]
pub struct TokenBalance {
    pub token_address: Address,
    pub balance: Uint256,
    pub minimum_to_convert: Uint256,
    pub decimals: u8,
    pub name: String,
}
#[derive(Debug)]
pub struct TokensToSwap {
    pub token_address: Address,
    pub minimum_to_convert: Uint256,
    pub decimals: u8,
    pub name: String,
}

impl TokensToSwap {
    /// Create a new TokensToSwap entry. Validates that `minimum_to_convert` is consistent
    /// with `decimals` — specifically that it's not accidentally specified in the wrong decimal
    /// base (e.g. 18-decimal units for a 6-decimal token like USDC).
    fn new(token_address: Address, minimum_usd_units: u128, decimals: u8, name: &str) -> Self {
        // Sanity check: for tokens with <= 8 decimals, minimum should be < 10^12
        // For tokens with > 8 decimals, minimum should be >= 10^12
        // This catches the most common misconfiguration of setting 18-decimal amounts for 6-decimal tokens
        let threshold: u128 = 1_000_000_000_000; // 10^12
        if decimals <= 8 && minimum_usd_units >= threshold {
            warn!(
                "TokensToSwap {name}: minimum_to_convert ({minimum_usd_units}) looks too large for {decimals}-decimal token. \
                 Did you accidentally use 18-decimal units?"
            );
        }
        if decimals > 8 && minimum_usd_units < threshold && minimum_usd_units > 0 {
            warn!(
                "TokensToSwap {name}: minimum_to_convert ({minimum_usd_units}) looks too small for {decimals}-decimal token. \
                 Did you accidentally use 6-decimal units?"
            );
        }
        Self {
            token_address,
            minimum_to_convert: minimum_usd_units.into(),
            decimals,
            name: name.to_string(),
        }
    }
}

pub fn get_input_tokens_for_swap() -> Vec<TokensToSwap> {
    vec![
        TokensToSwap::new(
            *web30::amm::DAI_CONTRACT_ADDRESS,
            2_000_000_000_000_000_000, // 2 DAI, 18 decimals
            18,
            "DAI",
        ),
        TokensToSwap::new(
            *web30::amm::USDC_CONTRACT_ADDRESS,
            2_000_000, // 2 USDC, 6 decimals
            6,
            "USDC",
        ),
        TokensToSwap::new(
            *web30::amm::USDT_CONTRACT_ADDRESS,
            2_000_000, // 2 USDT, 6 decimals
            6,
            "USDT",
        ),
        TokensToSwap::new(
            *web30::amm::WETH_CONTRACT_ADDRESS,
            1_000_000_000_000_000, // 0.001 WETH, 18 decimals (~$2 at $2000/ETH)
            18,
            "WETH",
        ),
        TokensToSwap::new(
            *web30::amm::USDS_CONTRACT_ADDRESS,
            2_000_000_000_000_000_000, // 2 USDS, 18 decimals
            18,
            "USDS",
        ),
        TokensToSwap::new(
            *web30::amm::SUSDS_CONTRACT_ADDRESS,
            2_000_000_000_000_000_000, // 2 sUSDS, 18 decimals
            18,
            "sUSDS",
        ),
    ]
}

/// Utility function to get the balance of all tokens we are interested in swapping in one call
/// and encoding the minimum bridge in values. The minimum is the max of both bridges minimum since this is
/// shared swap logic
pub async fn get_balances_of_input_tokens(
    web30: &web30::client::Web3,
    own_address: Address,
    requester: Address,
) -> Result<Vec<TokenBalance>, Web3Error> {
    let to_swap = get_input_tokens_for_swap();

    // Create futures for all balance checks to execute concurrently
    let balance_futures: Vec<_> = to_swap
        .into_iter()
        .map(|token| {
            let web30 = web30.clone();
            async move {
                let balance = web30
                    .get_erc20_balance_as_address(
                        Some(requester),
                        token.token_address,
                        own_address,
                        vec![SendTxOption::GasPriceMultiplier(2.0)],
                    )
                    .await?;
                Ok::<_, Web3Error>(TokenBalance {
                    token_address: token.token_address,
                    balance,
                    minimum_to_convert: token.minimum_to_convert,
                    decimals: token.decimals,
                    name: token.name,
                })
            }
        })
        .collect();

    // Execute all futures concurrently and collect results
    let results = futures::future::join_all(balance_futures).await;

    // Convert Vec<Result<TokenBalance, Web3Error>> to Result<Vec<TokenBalance>, Web3Error>
    results.into_iter().collect()
}

// Common swap token used in both bridge flows, swaps a shortlist of tokens into the target token on Uniswap v3.
async fn swap_stablecoins_to_target_token(
    // Mainnet Ethereum web3 client for swaps and balance checks
    web30: &web30::client::Web3,
    // The address we control and want to swap from
    our_private_key: &clarity::PrivateKey,
    // The token we are swapping into USDS for Gnosis and whatever the target token value is for Althea L1
    target_token: Address,
) {
    let token_balances = match get_balances_of_input_tokens(
        web30,
        our_private_key.to_address(),
        our_private_key.to_address(),
    )
    .await
    {
        Ok(balances) => balances,
        Err(e) => {
            warn!("Failed to get token balances for swap: {e}");
            return;
        }
    };

    info!("Our token balances for swap: {:?}", token_balances);

    let mut token_to_swap = None;
    let mut token_amount = None;
    for token in token_balances {
        if token.balance >= token.minimum_to_convert && token.token_address != target_token {
            token_to_swap = Some(token.token_address);
            token_amount = Some(token.balance);
            break;
        }
    }

    if let (Some(token), Some(token_amount)) = (token_to_swap, token_amount) {
        // 2% max slippage tolerance; tighter risks failing on legitimate volatility
        // and small swap sizes (where rounding/decimal differences eat more than 0.5%),
        // looser would invite more MEV extraction.
        let max_slippage = 0.02f64;

        // Use web30's route finder which generates and quotes (in parallel) all candidate
        // paths up to 2 intermediary hops through {WETH, USDC, USDT, DAI} across all
        // standard fee tiers (100, 500, 3000, 10000). It returns viable routes sorted
        // by output amount (best first). This handles cases where the direct USDC->USDS
        // 0.01% pool has no liquidity and the optimal path is e.g. USDC -> USDT -> USDS.
        let routes = match web30
            .find_uniswap_v3_routes(
                our_private_key.to_address(),
                token,
                target_token,
                token_amount,
                Some(max_slippage),
                None,    // try all generated routes
                Some(1), // we only need the best one
                None,    // default Quoter
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("No viable swap route from {token} to {target_token}: {e}");
                return;
            }
        };

        let (best_route, expected_out) = match routes.into_iter().next() {
            Some(pair) => pair,
            None => {
                warn!("Route finder returned no routes from {token} to {target_token}");
                return;
            }
        };

        // Apply slippage protection on the executed swap: amount_out_min is the quoted
        // output minus the slippage tolerance. This is what protects us from sandwich
        // attacks at execution time.
        let slippage_bps: Uint256 = ((max_slippage * 10_000.0) as u64).into();
        let amount_out_min =
            expected_out - (expected_out * slippage_bps / Uint256::from(10_000u64));

        let path = best_route.to_path();
        info!(
            "Swapping {token_amount} of {token} -> {target_token} via route {best_route:?} (expected {expected_out}, min {amount_out_min})"
        );

        match web30
            .swap_uniswap_v3_multihop(
                *our_private_key,
                token,
                &path,
                token_amount,
                amount_out_min,
                None, // deadline (defaults to +10min)
                None, // uniswap_router
                None, // options
                Some(ETH_TRANSFER_TIMEOUT),
            )
            .await
        {
            Ok(txid) => info!("Multi-hop swap succeeded, txid {txid}"),
            Err(e) => warn!("Multi-hop swap from {token} to {target_token} failed: {e}"),
        }
        detailed_state_change(DetailedBridgeState::Swap);
    }
}
