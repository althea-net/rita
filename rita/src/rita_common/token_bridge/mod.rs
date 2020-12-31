//! This module is designed to allow easy deposits for some supported chains using Ethereum. The idea
//! is pretty simple, the user deposits money into their routers Ethereum address, this is then exchanged
//! through uniswap into DAI and then from there it is bridged over to the Xdai proof of authority chains.
//! Support for Cosmos chains using a DAI-pegged native currency is next on the list.
//!
//! Essentially the goal is to allow users to deposit a popular and easy to acquire coin like Ethereum and then
//! actually transact in a stablecoin on a fast blockchain, eg not Ethereum. Withdraws are also transparently
//! converted back to Ethereum to allow easy exchange by the user.
//!
//! This entire module works on the premise we call the conveyor belt model. It's difficult to track
//! money through this entire process exactly, in fact there are some edge cases where it's simply not
//! possible to reliably say if a task has completed or not. With that in mind we simply always progress
//! the the process for Eth -> DAI -> XDAI unless we explicitly have a withdraw in progress. So if we find
//! some DAI in our address it will always be converted to XDAI even if we didn't convert that DAI from Eth
//! in the first place.
//!
//! For the withdraw process we create a withdraw request object which does a best effort shepherding of the
//! requested withdraw amount back to Eth and into the users hands. If this fails then the withdraw will timeout
//! and the money will not be lost but instead moved back into XDAI by the normal conveyor belt operation
//!
//!
//! TickEvent:
//!     State::Ready:
//!         If there is a Dai balance, send it thru the bridge into xdai (this rescues stuck funds in Dai)
//!
//!         If there is an `eth_balance` that is greater than the `minimum_to_exchange` amount,
//!         subtract the `reserve` amount and send it through uniswap into DAI. If not Change to State::Ready
//!         Future waits on Uniswap, and upon successful swap, sends dai thru the bridge into xdai.
//!         When the money is out of the Dai account and in the bridge, or if uniswap times out, change
//!         to State::Ready.
//!
//!     State::WithdrawRequest { to, amount, timestamp}:
//!         Performs the initial send to the bridge, then progresses to State::Withdrawing, this is required
//!         in order to ensure that we only send the funds for a given withdraw once
//!
//!     State::Withdrawing { to, amount, timestamp}:
//!         If the timestamp is expired, switch the state back into State::Ready.
//!
//!         If there is a dai balance greater or equal to the withdraw amount, send the withdraw
//!         amount through uniswap.
//!
//!         Future waits on Uniswap and upon successful swap, sends eth to "to" address. Another future
//!         waits on this transfer to complete. When it is complete, the state switches back to State::Ready

use crate::SETTING;
use althea_types::SystemChain;
use async_web30::types::SendTxOption;
use auto_bridge::ETH_TRANSACTION_GAS_LIMIT;
use auto_bridge::UNISWAP_GAS_LIMIT;
use auto_bridge::{HelperWithdrawInfo, ERC20_GAS_LIMIT};
use auto_bridge::{TokenBridge as TokenBridgeCore, TokenBridgeError};
use clarity::Address;
use failure::Error;
use num256::Uint256;
use num_traits::identities::Zero;
use rand::{thread_rng, Rng};
use settings::{payment::PaymentSettings, RitaCommonSettings};
use std::fmt;
use std::fmt::Display;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

lazy_static! {
    static ref BRIDGE: Arc<RwLock<TokenBridgeState>> =
        Arc::new(RwLock::new(TokenBridgeState::default()));
    static ref AMOUNTS: Arc<RwLock<LastAmounts>> = Arc::new(RwLock::new(LastAmounts::default()));
}

/// Six hours wall time. Only withdraw operations have a timeout since
/// they pause the movement of ETH -> DAI -> XDAI that is normal in the
/// system. Otherwise the normal process will be attempted indefinitely
const WITHDRAW_TIMEOUT: Duration = Duration::from_secs(3600 * 6);
pub const ETH_TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);
const UNISWAP_TIMEOUT: Duration = ETH_TRANSFER_TIMEOUT;

fn withdraw_is_timed_out(started: Instant) -> bool {
    Instant::now() - started > WITHDRAW_TIMEOUT
}

const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000_u128;

pub fn eth_to_wei(eth: u64) -> Uint256 {
    let wei = eth as u128 * WEI_PER_ETH;
    wei.into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum State {
    Ready,
    WithdrawRequest {
        amount: Uint256,
        to: Address,
        timestamp: Instant,
        withdraw_all: bool,
    },
    Withdrawing {
        // the txid of the transaction to the xdai bridge, required
        // to complete the process https://www.xdaichain.com/for-users/converting-xdai-via-bridge/transfer-sai-dai-without-the-ui-using-web3-or-mobile-wallet#transfer-xdai-to-dai-from-the-xdai-chain-to-the-ethereum-mainnet
        withdraw_xdai_txid: Uint256,
        unlock_details: Option<HelperWithdrawInfo>,
        amount: Uint256,
        to: Address,
        timestamp: Instant,
        withdraw_all: bool,
        amount_actually_exchanged: Option<Uint256>,
    },
}

impl Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Ready => write!(f, "Ready"),
            State::WithdrawRequest {
                amount: a,
                to: t,
                timestamp: ti,
                withdraw_all: w,
            } => write!(
                f,
                "WithdrawRequest:{{amount: {}, to: {}, timestamp: {:?}, withdraw_all: {}}}",
                a, t, ti, w
            ),
            State::Withdrawing {
                withdraw_xdai_txid: wt,
                unlock_details: ud,
                amount: a,
                to: t,
                timestamp: ti,
                withdraw_all: w,
                amount_actually_exchanged: aae
            } => write!(
                f,
                "Withdrawing:{{amount: {}, to: {}, timestamp: {:?}, withdraw_all: {}, amount_exchanged: {:?}, unlock_details {:?}, xdai_txid {:#066x}}}",
                a, t, ti, w, aae, ud, wt
            ),
        }
    }
}

/// This struct contains the state of the bridge. TokenBridgeAmounts contains the
/// amounts we commonly reference for the operation in this file and TokenBridgeCore
/// contains details fo the various inner workings of the actual contract and bridge calls
/// rather than the logic. This struct was previously combined with TokenBridgeAmounts but
/// we want to reload the amounts regularly without interfering with the state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenBridgeState {
    state: State,
    detailed_state: DetailedBridgeState,
}

/// The last values used for reserve and minimum to exchange
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct LastAmounts {
    minimum_to_exchange: u32,
    reserve_amount: u32,
}

pub async fn tick_token_bridge() {
    let bridge: TokenBridgeState = BRIDGE.read().unwrap().clone();
    let payment_settings = SETTING.get_payment();
    let system_chain = payment_settings.system_chain;

    if !payment_settings.bridge_enabled {
        return;
    }
    drop(payment_settings);

    info!("Launching bridge future with state {}", bridge.state);
    match system_chain {
        SystemChain::Xdai => state_change(xdai_bridge(bridge.state.clone()).await),
        SystemChain::Ethereum => eth_bridge().await,
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
    )
}

impl Default for TokenBridgeState {
    fn default() -> TokenBridgeState {
        TokenBridgeState {
            state: State::Ready,
            detailed_state: DetailedBridgeState::NoOp {
                eth_balance: Uint256::zero(),
                wei_per_dollar: Uint256::zero(),
            },
        }
    }
}

/// If some part of the depositing chain is disrupted due to a failure we may end up
/// with a stranded dai balance, this function detects that balance and 'rescues' stranded
/// dai
async fn rescue_dai(
    bridge: TokenBridgeCore,
    our_address: Address,
    minimum_stranded_dai_transfer: Uint256,
) -> Result<(), TokenBridgeError> {
    let dai_balance = bridge.get_dai_balance(our_address).await?;
    info!("Our DAI balance is {}", dai_balance);
    if dai_balance > minimum_stranded_dai_transfer {
        info!("rescuing dais");
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

/// simplified logic for bringing xdai back over to Eth if the user has xdai and then
/// selects Eth as their blockchain it will bring the full balance back into Eth
async fn eth_bridge() {
    let bridge = get_core();

    let our_dai_balance = match bridge.get_dai_balance(bridge.own_address).await {
        Ok(val) => val,
        Err(e) => {
            error!("Failed to get DAI balance with {:?}", e);
            return;
        }
    };
    let our_eth_balance = match bridge.eth_web3.eth_get_balance(bridge.own_address).await {
        Ok(val) => val,
        Err(e) => {
            error!("Failed to get ETH balance with {:?}", e);
            return;
        }
    };
    let wei_per_dollar = match bridge.dai_to_eth_price(eth_to_wei(1u8.into())).await {
        Ok(val) => val,
        Err(e) => {
            error!("Failed to get DAI price with {:?}", e);
            return;
        }
    };
    let our_xdai_balance = match bridge.xdai_web3.eth_get_balance(bridge.own_address).await {
        Ok(val) => val,
        Err(e) => {
            error!("Failed to get xDai balance with {:?}", e);
            return;
        }
    };

    info!(
        "xdai rescue state is {} dai {} eth {} xdai {} wei per dollar",
        our_dai_balance, our_eth_balance, our_xdai_balance, wei_per_dollar
    );
    let tx_gas: Uint256 = 21000u32.into();
    // if you actually ask for the gas price you'll get an incorrect value
    let xdai_gas_price: Uint256 = 60_000_000_000u128.into();
    let xdai_tx_cost = xdai_gas_price * tx_gas;
    // Money has come over the bridge
    if our_xdai_balance > xdai_tx_cost {
        let amount = our_xdai_balance - xdai_tx_cost;
        let res = bridge
            .xdai_to_dai_bridge(amount.clone(), SETTING.get_payment().gas_price.clone())
            .await;
        if res.is_err() {
            warn!("Xdai to xdai failed with {:?}", res);
        }
        detailed_state_change(DetailedBridgeState::XdaiToDai { amount });
    } else if our_dai_balance > 0u32.into() {
        // Then it converts to eth
        detailed_state_change(DetailedBridgeState::DaiToEth {
            amount_of_dai: our_dai_balance.clone(),
            wei_per_dollar,
        });
        let res = bridge
            .dai_to_eth_swap(our_dai_balance, UNISWAP_TIMEOUT)
            .await;
        if res.is_err() {
            warn!("Dai to Eth swap failed! {:?}", res);
        }
    // all other steps are done and the eth is sitting and waiting
    } else {
        detailed_state_change(DetailedBridgeState::NoOp {
            eth_balance: our_eth_balance,
            wei_per_dollar,
        });
    }
}

/// The logic for the Eth -> Xdai bridge operation
async fn xdai_bridge(state: State) -> State {
    let bridge = get_core();
    let eth_gas_price = match bridge.eth_web3.eth_gas_price().await {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get eth gas price with {}", e);
            return state;
        }
    };
    let wei_per_dollar = match bridge.dai_to_eth_price(eth_to_wei(1u8.into())).await {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get eth price with {}", e);
            return state;
        }
    };
    let wei_per_cent = wei_per_dollar.clone() / 100u32.into();
    let our_eth_balance = match bridge.eth_web3.eth_get_balance(bridge.own_address).await {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get eth balance {}", e);
            return state;
        }
    };
    let our_dai_balance = match bridge.get_dai_balance(bridge.own_address).await {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get dai balance {}", e);
            return state;
        }
    };
    // the amount of Eth to retain in WEI. This is the cost of our Uniswap exchange an ERC20 transfer
    // and one ETH transfer. To pay for Uniswap -> send to bridge and keep enough around for a withdraw
    // which involves a Uniswap exchange -> Eth send (since the ERC20 send is paid by the bridge)
    let reserve_amount = get_reserve_amount(eth_gas_price.clone());
    let minimum_to_exchange = reserve_amount.clone() * 2u32.into();
    set_last_amounts(
        lossy_u32(minimum_to_exchange.clone() / wei_per_cent.clone()),
        lossy_u32(reserve_amount.clone() / wei_per_cent.clone()),
    );
    // the minimum amount to transfer, this is in DAI wei, but we want it to be equal to the value
    // of two ERC20 transfers.
    let minimum_stranded_dai_transfer = minimum_to_exchange.clone();
    match state {
        State::Ready { .. } => {
            info!(
                "Ticking in bridge State::Ready. Eth Address: {}, Reserve amount: {}, Minimum to exchange: {}, Minimum DAI rescue: {}, Wei Per dollar: {}, Eth Gas Price: {}",
                bridge.own_address, reserve_amount, minimum_to_exchange, minimum_stranded_dai_transfer, wei_per_dollar, eth_gas_price
            );
            let res = rescue_dai(
                bridge.clone(),
                bridge.own_address,
                minimum_stranded_dai_transfer,
            )
            .await;
            if res.is_err() {
                warn!("Failed to rescue dai with {:?}", res);
            }
            trace!("rescued dai");
            // This means enough has been sent into our account to start the
            // deposit process.
            if our_eth_balance >= minimum_to_exchange {
                // Leave a reserve in the account to use for gas in the future
                let swap_amount = our_eth_balance - reserve_amount;

                detailed_state_change(DetailedBridgeState::EthToDai {
                    amount_of_eth: swap_amount.clone(),
                    wei_per_dollar,
                });

                info!("Converting to Dai");
                let dai_bought = match bridge.eth_to_dai_swap(swap_amount, UNISWAP_TIMEOUT).await {
                    Ok(val) => val,
                    Err(e) => {
                        warn!("Failed to swap dai with {:?}", e);
                        return State::Ready;
                    }
                };
                detailed_state_change(DetailedBridgeState::DaiToXdai {
                    amount: dai_bought.clone(),
                });
                // And over the bridge into xDai
                let _res = bridge
                    .dai_to_xdai_bridge(dai_bought, ETH_TRANSFER_TIMEOUT)
                    .await;
            } else {
                detailed_state_change(DetailedBridgeState::NoOp {
                    eth_balance: our_eth_balance,
                    wei_per_dollar,
                });
                // we don't have a lot of eth, we shouldn't do anything
            }
            State::Ready
        }
        State::WithdrawRequest {
            to,
            amount,
            timestamp,
            withdraw_all,
        } => match bridge
            .xdai_to_dai_bridge(amount.clone(), SETTING.get_payment().gas_price.clone())
            .await
        {
            Ok(bridge_tx_id) => {
                info!(
                    "We sent txid {:#066x} to the bridge with amount {}",
                    bridge_tx_id, amount
                );
                // Only change to Withdraw if there was no error
                detailed_state_change(DetailedBridgeState::XdaiToDai {
                    amount: amount.clone(),
                });
                State::Withdrawing {
                    unlock_details: None,
                    withdraw_xdai_txid: bridge_tx_id,
                    to,
                    amount,
                    timestamp: Instant::now(),
                    withdraw_all,
                    amount_actually_exchanged: None,
                }
            }
            Err(e) => {
                error!("Error in State::WithdrawRequest handler: {:?}", e);

                if withdraw_is_timed_out(timestamp) {
                    error!("Withdraw timed out!");
                    detailed_state_change(DetailedBridgeState::NoOp {
                        eth_balance: our_eth_balance,
                        wei_per_dollar,
                    });
                    State::Ready
                } else {
                    State::WithdrawRequest {
                        to,
                        amount,
                        timestamp,
                        withdraw_all,
                    }
                }
            }
        },
        State::Withdrawing {
            withdraw_xdai_txid,
            unlock_details,
            to,
            amount,
            timestamp,
            withdraw_all,
            amount_actually_exchanged,
        } => {
            info!("Ticking in bridge State:Withdrawing");
            // we can't get the match variable as a state withdrawing type
            // without some real tricks, so we just re-create it.
            let our_withdrawing_state = State::Withdrawing {
                withdraw_xdai_txid: withdraw_xdai_txid.clone(),
                unlock_details: unlock_details.clone(),
                to,
                amount: amount.clone(),
                timestamp,
                withdraw_all,
                amount_actually_exchanged: amount_actually_exchanged.clone(),
            };
            if withdraw_is_timed_out(timestamp) {
                error!("Withdraw timed out!");
                detailed_state_change(DetailedBridgeState::NoOp {
                    eth_balance: our_dai_balance,
                    wei_per_dollar,
                });
                State::Ready
            } else {
                info!(
                    "bridge withdraw state is {} dai {} eth {} wei per dollar {} amount {} withdraw_all {:?} amount_actually_exchanged",
                    our_dai_balance, our_eth_balance, wei_per_dollar, amount, withdraw_all, amount_actually_exchanged
                );

                // we wait here until the xdai validators have produced the signatures we need to unlock the funds
                // on the ethereum side
                if unlock_details.is_none() {
                    let res = bridge
                        .get_relay_message_hash(withdraw_xdai_txid.clone(), amount.clone())
                        .await;
                    if let Ok(info) = res {
                        return State::Withdrawing {
                            withdraw_xdai_txid: withdraw_xdai_txid.clone(),
                            unlock_details: Some(info),
                            to,
                            amount: amount.clone(),
                            timestamp,
                            withdraw_all,
                            amount_actually_exchanged: amount_actually_exchanged.clone(),
                        };
                    } else {
                        return our_withdrawing_state;
                    }

                // now that we have the details that we need we must create a transaction
                // to unlock the funds and send it off, we will sit here until we see the
                // funds causing at which point we will progress. The transition between
                // a high dai balance and having the eth balance we need is atomic (one block)
                // so this will progress properly once funds are unlocked.
                } else if our_dai_balance < amount
                    && !eth_balance_ready(
                        amount_actually_exchanged.clone(),
                        our_eth_balance.clone(),
                        amount.clone(),
                        wei_per_dollar.clone(),
                    )
                {
                    // can't panic because of the above if/else tree
                    let unlock_details = unlock_details.unwrap();
                    let _ = bridge
                        .submit_signatures_to_unlock_funds(unlock_details, UNISWAP_TIMEOUT)
                        .await;

                    return our_withdrawing_state;

                // this conversion is unique in that it's not lossy, when we withdraw
                // a given amount of xdai we will get exactly that many wei in dai back
                // into our balances, so we know for sure that this means the bridge has
                // come through
                } else if our_dai_balance >= amount {
                    detailed_state_change(DetailedBridgeState::DaiToEth {
                        amount_of_dai: amount.clone(),
                        wei_per_dollar,
                    });
                    // Then it converts to eth
                    match bridge
                        .dai_to_eth_swap(amount.clone(), UNISWAP_TIMEOUT)
                        .await
                    {
                        Ok(amount_actually_exchanged) => State::Withdrawing {
                            unlock_details,
                            withdraw_xdai_txid,
                            to,
                            amount: amount.clone(),
                            timestamp,
                            withdraw_all,
                            amount_actually_exchanged: Some(amount_actually_exchanged),
                        },
                        Err(e) => {
                            error!("Failed to perform dai_to_eth_swap {:?}", e);
                            our_withdrawing_state
                        }
                    }

                // do not touch this without understanding the comment on eth_balance_ready()
                } else if eth_balance_ready(
                    amount_actually_exchanged,
                    our_eth_balance.clone(),
                    amount.clone(),
                    wei_per_dollar.clone(),
                ) {
                    info!("Converted dai back to eth!");
                    let eth_gas_price = eth_gas_price * 2u32.into();
                    let withdraw_amount = if withdraw_all {
                        // if we're withdrawing everything don't leave any amount behind
                        let gas_price = eth_gas_price.clone();
                        let tx_cost = gas_price * ETH_TRANSACTION_GAS_LIMIT.into();
                        our_eth_balance - tx_cost
                    } else {
                        // if we're not cleaning out this wallet leave enough behind for future
                        // deposits and withdraws
                        our_eth_balance - get_withdraw_reserve_amount(eth_gas_price.clone())
                    };

                    detailed_state_change(DetailedBridgeState::EthToDest {
                        amount_of_eth: withdraw_amount.clone(),
                        wei_per_dollar,
                        dest_address: to,
                    });

                    // we must pass arguments here because the send_transaction function in web30
                    // won't modify the transaction amount. It will only reduce the gas price in
                    // order to ensure that a transaction is potentially valid. We can modify the send
                    // amount at this level and therefore we must compute the gas price. We also pass
                    // in the tx gas limit to ensure that we're computing on the same numbers.
                    let res = bridge
                        .eth_transfer(
                            to,
                            withdraw_amount,
                            ETH_TRANSFER_TIMEOUT,
                            vec![
                                SendTxOption::GasPrice(eth_gas_price),
                                SendTxOption::GasLimit(ETH_TRANSACTION_GAS_LIMIT.into()),
                            ],
                        )
                        .await;
                    if res.is_ok() {
                        info!("Issued an eth transfer for withdraw! Now complete!");
                        // we only exit the withdraw state on success or timeout
                        State::Ready
                    } else {
                        our_withdrawing_state
                    }
                } else {
                    info!("withdraw is waiting on bridge");
                    detailed_state_change(DetailedBridgeState::XdaiToDai { amount });
                    our_withdrawing_state
                }
            }
        }
    }
}

/// Determining if we have the correct amount of money in ETH is actually quite difficult. For the XDAI->DAI
/// exchange it's easy, we have exactly the amount of DAI we sent over. Xdai transactions are reliable enough
/// that we can assume that it will either succeed or fail. Here we have to dig deep into thinking about ways
/// eth_to_dai swap may fail. We may see the function return an error but the exchange actually goes through
/// in that case we have Some(amount_actually_exchanged) but at a different exchange rate. Or it goes through
/// and we have None but our exchange has gone through. In either case we provide 10% padding for exchange rate
/// fluctuations, which as far as I'm aware is an order of magnitude larger than any DAI off-peg we've ever seen
fn eth_balance_ready(
    amount_actually_exchanged: Option<Uint256>,
    our_eth_balance: Uint256,
    dai_amount: Uint256,
    wei_per_dollar: Uint256,
) -> bool {
    // padding is equal to 1/PADDING interpreted as a percent
    // so 1/10 is 10%
    const PADDING: u32 = 10;
    if let Some(amount_actually_exchanged) = amount_actually_exchanged {
        let padding = amount_actually_exchanged.clone() / PADDING.into();
        let threshold = amount_actually_exchanged - padding;
        info!("our_eth_balance {} >= {}", our_eth_balance, threshold);
        our_eth_balance >= threshold
    } else {
        let padding = dai_amount.clone() / PADDING.into();
        let threshold = dai_amount - padding;
        info!(
            "our_eth_balance {} / {} wei_per_dollar >= {}",
            our_eth_balance, wei_per_dollar, threshold
        );
        (our_eth_balance / wei_per_dollar) * WEI_PER_ETH.into() >= threshold
    }
}

/// Withdraw state struct for the bridge, if withdraw_all is true, the eth will be
/// cleaned up on the way out as well
pub struct Withdraw {
    pub to: Address,
    pub amount: Uint256,
    pub withdraw_all: bool,
}

pub fn withdraw(msg: Withdraw) -> Result<(), Error> {
    let payment_settings = SETTING.get_payment();
    let system_chain = payment_settings.system_chain;
    drop(payment_settings);
    let bridge = BRIDGE.read().unwrap().clone();

    let to = msg.to;
    let amount = msg.amount.clone();
    let withdraw_all = msg.withdraw_all;

    info!(
        "bridge withdraw handler amount {} withdraw_all {}",
        amount, withdraw_all
    );

    if let SystemChain::Xdai = system_chain {
        match bridge.state {
            State::Withdrawing { .. } | State::WithdrawRequest { .. } => {
                // Cannot start a withdraw when one is in progress
                bail!("Cannot start a withdraw when one is in progress")
            }
            _ => {
                state_change(State::WithdrawRequest {
                    to,
                    amount: amount.clone(),
                    timestamp: Instant::now(),
                    withdraw_all,
                });
                detailed_state_change(DetailedBridgeState::XdaiToDai { amount });
                Ok(())
            }
        }
    } else {
        bail!("Not on Xdai chain!");
    }
}

fn state_change(msg: State) {
    trace!("Changing state to {}", msg);
    let new_state = msg;
    let mut bridge = BRIDGE.write().unwrap();
    trace!("Got bridge write lock");
    bridge.state = new_state;
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
    /// The final eth transfer as part of a withdraw
    EthToDest {
        amount_of_eth: Uint256,
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
    let payment_settings = SETTING.get_payment();
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
    let payment_settings = SETTING.get_payment();
    token_bridge_core_from_settings(&payment_settings)
}

/// the amount of Eth to retain in WEI. This is the cost of our Uniswap exchange an ERC20 transfer
/// and one ETH transfer. To pay for Uniswap -> send to bridge and keep enough around for a withdraw
/// which involves a Uniswap exchange -> Eth send (since the ERC20 send is paid by the bridge)
/// this ensures that a withdraw is always possible. Currently we have reduced this to only ensure
/// that the deposit goes through. Because reserving enough funds is too expensive.
fn get_reserve_amount(eth_gas_price: Uint256) -> Uint256 {
    // eth_gas_price * (ERC20_GAS_LIMIT + (UNISWAP_GAS_LIMIT * 2) + ETH_TRANSACTION_GAS_LIMIT).into()
    eth_gas_price * (ERC20_GAS_LIMIT + UNISWAP_GAS_LIMIT).into()
}
/// the amount of Eth to retain in WEI. This time for withdraws such that we always leave enough
/// to pay for the next withdraw
fn get_withdraw_reserve_amount(eth_gas_price: Uint256) -> Uint256 {
    eth_gas_price * (UNISWAP_GAS_LIMIT + ETH_TRANSACTION_GAS_LIMIT).into()
}

fn lossy_u32(input: Uint256) -> u32 {
    match input.to_string().parse() {
        Ok(val) => val,
        // the only possible error the number being too large, both are unsigned. String formatting
        // won't change etc.
        Err(_e) => u32::MAX,
    }
}
