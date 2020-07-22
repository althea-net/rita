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
//!         Change to State::Depositing.
//!
//!         If there is an `eth_balance` that is greater than the `minimum_to_exchange` amount,
//!         subtract the `reserve` amount and send it through uniswap into DAI. If not Change to State::Ready
//!         Future waits on Uniswap, and upon successful swap, sends dai thru the bridge into xdai.
//!         When the money is out of the Dai account and in the bridge, or if uniswap times out, change
//!         to State::Ready.
//!
//!     State::Depositing:
//!         do nothing
//!
//!     State::Withdrawing { to, amount, timestamp}:
//!         If the timestamp is expired, switch the state back into State::Ready.
//!
//!         If there is a dai balance greater or equal to the withdraw amount, send the withdraw
//!         amount through uniswap.
//!
//!         Future waits on Uniswap and upon successful swap, sends eth to "to" address. Another future
//!         waits on this transfer to complete. When it is complete, the state switches back to State::Ready
//!
//! WithdrawEvent:
//!     State::Ready:
//!         Send amount into bridge, switch to State::Withdrawing.
//!
//!     State::Withdrawing { to, amount, timestamp}:
//!         Nothing happens

use crate::SETTING;
use althea_types::SystemChain;
use auto_bridge::TokenBridge as TokenBridgeCore;
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
}

const BRIDGE_TIMEOUT: Duration = Duration::from_secs(3600);
pub const ETH_TRANSFER_TIMEOUT: u64 = 600u64;
const UNISWAP_TIMEOUT: u64 = ETH_TRANSFER_TIMEOUT;
/// 1c in of dai in wei
pub const DAI_WEI_CENT: u128 = 10_000_000_000_000_000u128;

fn is_timed_out(started: Instant) -> bool {
    Instant::now() - started > BRIDGE_TIMEOUT
}

pub fn eth_to_wei(eth: u64) -> Uint256 {
    let wei = (eth * 1_000_000_000_000_000_000_u64) as u64;
    wei.into()
}

fn wei_dai_to_dai_cents(dai_wei: Uint256) -> Uint256 {
    dai_wei / DAI_WEI_CENT.into()
}

/// Provided an amount in DAI (wei dai so 1*10^18 per dollar) returns the equal amount in wei (or ETH if divided by 1*10^18)
pub fn eth_equal(dai_in_wei: Uint256, wei_per_cent: Uint256) -> Uint256 {
    wei_dai_to_dai_cents(dai_in_wei) * wei_per_cent
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum State {
    Ready {
        /// used to ensure that only the future chain that started an operation can end it
        former_state: Option<Box<State>>,
    },
    Depositing {
        timestamp: Instant,
    },
    WithdrawRequest {
        amount: Uint256,
        to: Address,
        timestamp: Instant,
        withdraw_all: bool,
    },
    Withdrawing {
        amount: Uint256,
        to: Address,
        timestamp: Instant,
        withdraw_all: bool,
    },
}

impl Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Ready {
                former_state: Some(_),
            } => write!(f, "Ready{{Some()}}"),
            State::Ready { former_state: None } => write!(f, "Ready{{None}}"),
            State::Depositing { .. } => write!(f, "Depositing"),
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
                amount: a,
                to: t,
                timestamp: ti,
                withdraw_all: w,
            } => write!(
                f,
                "Withdrawing:{{amount: {}, to: {}, timestamp: {:?}, withdraw_all: {}}}",
                a, t, ti, w
            ),
        }
    }
}

/// This struct contains the state of the bridge. TokenBridgeAmounts contains the
/// amounts we commonly reference for the operation in this file and TokenBridgeCore
/// contains details fo the various inner workings of the actual contract and bridge calls
/// rather than the logic. This struct was previously combined with TokenBridgeAmounts but
/// we want to reload the amounts regularly without interfering with the state.
pub struct TokenBridgeState {
    state: State,
    detailed_state: DetailedBridgeState,
}

pub struct TokenBridgeAmounts {
    // How much eth (denominated in dai) we are keeping in our Eth wallet
    // in order to pay for the fees of future actions we may be required to take to deposit or
    // withdraw.
    reserve_amount: u32,
    // The minimum amount of eth (denominated in dai) that can be exchanged without
    // fees becoming unreasonable.
    minimum_to_exchange: u32,
    // The minimum amount of dai to initiate a transfer to the bridge if we find it in our dai wallet
    // when no withdraw is in progress.
    minimum_stranded_dai_transfer: u32,
}

pub async fn tick() {
    let bridge = BRIDGE.read().unwrap();
    let amounts = { get_amounts() };
    assert!(amounts.minimum_to_exchange > amounts.reserve_amount);
    let payment_settings = SETTING.get_payment();
    let system_chain = payment_settings.system_chain;

    if !payment_settings.bridge_enabled {
        return;
    }
    drop(payment_settings);

    match system_chain {
        SystemChain::Xdai => xdai_bridge(bridge.state.clone(), &bridge).await,
        SystemChain::Ethereum => eth_bridge(&bridge).await,
        SystemChain::Rinkeby => {}
    }
}

fn token_bridge_core_from_settings(payment_settings: &PaymentSettings) -> TokenBridgeCore {
    let addresses = payment_settings.bridge_addresses.clone();
    TokenBridgeCore::new(
        addresses.uniswap_address,
        addresses.xdai_foreign_bridge_address,
        addresses.xdai_home_bridge_address,
        addresses.foreign_dai_contract_address,
        payment_settings.eth_address.unwrap(),
        payment_settings.eth_private_key.unwrap(),
        addresses.eth_full_node_url,
        addresses.xdai_full_node_url,
    )
}

impl Default for TokenBridgeState {
    fn default() -> TokenBridgeState {
        TokenBridgeState {
            state: State::Ready { former_state: None },
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
    minimum_stranded_dai_transfer: u32,
) -> Result<(), Error> {
    let dai_balance = bridge.get_dai_balance(our_address).await?;
    info!("Our DAI balance is {}", dai_balance);
    if dai_balance > eth_to_wei(minimum_stranded_dai_transfer.into()) {
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
async fn eth_bridge(bridge: &TokenBridgeState) {
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
        bridge.xdai_to_dai_bridge(amount.clone()).await;
        detailed_state_change(DetailedBridgeState::XdaiToDai { amount });
    } else if our_dai_balance > 0u32.into() {
        // Then it converts to eth
        detailed_state_change(DetailedBridgeState::DaiToEth {
            amount_of_dai: our_dai_balance.clone(),
            wei_per_dollar,
        });
        bridge
            .dai_to_eth_swap(our_dai_balance, UNISWAP_TIMEOUT)
            .await;
    // all other steps are done and the eth is sitting and waiting
    } else {
        detailed_state_change(DetailedBridgeState::NoOp {
            eth_balance: our_eth_balance,
            wei_per_dollar,
        });
    }
}

/// The logic for the Eth -> Xdai bridge operation
async fn xdai_bridge(state: State, bridge: &TokenBridgeState) {
    let amounts = { get_amounts() };
    let minimum_stranded_dai_transfer = amounts.minimum_stranded_dai_transfer;
    let reserve_amount = amounts.reserve_amount;
    let minimum_to_exchange = amounts.minimum_to_exchange;
    let bridge = get_core();
    match state {
        State::Ready { .. } => {
            info!(
                "Ticking in bridge State::Ready. Eth Address: {}",
                bridge.own_address
            );
            // Go into State::Depositing right away to prevent multiple attempts
            let state = State::Depositing {
                timestamp: Instant::now(),
            };
            state_change(state.clone());
            rescue_dai(
                bridge.clone(),
                bridge.own_address,
                minimum_stranded_dai_transfer,
            )
            .await;
            trace!("rescued dai");
            let wei_per_dollar = match bridge.dai_to_eth_price(eth_to_wei(1u8.into())).await {
                Ok(val) => val,
                Err(e) => {
                    warn!("Failed to get eth price with {:?}", e);
                    state_change(State::Ready {
                        former_state: Some(Box::new(state)),
                    });
                    return;
                }
            };
            let eth_balance = match bridge.eth_web3.eth_get_balance(bridge.own_address).await {
                Ok(val) => val,
                Err(e) => {
                    warn!("Failed to get eth balance {:?}", e);
                    state_change(State::Ready {
                        former_state: Some(Box::new(state)),
                    });
                    return;
                }
            };
            // These statements convert the reserve_amount and minimum_to_exchange
            // into eth using the current price (units of wei)
            let reserve = wei_per_dollar.clone() * reserve_amount.into();
            let minimum_to_exchange = wei_per_dollar.clone() * minimum_to_exchange.into();

            // This means enough has been sent into our account to start the
            // deposit process.
            if eth_balance >= minimum_to_exchange {
                // Leave a reserve in the account to use for gas in the future
                let swap_amount = eth_balance - reserve;

                detailed_state_change(DetailedBridgeState::EthToDai {
                    amount_of_eth: swap_amount.clone(),
                    wei_per_dollar,
                });

                info!("Converting to Dai");
                let dai_bought = match bridge.eth_to_dai_swap(swap_amount, UNISWAP_TIMEOUT).await {
                    Ok(val) => val,
                    Err(e) => {
                        warn!("Failed to swap dai with {:?}", e);
                        state_change(State::Ready {
                            former_state: Some(Box::new(state)),
                        });
                        return;
                    }
                };
                detailed_state_change(DetailedBridgeState::DaiToXdai {
                    amount: dai_bought.clone(),
                });
                // And over the bridge into xDai
                bridge
                    .dai_to_xdai_bridge(dai_bought, ETH_TRANSFER_TIMEOUT)
                    .await;
            } else {
                detailed_state_change(DetailedBridgeState::NoOp {
                    eth_balance,
                    wei_per_dollar,
                });
                // we don't have a lot of eth, we shouldn't do anything
            }
            // It goes back into State::Ready once the dai
            // is in the bridge or if failed. This prevents multiple simultaneous
            // attempts to bridge the same Dai.
            state_change(State::Ready {
                former_state: Some(Box::new(state)),
            });
        }
        State::Depositing { timestamp } => {
            info!("Tried to tick in bridge State::Depositing");
            // if the do_send at the end of state depositing fails we can get stuck here
            // at the time time we don't want to submit multiple eth transactions for each
            // step above, especially if they take a long time (note the timeouts are in the 10's of minutes)
            // so we often 'tick' in depositing because there's a background future we don't want to interrupt
            // if that future fails it's state change do_send a few lines up from here we're screwed and the bridge
            // forever sits in this no-op state. This is a rescue setup for that situation where we check that enough
            // time has elapsed. The theoretical max here is the uniswap timeout plus the eth transfer timeout
            let now = Instant::now();
            if now
                > timestamp
                    + Duration::from_secs(UNISWAP_TIMEOUT)
                    + Duration::from_secs(ETH_TRANSFER_TIMEOUT)
            {
                warn!("Rescued stuck bridge");
                state_change(State::Ready {
                    former_state: Some(Box::new(State::Depositing { timestamp })),
                });
            }
        }
        State::WithdrawRequest {
            to,
            amount,
            timestamp,
            withdraw_all,
        } => match bridge.xdai_to_dai_bridge(amount.clone()).await {
            Ok(res) => {
                // Only change to Withdraw if there was no error
                detailed_state_change(DetailedBridgeState::XdaiToDai {
                    amount: amount.clone(),
                });
                state_change(State::Withdrawing {
                    to,
                    amount,
                    timestamp: Instant::now(),
                    withdraw_all,
                });
            }
            Err(e) => {
                error!("Error in State::Deposit WithdrawRequest handler: {:?}", e);
                state_change(State::Ready { former_state: None });
            }
        },
        State::Withdrawing {
            to,
            amount,
            timestamp,
            withdraw_all,
        } => {
            info!("Ticking in bridge State:Withdrawing");
            if is_timed_out(timestamp) {
                error!("Withdraw timed out!");
                detailed_state_change(DetailedBridgeState::NoOp {
                    eth_balance: Uint256::zero(),
                    wei_per_dollar: Uint256::zero(),
                });
                state_change(State::Ready {
                    former_state: Some(Box::new(State::Withdrawing {
                        to,
                        amount,
                        timestamp,
                        withdraw_all,
                    })),
                });
            } else {
                let our_dai_balance = match bridge.get_dai_balance(bridge.own_address).await {
                    Ok(val) => val,
                    Err(_e) => return,
                };
                let our_eth_balance =
                    match bridge.eth_web3.eth_get_balance(bridge.own_address).await {
                        Ok(val) => val,
                        Err(_e) => return,
                    };
                let wei_per_dollar = match bridge.dai_to_eth_price(eth_to_wei(1u8.into())).await {
                    Ok(val) => val,
                    Err(_e) => return,
                };
                // todo why don't we compute this from the above? be careful if you're attempting this, the conversion
                // is fraught with ways to screw it up. Pull out the many units tricks from your physics class
                let wei_per_cent = match bridge.dai_to_eth_price(DAI_WEI_CENT.into()).await {
                    Ok(val) => val,
                    Err(_e) => return,
                };
                let eth_gas_price = match bridge.eth_web3.eth_gas_price().await {
                    Ok(val) => val,
                    Err(_e) => return,
                };

                info!(
                    "bridge withdraw state is {} dai {} eth {} wei per dollar",
                    our_dai_balance, our_eth_balance, wei_per_dollar
                );
                let transferred_eth = eth_equal(amount.clone(), wei_per_cent);

                // the amount we must leave behind to continue to pay for eth operations
                let reserve = wei_per_dollar.clone() * reserve_amount.into();
                // the reserve value with some margin, to deal with exchange rate fluctuations
                let reserve_with_margin = reserve.clone() * 10u32.into();

                // this code handles the case where you are withdrawing a large amount and
                // the exchange rate meaningfully goes down during your exchange and withdraw.
                // What occurs in this case is that your new eth balance is now no longer as much
                // as your withdraw amount. For small withdraws you A) don't move the price much
                // and B) the reserve amount can make up small shortfalls. For large withdraws you
                // may lose something like 1/2 dollars out of $500+ but then the eth would sit around
                // not enough to finish the withdraw. So what we do instead is withdraw what we can
                // over the reserve amount. If the balance is less than $10 (10x the current reserve)
                // then we can be pretty sure it at least wasn't us that moved the price that much
                let transferred_eth = if our_eth_balance < transferred_eth
                    && our_eth_balance.clone() / wei_per_dollar.clone() > reserve_with_margin
                {
                    if withdraw_all {
                        our_eth_balance.clone()
                    } else {
                        our_eth_balance.clone() - reserve
                    }
                } else {
                    transferred_eth
                };

                // Money has come over the bridge
                if our_dai_balance >= amount {
                    detailed_state_change(DetailedBridgeState::DaiToEth {
                        amount_of_dai: amount.clone(),
                        wei_per_dollar,
                    });
                    // Then it converts to eth
                    let _amount_actually_exchanged =
                        bridge.dai_to_eth_swap(amount, UNISWAP_TIMEOUT);
                // all other steps are done and the eth is sitting and waiting
                } else if our_eth_balance >= transferred_eth {
                    info!("Converted dai back to eth!");
                    let withdraw_amount = if withdraw_all {
                        // this only works because the gas price is hardcoded in auto_bridge
                        // that should be fixed someday and this should use dynamic gas
                        let gas_price = eth_gas_price;
                        let tx_gas: Uint256 = 21_000u32.into();
                        let tx_cost = gas_price * tx_gas;
                        our_eth_balance - tx_cost
                    } else {
                        transferred_eth
                    };

                    detailed_state_change(DetailedBridgeState::EthToDest {
                        amount_of_eth: withdraw_amount.clone(),
                        wei_per_dollar,
                        dest_address: to,
                    });

                    let res = bridge
                        .eth_transfer(to, withdraw_amount, ETH_TRANSFER_TIMEOUT)
                        .await;
                    if res.is_ok() {
                        info!("Issued an eth transfer for withdraw! Now complete!");
                        // we only exit the withdraw state on success or timeout
                        state_change(State::Ready {
                            former_state: Some(Box::new(State::Withdrawing {
                                to,
                                amount,
                                timestamp,
                                withdraw_all,
                            })),
                        });
                    }
                } else {
                    info!("withdraw is waiting on bridge");
                    detailed_state_change(DetailedBridgeState::XdaiToDai { amount });
                }
            }
        }
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
    let bridge = BRIDGE.read().unwrap();

    let to = msg.to;
    let amount = msg.amount.clone();
    let withdraw_all = msg.withdraw_all;

    info!(
        "bridge withdraw handler amount {} withdraw_all {}",
        amount, withdraw_all
    );

    if let SystemChain::Xdai = system_chain {
        match bridge.state.clone() {
            State::Withdrawing { .. } => {
                // Cannot start a withdraw when one is in progress
                bail!("Cannot start a withdraw when one is in progress")
            }
            _ => {
                state_change(State::WithdrawRequest {
                    to,
                    amount,
                    timestamp: Instant::now(),
                    withdraw_all,
                });
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
    // since multiple futures from this system may be in flight at once we face a race
    // condition, the solution we have used is to put some state into the ready message
    // the ready message contains the state that it expects to find the system in before
    // it becomes ready again. If for example the state is depositing and it sees a message
    // ready(depositing) we know it's the right state change. If we are in withdraw and we
    // see ready(depositing) we know that it's a stray in flight future that's trying to
    // modify the state machine incorrectly
    // TODO this may not be needed after async refactor
    if let State::Ready {
        former_state: Some(f),
    } = new_state.clone()
    {
        trace!("checking if we should change the state");
        if bridge.state != *f {
            trace!("{} != {}", bridge.state, *f);
            return;
        }
    }
    bridge.state = new_state;
}

fn detailed_state_change(msg: DetailedBridgeState) {
    trace!("Changing detailed state to {:?}", msg);
    let mut bridge = BRIDGE.write().unwrap();
    let new_state = msg;
    bridge.detailed_state = new_state;
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
    let amounts = get_amounts();
    let bridge = BRIDGE.read().unwrap();
    BridgeStatus {
        reserve_amount: amounts.reserve_amount,
        minimum_deposit: amounts.minimum_to_exchange,
        withdraw_chain,
        state: bridge.detailed_state.clone(),
    }
}

/// Grab state parameters from settings
fn get_core() -> TokenBridgeCore {
    let payment_settings = SETTING.get_payment();
    token_bridge_core_from_settings(&payment_settings)
}

fn get_amounts() -> TokenBridgeAmounts {
    let mut payment_settings = SETTING.get_payment();
    let minimum_to_exchange = match payment_settings.bridge_addresses.minimum_to_exchange {
        Some(val) => val,
        None => {
            payment_settings.bridge_addresses.minimum_to_exchange = Some(4);
            4
        }
    };
    let reserve_amount = match payment_settings.bridge_addresses.reserve_amount {
        Some(val) => val,
        None => {
            payment_settings.bridge_addresses.reserve_amount = Some(2);
            2
        }
    };
    TokenBridgeAmounts {
        minimum_to_exchange,
        reserve_amount,
        minimum_stranded_dai_transfer: 1,
    }
}
