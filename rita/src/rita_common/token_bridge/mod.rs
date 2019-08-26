//! This module is designed to allow easy deposits for some supported chains using Ethereum. The idea
//! is pretty simple, the user deposits money into their routers Ethereum address, this is then exchanged
//! through uniswap into DAI and then from there it is bridged over to the Xdai proof of authority chains.
//! Support for Cosmos chains using a DAI-pegged native currency is next on the list.
//!
//! Essentially the goal is to allow uers to deposit a popular and easy to aquire coin like Ethereum and then
//! actually transact in a stablecoin on a fast blockchain, eg not Ethereum. Withdraws are also transparently
//! converted back to Ethereum to allow easy exchange by the user.
//!
//! This entire module works on the premise we call the conveyor belt model. It's difficult to track
//! money through this entire process exactly, in fact there are some edge cases where it's simply not
//! possible to reliably say if a task has completed or not. With that in mind we simply always progress
//! the the process for Eth -> DAI -> XDAI unless we explicilty have a withdraw in progress. So if we find
//! some DAI in our address it will always be converted to XDAI even if we didn't convert that DAI from Eth
//! in the first place.
//!
//! For the withdraw process we create a withdraw request object which does a best effort sheparding of the
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
use actix::Actor;
use actix::Arbiter;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Supervised;
use actix::SystemService;
use althea_types::SystemChain;
use auto_bridge::TokenBridge as TokenBridgeCore;
use clarity::Address;
use failure::Error;
use futures::future;
use futures::future::Future;
use num256::Uint256;
use num_traits::identities::Zero;
use settings::RitaCommonSettings;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

const BRIDGE_TIMEOUT: Duration = Duration::from_secs(3600);
const UNISWAP_TIMEOUT: u64 = 600u64;
pub const ETH_TRANSFER_TIMEOUT: u64 = 600u64;
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
    Depositing {},
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

pub struct TokenBridge {
    bridge: TokenBridgeCore,
    state: State,
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
    detailed_state: DetailedBridgeState,
}

impl Actor for TokenBridge {
    type Context = Context<Self>;
}

impl Supervised for TokenBridge {}
impl SystemService for TokenBridge {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("TokenBridge started");
        assert!(self.minimum_to_exchange > self.reserve_amount);
    }
}

impl Default for TokenBridge {
    fn default() -> TokenBridge {
        TokenBridge {
            bridge: TokenBridgeCore::new(
                Address::from_str("0x09cabEC1eAd1c0Ba254B09efb3EE13841712bE14").unwrap(),
                Address::from_str("0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6").unwrap(),
                Address::from_str("0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016").unwrap(),
                Address::from_str("0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359").unwrap(),
                SETTING.get_payment().eth_address.unwrap(),
                SETTING.get_payment().eth_private_key.unwrap(),
                "https://eth.althea.org".into(),
                "https://dai.althea.net".into(),
            ),
            state: State::Ready { former_state: None },
            minimum_to_exchange: 2,
            reserve_amount: 1,
            minimum_stranded_dai_transfer: 1,
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
fn rescue_dai(
    bridge: TokenBridgeCore,
    our_address: Address,
    minimum_stranded_dai_transfer: u32,
) -> Box<dyn Future<Item = (), Error = Error>> {
    Box::new(bridge.get_dai_balance(our_address).and_then({
        move |dai_balance| {
            trace!("Our DAI balance is {}", dai_balance);
            if dai_balance > eth_to_wei(minimum_stranded_dai_transfer.into()) {
                trace!("rescuing dais");
                TokenBridge::from_registry().do_send(DetailedStateChange(
                    DetailedBridgeState::DaiToXdai {
                        amount: dai_balance.clone(),
                    },
                ));
                // Over the bridge into xDai
                Box::new(
                    bridge
                        .dai_to_xdai_bridge(dai_balance, ETH_TRANSFER_TIMEOUT)
                        .and_then(|_res| Ok(())),
                )
            } else {
                // we don't have a lot of dai, we shouldn't do anything
                Box::new(future::ok(())) as Box<dyn Future<Item = (), Error = Error>>
            }
        }
    }))
}

#[derive(Message)]
pub struct Tick();

impl Handler<Tick> for TokenBridge {
    type Result = ();

    fn handle(&mut self, _msg: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let payment_settings = SETTING.get_payment();
        let our_address = payment_settings.eth_address.unwrap();
        let system_chain = payment_settings.system_chain;

        if !payment_settings.bridge_enabled {
            return;
        }
        drop(payment_settings);

        let bridge = self.bridge.clone();
        let reserve_amount = self.reserve_amount;
        let minimum_to_exchange = self.minimum_to_exchange;
        let minimum_stranded_dai_transfer = self.minimum_stranded_dai_transfer;

        if let SystemChain::Xdai = system_chain {
            match self.state.clone() {
                State::Ready { .. } => {
                    trace!(
                        "Ticking in State::Ready. Eth Address: {}",
                        bridge.own_address
                    );
                    // Go into State::Depositing right away to prevent multiple attempts
                    TokenBridge::from_registry().do_send(StateChange(State::Depositing {}));
                    Arbiter::spawn(
                        rescue_dai(bridge.clone(), our_address, minimum_stranded_dai_transfer)
                            .and_then(move |_| {
                                trace!("rescued dai");
                                bridge
                                    .dai_to_eth_price(eth_to_wei(1u8.into()))
                                    .join(bridge.eth_web3.eth_get_balance(our_address))
                                    .and_then(move |(wei_per_dollar, eth_balance)| {
                                        // These statements convert the reserve_amount and minimum_to_exchange
                                        // into eth using the current price (units of wei)
                                        let reserve =
                                            wei_per_dollar.clone() * reserve_amount.into();
                                        let minimum_to_exchange =
                                            wei_per_dollar.clone() * minimum_to_exchange.into();

                                        // This means enough has been sent into our account to start the
                                        // deposit process.
                                        if eth_balance >= minimum_to_exchange {
                                            // Leave a reserve in the account to use for gas in the future
                                            let swap_amount = eth_balance - reserve;

                                            TokenBridge::from_registry().do_send(
                                                DetailedStateChange(
                                                    DetailedBridgeState::EthToDai {
                                                        amount_of_eth: swap_amount.clone(),
                                                        wei_per_dollar: wei_per_dollar.clone(),
                                                    },
                                                ),
                                            );

                                            trace!("Converting to Dai");
                                            Box::new(
                                                bridge
                                                    // Convert to Dai in Uniswap
                                                    .eth_to_dai_swap(
                                                        swap_amount,
                                                        ETH_TRANSFER_TIMEOUT,
                                                    )
                                                    .and_then(move |dai_bought| {
                                                        TokenBridge::from_registry().do_send(
                                                            DetailedStateChange(
                                                                DetailedBridgeState::DaiToXdai {
                                                                    amount: dai_bought.clone(),
                                                                },
                                                            ),
                                                        );
                                                        // And over the bridge into xDai
                                                        bridge.dai_to_xdai_bridge(
                                                            dai_bought,
                                                            ETH_TRANSFER_TIMEOUT,
                                                        )
                                                    })
                                                    .and_then(|_| Ok(())),
                                            )
                                                as Box<dyn Future<Item = (), Error = Error>>
                                        } else {
                                            TokenBridge::from_registry().do_send(
                                                DetailedStateChange(DetailedBridgeState::NoOp {
                                                    eth_balance,
                                                    wei_per_dollar,
                                                }),
                                            );
                                            // we don't have a lot of eth, we shouldn't do anything
                                            Box::new(future::ok(()))
                                                as Box<dyn Future<Item = (), Error = Error>>
                                        }
                                    })
                            })
                            .then(|res| {
                                // It goes back into State::Ready once the dai
                                // is in the bridge or if failed. This prevents multiple simultaneous
                                // attempts to bridge the same Dai.

                                if res.is_err() {
                                    error!("Error in State::Deposit Tick handler: {:?}", res);
                                }
                                TokenBridge::from_registry().do_send(StateChange(State::Ready {
                                    former_state: Some(Box::new(State::Depositing {})),
                                }));
                                Ok(())
                            }),
                    )
                }
                State::Depositing {} => trace!("Tried to tick in State::Depositing"),
                State::Withdrawing {
                    to,
                    amount,
                    timestamp,
                    withdraw_all,
                } => {
                    if is_timed_out(timestamp) {
                        error!("Withdraw timed out!");
                        TokenBridge::from_registry().do_send(DetailedStateChange(
                            DetailedBridgeState::NoOp {
                                eth_balance: Uint256::zero(),
                                wei_per_dollar: Uint256::zero(),
                            },
                        ));
                        TokenBridge::from_registry().do_send(StateChange(State::Ready {
                            former_state: Some(Box::new(State::Withdrawing {
                                to,
                                amount,
                                timestamp,
                                withdraw_all,
                            })),
                        }));
                    } else {
                        let amount_a = amount.clone();
                        Arbiter::spawn(
                            bridge
                                .get_dai_balance(our_address)
                                .join5(bridge.eth_web3.eth_get_balance(our_address),
                                bridge.dai_to_eth_price(eth_to_wei(1u8.into())),
                                bridge.dai_to_eth_price(DAI_WEI_CENT.into()),
                                bridge.eth_web3.eth_gas_price())
                                .and_then(move |(our_dai_balance, our_eth_balance, wei_per_dollar, wei_per_cent, eth_gas_price)| {
                                    trace!("withdraw state is {} dai {} eth {} wei per dollar", our_dai_balance, our_eth_balance, wei_per_dollar);
                                    let transferred_eth = eth_equal(amount_a.clone(), wei_per_cent);
                                    // Money has come over the bridge
                                    if our_dai_balance >= amount {
                                        TokenBridge::from_registry().do_send(DetailedStateChange(DetailedBridgeState::DaiToEth{
                                            amount_of_dai: amount_a.clone(),
                                            wei_per_dollar: wei_per_dollar.clone()
                                        }));
                                        Box::new(
                                            bridge
                                                // Then it converts to eth
                                                .dai_to_eth_swap(amount, UNISWAP_TIMEOUT).and_then(|_| Ok(()))
                                        )
                                            as Box<dyn Future<Item = (), Error = Error>>
                                    // all other steps are done and the eth is sitting and waiting
                                    } else if our_eth_balance >= transferred_eth {
                                        trace!("Converted dai back to eth!");
                                        let withdraw_amount = if withdraw_all {
                                            // this only works because the gas price is hardcoded in auto_bridge
                                            // that should be fixed someday and this should use dynamic gas
                                            let gas_price = eth_gas_price;
                                            let tx_gas: Uint256 = 21_000u32.into();
                                            let tx_cost = gas_price * tx_gas;
                                            our_eth_balance.clone() - tx_cost
                                            } else { transferred_eth };

                                        TokenBridge::from_registry().do_send(DetailedStateChange(DetailedBridgeState::EthToDest{
                                            amount_of_eth: withdraw_amount.clone(),
                                            wei_per_dollar: wei_per_dollar.clone(),
                                            dest_address: to
                                        }));
                                        Box::new(bridge.eth_transfer(
                                            to,
                                            withdraw_amount,
                                            ETH_TRANSFER_TIMEOUT,
                                        )
                                        .and_then(move |_| {
                                            trace!("Issued an eth transfer for withdraw! Now complete!");
                                            // we only exit the withdraw state on success or timeout
                                            TokenBridge::from_registry().do_send(StateChange(State::Ready {former_state: Some(Box::new(State::Withdrawing{to, amount: amount_a, timestamp, withdraw_all}))}));
                                            Ok(())}))
                                    } else {
                                        info!("withdraw is waiting on bridge");
                                        TokenBridge::from_registry().do_send(DetailedStateChange(DetailedBridgeState::XdaiToDai{amount}));
                                        Box::new(futures::future::ok(()))
                                            as Box<dyn Future<Item = (), Error = Error>>
                                    }
                                })
                                .then(|res| {
                                    if res.is_err() {
                                        error!("Error in State::Withdraw Tick handler: {:?}", res);
                                    }
                                    Ok(())
                                }),
                        )
                    }
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

impl Message for Withdraw {
    type Result = Result<(), Error>;
}

impl Handler<Withdraw> for TokenBridge {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: Withdraw, _ctx: &mut Context<Self>) -> Self::Result {
        let payment_settings = SETTING.get_payment();
        let system_chain = payment_settings.system_chain;
        drop(payment_settings);

        let to = msg.to;
        let amount = msg.amount.clone();
        let withdraw_all = msg.withdraw_all;

        let bridge = self.bridge.clone();

        if let SystemChain::Xdai = system_chain {
            match self.state.clone() {
                State::Withdrawing { .. } => {
                    (
                        // Cannot start a withdraw when one is in progress
                        bail!("Cannot start a withdraw when one is in progress")
                    )
                }
                _ => {
                    Arbiter::spawn(bridge.xdai_to_dai_bridge(amount.clone()).then(move |res| {
                        TokenBridge::from_registry().do_send(DetailedStateChange(
                            DetailedBridgeState::XdaiToDai {
                                amount: amount.clone(),
                            },
                        ));
                        if res.is_err() {
                            error!("Error in State::Deposit Withdraw handler: {:?}", res);
                        } else {
                            // Only change to Withdraw if there was no error
                            TokenBridge::from_registry().do_send(StateChange(State::Withdrawing {
                                to,
                                amount,
                                timestamp: Instant::now(),
                                withdraw_all,
                            }));
                        }
                        Ok(())
                    }));
                    Ok(())
                }
            }
        } else {
            bail!("Not on Xdai chain!");
        }
    }
}

#[derive(Message)]
struct StateChange(State);

impl Handler<StateChange> for TokenBridge {
    type Result = ();
    fn handle(&mut self, msg: StateChange, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("Changing state to {}", msg.0);
        let new_state = msg.0;
        // since multiple futures from this system may be in flight at once we face a race
        // condition, the solution we have used is to put some state into the ready message
        // the ready message contains the state that it expects to find the system in before
        // it becomes ready again. If for example the state is depositing and it sees a message
        // ready(depositing) we know it's the right state change. If we are in withdraw and we
        // see ready(depositing) we know that it's a stray in flight future that's trying to
        // modify the state machine incorrectly
        if let State::Ready {
            former_state: Some(f),
        } = new_state.clone()
        {
            trace!("checking if we should change the state");
            if self.state != *f {
                trace!("{} != {}", self.state, *f);
                return;
            }
        }
        self.state = new_state;
    }
}

#[derive(Message)]
struct DetailedStateChange(DetailedBridgeState);

impl Handler<DetailedStateChange> for TokenBridge {
    type Result = ();
    fn handle(&mut self, msg: DetailedStateChange, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("Changing detailed state to {:?}", msg.0);
        let new_state = msg.0;
        self.detailed_state = new_state;
    }
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

pub struct GetBridgeStatus;

impl Message for GetBridgeStatus {
    type Result = Result<BridgeStatus, Error>;
}

impl Handler<GetBridgeStatus> for TokenBridge {
    type Result = Result<BridgeStatus, Error>;
    fn handle(&mut self, _msg: GetBridgeStatus, _ctx: &mut Context<Self>) -> Self::Result {
        let payment_settings = SETTING.get_payment();
        let withdraw_chain = payment_settings.withdraw_chain;
        let ret = BridgeStatus {
            reserve_amount: self.reserve_amount,
            minimum_deposit: self.minimum_to_exchange,
            withdraw_chain,
            state: self.detailed_state.clone(),
        };
        Ok(ret)
    }
}

/// used to get the bridge object and manipulate eth elsewhere, returns
/// the reserve amount in eth and the TokenBridge struct
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub struct GetBridge();

impl Message for GetBridge {
    type Result = Result<(TokenBridgeCore, Uint256), Error>;
}

impl Handler<GetBridge> for TokenBridge {
    type Result = Result<(TokenBridgeCore, Uint256), Error>;
    fn handle(&mut self, _msg: GetBridge, _ctx: &mut Context<Self>) -> Self::Result {
        let bridge = self.bridge.clone();
        let reserve_amount = eth_to_wei(self.reserve_amount.into());
        Ok((bridge, reserve_amount))
    }
}
