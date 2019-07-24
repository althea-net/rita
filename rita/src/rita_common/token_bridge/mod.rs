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
//!         If there is an `eth_balance` that is greater than the `minimum_to_exchange` amount,
//!         subtract the `reserve` amount and send it through uniswap into DAI. Change to State::Depositing.
//!
//!     State::Depositing:
//!         Future (started in State::Ready) waits on Uniswap, and upon successful swap, sends dai
//!         thru the bridge into xdai. When the money is out of the Dai account and in the bridge,
//!         or if uniswap times out, change to State::Ready.
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
use settings::RitaCommonSettings;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

const BRIDGE_TIMEOUT: Duration = Duration::from_secs(600);
const UNISWAP_TIMEOUT: u64 = 600u64;
const ETH_TRANSFER_TIMEOUT: u64 = 600u64;

fn is_timed_out(started: Instant) -> bool {
    Instant::now() - started > BRIDGE_TIMEOUT
}

fn eth_to_wei(eth: f64) -> Uint256 {
    let wei = (eth * 1_000_000_000_000_000_000_f64) as u64;
    wei.into()
}

#[derive(Clone, Debug)]
pub enum State {
    Ready {},
    Depositing {},
    Withdrawing {
        amount: Uint256,
        to: Address,
        timestamp: Instant,
    },
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
                "https://mainnet.infura.io/v3/4bd80ea13e964a5a9f728a68567dc784".into(),
                "https://dai.althea.net".into(),
            ),
            state: State::Ready {},
            // operation_in_progress: None,
            minimum_to_exchange: 10,
            reserve_amount: 1,
            minimum_stranded_dai_transfer: 1,
        }
    }
}

fn rescue_dai(
    bridge: TokenBridgeCore,
    our_address: Address,
    minimum_stranded_dai_transfer: u32,
) -> Box<Future<Item = (), Error = Error>> {
    Box::new(bridge.get_dai_balance(our_address).and_then({
        move |dai_balance| {
            if dai_balance > eth_to_wei(minimum_stranded_dai_transfer.into()) {
                println!("rescuing dais");
                // Over the bridge into xDai
                Box::new(
                    bridge
                        .dai_to_xdai_bridge(dai_balance)
                        .and_then(|_res| Ok(())),
                )
            } else {
                // we don't have a lot of dai, we shouldn't do anything
                Box::new(future::ok(())) as Box<Future<Item = (), Error = Error>>
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
        drop(payment_settings);

        let bridge = self.bridge.clone();
        let reserve_amount = self.reserve_amount;
        let minimum_to_exchange = self.minimum_to_exchange;
        let minimum_stranded_dai_transfer = self.minimum_stranded_dai_transfer;

        if let SystemChain::Xdai = system_chain {
            match self.state.clone() {
                State::Ready {} => {
                    println!(
                        "Ticking in State::Ready. Eth Address: {:x}",
                        bridge.own_address
                    );
                    // Go into State::Depositing right away to prevent multiple attempts
                    TokenBridge::from_registry().do_send(StateChange(State::Depositing {}));
                    Arbiter::spawn(
                        rescue_dai(bridge.clone(), our_address, minimum_stranded_dai_transfer)
                            .and_then(move |_| {
                                println!("rescued dai");
                                bridge
                                    .dai_to_eth_price(eth_to_wei(1.into()))
                                    .join(bridge.eth_web3.eth_get_balance(our_address))
                                    .and_then(move |(wei_per_dollar, eth_balance)| {
                                        // These statements convert the reserve_amount and minimum_to_exchange
                                        // into eth using the current price (units of wei)
                                        let reserve =
                                            wei_per_dollar.clone() * reserve_amount.into();
                                        let minimum_to_exchange =
                                            wei_per_dollar * minimum_to_exchange.into();

                                        // This means enough has been sent into our account to start the
                                        // deposit process.
                                        if eth_balance >= minimum_to_exchange {
                                            // Leave a reserve in the account to use for gas in the future
                                            let swap_amount = eth_balance - reserve;
                                            println!("Converting to Dai");
                                            Box::new(
                                                bridge
                                                    // Convert to Dai in Uniswap
                                                    .eth_to_dai_swap(swap_amount, 600)
                                                    .and_then(move |dai_bought| {
                                                        // And over the bridge into xDai
                                                        bridge.dai_to_xdai_bridge(dai_bought)
                                                    })
                                                    .and_then(|_| Ok(())),
                                            )
                                                as Box<Future<Item = (), Error = Error>>
                                        } else {
                                            // we don't have a lot of eth, we shouldn't do anything
                                            Box::new(future::ok(()))
                                                as Box<Future<Item = (), Error = Error>>
                                        }
                                    })
                            })
                            .then(|res| {
                                // It goes back into State::Ready once the dai
                                // is in the bridge or if failed. This prevents multiple simultaneous
                                // attempts to bridge the same Dai.
                                TokenBridge::from_registry().do_send(StateChange(State::Ready {}));

                                if res.is_err() {
                                    error!("Error in State::Deposit Tick handler: {:?}", res);
                                }
                                Ok(())
                            }),
                    )
                }
                State::Depositing {} => println!("Tried to tick in State::Depositing"),
                State::Withdrawing {
                    to,
                    amount,
                    timestamp,
                } => {
                    if is_timed_out(timestamp) {
                        TokenBridge::from_registry().do_send(StateChange(State::Ready {}));
                    } else {
                        Arbiter::spawn(
                            bridge
                                .get_dai_balance(our_address)
                                .and_then(move |our_dai_balance| {
                                    // This is how it knows the money has come over from the bridge
                                    if our_dai_balance >= amount {
                                        Box::new(
                                            bridge
                                                // Then it converts to eth
                                                .dai_to_eth_swap(amount, UNISWAP_TIMEOUT)
                                                // And sends it to the recipient
                                                .and_then(move |transferred_eth| {
                                                    bridge.eth_transfer(
                                                        to,
                                                        transferred_eth,
                                                        ETH_TRANSFER_TIMEOUT,
                                                    )
                                                })
                                                .and_then(|_| Ok(())),
                                        )
                                            as Box<Future<Item = (), Error = Error>>
                                    } else {
                                        Box::new(futures::future::ok(()))
                                            as Box<Future<Item = (), Error = Error>>
                                    }
                                })
                                .then(|res| {
                                    if res.is_err() {
                                        error!("Error in State::Withdraw Tick handler: {:?}", res);
                                    }
                                    // Change to Deposit whether or not there was an error
                                    TokenBridge::from_registry()
                                        .do_send(StateChange(State::Ready {}));
                                    Ok(())
                                }),
                        )
                    }
                }
            }
        }
    }
}

#[derive(Message)]
pub struct Withdraw {
    to: Address,
    amount: Uint256,
}

impl Handler<Withdraw> for TokenBridge {
    type Result = ();

    fn handle(&mut self, msg: Withdraw, _ctx: &mut Context<Self>) -> Self::Result {
        let payment_settings = SETTING.get_payment();
        let system_chain = payment_settings.system_chain;
        drop(payment_settings);

        let to = msg.to;
        let amount = msg.amount.clone();

        let bridge = self.bridge.clone();

        if let SystemChain::Xdai = system_chain {
            match self.state.clone() {
                State::Withdrawing { .. } => (
                    // Cannot start a withdraw when one is in progress
                ),
                State::Depositing { .. } => (
                    // Figure out something to do here
                ),
                State::Ready {} => {
                    Arbiter::spawn(bridge.xdai_to_dai_bridge(amount.clone()).then(move |res| {
                        if res.is_err() {
                            error!("Error in State::Deposit Withdraw handler: {:?}", res);
                        } else {
                            // Only change to Withdraw if there was no error
                            TokenBridge::from_registry().do_send(StateChange(State::Withdrawing {
                                to,
                                amount,
                                timestamp: Instant::now(),
                            }));
                        }
                        Ok(())
                    }))
                }
            }
        }
    }
}

#[derive(Message)]
pub struct StateChange(State);

impl Handler<StateChange> for TokenBridge {
    type Result = ();
    fn handle(&mut self, msg: StateChange, _ctx: &mut Context<Self>) -> Self::Result {
        println!("Changing state to {:?}", msg.0);
        self.state = msg.0;
    }
}
