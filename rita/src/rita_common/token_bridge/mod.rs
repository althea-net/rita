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
//! It is implemented as a state machine:
//!
//! DefaultState:
//!     TickEvent:
//!         If there is an `eth_balance` that is greater than the `minimum_to_exchange` amount, subtract the `reserve` amount
//!         and convert it through uniswap into DAI.
//!
//!         If there is a dai balance, send it through the bridge into xdai
//!     
//!     WithdrawEvent(to, amount):
//!         Send amount into bridge, switch to WithdrawState.
//!
//! WithdrawState{ to, amount, timestamp}:
//!     TickEvent:
//!         If there is a dai balance greater or equal to the withdraw amount, send the withdraw
//!         amount through uniswap.
//!         Future waits on Uniswap and upon successful swap, sends eth to "to" address. Another future
//!         waits on this transfer to complete. When it is complete, the state switches back to DefaultState
//!
//!     WithdrawEvent:
//!         Nothing happens
//!

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
use futures_timer::FutureExt;
use num256::Uint256;
use settings::RitaCommonSettings;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use web30::types::SendTxOption;

const BRIDGE_TIMEOUT: Duration = Duration::from_secs(600);
const UNISWAP_TIMEOUT: u64 = 600u64;
const ETH_TRANSFER_TIMEOUT: u64 = 600u64;

fn is_timed_out(started: Instant) -> bool {
    Instant::now() - started > BRIDGE_TIMEOUT
}

/// List of all possible events that may be in progress in this module
/// as well as a starting time in order to apply timeouts
// pub enum InProgress {
//     EthToDai(Instant),
//     DaiToXdai(Instant),
//     XdaiToDai(Instant),
//     DaiToEth(Instant),
//     EthToWithdraw(Instant),
//     UniswapApprove(Instant),
// }

/// Represents a withdraw in progress
pub enum State {
    Deposit {},
    Withdraw {
        timestamp: Instant,
        amount: Uint256,
        to: Address,
    },
}

pub struct TokenBridge {
    bridge: TokenBridgeCore,
    state: State,
    // these amounts are in dollars, we also assume the dai price is equal to the dollar
    // exchange rate for Eth. The reserve amount is how much we are keeping in our Eth wallet
    // in order to pay for the fees of future actions we may be required to take to deposit or
    // withdraw. Minimum to exchange represents the minimum amount that can be exchanged without
    // fees becoming unreasonable.
    reserve_amount: u32,
    minimum_to_exchange: u32,
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
                "https://dai.althea.org".into(),
            ),
            state: State::Deposit {},
            // operation_in_progress: None,
            minimum_to_exchange: 10,
            reserve_amount: 1,
        }
    }
}

#[derive(Message)]
pub struct Update();

impl Handler<Update> for TokenBridge {
    type Result = ();

    fn handle(&mut self, _msg: Update, _ctx: &mut Context<Self>) -> Self::Result {
        let payment_settings = SETTING.get_payment();
        let our_address = payment_settings.eth_address.unwrap();
        let our_private_key = payment_settings.eth_private_key.unwrap();
        let balance = payment_settings.balance.clone();
        let gas_price = payment_settings.gas_price.clone();
        let system_chain = payment_settings.system_chain;
        drop(payment_settings);

        match system_chain {
            SystemChain::Xdai => match self.state {
                State::Deposit {} => {
                    Box::new(futures::future::ok(())) as Box<Future<Item = (), Error = Error>>
                }
                State::Withdraw {
                    timestamp,
                    to,
                    amount,
                } => Box::new(self.bridge.get_dai_balance(our_address).and_then(
                    move |our_dai_balance| {
                        if our_dai_balance >= amount {
                            Box::new(
                                self.bridge
                                    .dai_to_eth_swap(amount, UNISWAP_TIMEOUT)
                                    .and_then(|transferred_eth| {
                                        self.bridge
                                            .eth_web3
                                            .send_transaction(
                                                to,
                                                Vec::new(),
                                                transferred_eth,
                                                our_address,
                                                our_private_key,
                                                vec![
                                                    SendTxOption::GasPrice(
                                                        10_000_000_000u128.into(),
                                                    ),
                                                    SendTxOption::NetworkId(100u64),
                                                ],
                                            )
                                            .and_then(|tx_hash| {
                                                self.bridge
                                                    .eth_web3
                                                    .wait_for_transaction(tx_hash.into())
                                                    .timeout(Duration::from_secs(
                                                        ETH_TRANSFER_TIMEOUT,
                                                    ))
                                            })
                                    }),
                            ) as Box<Future<Item = (), Error = Error>>
                        } else {
                            Box::new(futures::future::ok(()))
                                as Box<Future<Item = (), Error = Error>>
                        }
                    },
                )),
            },
            // no other chains have auto migration code, ignore clippy for now
            _ => {}
        }
    }
}

// fn progress_xdai_deposits() {
//     dispatch_approval(bridge: TokenBridgeCore);
//     dispatch_eth_to_dai_swap(
//         bridge: TokenBridgeCore,
//         reserve_dollars: u32,
//         minimum_to_exchange_dollars: u32,
//         balance: Uint256,
//     );
//     dispatch_dai_to_xdai_swap(
//         bridge: TokenBridgeCore,
//         minimum_to_exchange_dollars: u32,
//         address: Address,
//     );
// }

// fn progress_xdai_withdraws() {
//     dispatch_approval(bridge: TokenBridgeCore);
//     dispatch_xdai_to_dai_swap(bridge: TokenBridgeCore, amount: Uint256);
//     dispatch_dai_to_eth_swap(bridge: TokenBridgeCore, address: Address);
//     dispatch_user_withdraw();
// }

/// Spawns a future that will attempt to swap Eth from our eth address into DAI also
/// in that same Eth address using Uniswap. The reserve dollars amount will always be
/// kept in Eth for txfees. If the Eth balance is not greater than the minimum to exchange
/// nothing will happen.
fn dispatch_eth_to_dai_swap(
    bridge: TokenBridgeCore,
    reserve_dollars: u32,
    minimum_to_exchange_dollars: u32,
    balance: Uint256,
) {
    Arbiter::spawn(
        bridge
            .dai_to_eth_price(1u8.into())
            .then(move |wei_per_dollar| {
                if wei_per_dollar.is_err() {
                    error!("Failed to get Dai to Eth Price with {:?}", wei_per_dollar);
                    return Box::new(future::ok(())) as Box<Future<Item = (), Error = ()>>;
                }

                let wei_per_dollar = wei_per_dollar.unwrap();
                let reserve = wei_per_dollar.clone() * reserve_dollars.into();
                let minimum_to_exchange = wei_per_dollar * minimum_to_exchange_dollars.into();

                if balance >= minimum_to_exchange {
                    // do stuff
                    let swap_amount = balance - reserve;
                    Box::new(bridge.eth_to_dai_swap(swap_amount, 600).then(|_res| Ok(())))
                        as Box<Future<Item = (), Error = ()>>
                } else {
                    // we don't have a lot of eth, we shouldn't do anything
                    Box::new(future::ok(())) as Box<Future<Item = (), Error = ()>>
                }
            }),
    );
}

/// Spawns a future that will send DAI from our Eth address into the POA XDAI bridge
/// this bridge will then spawn those DAI as XDAI in the same address on the XDAI side
/// once again if the DAI balance is smaller than the minimum to exchange this future
/// will do nothing.
fn dispatch_dai_to_xdai_swap(
    bridge: TokenBridgeCore,
    minimum_to_exchange_dollars: u32,
    address: Address,
) {
    Arbiter::spawn(
        bridge
            .get_dai_balance(address)
            .then(move |our_dai_balance| {
                if our_dai_balance.is_err() {
                    error!("Failed to get Dai balance with {:?}", our_dai_balance);
                    return Box::new(future::ok(())) as Box<Future<Item = (), Error = ()>>;
                }

                let our_dai_balance = our_dai_balance.unwrap();

                if our_dai_balance >= minimum_to_exchange_dollars.into() {
                    // do stuff
                    Box::new(
                        bridge
                            .dai_to_xdai_bridge(our_dai_balance)
                            .then(|_res| Ok(())),
                    ) as Box<Future<Item = (), Error = ()>>
                } else {
                    // we don't have a lot of eth, we shouldn't do anything
                    Box::new(future::ok(())) as Box<Future<Item = (), Error = ()>>
                }
            }),
    );
}

/// This is the first step to reversing the conversion process and getting XDAI back out
/// into Eth, this function will attempt to convert a given amount of XDAI on the POA XDAI
/// chain into Eth on the Eth chain. It is assumed that the user checked that they actually
/// have enough xdai to perform this conversion. This function does not accept a minimum
/// to exchange as all flows in this direction are user requested withdraws
fn dispatch_xdai_to_dai_swap(bridge: TokenBridgeCore, amount: Uint256) {
    Arbiter::spawn(
        bridge
            .xdai_to_dai_bridge(amount.clone())
            .then(move |bridge_txid| {
                match bridge_txid {
                    Ok(txid) => info!(
                        "Xdai to DAI withdraw for {} processed with txid {:#066x}",
                        amount, txid
                    ),
                    Err(e) => info!("Xdai to DAI withdraw failed with {:?}", e),
                }
                Ok(())
            }),
    );
}

/// This will convert Dai in our Eth address back to Eth using the uniswap exchange contract
/// on the Eth blockchian. It does not accept a minimum to exchange as all flows in this
/// direction are user requested withdraws
fn dispatch_dai_to_eth_swap(bridge: TokenBridgeCore, address: Address) {
    Arbiter::spawn(
        bridge
            .get_dai_balance(address)
            .then(move |our_dai_balance| {
                if our_dai_balance.is_err() {
                    error!("Failed to get Dai balance with {:?}", our_dai_balance);
                    return Box::new(future::ok(())) as Box<Future<Item = (), Error = ()>>;
                }

                let our_dai_balance = our_dai_balance.unwrap();

                Box::new(
                    bridge
                        .dai_to_eth_swap(our_dai_balance, 600)
                        .then(|_res| Ok(())),
                ) as Box<Future<Item = (), Error = ()>>
            }),
    );
}

/// In order to use the Uniswap contract on the Eth chain to exchange from DAI to ETH we need
/// to first approve the Uniswap contract to spend our DAI balance. This is somthing of an expensive
/// operation gas wise, so we first check if we've already done it.
fn dispatch_approval(bridge: TokenBridgeCore) {
    Arbiter::spawn(
        bridge
            .check_if_uniswap_dai_approved()
            .then(move |approval_status| {
                if approval_status.is_err() {
                    error!(
                        "Failed to Uniswap dai approved status with {:?}",
                        approval_status
                    );
                    return Box::new(future::ok(())) as Box<Future<Item = (), Error = ()>>;
                }

                let approved = approval_status.unwrap();

                if approved {
                    Box::new(future::ok(())) as Box<Future<Item = (), Error = ()>>
                } else {
                    Box::new(
                        bridge
                            .approve_uniswap_dai_transfers(Duration::from_secs(600))
                            .then(|_res| Ok(())),
                    ) as Box<Future<Item = (), Error = ()>>
                }
            }),
    );
}
