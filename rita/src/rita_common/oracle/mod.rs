//! This module is dedicated to updating local state with various pieces of infromation
//! relating to the blockchain being used. First and formost is maintaining an updated
//! balance and nonce as well as computing more complicated things like the closing and
//! payment treshhold based on gas prices.
//!
//! Finally the most traditional Oracle in this file is the pricing orcale which currently
//! operates by simply grabbing a text file from a configured server and adjusting prices
//! to match. More advanced pricing systems may be broken out into their own file some day

use ::actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use actix_web::error::PayloadError;
use actix_web::{client, Either, HttpMessage, Result};
use bytes::Bytes;
use num256::Uint256;
use num_traits::Zero;
use std::time::Duration;
use std::time::Instant;

use futures::{future, Future};

use num256::Int256;

use web30::client::Web3;

use clarity::Address;

use settings::RitaCommonSettings;

use althea_types::SystemChain;

use crate::rita_common::rita_loop::get_web3_server;

use crate::SETTING;

pub struct Oracle {
    last_updated: Instant,
}

impl Actor for Oracle {
    type Context = Context<Self>;
}

impl Supervised for Oracle {}
impl SystemService for Oracle {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Oracle started");
    }
}

impl Oracle {
    pub fn new() -> Self {
        Oracle {
            last_updated: Instant::now(),
        }
    }
}

impl Default for Oracle {
    fn default() -> Oracle {
        Oracle::new()
    }
}

/// How long we wait for a response from the full node
pub const ORACLE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Message)]
pub struct Update();

impl Handler<Update> for Oracle {
    type Result = ();

    fn handle(&mut self, _msg: Update, _ctx: &mut Context<Self>) -> Self::Result {
        let payment_settings = SETTING.get_payment();
        let full_node = get_web3_server();
        let web3 = Web3::new(&full_node, ORACLE_TIMEOUT);
        let our_address = payment_settings.eth_address.expect("No address!");
        let oracle_enabled = payment_settings.price_oracle_enabled;
        drop(payment_settings);

        info!("About to make web3 requests to {}", full_node);
        update_balance(our_address, &web3, full_node.clone());
        update_nonce(our_address, &web3, full_node.clone());
        update_gas_price(&web3, full_node.clone());
        get_net_version(&web3, full_node);
        if oracle_enabled {
            update_our_price();
        } else {
            info!("User has disabled the price oracle");
        }
        self.last_updated = Instant::now();
    }
}

/// Gets the balance for the provided eth address and updates it
/// in the global SETTING variable, do not use this function as a generic
/// balance getter.
fn update_balance(our_address: Address, web3: &Web3, full_node: String) {
    let res = web3
        .eth_get_balance(our_address)
        .then(move |balance| match balance {
            Ok(value) => {
                info!(
                    "Got response from {} balance request {:?}",
                    full_node, value
                );
                let our_balance = &mut SETTING.get_payment_mut().balance;
                // if our balance is not zero and the response we get from the full node
                // is zero either we very carefully emptied our wallet or it's that annoying Geth bug
                if !(*our_balance != Uint256::zero() && value == Uint256::zero()) {
                    *our_balance = value;
                }
                Ok(())
            }
            Err(e) => {
                warn!("Balance request to {} failed with {:?}", full_node, e);
                Err(e)
            }
        })
        .then(|_| Ok(()));

    Arbiter::spawn(res);
}

/// Updates the net_version in our global setting variable, this function
/// specifically runs into some security issues, a hostile node could provide
/// us with the wrong net_version, hoping to get a signed transaction good for
/// a different network than the one we are actually using. For example an address
/// that contains both real eth and test eth may be tricked into singing a transaction
/// for real eth while operating on the testnet. Because of this we have warnings behavior
fn get_net_version(web3: &Web3, full_node: String) {
    let res = web3.net_version()
                .then(move |net_version| match net_version {
                    Ok(value) => {
                        info!("Got response from {} for net_version request {:?}", full_node, value);
                        match value.parse::<u64>() {
                            Ok(net_id_num) => {
                                let mut payment_settings = SETTING.get_payment_mut();
                                let net_version = payment_settings.net_version;
                                // we could just take the first value and keept it but for now
                                // lets check that all nodes always agree on net version constantly
                                if net_version.is_some() && net_version.unwrap() != net_id_num {
                                    error!("GOT A DIFFERENT NETWORK ID VALUE, IT IS CRITICAL THAT YOU REVIEW YOUR NODE LIST FOR HOSTILE/MISCONFIGURED NODES");
                                }
                                else if net_version.is_none() {
                                    payment_settings.net_version = Some(net_id_num);
                                }
                            }
                            Err(e) => warn!("Failed to parse ETH network ID {:?}", e),
                        }

                        Ok(())
                    }
                    Err(e) => {
                        warn!("net_version request to {} failed with {:?}", full_node, e);
                        Err(e)
                    }
                }).then(|_| Ok(()));

    Arbiter::spawn(res);
}

/// Updates the nonce in global SETTING storage. The nonce of our next transaction
/// must always be greater than the nonce of our last transaction, since it's possible that other
/// programs are using the same private key and/or the router may be reset we need to get the nonce
/// from the blockchain at least once. We stick to incrementing it locally once we have it.
///
/// A potential attack here would be providing a lower nonce to cause you to replace an earlier transaction
/// that is still unconfirmed. That's a bit of a streach, more realistiically this would be spoofed in conjunction
/// with net_version
pub fn update_nonce(our_address: Address, web3: &Web3, full_node: String) {
    let res = web3
        .eth_get_transaction_count(our_address)
        .then(move |transaction_count| match transaction_count {
            Ok(value) => {
                info!(
                    "Got response from {} for nonce request {:?}",
                    full_node, value
                );
                let mut payment_settings = SETTING.get_payment_mut();
                payment_settings.nonce = value;
                Ok(())
            }
            Err(e) => {
                warn!("nonce request to {} failed with {:?}", full_node, e);
                Err(e)
            }
        })
        .then(|_| Ok(()));

    Arbiter::spawn(res);
}

/// This function updates the gas price and in the process adjusts our payment threshold
/// The average gas price over the last hour are averaged by the web3 call we then adjust our
/// expected payment amount and grace period so that every transaction pays 5% in transaction fees
/// (or whatever they care to configure as dyanmic_fee_factor). This also handles dramatic spikes in
/// gas prices by increasing the maximum debt before a drop to the free tier occurs. So if the blockchain
/// is simply to busy to use for some period of time payments will simply wait.
fn update_gas_price(web3: &Web3, full_node: String) {
    let res = web3
        .eth_gas_price()
        .then(move |gas_price| match gas_price {
            Ok(value) => {
                info!(
                    "Got response from {} for gas price request {:?}",
                    full_node, value
                );
                // Dynamic fee computation
                let mut payment_settings = SETTING.get_payment_mut();

                if payment_settings.system_chain == SystemChain::Xdai {
                    payment_settings.gas_price = 250_000_000_000u128.into();
                } else {
                    // use 105% of the gas price provided by the full node, this is designed
                    // to keep us above the median price provided by the full node.
                    // This should ensure that we maintain a higher-than-median priority even
                    // if the network is being spammed with transactions
                    payment_settings.gas_price = value.clone() + (value / 20u32.into());
                }
                let dynamic_fee_factor: Int256 = payment_settings.dynamic_fee_multiplier.into();
                let transaction_gas: Int256 = 21000.into();
                let neg_one = -1i32;
                let sign_flip: Int256 = neg_one.into();

                payment_settings.pay_threshold = transaction_gas
                    * payment_settings
                        .gas_price
                        .clone()
                        .to_int256()
                        .ok_or_else(|| {
                            format_err!("gas price is too high to fit into 256 signed bit integer")
                        })?
                    * dynamic_fee_factor.clone();
                trace!(
                    "Dynamically set pay threshold to {:?}",
                    payment_settings.pay_threshold
                );

                payment_settings.close_threshold =
                    sign_flip * 4u32.into() * payment_settings.pay_threshold.clone();
                trace!(
                    "Dynamically set close threshold to {:?}",
                    payment_settings.close_threshold
                );

                Ok(())
            }
            Err(e) => {
                warn!("gas price request to {} failed with {:?}", full_node, e);
                Err(e)
            }
        })
        .then(|_| Ok(()));

    Arbiter::spawn(res);
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct PriceUpdate {
    client: u32,
    gateway: u32,
    max: u32,
    dao_fee: u128,
    warning: u128,
    fee_multiplier: u32,
}

/// This is a very simple and early version of an automated pricing system
/// what it does right now is take the configured price_update_url from the settings
/// and query it for a file containing a suggested gateway and intermediary node price
/// the price the node charges is then set to this value.
fn update_our_price() {
    trace!("Starting price update");
    let url = SETTING.get_payment().price_oracle_url.clone();
    let is_gateway = SETTING.get_network().is_gateway;

    if !url.starts_with("https://") {
        error!("Unsafe price update url, your must use https!");
        return;
    }
    let res = client::get(url)
        .header("User-Agent", "Actix-web")
        .finish()
        .unwrap()
        .send()
        .timeout(ORACLE_TIMEOUT)
        .then(move |response| {
            match response {
                Ok(response) => {
                    Either::A(response.body().then(
                        move |message_body: Result<Bytes, PayloadError>| {
                            match message_body {
                                Ok(new_prices) => {
                                    // .json() only works on application/json content types unlike reqwest which handles bytes
                                    // transparently actix requests need to get the body and deserialize using serde_json in
                                    // an explicit fashion
                                    match serde_json::from_slice::<PriceUpdate>(&new_prices) {
                                        Ok(new_prices) => {
                                            // TODO this always seemed to have a lot of false positives, bet that
                                            // causes intermediaries to get priced like gateways
                                            let mut payment = SETTING.get_payment_mut();
                                            if is_gateway {
                                                payment.local_fee = new_prices.gateway;
                                            } else {
                                                payment.local_fee = new_prices.client;
                                            }
                                            payment.max_fee = new_prices.max;
                                            payment.balance_warning_level =
                                                new_prices.warning.into();
                                            payment.dynamic_fee_multiplier =
                                                new_prices.fee_multiplier;
                                            drop(payment);

                                            let new_dao_fee = Uint256::from(new_prices.dao_fee);
                                            let current_dao_fee = SETTING.get_dao().dao_fee.clone();
                                            if new_dao_fee > current_dao_fee {
                                                let mut dao = SETTING.get_dao_mut();
                                                dao.dao_fee = new_dao_fee;
                                            }

                                            trace!("Successfully updated prices");
                                        }
                                        Err(e) => warn!(
                                            "Failed to deserialize price update message with {:?}",
                                            e
                                        ),
                                    }
                                }
                                Err(e) => warn!("Failed to decode message body {:?}", e),
                            }
                            Ok(()) as Result<(), ()>
                        },
                    ))
                }
                Err(e) => Either::B({
                    trace!("Failed to make price update request with {:?}", e);
                    // don't ask me why these types agree
                    future::ok(())
                }),
            }
        });

    Arbiter::spawn(res);
}

/// A very simple function placed here for convinence that indicates
/// if the system should go into low balance mode
pub fn low_balance() -> bool {
    let payment_settings = SETTING.get_payment();
    let balance = payment_settings.balance.clone();
    let balance_warning_level = payment_settings.balance_warning_level.clone();

    balance < balance_warning_level
}
