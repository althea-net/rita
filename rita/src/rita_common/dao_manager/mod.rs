//! In the longer term this is supposed to manage SubnetDAO membership, for the time being
//! it simply manages payments to a multisig walllet address without any of the other indtended
//! features of the subnet DAO system.
//! The multisig payments are performed much like the bandwidth payments, using a target fee amount
//! to compute the amount it should pay at a time, these micropayments have the effect of pro-rating
//! the DAO fee amount and preventing the router from drastically making a large payment

use crate::rita_common::payment_controller::TRANSACTION_SUBMISSON_TIMEOUT;
use crate::rita_common::usage_tracker::UpdatePayments;
use crate::rita_common::usage_tracker::UsageTracker;
use crate::SETTING;
use ::actix::{Actor, Arbiter, Context, Handler, Message, Supervised, SystemService};
use althea_types::Identity;
use althea_types::PaymentTx;
use clarity::Transaction;
use futures::future::Future;
use num256::Int256;
use num_traits::Signed;
use rand::thread_rng;
use rand::Rng;
use settings::RitaCommonSettings;
use std::time::Instant;
use web30::client::Web3;

pub struct DAOManager {
    last_payment_time: Instant,
}

impl Actor for DAOManager {
    type Context = Context<Self>;
}
impl Supervised for DAOManager {}
impl SystemService for DAOManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("DAO manager started");
    }
}

impl Default for DAOManager {
    fn default() -> DAOManager {
        DAOManager::new()
    }
}

impl DAOManager {
    fn new() -> DAOManager {
        DAOManager {
            last_payment_time: Instant::now(),
        }
    }
}

/// Very basic loop for DAO manager payments
pub struct Tick;
impl Message for Tick {
    type Result = ();
}

impl Handler<Tick> for DAOManager {
    type Result = ();

    fn handle(&mut self, _msg: Tick, _: &mut Context<Self>) -> Self::Result {
        let dao_settings = SETTING.get_dao();
        let payment_settings = SETTING.get_payment();
        let eth_private_key = payment_settings.eth_private_key;
        let our_id = match SETTING.get_identity() {
            Some(id) => id,
            None => return,
        };
        let gas_price = payment_settings.gas_price.clone();
        let nonce = payment_settings.nonce.clone();
        let pay_threshold = payment_settings.pay_threshold.clone();
        let dao_addresses = dao_settings.dao_addresses.clone();
        let dao_fee = match dao_settings.dao_fee.to_int256() {
            Some(val) => val,
            None => return,
        };
        let we_have_a_dao = !dao_addresses.is_empty();
        let should_pay =
            (Int256::from(self.last_payment_time.elapsed().as_secs()) * dao_fee) > pay_threshold;
        trace!("We should pay the subnet dao {}", should_pay);
        trace!("We have a dao to pay {}", we_have_a_dao);

        if we_have_a_dao && should_pay {
            // pay all the daos on the list at once
            for address in dao_addresses {
                trace!("Paying subnet dao fee to {}", address);
                let amount_to_pay = match pay_threshold.abs().to_uint256().clone() {
                    Some(val) => val,
                    None => return,
                };

                let dao_identity = Identity {
                    eth_address: address,
                    // this key has no meaning, it's here so that we don't have to change
                    // the identity indexing
                    wg_public_key: "YJhxFPv+NVeU5e+eBmwIXFd/pVdgk61jUHojuSt8IU0="
                        .parse()
                        .unwrap(),
                    mesh_ip: "::1".parse().unwrap(),
                    nickname: None,
                };

                let full_node = get_web3_server();
                let web3 = Web3::new(&full_node, TRANSACTION_SUBMISSON_TIMEOUT);

                let tx = Transaction {
                    nonce: nonce.clone(),
                    gas_price: gas_price.clone(),
                    gas_limit: "21000".parse().unwrap(),
                    to: address,
                    value: amount_to_pay.clone(),
                    data: Vec::new(),
                    signature: None,
                };
                let transaction_signed = tx.sign(
                    &eth_private_key.expect("No private key configured!"),
                    payment_settings.net_version,
                );

                let transaction_bytes = match transaction_signed.to_bytes() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("Failed to generate DAO transaction, {:?}", e);
                        return;
                    }
                };

                let transaction_status = web3.eth_send_raw_transaction(transaction_bytes);

                // in theory this may fail, for now there is no handler and
                // we will just underpay when that occurs
                Arbiter::spawn(transaction_status.then(move |res| match res {
                    Ok(txid) => {
                        info!("Successfully paid the subnet dao {:#066x}!", txid);
                        UsageTracker::from_registry().do_send(UpdatePayments {
                            payment: PaymentTx {
                                to: dao_identity,
                                from: our_id,
                                amount: amount_to_pay,
                                txid: Some(txid),
                            },
                        });
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Failed to pay subnet dao! {:?}", e);
                        Ok(())
                    }
                }));
            }
            self.last_payment_time = Instant::now();
        }
    }
}

/// Checks the list of full nodes, panics if none exist, if there exist
/// one or more a random entry from the list is returned in an attempt
/// to load balance across fullnodes
fn get_web3_server() -> String {
    if SETTING.get_dao().node_list.is_empty() {
        panic!("No full nodes available for DAO queries!");
    }
    let node_list = SETTING.get_dao().node_list.clone();
    let mut rng = thread_rng();
    let val = rng.gen_range(0, node_list.len());

    node_list[val].clone()
}
