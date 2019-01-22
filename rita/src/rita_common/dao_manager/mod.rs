//! Manages subnet DAO membership, DAOManager mantains a cache of subnet DAO entries.
//! The workflow goes as follows, an actor message DAOCheck is sent to DAOManager
//! if the identity is not on the DAO it will run a callback to tunnel manager to remove
//! that tunnel from operation. If the identity is on the DAO it will do nothing.
//! Entires from the DAO are cached for a configurable amount of time, this may of course
//! have the effect of adding someone to the DAO taking time to kick in.

use ::actix::prelude::*;
use futures::Future;
use rand::thread_rng;
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use std::time::Instant;

use crate::rita_common::tunnel_manager::TunnelAction;
use crate::rita_common::tunnel_manager::TunnelManager;
use crate::rita_common::tunnel_manager::TunnelStateChange;
use althea_types::Identity;
use clarity::Address;
use settings::RitaCommonSettings;

use web3::client::Web3;
use web3::types::Data;
use web3::types::TransactionRequest;

use num256::Uint256;

use crate::SETTING;

mod membership_cache;
mod membership_fees;

use membership_cache::check_cache;
use membership_cache::CacheCallback;
use membership_cache::DAOEntry;

pub struct DAOManager {
    ident2dao: HashMap<Identity, Vec<DAOEntry>>,
}

impl Actor for DAOManager {
    type Context = Context<Self>;
}
impl Supervised for DAOManager {}
impl SystemService for DAOManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("dao manager started");
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
            ident2dao: HashMap::<Identity, Vec<DAOEntry>>::new(),
        }
    }
}

pub struct DAOUpdate(pub Vec<Identity>);
impl Message for DAOUpdate {
    type Result = ();
}

impl Handler<DAOUpdate> for DAOManager {
    type Result = ();

    fn handle(&mut self, msg: DAOUpdate, _: &mut Context<Self>) -> Self::Result {
        let neighbors_ids = msg.0;
        for id in neighbors_ids {
            check_cache(id, &self.ident2dao);
        }
    }
}

/// Checks the list of full nodes, panics if none exist, if there exist
/// one or more a random entry from the list is returned in an attempt
/// to load balance across fullnodes
fn get_web3_server() -> String {
    if SETTING.get_dao().node_list.is_empty() {
        panic!("DAO enforcement enabled but not DAO's configured!");
    }
    let node_list = SETTING.get_dao().node_list.clone();
    let mut rng = thread_rng();
    let val = rng.gen_range(0, node_list.len());

    node_list[val].clone()
}
