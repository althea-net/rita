//! Manages subnet DAO membership, DAOManager mantains a cache of subnet DAO entries.
//! The workflow goes as follows, an actor message DAOCheck is sent to DAOManager
//! if the identity is not on the DAO it will run a callback to tunnel manager to remove
//! that tunnel from operation. If the identity is on the DAO it will do nothing.
//! Entires from the DAO are cached for a configurable amount of time, this may of course
//! have the effect of adding someone to the DAO taking time to kick in.

use ::actix::prelude::*;
use ::actix_web::client::Connection;
use ::actix_web::error::JsonPayloadError;
use ::actix_web::*;
use futures::future::ok;
use futures::Future;
use num_traits::Zero;
use rand::thread_rng;
use rand::Rng;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream as TokioTcpStream;

use crate::rita_common::tunnel_manager::TunnelAction;
use crate::rita_common::tunnel_manager::TunnelManager;
use crate::rita_common::tunnel_manager::TunnelStateChange;
use althea_types::Identity;
use clarity::Address;
use num256::Uint256;
use settings::RitaCommonSettings;

use crate::SETTING;

// A json object specifcally for the web3 function
// call response we expect from the SubnetDAO contract
#[derive(Deserialize, Debug)]
pub struct Web3Response {
    jsonrpc: String,
    result: Option<String>,
    error: Option<Value>,
}

pub struct DAOManager {
    ident2dao: HashMap<Identity, Vec<DAOEntry>>,
}

impl Actor for DAOManager {
    type Context = Context<Self>;
}
impl Supervised for DAOManager {}
impl SystemService for DAOManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Tunnel manager started");
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

#[derive(Debug)]
pub struct DAOEntry {
    on_list: bool,
    dao_address: Address,
    id: Identity,
    last_updated: Instant,
}

pub struct DAOCheck(pub Identity);
impl Message for DAOCheck {
    type Result = ();
}

impl Handler<DAOCheck> for DAOManager {
    type Result = ();

    fn handle(&mut self, msg: DAOCheck, _: &mut Context<Self>) -> Self::Result {
        let their_id = msg.0;
        check_cache(their_id, &self.ident2dao);
    }
}

/// Called by returning DAO requests, sends a message to TunnelManager
pub struct CacheCallback {
    id: Identity,
    dao_address: Address,
    response: Web3Response,
}

impl Message for CacheCallback {
    type Result = ();
}

impl Handler<CacheCallback> for DAOManager {
    type Result = ();

    fn handle(&mut self, msg: CacheCallback, _: &mut Context<Self>) -> Self::Result {
        let their_id = msg.id;
        let dao_address = msg.dao_address;
        let response = msg.response;
        trace!("Got response {:?}", response);
        let num: Uint256 = match response.result {
            Some(uint) => match uint.replace("0x", "").parse() {
                Ok(parsed) => parsed,
                Err(e) => {
                    trace!("Parsing error {:?}", e);
                    return ();
                }
            },
            None => {
                trace!("Full node request got errror {:?}", response);
                return ();
            }
        };

        let has_vec = self.ident2dao.contains_key(&their_id);
        let on_dao = !(num == Uint256::zero());

        if has_vec {
            let entry_vec = self.ident2dao.get_mut(&their_id).unwrap();
            let mut found_entry = false;
            match entry_vec
                .iter_mut()
                .find(|ref i| dao_address == i.dao_address)
            {
                Some(entry) => {
                    entry.on_list = on_dao;
                    entry.last_updated = Instant::now();
                    found_entry = true;
                    trace!("Updating exising entry {:?}", entry);
                    send_membership_message(on_dao, their_id.clone());
                }
                None => (),
            }

            // We can't place this into the match because the mutable ref lives even
            // in the none case where it's obviously not being used. Until the borrow
            // checker is smart enough to allow that this will have to do
            if !found_entry {
                // A list exists but does not contain an entry from this dao
                // create one and insert it into the list
                let entry = DAOEntry {
                    on_list: on_dao,
                    dao_address: dao_address,
                    id: their_id.clone(),
                    last_updated: Instant::now(),
                };
                trace!("Adding new cache entry to existing ID {:?}", entry);
                entry_vec.push(entry);
                send_membership_message(on_dao, their_id);
            }
        } else {
            // No entry exists in the HashMap for this ID, create one
            let entry = DAOEntry {
                on_list: on_dao,
                dao_address: dao_address,
                id: their_id.clone(),
                last_updated: Instant::now(),
            };
            trace!("Creating new ID in cache {:?}", entry);
            self.ident2dao.insert(their_id.clone(), vec![entry]);

            send_membership_message(on_dao, their_id);
        }
    }
}

/// True if timestamp does not need to be updated
fn timer_check(timestamp: Instant) -> bool {
    Instant::now() - timestamp < Duration::new(SETTING.get_dao().cache_timeout_seconds, 0)
}

/// Sends off a message to TunnelManager about the dao state
fn send_membership_message(on_dao: bool, their_id: Identity) -> () {
    TunnelManager::from_registry().do_send(TunnelStateChange {
        identity: their_id.clone(),
        action: if on_dao {
            TunnelAction::MembershipConfirmed
        } else {
            TunnelAction::MembershipExpired
        },
    });
}

/// Checks if an identity is in at least one of the set of DAO's we are a member of.
/// will check the cache first before going out and updating via web3
fn check_cache(their_id: Identity, ident2dao: &HashMap<Identity, Vec<DAOEntry>>) -> () {
    trace!("Checking the DAOManager Cache for {:?}", their_id);
    let dao_settings = SETTING.get_dao();
    // we don't care about subnet DAO's, short circuit.
    if !dao_settings.dao_enforcement || dao_settings.dao_addresses.len() == 0 {
        trace!("DAO enforcement disabled DAOMAnager doing nothing!");
        send_membership_message(true, their_id);
        return ();
    }
    // TODO when we start enforcing dao state more strictly we will need
    // to detect when we are bootstrapping and explicitly allow everyone

    match ident2dao.get(&their_id) {
        // Cache hit
        Some(membership_list) => {
            for entry in membership_list.iter() {
                if entry.on_list && timer_check(entry.last_updated) {
                    trace!(
                        "{:?} is on the SubnetDAO {:?}",
                        their_id.clone(),
                        entry.dao_address
                    );
                    send_membership_message(true, their_id.clone());
                } else if !timer_check(entry.last_updated) {
                    trace!("Cache entry has expired, updating");
                    get_membership(entry.dao_address.clone(), entry.id.clone());
                }
            }
            trace!("{:?} is not on any SubnetDAO", their_id);
            send_membership_message(false, their_id);
        }
        // Cache miss, do a lookup for all DAO's
        None => {
            for dao in dao_settings.dao_addresses.iter() {
                get_membership(dao.clone(), their_id.clone());
            }
        }
    }
}

fn get_membership(dao_address: Address, target: Identity) -> () {
    let url = get_web3_server();
    let endpoint = format!("http://{}/", url);
    trace!("Getting DAO membership from {}", url);
    let socket: SocketAddr = match url.to_socket_addrs() {
        Ok(mut iter) => match iter.next() {
            Some(socket) => socket,
            None => {
                trace!("No ip found for domain name!");
                return ();
            }
        },
        Err(e) => {
            trace!("Could not resolve full node domain name {:?}", e);
            return ();
        }
    };
    trace!("Got IP {:?}", socket);

    // We transform the ip address into a argument
    let ip_bytes = match target.mesh_ip {
        IpAddr::V6(ip) => ip.octets(),
        _ => panic!("MeshIP must be ipv6 and is not!"),
    };
    let mut full_bytes: [u8; 32] = [0; 32];
    let mut i = 0;
    let func_magic = [0x37, 0x66, 0x79, 0xb0];
    for byte in func_magic.iter() {
        full_bytes[i] = byte.clone();
        i = i + 1;
    }
    for byte in ip_bytes.iter() {
        full_bytes[i] = byte.clone();
        i = i + 1;
    }

    let call_args: Uint256 = full_bytes.into();
    let func_call = format!("{{'jsonrpc':'2.0','method':'eth_call','params':[{{'to': '0x{:x}', 'data': '0x{:x}'}}, 'latest'],'id':1}}", dao_address, call_args);

    // it's really awkward to escape that many " so we just repace them
    let func_call = func_call.replace("'", "\"");
    trace!("Calling full node with: {}", func_call);
    let stream = TokioTcpStream::connect(&socket);

    let res = stream
        .then(move |stream| {
            let stream = stream.expect("Error attaching to full node socket");
            client::post(&endpoint)
                .timeout(Duration::from_secs(8))
                .with_connection(Connection::from_stream(stream))
                .content_type("application/json")
                .body(func_call)
                .unwrap()
                .send()
                .then(move |response| {
                    trace!("Got response {:?}", response);
                    match response {
                        Ok(res) => Box::new(res.json().then(
                            move |val: Result<Web3Response, JsonPayloadError>| match val {
                                Ok(val) => {
                                    DAOManager::from_registry().do_send(CacheCallback {
                                        id: target,
                                        dao_address: dao_address.clone(),
                                        response: val,
                                    });
                                    Ok(())
                                }
                                Err(e) => {
                                    trace!("Got bad Web3Response {:?}", e);
                                    return Ok(());
                                }
                            },
                        ))
                            as Box<dyn Future<Item = (), Error = JsonPayloadError>>,
                        Err(e) => {
                            warn!("Got error from full node {:?}", e);
                            Box::new(ok(()))
                        }
                    }
                })
        })
        .then(|_err| Ok(()));
    Arbiter::spawn(res);
}

/// Checks the list of full nodes, panics if none exist, if there exist
/// one or more a random entry from the list is returned in an attempt
/// to load balance across fullnodes
fn get_web3_server() -> String {
    if SETTING.get_dao().node_list.len() == 0 {
        panic!("DAO enforcement enabled but not DAO's configured!");
    }
    let node_list = SETTING.get_dao().node_list.clone();
    let mut rng = thread_rng();
    let val = rng.gen_range(0, node_list.len());

    node_list[val].clone()
}
