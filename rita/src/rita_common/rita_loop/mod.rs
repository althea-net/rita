//! The main actor loop for Rita, this loop is common to both rita and rita_exit (as is everything
//! in rita common).
//!
//! This loops ties together various actors through messages and is generally the rate limiter on
//! all system functions. Anything that blocks will eventually filter up to block this loop and
//! halt essential functions like opening tunnels and managing peers

use std::time::{Duration, Instant};

use rand::thread_rng;
use rand::Rng;

use actix::prelude::*;
use actix::registry::SystemService;
use actix_utils::KillActor;

use actix_utils::ResolverWrapper;

use guac_core::web3::client::{Web3, Web3Client};

use KI;

use rita_common::tunnel_manager::{GetNeighbors, TriggerGC, TunnelManager};

use rita_common::traffic_watcher::{TrafficWatcher, Watch};

use rita_common::peer_listener::PeerListener;

use rita_common::debt_keeper::{DebtKeeper, SendUpdate};

use rita_common::payment_controller::{PaymentController, UpdateBalance};

use rita_common::peer_listener::GetPeers;

use rita_common::dao_manager::DAOCheck;
use rita_common::dao_manager::DAOManager;

use rita_common::tunnel_manager::PeersToContact;

use failure::Error;

use futures::Future;

use settings::RitaCommonSettings;
use SETTING;

pub struct RitaLoop {
    was_gateway: bool,
}

impl RitaLoop {
    pub fn new() -> RitaLoop {
        RitaLoop { was_gateway: false }
    }
}

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        trace!("Common rita loop started!");

        ctx.run_interval(Duration::from_secs(5), |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), Error>;
}

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        trace!("Common tick!");

        // Resolves the gateway client corner case
        // Background info here https://forum.altheamesh.com/t/the-gateway-client-corner-case/35
        if SETTING.get_network().is_gateway {
            if !self.was_gateway {
                let resolver_addr: Addr<ResolverWrapper> = System::current().registry().get();
                resolver_addr.do_send(KillActor);

                self.was_gateway = true
            }

            match KI.get_resolv_servers() {
                Ok(s) => {
                    for ip in s.iter() {
                        trace!("Resolv route {:?}", ip);
                        KI.manual_peers_route(&ip, &mut SETTING.get_network_mut().default_route)
                            .unwrap();
                    }
                }
                Err(e) => warn!("Failed to add DNS routes with {:?}", e),
            }
        } else {
            self.was_gateway = false
        }

        let start = Instant::now();
        ctx.spawn(
            TunnelManager::from_registry()
                .send(GetNeighbors)
                .into_actor(self)
                .then(move |res, act, _ctx| {
                    let res = res.unwrap().unwrap();

                    trace!("Currently open tunnels: {:?}", res);

                    let neigh = Instant::now();
                    info!(
                        "GetNeighbors completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_nanos() / 1000000
                    );

                    TrafficWatcher::from_registry()
                        .send(Watch::new(res))
                        .into_actor(act)
                        .then(move |_res, _act, _ctx| {
                            info!(
                                "TrafficWatcher completed in {}s {}ms",
                                neigh.elapsed().as_secs(),
                                neigh.elapsed().subsec_nanos() / 1000000
                            );
                            DebtKeeper::from_registry().do_send(SendUpdate {});
                            actix::fut::ok(())
                        })
                }),
        );

        trace!("Starting DAOManager loop");
        Arbiter::spawn(
            TunnelManager::from_registry()
                .send(GetNeighbors)
                .then(move |neighbors| {
                    match neighbors {
                        Ok(Ok(neighbors)) => {
                            trace!("Sending DAOCheck");
                            for neigh in neighbors.iter() {
                                let their_id = neigh.identity.global.clone();
                                DAOManager::from_registry().do_send(DAOCheck(their_id));
                            }
                        }
                        Ok(Err(e)) => {
                            trace!("Failed to get neighbors from tunnel manager {:?}", e);
                        }
                        Err(e) => {
                            trace!("Failed to get neighbors from tunnel manager {:?}", e);
                        }
                    };
                    Ok(())
                }),
        );

        let start = Instant::now();
        Arbiter::spawn(
            TunnelManager::from_registry()
                .send(TriggerGC(Duration::from_secs(
                    SETTING.get_network().tunnel_timeout_seconds,
                )))
                .then(move |res| {
                    info!(
                        "TunnelManager GC pass completed in {}s {}ms, with result {:?}",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_nanos() / 1000000,
                        res
                    );
                    res
                })
                .then(|_| Ok(())),
        );

        let start = Instant::now();
        trace!("Starting PeerListener tick");
        Arbiter::spawn(
            PeerListener::from_registry()
                .send(Tick {})
                .then(move |res| {
                    info!(
                        "PeerListener tick completed in {}s {}ms, with result {:?}",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_nanos() / 1000000,
                        res
                    );
                    res
                })
                .then(|_| Ok(())),
        );

        let start = Instant::now();
        trace!("Getting Peers from PeerListener to pass to TunnelManager");
        Arbiter::spawn(
            PeerListener::from_registry()
                .send(GetPeers {})
                .and_then(move |peers| {
                    info!(
                        "PeerListener get peers completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_nanos() / 1000000
                    );
                    TunnelManager::from_registry().send(PeersToContact::new(peers.unwrap())) // GetPeers never fails so unwrap is safe
                })
                .then(|_| Ok(())),
        );

        let full_node = get_web3_server();
        let web3 = Web3Client::new(&full_node);
        let our_address = SETTING.get_payment().eth_address;
        Arbiter::spawn(
            web3.eth_get_balance(our_address)
                .then(move |balance| match balance {
                    Ok(value) => {
                        trace!(
                            "Got response from balance request to {}! {:?}",
                            full_node,
                            value
                        );
                        PaymentController::from_registry().do_send(UpdateBalance {
                            balance: value.clone(),
                        });
                        Ok(value)
                    }
                    Err(e) => {
                        warn!("Balance request to {} failed with {:?}", full_node, e);
                        Err(e)
                    }
                })
                .then(|_| Ok(())),
        );

        Ok(())
    }
}

/// Checks the list of full nodes, panics if none exist, if there exist
/// one or more a random entry from the list is returned in an attempt
/// to load balance across fullnodes
pub fn get_web3_server() -> String {
    if SETTING.get_payment().node_list.len() == 0 {
        panic!("no full nodes configured!");
    }
    let node_list = SETTING.get_payment().node_list.clone();
    let mut rng = thread_rng();
    let val = rng.gen_range(0, node_list.len());

    node_list[val].clone()
}
