use crate::blockchain_oracle::update as BlockchainOracleUpdate;
use crate::debt_keeper::send_debt_update;
use crate::eth_compatible_withdraw;
use crate::handle_shaping;
use crate::network_monitor::update_network_info;
use crate::network_monitor::NetworkInfo as NetworkMonitorTick;
use crate::payment_controller::tick_payment_controller;
use crate::payment_validator::validate;
use crate::peer_listener::get_peers;
use crate::peer_listener::tick;
use crate::tm_trigger_gc;
use crate::traffic_watcher::{TrafficWatcher, Watch};
use crate::tunnel_manager::gc::TriggerGc;
use crate::tunnel_manager::tm_contact_peers;
use crate::tunnel_manager::tm_get_neighbors;
use crate::tunnel_manager::PeersToContact;
use crate::update_neighbor_status;
use crate::RitaCommonError;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    System, SystemService,
};
use actix_async::System as AsyncSystem;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_interfaces;
use babel_monitor::parse_neighs;
use babel_monitor::parse_routes;
use babel_monitor_legacy::open_babel_stream_legacy;
use babel_monitor_legacy::parse_routes_legacy;
use babel_monitor_legacy::start_connection_legacy;
use futures01::Future;

use std::thread;
use std::time::{Duration, Instant};

// the speed in seconds for the common loop
pub const FAST_LOOP_SPEED: Duration = Duration::from_secs(5);
pub const FAST_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

/// if we haven't heard a hello from a peer after this time we clean up the tunnel
/// 15 minutes currently, this is not the final say on this value we check if the tunnel
/// has seen any handshakes in TUNNEL_HANDSHAKE_TIMEOUT seconds, if it has we spare it from
/// reaping
pub const TUNNEL_TIMEOUT: Duration = Duration::from_secs(900);
pub const TUNNEL_HANDSHAKE_TIMEOUT: Duration = TUNNEL_TIMEOUT;

#[derive(Default)]
pub struct RitaFastLoop {}

impl Actor for RitaFastLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        trace!("Common rita loop started!");

        ctx.run_interval(FAST_LOOP_SPEED, |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

impl SystemService for RitaFastLoop {}
impl Supervised for RitaFastLoop {
    fn restarting(&mut self, _ctx: &mut Context<RitaFastLoop>) {
        error!("Rita Common loop actor died! recovering!");
    }
}

/// Used to test actor respawning
pub struct Crash;

impl Message for Crash {
    type Result = Result<(), RitaCommonError>;
}

impl Handler<Crash> for RitaFastLoop {
    type Result = Result<(), RitaCommonError>;
    fn handle(&mut self, _: Crash, ctx: &mut Context<Self>) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), RitaCommonError>;
}

impl Handler<Tick> for RitaFastLoop {
    type Result = Result<(), RitaCommonError>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let babel_port = settings::get_rita_common().network.babel_port;
        trace!("Common tick!");

        let start = Instant::now();

        let res = tm_get_neighbors();
        trace!("Currently open tunnels: {:?}", res);
        let neighbors = res;
        let neigh = Instant::now();
        info!(
            "GetNeighbors completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis()
        );

        //watch neighbors for billing
        Arbiter::spawn(
            open_babel_stream_legacy(babel_port)
                .from_err()
                .and_then(move |stream| {
                    start_connection_legacy(stream).and_then(move |stream| {
                        parse_routes_legacy(stream).and_then(move |routes| {
                            TrafficWatcher::from_registry()
                                .send(Watch::new(neighbors, routes.1))
                                .timeout(FAST_LOOP_TIMEOUT)
                                .then(move |_res| {
                                    info!(
                                        "TrafficWatcher completed in {}s {}ms",
                                        neigh.elapsed().as_secs(),
                                        neigh.elapsed().subsec_millis()
                                    );
                                    Ok(())
                                })
                        })
                    })
                })
                .then(|ret| {
                    if let Err(e) = ret {
                        error!("Failed to watch client traffic with {:?}", e)
                    }
                    Ok(())
                }),
        );

        // Observe the dataplane for status and problems. Tunnel GC checks for specific issues
        // (tunnels that are installed but not active) and cleans up cruft. We put these together
        // because both can fail without anything truly bad happening and we get a slight efficiency
        // bonus running them together (fewer babel socket connections per loop iteration)
        let rita_neighbors = tm_get_neighbors();
        if let Ok(mut stream) = open_babel_stream(babel_port, FAST_LOOP_TIMEOUT) {
            let babel_neighbors = parse_neighs(&mut stream);
            let babel_interfaces = parse_interfaces(&mut stream);
            let babel_routes = parse_routes(&mut stream);
            if let (Ok(babel_neighbors), Ok(babel_routes)) = (babel_neighbors, babel_routes) {
                trace!("Sending network monitor tick");
                update_network_info(NetworkMonitorTick {
                    babel_neighbors,
                    babel_routes,
                    rita_neighbors,
                });
            }

            if let Ok(babel_interfaces) = babel_interfaces {
                trace!("Sending tunnel GC");
                let _res = tm_trigger_gc(TriggerGc {
                    tunnel_timeout: TUNNEL_TIMEOUT,
                    tunnel_handshake_timeout: TUNNEL_HANDSHAKE_TIMEOUT,
                    babel_interfaces,
                });
            }
        }

        // Update debts
        if let Err(e) = send_debt_update() {
            warn!("Debt keeper update failed! {:?}", e);
        }

        let start = Instant::now();
        trace!("Starting PeerListener tick");

        tick();

        info!(
            "PeerListener tick completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis(),
        );

        let start = Instant::now();
        trace!("Getting Peers from PeerListener to pass to TunnelManager");

        let peers = get_peers();
        info!(
            "PeerListener get {} peers completed in {}s {}ms",
            peers.len(),
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis(),
        );

        update_neighbor_status();
        handle_shaping();
        //Contact peers
        tm_contact_peers(PeersToContact::new(peers));

        Ok(())
    }
}

/// Rita fast loop thread spawning function, there are currently two rita fast loops, one that
/// runs as a thread with async/await support and one that runs as a actor using old futures
/// slowly things will be migrated into this new sync loop as we move to async/await
pub fn start_rita_fast_loop() {
    let mut last_restart = Instant::now();
    // this is a reference to the non-async actix system since this can bring down the whole process
    let system = System::current();
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || loop {
                let start = Instant::now();
                trace!("Common Fast tick!");

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    // updating blockchain info often is easier than dealing with edge cases
                    // like out of date nonces or balances, also users really really want fast
                    // balance updates, think very long and very hard before running this more slowly
                    BlockchainOracleUpdate().await;
                    // Check on payments, only really needs to be run this quickly
                    // on large nodes where very high variation in throughput can result
                    // in blowing through the entire grace in less than a minute
                    validate().await;
                    // Process payments queued for sending, needs to be run often for
                    // the same reason as the validate code, during high throughput periods
                    // payments must be sent quickly to avoid enforcement
                    tick_payment_controller().await;
                    // processes user withdraw requests from the dashboard, only needed until we
                    // migrate our endpoints to async/await
                    eth_compatible_withdraw().await;
                });

                // sleep until it has been FAST_LOOP_SPEED seconds from start, whenever that may be
                // if it has been more than FAST_LOOP_SPEED seconds from start, go right ahead
                if start.elapsed() < FAST_LOOP_SPEED {
                    thread::sleep(FAST_LOOP_SPEED - start.elapsed());
                }
            })
            .join()
        } {
            error!("Rita common fast loop thread paniced! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                system.stop_with_code(121)
            }
            last_restart = Instant::now();
        }
    });
}
