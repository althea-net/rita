use crate::blockchain_oracle::update as BlockchainOracleUpdate;
use crate::debt_keeper::send_debt_update;
use crate::eth_compatible_withdraw;
use crate::network_monitor::NetworkInfo as NetworkMonitorTick;
use crate::network_monitor::NetworkMonitor;
use crate::payment_controller::tick_payment_controller;
use crate::payment_validator::validate;
use crate::peer_listener::get_peers;
use crate::peer_listener::tick;
use crate::rita_loop::set_gateway;
use crate::traffic_watcher::{TrafficWatcher, Watch};
use crate::tunnel_manager::gc::TriggerGc;
use crate::tunnel_manager::PeersToContact;
use crate::tunnel_manager::{GetNeighbors, TunnelManager};
use crate::KI;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    System, SystemService,
};
use actix_async::System as AsyncSystem;
use babel_monitor_legacy::open_babel_stream_legacy;
use babel_monitor_legacy::parse_interfaces_legacy;
use babel_monitor_legacy::parse_neighs_legacy;
use babel_monitor_legacy::parse_routes_legacy;
use babel_monitor_legacy::start_connection_legacy;
use failure::Error;
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

pub struct RitaFastLoop {}

impl Default for RitaFastLoop {
    fn default() -> RitaFastLoop {
        RitaFastLoop {}
    }
}

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
    type Result = Result<(), Error>;
}

impl Handler<Crash> for RitaFastLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Crash, ctx: &mut Context<Self>) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), Error>;
}

impl Handler<Tick> for RitaFastLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let babel_port = settings::get_rita_common().network.babel_port;
        trace!("Common tick!");

        manage_gateway();

        let start = Instant::now();

        // watch neighbors for billing
        Arbiter::spawn(
            TunnelManager::from_registry()
                .send(GetNeighbors)
                .timeout(FAST_LOOP_TIMEOUT)
                .then(move |res| {
                    trace!("Currently open tunnels: {:?}", res);
                    let neighbors = res.unwrap().unwrap();

                    let neigh = Instant::now();
                    info!(
                        "GetNeighbors completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

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
                        })
                }),
        );

        // Observe the dataplane for status and problems. Tunnel GC checks for specific issues
        // (tunnels that are installed but not active) and cleans up cruft. We put these together
        // because both can fail without anything truly bad happening and we get a slight efficiency
        // bonus running them together (fewer babel socket connections per loop iteration)
        Arbiter::spawn(TunnelManager::from_registry().send(GetNeighbors).then(
            move |rita_neighbors| {
                let rita_neighbors = rita_neighbors.unwrap().unwrap();
                open_babel_stream_legacy(babel_port)
                    .from_err()
                    .and_then(move |stream| {
                        start_connection_legacy(stream).and_then(move |stream| {
                            parse_routes_legacy(stream).and_then(move |(stream, babel_routes)| {
                                parse_neighs_legacy(stream).and_then(
                                    move |(stream, babel_neighbors)| {
                                        parse_interfaces_legacy(stream).and_then(
                                            move |(_stream, babel_interfaces)| {
                                                trace!("Sending network monitor tick");
                                                NetworkMonitor::from_registry().do_send(
                                                    NetworkMonitorTick {
                                                        babel_neighbors,
                                                        babel_routes,
                                                        rita_neighbors,
                                                    },
                                                );

                                                trace!("Sending tunnel GC");
                                                TunnelManager::from_registry().do_send(TriggerGc {
                                                    tunnel_timeout: TUNNEL_TIMEOUT,
                                                    tunnel_handshake_timeout:
                                                        TUNNEL_HANDSHAKE_TIMEOUT,
                                                    babel_interfaces,
                                                });
                                                Ok(())
                                            },
                                        )
                                    },
                                )
                            })
                        })
                    })
                    .then(|ret| {
                        if let Err(e) = ret {
                            error!("Failed to watch network latency with {:?}", e)
                        }
                        Ok(())
                    })
            },
        ));

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
        TunnelManager::from_registry().do_send(PeersToContact::new(peers));

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

/// Manages gateway functionality and maintains the gateway parameter, this is different from the gateway
/// identification in rita_client because this must function even if we aren't registered for an exit it's also
/// very prone to being true when the device has a wan port but no actual wan connection.
fn manage_gateway() {
    // Resolves the gateway client corner case
    // Background info here https://forum.altheamesh.com/t/the-gateway-client-corner-case/35
    // the is_up detection is mostly useless because these ports reside on switches which mark
    // all ports as up all the time.
    let gateway = match settings::get_rita_common().network.external_nic {
        Some(ref external_nic) => KI.is_iface_up(external_nic).unwrap_or(false),
        None => false,
    };

    info!("We are a Gateway: {}", gateway);
    set_gateway(gateway);

    if gateway {
        let mut common = settings::get_rita_common();
        match KI.get_resolv_servers() {
            Ok(s) => {
                for ip in s.iter() {
                    trace!("Resolv route {:?}", ip);
                    KI.manual_peers_route(ip, &mut common.network.last_default_route)
                        .unwrap();
                }
                settings::set_rita_common(common);
            }
            Err(e) => warn!("Failed to add DNS routes with {:?}", e),
        }
    }
}
