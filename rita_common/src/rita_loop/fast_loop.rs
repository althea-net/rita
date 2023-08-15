use crate::blockchain_oracle::update as BlockchainOracleUpdate;
use crate::debt_keeper::send_debt_update;
use crate::network_monitor::update_network_info;
use crate::network_monitor::NetworkInfo as NetworkMonitorTick;
use crate::payment_controller::tick_payment_controller;
use crate::payment_validator::validate;
use crate::peer_listener::peerlistener_tick;
use crate::peer_listener::structs::PeerListener;
use crate::traffic_watcher::watch;
use crate::tunnel_manager::contact_peers::tm_contact_peers;
use crate::tunnel_manager::tm_get_neighbors;
use actix_async::System as AsyncSystem;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_neighs;
use babel_monitor::parse_routes;

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

/// Rita fast loop thread spawning function, there are currently two rita fast loops, one that
/// runs as a thread with async/await support and one that runs as a actor using old futures
/// slowly things will be migrated into this new sync loop as we move to async/await
pub fn start_rita_fast_loop() {
    let mut last_restart = Instant::now();
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || loop {
                trace!("Common Fast tick!");
                let start = Instant::now();

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    let babel_port = settings::get_rita_common().network.babel_port;
                    trace!("Common tick!");

                    let res = tm_get_neighbors();
                    trace!("Currently open tunnels: {:?}", res);
                    let neighbors = res;
                    let neigh = Instant::now();

                    if let Ok(mut stream) = open_babel_stream(babel_port, FAST_LOOP_TIMEOUT) {
                        if let Ok(babel_routes) = parse_routes(&mut stream) {
                            if let Err(e) = watch(babel_routes.clone(), &neighbors) {
                                error!("Error for Rita common traffic watcher {}", e);
                            }
                            info!(
                                "TrafficWatcher completed in {}s {}ms",
                                neigh.elapsed().as_secs(),
                                neigh.elapsed().subsec_millis()
                            );

                            // Observe the dataplane for status and problems.
                            if let Ok(babel_neighbors) = parse_neighs(&mut stream) {
                                let rita_neighbors = tm_get_neighbors();
                                trace!("Sending network monitor tick");
                                update_network_info(NetworkMonitorTick {
                                    babel_neighbors,
                                    babel_routes,
                                    rita_neighbors,
                                });
                            }
                        }
                    }

                    // Update debts
                    if let Err(e) = send_debt_update() {
                        warn!("Debt keeper update failed! {:?}", e);
                    }

                    // updating blockchain info often is easier than dealing with edge cases
                    // like out of date nonces or balances, also users really really want fast
                    // balance updates, think very long and very hard before running this more slowly
                    BlockchainOracleUpdate().await;
                    info!("Finished oracle update!");
                    // Check on payments, only really needs to be run this quickly
                    // on large nodes where very high variation in throughput can result
                    // in blowing through the entire grace in less than a minute
                    validate().await;
                    info!("Finished validated!");
                    // Process payments queued for sending, needs to be run often for
                    // the same reason as the validate code, during high throughput periods
                    // payments must be sent quickly to avoid enforcement
                    tick_payment_controller().await;
                    info!("Finished tick payment controller!");
                });
                info!(
                    "Common Fast tick completed in {}s {}ms",
                    start.elapsed().as_secs(),
                    start.elapsed().subsec_millis()
                );

                thread::sleep(FAST_LOOP_SPEED);
            })
            .join()
        } {
            error!("Rita common fast loop thread paniced! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = AsyncSystem::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}

/// This asnyc loop runs functions related to peer discovery. This is put in its own loop to prevent dns lookup
/// to block the entire loop
pub fn peer_discovery_loop() {
    let mut last_restart = Instant::now();
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || {
                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    let mut pl = PeerListener::new();
                    loop {
                        let start = Instant::now();
                        info!("Common peer discovery tick!");
                        let measure_tick = Instant::now();
                        info!("Starting PeerListener tick");

                        pl = peerlistener_tick(pl);

                        info!(
                            "PeerListener tick completed in {}s {}ms",
                            measure_tick.elapsed().as_secs(),
                            measure_tick.elapsed().subsec_millis(),
                        );

                        info!("Starting TM contact peers");
                        // Contact manual peers
                        tm_contact_peers(&pl).await;
                        info!("Done contacting peers");

                        // sleep until it has been FAST_LOOP_SPEED seconds from start, whenever that may be
                        // if it has been more than FAST_LOOP_SPEED seconds from start, go right ahead
                        info!("Peer Listener loop elapsed in = {:?}", start.elapsed());
                        if start.elapsed() < FAST_LOOP_SPEED {
                            info!(
                                "Peer listener sleeping for {:?}",
                                FAST_LOOP_SPEED - start.elapsed()
                            );
                            thread::sleep(FAST_LOOP_SPEED - start.elapsed());
                        }
                        info!("Peer Listener sleeping Done!");
                    }
                })
            })
            .join()
        } {
            error!(
                "Rita common peer discovery loop thread paniced! Respawning {:?}",
                e
            );
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = AsyncSystem::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}
