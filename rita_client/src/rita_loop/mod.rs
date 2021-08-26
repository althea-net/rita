//! This is the primary actor loop for rita-client, where periodic tasks are spawned and Actors are
//! tied together with message calls.
//!
//! This loop manages exit signup based on the settings configuration state and deploys an exit vpn
//! tunnel if the signup was successful on the selected exit.

use crate::exit_manager::exit_manager_tick;
use crate::heartbeat::send_udp_heartbeat;
use crate::light_client_manager::light_client_hello_response;
use crate::light_client_manager::LightClientManager;
use crate::light_client_manager::Watch;
use crate::operator_fee_manager::OperatorFeeManager;
use crate::operator_fee_manager::Tick as OperatorTick;
use crate::operator_update::{OperatorUpdate, Update};
use crate::traffic_watcher::GetExitDestPrice;
use crate::traffic_watcher::TrafficWatcherActor;
use rita_common::tunnel_manager::GetNeighbors;
use rita_common::tunnel_manager::GetTunnels;
use rita_common::tunnel_manager::TunnelManager;

use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    System, SystemService,
};
use actix_web::http::Method;
use actix_web::{server, App};

use actix_async::System as AsyncSystem;
use std::thread;
use std::time::{Duration, Instant};

use althea_types::ExitState;
use failure::Error;
use futures01::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

lazy_static! {
    /// see the comment on check_for_gateway_client_billing_corner_case()
    /// to identify why this variable is needed. In short it identifies
    /// a specific billing corner case.
    static ref IS_GATEWAY_CLIENT: AtomicBool = AtomicBool::new(false);
}

pub fn is_gateway_client() -> bool {
    IS_GATEWAY_CLIENT.load(Ordering::Relaxed)
}

pub fn set_gateway_client(input: bool) {
    IS_GATEWAY_CLIENT.store(input, Ordering::Relaxed)
}

/// This function determines if metrics are permitted for this device, if the user has
/// disabled logging we should not send any logging data. If they are a member of a network
/// with an operator address this overrides the logging setting to ensure metrics are sent.
/// Since an operator address indicates an operator that is being paid for supporting this user
/// and needs info to assist them. The logging setting may be inspected to disable metrics
/// not required for a normal operator
pub fn metrics_permitted() -> bool {
    settings::get_rita_client().log.enabled
        || settings::get_rita_client()
            .operator
            .operator_address
            .is_some()
}

pub struct RitaLoop {}

impl Default for RitaLoop {
    fn default() -> Self {
        RitaLoop {}
    }
}

// the speed in seconds for the client loop
pub const CLIENT_LOOP_SPEED: u64 = 5;
pub const CLIENT_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        ctx.run_interval(Duration::from_secs(CLIENT_LOOP_SPEED), |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

impl SystemService for RitaLoop {}
impl Supervised for RitaLoop {
    fn restarting(&mut self, _ctx: &mut Context<RitaLoop>) {
        error!("Rita Client loop actor died! recovering!");
    }
}

/// Used to test actor respawning
pub struct Crash;

impl Message for Crash {
    type Result = Result<(), Error>;
}

impl Handler<Crash> for RitaLoop {
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

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let start = Instant::now();
        trace!("Client Tick!");

        Arbiter::spawn(check_for_gateway_client_billing_corner_case());

        let dest_price = TrafficWatcherActor::from_registry().send(GetExitDestPrice);
        let tunnels = TunnelManager::from_registry().send(GetTunnels);
        Arbiter::spawn(dest_price.join(tunnels).then(move |res| {
            // unwrap top level actix error, ok to crash if this fails
            let (exit_dest_price, tunnels) = res.unwrap();
            // these can't ever happen as the function only returns a Result for Actix
            // type checking
            let tunnels = tunnels.unwrap();
            let exit_dest_price = exit_dest_price.unwrap();
            LightClientManager::from_registry()
                .send(Watch {
                    tunnels,
                    exit_dest_price,
                })
                .then(|_res| Ok(()))
        }));

        if metrics_permitted() {
            send_udp_heartbeat();
        }

        // Check Operator payments
        OperatorFeeManager::from_registry().do_send(OperatorTick);
        // Check in with Operator
        OperatorUpdate::from_registry().do_send(Update);

        info!(
            "Rita Client loop completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis()
        );
        Ok(())
    }
}

/// Rita loop thread spawning function, there are currently two rita loops, one that
/// runs as a thread with async/await support and one that runs as a actor using old futures
/// slowly things will be migrated into this new sync loop as we move to async/await
pub fn start_rita_loop() {
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
                trace!("Client tick!");

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    exit_manager_tick().await;
                });

                // sleep until it has been CLIENT_LOOP_SPEED seconds from start, whenever that may be
                // if it has been more than CLIENT_LOOP_SPEED seconds from start, go right ahead
                let client_loop_speed = Duration::from_secs(CLIENT_LOOP_SPEED);
                if start.elapsed() < client_loop_speed {
                    thread::sleep(client_loop_speed - start.elapsed());
                }
            })
            .join()
        } {
            error!("Rita client loop thread paniced! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                system.stop_with_code(121)
            }
            last_restart = Instant::now();
        }
    });
}

pub fn check_rita_client_actors() {
    assert!(crate::rita_loop::RitaLoop::from_registry().connected());
    crate::rita_loop::start_rita_loop();
}

/// There is a complicated corner case where the gateway is a client and a relay to
/// the same exit, this will produce incorrect billing data as we need to reconcile the
/// relay bills (under the exit relay id) and the client bills (under the exit id) versus
/// the exit who just has the single billing id for the client and is combining debts
/// This function grabs neighbors and determines if we have a neighbor with the same mesh ip
/// and eth address as our selected exit, if we do we trigger the special case handling
fn check_for_gateway_client_billing_corner_case() -> impl Future<Item = (), Error = ()> {
    TunnelManager::from_registry()
        .send(GetNeighbors)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .then(move |res| {
            // strange notation lets us scope our access to SETTING and prevent
            // holding a readlock
            let exit_server = {
                settings::get_rita_client()
                    .exit_client
                    .get_current_exit()
                    .cloned()
            };
            let neighbors = res.unwrap().unwrap();

            if let Some(exit) = exit_server {
                if let ExitState::Registered { .. } = exit.info {
                    for neigh in neighbors {
                        // we have a neighbor who is also our selected exit!
                        // wg_key excluded due to multihomed exits having a different one
                        if neigh.identity.global.mesh_ip
                            == exit
                                .selected_exit
                                .selected_id
                                .expect("Expected exit ip, none present")
                            && neigh.identity.global.eth_address == exit.eth_address
                        {
                            info!("We are a gateway client");
                            set_gateway_client(true);
                            return Ok(());
                        }
                    }
                    set_gateway_client(false);
                }
            }
            Ok(())
        })
}

pub fn start_rita_client_endpoints(workers: usize) {
    // listen on the light client gateway ip if it's not none
    if let Some(gateway_ip) = settings::get_rita_client().network.light_client_router_ip {
        trace!("Listening for light client hellos on {}", gateway_ip);
        let unstarted_server = server::new(|| {
            App::new().resource("/light_client_hello", |r| {
                r.method(Method::POST).with(light_client_hello_response)
            })
        })
        .workers(workers)
        .bind(format!(
            "{}:{}",
            gateway_ip,
            settings::get_rita_client().network.light_client_hello_port
        ));
        if let Ok(val) = unstarted_server {
            val.shutdown_timeout(0).start();
        } else {
            trace!("Failed to bind to light client ip, probably toggled off!")
        }
    }
}
