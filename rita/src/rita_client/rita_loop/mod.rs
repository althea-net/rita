//! This is the primary actor loop for rita-client, where periodic tasks are spawed and Actors are
//! tied together with message calls.
//!
//! This loop manages exit signup based on the settings configuration state and deploys an exit vpn
//! tunnel if the signup was successful on the selected exit.

use crate::rita_client::exit_manager::ExitManager;
use crate::rita_client::traffic_watcher::TrafficWatcher;
use crate::rita_client::traffic_watcher::WeAreGatewayClient;
use crate::rita_common::tunnel_manager::GetNeighbors;
use crate::rita_common::tunnel_manager::TunnelManager;
use crate::SETTING;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    SystemService,
};
use althea_types::ExitState;
use failure::Error;
use futures01::future::Future;
use settings::client::RitaClientSettings;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct RitaLoop;

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

        ExitManager::from_registry().do_send(Tick {});

        Arbiter::spawn(check_for_gateway_client_billing_corner_case());

        info!(
            "Rita Client loop completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis()
        );
        Ok(())
    }
}

pub fn check_rita_client_actors() {
    assert!(crate::rita_client::rita_loop::RitaLoop::from_registry().connected());
    assert!(crate::rita_client::exit_manager::ExitManager::from_registry().connected());
}

/// There is a complicated corner case where the gateway is a client and a relay to
/// the same exit, this will produce incorrect billing data as we need to reconcile the
/// relay bills (under the exit relay id) and the client bills (under the exit id) versus
/// the exit who just has the single billing id for the client and is combining debts
/// This function grabs neighbors and etermines if we have a neighbor with the same mesh ip
/// and eth adress as our selected exit, if we do we trigger the special case handling
fn check_for_gateway_client_billing_corner_case() -> impl Future<Item = (), Error = ()> {
    TunnelManager::from_registry()
        .send(GetNeighbors)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .then(move |res| {
            // strange notation lets us scope our access to SETTING and prevent
            // holding a readlock
            let exit_server = { SETTING.get_exit_client().get_current_exit().cloned() };
            let neighbors = res.unwrap().unwrap();

            if let Some(exit) = exit_server {
                if let ExitState::Registered { .. } = exit.info {
                    for neigh in neighbors {
                        // we have a neighbor who is also our selected exit!
                        // wg_key exluded due to multihomed exits having a different one
                        if neigh.identity.global.mesh_ip == exit.id.mesh_ip
                            && neigh.identity.global.eth_address == exit.id.eth_address
                        {
                            TrafficWatcher::from_registry()
                                .do_send(WeAreGatewayClient { value: true });
                            return Ok(());
                        }
                    }
                    TrafficWatcher::from_registry().do_send(WeAreGatewayClient { value: false });
                }
            }
            Ok(())
        })
}
