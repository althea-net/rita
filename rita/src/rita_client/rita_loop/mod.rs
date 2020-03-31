//! This is the primary actor loop for rita-client, where periodic tasks are spawed and Actors are
//! tied together with message calls.
//!
//! This loop manages exit signup based on the settings configuration state and deploys an exit vpn
//! tunnel if the signup was successful on the selected exit.

use crate::rita_client::exit_manager::ExitManager;
use crate::rita_client::heartbeat::send_udp_heartbeat;
use crate::rita_client::heartbeat::HEARTBEAT_SERVER_KEY;
use crate::rita_client::light_client_manager::light_client_hello_response;
use crate::rita_client::light_client_manager::LightClientManager;
use crate::rita_client::light_client_manager::Watch;
use crate::rita_client::operator_fee_manager::OperatorFeeManager;
use crate::rita_client::operator_fee_manager::Tick as OperatorTick;
use crate::rita_client::operator_update::{OperatorUpdate, Update};
use crate::rita_client::traffic_watcher::GetExitDestPrice;
use crate::rita_client::traffic_watcher::TrafficWatcher;
use crate::rita_client::traffic_watcher::WeAreGatewayClient;
use crate::rita_common::tunnel_manager::GetNeighbors;
use crate::rita_common::tunnel_manager::GetTunnels;
use crate::rita_common::tunnel_manager::TunnelManager;
use crate::SETTING;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    SystemService,
};
use actix_web::http::Method;
use actix_web::{server, App};
use althea_types::ExitState;
use antenna_forwarding_client::start_antenna_forwarding_proxy;
use failure::Error;
use futures01::future::Future;
use settings::client::RitaClientSettings;
use settings::RitaCommonSettings;
use std::time::{Duration, Instant};

pub struct RitaLoop {
    antenna_forwarder_started: bool,
}

impl Default for RitaLoop {
    fn default() -> Self {
        RitaLoop {
            antenna_forwarder_started: false,
        }
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

        ExitManager::from_registry().do_send(Tick {});

        Arbiter::spawn(check_for_gateway_client_billing_corner_case());

        let dest_price = TrafficWatcher::from_registry().send(GetExitDestPrice);
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

        if SETTING.get_log().enabled {
            send_udp_heartbeat();

            if !self.antenna_forwarder_started {
                let network = SETTING.get_network();
                let our_id = SETTING.get_identity().unwrap();
                let logging = SETTING.get_log();
                start_antenna_forwarding_proxy(
                    logging.forwarding_checkin_url.clone(),
                    our_id,
                    *HEARTBEAT_SERVER_KEY,
                    network.wg_public_key.unwrap(),
                    network.wg_private_key.unwrap(),
                    network.peer_interfaces.clone(),
                );
                self.antenna_forwarder_started = true;
            }
        }

        // Check Operator payments
        OperatorFeeManager::from_registry().do_send(OperatorTick);
        // Check in with Organizer
        OperatorUpdate::from_registry().do_send(Update);

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

pub fn start_rita_client_endpoints(workers: usize) {
    // listen on the light client gateway ip if it's not none
    if let Some(gateway_ip) = SETTING.get_network().light_client_router_ip {
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
            SETTING.get_network().light_client_hello_port
        ));
        if let Ok(val) = unstarted_server {
            val.shutdown_timeout(0).start();
        } else {
            trace!("Failed to bind to light client ip, probably toggled off!")
        }
    }
}
