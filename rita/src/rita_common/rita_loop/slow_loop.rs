use crate::rita_common::simulated_txfee_manager::SimulatedTxFeeManager;
use crate::rita_common::simulated_txfee_manager::Tick as TxFeeTick;
use crate::rita_common::token_bridge::Tick as TokenBridgeTick;
use crate::rita_common::token_bridge::TokenBridge;
use crate::rita_common::tunnel_manager::gc::TriggerGC;
use crate::rita_common::tunnel_manager::TunnelManager;
use crate::SETTING;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    SystemService,
};
use babel_monitor::open_babel_stream;
use babel_monitor::parse_interfaces;
use babel_monitor::set_local_fee;
use babel_monitor::set_metric_factor;
use babel_monitor::start_connection;
use failure::Error;
use futures01::future::Future;
use settings::RitaCommonSettings;
use std::time::Duration;
use tokio::util::FutureExt;

/// the speed in seconds for the common loop
pub const SLOW_LOOP_SPEED: u64 = 60;
pub const SLOW_LOOP_TIMEOUT: Duration = Duration::from_secs(15);
/// if we haven't heard a hello from a peer after this time we clean up the tunnel
/// 15 minutes currently, this is not the final say on this value we check if the tunnel
/// has seen any handshakes in TUNNEL_HANDSHAKE_TIMEOUT seconds, if it has we spare it from
/// reaping
pub const TUNNEL_TIMEOUT: Duration = Duration::from_secs(900);
pub const TUNNEL_HANDSHAKE_TIMEOUT: Duration = TUNNEL_TIMEOUT;

pub struct RitaSlowLoop;

impl Default for RitaSlowLoop {
    fn default() -> RitaSlowLoop {
        RitaSlowLoop {}
    }
}

impl Actor for RitaSlowLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        trace!("Common rita loop started!");

        ctx.run_interval(Duration::from_secs(SLOW_LOOP_SPEED), |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

impl SystemService for RitaSlowLoop {}
impl Supervised for RitaSlowLoop {
    fn restarting(&mut self, _ctx: &mut Context<RitaSlowLoop>) {
        error!("Rita Common loop actor died! recovering!");
    }
}

/// Used to test actor respawning
pub struct Crash;

impl Message for Crash {
    type Result = Result<(), Error>;
}

impl Handler<Crash> for RitaSlowLoop {
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

impl Handler<Tick> for RitaSlowLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("Common Slow tick!");
        let babel_port = SETTING.get_network().babel_port;

        SimulatedTxFeeManager::from_registry().do_send(TxFeeTick);

        Arbiter::spawn(
            open_babel_stream(babel_port)
                .from_err()
                .and_then(move |stream| {
                    start_connection(stream).and_then(move |stream| {
                        parse_interfaces(stream).and_then(move |(_stream, babel_interfaces)| {
                            trace!("Sending tunnel GC");
                            TunnelManager::from_registry().do_send(TriggerGC {
                                tunnel_timeout: TUNNEL_TIMEOUT,
                                tunnel_handshake_timeout: TUNNEL_HANDSHAKE_TIMEOUT,
                                babel_interfaces,
                            });
                            Ok(())
                        })
                    })
                })
                .then(|ret| {
                    if let Err(e) = ret {
                        error!("Tunnel Garbage collection failed with {:?}", e)
                    }
                    Ok(())
                }),
        );

        TokenBridge::from_registry().do_send(TokenBridgeTick());

        // we really only need to run this on startup, but doing so periodically
        // could catch the edge case where babel is restarted under us
        set_babel_price();

        Ok(())
    }
}

fn set_babel_price() {
    let babel_port = SETTING.get_network().babel_port;
    let local_fee = SETTING.get_payment().local_fee;
    let metric_factor = SETTING.get_network().metric_factor;
    Arbiter::spawn(
        open_babel_stream(babel_port)
            .from_err()
            .and_then(move |stream| {
                start_connection(stream).and_then(move |stream| {
                    set_local_fee(stream, local_fee)
                        .and_then(move |stream| Ok(set_metric_factor(stream, metric_factor)))
                })
            })
            .timeout(SLOW_LOOP_TIMEOUT)
            .then(|res| {
                if let Err(e) = res {
                    error!("Failed to set babel price {:?}", e);
                }
                Ok(())
            }),
    )
}
