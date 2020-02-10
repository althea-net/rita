use crate::rita_common::dao_manager::DAOManager;
use crate::rita_common::dao_manager::Tick as DAOTick;
use crate::rita_common::simulated_txfee_manager::SimulatedTxFeeManager;
use crate::rita_common::simulated_txfee_manager::Tick as TxFeeTick;
use crate::rita_common::token_bridge::Tick as TokenBridgeTick;
use crate::rita_common::token_bridge::TokenBridge;
use crate::rita_common::tunnel_manager::{TriggerGC, TunnelManager};
use crate::SETTING;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    SystemService,
};
use babel_monitor::open_babel_stream;
use babel_monitor::set_local_fee;
use babel_monitor::set_metric_factor;
use babel_monitor::start_connection;
use failure::Error;
use futures01::future::Future;
use settings::RitaCommonSettings;
use std::time::Duration;
use tokio::util::FutureExt;

// the speed in seconds for the common loop
pub const SLOW_LOOP_SPEED: u64 = 60;
pub const SLOW_LOOP_TIMEOUT: Duration = Duration::from_secs(15);

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

        // Check DAO payments
        DAOManager::from_registry().do_send(DAOTick);

        SimulatedTxFeeManager::from_registry().do_send(TxFeeTick);

        TunnelManager::from_registry().do_send(TriggerGC(Duration::from_secs(
            SETTING.get_network().tunnel_timeout_seconds,
        )));

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
