use crate::rita_common::dao_manager::DAOManager;
use crate::rita_common::dao_manager::Tick as DAOTick;
use crate::rita_common::oracle::{Oracle, Update};
use crate::rita_common::payment_validator::{PaymentValidator, Validate};
use crate::rita_common::tunnel_manager::{TriggerGC, TunnelManager};
use crate::SETTING;
use actix::{
    Actor, ActorContext, Addr, AsyncContext, Context, Handler, Message, Supervised, SystemService,
};
use failure::Error;
use settings::RitaCommonSettings;
use std::time::Duration;

// the speed in seconds for the common loop
pub const SLOW_LOOP_SPEED: u64 = 60;

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

        // Check payments
        PaymentValidator::from_registry().do_send(Validate());
        // Update blockchain info
        Oracle::from_registry().do_send(Update());

        TunnelManager::from_registry().do_send(TriggerGC(Duration::from_secs(
            SETTING.get_network().tunnel_timeout_seconds,
        )));

        Ok(())
    }
}
