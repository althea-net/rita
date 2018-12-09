//! This is the primary actor loop for rita-client, where periodic tasks are spawed and Actors are
//! tied together with message calls.
//!
//! This loop manages exit signup based on the settings configuration state and deploys an exit vpn
//! tunnel if the signup was successful on the selected exit.

use std::time::{Duration, Instant};

use ::actix::prelude::*;
use ::actix::registry::SystemService;

use crate::rita_client::exit_manager::ExitManager;

use failure::Error;

pub struct RitaLoop;

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
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
        let start = Instant::now();
        trace!("Client Tick!");

        ctx.spawn(
            ExitManager::from_registry()
                .send(Tick {})
                .into_actor(self)
                .then(|res, _act, _ctx| {
                    trace!("exit manager said {:?}", res);
                    actix::fut::ok(())
                }),
        );

        info!(
            "Rita Client loop completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_nanos() / 1000000
        );
        Ok(())
    }
}
