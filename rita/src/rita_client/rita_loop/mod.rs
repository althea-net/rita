use std::time::Duration;

use actix::prelude::*;
use actix::registry::SystemService;

use rita_client::exit_manager::ExitManager;

use failure::Error;

pub struct RitaLoop;

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        ctx.notify_later(Tick {}, Duration::from_secs(5));
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
                .then(|res, _act, ctx| {
                    trace!("exit manager said {:?}", res);
                    ctx.notify_later(Tick {}, Duration::from_secs(10));
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
