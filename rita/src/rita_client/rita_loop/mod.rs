use std::time::{Duration, Instant};
use std::thread;
use std::path::Path;

use actix::prelude::*;
use actix::registry::SystemService;

use serde_json;

use babel_monitor::Babel;

use rita_client::exit_manager::ExitManager;

use rita_common::debt_keeper;
use rita_common::debt_keeper::DebtKeeper;

use rita_common::payment_controller;
use rita_common::payment_controller::{MakePayment, PaymentController};

use rita_common;

use failure::Error;

use SETTING;
use althea_kernel_interface::KernelInterface;

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
        trace!("Client Tick!");

        ctx.spawn(
            ExitManager::from_registry()
                .send(Tick {})
                .into_actor(self)
                .then(|res, act, ctx| {
                    trace!("exit manager said {:?}", res);
                    actix::fut::ok(())
                }),
        );

        ctx.notify_later(Tick {}, Duration::from_secs(5));

        Ok(())
    }
}
