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
        ctx.run_later(Duration::from_secs(5), |act, ctx| {
            let addr: Address<Self> = ctx.address();
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
        trace!("Tick!");

        ExitManager::from_registry().do_send(Tick {});

        ctx.run_later(Duration::from_secs(5), |act, ctx| {
            let addr: Address<Self> = ctx.address();
            addr.do_send(Tick);
        });

        Ok(())
    }
}
