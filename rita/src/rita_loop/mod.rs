use std::time::Duration;
use std::thread;

use futures::{Future, future};
use actix::prelude::*;
use actix::registry::SystemService;

use serde_json;

use babel_monitor::Babel;
use tunnel_manager::TunnelManager;
use traffic_watcher;

use debt_keeper;
use debt_keeper::DebtKeeper;

use payment_controller;
use payment_controller::PaymentController;

use settings::SETTING;
use althea_kernel_interface::KernelInterface;

use network_endpoints::{make_payments};

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

#[derive(Message)]
pub struct Tick;

impl Handler<Tick> for RitaLoop {
    type Result = ();
    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        trace!("Tick!");

        let mut ki = KernelInterface {};
        let mut tm = TunnelManager::new();
        let mut babel = Babel::new(&format!("[::1]:{}", SETTING.network.babel_port).parse().unwrap());

        let neighbors = tm.get_neighbors().unwrap();
        info!("got neighbors: {:?}", neighbors);

        let debts = traffic_watcher::watch(neighbors, &mut ki, &mut babel).unwrap();
        info!("got debts: {:?}", debts);

        for (from, amount) in debts {
            let update = debt_keeper::TrafficUpdate { from, amount };
            let adjustment = debt_keeper::SendUpdate { from };

            Arbiter::handle().spawn(
                DebtKeeper::from_registry().send(update).then(
                    move |_| {
                        DebtKeeper::from_registry().do_send(adjustment);
                        future::result(Ok(()))
                    }));
        }
        PaymentController::from_registry().do_send(payment_controller::PaymentControllerUpdate);

        ctx.run_later(Duration::from_secs(5), |act, ctx| {
            let addr: Address<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}