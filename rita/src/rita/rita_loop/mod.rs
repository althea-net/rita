use std::time::{Duration, Instant};
use std::thread;
use std::path::Path;

use actix::prelude::*;
use actix::registry::SystemService;

use serde_json;

use babel_monitor::Babel;

use rita::tunnel_manager::{GetNeighbors, TunnelManager};

use rita::traffic_watcher::{TrafficWatcher, Watch};

use debt_keeper;
use debt_keeper::DebtKeeper;

use payment_controller;
use payment_controller::{MakePayment, PaymentController};

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

#[derive(Message)]
pub struct Tick;

impl Handler<Tick> for RitaLoop {
    type Result = ();
    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        trace!("Tick!");

        // let mut babel = Babel::new(&format!("[::1]:{}", SETTING.network.babel_port).parse().unwrap());

        let start = Instant::now();

        ctx.spawn(
            TunnelManager::from_registry()
                .send(GetNeighbors)
                .into_actor(self)
                .then(move |res, act, ctx| {
                    info!("got neighbors: {:?}", res);

                    let neigh = Instant::now();

                    TrafficWatcher::from_registry()
                        .send(Watch(res.unwrap().unwrap()))
                        .into_actor(act)
                        .then(move |res, act, ctx| {
                            info!("loop completed in {:?}", start.elapsed());
                            info!("traffic watcher completed in {:?}", neigh.elapsed());
                            ctx.run_later(Duration::from_secs(5), |act, ctx| {
                                let addr: Address<Self> = ctx.address();
                                addr.do_send(Tick);
                            });
                            actix::fut::ok(())
                        })
                }),
        );
    }
}
