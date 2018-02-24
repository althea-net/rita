use std::time::{Duration, Instant};
use std::thread;
use std::path::Path;

use actix::prelude::*;
use actix::registry::SystemService;

use serde_json;

use babel_monitor::Babel;

use tunnel_manager;
use tunnel_manager::TunnelManager;

use traffic_watcher;
use traffic_watcher::TrafficWatcher;

use debt_keeper;
use debt_keeper::DebtKeeper;

use payment_controller;
use payment_controller::PaymentController;

use SETTING;
use althea_kernel_interface::KernelInterface;

use network_endpoints::make_payments;

pub struct RitaLoop;

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        let mut ki = KernelInterface {};
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

        // let mut babel = Babel::new(&format!("[::1]:{}", SETTING.network.babel_port).parse().unwrap());

        let start = Instant::now();

        ctx.spawn(
            TunnelManager::from_registry()
                .send(tunnel_manager::GetNeighbors)
                .into_actor(self)
                .then(move |res, act, ctx| {
                    info!("got neighbors: {:?}", res);

                    let neigh = Instant::now();

                    TrafficWatcher::from_registry()
                        .send(traffic_watcher::Watch(res.unwrap().unwrap()))
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
