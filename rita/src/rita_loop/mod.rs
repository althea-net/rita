use std::time::Duration;
use std::thread;

use futures::{Future, future};
use actix::prelude::*;
use rouille;
use serde_json;

use babel_monitor::Babel;
use tunnel_manager::TunnelManager;
use traffic_watcher;

use debt_keeper;
use debt_keeper::DEBT_KEEPER;

use payment_controller;
use payment_controller::PAYMENT_CONTROLLER;

use settings::SETTING;
use althea_kernel_interface::KernelInterface;

use network_endpoints::make_payments;

pub struct RitaLoop;
impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        assert!(DEBT_KEEPER.connected());
        assert!(PAYMENT_CONTROLLER.connected());
        thread::spawn(move || {
            rouille::start_server(format!("[::0]:{}", SETTING.network.rita_port), move |request| {
                router!(request,
                (POST) (/make_payment) => {
                    make_payments(request)
                },
                (GET) (/hello) => {
                    rouille::Response::text(serde_json::to_string(&SETTING.get_identity()).unwrap())
                },
                _ => rouille::Response::text("404")
            )
            });
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
                DEBT_KEEPER.send(update).then(
                    move |_| {
                        DEBT_KEEPER.do_send(adjustment);
                        future::result(Ok(()))
                    }));
        }
        PAYMENT_CONTROLLER.do_send(payment_controller::PaymentControllerUpdate);

        ctx.run_later(Duration::from_secs(5), |act, ctx| {
            let addr: Address<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}