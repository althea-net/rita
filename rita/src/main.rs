#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use] extern crate log;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate derive_error;

extern crate eui48;
extern crate ip_network;
extern crate simple_logger;
extern crate reqwest;
extern crate minihttpse;
extern crate config;
extern crate docopt;
extern crate actix;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate futures;
extern crate actix_web;
extern crate bytes;

use actix::*;
use actix::registry::SystemService;
use actix_web::*;

extern crate num256;
extern crate althea_kernel_interface;
extern crate babel_monitor;
extern crate althea_types;

mod debt_keeper;
mod payment_controller;
mod tunnel_manager;
mod network_endpoints;
mod traffic_watcher;
mod settings;
mod rita_loop;

use network_endpoints::{make_payments, hello_response};
use settings::SETTING;

fn main() {
    simple_logger::init().unwrap();
    trace!("Starting");
    trace!("Starting with Identity: {:?}", SETTING.get_identity());

    let system = actix::System::new(format!("main {}", SETTING.network.own_ip));

    assert!(debt_keeper::DebtKeeper::from_registry().connected());
    assert!(payment_controller::PaymentController::from_registry().connected());

    HttpServer::new(
        || Application::new()
            .resource("/make_payment", |r| r.h(make_payments))
            .resource("/hello", |r| r.h(hello_response)))
        .bind(format!("[::0]:{}", SETTING.network.rita_port)).unwrap()
        .start();


    let rita = rita_loop::RitaLoop{};
    let _: Address<_> = rita.start();

    system.run();
}