#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use] extern crate log;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate derive_error;
#[macro_use] extern crate rouille;

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
use actix::prelude::*;
use actix::fut::*;
use futures::Future;

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

use settings::SETTING;

fn main() {
    simple_logger::init().unwrap();
    trace!("Starting");
    trace!("Starting with Identity: {:?}", SETTING.get_identity());

    let system = actix::System::new(format!("main {}", SETTING.network.own_ip));

    let rita = rita_loop::RitaLoop{};
    let loop_addr: Address<_> = rita.start();

    loop_addr.do_send(rita_loop::Tick);

    system.run();
}