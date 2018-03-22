#![cfg_attr(feature = "system_alloc", feature(alloc_system, global_allocator, allocator_api))]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

#[cfg(feature = "system_alloc")]
extern crate alloc_system;

#[cfg(feature = "system_alloc")]
use alloc_system::System;

#[cfg(feature = "system_alloc")]
#[global_allocator]
static A: System = System;

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

extern crate actix;
extern crate actix_web;
extern crate bytes;
extern crate docopt;
extern crate dotenv;
extern crate env_logger;
extern crate eui48;
extern crate futures;
extern crate ip_network;
extern crate minihttpse;
extern crate rand;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate settings;
extern crate tokio;

use settings::RitaExitSettings;
use docopt::Docopt;

use actix::*;
use actix::registry::SystemService;
use actix_web::*;

extern crate althea_kernel_interface;
extern crate althea_types;
extern crate babel_monitor;
extern crate exit_db;
extern crate num256;

mod rita_exit;
mod rita_common;

use rita_common::network_endpoints::{hello_response, make_payments};
use rita_exit::network_endpoints::setup_request;

use std::sync::{Arc, RwLock};

const USAGE: &str = "
Usage: rita_common --config <settings> --default <default>
Options:
    --config   Name of config file
    --default   Name of default config file
";

lazy_static! {
    pub static ref SETTING: Arc<RwLock<RitaExitSettings>> = {
        let args = Docopt::new(USAGE)
            .and_then(|d| d.parse())
            .unwrap_or_else(|e| e.exit());

        let settings_file = args.get_str("<settings>");
        let defaults_file = args.get_str("<default>");

        let s = RitaExitSettings::new_watched(settings_file, defaults_file).unwrap();
        s.read().unwrap().write(settings_file).unwrap();
        s
    };
}

fn main() {
    env_logger::init();
    trace!("Starting");
    trace!(
        "Starting with Identity: {:?}",
        SETTING.read().unwrap().get_identity()
    );

    let system = actix::System::new(format!("main {}", SETTING.read().unwrap().network.own_ip));

    assert!(rita_common::debt_keeper::DebtKeeper::from_registry().connected());
    assert!(rita_common::payment_controller::PaymentController::from_registry().connected());
    assert!(rita_common::tunnel_manager::TunnelManager::from_registry().connected());
    assert!(rita_common::http_client::HTTPClient::from_registry().connected());
    assert!(rita_common::traffic_watcher::TrafficWatcher::from_registry().connected());

    assert!(rita_exit::traffic_watcher::TrafficWatcher::from_registry().connected());
    assert!(rita_exit::db_client::DbClient::from_registry().connected());

    HttpServer::new(|| {
        Application::new()
            // Client stuff
            .resource("/make_payment", |r| r.h(make_payments))
            .resource("/hello", |r| r.h(hello_response))
            // Exit stuff
            .resource("/setup", |r| r.h(setup_request))
    }).bind(format!(
        "[::0]:{}",
        SETTING.read().unwrap().network.rita_port
    ))
        .unwrap()
        .start();

    let common = rita_common::rita_loop::RitaLoop::new();
    let _: Addr<Unsync, _> = common.start();

    let exit = rita_exit::rita_loop::RitaLoop {};
    let _: Addr<Unsync, _> = exit.start();

    system.run();
}
