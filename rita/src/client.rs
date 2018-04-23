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
extern crate clu;
extern crate docopt;
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

use docopt::Docopt;
use settings::{FileWrite, RitaCommonSettings, RitaSettingsStruct};

use actix::registry::SystemService;
use actix::*;
use actix_web::*;

use std::sync::{Arc, Mutex, RwLock};

extern crate althea_kernel_interface;
extern crate althea_types;
extern crate babel_monitor;
extern crate num256;

mod rita_client;
mod rita_common;

use rita_client::network_endpoints::setup_exit;
use rita_common::dashboard::network_endpoints::{get_node_info, get_wifi_config, set_wifi_config};
use rita_common::network_endpoints::{hello_response, make_payments};

const USAGE: &str = "
Usage: rita --config <settings> --platform <platform>
Options:
    --config   Name of config file
    --platform   Platform (linux or openwrt)
";

use althea_kernel_interface::{KernelInterface, LinuxCommandRunner, TestCommandRunner};

#[cfg(test)]
lazy_static! {
    pub static ref KI: Box<KernelInterface> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|program, args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(not(test))]
lazy_static! {
    pub static ref KI: Box<KernelInterface> = Box::new(LinuxCommandRunner {});
}

#[cfg(not(test))]
lazy_static! {
    pub static ref SETTING: Arc<RwLock<RitaSettingsStruct>> = {
        let args = Docopt::new(USAGE)
            .and_then(|d| d.parse())
            .unwrap_or_else(|e| e.exit());

        let settings_file = args.get_str("<settings>");
        let platform = args.get_str("<platform>");

        let s = RitaSettingsStruct::new_watched(settings_file).unwrap();

        clu::init(platform, s.clone());

        s.read().unwrap().write(settings_file).unwrap();
        s
    };
}

#[cfg(test)]
lazy_static! {
    pub static ref SETTING: Arc<RwLock<RitaSettingsStruct>> =
        { Arc::new(RwLock::new(RitaSettingsStruct::default())) };
}

fn main() {
    env_logger::init();
    trace!("Starting");
    trace!("Starting with Identity: {:?}", SETTING.get_identity());

    let system = actix::System::new(format!("main {}", SETTING.get_network().own_ip));

    assert!(rita_common::debt_keeper::DebtKeeper::from_registry().connected());
    assert!(rita_common::payment_controller::PaymentController::from_registry().connected());
    assert!(rita_common::tunnel_manager::TunnelManager::from_registry().connected());
    assert!(rita_common::http_client::HTTPClient::from_registry().connected());
    assert!(rita_common::traffic_watcher::TrafficWatcher::from_registry().connected());
    assert!(rita_client::exit_manager::ExitManager::from_registry().connected());

    // rita
    server::new(|| {
        App::new()
            .resource("/make_payment", |r| r.h(make_payments))
            .resource("/hello", |r| r.h(hello_response))
    }).threads(1)
        .bind(format!("[::0]:{}", SETTING.get_network().rita_hello_port))
        .unwrap()
        .start();

    // dashboard
    server::new(|| {
        App::new()
            .resource("/wifisettings", |r| {
                r.route().filter(pred::Get()).h(get_wifi_config)
            })
            .resource("/wifisettings", |r| {
                r.route().filter(pred::Post()).h(set_wifi_config)
            })
            .resource("/neighbors", |r| r.h(get_node_info))
            .resource("/exit_setup", |r| r.h(setup_exit))
    }).threads(1)
        .bind(format!(
            "[::0]:{}",
            SETTING.get_network().rita_dashboard_port
        ))
        .unwrap()
        .start();

    let common = rita_common::rita_loop::RitaLoop {};
    let _: Addr<Unsync, _> = common.start();

    let client = rita_client::rita_loop::RitaLoop {};
    let _: Addr<Unsync, _> = client.start();

    system.run();
}
