//! This is the main source file for the Rita exit binary, by 'exit' we mean 'a vpn server, not a
//! mesh router out in the field'.
//!
//! All meshing and billing functionaltiy is contained in `rita_common` and is common to both rita and
//! `rita_exit`. The major difference is billing and connection code for the 'exit', the mandatory
//! vpn system integrated into the Althea network design, as well as API endpoints for a management
//! dashboard of router functions like wifi, which the exit is not expected to have.
//!
//! This file initilizes the dashboard endpoints for the exit as well as the common and exit
//! specific actors.

#![cfg_attr(feature = "system_alloc", feature(alloc_system, allocator_api))]
#![warn(clippy::all)]
#![allow(clippy::pedantic)]

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
#[macro_use]
extern crate serde_json;

use env_logger;

use openssl_probe;

use settings::exit::{RitaExitSettings, RitaExitSettingsStruct};
use settings::RitaCommonSettings;

use docopt::Docopt;
#[cfg(not(test))]
use settings::FileWrite;

use actix::registry::SystemService;
use actix::*;
use actix_web::http::Method;
use actix_web::{http, server, App};

pub mod actix_utils;
mod middleware;
mod rita_common;
mod rita_exit;

use crate::rita_common::dashboard::babel::*;
use crate::rita_common::dashboard::dao::*;
use crate::rita_common::dashboard::debts::*;
use crate::rita_common::dashboard::development::*;
use crate::rita_common::dashboard::own_info::*;
use crate::rita_common::dashboard::pricing::*;
use crate::rita_common::dashboard::settings::*;
use crate::rita_common::dashboard::wallet::*;

use crate::rita_common::network_endpoints::*;
use crate::rita_exit::network_endpoints::*;

use std::sync::{Arc, RwLock};

#[cfg(test)]
use std::sync::Mutex;

#[derive(Debug, Deserialize, Default)]
pub struct Args {
    flag_config: String,
    flag_future: bool,
}

lazy_static! {
    static ref USAGE: String = format!(
        "Usage: rita_exit --config=<settings>
Options:
    -c, --config=<settings>   Name of config file
    --future                    Enable B side of A/B releases
About:
    Version {}
    git hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
}

use althea_kernel_interface::KernelInterface;

#[cfg(not(test))]
use althea_kernel_interface::LinuxCommandRunner;
#[cfg(test)]
use althea_kernel_interface::TestCommandRunner;

#[cfg(test)]
lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|_program, _args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(test)]
lazy_static! {
    pub static ref ARGS: Args = Args::default();
}

#[cfg(not(test))]
lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
}

#[cfg(not(test))]
lazy_static! {
    pub static ref ARGS: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
}

#[cfg(not(test))]
lazy_static! {
    pub static ref SETTING: Arc<RwLock<RitaExitSettingsStruct>> = {
        let settings_file = &ARGS.flag_config;

        let s = RitaExitSettingsStruct::new_watched(settings_file).unwrap();

        s.set_future(ARGS.flag_future);

        clu::exit_init("linux", s.clone());

        s.read().unwrap().write(settings_file).unwrap();

        s
    };
}

#[cfg(test)]
lazy_static! {
    pub static ref SETTING: Arc<RwLock<RitaExitSettingsStruct>> =
        { Arc::new(RwLock::new(RitaExitSettingsStruct::default())) };
}

fn main() {
    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    openssl_probe::init_ssl_cert_env_vars();
    env_logger::init();

    if cfg!(feature = "development") {
        println!("Warning!");
        println!("This build is meant only for development purposes.");
        println!("Running this on production as an exit node is unsupported and not safe!");
    }

    let args: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let settings_file = args.flag_config;

    // to get errors before lazy static
    RitaExitSettingsStruct::new(&settings_file).expect("Settings parse failure");

    trace!("Starting");
    info!(
        "crate ver {}, git hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
    trace!("Starting with Identity: {:?}", SETTING.get_identity());

    let system = actix::System::new(format!("main {:?}", SETTING.get_network().mesh_ip));

    assert!(rita_common::debt_keeper::DebtKeeper::from_registry().connected());
    assert!(rita_common::payment_controller::PaymentController::from_registry().connected());
    assert!(rita_common::payment_validator::PaymentValidator::from_registry().connected());
    assert!(rita_common::tunnel_manager::TunnelManager::from_registry().connected());
    assert!(rita_common::hello_handler::HelloHandler::from_registry().connected());
    assert!(rita_common::traffic_watcher::TrafficWatcher::from_registry().connected());
    assert!(rita_common::peer_listener::PeerListener::from_registry().connected());

    assert!(rita_exit::traffic_watcher::TrafficWatcher::from_registry().connected());
    assert!(rita_exit::db_client::DbClient::from_registry().connected());

    server::new(|| App::new().resource("/hello", |r| r.method(Method::POST).with(hello_response)))
        .bind(format!("[::0]:{}", SETTING.get_network().rita_hello_port))
        .unwrap()
        .shutdown_timeout(0)
        .start();
    server::new(|| {
        App::new().resource("/make_payment", |r| {
            r.method(Method::POST).with(make_payments)
        })
    })
    .workers(1)
    .bind(format!("[::0]:{}", SETTING.get_network().rita_contact_port))
    .unwrap()
    .shutdown_timeout(0)
    .start();

    // Exit stuff
    server::new(|| {
        App::new()
            .resource("/setup", |r| r.method(Method::POST).with(setup_request))
            .resource("/status", |r| {
                r.method(Method::POST).with_async(status_request)
            })
            .resource("/list", |r| r.method(Method::POST).with(list_clients))
            .resource("/exit_info", |r| {
                r.method(Method::GET).with(get_exit_info_http)
            })
            .resource("/rtt", |r| r.method(Method::GET).with(rtt))
    })
    .bind(format!(
        "[::0]:{}",
        SETTING.get_exit_network().exit_hello_port
    ))
    .unwrap()
    .shutdown_timeout(0)
    .start();

    // Dashboard
    server::new(|| {
        App::new()
            .middleware(middleware::Headers)
            // assuming exit nodes dont need wifi
            //.resource("/wifisettings", |r| r.route().filter(pred::Get()).h(get_wifi_config))
            //.resource("/wifisettings", |r| r.route().filter(pred::Post()).h(set_wifi_config))
            .route("/info", Method::GET, get_own_info)
            .route("/local_fee", Method::GET, get_local_fee)
            .route("/local_fee/{fee}", Method::POST, set_local_fee)
            .route("/metric_factor", Method::GET, get_metric_factor)
            .route("/metric_factor/{factor}", Method::POST, set_metric_factor)
            .route("/settings", Method::GET, get_settings)
            .route("/settings", Method::POST, set_settings)
            .route("/version", Method::GET, version)
            .route("/wipe", Method::POST, wipe)
            .route("/database", Method::DELETE, nuke_db)
            .route("/debts", Method::GET, get_debts)
            .route("/dao_list", Method::GET, get_dao_list)
            .route("/dao_list/add/{address}", Method::POST, add_to_dao_list)
            .route(
                "/dao_list/remove/{address}",
                Method::POST,
                remove_from_dao_list,
            )
            .route("/withdraw/{address}/{amount}", Method::POST, withdraw)
            .route(
                "/auto_price/enabled/{status}",
                Method::POST,
                set_auto_pricing,
            )
            .route("/auto_price/enabled", Method::GET, auto_pricing_status)
    })
    .bind(format!(
        "[::0]:{}",
        SETTING.get_network().rita_dashboard_port
    ))
    .unwrap()
    .shutdown_timeout(0)
    .start();

    let common = rita_common::rita_loop::RitaLoop::new();
    let _: Addr<_> = common.start();

    let exit = rita_exit::rita_loop::RitaLoop {};
    let _: Addr<_> = exit.start();

    system.run();
}
