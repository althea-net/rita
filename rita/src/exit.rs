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

#![warn(clippy::all)]
#![allow(clippy::pedantic)]

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

extern crate phonenumber;

use env_logger;

use openssl_probe;

use settings::exit::{RitaExitSettings, RitaExitSettingsStruct};
use settings::RitaCommonSettings;

use docopt::Docopt;
#[cfg(not(test))]
use settings::FileWrite;

use actix_web::http::Method;
use actix_web::{http, server, App};

mod middleware;
mod rita_common;
mod rita_exit;

use rita_common::rita_loop::check_rita_common_actors;
use rita_common::rita_loop::start_core_rita_endpoints;

use rita_exit::rita_loop::check_rita_exit_actors;
use rita_exit::rita_loop::start_rita_exit_endpoints;

use crate::rita_common::dashboard::babel::*;
use crate::rita_common::dashboard::dao::*;
use crate::rita_common::dashboard::debts::*;
use crate::rita_common::dashboard::development::*;
use crate::rita_common::dashboard::nickname::*;
use crate::rita_common::dashboard::own_info::*;
use crate::rita_common::dashboard::pricing::*;
use crate::rita_common::dashboard::settings::*;
use crate::rita_common::dashboard::usage::*;
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
        { Arc::new(RwLock::new(RitaExitSettingsStruct::test_default())) };
}

/// used to crash the exit on first startup if config does not make sense
/// as is usually desirable for cloud infrastruture
fn sanity_check_config() {
    if !SETTING.get_allowed_countries().is_empty()
        && SETTING.get_exit_network().geoip_api_key.is_none()
    {
        panic!("GEOIP enforcement configured but not api key provided!");
    }
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
    sanity_check_config();

    let system = actix::System::new(format!("main {:?}", SETTING.get_network().mesh_ip));

    check_rita_common_actors();
    check_rita_exit_actors();
    start_core_rita_endpoints(8);
    start_rita_exit_endpoints(128);
    start_rita_exit_dashboard();

    system.run();
}

fn start_rita_exit_dashboard() {
    // Dashboard
    server::new(|| {
        App::new()
            .middleware(middleware::Headers)
            .route("/info", Method::GET, get_own_info)
            .route("/local_fee", Method::GET, get_local_fee)
            .route("/local_fee/{fee}", Method::POST, set_local_fee)
            .route("/dao_fee", Method::GET, get_dao_fee)
            .route("/dao_fee/{fee}", Method::POST, set_dao_fee)
            .route("/metric_factor", Method::GET, get_metric_factor)
            .route("/metric_factor/{factor}", Method::POST, set_metric_factor)
            .route("/settings", Method::GET, get_settings)
            .route("/settings", Method::POST, set_settings)
            .route("/version", Method::GET, version)
            .route("/wipe", Method::POST, wipe)
            .route("/database", Method::DELETE, nuke_db)
            .route("/debts", Method::GET, get_debts)
            .route("/debts/reset", Method::POST, reset_debt)
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
            .route("/nickname/get/", Method::GET, get_nickname)
            .route("/nickname/set/", Method::POST, set_nickname)
            .route("/crash_actors", Method::POST, crash_actors)
            .route("/usage/payments", Method::GET, get_payments)
    })
    .bind(format!(
        "[::0]:{}",
        SETTING.get_network().rita_dashboard_port
    ))
    .unwrap()
    .workers(1)
    .shutdown_timeout(0)
    .start();
}
