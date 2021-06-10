//! This is the main source file for the Rita exit binary, by 'exit' we mean 'a vpn server, not a
//! mesh router out in the field'.
//!
//! All meshing and billing functionality is contained in `rita_common` and is common to both rita and
//! `rita_exit`. The major difference is billing and connection code for the 'exit', the mandatory
//! vpn system integrated into the Althea network design, as well as API endpoints for a management
//! dashboard of router functions like wifi, which the exit is not expected to have.
//!
//! This file initializes the dashboard endpoints for the exit as well as the common and exit
//! specific actors.

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[cfg(feature = "jemalloc")]
use jemallocator::Jemalloc;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
extern crate phonenumber;

use actix_web::http::Method;
use actix_web::{http, server, App};
use docopt::Docopt;

use settings::exit::RitaExitSettingsStruct;

use rita_common::dashboard::own_info::READABLE_VERSION;
use rita_common::rita_loop::check_rita_common_actors;
use rita_common::rita_loop::start_core_rita_endpoints;
use rita_common::utils::env_vars_contains;
use rita_exit::database::sms::send_admin_notification_sms;
use rita_exit::logging::enable_remote_logging;
use rita_exit::rita_loop::check_rita_exit_actors;
use rita_exit::rita_loop::start_rita_exit_endpoints;
use rita_exit::rita_loop::start_rita_exit_loop;

use rita_common::dashboard::babel::*;
use rita_common::dashboard::debts::*;
use rita_common::dashboard::development::*;
use rita_common::dashboard::nickname::*;
use rita_common::dashboard::own_info::*;
use rita_common::dashboard::settings::*;
use rita_common::dashboard::token_bridge::*;
use rita_common::dashboard::usage::*;
use rita_common::dashboard::wallet::*;
use rita_common::dashboard::wg_key::*;
use rita_common::network_endpoints::*;
use rita_exit::network_endpoints::*;
pub mod middleware;

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
    Version {} - {}
    git hash {}",
        READABLE_VERSION,
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
}

/// used to crash the exit on first startup if config does not make sense
/// as is usually desirable for cloud infrastruture
fn sanity_check_config() {
    let exit_settings = settings::get_rita_exit();
    if !exit_settings.allowed_countries.is_empty()
        && exit_settings.exit_network.geoip_api_key.is_none()
    {
        panic!("GEOIP enforcement configured but not api key provided!");
    }
}

fn main() {
    let args: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // load the settings file, setup a thread to save it out every so often
    // and populate the memory cache of settings used throughout the program
    let settings = {
        let settings_file = args.flag_config;
        let settings = RitaExitSettingsStruct::new_watched(&settings_file).unwrap();

        settings::set_git_hash(env!("GIT_HASH").to_string());

        let settings = clu::exit_init("linux", settings);
        settings::set_rita_exit(settings.clone());
        sanity_check_config();
        println!("Look the exit settings! {:?}", settings);
        settings
    };

    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    openssl_probe::init_ssl_cert_env_vars();

    // An exit setting dictating if this exit operator wants to log remotely or locally
    let should_remote_log = settings.remote_log;
    // if remote logging is disabled, or the NO_REMOTE_LOG env var is set we should use the
    // local logger and log to std-out. Note we don't care what is actually set in NO_REMOTE_LOG
    // just that it is set
    if !should_remote_log || env_vars_contains("NO_REMOTE_LOG") {
        env_logger::init();
    } else {
        let res = enable_remote_logging();
        println!("logging status {:?}", res);
    }

    if cfg!(feature = "development") {
        println!("Warning!");
        println!("This build is meant only for development purposes.");
        println!("Running this on production as an exit node is unsupported and not safe!");
    }

    trace!("Starting");
    info!(
        "crate ver {}, git hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
    trace!("Starting with Identity: {:?}", settings.get_identity());

    send_admin_notification_sms("Exit restarted");

    let system = actix::System::new(format!("main {:?}", settings.network.mesh_ip));

    check_rita_common_actors();
    check_rita_exit_actors();
    start_rita_exit_loop();
    let workers = settings.workers;
    start_core_rita_endpoints(workers as usize);
    start_rita_exit_endpoints(workers as usize);
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
            .route("/metric_factor", Method::GET, get_metric_factor)
            .route("/metric_factor/{factor}", Method::POST, set_metric_factor)
            .route("/settings", Method::GET, get_settings)
            .route("/settings", Method::POST, set_settings)
            .route("/version", Method::GET, version)
            .route("/wg_public_key", Method::GET, get_wg_public_key)
            .route("/wipe", Method::POST, wipe)
            .route("/database", Method::DELETE, nuke_db)
            .route("/debts", Method::GET, get_debts)
            .route("/debts/reset", Method::POST, reset_debt)
            .route("/withdraw/{address}/{amount}", Method::POST, withdraw)
            .route("/withdraw_all/{address}", Method::POST, withdraw_all)
            .route("/nickname/get/", Method::GET, get_nickname)
            .route("/nickname/set/", Method::POST, set_nickname)
            .route("/crash_actors", Method::POST, crash_actors)
            .route("/usage/payments", Method::GET, get_payments)
            .route("/token_bridge/status", Method::GET, get_bridge_status)
    })
    .bind(format!(
        "[::0]:{}",
        settings::get_rita_exit().network.rita_dashboard_port
    ))
    .unwrap()
    .workers(1)
    .shutdown_timeout(0)
    .start();
}
