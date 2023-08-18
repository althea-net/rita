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
extern crate log;

use docopt::Docopt;
use rita_common::debt_keeper::save_debt_on_shutdown;
use rita_common::logging::enable_remote_logging;
use rita_common::rita_loop::start_core_rita_endpoints;
use rita_common::rita_loop::start_rita_common_loops;
use rita_common::rita_loop::write_to_disk::save_to_disk_loop;
use rita_common::rita_loop::write_to_disk::SettingsOnDisk;
use rita_common::usage_tracker::save_usage_on_shutdown;
use rita_common::utils::env_vars_contains;
use rita_exit::operator_update::update_loop::start_operator_update_loop;
use rita_exit::rita_loop::start_rita_exit_endpoints;
use rita_exit::rita_loop::start_rita_exit_loop;
use rita_exit::start_rita_exit_dashboard;
use rita_exit::{get_exit_usage, Args};
use settings::exit::RitaExitSettingsStruct;
use settings::save_settings_on_shutdown;

/// used to crash the exit on first startup if config does not make sense
/// as is usually desirable for cloud infrastruture
fn sanity_check_config() {
    let exit_settings = settings::get_rita_exit();
    if !exit_settings.allowed_countries.is_empty()
        && exit_settings.exit_network.geoip_api_key.is_none()
    {
        panic!("GEOIP enforcement configured but not api key provided!");
    }

    // check wg_exit_v2 port is valid
    assert!(exit_settings.exit_network.wg_v2_tunnel_port < 59999);
}

fn main() {
    //Setup a SIGTERM hadler
    ctrlc::set_handler(move || {
        info!("received Ctrl+C!");
        save_debt_on_shutdown();
        save_usage_on_shutdown();
        save_settings_on_shutdown();

        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let args: Args = Docopt::new(get_exit_usage(env!("CARGO_PKG_VERSION"), env!("GIT_HASH")))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // load the settings file, setup a thread to save it out every so often
    // and populate the memory cache of settings used throughout the program
    let settings = {
        let settings_file = args.flag_config;
        let settings = RitaExitSettingsStruct::new_watched(&settings_file).unwrap();

        let settings = clu::exit_init("linux", settings);
        settings::set_rita_exit(settings.clone());
        sanity_check_config();
        println!("Look the exit settings! {settings:?}");
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
        let logging_url: String = "https://stats.altheamesh.com:9999/compressed_sink".into();
        let level: String = "INFO".to_string();

        let key = settings
            .network
            .wg_public_key
            .expect("Tried to init remote logging without WgKey!");

        let res =
            enable_remote_logging("rita_exit".to_string(), logging_url, level, key.to_string());
        println!("logging status {res:?}");
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

    let system = actix_async::System::new();

    start_rita_common_loops();
    start_rita_exit_loop();
    start_operator_update_loop();
    save_to_disk_loop(SettingsOnDisk::RitaExitSettingsStruct(Box::new(
        settings::get_rita_exit(),
    )));

    let workers = settings.workers;
    start_core_rita_endpoints(workers as usize);
    start_rita_exit_endpoints(workers as usize);
    start_rita_exit_dashboard();

    if let Err(e) = system.run() {
        error!("Starting Exit failed with {}", e);
    }

    info!("Started rita Exit");
}
