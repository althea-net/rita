//! This is the main source file for the Rita client binary, by 'client' we mean 'not an exit server'
//! all meshing and billing functionality is contained in `rita_common` and is common to both rita and
//! `rita_exit`. The major difference is billing and connection code for the 'exit', the mandatory
//! vpn system integrated into the Althea network design, as well as API endpoints for a management
//! dashboard of router functions like wifi, which the exit is not expected to have.
//!
//! This file initializes the dashboard endpoints for the client as well as the common and client
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
extern crate lazy_static;
#[macro_use]
extern crate log;

use althea_kernel_interface::KernelInterface;
use althea_kernel_interface::LinuxCommandRunner;
use docopt::Docopt;
use rita_client::dashboard::start_client_dashboard;
use rita_client::get_client_usage;
use rita_client::rita_loop::start_antenna_forwarder;
use rita_client::rita_loop::start_rita_client_loops;
use rita_client::rita_loop::update_dns_conf;
use rita_client::rita_loop::update_system_time;
use rita_client::Args;
use rita_common::debt_keeper::save_debt_on_shutdown;
use rita_common::logging::enable_remote_logging;
use rita_common::rita_loop::start_core_rita_endpoints;
use rita_common::rita_loop::start_rita_common_loops;
use rita_common::rita_loop::write_to_disk::save_to_disk_loop;
use rita_common::rita_loop::write_to_disk::SettingsOnDisk;
use rita_common::usage_tracker::save_usage_on_shutdown;
use rita_common::utils::env_vars_contains;
use settings::client::RitaClientSettings;
use settings::save_settings_on_shutdown;
use settings::FileWrite;

lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
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

    // Because Rita clears and sets up new Wireguard Tunnels on every restart Babel, which was attached and listening to
    // the old tunnels is now in an incorrect state. We must either restart babel or empty it's interfaces list so that the newly
    // created wireguard tunnels can be re-added by this instance of Rita. Due to errors in babel (see git history there)
    // restarting is the way to go as removing dead interfaces often does not work
    KI.restart_babel();

    let args: Args = Docopt::new(get_client_usage(
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH"),
    ))
    .and_then(|d| d.deserialize())
    .unwrap_or_else(|e| e.exit());

    let settings_file = args.flag_config;
    println!("Settings file {}", settings_file.display());

    // load the settings file, setup a thread to save it out every so often
    // and populate the memory cache of settings used throughout the program
    let settings: RitaClientSettings = {
        let platform = &args.flag_platform;

        RitaClientSettings::new_watched(settings_file.clone()).unwrap();
        let mut s = settings::get_rita_client();

        settings::set_flag_config(settings_file.clone());

        s.set_future(args.flag_future);

        let s = clu::init(platform, s);

        s.write(settings_file).unwrap();
        settings::set_rita_client(s.clone());
        println!("Look the client settings! {s:?}");
        s
    };

    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    openssl_probe::init_ssl_cert_env_vars();

    // we should remove log if there's an operator address or if logging is enabled
    let should_remote_log = settings.log.enabled || settings.operator.operator_address.is_some();
    // if remote logging is disabled, or the NO_REMOTE_LOG env var is set we should use the
    // local logger and log to std-out. Note we don't care what is actually set in NO_REMOTE_LOG
    // just that it is set
    if !should_remote_log || env_vars_contains("NO_REMOTE_LOG") {
        env_logger::init();
    } else {
        let log = settings.log.clone();
        let key = settings
            .network
            .wg_public_key
            .expect("Tried to init remote logging without WgKey!");

        let res =
            enable_remote_logging("rita".to_string(), log.dest_url, log.level, key.to_string());

        println!("logging status {res:?}");
    }

    if cfg!(feature = "development") {
        println!("Warning!");
        println!("This build is meant only for development purposes.");
        println!("Running this on production is unsupported and not safe!");
    }

    // If we are an an OpenWRT device try and rescue it from update issues
    if KI.is_openwrt() && KI.check_cron().is_err() {
        error!("Failed to setup cron!");
    }

    info!(
        "crate ver {}, git hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
    trace!("Starting with Identity: {:?}", settings.get_identity());

    let system = actix_async::System::new();

    start_rita_common_loops();
    start_rita_client_loops();
    save_to_disk_loop(SettingsOnDisk::RitaClientSettings(Box::new(
        settings::get_rita_client(),
    )));
    start_core_rita_endpoints(4);
    start_client_dashboard(settings.network.rita_dashboard_port);
    start_antenna_forwarder(settings);

    // utility and rescue fucntions, these perform some upgrade or check
    update_dns_conf();
    update_system_time();

    if let Err(e) = system.run() {
        error!("Starting client failed with {}", e);
    }

    info!("Started Rita Client!");
}
