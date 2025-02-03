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

use althea_types::Identity;
use clarity::Address;
use exit_trust_root::client_db::get_all_registered_clients;
#[cfg(feature = "jemalloc")]
use jemallocator::Jemalloc;
use rita_exit::rita_loop::start_rita_exit_list_endpoint;
use rita_exit::ClientListAnIpAssignmentMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[macro_use]
extern crate log;

use docopt::Docopt;
use rita_common::debt_keeper::save_debt_on_shutdown;
use rita_common::logging::enable_remote_logging;
use rita_common::rita_loop::get_web3_server;
use rita_common::rita_loop::start_core_rita_endpoints;
use rita_common::rita_loop::start_rita_common_loops;
use rita_common::rita_loop::write_to_disk::save_to_disk_loop;
use rita_common::rita_loop::write_to_disk::SettingsOnDisk;
use rita_common::usage_tracker::save_usage_on_shutdown;
use rita_common::utils::apply_babeld_settings_defaults;
use rita_common::utils::env_vars_contains;
use rita_exit::dashboard::start_rita_exit_dashboard;
use rita_exit::operator_update::update_loop::start_operator_update_loop;
use rita_exit::rita_loop::start_rita_exit_endpoints;
use rita_exit::rita_loop::start_rita_exit_loop;
use rita_exit::{get_exit_usage, Args};
use settings::exit::RitaExitSettingsStruct;
use settings::save_settings_on_shutdown;
use web30::jsonrpc::error::Web3Error;

/// used to crash the exit on first startup if config does not make sense
/// as is usually desirable for cloud infrastruture
fn sanity_check_config() {
    let exit_settings = settings::get_rita_exit();
    if !exit_settings.allowed_countries.is_empty()
        && exit_settings.exit_network.geoip_api_key.is_none()
    {
        panic!("GEOIP enforcement configured but not api key provided!");
    }
    if !exit_settings.validate() {
        panic!("Invalid settings file!");
    }
}

#[actix_rt::main]
async fn main() {
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
        let settings = RitaExitSettingsStruct::new_watched(settings_file.clone()).unwrap();

        settings::set_flag_config(settings_file.clone());

        if !settings.validate() {
            panic!("Invalid settings file!")
        }

        let settings = clu::exit_init(settings);
        settings::set_rita_exit(settings.clone());
        sanity_check_config();
        println!("Look the exit settings! {settings:?}");
        settings
    };
    apply_babeld_settings_defaults(
        settings.network.babel_port,
        settings.network.babeld_settings,
    );

    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    openssl_probe::probe();

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

    // This lock will be shared between this thread and the dashboard thread, it will be
    // set to true one the exit has started up and is ready to serve traffic. Before that
    // it will show error messages on the dashboard to assist with setup.
    let startup_status = Arc::new(RwLock::new(Some(String::from("Preparing to start"))));
    start_rita_exit_dashboard(startup_status.clone());

    // Exits require the ability to query the blockchain to setup the user list, they also need to
    // have a backend database contract to store user data. Exits always have backhaul internet
    // otherwise they wouldn't be able to exit traffic out to the internet.
    //
    // This function will hold the program here until we have confirmed that everything is in good shape
    // and perform startup
    let clients =
        check_startup_balance_and_contract(args.flag_fail_on_startup, startup_status).await;

    let workers = settings.workers;

    let client_and_ip_map = Arc::new(RwLock::new(ClientListAnIpAssignmentMap::new(
        clients,
        settings.exit_network.ipv6_routing,
        settings.exit_network.ipv4_routing,
        settings.exit_network.internal_ipv4,
    )));

    start_core_rita_endpoints(workers as usize);
    start_rita_exit_endpoints(client_and_ip_map.clone());
    start_rita_exit_list_endpoint();

    start_rita_common_loops();
    start_operator_update_loop();
    save_to_disk_loop(SettingsOnDisk::RitaExitSettingsStruct(Box::new(
        settings::get_rita_exit(),
    )));

    // this call blocks, transforming this startup thread into the main exit watchdog thread
    start_rita_exit_loop(client_and_ip_map).await;
}

/// This function performs startup integrity checks on the config and system. It checks that we can reach the internet
/// reach the provided full node, query the provided contract and that the provided address has a balance. By the time this
/// function returns we have the list of users and are ready to start the exit and forward traffic to the outside world.
///
/// This function will hold the program here until we have confirmed that everything is in good shape sening error messages
/// using the startup_status RwLock to the dashboard to assist with setup.If the fail_on_startup flag is set the program will
/// exit immediately if any of these checks fail.
async fn check_startup_balance_and_contract(
    fail_on_startup: bool,
    startup_status: Arc<RwLock<Option<String>>>,
) -> HashSet<Identity> {
    let payment_settings = settings::get_rita_common().payment;
    let our_address = payment_settings.eth_address.expect("No address!");

    // spin here until basic conditions are met
    while check_balance(our_address, startup_status.clone())
        .await
        .is_err()
    {
        if fail_on_startup {
            std::process::exit(1);
        }
    }

    // Next we actually get the list of users
    let mut users = get_registered_users().await;
    while let Err(e) = users {
        let error_message = format!("Failed to get registered users with error {:?}. Check your configured Registered Users Contract Address!", e);
        error!("{error_message}");
        startup_status
            .write()
            .unwrap()
            .replace(error_message.clone());
        if fail_on_startup {
            std::process::exit(1);
        }
        users = get_registered_users().await;
    }

    users.unwrap()
}

async fn get_registered_users() -> Result<HashSet<Identity>, Web3Error> {
    let payment_settings = settings::get_rita_common().payment;
    let our_address = payment_settings.eth_address.expect("No address!");
    let full_node = get_web3_server();
    let web3 = web30::client::Web3::new(&full_node, Duration::from_secs(5));
    let contract_address = settings::get_rita_exit()
        .exit_network
        .registered_users_contract_addr;
    get_all_registered_clients(&web3, our_address, contract_address).await
}

async fn check_balance(
    our_address: Address,
    startup_status: Arc<RwLock<Option<String>>>,
) -> Result<(), String> {
    let full_node = get_web3_server();
    let web3 = web30::client::Web3::new(&full_node, Duration::from_secs(5));
    let res = web3.eth_get_balance(our_address).await;
    match res {
        Ok(balance) => {
            if balance == 0u8.into() {
                let error_message = format!(
                    "Rita Exit requires a balance to start, please fund your address {} with a small amount and restart",
                    our_address
                );
                startup_status
                    .write()
                    .unwrap()
                    .replace(error_message.clone());
                Err(error_message)
            } else {
                Ok(())
            }
        }
        Err(e) => {
            let error_message = format!(
                "Failed to get balance for account with error {:?}, Check backhaul network configuration and configured full node RPC",
                e
            );
            error!("{error_message}");
            startup_status
                .write()
                .unwrap()
                .replace(error_message.clone());
            Err(error_message)
        }
    }
}
