//! This is the main source file for the Rita extender binary
//!
//! This binary takes wifi settings from a master router its connected to and
//! applies them locally

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate log;

use rita_client::extender::get_device_mac;
use rita_client::extender::ExtenderUpdate;
use rita_common::logging::enable_remote_logging;
use rita_common::utils::env_vars_contains;
use rita_extender::dashboard::start_extender_dashboard;
use rita_extender::extender_checkin;
use rita_extender::get_checkin_message;
use rita_extender::start_rita_extender_loop;
use rita_extender::DEFAULT_UPSTREAM_ENDPOINT;

const DEFAULT_DASHBOARD_PORT: u16 = 4877;

fn main() {
    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    unsafe {
        openssl_probe::init_openssl_env_vars();
    }

    // Connect to router and get its revevant info. Called here to get logging info
    let setting = get_initial_logging_settings();
    println!("Initial checkin returned {setting:?}");

    // we should remote log if there's an operator address or if logging is enabled. If we are unable to query
    // the router for remote logging, default to local logging
    let mut logging_url: String = "https://stats.altheamesh.com:9999/compressed_sink".into();
    let mut level: String = "INFO".to_string();
    let mut wgkey: String = format!("{:x}", get_device_mac());
    let mut dashboard_port = DEFAULT_DASHBOARD_PORT;

    let should_remote_log = if let Some(setting) = setting {
        logging_url = setting.logging_settings.dest_url;
        level = setting.logging_settings.level;
        if let Some(key) = setting.additional_settings.wg_key {
            wgkey = key.to_string();
        }
        dashboard_port = setting.additional_settings.rita_dashboard_port;
        setting.logging_settings.enabled || setting.additional_settings.operator_addr.is_some()
    } else {
        false
    };
    // if remote logging is disabled, or the NO_REMOTE_LOG env var is set we should use the
    // local logger and log to std-out. Note we don't care what is actually set in NO_REMOTE_LOG
    // just that it is set
    if !should_remote_log || env_vars_contains("NO_REMOTE_LOG") {
        env_logger::init();
    } else {
        let res = enable_remote_logging("rita_extender".to_string(), logging_url, level, wgkey);

        println!("logging status {res:?}");
    }

    info!(
        "extender crate ver {}, git hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );

    let system = actix::System::new();

    start_rita_extender_loop();
    start_extender_dashboard(dashboard_port);

    if let Err(e) = system.run() {
        error!("Starting extender failed with {}", e);
    }

    info!("Started Rita Extender!");
}

#[actix_rt::main]
async fn get_initial_logging_settings() -> Option<ExtenderUpdate> {
    println!("Trying to perform initial checkin with {DEFAULT_UPSTREAM_ENDPOINT}");
    if let Ok(a) = extender_checkin(DEFAULT_UPSTREAM_ENDPOINT.into(), get_checkin_message()).await {
        return Some(a);
    }
    None
}
