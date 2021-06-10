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

use antenna_forwarding_client::start_antenna_forwarding_proxy;
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
extern crate arrayvec;

use actix_web::http::Method;
use actix_web::{http, server, App};
use docopt::Docopt;
use rita_client::logging::enable_remote_logging;
use rita_client::rita_loop::metrics_permitted;
use settings::client::RitaClientSettings;
use std::env;
use std::time::{Duration, Instant};

use settings::FileWrite;

use rita_client::rita_loop::check_rita_client_actors;
use rita_client::rita_loop::start_rita_client_endpoints;
use rita_common::dashboard::own_info::READABLE_VERSION;
use rita_common::rita_loop::check_rita_common_actors;
use rita_common::rita_loop::start_core_rita_endpoints;
use rita_common::utils::env_vars_contains;

use althea_kernel_interface::KernelInterface;
use althea_kernel_interface::LinuxCommandRunner;
use rita_client::dashboard::auth::*;
use rita_client::dashboard::backup_created::*;
use rita_client::dashboard::bandwidth_limit::*;
use rita_client::dashboard::contact_info::*;
use rita_client::dashboard::eth_private_key::*;
use rita_client::dashboard::exits::*;
use rita_client::dashboard::installation_details::*;
use rita_client::dashboard::interfaces::*;
use rita_client::dashboard::localization::*;
use rita_client::dashboard::logging::*;
use rita_client::dashboard::mesh_ip::*;
use rita_client::dashboard::neighbors::*;
use rita_client::dashboard::notifications::*;
use rita_client::dashboard::operator::*;
use rita_client::dashboard::prices::*;
use rita_client::dashboard::release_feed::*;
use rita_client::dashboard::remote_access::*;
use rita_client::dashboard::router::*;
use rita_client::dashboard::system_chain::*;
use rita_client::dashboard::usage::*;
use rita_client::dashboard::wifi::*;
use rita_client::heartbeat::HEARTBEAT_SERVER_KEY;
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
mod middleware;

#[derive(Debug, Deserialize, Default)]
pub struct Args {
    flag_config: String,
    flag_platform: String,
    flag_future: bool,
}

// TODO we should remove --platform as it's not used, but that requires
// changing how rita is invoked everywhere, because that's difficult
// with in the field routers this is waiting on another more pressing
// upgrade to the init file for Rita on the routers
lazy_static! {
    static ref USAGE: String = format!(
        "Usage: rita --config=<settings> --platform=<platform> [--future]
Options:
    -c, --config=<settings>     Name of config file
    -p, --platform=<platform>   Platform (linux or OpenWrt)
    --future                    Enable B side of A/B releases
About:
    Version {} - {}
    git hash {}",
        READABLE_VERSION,
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
}

lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
}

/// Some devices (n600/n750) will provide junk file reads during disk init
/// post flashing, this adds in retry for the settings file read for up to
/// two minutes
fn wait_for_settings(settings_file: &str) -> RitaClientSettings {
    let start = Instant::now();
    let timeout = Duration::from_secs(120);
    let mut res = RitaClientSettings::new(settings_file);
    while (Instant::now() - start) < timeout {
        if let Ok(val) = res {
            return val;
        }
        res = RitaClientSettings::new(settings_file);
    }
    match res {
        Ok(val) => val,
        Err(e) => panic!("Settings parse failure {:?}", e),
    }
}

fn main() {
    let args: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let settings_file = args.flag_config;
    wait_for_settings(&settings_file);

    // load the settings file, setup a thread to save it out every so often
    // and populate the memory cache of settings used throughout the program
    let settings: RitaClientSettings = {
        let platform = &args.flag_platform;

        let mut s = RitaClientSettings::new_watched(&settings_file).unwrap();

        settings::set_flag_config(settings_file.to_string());

        settings::set_git_hash(env!("GIT_HASH").to_string());

        s.set_future(args.flag_future);

        let s = clu::init(platform, s);

        s.write(&settings_file).unwrap();
        settings::set_rita_client(s.clone());
        println!("Look the client settings! {:?}", s);
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
        let res = enable_remote_logging();
        println!("logging status {:?}", res);
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

    let system = actix::System::new(format!("main {:?}", settings.network.mesh_ip));

    check_rita_common_actors();
    check_rita_client_actors();
    start_core_rita_endpoints(4);
    start_rita_client_endpoints(1);
    start_client_dashboard();
    start_antenna_forwarder(settings);

    system.run();
    info!("Started Rita Client!");
}

/// starts the antenna forwarder, this is a logically independent set of code
/// that does not care about anything else Rita is doing, it only deals with the
/// actual physical interfaces and attempting to find antennas to forward on them.
fn start_antenna_forwarder(settings: RitaClientSettings) {
    if metrics_permitted() {
        #[cfg(not(feature = "operator_debug"))]
        let url = "operator.althea.net:33334";
        #[cfg(feature = "operator_debug")]
        let url = "192.168.10.2:33334";

        let our_id = settings.get_identity().unwrap();
        let network = settings.network;
        let mut interfaces = network.peer_interfaces.clone();
        interfaces.insert("br-pbs".to_string());
        start_antenna_forwarding_proxy(
            url.to_string(),
            our_id,
            *HEARTBEAT_SERVER_KEY,
            network.wg_public_key.unwrap(),
            network.wg_private_key.unwrap(),
            interfaces,
        );
    }
}

fn start_client_dashboard() {
    // dashboard
    server::new(|| {
        App::new()
            .middleware(middleware::Headers)
            .middleware(middleware::Auth)
            .route("/backup_created", Method::GET, get_backup_created)
            .route("/backup_created/{status}", Method::POST, set_backup_created)
            .route("/dao_list", Method::GET, get_dao_list)
            .route("/dao_list/add/{address}", Method::POST, add_to_dao_list)
            .route(
                "/dao_list/remove/{address}",
                Method::POST,
                remove_from_dao_list,
            )
            .route("/dao_fee", Method::GET, get_dao_fee)
            .route("/dao_fee/{fee}", Method::POST, set_dao_fee)
            .route("/operator", Method::GET, get_operator)
            .route("/operator/{address}", Method::POST, change_operator)
            .route("/operator/remove", Method::POST, remove_operator)
            .route("/operator_fee", Method::GET, get_operator_fee)
            .route("/operator_debt", Method::GET, get_operator_debt)
            .route("/debts", Method::GET, get_debts)
            .route("/debts/reset", Method::POST, reset_debt)
            .route("/exits", Method::GET, get_exit_info)
            .route("/exits", Method::POST, add_exits)
            .route("/exits/{name}/register", Method::POST, register_to_exit)
            .route("/exits/{name}/reset", Method::POST, reset_exit)
            .route("/exits/{name}/select", Method::POST, select_exit)
            .route("/local_fee", Method::GET, get_local_fee)
            .route("/local_fee/{fee}", Method::POST, set_local_fee)
            .route("/metric_factor", Method::GET, get_metric_factor)
            .route("/metric_factor/{factor}", Method::POST, set_metric_factor)
            .route(
                "/exits/{name}/verify/{code}",
                Method::POST,
                verify_on_exit_with_code,
            )
            .route("/info", Method::GET, get_own_info)
            .route("/interfaces", Method::GET, get_interfaces_endpoint)
            .route("/interfaces", Method::POST, set_interfaces_endpoint)
            .route("/interfaces/mesh", Method::GET, wlan_mesh_get)
            .route("/interfaces/lightclient", Method::GET, wlan_lightclient_get)
            .route("/interfaces/mesh/{enabled}", Method::POST, wlan_mesh_set)
            .route(
                "/interfaces/lightclient/{enabled}",
                Method::POST,
                wlan_lightclient_set,
            )
            .route("/eth_private_key", Method::GET, get_eth_private_key)
            .route("/mesh_ip", Method::GET, get_mesh_ip)
            .route("/neighbors", Method::GET, get_neighbor_info)
            .route("/routes", Method::GET, get_routes)
            .route("/remote_logging/enabled", Method::GET, get_remote_logging)
            .route(
                "/remote_logging/enabled/{enabled}",
                Method::POST,
                remote_logging,
            )
            .route(
                "/remote_logging/level",
                Method::GET,
                get_remote_logging_level,
            )
            .route(
                "/remote_logging/level/{level}",
                Method::POST,
                remote_logging_level,
            )
            .route("/settings", Method::GET, get_settings)
            .route("/settings", Method::POST, set_settings)
            .route("/version", Method::GET, version)
            .route("/wg_public_key", Method::GET, get_wg_public_key)
            .route("/wifi_settings", Method::POST, set_wifi_multi)
            .route(
                "/wifi_settings/get_channels/{radio}",
                Method::GET,
                get_allowed_wifi_channels,
            )
            .route("/wifi_settings", Method::GET, get_wifi_config)
            .route("/withdraw/{address}/{amount}", Method::POST, withdraw)
            .route("/withdraw_all/{address}", Method::POST, withdraw_all)
            .route(
                "/auto_price/enabled/{status}",
                Method::POST,
                set_auto_pricing,
            )
            .route("/auto_price/enabled", Method::GET, auto_pricing_status)
            .route("/prices", Method::GET, get_prices)
            .route(
                "/blockchain/set/{chain_id}",
                Method::POST,
                set_system_blockchain_endpoint,
            )
            .route("/blockchain/get", Method::GET, get_system_blockchain)
            .route("/nickname/get", Method::GET, get_nickname)
            .route("/nickname/set", Method::POST, set_nickname)
            .route(
                "/low_balance_notification",
                Method::GET,
                get_low_balance_notification,
            )
            .route(
                "/low_balance_notification/{status}",
                Method::POST,
                set_low_balance_notification,
            )
            .route("/usage/relay", Method::GET, get_relay_usage)
            .route("/usage/client", Method::GET, get_client_usage)
            .route("/usage/payments", Method::GET, get_payments)
            .route("/token_bridge/status", Method::GET, get_bridge_status)
            .route("/router/reboot", Method::POST, reboot_router)
            .route("/router/update", Method::POST, update_router)
            .route("/router/password", Method::POST, set_pass)
            .route("/release_feed/get", Method::GET, get_release_feed_http)
            .route(
                "/release_feed/set/{feed}",
                Method::POST,
                set_release_feed_http,
            )
            .route("/remote_access", Method::GET, get_remote_access_status)
            .route(
                "/remote_access/{status}",
                Method::POST,
                set_remote_access_status,
            )
            .route("/wipe", Method::POST, wipe)
            .route("/crash_actors", Method::POST, crash_actors)
            .route("/localization", Method::GET, get_localization)
            .route("/wyre_reservation", Method::POST, get_wyre_reservation)
            .route(
                "/installation_details",
                Method::POST,
                set_installation_details,
            )
            .route(
                "/installation_details",
                Method::GET,
                get_installation_details,
            )
            .route("/billing_details", Method::GET, get_billing_details)
            .route("/billing_details", Method::POST, set_billing_details)
            .route("/bandwidth_limit", Method::GET, get_bandwidth_limit)
            .route(
                "/bandwidth_limit/{limit}",
                Method::POST,
                set_bandwidth_limit,
            )
            .route(
                "/operator_setup/{enabled}",
                Method::POST,
                set_display_operator_setup,
            )
            .route("/operator_setup", Method::GET, display_operator_setup)
            .route("/phone", Method::GET, get_phone_number)
            .route("/phone", Method::POST, set_phone_number)
            .route("/email", Method::GET, get_email)
            .route("/email", Method::POST, set_email)
    })
    .workers(1)
    .bind(format!(
        "[::0]:{}",
        settings::get_rita_client()
            .get_network()
            .rita_dashboard_port
    ))
    .unwrap()
    .shutdown_timeout(0)
    .start();
}
