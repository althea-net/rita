//! This file contains all the network endpoints used for the client dashbaord. This management dashboard
//! is for users to use to configure and manage their router and should be firewalled from the outside
//! world.
//!
//! For more documentation on specific functions see the router-dashboard file in the docs folder

pub mod auth;
pub mod backup_created;
pub mod bandwidth_limit;
pub mod contact_info;
pub mod eth_private_key;
pub mod exits;
pub mod installation_details;
pub mod interfaces;
pub mod localization;
pub mod logging;
pub mod mesh_ip;
pub mod neighbors;
pub mod notifications;
pub mod operator;
pub mod prices;
pub mod release_feed;
pub mod remote_access;
pub mod router;
pub mod system_chain;
pub mod usage;
pub mod wifi;

use crate::dashboard::auth::*;
use crate::dashboard::backup_created::*;
use crate::dashboard::bandwidth_limit::*;
use crate::dashboard::contact_info::*;
use crate::dashboard::eth_private_key::*;
use crate::dashboard::exits::*;
use crate::dashboard::installation_details::*;
use crate::dashboard::interfaces::*;
use crate::dashboard::localization::*;
use crate::dashboard::logging::*;
use crate::dashboard::mesh_ip::*;
use crate::dashboard::neighbors::*;
use crate::dashboard::notifications::*;
use crate::dashboard::operator::*;
use crate::dashboard::prices::*;
use crate::dashboard::release_feed::*;
use crate::dashboard::remote_access::*;
use crate::dashboard::router::*;
use crate::dashboard::system_chain::*;
use crate::dashboard::usage::*;
use crate::dashboard::wifi::*;
use actix_web::http::Method;
use actix_web::{server, App};
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
use rita_common::middleware;
use rita_common::network_endpoints::*;

pub fn start_client_dashboard(rita_dashboard_password: u16) {
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
    .bind(format!("[::0]:{}", rita_dashboard_password))
    .unwrap()
    .shutdown_timeout(0)
    .start();
}
