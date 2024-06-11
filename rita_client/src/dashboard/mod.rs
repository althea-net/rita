//! This file contains all the network endpoints used for the client dashbaord. This management dashboard
//! is for users to use to configure and manage their router and should be firewalled from the outside
//! world.
//!
//! For more documentation on specific functions see the router-dashboard file in the docs folder

pub mod bandwidth_limit;
pub mod devices_on_lan;
pub mod exits;
pub mod extender_checkin;
pub mod installation_details;
pub mod logging;
pub mod mesh_ip;
pub mod neighbors;
pub mod notifications;
pub mod operator;
pub mod prices;
pub mod remote_access;
pub mod router;
pub mod usage;

use crate::dashboard::bandwidth_limit::*;
use crate::dashboard::exits::*;
use crate::dashboard::extender_checkin::*;
use crate::dashboard::installation_details::*;
use crate::dashboard::logging::*;
use crate::dashboard::mesh_ip::*;
use crate::dashboard::neighbors::*;
use crate::dashboard::notifications::*;
use crate::dashboard::operator::*;
use crate::dashboard::prices::*;
use crate::dashboard::remote_access::*;
use crate::dashboard::router::*;
use crate::dashboard::usage::*;
use actix_async::System;
use actix_web_async::{web, App, HttpServer};
use rita_common::dashboard::auth::*;
use rita_common::dashboard::babel::*;
use rita_common::dashboard::backup_created::*;
use rita_common::dashboard::contact_info::*;
use rita_common::dashboard::debts::*;
use rita_common::dashboard::development::*;
use rita_common::dashboard::eth_private_key::*;
use rita_common::dashboard::interfaces::*;
use rita_common::dashboard::localization::*;
use rita_common::dashboard::nickname::*;
use rita_common::dashboard::own_info::*;
use rita_common::dashboard::settings::*;
use rita_common::dashboard::system_chain::*;
use rita_common::dashboard::token_bridge::*;
use rita_common::dashboard::usage::*;
use rita_common::dashboard::wallet::*;
use rita_common::dashboard::wg_key::*;
use rita_common::dashboard::wifi::*;
use rita_common::middleware;
use rita_common::network_endpoints::*;
use std::thread;

use self::devices_on_lan::get_devices_lan_endpoint;

pub fn start_client_dashboard(rita_dashboard_port: u16) {
    // dashboard
    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            let _res = HttpServer::new(|| {
                App::new()
                    .wrap(middleware::AuthMiddlewareFactory)
                    .wrap(middleware::HeadersMiddlewareFactory)
                    .route("/backup_created", web::get().to(get_backup_created))
                    .route(
                        "/backup_created/{status}",
                        web::post().to(set_backup_created),
                    )
                    .route("/operator", web::get().to(get_operator))
                    .route("/operator/{address}", web::post().to(change_operator))
                    .route("/operator/remove", web::post().to(remove_operator))
                    .route("/operator_fee", web::get().to(get_operator_fee))
                    .route("/operator_fee/{fee}", web::post().to(set_operator_fee))
                    .route("/operator_debt", web::get().to(get_operator_debt))
                    .route("/debts", web::get().to(get_debts))
                    .route("/debts/reset", web::post().to(reset_debt))
                    .route("/exits", web::get().to(get_exit_info))
                    .route("/exits", web::post().to(add_exits))
                    .route("/exits/{name}/register", web::post().to(register_to_exit))
                    .route("/exits/{name}/reset", web::post().to(reset_exit))
                    .route("/exits/{name}/select", web::post().to(select_exit))
                    .route(
                        "/extender_checkin",
                        web::post().to(extender_checkin_handler),
                    )
                    .route("/local_fee", web::get().to(get_local_fee))
                    .route("/local_fee/{fee}", web::post().to(set_local_fee))
                    .route("/metric_factor", web::get().to(get_metric_factor))
                    .route("/metric_factor/{factor}", web::post().to(set_metric_factor))
                    .route("/lan_devices", web::get().to(get_devices_lan_endpoint))
                    .route(
                        "/exits/{name}/verify/{code}",
                        web::post().to(verify_on_exit_with_code),
                    )
                    .route("/info", web::get().to(get_own_info))
                    .route("/interfaces", web::get().to(get_interfaces_endpoint))
                    .route("/interfaces", web::post().to(set_interfaces_endpoint))
                    .route("/interfaces/mesh", web::get().to(wlan_mesh_get))
                    .route("/interfaces/mesh/{enabled}", web::post().to(wlan_mesh_set))
                    .route("/eth_private_key", web::get().to(get_eth_private_key))
                    .route("/mesh_ip", web::get().to(get_mesh_ip))
                    .route("/neighbors", web::get().to(get_neighbor_info))
                    .route("/routes", web::get().to(get_routes))
                    .route("/remote_logging/enabled", web::get().to(get_remote_logging))
                    .route(
                        "/remote_logging/enabled/{enabled}",
                        web::post().to(remote_logging),
                    )
                    .route(
                        "/remote_logging/level",
                        web::get().to(get_remote_logging_level),
                    )
                    .route(
                        "/remote_logging/level/{level}",
                        web::post().to(remote_logging_level),
                    )
                    .route("/settings", web::get().to(get_settings))
                    .route("/settings", web::post().to(set_settings))
                    .route("/version", web::get().to(version))
                    .route("/wg_public_key", web::get().to(get_wg_public_key))
                    .route("/wifi_settings", web::post().to(set_wifi_multi))
                    .route(
                        "/wifi_settings/get_channels/{radio}",
                        web::get().to(get_allowed_wifi_channels),
                    )
                    .route(
                        "/wifi_settings/get_encryption/{radio}",
                        web::get().to(get_allowed_encryption_modes),
                    )
                    .route("/wifi_settings", web::get().to(get_wifi_config))
                    .route("/withdraw/{address}/{amount}", web::post().to(withdraw))
                    .route("/withdraw_all/{address}", web::post().to(withdraw_all))
                    .route(
                        "/auto_price/enabled/{status}",
                        web::post().to(set_auto_pricing),
                    )
                    .route("/auto_price/enabled", web::get().to(auto_pricing_status))
                    .route("/prices", web::get().to(get_prices))
                    .route(
                        "/blockchain/set/{chain_id}",
                        web::post().to(set_system_blockchain_endpoint),
                    )
                    .route("/blockchain/get", web::get().to(get_system_blockchain))
                    .route("/nickname/get", web::get().to(get_nickname))
                    .route("/nickname/set", web::post().to(set_nickname))
                    .route(
                        "/low_balance_notification",
                        web::get().to(get_low_balance_notification),
                    )
                    .route(
                        "/low_balance_notification/{status}",
                        web::post().to(set_low_balance_notification),
                    )
                    .route("/usage/relay", web::get().to(get_relay_usage))
                    .route("/usage/client", web::get().to(get_client_usage))
                    .route("/usage/payments", web::get().to(get_payments))
                    .route("/token_bridge/status", web::get().to(get_bridge_status))
                    .route("/router/reboot", web::post().to(reboot_router))
                    .route("/router/update", web::post().to(update_router))
                    .route("/router/password", web::post().to(set_pass))
                    .route("/remote_access", web::get().to(get_remote_access_status))
                    .route(
                        "/remote_access/{status}",
                        web::post().to(set_remote_access_status),
                    )
                    .route("/wipe", web::post().to(wipe))
                    .route("/localization", web::get().to(get_localization))
                    .route(
                        "/installation_details",
                        web::post().to(set_installation_details),
                    )
                    .route(
                        "/installation_details",
                        web::get().to(get_installation_details),
                    )
                    .route("/billing_details", web::get().to(get_billing_details))
                    .route("/billing_details", web::post().to(set_billing_details))
                    .route("/bandwidth_limit", web::get().to(get_bandwidth_limit))
                    .route(
                        "/bandwidth_limit/{limit}",
                        web::post().to(set_bandwidth_limit),
                    )
                    .route(
                        "/operator_setup/{enabled}",
                        web::post().to(set_display_operator_setup),
                    )
                    .route("/operator_setup", web::get().to(display_operator_setup))
                    .route("/phone", web::get().to(get_phone_number))
                    .route("/phone", web::post().to(set_phone_number))
                    .route("/email", web::get().to(get_email))
                    .route("/email", web::post().to(set_email))
            })
            .workers(1)
            .bind(format!("[::0]:{rita_dashboard_port}"))
            .unwrap()
            .shutdown_timeout(0)
            .run()
            .await;
        });
    });
}
