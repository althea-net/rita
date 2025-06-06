pub use crate::database::geoip::*;
pub use crate::database::ipddr_assignment::*;
use actix::System;
use actix_web::web;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpServer;
use exit_endpoints::get_exit_network_settings;
use exit_endpoints::get_next_static_ip;
use exit_endpoints::get_num_clients;
use exit_endpoints::get_throughput;
use exit_endpoints::set_exit_mode;
use rita_common::dashboard::auth::*;
use rita_common::dashboard::babel::*;
use rita_common::dashboard::backup_created::*;
use rita_common::dashboard::contact_info::*;
use rita_common::dashboard::debts::*;
use rita_common::dashboard::eth_private_key::get_eth_private_key;
use rita_common::dashboard::interfaces::*;
use rita_common::dashboard::localization::*;
use rita_common::dashboard::logging::*;
use rita_common::dashboard::mesh_ip::*;
use rita_common::dashboard::nickname::*;
use rita_common::dashboard::operator::*;
use rita_common::dashboard::own_info::*;
use rita_common::dashboard::remote_access::*;
use rita_common::dashboard::settings::*;
use rita_common::dashboard::system_chain::get_system_blockchain;
use rita_common::dashboard::system_chain::set_system_blockchain_endpoint;
use rita_common::dashboard::token_bridge::*;
use rita_common::dashboard::usage::*;
use rita_common::dashboard::wallet::*;
use rita_common::dashboard::wg_key::*;
use rita_common::dashboard::wifi::*;
use rita_common::middleware;
use rita_common::network_endpoints::version;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;

pub mod exit_endpoints;

pub fn start_rita_exit_dashboard(startup_status: Arc<RwLock<Option<String>>>) {
    let startup_status = web::Data::new(startup_status.clone());
    // the dashboard runs in this thread and this function returns right away with that thread left running
    // in the background
    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            let _res = HttpServer::new(move || {
                App::new()
                    .wrap(middleware::AuthMiddlewareFactory)
                    .wrap(middleware::HeadersMiddlewareFactory)
                    .route("/info", web::get().to(get_own_info))
                    .route("/operator", web::get().to(get_operator))
                    .route("/operator/{address}", web::post().to(change_operator))
                    .route("/operator/remove", web::post().to(remove_operator))
                    .route("/local_fee", web::get().to(get_local_fee))
                    .route("/local_fee/{fee}", web::post().to(set_local_fee))
                    .route("/metric_factor", web::get().to(get_metric_factor))
                    .route("/metric_factor/{factor}", web::post().to(set_metric_factor))
                    .route("/settings", web::get().to(get_settings))
                    .route("/settings", web::post().to(set_settings))
                    .route("/version", web::get().to(version))
                    .route("/wg_public_key", web::get().to(get_wg_public_key))
                    .route("/debts", web::get().to(get_debts))
                    .route("/debts/reset", web::post().to(reset_debt))
                    .route("/withdraw/{address}/{amount}", web::post().to(withdraw))
                    .route("/withdraw_all/{address}", web::post().to(withdraw_all))
                    .route("/nickname/get/", web::get().to(get_nickname))
                    .route("/nickname/set/", web::post().to(set_nickname))
                    .route("/usage/payments", web::get().to(get_payments))
                    .route("/token_bridge/status", web::get().to(get_bridge_status))
                    .route(
                        "/blockchain/set/{chain_id}",
                        web::post().to(set_system_blockchain_endpoint),
                    )
                    .route("/blockchain/get", web::get().to(get_system_blockchain))
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
                    .app_data(startup_status.clone())
                    .route("/startup_status", web::get().to(get_startup_status))
                    .route("/interfaces", web::get().to(get_interfaces_endpoint))
                    .route("/interfaces", web::post().to(set_interfaces_exit_endpoint))
                    .route("/phone", web::get().to(get_phone_number))
                    .route("/phone", web::post().to(set_phone_number))
                    .route("/email", web::get().to(get_email))
                    .route("/email", web::post().to(set_email))
                    .route("/localization", web::get().to(get_localization))
                    .route("/backup_created", web::get().to(get_backup_created))
                    .route(
                        "/backup_created/{status}",
                        web::post().to(set_backup_created),
                    )
                    .route("/eth_private_key", web::get().to(get_eth_private_key))
                    .route("/router/password", web::post().to(set_pass))
                    .route("/remote_access", web::get().to(get_remote_access_status))
                    .route(
                        "/remote_access/{status}",
                        web::post().to(set_remote_access_status),
                    )
                    .route("/mesh_ip", web::get().to(get_mesh_ip))
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
                    .route(
                        "/get_exit_network",
                        web::get().to(get_exit_network_settings),
                    )
                    .route("/set_exit_network", web::post().to(set_exit_mode))
                    .route("/get_next_static_ip", web::post().to(get_next_static_ip))
                    .route("/throughput", web::get().to(get_throughput))
                    .route("/clients", web::get().to(get_num_clients))
            })
            .bind(format!(
                "[::0]:{}",
                settings::get_rita_exit().network.rita_dashboard_port
            ))
            .unwrap()
            .workers(1)
            .shutdown_timeout(0)
            .run()
            .await;
        });
    });
}

/// Retrieves the startup status of the exit, None or null (since we're converting to json)
/// means the startup was successful, otherwise it will be a string with the error message
pub async fn get_startup_status(
    startup_status: web::Data<Arc<RwLock<Option<String>>>>,
) -> HttpResponse {
    trace!("/startup_status hit");
    HttpResponse::Ok().json(startup_status.read().unwrap().clone())
}
