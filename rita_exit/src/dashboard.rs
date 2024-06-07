pub use crate::database::geoip::*;
pub use crate::database::in_memory_database::*;
use actix_async::System;
use actix_web_async::web;
use actix_web_async::App;
use actix_web_async::HttpResponse;
use actix_web_async::HttpServer;
use rita_common::dashboard::babel::*;
use rita_common::dashboard::debts::*;
use rita_common::dashboard::development::*;
use rita_common::dashboard::interfaces::*;
use rita_common::dashboard::nickname::*;
use rita_common::dashboard::own_info::*;
use rita_common::dashboard::settings::*;
use rita_common::dashboard::system_chain::get_system_blockchain;
use rita_common::dashboard::system_chain::set_system_blockchain_endpoint;
use rita_common::dashboard::token_bridge::*;
use rita_common::dashboard::usage::*;
use rita_common::dashboard::wallet::*;
use rita_common::dashboard::wg_key::*;
use rita_common::middleware;
use rita_common::network_endpoints::version;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;

pub fn start_rita_exit_dashboard(startup_status: Arc<RwLock<Option<String>>>) {
    let startup_status = web::Data::new(startup_status.clone());
    // the dashboard runs in this thread and this function returns right away with that thread left running
    // in the background
    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            let _res = HttpServer::new(move || {
                App::new()
                    .wrap(middleware::HeadersMiddlewareFactory)
                    .route("/info", web::get().to(get_own_info))
                    .route("/local_fee", web::get().to(get_local_fee))
                    .route("/local_fee/{fee}", web::post().to(set_local_fee))
                    .route("/metric_factor", web::get().to(get_metric_factor))
                    .route("/metric_factor/{factor}", web::post().to(set_metric_factor))
                    .route("/settings", web::get().to(get_settings))
                    .route("/settings", web::post().to(set_settings))
                    .route("/version", web::get().to(version))
                    .route("/wg_public_key", web::get().to(get_wg_public_key))
                    .route("/wipe", web::post().to(wipe))
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
                    .app_data(startup_status.clone())
                    .route("startup_status", web::get().to(get_startup_status))
                    .route("/interfaces", web::get().to(get_interfaces_endpoint))
                    .route("/interfaces", web::post().to(set_interfaces_exit_endpoint))
                    .route("/interfaces/mesh", web::get().to(wlan_mesh_get))
                    .route("/interfaces/mesh/{enabled}", web::post().to(wlan_mesh_set))
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
