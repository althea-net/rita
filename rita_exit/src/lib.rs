#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

pub mod database;
pub mod network_endpoints;
pub mod operator_update;
pub mod rita_loop;
pub mod traffic_watcher;

mod error;
use actix_async::System;
use actix_web_async::web;
use actix_web_async::App;
use actix_web_async::HttpServer;
pub use error::RitaExitError;

pub use crate::database::database_tools::*;
pub use crate::database::database_tools::*;
pub use crate::database::geoip::*;
use rita_common::dashboard::babel::*;
use rita_common::dashboard::debts::*;
use rita_common::dashboard::development::*;
use rita_common::dashboard::nickname::*;
use rita_common::dashboard::own_info::READABLE_VERSION;
use rita_common::dashboard::own_info::*;
use rita_common::dashboard::settings::*;
use rita_common::dashboard::token_bridge::*;
use rita_common::dashboard::usage::*;
use rita_common::dashboard::wallet::*;
use rita_common::dashboard::wg_key::*;
use rita_common::middleware;
use rita_common::network_endpoints::version;
use std::thread;

#[derive(Debug, Deserialize, Default)]
pub struct Args {
    pub flag_config: String,
    pub flag_future: bool,
}

pub fn get_exit_usage(version: &str, git_hash: &str) -> String {
    format!(
        "Usage: rita_exit --config=<settings>
Options:
    -c, --config=<settings>   Name of config file
    --future                    Enable B side of A/B releases
About:
    Version {READABLE_VERSION} - {version}
    git hash {git_hash}"
    )
}

pub fn start_rita_exit_dashboard() {
    // Dashboard
    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            let _res = HttpServer::new(|| {
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
