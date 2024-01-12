#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

pub mod database;
pub mod ip_increment;
pub mod network_endpoints;
pub mod operator_update;
pub mod rita_loop;
pub mod traffic_watcher;

mod error;
use actix_async::System;
pub use error::RitaExitError;

pub use crate::database::database_tools::*;
pub use crate::database::database_tools::*;
pub use crate::database::db_client::*;
pub use crate::database::email::*;
pub use crate::database::geoip::*;
pub use crate::database::sms::*;
use crate::network_endpoints::nuke_db;
use actix_web_async::{web, App, HttpServer};
use althea_types::SystemChain;
use althea_types::WgKey;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::PgConnection;
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
use settings::exit::ExitNetworkSettings;
use settings::exit::ExitVerifSettings;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;
use std::time::Instant;

// These are a set of vars that are never updated during runtime. This means we can have
// read only versions of them available here to prevent lock contention on large exits.
// this is probably an overengineered optimization that can be safely removed
lazy_static! {
    pub static ref EXIT_WG_PRIVATE_KEY: WgKey =
        settings::get_rita_exit().exit_network.wg_private_key;
}
lazy_static! {
    pub static ref EXIT_VERIF_SETTINGS: Option<ExitVerifSettings> =
        settings::get_rita_exit().verif_settings;
}
// this value is actually updated so that exit prices can be changed live and we can hit the read
// only lock the vast majority of the time.
lazy_static! {
    pub static ref EXIT_NETWORK_SETTINGS: ExitNetworkSettings =
        settings::get_rita_exit().exit_network;
}
lazy_static! {
    pub static ref EXIT_SYSTEM_CHAIN: SystemChain = settings::get_rita_exit().payment.system_chain;
}
lazy_static! {
    pub static ref EXIT_DESCRIPTION: String = settings::get_rita_exit().description;
}
lazy_static! {
    pub static ref EXIT_ALLOWED_COUNTRIES: HashSet<String> =
        settings::get_rita_exit().allowed_countries;
}
// price is updated at runtime, but we only want to grab a read lock to update it every few seconds
// since this is done cooperatively in get_exit_info() only one read lock is aquired but we can
// still update it every UPDATE_INTERVAL seconds
// in the format price/last updated time
lazy_static! {
    pub static ref EXIT_PRICE: Arc<RwLock<(u64, Instant)>> = Arc::new(RwLock::new((
        settings::get_rita_exit().exit_network.exit_price,
        Instant::now()
    )));
}

lazy_static! {
    pub static ref DB_POOL: Arc<RwLock<Pool<ConnectionManager<PgConnection>>>> = {
        let db_uri = settings::get_rita_exit().db_uri;

        if !(db_uri.contains("postgres://")
            || db_uri.contains("postgresql://")
            || db_uri.contains("psql://"))
        {
            panic!("You must provide a valid postgressql database uri!");
        }

        let manager = ConnectionManager::new(settings::get_rita_exit().db_uri);
        Arc::new(RwLock::new(
            r2d2::Pool::builder()
                .max_size(settings::get_rita_exit().workers + 1)
                .build(manager)
                .expect("Failed to create pool. Check exit IP is trusted to access postgresql"),
        ))
    };
}
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
                    .route("/database", web::delete().to(nuke_db))
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
