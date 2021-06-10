#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate failure;

#[macro_use]
extern crate serde_derive;

use althea_types::SystemChain;
use settings::exit::ExitNetworkSettings;
use settings::exit::ExitVerifSettings;

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
                .expect("Failed to create pool."),
        ))
    };
}

pub mod database;
pub mod logging;
pub mod network_endpoints;
pub mod rita_loop;
pub mod traffic_watcher;

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

use althea_types::WgKey;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::PgConnection;

pub use crate::database::database_tools::*;
pub use crate::database::database_tools::*;
pub use crate::database::db_client::*;
pub use crate::database::email::*;
pub use crate::database::geoip::*;
pub use crate::database::sms::*;
pub use crate::logging::*;
