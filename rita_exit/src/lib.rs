#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

pub mod dashboard;
pub mod database;
mod error;
pub mod network_endpoints;
pub mod operator_update;
pub mod rita_loop;
pub mod traffic_watcher;

pub use crate::database::geoip::*;
pub use crate::database::in_memory_database::*;
pub use error::RitaExitError;
use rita_common::dashboard::own_info::READABLE_VERSION;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
pub struct Args {
    pub flag_config: PathBuf,
    pub flag_fail_on_startup: bool,
}

pub fn get_exit_usage(version: &str, git_hash: &str) -> String {
    format!(
        "Usage: rita_exit --config=<settings>
Options:
    -c, --config=<settings>   Name of config file
    -f, --fail-on-startup     Exit immeidately if status checks fail on startup
About:
    Version {READABLE_VERSION} - {version}
    git hash {git_hash}"
    )
}
