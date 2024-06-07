#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

pub mod dashboard;
mod error;
pub mod exit_manager;
pub mod extender;
pub mod heartbeat;
pub mod logging;
pub mod operator_fee_manager;
pub mod operator_update;
pub mod rita_loop;
mod self_rescue;
pub mod traffic_watcher;

pub use error::RitaClientError;
use rita_common::READABLE_VERSION;
use settings::client::{default_config_path, APP_NAME};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Args {
    #[serde(default = "default_config_path")]
    pub flag_config: PathBuf,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            flag_config: default_config_path(),
        }
    }
}

/// TODO platform is in the process of being removed as a support argument
/// as it's not even used. Config can still be used but has a sane default
/// and does not need to be specified.
pub fn get_client_usage(version: &str, git_hash: &str) -> String {
    format!(
        "Usage: {APP_NAME} [--config=<settings>] [--platform=<platform>] [--future]
Options:
    -c, --config=<settings>     Name of config file
About:
    Version {READABLE_VERSION} - {version}
    git hash {git_hash}"
    )
}
