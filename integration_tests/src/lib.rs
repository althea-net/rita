#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

use std::time::Duration;

pub mod contract_test;
pub mod debts;
pub mod five_nodes;
pub mod mutli_exit;
pub mod payments_althea;
pub mod payments_eth;
pub mod setup_utils;
pub mod snat_exit;
pub mod utils;

/// The amount of time we wait for a network to stabalize before testing
pub const SETUP_WAIT: Duration = Duration::from_secs(60);
