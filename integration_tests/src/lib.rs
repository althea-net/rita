#[macro_use]
extern crate lazy_static;

use std::time::Duration;

pub mod config;
pub mod contract_test;
pub mod debts;
pub mod five_nodes;
pub mod mutli_exit;
pub mod payments_althea;
pub mod payments_eth;
pub mod registration_server;
pub mod setup_utils;
pub mod utils;

/// The amount of time we wait for a network to stabalize before testing
pub const SETUP_WAIT: Duration = Duration::from_secs(60);
