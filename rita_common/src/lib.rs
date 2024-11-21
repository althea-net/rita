#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;
extern crate arrayvec;

pub static DROPBEAR_CONFIG: &str = "/etc/config/dropbear";
pub static DROPBEAR_AUTHORIZED_KEYS: &str = "/etc/dropbear/authorized_keys";

/// Default wg_exit port on the client side, by default the client reaches out to the server on the port
/// provided in th exit entry. But the exit can reach out to the client provided it knows the port
/// the client is listening on. Which will be this value.
pub const CLIENT_WG_PORT: u16 = 59999;

pub mod blockchain_oracle;
pub mod dashboard;
pub mod debt_keeper;
pub mod logging;
pub mod middleware;
pub mod network_endpoints;
pub mod network_monitor;
pub mod payment_controller;
pub mod payment_validator;
pub mod peer_listener;
pub mod rita_loop;
pub mod simulated_txfee_manager;
pub mod token_bridge;
pub mod traffic_watcher;
pub mod tunnel_manager;
pub mod usage_tracker;
pub mod utils;

mod error;
pub use error::RitaCommonError;

pub use crate::dashboard::babel::*;
pub use crate::dashboard::debts::*;
pub use crate::dashboard::nickname::*;
pub use crate::dashboard::own_info::*;
pub use crate::dashboard::settings::*;
pub use crate::dashboard::token_bridge::*;
pub use crate::dashboard::usage::*;
pub use crate::dashboard::wallet::*;
pub use crate::dashboard::wg_key::*;
pub use crate::logging::*;
pub use crate::peer_listener::message::*;
pub use crate::rita_loop::fast_loop::*;
pub use crate::rita_loop::slow_loop::*;
pub use crate::tunnel_manager::gc::*;
pub use crate::tunnel_manager::id_callback::*;
pub use crate::tunnel_manager::neighbor_status::*;
pub use crate::tunnel_manager::shaping::*;
