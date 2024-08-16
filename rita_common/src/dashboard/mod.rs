//! The common user infromation endpoints for Rita, these are http endpoints that exist for user
//! management and automation. They exist on port 4877 by default and should be firewalled
//! from the outside world for obvious security reasons.

pub mod auth;
pub mod babel;
pub mod backup_created;
pub mod contact_info;
pub mod debts;
pub mod development;
pub mod eth_private_key;
pub mod interfaces;
pub mod localization;
pub mod logging;
pub mod mesh_ip;
pub mod nickname;
pub mod operator;
pub mod own_info;
pub mod remote_access;
pub mod settings;
pub mod system_chain;
pub mod token_bridge;
pub mod usage;
pub mod wallet;
pub mod wg_key;
pub mod wifi;
