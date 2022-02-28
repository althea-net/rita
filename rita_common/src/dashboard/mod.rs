//! The common user infromation endpoints for Rita, these are http endpoints that exist for user
//! management and automation. They exist on port 4877 by default and should be firewalled
//! from the outside world for obvious security reasons.

pub mod babel;
pub mod debts;
pub mod development;
pub mod nickname;
pub mod own_info;
pub mod settings;
pub mod token_bridge;
pub mod usage;
pub mod wallet;
pub mod wg_key;
