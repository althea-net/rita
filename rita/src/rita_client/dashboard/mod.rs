//! This file contains all the network endpoints used for the client dashbaord. This management dashboard
//! is for users to use to configure and manage their router and should be firewalled from the outside
//! world.
//!
//! For more documentation on specific functions see the router-dashboard file in the docs folder

pub mod eth_private_key;
pub mod exits;
pub mod interfaces;
pub mod logging;
pub mod mesh_ip;
pub mod neighbors;
pub mod notifications;
pub mod system_chain;
pub mod update;
pub mod wifi;
