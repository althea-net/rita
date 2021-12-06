//! The common user infromation endpoints for Rita, these are http endpoints that exist for user
//! management and automation. They exist on port 4877 by default and should be firewalled
//! from the outside world for obvious security reasons.

use actix::prelude::*;
use actix::registry::SystemService;

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

#[derive(Default)]
pub struct Dashboard;

impl Actor for Dashboard {
    type Context = Context<Self>;
}

impl Supervised for Dashboard {}
impl SystemService for Dashboard {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Dashboard started");
    }
}
