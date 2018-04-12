use actix::prelude::*;

use althea_types::Identity;

use SETTING;
use settings::RitaClientSettings;

use rita_client::rita_loop::Tick;
use rita_client::traffic_watcher::{TrafficWatcher, Watch};

use failure::Error;

/// An actor which pays the exit
#[derive(Default)]
pub struct ExitManager;

impl Actor for ExitManager {
    type Context = Context<Self>;
}

impl Supervised for ExitManager {}
impl SystemService for ExitManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Exit Manager started");
    }
}

impl Handler<Tick> for ExitManager {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        if SETTING.exit_client_is_set() && SETTING.exit_client_details_is_set() {
            TrafficWatcher::from_registry().do_send(Watch(
                Identity {
                    mesh_ip: SETTING.get_exit_client().exit_ip,
                    wg_public_key: SETTING.get_exit_client_details().wg_public_key.clone(),
                    eth_address: SETTING.get_exit_client_details().eth_address,
                },
                SETTING.get_exit_client_details().exit_price,
            ));
        }

        Ok(())
    }
}
