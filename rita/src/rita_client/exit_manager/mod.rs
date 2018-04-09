use actix::prelude::*;

use althea_types::Identity;

use SETTING;

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
        if SETTING.read().unwrap().exit_client.is_some() {
            if let Some(ref exit_details) =
                SETTING.read().unwrap().clone().exit_client.unwrap().details
            {
                TrafficWatcher::from_registry().do_send(Watch(
                    Identity {
                        mesh_ip: SETTING.read().unwrap().exit_client.clone().unwrap().exit_ip,
                        wg_public_key: exit_details.wg_public_key.clone(),
                        eth_address: exit_details.eth_address,
                    },
                    exit_details.exit_price,
                ))
            };
        }

        Ok(())
    }
}
