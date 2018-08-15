use std::time::{Duration, Instant};

use actix::prelude::*;
use actix::registry::SystemService;

use rita_exit::db_client::{DbClient, ListClients};

use rita_exit::traffic_watcher::{TrafficWatcher, Watch};

use exit_db::models::Client;

use failure::Error;

use settings::{RitaCommonSettings, RitaExitSettings};
use SETTING;

use althea_kernel_interface::{ExitClient, KI};

use althea_types::Identity;

pub struct RitaLoop;

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        info!("exit loop started");
        ctx.run_interval(Duration::from_secs(5), |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), Error>;
}

fn to_identity(client: Client) -> Identity {
    Identity {
        mesh_ip: client.mesh_ip.parse().unwrap(),
        eth_address: SETTING.get_payment().eth_address, // we should never be paying them, but if somehow we do, it goes back to us
        wg_public_key: client.wg_pubkey,
    }
}

fn to_exit_client(client: Client) -> Result<ExitClient, Error> {
    Ok(ExitClient {
        mesh_ip: client.mesh_ip.parse()?,
        internal_ip: client.internal_ip.parse()?,
        port: client.wg_port.parse()?,
        public_key: client.wg_pubkey,
    })
}

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        let start = Instant::now();
        trace!("Exit tick!");

        ctx.spawn(
            DbClient::from_registry()
                .send(ListClients {})
                .into_actor(self)
                .then(|res, _act, ctx| {
                    let clients = res.unwrap().unwrap();
                    let ids = clients
                        .clone()
                        .into_iter()
                        .filter(|c| c.verified)
                        .map(to_identity)
                        .collect();
                    TrafficWatcher::from_registry().do_send(Watch(ids));

                    let mut wg_clients = Vec::new();

                    trace!("got clients from db {:?}", clients);

                    for c in clients {
                        if let Ok(c) = to_exit_client(c) {
                            wg_clients.push(c);
                        }
                    }

                    trace!("converted clients {:?}", wg_clients);

                    let exit_status = KI.set_exit_wg_config(
                        wg_clients,
                        SETTING.get_exit_network().wg_tunnel_port,
                        &SETTING.get_network().wg_private_key_path,
                        &SETTING.get_exit_network().own_internal_ip,
                        SETTING.get_exit_network().netmask,
                    );

                    match exit_status {
                        Ok(_) => (),
                        Err(e) => warn!("Error in Exit WG setup {:?}", e),
                    }

                    actix::fut::ok(())
                }),
        );

        info!(
            "Rita Exit loop completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_nanos() / 1000000
        );
        Ok(())
    }
}
