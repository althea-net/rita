//! This is the primary actor loop for rita-exit, where periodic tasks are spawed and Actors are
//! tied together with message calls.
//!
//! In this loop the exit checks it's database for registered users and deploys the endpoint for
//! their exit tunnel

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ::actix::prelude::*;
use ::actix::registry::SystemService;

use crate::rita_exit::db_client::{DbClient, ListClients};

use futures::future::Either;
use futures::{future, Future};

use crate::rita_common::debt_keeper::DebtAction;
use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::GetDebtsList;
use crate::rita_exit::traffic_watcher::{TrafficWatcher, Watch};

use exit_db::models::Client;

use failure::Error;

use crate::SETTING;
use settings::{RitaCommonSettings, RitaExitSettings};

use althea_kernel_interface::{ExitClient, KI};

use althea_types::Identity;

pub struct RitaLoop;

// the speed in seconds for the exit loop
pub const EXIT_LOOP_SPEED: u64 = 5;

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        info!("exit loop started");
        ctx.run_interval(Duration::from_secs(EXIT_LOOP_SPEED), |_act, ctx| {
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
    trace!("Converting client {:?}", client);
    Identity {
        mesh_ip: client.mesh_ip.parse().expect("Corrupt database entry!"),
        eth_address: client.eth_address.parse().expect("Corrupt database entry!"),
        wg_public_key: client.wg_pubkey.parse().expect("Corrupt database entry!"),
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
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let start = Instant::now();
        trace!("Exit tick!");

        // Create and update client tunnels
        Arbiter::spawn(
            DbClient::from_registry()
                .send(ListClients {})
                .then(move |res| {
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
                    info!(
                        "Rita Exit loop completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );
                    Ok(())
                }),
        );

        // handle enforcement on client tunnels by querying debt keeper
        Arbiter::spawn(
            DebtKeeper::from_registry()
                .send(GetDebtsList)
                .and_then(|debts_list| match debts_list {
                    Ok(list) => Either::A(DbClient::from_registry().send(ListClients {}).and_then(
                        move |res| {
                            let clients = res.unwrap();
                            let mut clients_by_id = HashMap::new();
                            let free_tier_limit = SETTING.get_payment().free_tier_throughput;
                            for client in clients.iter() {
                                let id = to_identity(client.clone());
                                clients_by_id.insert(id, client);
                            }

                            for debt_entry in list.iter() {
                                match clients_by_id.get(&debt_entry.identity) {
                                    Some(client) => {
                                        let _ = match client.internal_ip.parse() {
                                            Ok(IpAddr::V4(ip)) => {
                                                let class_id = KI.get_class_id(&ip);
                                                let res = if debt_entry.payment_details.action
                                                    == DebtAction::SuspendTunnel
                                                {
                                                    KI.set_class_limit(
                                                        "wg_exit",
                                                        free_tier_limit,
                                                        free_tier_limit,
                                                        class_id,
                                                    )
                                                } else {
                                                    // set to 50mbps garunteed bandwidth and 5gbps
                                                    // absolute max
                                                    KI.set_class_limit(
                                                        "wg_exit", 50000, 5000000, class_id,
                                                    )
                                                };
                                                if res.is_err() {
                                                    warn!("Failed to limit {} with {:?}", ip, res);
                                                }
                                            }
                                            _ => warn!("Can't parse Ipv4Addr to create limit!"),
                                        };
                                    }
                                    None => {
                                        warn!(
                                            "Could not find {:?} to suspend!",
                                            debt_entry.identity
                                        );
                                    }
                                }
                            }

                            Ok(())
                        },
                    )),
                    Err(e) => {
                        warn!("Failed to get debts from DebtKeeper! {:?}", e);
                        Either::B(future::ok(()))
                    }
                })
                .then(|_| Ok(())),
        );

        Ok(())
    }
}
