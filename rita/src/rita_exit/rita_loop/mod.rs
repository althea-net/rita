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

use crate::rita_exit::db_client::{DbClient, DeleteClient, ListClients, SetClientTimestamp};

use futures::future::Either;
use futures::{future, Future};

use crate::rita_common::debt_keeper::DebtAction;
use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::GetDebtsList;
use crate::rita_exit::traffic_watcher::{TrafficWatcher, Watch};

use exit_db::models::Client;

use failure::Error;

use crate::SETTING;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;

use althea_kernel_interface::{ExitClient, KI};

use althea_types::Identity;

mod cleanup;
mod enforcement;
mod setup;
use cleanup::cleanup_exit_clients;
use enforcement::enforce_exit_clients;
use setup::setup_exit_clients;

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

fn to_identity(client: &Client) -> Result<Identity, Error> {
    trace!("Converting client {:?}", client);
    Ok(Identity {
        mesh_ip: client.mesh_ip.clone().parse()?,
        eth_address: client.eth_address.clone().parse()?,
        wg_public_key: client.wg_pubkey.clone().parse()?,
    })
}

fn to_exit_client(client: Client) -> Result<ExitClient, Error> {
    Ok(ExitClient {
        mesh_ip: client.mesh_ip.parse()?,
        internal_ip: client.internal_ip.parse()?,
        port: client.wg_port.parse()?,
        public_key: client.wg_pubkey,
    })
}

fn clients_to_ids(clients: Vec<Client>) -> Vec<Identity> {
    let mut ids: Vec<Identity> = Vec::new();
    for client in clients.iter() {
        match (client.verified, to_identity(client)) {
            (true, Ok(id)) => ids.push(id),
            (true, Err(e)) => warn!("Corrupt database entry {:?}", e),
            (false, _) => trace!("{:?} is not registered", client),
        }
    }
    ids
}

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("Exit tick!");

        // Create and update client tunnels
        Arbiter::spawn(setup_exit_clients());

        // handle enforcement on client tunnels by querying debt keeper
        Arbiter::spawn(enforce_exit_clients());

        // find users that have not been active within the configured time period
        // and remove them from the db
        Arbiter::spawn(cleanup_exit_clients());

        Ok(())
    }
}
