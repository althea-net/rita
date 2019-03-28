//! This is the primary actor loop for rita-exit, where periodic tasks are spawed and Actors are
//! tied together with message calls.
//!
//! In this loop the exit checks it's database for registered users and deploys the endpoint for
//! their exit tunnel

use crate::rita_exit::database::struct_tools::clients_to_ids;
use crate::rita_exit::database::{
    cleanup_exit_clients, enforce_exit_clients, get_database_connection, setup_clients,
    validate_clients_region,
};
use crate::rita_exit::traffic_watcher::{TrafficWatcher, Watch};
use crate::SETTING;
use actix::prelude::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    SystemService,
};
use diesel::query_dsl::RunQueryDsl;
use exit_db::models;
use failure::Error;
use settings::exit::RitaExitSettings;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Default)]
pub struct RitaLoop {
    /// a simple cache to prevent regularly asking Maxmind for the same geoip data
    pub geoip_cache: HashMap<IpAddr, String>,
}

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

impl SystemService for RitaLoop {}
impl Supervised for RitaLoop {
    fn restarting(&mut self, _ctx: &mut Context<RitaLoop>) {
        error!("Rita Exit loop actor died! recovering!");
    }
}

/// Used to test actor respawning
pub struct Crash;

impl Message for Crash {
    type Result = Result<(), Error>;
}

impl Handler<Crash> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Crash, ctx: &mut Context<Self>) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), Error>;
}

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        use exit_db::schema::clients::dsl::clients;
        trace!("Exit tick!");

        // opening a database connection takes at least several milliseconds, as the database server
        // may be across the country, so to save on back and forth we open on and reuse it as much
        // as possible
        let conn = get_database_connection()?;

        let clients_list = clients.load::<models::Client>(&conn)?;
        let ids = clients_to_ids(clients_list.clone());

        // watch and bill for traffic it's super important this gets spawned!
        TrafficWatcher::from_registry().do_send(Watch(ids));

        // Create and update client tunnels
        let res = setup_clients(&clients_list);
        if res.is_err() {
            error!("Setup clients failed with {:?}", res);
        }

        // find users that have not been active within the configured time period
        // and remove them from the db
        let res = cleanup_exit_clients(&clients_list, &conn);
        if res.is_err() {
            error!("Exit client cleanup failed with {:?}", res);
        }

        // Make sure no one we are setting up is geoip unauthorized
        if !SETTING.get_allowed_countries().is_empty() {
            let res = validate_clients_region(&mut self.geoip_cache, &clients_list, &conn);
            if res.is_err() {
                error!("Validate clients failed with {:?}", res);
            }
        }

        // handle enforcement on client tunnels by querying debt keeper
        // this consumes client list, you can move it up in exchange for a clone
        Arbiter::spawn(enforce_exit_clients(clients_list));

        Ok(())
    }
}
