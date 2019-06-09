//! This is the primary actor loop for rita-exit, where periodic tasks are spawed and Actors are
//! tied together with message calls.
//!
//! In this loop the exit checks it's database for registered users and deploys the endpoint for
//! their exit tunnel the execution model for all of this is pretty whacky thanks to Actix quirks
//! we have the usual actors, these actors process Async events, but we have database queries by
//! Diesel that are syncronous so we create a special actix construct called a 'sync actor' that
//! is really another thread dedicated to running an actor which may block. Since it's another thread
//! the block now only halts the single actor. In order to run an actor like this regularly we would like
//! to use the run_interval closure setup, but that's only implemented for normal Async actors, likewise
//! the system service setup which lets us use from_registry also doesn't work with SyncActors
//! so as a workaround for both of those we have an actor Ritaloop which creates the SyncActor thread
//! and address on startup and then proceeds to spawn futures there using it's own loop.
//!
//! Crash behavior is really where this starts to cause issues, SyncActors can't really crash
//! they will always be ready for another message, AsyncActors on the other hand can, which is why
//! this one is marked as a system service, so that it will be restarted. But when it's restarted it
//! will create another SyncActor loop and addres to send messages to! Hopefully the borro checker and
//! actix work together on this on properly, not that I've every seen simple actors like the loop crash
//! very often.

use crate::rita_exit::database::struct_tools::clients_to_ids;
use crate::rita_exit::database::{
    cleanup_exit_clients, enforce_exit_clients, get_database_connection, setup_clients,
    validate_clients_region,
};
use crate::rita_exit::network_endpoints::*;
use crate::rita_exit::traffic_watcher::{TrafficWatcher, Watch};
use crate::KI;
use crate::SETTING;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    SystemService,
};
use actix_web::http::Method;
use actix_web::{server, App};
use althea_kernel_interface::ExitClient;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::start_connection;
use diesel::query_dsl::RunQueryDsl;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::PooledConnection;
use diesel::PgConnection;
use exit_db::models;
use failure::Error;
use futures::future::Future;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use std::time::Instant;
use tokio::util::FutureExt;

// the speed in seconds for the exit loop
pub const EXIT_LOOP_SPEED: u64 = 5;
pub const EXIT_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Default)]
pub struct RitaLoop {
    /// a simple cache to prevent regularly asking Maxmind for the same geoip data
    pub geoip_cache: HashMap<IpAddr, String>,
    /// a cache of what tunnels we had setup last round, used to prevent extra setup ops
    pub wg_clients: HashSet<ExitClient>,
}


impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        info!("exit loop started");
        setup_exit_wg_tunnel();
        ctx.run_interval(Duration::from_secs(EXIT_LOOP_SPEED), move |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            Arbiter::spawn(get_database_connection().then(move |database| {
                match database {
                    Ok(database) => addr.do_send(Tick(database)),
                    Err(e) => error!("Could not reach database for Rita sync loop! {:?}", e),
                }
                Ok(())
            }));
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

pub struct Tick(PooledConnection<ConnectionManager<PgConnection>>);

impl Message for Tick {
    type Result = Result<(), Error>;
}

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let start = Instant::now();
        use exit_db::schema::clients::dsl::clients;
        let babel_port = SETTING.get_network().babel_port;
        info!("Exit tick!");

        // opening a database connection takes at least several milliseconds, as the database server
        // may be across the country, so to save on back and forth we open on and reuse it as much
        // as possible
        let conn = msg.0;

        let clients_list = clients.load::<models::Client>(&conn)?;
        let ids = clients_to_ids(clients_list.clone());

        // watch and bill for traffic

        Arbiter::spawn(
            open_babel_stream(babel_port)
                .from_err()
                .and_then(|stream| {
                    start_connection(stream).and_then(|stream| {
                        parse_routes(stream).and_then(|routes| {
                            TrafficWatcher::from_registry().do_send(Watch {
                                users: ids,
                                routes: routes.1,
                            });
                            Ok(())
                        })
                    })
                })
                .timeout(EXIT_LOOP_TIMEOUT)
                .then(|ret| {
                    if let Err(e) = ret {
                        error!("Failed to watch Exit traffic with {:?}", e)
                    }
                    Ok(())
                }),
        );

        // Create and update client tunnels
        match setup_clients(&clients_list, &self.wg_clients) {
            Ok(wg_clients) => self.wg_clients = wg_clients,
            Err(e) => error!("Setup clients failed with {:?}", e),
        }

        // find users that have not been active within the configured time period
        // and remove them from the db
        let res = cleanup_exit_clients(&clients_list, &conn);
        if res.is_err() {
            error!("Exit client cleanup failed with {:?}", res);
        }

        // Make sure no one we are setting up is geoip unauthorized
        if !SETTING.get_allowed_countries().is_empty() {
            Arbiter::spawn(validate_clients_region(clients_list.clone()));
        }

        // handle enforcement on client tunnels by querying debt keeper
        // this consumes client list, you can move it up in exchange for a clone
        Arbiter::spawn(enforce_exit_clients(clients_list));

        info!(
            "Completed Rita sync loop in {}s {}ms, all vars should be dropped",
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis(),
        );
        Ok(())
    }
}

fn setup_exit_wg_tunnel() {
    if let Err(e) = KI.setup_wg_if_named("wg_exit") {
        warn!("exit setup returned {}", e)
    }
    KI.one_time_exit_setup(
        &SETTING.get_exit_network().own_internal_ip.into(),
        SETTING.get_exit_network().netmask,
    )
    .expect("Failed to setup wg_exit!");
    KI.setup_nat(&SETTING.get_network().external_nic.clone().unwrap())
        .unwrap();
}

pub fn check_rita_exit_actors() {
    assert!(crate::rita_exit::rita_loop::RitaLoop::from_registry().connected());
    assert!(crate::rita_exit::traffic_watcher::TrafficWatcher::from_registry().connected());
    assert!(crate::rita_exit::database::db_client::DbClient::from_registry().connected());
}

pub fn start_rita_exit_endpoints(workers: usize) {
    // Exit stuff, huge threadpool to offset Pgsql blocking
    server::new(|| {
        App::new()
            .resource("/setup", |r| r.method(Method::POST).with(setup_request))
            .resource("/status", |r| r.method(Method::POST).with(status_request))
            .resource("/exit_info", |r| {
                r.method(Method::GET).with(get_exit_info_http)
            })
            .resource("/rtt", |r| r.method(Method::GET).with(rtt))
            .resource("/client_debt", |r| {
                r.method(Method::POST).with(get_client_debt)
            })
    })
    .workers(workers)
    .bind(format!(
        "[::0]:{}",
        SETTING.get_exit_network().exit_hello_port
    ))
    .unwrap()
    .shutdown_timeout(0)
    .start();
}
