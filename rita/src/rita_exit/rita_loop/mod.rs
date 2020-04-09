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

use crate::rita_exit::database::database_tools::get_database_connection;
use crate::rita_exit::database::struct_tools::clients_to_ids;
use crate::rita_exit::database::{
    cleanup_exit_clients, enforce_exit_clients, setup_clients, validate_clients_region,
};
use crate::rita_exit::network_endpoints::*;
use crate::rita_exit::traffic_watcher::{TrafficWatcher, Watch};
use crate::KI;
use crate::SETTING;
use actix::{Arbiter, SystemService};
use actix_web::http::Method;
use actix_web::{server, App};
use althea_kernel_interface::ExitClient;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::start_connection;
use diesel::query_dsl::RunQueryDsl;
use exit_db::models;
use futures01::future::Future;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tokio::util::FutureExt;

// the speed in seconds for the exit loop
pub const EXIT_LOOP_SPEED: u64 = 5;
pub const EXIT_LOOP_SPEED_DURATION: Duration = Duration::from_secs(EXIT_LOOP_SPEED);
pub const EXIT_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

pub fn start_rita_exit_loop() {
    setup_exit_wg_tunnel();
    // a cache of what tunnels we had setup last round, used to prevent extra setup ops
    let mut wg_clients: HashSet<ExitClient> = HashSet::new();
    thread::spawn(move || {
        loop {
            // opening a database connection takes at least several milliseconds, as the database server
            // may be across the country, so to save on back and forth we open on and reuse it as much
            // as possible
            if let Ok(conn) = get_database_connection().timeout(EXIT_LOOP_TIMEOUT).wait() {
                let start = Instant::now();
                use exit_db::schema::clients::dsl::clients;
                let babel_port = SETTING.get_network().babel_port;
                info!("Exit tick!");

                if let Ok(clients_list) = clients.load::<models::Client>(&conn) {
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
                    match setup_clients(&clients_list, &wg_clients) {
                        Ok(new_wg_clients) => wg_clients = new_wg_clients,
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
                }
            }
            // sleep for 5 seconds
            thread::sleep(EXIT_LOOP_SPEED_DURATION);
        }
    });
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
    start_rita_exit_loop();
    assert!(crate::rita_exit::traffic_watcher::TrafficWatcher::from_registry().connected());
    assert!(crate::rita_exit::database::db_client::DbClient::from_registry().connected());
}

pub fn start_rita_exit_endpoints(workers: usize) {
    // Exit stuff, huge threadpool to offset Pgsql blocking
    server::new(|| {
        App::new()
            .resource("/secure_setup", |r| {
                r.method(Method::POST).with(secure_setup_request)
            })
            .resource("/secure_status", |r| {
                r.method(Method::POST).with(secure_status_request)
            })
            .resource("/exit_info", |r| {
                r.method(Method::GET).with(get_exit_info_http)
            })
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
