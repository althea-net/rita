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
use actix::{Arbiter, SystemService};
use diesel::query_dsl::RunQueryDsl;
use exit_db::models;
use settings::exit::RitaExitSettings;
use std::collections::HashMap;
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

pub fn start_rita_exit_loop() {
    let mut geoip_cache: HashMap<IpAddr, String> = HashMap::new();
    thread::spawn(move || loop {
        use exit_db::schema::clients::dsl::clients;
        trace!("Exit tick!");

        // opening a database connection takes at least several milliseconds, as the database server
        // may be across the country, so to save on back and forth we open on and reuse it as much
        // as possible
        let conn = match get_database_connection() {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to reach database! with {:?}", e);
                continue;
            }
        };

        let clients_list = match clients.load::<models::Client>(&conn) {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to reach database! with {:?}", e);
                continue;
            }
        };
        let ids = clients_to_ids(clients_list.clone());

        // watch and bill for traffic it's super important this gets spawned!
        TrafficWatcher::from_registry().do_send(Watch(ids));

        // Create and update client tunnels
        trace!("here?");
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
            let res = validate_clients_region(&mut geoip_cache, &clients_list, &conn);
            if res.is_err() {
                error!("Validate clients failed with {:?}", res);
            }
        }
        // handle enforcement on client tunnels by querying debt keeper
        // this consumes client list, you can move it up in exchange for a clone
        Arbiter::spawn(enforce_exit_clients(clients_list));
        thread::sleep(Duration::from_secs(5));
    });
}
