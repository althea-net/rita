#[macro_use] extern crate log;

extern crate env_logger;

#[macro_use] extern crate rouille;
use rouille::{Request, Response};

#[macro_use] extern crate diesel;

use diesel::prelude::*;
use diesel::select;
use diesel::dsl::exists;

use std::io::Read;
use std::env;
use std::sync::Mutex;

extern crate dotenv;
use dotenv::dotenv;

extern crate post_office_settings;
use post_office_settings::SETTING;

extern crate exit_db;
use exit_db::models::Client;
use exit_db::schema::client::dsl::*;

extern crate althea_types;
use althea_types::ExitIdentity;


pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

fn main() {
    env_logger::init().unwrap();

    let conn = Mutex::new(establish_connection());

    rouille::start_server("127.0.0.1:8090", move |request| {
        router!(request,
        (POST) (/setup) => {
            setup(request, &conn)
        },

        (POST) (/hello) => {
            rouille::Response::empty_404()
        },

        _ => {
        trace!("Got an unknown hit");
        rouille::Response::empty_404()
        }
        )
    });
}

fn setup(request: &Request, conn: &Mutex<SqliteConnection>) -> Response {
    let conn = conn.lock().unwrap();
    trace!("Got a setup hit");
    let id: ExitIdentity = try_or_400!(rouille::input::json_input(request));
    let c = Client {
        mesh_ip: id.global.mesh_ip.to_string(),
        wg_pubkey: id.global.wg_public_key.to_string(),
        wg_port: id.wg_port.to_string(),
        luci_pass: "".to_string(),
        internal_ip: "".to_string(),
    };

    trace!("deserialized to {:?}", id);
    trace!("converted to {:?}", c);

    trace!("Checking if record exists for {:?}", &c.internal_ip);

    let exists = select(exists(
        client
        .filter(mesh_ip.eq(c.internal_ip.clone()))))
        .get_result(&*conn)
        .expect("Error loading statuses");


    if exists {
        trace!("record exists, updating");
        // updating
        diesel::update(client.find(c.mesh_ip.clone())
            .filter(internal_ip.eq(c.internal_ip.clone()))) // make sure client doesn't change out their internal ip from under us
            .set(&c)
            .execute(&*conn)
            .expect("Error saving");
    } else {
        trace!("record does not exist, creating");
        // first time seeing

        // c.internal_ip = ...

        diesel::insert_into(client)
            .values(&c)
            .execute(&*conn)
            .expect("Error saving");
    }

    rouille::Response::json(&c)
}