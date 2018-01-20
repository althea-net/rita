#![cfg_attr(feature="system_alloc", feature(alloc_system, global_allocator, allocator_api))]

#[cfg(feature = "system_alloc")]
extern crate alloc_system;

#[cfg(feature = "system_alloc")]
use alloc_system::System;

#[cfg(feature = "system_alloc")]
#[global_allocator]
static A: System = System;

#[macro_use] extern crate log;

#[macro_use] extern crate rouille;
use rouille::{Request, Response};

#[macro_use] extern crate diesel;
extern crate dotenv;
extern crate simple_logger;

extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

extern crate num256;
use num256::Int256;

extern crate althea_types;
use althea_types::{Identity, PaymentTx};

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::select;
use diesel::dsl::exists;
use dotenv::dotenv;

use std::env;
use std::io::Read;
use std::sync::Mutex;

pub mod schema;
pub mod models;
use self::models::*;

use self::schema::status::dsl::*;

pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BountyUpdate {
    pub from: Identity,
    pub balance: Int256,
    pub tx: PaymentTx,
}

fn main() {
    simple_logger::init().unwrap();
    trace!("Starting");

    let conn = Mutex::new(establish_connection());

    rouille::start_server("[::0]:8888", move |request| { // TODO: fix the port
        router!(request,
            (POST) (/update) => {
                process_updates(request, &conn)
            },
            (GET) (/list) => {
                list_status(request, &conn)
            },
            _ => rouille::Response::empty_404()
        )
    });
}

fn process_updates(request: &Request, conn: &Mutex<SqliteConnection>) -> Response {
    let conn = conn.lock().unwrap();
    if let Some(mut data) = request.data() {
        let mut status_str = String::new();
        data.read_to_string(&mut status_str).unwrap();
        let update: BountyUpdate = serde_json::from_str(&status_str).unwrap();
        trace!("Received update, status: {:?}", update);
        trace!("Received update, balance: {}", update.balance);

        let stat = Status {
            ip: String::from(format!("{}", update.from.ip_address)),
            mac: String::from(format!("{}", update.from.mac_address)),
            balance: String::from(format!("{}", update.balance))
        };

        trace!("Checking if record exists for {}", stat.ip);

        let exists = select(exists(status.filter(ip.eq(stat.ip.clone()))))
            .get_result(&*conn)
            .expect("Error loading statuses");

        if exists {
            trace!("record exists, updating");
            // updating
            diesel::update(status.find(stat.ip))
                .set(balance.eq(stat.balance))
                .execute(&*conn)
                .expect("Error saving");
        } else {
            trace!("record does not exist, creating");
            // first time seeing
            diesel::insert_into(status)
                .values(&stat)
                .execute(&*conn)
                .expect("Error saving");
        }
        Response::text("Received Successfully")
    } else {
        panic!("Empty body")
    }
}

fn list_status(_request: &Request, conn: &Mutex<SqliteConnection>) -> Response {
let conn = conn.lock().unwrap();
let results = status
.load::<Status>(&*conn)
.expect("Error loading statuses");
trace!("Sending response: {:?}", results);
rouille::Response::text(serde_json::to_string(&results).unwrap())
}
