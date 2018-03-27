#![cfg_attr(feature = "system_alloc", feature(alloc_system, global_allocator, allocator_api))]

#[cfg(feature = "system_alloc")]
extern crate alloc_system;

#[cfg(feature = "system_alloc")]
use alloc_system::System;

#[cfg(feature = "system_alloc")]
#[global_allocator]
static A: System = System;

#[macro_use]
extern crate log;

#[macro_use]
extern crate rouille;
use rouille::{Request, Response};

#[macro_use]
extern crate diesel;
extern crate dotenv;
extern crate env_logger;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

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

extern crate failure;

use failure::Error;

pub mod schema;
pub mod models;
use self::models::*;

use self::schema::nodes::dsl::*;

pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

fn main() {
    env_logger::init();
    trace!("Starting");

    let conn = Mutex::new(establish_connection());

    rouille::start_server("[::0]:8888", move |request| {
        router!(request,
            (POST) (/update) => {
                process_updates(request, &conn)
            },
            (POST) (/checkin) => {
                checkin(request, &conn)
            },
            (GET) (/list) => {
                list_nodes(request, &conn)
            },
            _ => rouille::Response::empty_404()
        )
    });
}

fn insert_node(identity: &Identity, conn: &SqliteConnection) {
    let exists = select(exists(nodes.filter(ip.eq(identity.mesh_ip.to_string()))))
        .get_result(conn)
        .expect("Error loading statuses");

    if exists {
        trace!("record exists for {:?}, skipping", identity);
    } else {
        trace!("record does not exist, creating");
        let stat = Node {
            ip: identity.mesh_ip.to_string(),
            balance: "0".to_string(),
        };

        diesel::insert_into(nodes)
            .values(&stat)
            .execute(conn)
            .expect("Error saving");
    }
}

fn get_balance(identity: &Identity, conn: &SqliteConnection) -> Int256 {
    insert_node(identity, conn);

    let node = nodes
        .filter(ip.eq(identity.mesh_ip.to_string()))
        .limit(2)
        .load::<Node>(conn)
        .unwrap();

    assert_eq!(node.len(), 1);

    return serde_json::from_str(&format!("\"{}\"", &node[0].balance)).unwrap();
}

fn save_balance(identity: &Identity, new_balance: Int256, conn: &SqliteConnection) {
    insert_node(identity, conn);

    diesel::update(nodes.find(identity.mesh_ip.to_string()))
        .set(balance.eq(format!("{}", new_balance)))
        .execute(conn)
        .expect("Error saving");
}

fn process_updates(request: &Request, conn: &Mutex<SqliteConnection>) -> Response {
    let conn = conn.lock().unwrap();

    if let Some(mut data) = request.data() {
        let to_balance = conn.transaction::<_, Error, _>(|| {
            let mut payment_str = String::new();
            data.read_to_string(&mut payment_str).unwrap();
            let payment: PaymentTx = serde_json::from_str(&payment_str).unwrap();
            trace!("Received update, status: {:?}", payment);

            let mut from_balance = get_balance(&payment.from, &*conn);
            let mut to_balance = get_balance(&payment.to, &*conn);

            from_balance -= payment.amount.clone();
            to_balance += payment.amount.clone();

            save_balance(&payment.from, from_balance, &*conn);
            save_balance(&payment.to, to_balance.clone(), &*conn);

            let list = nodes.load::<Node>(&*conn).expect("Error loading nodes");

            trace!("nodes: {:?}", list);

            Ok(to_balance)
        }).unwrap();

        Response::json(&to_balance)
    } else {
        panic!("Empty body")
    }
}

fn checkin(request: &Request, conn: &Mutex<SqliteConnection>) -> Response {
    let conn = conn.lock().unwrap();
    if let Some(mut data) = request.data() {
        let mut id_str = String::new();
        data.read_to_string(&mut id_str).unwrap();
        let identity: Identity = serde_json::from_str(&id_str).unwrap();
        let client_balance = conn.transaction::<_, Error, _>(|| {
            insert_node(&identity, &*conn);
            let client_balance = get_balance(&identity, &*conn);
            Ok(client_balance)
        }).unwrap();
        Response::json(&client_balance)
    } else {
        panic!("Empty body")
    }
}

fn list_nodes(_request: &Request, conn: &Mutex<SqliteConnection>) -> Response {
    let conn = conn.lock().unwrap();
    let results = nodes.load::<Node>(&*conn).expect("Error loading nodes");
    trace!("Sending response: {:?}", results);
    rouille::Response::text(serde_json::to_string(&results).unwrap())
}
