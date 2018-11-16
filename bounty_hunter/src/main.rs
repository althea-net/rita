#[macro_use]
extern crate diesel;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

extern crate actix_web;
extern crate clarity;
extern crate dotenv;
extern crate env_logger;
extern crate futures;
extern crate libc;
extern crate num256;
extern crate num_traits;
extern crate openssl;
extern crate serde;
extern crate serde_json;

mod models;
mod network_endpoints;
mod schema;

use actix_web::{http::Method, server, App};
use diesel::{connection::Connection, sqlite::SqliteConnection};
use dotenv::dotenv;
use env_logger::Builder;
use log::LevelFilter;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use std::{env, path, process, sync::Mutex};

use network_endpoints::{handle_get_channel_state, handle_upload_channel_state};

lazy_static! {
    static ref DB_CONN: Mutex<SqliteConnection> = {
        dotenv().ok();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let conn = SqliteConnection::establish(&database_url)
            .expect(&format!("Error connecting to {}", database_url));
        Mutex::new(conn)
    };
}

static BOUNTY_HUNTER_PORT: u16 = 4878u16;

fn main() {
    match env::var("RUST_LOG") {
        Ok(_) => env_logger::init(),
        Err(_) => Builder::new().filter_level(LevelFilter::Info).init(),
    }

    info!("Althea Bounty Hunter {}", env!("CARGO_PKG_VERSION"));

    let system = actix::System::new("main");

    dotenv().ok();
    let cert = env::var("BOUNTY_HUNTER_CERT").ok();
    let key = env::var("BOUNTY_HUNTER_KEY").ok();

    match (cert, key) {
        (Some(cert), Some(key)) => {
            if path::Path::new(&key).exists() && path::Path::new(&cert).exists() {
                info!("Starting HTTP server (TLS: key {}, cert {})", key, cert);
                let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
                builder
                    .set_certificate_file(cert, SslFiletype::PEM)
                    .unwrap();
                builder.set_private_key_file(key, SslFiletype::PEM).unwrap();

                // Serve over TLS
                server::new(|| {
                    App::new()
                        .route(
                            "/upload_channel_state",
                            Method::POST,
                            handle_upload_channel_state,
                        ).route(
                            "/get_channel_state/{ch_id}",
                            Method::GET,
                            handle_get_channel_state,
                        )
                }).workers(1)
                .bind_ssl(format!("[::]:{}", BOUNTY_HUNTER_PORT), builder)
                .unwrap()
                .shutdown_timeout(0)
                .start();
            } else {
                error!("TLS: cert and key paths configured (key {}, cert {}) but at least one is not present on disk, bailing out", key, cert);
                process::exit(libc::EINVAL);
            }
        }
        (other_key_state, other_cert_state) => {
            error!(
                "TLS: not configured, got key {:?} and cert {:?}, expected two defined paths, bailing out",
                other_key_state, other_cert_state
                );
            process::exit(libc::EINVAL);
        }
    }
    system.run();
}
