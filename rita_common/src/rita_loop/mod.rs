//! The main actor loop for Rita, this loop is common to both rita and rita_exit (as is everything
//! in rita common).
//!
//! This loops ties together various actors through messages and is generally the rate limiter on
//! all system functions. Anything that blocks will eventually filter up to block this loop and
//! halt essential functions like opening tunnels and managing peers

use crate::network_endpoints::*;
use crate::traffic_watcher::init_traffic_watcher;
use actix_async::System;
use actix_web_async::{web, App, HttpServer};
use rand::thread_rng;
use rand::Rng;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;

pub mod fast_loop;
pub mod slow_loop;
pub mod write_to_disk;

lazy_static! {
    /// keeps track of if this node is a gateway, specifically if this node
    /// needs to perform the various edge case behaviors required to manage
    /// peering out to exits over a WAN port. This includes DHCP lookups
    /// in tunnel manager, where the gateway reaches out to it's manual peers
    /// to create NAT punching tunnels to the exit and setting routes to prevent
    /// exit traffic from going over the exit tunnel (which obviously doesn't work)
    static ref IS_GATEWAY: AtomicBool = AtomicBool::new(false);
}

pub fn is_gateway() -> bool {
    IS_GATEWAY.load(Ordering::Relaxed)
}

pub fn set_gateway(input: bool) {
    IS_GATEWAY.store(input, Ordering::Relaxed)
}

/// Checks the list of full nodes, panics if none exist, if there exist
/// one or more a random entry from the list is returned in an attempt
/// to load balance across fullnodes
pub fn get_web3_server() -> String {
    let common = settings::get_rita_common();
    if common.payment.eth_node_list.is_empty() {
        panic!("no full nodes configured!");
    }
    let node_list = common.payment.eth_node_list;
    let mut rng = thread_rng();
    let val = rng.gen_range(0..node_list.len());

    node_list[val].clone()
}

pub fn start_core_rita_endpoints(workers: usize) {
    // Rita hello function

    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            let common = settings::get_rita_common();
            let res =
                HttpServer::new(|| App::new().route("/hello", web::post().to(hello_response)))
                    .workers(workers)
                    .bind(format!("[::0]:{}", common.network.rita_hello_port))
                    .unwrap()
                    .shutdown_timeout(0)
                    .run()
                    .await;

            info!("Hello handler endpoint started with: {:?}", res);
        });
    });
    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            let common = settings::get_rita_common();

            // Rita accept payment function, on a different port
            let res = HttpServer::new(|| {
                App::new()
                    .route("/make_payment", web::post().to(make_payments))
                    .route("/make_payment_v2", web::post().to(make_payments_v2))
            })
            .workers(workers)
            .bind(format!("[::0]:{}", common.network.rita_contact_port))
            .unwrap()
            .shutdown_timeout(0)
            .run()
            .await;
            info!("Make payment endpoint started with: {:?}", res);
        });
    });
}

pub fn start_rita_common_loops() {
    init_traffic_watcher();
    crate::rita_loop::slow_loop::start_rita_slow_loop();
    crate::rita_loop::fast_loop::start_rita_fast_loop();
    crate::rita_loop::fast_loop::peer_discovery_loop();
}
