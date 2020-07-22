//! The main actor loop for Rita, this loop is common to both rita and rita_exit (as is everything
//! in rita common).
//!
//! This loops ties together various actors through messages and is generally the rate limiter on
//! all system functions. Anything that blocks will eventually filter up to block this loop and
//! halt essential functions like opening tunnels and managing peers

use crate::rita_common::network_endpoints::*;
use crate::SETTING;
use actix::SystemService;
use actix_web::http::Method;
use actix_web::{server, App};
use rand::thread_rng;
use rand::Rng;
use settings::RitaCommonSettings;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

pub mod fast_loop;
pub mod slow_loop;

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
    if SETTING.get_payment().node_list.is_empty() {
        panic!("no full nodes configured!");
    }
    let node_list = SETTING.get_payment().node_list.clone();
    let mut rng = thread_rng();
    let val = rng.gen_range(0, node_list.len());

    node_list[val].clone()
}

pub fn start_core_rita_endpoints(workers: usize) {
    // Rita hello function
    server::new(|| App::new().resource("/hello", |r| r.method(Method::POST).with(hello_response)))
        .workers(workers)
        .bind(format!("[::0]:{}", SETTING.get_network().rita_hello_port))
        .unwrap()
        .shutdown_timeout(0)
        .start();

    // Rita accept payment function, on a different port
    server::new(|| {
        App::new().resource("/make_payment", |r| {
            r.method(Method::POST).with(make_payments)
        })
    })
    .workers(workers)
    .bind(format!("[::0]:{}", SETTING.get_network().rita_contact_port))
    .unwrap()
    .shutdown_timeout(0)
    .start();
}

pub fn check_rita_common_actors() {
    assert!(crate::rita_common::debt_keeper::DebtKeeper::from_registry().connected());
    assert!(crate::rita_common::payment_controller::PaymentController::from_registry().connected());
    assert!(crate::rita_common::payment_validator::PaymentValidator::from_registry().connected());
    assert!(crate::rita_common::tunnel_manager::TunnelManager::from_registry().connected());
    assert!(crate::rita_common::hello_handler::HelloHandler::from_registry().connected());
    assert!(crate::rita_common::traffic_watcher::TrafficWatcher::from_registry().connected());
    assert!(crate::rita_common::peer_listener::PeerListener::from_registry().connected());
    assert!(crate::rita_common::rita_loop::fast_loop::RitaFastLoop::from_registry().connected());
    crate::rita_common::rita_loop::slow_loop::start_rita_slow_loop();
}
