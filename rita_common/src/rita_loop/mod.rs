//! The main actor loop for Rita, this loop is common to both rita and rita_exit (as is everything
//! in rita common).
//!
//! This loops ties together various actors through messages and is generally the rate limiter on
//! all system functions. Anything that blocks will eventually filter up to block this loop and
//! halt essential functions like opening tunnels and managing peers

use crate::dashboard::interfaces::get_interfaces;
use crate::dashboard::interfaces::InterfaceMode;
use crate::network_endpoints::*;
use crate::traffic_watcher::init_traffic_watcher;
use actix::System;
use actix_web::{web, App, HttpServer};
use althea_kernel_interface::ip_addr::is_iface_up;
use rand::thread_rng;
use rand::Rng;
use std::thread;

pub mod fast_loop;
pub mod slow_loop;
pub mod write_to_disk;

/// returns true if this node is a gateway, specifically if this node
/// needs to perform the various edge case behaviors required to manage
/// peering out to exits over a WAN port. This includes DHCP lookups
/// in tunnel manager, where the gateway reaches out to it's manual peers
/// to create NAT punching tunnels to the exit and setting routes to prevent
/// exit traffic from going over the exit tunnel (which obviously doesn't work)
pub fn is_gateway() -> bool {
    if let Some(external_nic) = settings::get_rita_common().network.external_nic {
        if is_iface_up(&external_nic).unwrap_or(false) {
            if let Ok(interfaces) = get_interfaces() {
                if let Some(mode) = interfaces.get(&external_nic) {
                    if matches!(mode, InterfaceMode::Wan | InterfaceMode::StaticWan { .. }) {
                        return true;
                    }
                }
            }
        }
    }
    false
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

/// Checks the list of full nodes, panics if none exist, if there exist
/// one or more a random entry from the list is returned in an attempt
/// to load balance across fullnodes
pub fn get_altheal1_server() -> String {
    let common = settings::get_rita_common();
    if common.payment.althea_grpc_list.is_empty() {
        panic!("no full nodes configured!");
    }
    let node_list = common.payment.althea_grpc_list;
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
