#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use] extern crate log;

#[macro_use]
extern crate serde_derive;

use std::fs::File;
use std::io::prelude::*;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::process;
use std::thread;

use std::net::{Ipv6Addr, IpAddr};

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate babel_monitor;
use babel_monitor::Babel;

extern crate traffic_watcher;

extern crate debt_keeper;
use debt_keeper::{DebtKeeper, DebtAction, DebtKeeperMsg};

extern crate payment_controller;

use payment_controller::{PaymentController, PaymentControllerMsg};

extern crate althea_types;
use althea_types::{Identity, PaymentTx, Int256};

extern crate ip_network;
extern crate simple_logger;

extern crate tunnel_manager;
use tunnel_manager::TunnelManager;

#[macro_use] extern crate rouille;
use rouille::{Response};

extern crate serde;
extern crate serde_json;

extern crate rand;

mod network_endpoints;
use network_endpoints::make_payments;

extern crate settings;
use settings::SETTING;

fn main() {
    simple_logger::init().unwrap();
    trace!("Starting");

    let my_ident = Identity {
        mac_address: SETTING.network.own_mac.clone(),
        ip_address: SETTING.network.own_ip.clone(),
        eth_address: SETTING.payment.eth_address.clone(),
    };

    trace!("Starting with Identity: {:?}", my_ident);


    let (debt_keeper_input_master, debt_keeper_output) = DebtKeeper::start(
        SETTING.payment.pay_threshold.clone(),
        SETTING.payment.close_threshold.clone(),
        SETTING.payment.close_fraction.clone(),
        SETTING.payment.buffer_period.clone());

    let payment_controller_input_master = PaymentController::start(
        &my_ident,
        Arc::new(Mutex::new(debt_keeper_input_master.clone()))
    );

    let payment_controller_input = payment_controller_input_master.clone();
    let debt_keeper_input = mpsc::Sender::clone(&debt_keeper_input_master);
    thread::spawn(move || {
        let mut ki = KernelInterface {};
        let mut tm = TunnelManager::new();
        let mut babel = Babel::new(&format!("[::1]:{}", SETTING.network.babel_port).parse().unwrap());

        loop {
            let neighbors = tm.get_neighbors().unwrap();
            info!("got neighbors: {:?}", neighbors);

            let debts = traffic_watcher::watch(neighbors, 5, &mut ki, &mut babel, SETTING.network.own_ip).unwrap();
            info!("got debts: {:?}", debts);

            for (from, amount) in debts {
                let update = DebtKeeperMsg::TrafficUpdate { from, amount };
                let adjustment = DebtKeeperMsg::SendUpdate { from };
                debt_keeper_input.send(update).unwrap();
                debt_keeper_input.send(adjustment).unwrap();
            }
            payment_controller_input.send(PaymentControllerMsg::Update);
        };
    });

    let payment_controller_input = payment_controller_input_master.clone();

    thread::spawn(move || {
        let pc = Arc::new(Mutex::new(payment_controller_input_master.clone()));
        rouille::start_server(format!("[::0]:{}", SETTING.network.rita_port), move |request| {
            router!(request,
                (POST) (/make_payment) => {
                    make_payments(request, pc.clone())
                },
                (GET) (/hello) => {
                    Response::text(serde_json::to_string(&my_ident).unwrap())
                    // Response::text("0xb794f5ea0ba39494ce839613fffba74279579268")
                },
                _ => Response::text("404")
            )
        });
    });

    for msg in debt_keeper_output {
        match msg {
            Some(DebtAction::SuspendTunnel) => {
                trace!("Suspending Tunnel");
            }, // tunnel manager should suspend forwarding here
            Some(DebtAction::OpenTunnel) => {
                trace!("Opening Tunnel");
            }, // tunnel manager should reopen tunnel here
            Some(DebtAction::MakePayment {to, amount}) => {
                payment_controller_input.send(PaymentControllerMsg::MakePayment(PaymentTx {
                    from: my_ident,
                    to: to,
                    amount
                })).unwrap();
            },
            None => ()
        };
    }
}