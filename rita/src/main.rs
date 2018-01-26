#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use] extern crate log;

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
use althea_types::{Identity, PaymentTx};

extern crate docopt;
use docopt::Docopt;

extern crate ip_network;
extern crate simple_logger;

extern crate tunnel_manager;
use tunnel_manager::TunnelManager;

extern crate num256;
use num256::Int256;

#[macro_use] extern crate rouille;
use rouille::{Response};

extern crate serde;
extern crate serde_json;

extern crate rand;

mod network_endpoints;
use network_endpoints::make_payments;

const USAGE: &'static str = "
Usage: rita --ip <ip addr>
Options:
    --ip   Mesh IP of node
";

fn main() {
    simple_logger::init().unwrap();
    trace!("Starting");

    let args = Docopt::new(USAGE)
        .and_then(|d| d.parse())
        .unwrap_or_else(|e| e.exit());

    let ip: Ipv6Addr = args.get_str("<ip addr>").parse().unwrap();

    let my_ident = Identity {
        mac_address: "12:34:56:78:90:ab".parse().unwrap(), // TODO: make this not a hack
        ip_address: IpAddr::V6(ip),
        eth_address: "0xb794f5ea0ba39494ce839613fffba74279579268".parse().unwrap()
    };

    trace!("Starting with Identity: {:?}", my_ident);

    
    let (debt_keeper_input, debt_keeper_output) = DebtKeeper::start(Int256::from(500000), Int256::from(-1000000));

    let debt_keeper_input1 = mpsc::Sender::clone(&debt_keeper_input);
    thread::spawn(move || {
        let mut ki = KernelInterface {};
        let mut tm = TunnelManager::new();
        let mut babel = Babel::new(&"[::1]:8080".parse().unwrap());

        loop {
            let neighbors = tm.get_neighbors().unwrap();
            info!("got neighbors: {:?}", neighbors);

            let debts = traffic_watcher::watch(neighbors, 5, &mut ki, &mut babel).unwrap();
            info!("got debts: {:?}", debts);

            for (from, amount) in debts {
                let adjustment = DebtKeeperMsg::Traffic { from, amount };
                debt_keeper_input1.send(adjustment).unwrap();
            }
        };
    });

    let payment_controller_input = PaymentController::start(
        &my_ident,
        Arc::new(Mutex::new(debt_keeper_input.clone()))
    );

    let payment_controller_input1 = payment_controller_input.clone();

    thread::spawn(move || {
        let pc = Arc::new(Mutex::new(payment_controller_input.clone()));
        rouille::start_server("[::0]:4876", move |request| {
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
                payment_controller_input1.send(PaymentControllerMsg::MakePayment(PaymentTx {
                    from: my_ident,
                    to: to,
                    amount
                })).unwrap();
            },
            None => ()
        };
    }
}