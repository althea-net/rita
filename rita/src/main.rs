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
use debt_keeper::{DebtKeeper, DebtAction, DebtAdjustment};

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

    let (tx, rx) = mpsc::channel();

    let tx1 = mpsc::Sender::clone(&tx);
    thread::spawn(move || {
        let mut ki = KernelInterface {};
        let mut tm = TunnelManager::new();
        let mut babel = Babel::new(&"[::1]:8080".parse().unwrap()); //TODO: Do we really want [::1] and not [::0]?

        loop {
            let neighbors = tm.get_neighbors().unwrap();
            info!("got neighbors: {:?}", neighbors);

            let debts = traffic_watcher::watch(neighbors, 5, &mut ki, &mut babel).unwrap();
            info!("got debts: {:?}", debts);

            for (ident, amount) in debts {
                let adjustment = DebtAdjustment {ident, amount};
                trace!("Sent debt adjustment {:?}", &adjustment);
                tx1.send(adjustment).unwrap();
            }
        };
    });

    let m_tx = Arc::new(Mutex::new(tx.clone()));

    let pc = PaymentController::start(&my_ident, m_tx);

    let pc1 = pc.clone();

    thread::spawn(move || {
        let pc = Arc::new(Mutex::new(pc1));
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

    let mut dk = DebtKeeper::new(Int256::from(5), Int256::from(-10));

    for debt_adjustment in rx {
        match dk.apply_debt(debt_adjustment.ident, debt_adjustment.amount) {
            Some(DebtAction::SuspendTunnel) => {
                trace!("Suspending Tunnel");
            }, // tunnel manager should suspend forwarding here
            Some(DebtAction::OpenTunnel) => {
                trace!("Opening Tunnel");
            }, // tunnel manager should reopen tunnel here
            Some(DebtAction::MakePayment(amt)) => {
                pc.send(PaymentControllerMsg::MakePayment(PaymentTx {
                    from: my_ident,
                    to: debt_adjustment.ident,
                    amount: amt.clone()
                })).unwrap();

                trace!("Sent payment, Payment: {:?}", PaymentTx {
                    from: my_ident,
                    to: debt_adjustment.ident,
                    amount: amt.clone()
                });
            },
            None => ()
        };
    }
}