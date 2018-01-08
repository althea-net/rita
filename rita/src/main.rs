#![feature(getpid)]

#[macro_use] extern crate log;

use std::fs::File;
use std::io::prelude::*;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::process;
use std::thread;

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate babel_monitor;
use babel_monitor::Babel;

extern crate traffic_watcher;

extern crate debt_keeper;
use debt_keeper::{DebtKeeper, DebtAction, DebtAdjustment, Identity};

extern crate payment_controller;
use payment_controller::{PaymentTx, PaymentController};

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

const USAGE: &'static str = "
Usage: rita [--pid <pid file>]
Options:
    --pid  Which file to write the PID to.
";

fn main() {
    simple_logger::init().unwrap();
    trace!("Starting");

    let args = Docopt::new(USAGE)
        .and_then(|d| d.parse())
        .unwrap_or_else(|e| e.exit());

    if args.get_bool("--pid") {
        let mut file = File::create(args.get_str("<pid file>")).unwrap();
        file.write_all(format!("{}", process::id()).as_bytes())
            .unwrap();
    }

    let my_ident = Identity {
        mac_address: "00:00:00:aa:00:02".parse().unwrap(),
        ip_address: "2001::3".parse().unwrap(),
        eth_address: "0xb794f5ea0ba39494ce839613fffba74279579268".parse().unwrap()
    };

    let (tx, rx) = mpsc::channel();

    let tx1 = mpsc::Sender::clone(&tx);
    thread::spawn(move || {
        let mut ki = KernelInterface {};
        let mut tm = TunnelManager::new();
        let mut babel = Babel::new(&"[::1]:8080".parse().unwrap());

        loop {
            let neighbors = tm.get_neighbors().unwrap();
            info!("got neighbors: {:?}", neighbors);

            let debts = traffic_watcher::watch(neighbors, 5, &mut ki, &mut babel).unwrap();
            info!("got debts: {:?}", debts);

            for (ident, amount) in debts {
                tx1.send(DebtAdjustment {
                    ident,
                    amount 
                }).unwrap();
            }
        };
    });

    let m_tx = Arc::new(Mutex::new(tx.clone()));

    thread::spawn(move || {
        rouille::start_server("localhost:4876", move |request| {
            router!(request,
                (POST) (/make_payment) => {
                    if let Some(data) = request.data() {
                        let pmt: PaymentTx = serde_json::from_reader(data).unwrap();
                        m_tx.lock().unwrap().send(
                            DebtAdjustment {
                                ident: pmt.from,
                                amount: Int256::from(pmt.amount)
                            }
                        ).unwrap();
                    }

                    Response::text("")
                },
                (GET) (/hello) => {
                    Response::text("0xb794f5ea0ba39494ce839613fffba74279579268")
                },
                _ => Response::text("404")
            )
        });
    });

    let mut dk = DebtKeeper::new(Int256::from(5), Int256::from(10));
    let pc = PaymentController::new();

    for debt_adjustment in rx {
        match dk.apply_debt(debt_adjustment.ident, debt_adjustment.amount) {
            Some(DebtAction::SuspendTunnel) => unimplemented!(), // tunnel manager should suspend forwarding here
            Some(DebtAction::MakePayment(amt)) => pc.make_payment(PaymentTx {
                from: my_ident,
                to: debt_adjustment.ident,
                amount: amt
            }).unwrap(),
            None => ()
        };
    }
}