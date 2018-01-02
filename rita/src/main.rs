#![feature(getpid)]

#[macro_use] extern crate serde_derive;
#[macro_use] extern crate log;

use std::net::SocketAddr;
use std::fs::File;
use std::io::prelude::*;
use std::sync::mpsc;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::process;
use std::thread;

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate babel_monitor;
use babel_monitor::Babel;

extern crate traffic_watcher;

extern crate debt_keeper;
use debt_keeper::{Key, DebtKeeper};
use debt_keeper::DebtAction;

extern crate payment_controller;
use payment_controller::{Payment, PaymentController};

extern crate docopt;
use docopt::Docopt;

extern crate ip_network;
extern crate simple_logger;

extern crate num256;
use num256::Int256;

extern crate rouille;
use rouille::{Request, Response};

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


    let (tx, rx) = mpsc::channel();

    let mut ki = KernelInterface {};

    let mut babel = Babel::new(&"[::1]:8080".parse().unwrap());

    let tx1 = mpsc::Sender::clone(&tx);
    thread::spawn(move || {
        loop {
            let debts = traffic_watcher::watch(5, &mut ki, &mut babel);

            for (ip, debt) in debts {
                tx1.send((Key::IpAddr(ip), Int256::from(debt as i64)));
            }
            // tx1.send(format!(
            //     "{:?}",
            //     traffic_watcher::watch(5, &mut ki, &mut babel)
            // ));
        };
    });


    let m_tx = Arc::new(Mutex::new(tx.clone()));

    thread::spawn(move || {
        rouille::start_server("localhost:8080", move |request| {
            let pmt: Payment = serde_json::from_reader(request.data().unwrap()).unwrap();
            m_tx.lock().unwrap().send(
                (Key::EthAddress(pmt.from), Int256::from(pmt.amount))
            ).unwrap();

            Response::text("")
        });
    });



    let mut dk = DebtKeeper::new(Int256::from(5), Int256::from(10));
    let mut pc = PaymentController::new();

    for received in rx {
        match dk.apply_debt(received.0, received.1).unwrap() {
            DebtAction::SuspendTunnel => unimplemented!(), // tunnel manager should suspend forwarding here
            DebtAction::MakePayment(amt) =>  unimplemented!()
        };

        // if res.0 {
        //     // tunnel manager should suspend forwarding here
        // }

        // if res.1 != Int256::from(0) {

        // }
    }
    // thread::spawn(move || {
    //     // let vals = vec![
    //     //     String::from("more"),
    //     //     String::from("messages"),
    //     //     String::from("for"),
    //     //     String::from("you"),
    //     // ];

    //     // for val in vals {
    //     //     tx.send(val).unwrap();
    //     //     thread::sleep(Duration::from_secs(1));
    //     // }
    //     let pmt_ctrl = PaymentController { debt_keeper_input: tx };
    // });
}
