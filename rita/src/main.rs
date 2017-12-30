#![feature(getpid)]
extern crate althea_kernel_interface;
extern crate babel_monitor;

extern crate traffic_watcher;

use std::process;

extern crate docopt;

#[macro_use]
extern crate log;

extern crate ip_network;
extern crate simple_logger;

use std::thread;
// use std::collections::HashMap;
use althea_kernel_interface::KernelInterface;
use babel_monitor::Babel;
// use std::net::IpAddr;
// use ip_network::IpNetwork;
use std::net::SocketAddr;
use docopt::Docopt;

use std::fs::File;
use std::io::prelude::*;
// use std::env;
use std::sync::mpsc;
use std::time::Duration;

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
        while true {
            tx1.send(format!(
                "{:?}",
                traffic_watcher::watch(5, &mut ki, &mut babel)
            ));
        };
    });

    thread::spawn(move || {
        let vals = vec![
            String::from("more"),
            String::from("messages"),
            String::from("for"),
            String::from("you"),
        ];

        for val in vals {
            tx.send(val).unwrap();
            thread::sleep(Duration::from_secs(1));
        }
    });

    for received in rx {
        println!("Got: {}", received);
    }
}
