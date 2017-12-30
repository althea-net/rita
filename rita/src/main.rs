// #![feature(getpid)]
extern crate althea_kernel_interface;
extern crate babel_monitor;

extern crate traffic_watcher;

// use std::process;

extern crate docopt;

// #[macro_use]
// extern crate log;

extern crate ip_network;
extern crate simple_logger;

use std::thread;
// use std::collections::HashMap;
use althea_kernel_interface::KernelInterface;
use babel_monitor::Babel;
// use std::net::IpAddr;
// use ip_network::IpNetwork;
use std::net::SocketAddr;
// use docopt::Docopt;

// use std::fs::File;
// use std::io::prelude::*;
// use std::env;
use std::sync::mpsc;
use std::time::Duration;

fn main() {
    let (tx, rx) = mpsc::channel();

    let mut ki = KernelInterface {};

    let mut babel = Babel::new(&"[::1]:8080".parse().unwrap());

    let tx1 = mpsc::Sender::clone(&tx);
    thread::spawn(move || {
        // let vals = vec![
        //     String::from("hi"),
        //     String::from("from"),
        //     String::from("the"),
        //     String::from("thread"),
        // ];

        // for val in vals {
        //     tx1.send(val).unwrap();
        //     thread::sleep(Duration::from_secs(1));
        // }
        tx1.send(format!(
            "{:?}",
            traffic_watcher::watch(5, &mut ki, &mut babel)
        ))
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
