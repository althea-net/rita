extern crate althea_kernel_interface;
extern crate babel_monitor;
extern crate ip_network;

use std::{thread, time};
use std::collections::HashMap;
use babel_monitor::Babel;
use althea_kernel_interface::KernelInterface;
use std::net::IpAddr;
use ip_network::IpNetwork;

fn main() {
    println!("Hello, world!");
    let mut ki = KernelInterface::new();

    let mut babel = Babel::new("127.0.0.0:8080");

    let mut neigh_debts = HashMap::new();

    loop {
        let neighbors = ki.get_neighbors().unwrap();
        let destinations = babel.parse_routes().unwrap();

        let mut dest_map = HashMap::new();

        for dest in &destinations {
            dest_map.insert(dest.prefix.to_string(), dest);
            if let IpNetwork::V6(ref i) = dest.prefix {
                for &(neigh_mac, _) in &neighbors {
                    ki.start_flow_counter(neigh_mac, IpAddr::V6(i.get_network_address()))
                        .unwrap();
                }
            }
        }

        thread::sleep(time::Duration::from_secs(5));

        let counters = ki.read_flow_counters().unwrap();

        for (neigh_mac, dest_ip, bytes) in counters {
            let kb = bytes / 1000;
            let price = dest_map.get(&dest_ip.to_string()).unwrap().price;
            let debt = price as u64 * kb;

            *neigh_debts.entry(neigh_mac.to_string()).or_insert(0) += debt;
        }
    }
}
