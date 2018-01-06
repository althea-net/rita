use std::net::IpAddr;

extern crate althea_types;
use althea_types::EthAddress;

extern crate debt_keeper;
use debt_keeper::{Identity, Key};

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate reqwest;
use reqwest::Client;

pub struct TunnelManager {
    pub client: Client,
    pub ki: KernelInterface,
}

impl TunnelManager {
    pub fn new() -> Self {
        TunnelManager {
            client: Client::new(),
            ki: KernelInterface {},
        }
    }
    pub fn get_neighbors(&mut self) -> Vec<Identity> {
        self.ki
            .get_neighbors()
            .unwrap()
            .iter()
            .map(|&(mac_address, ip_address)| {
                Identity {
                    ip_address: ip_address,
                    mac_address: mac_address,
                    eth_address: self.neighbor_inquiry(ip_address),
                }
            })
            .collect()
    }

    fn neighbor_inquiry(&self, ip: IpAddr) -> EthAddress {
        self.client
            .get(&format!("http://{}/hello", ip))
            .send()
            .unwrap()
            .json()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
