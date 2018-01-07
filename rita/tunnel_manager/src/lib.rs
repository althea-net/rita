#[macro_use]
extern crate derive_error;

use std::net::IpAddr;

extern crate althea_types;
use althea_types::EthAddress;

extern crate debt_keeper;
use debt_keeper::{Identity, Key};

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate reqwest;
use reqwest::Client;

#[derive(Debug, Error)]
pub enum Error {
    KernelInterfaceError(althea_kernel_interface::Error),
    HttpReqError(reqwest::Error),
    #[error(msg_embedded, no_from, non_std)]
    TunnelManagerError(String),
}

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
    pub fn get_neighbors(&mut self) -> Result<Vec<Identity>, Error> {
        Ok(self.ki
            .get_neighbors()?
            .iter()
            .filter_map(|&(mac_address, ip_address)| {
                match self.neighbor_inquiry(ip_address) {
                    Ok(eth_address) => Some(Identity {
                        ip_address,
                        mac_address,
                        eth_address,
                    }),
                    Err(e) => None
                }
            })
            .collect())
    }

    fn neighbor_inquiry(&self, ip: IpAddr) -> Result<EthAddress, Error> {
        Ok(self.client
            .get(&format!("http://{}/hello", ip))
            .send()?
            .json()?)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
