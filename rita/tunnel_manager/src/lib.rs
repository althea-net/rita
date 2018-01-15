#[macro_use]
extern crate derive_error;

#[macro_use]
extern crate log;

use std::net::IpAddr;

extern crate althea_types;
use althea_types::EthAddress;

extern crate debt_keeper;
use debt_keeper::Identity;

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate reqwest;
use reqwest::Client;

#[derive(Debug, Error)]
pub enum Error {
    KernelInterfaceError(althea_kernel_interface::Error),
    HttpReqError(reqwest::Error),
    #[error(msg_embedded, no_from, non_std)] TunnelManagerError(String),
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
        Ok(
            self.ki
                .get_neighbors()?
                .iter()
                .filter_map(|&(mac_address, ip_address, ref dev)| {
                    let identity = self.neighbor_inquiry(ip_address, &dev);
                    trace!("got neighbor: {:?}", identity);
                    match identity {
                        Ok(identity) => Some(identity),
                        Err(_) => None,
                    }
                })
                .collect(),
        )
    }

    pub fn neighbor_inquiry(&mut self, ip: IpAddr, dev: &str) -> Result<Identity, Error> {
        let url = format!("http://[{}%25{}]:4876/hello", ip, dev);
        trace!("Saying hello to: {:?}", url);
        Ok(self.client.get(&url).send()?.json()?)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
