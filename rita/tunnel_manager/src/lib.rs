#[macro_use]
extern crate derive_error;

#[macro_use]
extern crate log;

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, SocketAddrV4, TcpStream};
use std::time::Duration;

use std::io::{Read, Write};

extern crate serde_json;

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
    IOError(std::io::Error),
    DeserializationError(serde_json::Error),
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

        let socket = match ip {
            IpAddr::V6(ip_v6) => {
                SocketAddr::V6(SocketAddrV6::new(ip_v6, 4876, 0, self.ki.get_iface_index(dev)?))
            }
            IpAddr::V4(ip_v4) => {
                SocketAddr::V4(SocketAddrV4::new(ip_v4, 4876)) //TODO: Do we want to allow IPv4?
            }
        };

        let mut stream = TcpStream::connect(socket)?;

        // Format HTTP request
        let mut header = format!("GET /hello HTTP/1.0\r\nHost: [{}%25{}]\r\n\r\n", ip, dev);  //TODO: check if this is a proper HTTP request
        stream.write(header.as_bytes());

        // Make request and return response as string
        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;

        trace!("They replied {}", resp);

        Ok(serde_json::from_str(&resp)?)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
