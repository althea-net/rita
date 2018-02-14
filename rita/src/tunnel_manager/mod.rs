use std::net::{IpAddr, SocketAddr, SocketAddrV6, SocketAddrV4, TcpStream};
use std::path::Path;
use std::time::Duration;
use std::io::{Read, Write};
use std::collections::HashMap;
use std::sync::mpsc::{Sender, Receiver, channel};

use minihttpse::Response;

use althea_types::{EthAddress, Identity, LocalIdentity};

use althea_kernel_interface::KernelInterface;
use althea_kernel_interface;

use reqwest;
use reqwest::Client;
use serde_json;

use std;

#[derive(Debug, Error)]
pub enum Error {
    KernelInterfaceError(althea_kernel_interface::Error),
    HttpReqError(reqwest::Error),
    IOError(std::io::Error),
    DeserializationError(serde_json::Error),
    HTTPParseError,
    #[error(msg_embedded, no_from, non_std)] TunnelManagerError(String),
}

pub struct TunnelManagerMsg {

}

struct TunnelData {
    iface_name: String,
}

impl TunnelData {
    fn new() -> TunnelData {
        let mut ki =  KernelInterface {};
        let iface_name = ki.setup_wg_if().unwrap();
        TunnelData{
            iface_name
        }
    }
}

pub struct TunnelManager {
    pub client: Client,
    pub ki: KernelInterface,

    tunnel_map: HashMap<IpAddr, TunnelData>
}

use settings::SETTING;

impl TunnelManager {
    pub fn new() -> Self {
        let mut tm = TunnelManager {
            client: Client::new(),
            ki: KernelInterface {},
            tunnel_map: HashMap::new()
        };
        tm.ki.create_wg_key(Path::new(&SETTING.network.wg_private_key));
        tm
    }

    /// This gets the list of link-local neighbors, and then contacts them to get their
    /// Identity using `neighbor_inquiry`. It also puts the MAC address of each neighbor
    /// into the identity. This is hacky, but the next version of Rita will not use
    /// a public key instead of a MAC address to identify neighbors, meaning that it is very temporary.
    pub fn get_neighbors(&mut self) -> Result<Vec<Identity>, Error> {
        Ok(
            self.ki
                .get_neighbors()?
                .iter()
                .filter_map(|&(mac_address, ip_address, ref dev)| {
                    trace!("neighbor at interface {}, ip {}, mac {}", dev, ip_address, mac_address);
                    if &dev[..2] != "wg" {
                        {
                            //let mut tunnel = self.tunnel_map.entry(ip_address).or_insert(TunnelData::new());
                            let identity = {self.neighbor_inquiry(ip_address, &dev)};
//                            if let IpAddr::V6(ip_address) = IpAddr {
//                                let mut tunnel = self.tunnel_map.entry(ip_address).or_insert(TunnelData::new());
//                                self.ki.open_tunnel(tunnel.iface_name,
//                                                    SocketAddrV6::new(ip_address, 0, 0, 0),
//                                                    identity.pubkey,
//                                                    SETTINGS.wg_private_key
//                                )
//                            } else {
//                                Err(Error::TunnelManagerError("Only IPv6 is supported"))
//                            }
                            match identity {
                                Ok(mut identity) => {
                                    identity.wg_public_key = mac_address.clone(); // TODO: make this not a hack
                                    Some(identity)
                                },
                                Err(_) => None,
                            }
                        }
                    } else {
                        None
                    }
                })
                .collect(),
        )
    }

    /// Contacts one neighbor to get its Identity.
    pub fn neighbor_inquiry(&mut self, ip: IpAddr, dev: &str) -> Result<Identity, Error> {
        let url = format!("http://[{}%{}]:4876/hello", ip, dev);
        trace!("Saying hello to: {:?}", url);

        let socket = match ip {
            IpAddr::V6(ip_v6) => {
                SocketAddr::V6(SocketAddrV6::new(ip_v6, 4876, 0, self.ki.get_iface_index(dev)?))
            }
            IpAddr::V4(_) => {
                return Err(Error::TunnelManagerError(String::from("IPv4 neighbors are not supported")))
            }
        };

        let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(1))?;

        // Format HTTP request
        let header = format!("GET /hello HTTP/1.0\r\nHost: {}%{}\r\n\r\n", ip, dev);  //TODO: check if this is a proper HTTP request
        stream.write(header.as_bytes())?;

        // Make request and return response as string
        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;

        trace!("They replied {}", &resp);

        if let Ok(response) = Response::new(resp.into_bytes()){
            let mut identity: Identity = serde_json::from_str(&response.text())?;
            Ok(identity)
        }else{
            Err(Error::HTTPParseError)
        }
    }

//    /// Given a LocalIdentity, connect to the neighbor over wireguard
//    pub fn connect(&mut self, id: LocalIdentity) -> Result<Identity, Error> {
//        let mut tunnel = self.tunnel_map.entry(id.global.mesh_ip).or_insert(TunnelData::new());
//        self.ki.open_tunnel(&tunnel.iface_name,
//                            SocketAddrV6::new(id.local_ip, id.wg_port, 0, 0),
//                            id.global.wg_public_key,
//                            SETTING.wg_private_key,
//        )?;
//        Ok(())
//    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
