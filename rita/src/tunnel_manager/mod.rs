use std;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, SocketAddrV4, TcpStream};
use std::path::Path;
use std::time::Duration;
use std::io::{Read, Write};
use std::collections::HashMap;
use std::sync::mpsc::{Sender, Receiver, channel};

use minihttpse::Response;

use actix::prelude::*;

use althea_types::{EthAddress, Identity, LocalIdentity};

use althea_kernel_interface::KernelInterface;
use althea_kernel_interface;

use reqwest;
use reqwest::Client;
use serde_json;

use settings::SETTING;

#[derive(Debug, Error)]
pub enum Error {
    KernelInterfaceError(althea_kernel_interface::Error),
    HttpReqError(reqwest::Error),
    IOError(std::io::Error),
    DeserializationError(serde_json::Error),
    HTTPParseError,
    #[error(msg_embedded, no_from, non_std)] TunnelManagerError(String),
}


#[derive(Debug, Clone)]
struct TunnelData {
    iface_name: String,
    listen_port: u16
}

impl TunnelData {
    fn new(listen_port: u16) -> TunnelData {
        let mut ki =  KernelInterface {};
        let iface_name = ki.setup_wg_if().unwrap();
        TunnelData{
            iface_name,
            listen_port
        }
    }
}

pub struct TunnelManager {
    pub client: Client,
    pub ki: KernelInterface,
    pub port: u16,

    tunnel_map: HashMap<IpAddr, TunnelData>
}

impl Actor for TunnelManager {
    type Context = Context<Self>;
}
impl Supervised for TunnelManager {}
impl SystemService for TunnelManager {
    fn service_started(&mut self, ctx: &mut Context<Self>) {
        info!("Tunnel manager started");
    }
}

impl Default for TunnelManager {
    fn default() -> TunnelManager {
        TunnelManager::new()
    }
}

pub struct GetNeighbors;
impl Message for GetNeighbors {
    type Result = Result<Vec<LocalIdentity>, Error>;
}

impl Handler<GetNeighbors> for TunnelManager {
    type Result = MessageResult<GetNeighbors>;

    fn handle(&mut self, _: GetNeighbors, _: &mut Context<Self>) -> Self::Result {
        MessageResult(self.get_neighbors())
    }
}

pub struct GetLocalIdentity {
    pub requester: LocalIdentity,
}
impl Message for GetLocalIdentity {
    type Result = LocalIdentity;
}

impl Handler<GetLocalIdentity> for TunnelManager {
    type Result = MessageResult<GetLocalIdentity>;

    fn handle(&mut self, their_id: GetLocalIdentity, _: &mut Context<Self>) -> Self::Result {
        MessageResult(self.get_local_identity(&their_id.requester))
    }
}

pub struct OpenTunnel(pub LocalIdentity);

impl Message for OpenTunnel {
    type Result = ();
}

impl Handler<OpenTunnel> for TunnelManager {
    type Result =();

    fn handle(&mut self, their_id: OpenTunnel, _: &mut Context<Self>) -> Self::Result {
        self.open_tunnel(their_id.0);
        ()
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    if let IpAddr::V6(ip) = ip {
        return (ip.segments()[0] & 0xffc0) == 0xfe80
    }
    false
}

impl TunnelManager {
    pub fn new() -> Self {
        let mut tm = TunnelManager {
            client: Client::new(),
            ki: KernelInterface {},
            tunnel_map: HashMap::new(),
            port: SETTING.network.wg_start_port,
        };
        tm
    }

    fn new_if(&mut self) -> TunnelData {
        let r = TunnelData::new(self.port);
        self.port += 1;
        r
    }

    fn get_if(&mut self, ip: &IpAddr) -> TunnelData {
        if self.tunnel_map.contains_key(&ip) {
            trace!("found existing wg interface for {}", ip);
            self.tunnel_map[ip].clone()
        } else {
            trace!("creating new wg interface for {}", ip);
            let new = self.new_if();
            self.tunnel_map.insert(ip.clone(), new.clone());
            new
        }
    }

    /// This gets the list of link-local neighbors, and then contacts them to get their
    /// Identity using `neighbor_inquiry`. It also puts the MAC address of each neighbor
    /// into the identity. This is hacky, but the next version of Rita will not use
    /// a public key instead of a MAC address to identify neighbors, meaning that it is very temporary.
    pub fn get_neighbors(&mut self) -> Result<Vec<LocalIdentity>, Error> {
        Ok(self.ki
            .get_neighbors()?
            .iter()
            .filter_map(|&(mac_address, ip_address, ref dev)| {
                trace!("neighbor at interface {}, ip {}, mac {}", dev, ip_address, mac_address);
                if &dev[..2] != "wg" && is_link_local(ip_address) {
                    {
                        let identity = self.neighbor_inquiry(ip_address, &dev);
                        match identity {
                            Ok(identity) => {

                                trace!("opening tunnel in get neighbour for {:?}", identity);
                                self.open_tunnel(identity.clone());
                                Some(identity)
                            },
                            Err(something) => {
                                trace!("error!!!: {:?}", something);
                                None
                            },
                        }
                    }
                } else {
                    None
                }
            })
            .collect())
    }

    /// Contacts one neighbor with our LocalIdentity to get their LocalIdentity.
    pub fn neighbor_inquiry(&mut self, their_ip: IpAddr, dev: &str) -> Result<LocalIdentity, Error> {
        let url = format!("http://[{}%{}]:4876/hello", their_ip, dev);
        trace!("Saying hello to: {:?}", url);

        let socket = match their_ip {
            IpAddr::V6(ip_v6) => {
                SocketAddr::V6(SocketAddrV6::new(ip_v6, 4876, 0, self.ki.get_iface_index(dev)?))
            }
            IpAddr::V4(_) => {
                return Err(Error::TunnelManagerError(String::from("IPv4 neighbors are not supported")))
            }
        };

        let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(1))?;

        trace!("Getting tunnel, inq");
        let tunnel = self.get_if(&their_ip);

        let my_id = LocalIdentity {
            global: SETTING.get_identity(),
            local_ip: self.ki.get_link_local_reply_ip_linux(their_ip)?,
            wg_port: tunnel.listen_port,
        };

        let my_id = serde_json::to_string(&my_id)?;

        // Format HTTP request
        let request = format!("POST /hello HTTP/1.0\r\n\
Host: {}%{}\r\n\
Content-Type:application/json\r\n\
Content-Length: {}\r\n\r\n
{}\r\n", their_ip, dev, my_id.len() + 1, my_id);  //TODO: make this a lot less ugly

        trace!("Sending http request:\
        {}\nEND", request);
        stream.write(request.as_bytes())?;

        // Make request and return response as string
        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;

        trace!("They replied {}", &resp);

        if let Ok(response) = Response::new(resp.into_bytes()){
            let mut identity: LocalIdentity = serde_json::from_str(&response.text())?;
            Ok(identity)
        }else{
            Err(Error::HTTPParseError)
        }
    }

    pub fn get_local_identity(&mut self, requester: &LocalIdentity) -> LocalIdentity {
        trace!("Getting tunnel, local id");
        let tunnel = self.get_if(&requester.local_ip);

        let local_ip = self.ki.get_link_local_reply_ip_linux(requester.local_ip).unwrap();

        LocalIdentity{
            global: SETTING.get_identity(),
            local_ip,
            wg_port: tunnel.listen_port
        }
    }

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    pub fn open_tunnel(&mut self, their_id: LocalIdentity) -> Result<(), Error> {
        trace!("Getting tunnel, open tunnel");
        let tunnel = self.get_if(&their_id.local_ip);
        self.ki.open_tunnel(&tunnel.iface_name,
                            tunnel.listen_port,
                            &SocketAddr::new(their_id.local_ip, their_id.wg_port),
                            &their_id.global.wg_public_key,
                            Path::new(&SETTING.network.wg_private_key),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
