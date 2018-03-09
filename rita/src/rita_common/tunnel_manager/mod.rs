use std;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::path::Path;
use std::time::Duration;
use std::io::{Read, Write};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};

use minihttpse::Response;

use actix::prelude::*;
use actix::actors::*;

use futures;
use futures::Future;

use althea_types::{EthAddress, Identity, LocalIdentity};

use althea_kernel_interface::KernelInterface;
use althea_kernel_interface;

use babel_monitor::Babel;

use rita_common::http_client::{HTTPClient, Hello};

use serde_json;

use SETTING;

use failure::Error;

#[derive(Debug, Fail)]
pub enum TunnelManagerError {
    #[fail(display = "IPV4 unsupported error")]
    IPv4UnsupportedError,
}

#[derive(Debug, Clone)]
struct TunnelData {
    iface_name: String,
    listen_port: u16,
}

impl TunnelData {
    fn new(listen_port: u16) -> TunnelData {
        let mut ki = KernelInterface {};
        let iface_name = ki.setup_wg_if().unwrap();
        TunnelData {
            iface_name,
            listen_port,
        }
    }
}

pub struct TunnelManager {
    pub ki: KernelInterface,
    pub port: u16,

    tunnel_map: HashMap<IpAddr, TunnelData>,
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
    type Result = Result<Vec<(LocalIdentity, String)>, Error>;
}

impl Handler<GetNeighbors> for TunnelManager {
    type Result = ResponseFuture<Vec<(LocalIdentity, String)>, Error>;

    fn handle(&mut self, _: GetNeighbors, _: &mut Context<Self>) -> Self::Result {
        self.get_neighbors()
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
    type Result = ();

    fn handle(&mut self, their_id: OpenTunnel, _: &mut Context<Self>) -> Self::Result {
        self.open_tunnel(their_id.0);
        ()
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    if let IpAddr::V6(ip) = ip {
        return (ip.segments()[0] & 0xffc0) == 0xfe80;
    }
    false
}

impl TunnelManager {
    pub fn new() -> Self {
        let tm = TunnelManager {
            ki: KernelInterface {},
            tunnel_map: HashMap::new(),
            port: SETTING.read().unwrap().network.wg_start_port,
        };
        tm
    }

    fn new_if(&mut self) -> TunnelData {
        trace!("creating new interface");
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
    /// Identity using `neighbor_inquiry` as well as their wireguard tunnel name
    pub fn get_neighbors(&mut self) -> ResponseFuture<Vec<(LocalIdentity, String)>, Error> {
        self.ki.trigger_neighbor_disc();
        let neighs: Vec<Box<Future<Item = Option<(LocalIdentity, String)>, Error = Error>>> =
            self.ki
                .get_neighbors()
                .unwrap()
                .iter()
                .filter_map(|&(mac_address, ip_address, ref dev)| {
                    trace!(
                        "neighbor at interface {}, ip {}, mac {}",
                        dev,
                        ip_address,
                        mac_address
                    );
                    if &dev[..2] != "wg" && is_link_local(ip_address) {
                        {
                            Some(
                                Box::new(self.neighbor_inquiry(ip_address, &dev).then(|res| {
                                    match res {
                                        Ok(res) => futures::future::ok(Some(res)),
                                        Err(err) => {
                                            warn!("got error {:} from neighbor inquiry", err);
                                            futures::future::ok(None)
                                        }
                                    }
                                }))
                                    as Box<
                                        Future<
                                            Item = Option<(LocalIdentity, String)>,
                                            Error = Error,
                                        >,
                                    >,
                            )
                        }
                    } else {
                        None
                    }
                })
                .collect();
        Box::new(futures::future::join_all(neighs).then(|res| {
            let mut output = Vec::new();
            for i in res.unwrap() {
                match i {
                    Some(i) => {
                        output.push(i);
                    }
                    _ => {}
                }
            }
            futures::future::ok(output)
        }))
    }

    /// Contacts one neighbor with our LocalIdentity to get their LocalIdentity and wireguard tunnel
    /// interface name.
    pub fn neighbor_inquiry(
        &mut self,
        their_ip: IpAddr,
        dev: &str,
    ) -> ResponseFuture<(LocalIdentity, String), Error> {
        let url = format!("http://[{}%{}]:4876/hello", their_ip, dev);
        trace!("Saying hello to: {:?}", url);

        let socket = match their_ip {
            IpAddr::V6(ip_v6) => SocketAddr::V6(SocketAddrV6::new(
                ip_v6,
                4876,
                0,
                self.ki.get_iface_index(dev).unwrap(),
            )),
            IpAddr::V4(_) => {
                return Box::new(futures::future::err(
                    TunnelManagerError::IPv4UnsupportedError.into(),
                ))
            }
        };

        trace!("Getting tunnel, inq");
        let tunnel = self.get_if(&their_ip);

        let my_id = LocalIdentity {
            global: SETTING.read().unwrap().get_identity(),
            local_ip: self.ki.get_link_local_reply_ip(their_ip).unwrap(),
            wg_port: tunnel.listen_port,
        };

        Box::new(
            HTTPClient::from_registry()
                .send(Hello { my_id, to: socket })
                .then(|res| {
                    let r = res??;
                    Ok((r, tunnel.iface_name))
                }),
        )
    }

    pub fn get_local_identity(&mut self, requester: &LocalIdentity) -> LocalIdentity {
        trace!("Getting tunnel, local id");
        let tunnel = self.get_if(&requester.local_ip);

        let local_ip = self.ki.get_link_local_reply_ip(requester.local_ip).unwrap();

        LocalIdentity {
            global: SETTING.read().unwrap().get_identity(),
            local_ip,
            wg_port: tunnel.listen_port,
        }
    }

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    pub fn open_tunnel(&mut self, their_id: LocalIdentity) -> Result<(), Error> {
        trace!("Getting tunnel, open tunnel");
        let tunnel = self.get_if(&their_id.local_ip);
        self.ki.open_tunnel(
            &tunnel.iface_name,
            tunnel.listen_port,
            &SocketAddr::new(their_id.local_ip, their_id.wg_port),
            &their_id.global.wg_public_key,
            Path::new(&SETTING.read().unwrap().network.wg_private_key_path),
            &SETTING.read().unwrap().network.own_ip,
        )?;

        let mut babel = Babel::new(&format!(
            "[::1]:{}",
            SETTING.read().unwrap().network.babel_port
        ).parse()
            .unwrap());
        babel.monitor(&tunnel.iface_name)?;
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
