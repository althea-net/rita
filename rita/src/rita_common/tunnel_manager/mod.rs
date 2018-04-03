use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::path::Path;
use std::collections::HashMap;

use actix::prelude::*;

use futures;
use futures::Future;

use althea_types::LocalIdentity;

use althea_kernel_interface::KernelInterface;

use babel_monitor::Babel;

use rita_common::http_client::{HTTPClient, Hello};

use SETTING;

use failure::Error;
use std::net::SocketAddrV4;

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
        let ki = KernelInterface {};
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
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
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
        self.open_tunnel(their_id.0).unwrap();
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
        TunnelManager {
            ki: KernelInterface {},
            tunnel_map: HashMap::new(),
            port: SETTING.read().unwrap().network.wg_start_port,
        }
    }

    fn new_if(&mut self) -> TunnelData {
        let r = TunnelData::new(self.port);
        info!("creating new wg interface {:?}", r);

        self.port += 1;
        r
    }

    fn get_if(&mut self, ip: &IpAddr) -> TunnelData {
        if self.tunnel_map.contains_key(ip) {
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
        self.ki.trigger_neighbor_disc().unwrap();
        let neighs: Vec<Box<Future<Item = Option<(LocalIdentity, String)>, Error = Error>>> =
            self.ki
                .get_neighbors()
                .unwrap()
                .iter()
                .map(
                    |&(ip_address, ref dev)| {
                        (ip_address, Some(dev))
                    }
                )
                .filter_map(|(ip_address, ref dev)| {
                    info!(
                        "neighbor at interface {:?}, ip {}",
                        dev,
                        ip_address,
                    );
                    if let Some(dev) = dev.clone() {
                        if &dev[..2] == "wg" {
                            return None
                        }
                    }
                    Some(Box::new(self.neighbor_inquiry(ip_address, dev.clone()).then(|res| {
                        match res {
                            Ok(res) => futures::future::ok(Some(res)),
                            Err(err) => {
                                warn!("got error {:} from neighbor inquiry", err);
                                futures::future::ok(None)
                            }
                        }
                    }))
                        as Box<
                            Future<Item = Option<(LocalIdentity, String)>, Error = Error>,
                        >)
                })
                .collect();
        Box::new(futures::future::join_all(neighs).then(|res| {
            let mut output = Vec::new();
            for i in res.unwrap() {
                if let Some(i) = i {
                    output.push(i);
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
        dev: Option<&String>,
    ) -> ResponseFuture<(LocalIdentity, String), Error> {
        let url = format!("http://[{}%{:?}]:4876/hello", their_ip, dev);
        info!("Saying hello to: {:?}", url);

        let socket = match their_ip {
            IpAddr::V6(ip_v6) => SocketAddr::V6(SocketAddrV6::new(
                ip_v6,
                4876,
                0,
                if let Some(dev) = dev {
                    self.ki.get_iface_index(dev).unwrap()
                } else {
                    0
                }
            )),
            IpAddr::V4(ip_v4) => {
                SocketAddr::V4(SocketAddrV4::new(
                    ip_v4,
                    4876,
                ))
            }
        };

        trace!("Getting tunnel, inq");
        let tunnel = self.get_if(&their_ip);

        let my_id = LocalIdentity {
            global: SETTING.read().unwrap().get_identity(),
            local_ip: self.ki.get_reply_ip(their_ip, SETTING.read().unwrap().network.global_non_mesh_ip.clone()).unwrap(),
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

        let local_ip = self.ki.get_reply_ip(requester.local_ip, SETTING.read().unwrap().network.global_non_mesh_ip.clone()).unwrap();

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
