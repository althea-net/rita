use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::path::Path;

use actix::actors::resolver;
use actix::prelude::*;

use futures;
use futures::Future;

use althea_types::{Identity, LocalIdentity};

use KI;

use babel_monitor::{Babel, Route};

use rita_common;
use rita_common::http_client::Hello;

use settings::RitaCommonSettings;
use SETTING;

use failure::Error;

#[cfg(test)]
use actix::actors::mocker::Mocker;
use ipnetwork::IpNetwork;

#[cfg(test)]
type HTTPClient = Mocker<rita_common::http_client::HTTPClient>;

#[cfg(not(test))]
type HTTPClient = rita_common::http_client::HTTPClient;

#[cfg(test)]
type Resolver = Mocker<resolver::Resolver>;

#[cfg(not(test))]
type Resolver = resolver::Resolver;

#[derive(Debug, Fail)]
pub enum TunnelManagerError {
    #[fail(display = "DNS lookup error")]
    DNSLookupError,
}

#[derive(Debug, Clone)]
pub struct TunnelData {
    pub iface_name: String,
    pub listen_port: u16,
}

impl TunnelData {
    fn new(listen_port: u16) -> TunnelData {
        let iface_name = KI.setup_wg_if().unwrap();
        TunnelData {
            iface_name,
            listen_port,
        }
    }
}

pub struct TunnelManager {
    pub port: u16,

    tunnel_map: HashMap<IpAddr, TunnelData>,
    listen_interfaces: HashSet<String>,
}

impl Actor for TunnelManager {
    type Context = Context<Self>;
}
impl Supervised for TunnelManager {}
impl SystemService for TunnelManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Tunnel manager started");

        for i in SETTING.get_network().peer_interfaces.clone() {
            self.listen_interfaces.insert(i);
        }
        trace!("Loaded listen interfaces {:?}", self.listen_interfaces);
    }
}

impl Default for TunnelManager {
    fn default() -> TunnelManager {
        TunnelManager::new()
    }
}

pub struct GetWgInterface(pub IpAddr);
impl Message for GetWgInterface {
    type Result = Result<TunnelData, Error>;
}

impl Handler<GetWgInterface> for TunnelManager {
    type Result = Result<TunnelData, Error>;

    fn handle(&mut self, msg: GetWgInterface, _: &mut Context<Self>) -> Self::Result {
        Ok(self.get_if(msg.0))
    }
}

pub struct Listen(pub String);
impl Message for Listen {
    type Result = ();
}

impl Handler<Listen> for TunnelManager {
    type Result = ();

    fn handle(&mut self, listen: Listen, _: &mut Context<Self>) -> Self::Result {
        self.listen_interfaces.insert(listen.0);
        SETTING.get_network_mut().peer_interfaces = self.listen_interfaces.clone();
    }
}

#[derive(Debug)]
pub struct GetPhyIpFromMeshIp(pub IpAddr);
impl Message for GetPhyIpFromMeshIp {
    type Result = Result<IpAddr, Error>;
}

impl Handler<GetPhyIpFromMeshIp> for TunnelManager {
    type Result = Result<IpAddr, Error>;

    fn handle(&mut self, mesh_ip: GetPhyIpFromMeshIp, _: &mut Context<Self>) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;

        let mut babel = Babel::new(stream);
        babel.start_connection()?;
        let routes = babel.parse_routes()?;

        let mut route_to_des: Option<Route> = None;

        for route in routes {
            // Only ip6
            if let IpNetwork::V6(ref ip) = route.prefix {
                // Only host addresses and installed routes
                if ip.prefix() == 128 && route.installed {
                    if IpAddr::V6(ip.ip()) == mesh_ip.0 {
                        route_to_des = Some(route.clone());
                    }
                }
            }
        }

        match route_to_des {
            Some(route) => Ok(KI.get_wg_remote_ip(&route.iface)?),
            None => bail!("No route found for mesh ip: {:?}", mesh_ip),
        }
    }
}

pub struct UnListen(pub String);
impl Message for UnListen {
    type Result = ();
}

impl Handler<UnListen> for TunnelManager {
    type Result = ();

    fn handle(&mut self, un_listen: UnListen, _: &mut Context<Self>) -> Self::Result {
        self.listen_interfaces.remove(&un_listen.0);
        SETTING.get_network_mut().peer_interfaces = self.listen_interfaces.clone();
    }
}

pub struct GetListen;
impl Message for GetListen {
    type Result = Result<HashSet<String>, Error>;
}

impl Handler<GetListen> for TunnelManager {
    type Result = Result<HashSet<String>, Error>;
    fn handle(&mut self, _: GetListen, _: &mut Context<Self>) -> Self::Result {
        Ok(self.listen_interfaces.clone())
    }
}

pub struct GetNeighbors;
impl Message for GetNeighbors {
    type Result = Result<Vec<(LocalIdentity, String, IpAddr)>, Error>;
}

impl Handler<GetNeighbors> for TunnelManager {
    type Result = ResponseFuture<Vec<(LocalIdentity, String, IpAddr)>, Error>;

    fn handle(&mut self, _: GetNeighbors, _: &mut Context<Self>) -> Self::Result {
        self.get_neighbors()
    }
}

pub struct GetLocalIdentity {
    pub from: IpAddr,
}
impl Message for GetLocalIdentity {
    type Result = LocalIdentity;
}

impl Handler<GetLocalIdentity> for TunnelManager {
    type Result = MessageResult<GetLocalIdentity>;

    fn handle(&mut self, their_id: GetLocalIdentity, _: &mut Context<Self>) -> Self::Result {
        MessageResult(self.get_local_identity(their_id.from))
    }
}

pub struct OpenTunnel(pub LocalIdentity, pub IpAddr);

impl Message for OpenTunnel {
    type Result = ();
}

impl Handler<OpenTunnel> for TunnelManager {
    type Result = ();

    fn handle(&mut self, their_id: OpenTunnel, _: &mut Context<Self>) -> Self::Result {
        self.open_tunnel(their_id.0, their_id.1).unwrap();
        ()
    }
}

pub struct OpenTunnelListener(pub Identity);

impl Message for OpenTunnelListener {
    type Result = ();
}

impl Handler<OpenTunnelListener> for TunnelManager {
    type Result = ();

    fn handle(&mut self, their_id: OpenTunnelListener, _: &mut Context<Self>) -> Self::Result {
        self.open_tunnel_listener(their_id.0).unwrap();
        ()
    }
}

impl TunnelManager {
    pub fn new() -> Self {
        TunnelManager {
            tunnel_map: HashMap::new(),
            port: SETTING.get_network().wg_start_port,
            listen_interfaces: SETTING.get_network().peer_interfaces.clone(),
        }
    }

    fn new_if(&mut self) -> TunnelData {
        trace!("creating new interface");
        let r = TunnelData::new(self.port);
        info!("creating new wg interface {:?}", r);

        self.port += 1;
        r
    }

    fn get_if(&mut self, ip: IpAddr) -> TunnelData {
        if self.tunnel_map.contains_key(&ip) {
            trace!("found existing wg interface for {}", ip);
            self.tunnel_map[&ip].clone()
        } else {
            trace!("creating new wg interface for {}", ip);
            let new = self.new_if();
            self.tunnel_map.insert(ip.clone(), new.clone());
            new
        }
    }

    /// This gets the list of link-local neighbors, and then contacts them to get their
    /// Identity using `neighbor_inquiry` as well as their wireguard tunnel name
    pub fn get_neighbors(&mut self) -> ResponseFuture<Vec<(LocalIdentity, String, IpAddr)>, Error> {
        KI.trigger_neighbor_disc(&SETTING.get_network().peer_interfaces)
            .unwrap();
        let neighs: Vec<
            Box<Future<Item = Option<(LocalIdentity, String, IpAddr)>, Error = ()>>,
        > = KI
            .get_neighbors()
            .unwrap()
            .iter()
            .map(|&(ip_address, ref dev)| (ip_address.to_string(), Some(dev.clone())))
            .chain({
                let mut out = Vec::new();
                if SETTING.get_network().is_gateway && SETTING.get_network().external_nic.is_some()
                {
                    for i in SETTING.get_network().manual_peers.clone() {
                        out.push((i, SETTING.get_network().external_nic.clone()))
                    }
                }
                out
            }).filter_map(|(ip_address, dev)| {
                info!("neighbor at interface {:?}, ip {}", dev, ip_address,);
                if let Some(dev) = dev.clone() {
                    // Demorgans equal to "if a neighbor is on the listen interfaces and has a valid
                    // ip or if it's a manual peer and from the right nic don't filter it"
                    if !(self.listen_interfaces.contains(&dev)
                        && ip_address.parse::<IpAddr>().is_ok())
                        && !(SETTING.get_network().external_nic.is_some()
                            && SETTING
                                .get_network()
                                .external_nic
                                .clone()
                                .unwrap()
                                .contains(&dev)
                            && SETTING.get_network().manual_peers.contains(&ip_address))
                    {
                        info!(
                            "Filtering neighbor at interface {:?}, ip {}",
                            dev, ip_address,
                        );
                        return None;
                    }
                }
                Some(
                    Box::new(
                        self.neighbor_inquiry(ip_address, dev.clone())
                            .then(|res| match res {
                                Ok(res) => futures::future::ok(Some(res)),
                                Err(err) => {
                                    warn!("got error {:} from neighbor inquiry", err);
                                    futures::future::ok(None)
                                }
                            }),
                    )
                        as Box<Future<Item = Option<(LocalIdentity, String, IpAddr)>, Error = ()>>,
                )
            }).collect();
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
        their_hostname: String,
        dev: Option<String>,
    ) -> Box<Future<Item = (LocalIdentity, String, IpAddr), Error = Error>> {
        trace!("Getting tunnel, inq");
        let iface_index = if let Some(dev) = dev.clone() {
            KI.get_iface_index(&dev).unwrap()
        } else {
            0
        };

        trace!("Checking if {} is a url", their_hostname);
        match their_hostname.parse::<IpAddr>() {
            Ok(ip) => Box::new({
                let url = format!("http://[{}%{:?}]:4876/hello", their_hostname, dev);
                info!("Saying hello to: {:?}", url);

                TunnelManager::contact_neighbor(iface_index, ip)
            }),
            _ => Box::new(
                Resolver::from_registry()
                    .send(resolver::Resolve::host(their_hostname.clone()))
                    .from_err()
                    .and_then(move |res| {
                        let url = format!("http://[{}%{:?}]:4876/hello", their_hostname, dev);
                        info!("Saying hello to: {:?} at ip {:?}", url, res);

                        if let Ok(res) = res {
                            if res.len() > 0 && SETTING.get_network().is_gateway {
                                let their_ip = res[0].ip();

                                TunnelManager::contact_neighbor(iface_index, their_ip)
                            } else {
                                trace!(
                                    "We're not a gateway or we got a zero length dns response: {:?}",
                                    res
                                );
                                Box::new(futures::future::err(
                                    TunnelManagerError::DNSLookupError.into(),
                                ))
                            }
                        } else {
                            trace!("Error during dns request!");
                            Box::new(futures::future::err(
                                TunnelManagerError::DNSLookupError.into(),
                            ))
                        }
                    }),
            ),
        }
    }

    fn contact_neighbor(
        iface_index: u32,
        their_ip: IpAddr,
    ) -> Box<Future<Item = (LocalIdentity, String, IpAddr), Error = Error>> {
        KI.manual_peers_route(&their_ip, &mut SETTING.get_network_mut().default_route)
            .unwrap();

        let socket = match their_ip {
            IpAddr::V6(ip_v6) => SocketAddr::V6(SocketAddrV6::new(
                ip_v6,
                SETTING.get_network().rita_hello_port,
                0,
                iface_index,
            )),
            IpAddr::V4(ip_v4) => SocketAddr::V4(SocketAddrV4::new(
                ip_v4,
                SETTING.get_network().rita_hello_port,
            )),
        };
        Box::new(
            HTTPClient::from_registry()
                .send(Hello {
                    my_id: SETTING.get_identity(),
                    to: socket,
                }).from_err()
                .and_then(move |res| match res {
                    Ok(res) => Box::new(
                        TunnelManager::from_registry()
                            .send(GetWgInterface(res.global.mesh_ip))
                            .from_err()
                            .and_then(move |interface| Ok((res, interface?.iface_name, their_ip))),
                    )
                        as Box<Future<Item = (LocalIdentity, String, IpAddr), Error = Error>>,
                    Err(e) => Box::new(futures::future::err(e))
                        as Box<Future<Item = (LocalIdentity, String, IpAddr), Error = Error>>,
                }),
        )
    }

    pub fn get_local_identity(&mut self, mesh_ip: IpAddr) -> LocalIdentity {
        trace!("Getting tunnel, local id");
        let tunnel = self.get_if(mesh_ip);

        LocalIdentity {
            global: SETTING.get_identity(),
            wg_port: tunnel.listen_port,
        }
    }

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    pub fn open_tunnel(&mut self, their_id: LocalIdentity, ip: IpAddr) -> Result<(), Error> {
        trace!("Getting tunnel, open tunnel");
        let tunnel = self.get_if(their_id.global.mesh_ip);
        let network = SETTING.get_network().clone();

        KI.open_tunnel(
            &tunnel.iface_name,
            tunnel.listen_port,
            &SocketAddr::new(ip, their_id.wg_port),
            &their_id.global.wg_public_key,
            Path::new(&network.wg_private_key_path),
            &network.own_ip,
            network.external_nic.clone(),
            &mut SETTING.get_network_mut().default_route,
        )?;

        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;

        let mut babel = Babel::new(stream);

        babel.start_connection()?;
        babel.monitor(&tunnel.iface_name)?;
        Ok(())
    }

    /// Given a LocalIdentity, listens for a neighbor over wireguard
    pub fn open_tunnel_listener(&mut self, their_id: Identity) -> Result<(), Error> {
        trace!("Getting tunnel, open tunnel");
        let tunnel = self.get_if(their_id.mesh_ip);
        let network = SETTING.get_network().clone();

        KI.open_tunnel_listener(
            &tunnel.iface_name,
            tunnel.listen_port,
            &their_id.wg_public_key,
            Path::new(&network.wg_private_key_path),
            &network.own_ip,
        )?;

        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;

        let mut babel = Babel::new(stream);

        babel.start_connection()?;
        babel.monitor(&tunnel.iface_name)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use actix::*;
    use futures::{future, Future};

    use env_logger;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    use super::*;

    use actix::actors::resolver::ResolverError;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    fn vec_string_to_str<'a>(vstr: &'a Vec<String>) -> Vec<&'a str> {
        let mut arr = Vec::new();
        for i in 0..vstr.len() {
            arr.push(vstr[i].as_str());
        }
        arr
    }

    #[test]
    fn test_contact_neighbor_ipv4() {
        env_logger::init();

        let link_args = &["link"];
        let link_add = &["link", "add", "wg1", "type", "wireguard"];

        let mut counter = 0;
        KI.set_mock(Box::new(move |program, args| {
            counter += 1;

            trace!(
                "program {:?}, args {:?}, counter {}",
                program,
                args,
                counter
            );

            match counter {
                1 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, ["route", "list", "default"]);
                    Ok(Output {
                        stdout: b"default via 192.168.1.1 dev eth0 proto static metric 600\n"
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                2 => {
                    assert_eq!(program, "ip");
                    assert_eq!(
                        args,
                        [
                            "route",
                            "add",
                            "1.1.1.1",
                            "via",
                            "192.168.1.1",
                            "dev",
                            "eth0",
                            "proto",
                            "static",
                            "metric",
                            "600"
                        ]
                    );
                    Ok(Output {
                        stdout: b"ok".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                3 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, link_args);
                    Ok(Output {
                        stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                4 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, link_add);
                    Ok(Output {
                        stdout: b"".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                _ => panic!("command called too many times"),
            }
        }));

        let sys = System::new("test");

        System::current().registry().set(
            HTTPClient::mock(Box::new(|msg, _ctx| {
                assert_eq!(
                    msg.downcast_ref::<Hello>(),
                    Some(&Hello {
                        my_id: SETTING.get_identity(),
                        to: SocketAddr::V4(SocketAddrV4::new("1.1.1.1".parse().unwrap(), 4876))
                    })
                );

                let ret: Result<LocalIdentity, Error> = Ok(LocalIdentity {
                    wg_port: 60000,
                    global: SETTING.get_identity(),
                });
                Box::new(Some(ret))
            })).start(),
        );

        let res = TunnelManager::contact_neighbor(0, "1.1.1.1".parse().unwrap());

        Arbiter::spawn(res.then(|res| {
            assert_eq!(
                res.unwrap(),
                (
                    LocalIdentity {
                        wg_port: 60000,
                        global: SETTING.get_identity(),
                    },
                    "wg1".to_string(),
                    "1.1.1.1".parse().unwrap()
                )
            );

            System::current().stop();
            future::result(Ok(()))
        }));

        sys.run();
    }

    #[test]
    fn test_neighbor_inquiry_domain() {
        let link_args = &["link"];
        let link_add = &["link", "add", "wg1", "type", "wireguard"];

        let mut counter = 0;
        KI.set_mock(Box::new(move |program, args| {
            counter += 1;
            trace!(
                "program {:?}, args {:?}, counter {}",
                program,
                args,
                counter
            );

            match counter {
                1 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, ["route", "list", "default"]);
                    Ok(Output {
                        stdout: b"default via 192.168.1.1 dev eth0 proto static metric 600\n"
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                2 => {
                    assert_eq!(program, "ip");
                    assert_eq!(
                        args,
                        [
                            "route",
                            "add",
                            "1.1.1.1",
                            "via",
                            "192.168.1.1",
                            "dev",
                            "eth0",
                            "proto",
                            "static",
                            "metric",
                            "600"
                        ]
                    );
                    Ok(Output {
                        stdout: b"ok".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                3 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, link_args);
                    Ok(Output {
                        stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                4 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, link_add);
                    Ok(Output {
                        stdout: b"".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                _ => panic!("command called too many times"),
            }
        }));

        let sys = System::new("test");

        System::current().registry().set(
            HTTPClient::mock(Box::new(|msg, _ctx| {
                assert_eq!(
                    msg.downcast_ref::<Hello>(),
                    Some(&Hello {
                        my_id: SETTING.get_identity(),
                        to: SocketAddr::V4(SocketAddrV4::new("1.1.1.1".parse().unwrap(), 4876))
                    })
                );

                let ret: Result<LocalIdentity, Error> = Ok(LocalIdentity {
                    wg_port: 60000,
                    global: SETTING.get_identity(),
                });
                Box::new(Some(ret))
            })).start(),
        );

        System::current().registry().set(
            Resolver::mock(Box::new(|msg, _ctx| {
                assert_eq!(
                    msg.downcast_ref::<actors::resolver::Resolve>(),
                    Some(&actors::resolver::Resolve::host("test.altheamesh.com"))
                );

                let ret: Result<VecDeque<SocketAddr>, ResolverError> = Ok({
                    let mut ips = VecDeque::new();
                    ips.push_back(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 0));
                    ips
                });
                Box::new(Some(ret))
            })).start(),
        );

        let mut tm = TunnelManager::new();
        let res = tm.neighbor_inquiry("test.altheamesh.com".to_string(), None);

        Arbiter::spawn(res.then(|res| {
            assert_eq!(
                res.unwrap(),
                (
                    LocalIdentity {
                        wg_port: 60000,
                        global: SETTING.get_identity(),
                    },
                    "wg1".to_string(),
                    "1.1.1.1".parse().unwrap()
                )
            );

            System::current().stop();
            future::result(Ok(()))
        }));

        sys.run();
    }

    #[test]
    fn test_neighbor_inquiry_ip() {
        let link_args = &["link"];
        let link_add = &["link", "add", "wg1", "type", "wireguard"];

        let mut counter = 0;
        KI.set_mock(Box::new(move |program, args| {
            counter += 1;
            trace!(
                "program {:?}, args {:?}, counter {}",
                program,
                args,
                counter
            );

            match counter {
                1 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, ["route", "list", "default"]);
                    Ok(Output {
                        stdout: b"default via 192.168.1.1 dev eth0 proto static metric 600\n"
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                2 => {
                    assert_eq!(program, "ip");
                    assert_eq!(
                        args,
                        [
                            "route",
                            "add",
                            "1.1.1.1",
                            "via",
                            "192.168.1.1",
                            "dev",
                            "eth0",
                            "proto",
                            "static",
                            "metric",
                            "600"
                        ]
                    );
                    Ok(Output {
                        stdout: b"ok".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                3 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, link_args);
                    Ok(Output {
                        stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                4 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, link_add);
                    Ok(Output {
                        stdout: b"".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                _ => panic!("command called too many times"),
            }
        }));

        let sys = System::new("test");

        System::current().registry().set(
            HTTPClient::mock(Box::new(|msg, _ctx| {
                assert_eq!(
                    msg.downcast_ref::<Hello>(),
                    Some(&Hello {
                        my_id: SETTING.get_identity(),
                        to: SocketAddr::V4(SocketAddrV4::new("1.1.1.1".parse().unwrap(), 4876))
                    })
                );

                let ret: Result<LocalIdentity, Error> = Ok(LocalIdentity {
                    wg_port: 60000,
                    global: SETTING.get_identity(),
                });
                Box::new(Some(ret))
            })).start(),
        );

        System::current().registry().set(
            Resolver::mock(Box::new(|msg, _ctx| {
                assert_eq!(
                    msg.downcast_ref::<actors::resolver::Resolve>(),
                    Some(&actors::resolver::Resolve::host("1.1.1.1"))
                );

                let ret: Result<VecDeque<SocketAddr>, ResolverError> =
                    Err(ResolverError::Resolver("Thats an IP address!".to_string()));
                Box::new(Some(ret))
            })).start(),
        );

        let mut tm = TunnelManager::new();
        let res = tm.neighbor_inquiry("1.1.1.1".to_string(), None);

        Arbiter::spawn(res.then(|res| {
            assert_eq!(
                res.unwrap(),
                (
                    LocalIdentity {
                        wg_port: 60000,
                        global: SETTING.get_identity(),
                    },
                    "wg1".to_string(),
                    "1.1.1.1".parse().unwrap()
                )
            );

            System::current().stop();
            future::result(Ok(()))
        }));

        sys.run();
    }

    fn get_inc_id(ctr: u16) -> Identity {
        let mut their_id = SETTING.get_identity();
        match their_id.mesh_ip {
            IpAddr::V6(address) => {
                let mut segments = address.segments();
                segments[7] = ctr;
                their_id.mesh_ip = segments.into();
            }
            _ => panic!("Mesh IP must be ipv6"),
        }
        their_id
    }

    #[test]
    fn test_get_neighbors() {
        let mut ip_route_add_counter = 0;
        let mut iface_counter = 0;

        let external_ips = ["fe80::1234", "2.2.2.2", "1.1.1.1"];
        let wg_ifaces = ["wg0", "wg1", "wg2"];

        KI.set_mock(Box::new(move |program, args| {
            match (program.as_str(), &vec_string_to_str(&args)[..]) {
                ("ping6", _) => {
                    return Ok(Output {
                        stdout: b"".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                ("ip", ["neighbor"]) => {
                    return Ok(Output {
                        stdout: b"fe80::1234 dev eth0 lladdr dc:6d:cd:ae:bd:a6 REACHABLE".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                ("ip", ["route", "list", "default"]) => {
                    return Ok(Output {
                        stdout: b"default via 192.168.1.1 dev eth0 proto static metric 600\n"
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                (
                    "ip",
                    ["route", "add", external_ip, "via", "192.168.1.1", "dev", "eth0", "proto", "static", "metric", "600"],
                ) => {
                    assert_eq!(external_ip, &external_ips[ip_route_add_counter]);
                    ip_route_add_counter += 1;
                    return Ok(Output {
                        stdout: b"ok".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    });
                }
                ("ip", ["link", "add", iface_name, "type", "wireguard"]) => {
                    assert_eq!(iface_name, &wg_ifaces[iface_counter]);
                    iface_counter += 1;
                    return Ok(Output {
                        stdout: b"".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                ("ip", ["link"]) => {
                    match iface_counter {
                        0 => {
                            return Ok(Output {
                                stdout: b"82: eth0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                                stderr: b"".to_vec(),
                                status: ExitStatus::from_raw(0),
                            })
                        }
                        1 => {
                            return Ok(Output {
                                stdout: b"82: eth0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000\
83: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                                stderr: b"".to_vec(),
                                status: ExitStatus::from_raw(0),
                            })
                        }
                        2 => {
                            return Ok(Output {
                                stdout: b"82: eth0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000\
83: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000\
84: wg1: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                                stderr: b"".to_vec(),
                                status: ExitStatus::from_raw(0),
                            })
                        }
                        _ => {
                            panic!("ip link called too many times")
                        }
                    }
                }
                (program, args) => (
                    panic!("unimplemented program: {} {:?}", program, args)
                    ),
            }
        }));

        let sys = System::new("test");

        SETTING.get_network_mut().manual_peers =
            vec!["test.altheamesh.com".to_string(), "2.2.2.2".to_string()];
        SETTING.get_network_mut().is_gateway = true;
        SETTING
            .get_network_mut()
            .peer_interfaces
            .insert("eth0".to_string());
        SETTING.get_network_mut().external_nic = Some("eth0".to_string());

        let mut ctr = 1;

        System::current().registry().set(
            HTTPClient::mock(Box::new(move |msg, _ctx| {
                trace!("{:?}", msg.downcast_ref::<Hello>());
                let ret: Result<LocalIdentity, Error> = match msg.downcast_ref::<Hello>() {
                    Some(&Hello {
                        my_id: ref id,
                        to: _,
                    }) => {
                        assert_eq!(id, &SETTING.get_identity());
                        Ok(LocalIdentity {
                            wg_port: 60000 + ctr,
                            global: get_inc_id(ctr),
                        })
                    }
                    _ => {
                        panic!("Wrong message sent to HTTPClient");
                    }
                };
                ctr += 1;
                Box::new(Some(ret))
            })).start(),
        );

        System::current().registry().set(
            Resolver::mock(Box::new(|msg, _ctx| {
                let msg = msg.downcast_ref::<actors::resolver::Resolve>().unwrap();
                let ret: Result<VecDeque<SocketAddr>, ResolverError> = if msg
                    == &actors::resolver::Resolve::host("fe80::1234")
                {
                    Err(ResolverError::Resolver("Thats an IP address!".to_string()))
                } else if msg == &actors::resolver::Resolve::host("2.2.2.2") {
                    Err(ResolverError::Resolver("Thats an IP address!".to_string()))
                } else if msg == &actors::resolver::Resolve::host("test.altheamesh.com") {
                    Ok({
                        let mut ips = VecDeque::new();
                        ips.push_back(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 0));
                        ips
                    })
                } else {
                    panic!("unexpected host found")
                };
                Box::new(Some(ret))
            })).start(),
        );

        let mut tm = TunnelManager::new();
        let res = tm.get_neighbors();

        Arbiter::spawn(res.then(|res| {
            assert_eq!(
                res.unwrap(),
                vec![
                    (
                        LocalIdentity {
                            wg_port: 60001,
                            global: get_inc_id(1),
                        },
                        "wg0".to_string(),
                        "fe80::1234".parse().unwrap(),
                    ),
                    (
                        LocalIdentity {
                            wg_port: 60003,
                            global: get_inc_id(3),
                        },
                        "wg2".to_string(),
                        "1.1.1.1".parse().unwrap(),
                    ),
                    (
                        LocalIdentity {
                            wg_port: 60002,
                            global: get_inc_id(2),
                        },
                        "wg1".to_string(),
                        "2.2.2.2".parse().unwrap(),
                    ),
                ]
            );

            System::current().stop();
            future::result(Ok(()))
        }));

        sys.run();
    }
}
