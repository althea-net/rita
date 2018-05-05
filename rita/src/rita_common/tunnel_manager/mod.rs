use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::path::Path;

use actix::actors;
use actix::actors::mocker::Mocker;
use actix::prelude::*;

use futures;
use futures::Future;

use althea_types::LocalIdentity;

use KI;

use babel_monitor::Babel;

use rita_common;
use rita_common::http_client::Hello;

use settings::RitaCommonSettings;
use SETTING;

use failure::Error;

#[cfg(test)]
type HTTPClient = Mocker<rita_common::http_client::HTTPClient>;

#[cfg(not(test))]
type HTTPClient = rita_common::http_client::HTTPClient;

#[cfg(test)]
type Connector = Mocker<actors::Connector>;

#[cfg(not(test))]
type Connector = actors::Connector;

#[derive(Debug, Fail)]
pub enum TunnelManagerError {
    #[fail(display = "DNS lookup error")]
    DNSLookupError,
}

#[derive(Debug, Clone)]
struct TunnelData {
    iface_name: String,
    listen_port: u16,
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

    tunnel_map: HashMap<String, TunnelData>,
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

pub struct Listen(pub String);
impl Message for Listen {
    type Result = ();
}

impl Handler<Listen> for TunnelManager {
    type Result = ();

    fn handle(&mut self, listen: Listen, _: &mut Context<Self>) -> Self::Result {
        self.listen_interfaces.insert(listen.0);
        SETTING.set_network().peer_interfaces = self.listen_interfaces.clone();
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
        SETTING.set_network().peer_interfaces = self.listen_interfaces.clone();
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

    fn get_if(&mut self, ip: String) -> TunnelData {
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
        KI.trigger_neighbor_disc().unwrap();
        let neighs: Vec<
            Box<Future<Item = Option<(LocalIdentity, String, IpAddr)>, Error = ()>>,
        > = KI.get_neighbors()
            .unwrap()
            .iter()
            .map(|&(ip_address, ref dev)| (ip_address.to_string(), Some(dev.clone())))
            .chain({
                let mut out = Vec::new();
                for i in SETTING.get_network().manual_peers.clone() {
                    out.push((i, None))
                }
                out
            })
            .filter_map(|(ip_address, dev)| {
                info!("neighbor at interface {:?}, ip {}", dev, ip_address,);
                if let Some(dev) = dev.clone() {
                    if !self.listen_interfaces.contains(&dev) {
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
        their_ip: String,
        dev: Option<String>,
    ) -> Box<Future<Item = (LocalIdentity, String, IpAddr), Error = Error>> {
        trace!("Getting tunnel, inq");
        let tunnel = self.get_if(their_ip.clone());
        let iface_index = if let Some(dev) = dev.clone() {
            KI.get_iface_index(&dev).unwrap()
        } else {
            0
        };

        Box::new(
            Connector::from_registry()
                .send(actors::Resolve::host(their_ip.clone()))
                .from_err()
                .and_then(move |res| {
                    let url = format!("http://[{}%{:?}]:4876/hello", their_ip, dev);
                    info!("Saying hello to: {:?} at ip {:?}", url, res);

                    if let Ok(res) = res {
                        if res.len() > 0 {
                            let their_ip = res[0].ip();

                            TunnelManager::contact_neighbor(tunnel, iface_index, their_ip)
                        } else {
                            Box::new(futures::future::err(
                                TunnelManagerError::DNSLookupError.into(),
                            ))
                        }
                    } else {
                        match their_ip.parse() {
                            Ok(their_ip) => {
                                TunnelManager::contact_neighbor(tunnel, iface_index, their_ip)
                            }
                            Err(err) => Box::new(futures::future::err(err.into())),
                        }
                    }
                }),
        )
    }

    fn contact_neighbor(
        tunnel: TunnelData,
        iface_index: u32,
        their_ip: IpAddr,
    ) -> Box<Future<Item = (LocalIdentity, String, IpAddr), Error = Error>> {
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
        let my_id = LocalIdentity {
            global: SETTING.get_identity(),
            wg_port: tunnel.listen_port,
        };
        Box::new(
            HTTPClient::from_registry()
                .send(Hello { my_id, to: socket })
                .then(move |res| {
                    let r = res??;
                    Ok((r, tunnel.iface_name, socket.ip()))
                }),
        ) as ResponseFuture<(LocalIdentity, String, IpAddr), Error>
    }

    pub fn get_local_identity(&mut self, local_ip: IpAddr) -> LocalIdentity {
        trace!("Getting tunnel, local id");
        let tunnel = self.get_if(local_ip.to_string());

        LocalIdentity {
            global: SETTING.get_identity(),
            wg_port: tunnel.listen_port,
        }
    }

    /// Given a LocalIdentity, connect to the neighbor over wireguard
    pub fn open_tunnel(&mut self, their_id: LocalIdentity, ip: IpAddr) -> Result<(), Error> {
        trace!("Getting tunnel, open tunnel");
        let tunnel = self.get_if(ip.to_string());
        let network = SETTING.get_network().clone();

        KI.open_tunnel(
            &tunnel.iface_name,
            tunnel.listen_port,
            &SocketAddr::new(ip, their_id.wg_port),
            &their_id.global.wg_public_key,
            Path::new(&network.wg_private_key_path),
            &network.own_ip,
            network.external_nic.clone(),
            &mut SETTING.set_network().default_route,
        )?;

        let mut stream = TcpStream::connect::<SocketAddr>(format!(
            "[::1]:{}",
            SETTING.get_network().babel_port
        ).parse()?)?;

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

    use actix::actors::ConnectorError;
    use std::collections::{HashSet, VecDeque};
    use std::net::Ipv4Addr;

    #[test]
    fn test_contact_neighbor_ipv4() {
        let link_args = &["link"];
        let link_add = &["link", "add", "wg1", "type", "wireguard"];

        let mut counter = 0;
        KI.set_mock(Box::new(move |program, args| {
            assert_eq!(program, "ip");
            counter += 1;

            match counter {
                1 => {
                    assert_eq!(args, link_args);
                    Ok(Output {
                        stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                2 => {
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

        let _: Addr<Syn, _> = HTTPClient::init_actor(|_| {
            HTTPClient::mock(Box::new(|msg, ctx| {
                assert_eq!(
                    msg.downcast_ref::<Hello>(),
                    Some(&Hello {
                        my_id: LocalIdentity {
                            wg_port: 60000,
                            global: SETTING.get_identity()
                        },
                        to: SocketAddr::V4(SocketAddrV4::new("1.1.1.1".parse().unwrap(), 4876))
                    })
                );

                let ret: Result<LocalIdentity, Error> = Ok(LocalIdentity {
                    wg_port: 60000,
                    global: SETTING.get_identity(),
                });
                Box::new(Some(ret))
            }))
        });

        let mut tm = TunnelManager::new();
        let res = TunnelManager::contact_neighbor(
            tm.get_if(String::from("aa")),
            0,
            "1.1.1.1".parse().unwrap(),
        );

        sys.handle().spawn(res.then(|res| {
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

            Arbiter::system().do_send(msgs::SystemExit(0));
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
            assert_eq!(program, "ip");
            counter += 1;

            match counter {
                1 => {
                    assert_eq!(args, link_args);
                    Ok(Output {
                        stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                2 => {
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

        let _: Addr<Syn, _> = HTTPClient::init_actor(|_| {
            HTTPClient::mock(Box::new(|msg, ctx| {
                assert_eq!(
                    msg.downcast_ref::<Hello>(),
                    Some(&Hello {
                        my_id: LocalIdentity {
                            wg_port: 60000,
                            global: SETTING.get_identity()
                        },
                        to: SocketAddr::V4(SocketAddrV4::new("1.1.1.1".parse().unwrap(), 4876))
                    })
                );

                let ret: Result<LocalIdentity, Error> = Ok(LocalIdentity {
                    wg_port: 60000,
                    global: SETTING.get_identity(),
                });
                Box::new(Some(ret))
            }))
        });

        let _: Addr<Unsync, _> = Connector::init_actor(|_| {
            Connector::mock(Box::new(|msg, ctx| {
                assert_eq!(
                    msg.downcast_ref::<actors::Resolve>(),
                    Some(&actors::Resolve::host("test.altheamesh.com"))
                );

                let ret: Result<VecDeque<SocketAddr>, ConnectorError> = Ok({
                    let mut ips = VecDeque::new();
                    ips.push_back(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 0));
                    ips
                });
                Box::new(Some(ret))
            }))
        });

        let mut tm = TunnelManager::new();
        let res = tm.neighbor_inquiry("test.altheamesh.com".to_string(), None);

        sys.handle().spawn(res.then(|res| {
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

            Arbiter::system().do_send(msgs::SystemExit(0));
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
            assert_eq!(program, "ip");

            counter += 1;

            match counter {
                1 => {
                    assert_eq!(args, link_args);
                    Ok(Output {
                        stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                2 => {
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

        let _: Addr<Syn, _> = HTTPClient::init_actor(|_| {
            HTTPClient::mock(Box::new(|msg, ctx| {
                assert_eq!(
                    msg.downcast_ref::<Hello>(),
                    Some(&Hello {
                        my_id: LocalIdentity {
                            wg_port: 60000,
                            global: SETTING.get_identity()
                        },
                        to: SocketAddr::V4(SocketAddrV4::new("1.1.1.1".parse().unwrap(), 4876))
                    })
                );

                let ret: Result<LocalIdentity, Error> = Ok(LocalIdentity {
                    wg_port: 60000,
                    global: SETTING.get_identity(),
                });
                Box::new(Some(ret))
            }))
        });

        let _: Addr<Unsync, _> = Connector::init_actor(|_| {
            Connector::mock(Box::new(|msg, ctx| {
                assert_eq!(
                    msg.downcast_ref::<actors::Resolve>(),
                    Some(&actors::Resolve::host("1.1.1.1"))
                );

                let ret: Result<VecDeque<SocketAddr>, ConnectorError> =
                    Err(ConnectorError::Resolver("Thats an IP address!".to_string()));
                Box::new(Some(ret))
            }))
        });

        let mut tm = TunnelManager::new();
        let res = tm.neighbor_inquiry("1.1.1.1".to_string(), None);

        sys.handle().spawn(res.then(|res| {
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

            Arbiter::system().do_send(msgs::SystemExit(0));
            future::result(Ok(()))
        }));

        sys.run();
    }

    #[test]
    fn test_get_neighbors() {
        env_logger::init();
        let mut counter = 0;
        KI.set_mock(Box::new(move |program, args| {
            trace!("program {:?}, args {:?}", program, args);
            if program == "ping6" {
                return Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                });
            }

            counter += 1;

            match counter {
                1 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["link"]);
                    Ok(Output {
                        stdout: b"82: eth0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                2 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["neighbor"]);
                    Ok(Output {
                        stdout: b"fe80::1234 dev eth0 lladdr dc:6d:cd:ae:bd:a6 REACHABLE".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                3 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["link"]);
                    Ok(Output {
                        stdout: b"82: eth0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                4 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["link", "add", "wg0", "type", "wireguard"]);
                    Ok(Output {
                        stdout: b"".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                5 | 6 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["link"]);
                    Ok(Output {
                        stdout: b"82: eth0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000\
83: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                7 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["link", "add", "wg1", "type", "wireguard"]);
                    Ok(Output {
                        stdout: b"".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                8 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["link"]);
                    Ok(Output {
                        stdout: b"82: eth0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000\
83: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000\
84: wg1: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
                }
                9 => {
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["link", "add", "wg2", "type", "wireguard"]);
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

        SETTING.set_network().manual_peers =
            vec!["test.altheamesh.com".to_string(), "2.2.2.2".to_string()];
        SETTING
            .set_network()
            .peer_interfaces
            .insert("eth0".to_string());

        let _: Addr<Syn, _> = HTTPClient::init_actor(|_| {
            HTTPClient::mock(Box::new(|msg, ctx| {
                trace!("{:?}", msg.downcast_ref::<Hello>());
                let ret: Result<LocalIdentity, Error> = match msg.downcast_ref::<Hello>() {
                    Some(&Hello {
                        my_id:
                            LocalIdentity {
                                wg_port: port,
                                global: ref id,
                            },
                        to: _,
                    }) => {
                        assert_eq!(id, &SETTING.get_identity());
                        Ok(LocalIdentity {
                            wg_port: port,
                            global: SETTING.get_identity(),
                        })
                    }
                    _ => {
                        panic!("Wrong message sent to HTTPClient");
                    }
                };
                Box::new(Some(ret))
            }))
        });

        let _: Addr<Unsync, _> = Connector::init_actor(|_| {
            Connector::mock(Box::new(|msg, ctx| {
                let msg = msg.downcast_ref::<actors::Resolve>().unwrap();
                let ret: Result<VecDeque<SocketAddr>, ConnectorError> = if msg
                    == &actors::Resolve::host("fe80::1234")
                {
                    Err(ConnectorError::Resolver("Thats an IP address!".to_string()))
                } else if msg == &actors::Resolve::host("2.2.2.2") {
                    Err(ConnectorError::Resolver("Thats an IP address!".to_string()))
                } else if msg == &actors::Resolve::host("test.altheamesh.com") {
                    Ok({
                        let mut ips = VecDeque::new();
                        ips.push_back(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 0));
                        ips
                    })
                } else {
                    panic!("unexpected host found")
                };
                Box::new(Some(ret))
            }))
        });

        let mut tm = TunnelManager::new();
        let res = tm.get_neighbors();

        sys.handle().spawn(res.then(|res| {
            assert_eq!(
                res.unwrap(),
                vec![
                    (
                        LocalIdentity {
                            wg_port: 60000,
                            global: SETTING.get_identity(),
                        },
                        "wg0".to_string(),
                        "fe80::1234".parse().unwrap(),
                    ),
                    (
                        LocalIdentity {
                            wg_port: 60001,
                            global: SETTING.get_identity(),
                        },
                        "wg1".to_string(),
                        "1.1.1.1".parse().unwrap(),
                    ),
                    (
                        LocalIdentity {
                            wg_port: 60002,
                            global: SETTING.get_identity(),
                        },
                        "wg2".to_string(),
                        "2.2.2.2".parse().unwrap(),
                    ),
                ]
            );

            Arbiter::system().do_send(msgs::SystemExit(0));
            future::result(Ok(()))
        }));

        sys.run();
    }
}
