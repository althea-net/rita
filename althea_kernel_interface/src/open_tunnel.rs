use crate::{DefaultRoute, KernelInterface, KernelInterfaceError};
use althea_types::WgKey;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;

pub fn to_wg_local(ip: &IpAddr) -> IpAddr {
    match *ip {
        IpAddr::V6(ip) => {
            let seg = ip.segments();
            assert_eq!((seg[0] & 0xfd00), 0xfd00);
            IpAddr::V6(Ipv6Addr::new(
                0xfe80, 0x0, 0x0, 0x0, seg[4], seg[5], seg[6], seg[7],
            ))
        }
        _ => unreachable!(),
    }
}

#[test]
fn test_to_wg_local() {
    assert_eq!(
        to_wg_local(&"fd00::1".parse().unwrap()),
        "fe80::1".parse::<IpAddr>().unwrap()
    )
}

pub fn is_link_local(ip: IpAddr) -> bool {
    if let IpAddr::V6(ip) = ip {
        return (ip.segments()[0] & 0xffc0) == 0xfe80;
    }
    false
}

/// socket to string with interface id support
fn socket_to_string(
    endpoint: &SocketAddr,
    interface_name: Option<String>,
) -> Result<String, KernelInterfaceError> {
    match *endpoint {
        SocketAddr::V6(endpoint) => {
            if is_link_local(IpAddr::V6(*endpoint.ip())) {
                if let Some(interface_name) = interface_name {
                    Ok(format!(
                        "[{}%{}]:{}",
                        endpoint.ip(),
                        interface_name,
                        endpoint.port()
                    ))
                } else {
                    Err(KernelInterfaceError::NoInterfaceError(format!(
                        "Endpoint {} is ipv6 link local and should have an interaface name",
                        endpoint
                    )))
                }
            } else {
                Ok(format!("[{}]:{}", endpoint.ip(), endpoint.port()))
            }
        }
        SocketAddr::V4(endpoint) => Ok(format!("{}:{}", endpoint.ip(), endpoint.port())),
    }
}

#[derive(Debug)]
pub struct TunnelOpenArgs<'a> {
    /// the wg tunnel name
    pub interface: String,
    /// the port we will listen on
    pub port: u16,
    /// the peers ip and endpoint port
    pub endpoint: SocketAddr,
    /// the remote peers public key
    pub remote_pub_key: WgKey,
    /// the path to a file on the local system containing our private key
    pub private_key_path: &'a Path,
    /// our mesh ipv6 address
    pub own_ip: IpAddr,
    /// Exit second mesh ip used for exit roaming
    /// This can be removed after all client migrate to Beta20 and have exit swithcing enabled
    pub own_ip_v2: Option<IpAddr>,
    /// the nic that we use to get to the internet if we are a gateway, only used to handle
    /// default route considerations on the gateway
    pub external_nic: Option<String>,
    /// the default route that we use to get to the internet if we are a gateway, only used to handle
    /// default route considerations on the gateway
    pub settings_default_route: &'a mut Option<DefaultRoute>,
}

impl dyn KernelInterface {
    pub fn open_tunnel(&self, args: TunnelOpenArgs) -> Result<(), KernelInterfaceError> {
        let (phy_name, external_peer) = match is_link_local(args.endpoint.ip()) {
            true => (self.get_device_name(args.endpoint.ip())?, false),
            false => match args.external_nic.clone() {
                Some(external_nic) => (external_nic, true),
                None => {
                    // external peers need to have an interface name to setup static routes for
                    return Err(KernelInterfaceError::NoInterfaceError(format!(
                        "Endpoint {} is not link local and should have an interaface name",
                        args.endpoint
                    )));
                }
            },
        };

        let allowed_addresses = "::/0".to_string();

        let socket_connect_str = socket_to_string(&args.endpoint, Some(phy_name))?;
        trace!("socket connect string: {}", socket_connect_str);
        let output = self.run_command(
            "wg",
            &[
                "set",
                &args.interface,
                "listen-port",
                &format!("{}", args.port),
                "private-key",
                args.private_key_path.to_str().unwrap(),
                "peer",
                &format!("{}", args.remote_pub_key),
                "endpoint",
                &socket_connect_str,
                "allowed-ips",
                &allowed_addresses,
                "persistent-keepalive",
                "5",
            ],
        )?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error from wg command: {}",
                String::from_utf8(output.stderr)?
            )));
        }
        let _output = self.run_command(
            "ip",
            &[
                "address",
                "add",
                &args.own_ip.to_string(),
                "dev",
                &args.interface,
            ],
        )?;

        // Add second ip to tunnel used only by exits currently
        if let Some(ip) = args.own_ip_v2 {
            let _output = self.run_command(
                "ip",
                &["address", "add", &ip.to_string(), "dev", &args.interface],
            )?;
        }

        // add ipv6 link local slacc address manually, this is required for peer discovery
        self.run_command(
            "ip",
            &[
                "address",
                "add",
                &format!("{}/64", to_wg_local(&args.own_ip)),
                "dev",
                &args.interface,
            ],
        )?;

        if external_peer {
            self.manual_peers_route(&args.endpoint.ip(), args.settings_default_route)?;
        }

        let output = self.run_command("ip", &["link", "set", "dev", &args.interface, "up"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error setting wg interface {:?} up: {}",
                args,
                String::from_utf8(output.stderr)?
            )));
        }
        Ok(())
    }
}

#[test]
fn test_open_tunnel_linux() {
    use crate::KI;

    use crate::ip_route::DefaultRoute;
    use std::net::SocketAddrV6;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let interface = String::from("wg1");
    let endpoint_link_local_ip = Ipv6Addr::new(0xfe80, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x90);
    let own_mesh_ip = "fd00::1".parse::<IpAddr>().unwrap();
    let endpoint = SocketAddr::V6(SocketAddrV6::new(endpoint_link_local_ip, 8088, 0, 123));
    let remote_pub_key = "x8AcR9wI4t97aowYFlis077BDBk9SLdq6khMiixuTsQ="
        .parse()
        .unwrap();
    let private_key_path = Path::new("private_key");

    let wg_args = &[
        "set",
        "wg1",
        "listen-port",
        "8088",
        "private-key",
        "private_key",
        "peer",
        "x8AcR9wI4t97aowYFlis077BDBk9SLdq6khMiixuTsQ=",
        "endpoint",
        "[fe80::12:34:56:78:90%eth2]:8088",
        "allowed-ips",
        "::/0",
        "persistent-keepalive",
        "5",
    ];

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                //get interfaces
                assert_eq!(program, "ip");
                assert_eq!(args, &["neigh"]);

                Ok(Output {
                    stdout: b"10.0.2.2 dev eth0 lladdr 00:00:00:aa:00:03 STALE
10.0.0.2 dev eth0  FAILED
10.0.1.2 dev eth0 lladdr 00:00:00:aa:00:05 REACHABLE
2001::2 dev eth0 lladdr 00:00:00:aa:00:56 REACHABLE
fe80:0:0:12:34:56:78:90 dev eth2 lladdr 76:59:8e:98:00:81 STALE
fe80::433:25ff:fe8c:e1ea dev eth0 lladdr 1a:32:06:78:05:0a STALE
2001::2 dev eth0  FAILED"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            2 => {
                // setup wg interface
                assert_eq!(program, "wg");
                assert_eq!(args, wg_args);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            3 => {
                // add global ip
                assert_eq!(program, "ip");
                assert_eq!(args, ["address", "add", "fd00::1", "dev", "wg1"]);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            4 => {
                // add link local ip
                assert_eq!(program, "ip");
                assert_eq!(args, ["address", "add", "fe80::1/64", "dev", "wg1"]);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            5 => {
                // bring if up
                assert_eq!(program, "ip");
                assert_eq!(args, ["link", "set", "dev", "wg1", "up"]);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => unimplemented!(),
        }
    }));

    let def_route = DefaultRoute {
        via: "192.168.8.1".parse().unwrap(),
        nic: "wifiinterface".to_string(),
        proto: Some("dhcp".to_string()),
        metric: Some(600),
        src: None,
    };

    let args = TunnelOpenArgs {
        interface,
        port: 8088,
        endpoint,
        remote_pub_key,
        private_key_path,
        own_ip: own_mesh_ip,
        own_ip_v2: None,
        external_nic: None,
        settings_default_route: &mut Some(def_route),
    };

    KI.open_tunnel(args).unwrap();
}
