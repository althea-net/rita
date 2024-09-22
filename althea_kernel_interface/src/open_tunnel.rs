use crate::ip_route::manual_peers_route;
use crate::link_local_tools::get_device_name;
use crate::{run_command, DefaultRoute, KernelInterfaceError};
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

pub fn open_tunnel(args: TunnelOpenArgs) -> Result<(), KernelInterfaceError> {
    let (setup_gateway_routes, socket_connect_str) = match args.endpoint {
        SocketAddr::V4(sockv4) => (
            // if the ipv4 address is not private we are connecting to an exit
            // and instead we are connecting to a local peer over ipv4
            !sockv4.ip().is_private(),
            format!("{}:{}", sockv4.ip(), sockv4.port()),
        ),
        SocketAddr::V6(sockv6) => {
            let is_link_local = is_link_local(IpAddr::V6(*sockv6.ip()));
            if is_link_local {
                // if the ipv6 address is link local we need to add the interface name
                // to the endpoint
                let interface_name = get_device_name((*sockv6.ip()).into())?;
                (
                    false,
                    format!("[{}%{}]:{}", sockv6.ip(), interface_name, sockv6.port()),
                )
            } else {
                // ipv6 is not link local, it's over the internet
                (true, format!("[{}]:{}", sockv6.ip(), sockv6.port()))
            }
        }
    };

    let allowed_addresses = "::/0".to_string();

    trace!("socket connect string: {}", socket_connect_str);
    let output = run_command(
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
    let _output = run_command(
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
        let _output = run_command(
            "ip",
            &["address", "add", &ip.to_string(), "dev", &args.interface],
        )?;
    }

    // add ipv6 link local slacc address manually, this is required for peer discovery
    run_command(
        "ip",
        &[
            "address",
            "add",
            &format!("{}/64", to_wg_local(&args.own_ip)),
            "dev",
            &args.interface,
        ],
    )?;

    if setup_gateway_routes {
        manual_peers_route(&args.endpoint.ip(), args.settings_default_route)?;
    }

    let output = run_command("ip", &["link", "set", "dev", &args.interface, "up"])?;
    if !output.stderr.is_empty() {
        return Err(KernelInterfaceError::RuntimeError(format!(
            "received error setting wg interface {:?} up: {}",
            args,
            String::from_utf8(output.stderr)?
        )));
    }
    Ok(())
}
