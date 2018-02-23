use super::{Error, KernelInterface};

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::Path;

impl KernelInterface {
    pub fn open_tunnel(
        &mut self,
        interface: &String,
        port: u16,
        endpoint: &SocketAddr,
        remote_pub_key: &String,
        private_key_path: &Path,
        own_ip: &IpAddr,
    ) -> Result<(), Error> {
        if let &SocketAddr::V6(socket) = endpoint {
            let phy_name = self.get_device_name(endpoint.ip())?;
            let output = self.run_command(
                "wg",
                &[
                    "set",
                    &interface,
                    "listen-port",
                    &format!("{}", port),
                    "private-key",
                    &format!("{}", private_key_path.to_str().unwrap()),
                    "peer",
                    &format!("{}", remote_pub_key),
                    "endpoint",
                    &format!("[{}%{}]:{}", endpoint.ip(), phy_name, endpoint.port()),
                    "allowed-ips",
                    "::/0",
                    "persistent-keepalive",
                    "5",
                ],
            )?;
            if !output.stderr.is_empty() {
                return Err(Error::RuntimeError(format!(
                    "received error from wg command: {}",
                    String::from_utf8(output.stderr)?
                )));
            }
            let output = self.run_command(
                "ip",
                &["address", "add", &format!("{}", own_ip), "dev", &interface],
            )?;
            if !output.stderr.is_empty() {
                return Err(Error::RuntimeError(format!(
                    "received error adding wg link: {}",
                    String::from_utf8(output.stderr)?
                )));
            }
            let output = self.run_command(
                "ip",
                &[
                    "address",
                    "add",
                    &format!("fe80::{}/64", own_ip.to_string().clone().pop().unwrap()),
                    "dev",
                    &interface,
                ],
            )?;
            if !output.stderr.is_empty() {
                return Err(Error::RuntimeError(format!(
                    "received error adding wg link: {}",
                    String::from_utf8(output.stderr)?
                )));
            }
            let output = self.run_command("ip", &["link", "set", "dev", &interface, "up"])?;
            if !output.stderr.is_empty() {
                return Err(Error::RuntimeError(format!(
                    "received error setting wg interface up: {}",
                    String::from_utf8(output.stderr)?
                )));
            }
            Ok(())
        } else {
            return Err(Error::RuntimeError(format!(
                "Only ipv6 neighbors are supported"
            )));
        }
    }
}

#[test]
fn test_open_tunnel_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let interface = String::from("wg1");
    let endpoint_link_local_ip = Ipv6Addr::new(0xfe80, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x90);
    let own_mesh_ip = "fd::1".parse::<IpAddr>().unwrap();
    let endpoint = SocketAddr::V6(SocketAddrV6::new(endpoint_link_local_ip, 8088, 0, 123));
    let remote_pub_key = String::from("x8AcR9wI4t97aowYFlis077BDBk9SLdq6khMiixuTsQ=");
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

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program, args| {
            counter += 1;
            match counter {
                1 => {
                    //get interfaces
                    assert_eq!(program, "ip");
                    assert_eq!(args, &["neighbor"]);

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
                    assert_eq!(args, ["address", "add", "fd::1", "dev", "wg1"]);
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
        })),
    };

    ki.open_tunnel(
        &interface,
        8088,
        &endpoint,
        &remote_pub_key,
        &private_key_path,
        &own_mesh_ip,
    ).unwrap();
}
