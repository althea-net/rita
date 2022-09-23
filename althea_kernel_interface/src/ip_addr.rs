use crate::KernelInterface;
use crate::KernelInterfaceError as Error;
use ipnetwork::IpNetwork;
use std::net::Ipv4Addr;

impl dyn KernelInterface {
    /// Returns a bool based on device state, "UP" or "DOWN", "UNKNOWN" is
    /// interpreted as DOWN
    pub fn is_iface_up(&self, dev: &str) -> Option<bool> {
        let output = self
            .run_command("ip", &["addr", "show", "dev", dev])
            .unwrap();

        // Get the first line, check if it has state "UP"
        match String::from_utf8(output.stdout) {
            Ok(stdout) => stdout.lines().next().map(|line| line.contains("state UP")),
            _ => None,
        }
    }

    /// Adds an ipv4 address to a given interface, true is returned when
    /// the ip is added, false if it is already there and Error if the interface
    /// does not exist or some other error has occured
    pub fn add_ipv4(&self, ip: Ipv4Addr, dev: &str) -> Result<bool, Error> {
        // upwrap here because it's ok if we panic when the system does not have 'ip' installed
        let output = self
            .run_command("ip", &["addr", "add", &format!("{}/32", ip), "dev", dev])
            .unwrap();
        // Get the first line, check if it has "file exists"
        match String::from_utf8(output.stderr) {
            Ok(stdout) => match stdout.lines().next() {
                Some(line) => {
                    if line.contains("File exists") {
                        Ok(false)
                    } else {
                        Err(Error::RuntimeError(format!("Error setting ip {}", line)))
                    }
                }
                None => Ok(true),
            },
            Err(e) => Err(Error::RuntimeError(format!(
                "Could not decode stderr from ip with {:?}",
                e
            ))),
        }
    }

    /// After receiving an ipv6 addr from the exit, this function adds that ip
    /// to /etc/network/addr. SLAAC takes this ip and assigns a /64 to hosts that connect
    /// to the router
    pub fn setup_ipv6_slaac(&self, router_ipv6_str: IpNetwork) {
        let output = match self.run_command("uci", &["get", "network.lan.ip6addr"]) {
            Ok(a) => a,
            Err(e) => {
                error!("uci get network.lan.ip6addr failed. Unable to setup ipv6 subnet correctly: {:?}", e);
                return;
            }
        };

        match String::from_utf8(output.stdout) {
            Ok(a) => {
                if a.is_empty()
                    || {
                        router_ipv6_str
                            != {
                                let val = a.replace('\n', "").parse::<IpNetwork>();
                                match val {
                                    Ok(a) => a,
                                    Err(e) => {
                                        error!("This should be a valid network! Unable to setup ipv6 subnet correctly: {:?}", e);
                                        return;
                                    }
                                }
                            }
                    }
                {
                    let mut append_str = "network.lan.ip6addr=".to_owned();
                    append_str.push_str(&router_ipv6_str.to_string());
                    let res1 = self.run_command("uci", &["set", &append_str]);
                    let res2 = self.run_command("uci", &["commit", "network"]);
                    let res3 = self.run_command("/etc/init.d/network", &["reload"]);

                    match (res1.clone(), res2.clone(), res3.clone()) {
                        (Ok(_), Ok(_), Ok(_)) => {},
                        _ => error!("Unable to set ipv6 subnet correctly. Following are the results of command: {:?}, {:?}, {:?}", res1, res2, res3),
                    }
                }
            }
            Err(e) => error!("Error setting ipv6: {:?}", e),
        }
    }

    /// Adds an ipv4 address to a given interface, true is returned when
    /// the ip is added, false if it is already there and Error if the interface
    /// does not exist or some other error has occured
    pub fn add_ipv4_mask(&self, ip: Ipv4Addr, mask: u32, dev: &str) -> Result<bool, Error> {
        // upwrap here because it's ok if we panic when the system does not have 'ip' installed
        let output = self
            .run_command(
                "ip",
                &["addr", "add", &format!("{}/{}", ip, mask), "dev", dev],
            )
            .unwrap();
        // Get the first line, check if it has "file exists"
        match String::from_utf8(output.stderr) {
            Ok(stdout) => match stdout.lines().next() {
                Some(line) => {
                    if line.contains("File exists") {
                        Ok(false)
                    } else {
                        Err(Error::RuntimeError(format!("Error setting ip {}", line)))
                    }
                }
                None => Ok(true),
            },
            Err(e) => Err(Error::RuntimeError(format!(
                "Could not decode stderr from ip with {:?}",
                e
            ))),
        }
    }
}

#[test]
fn test_add_ipv4() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "add", "192.168.31.2/32", "dev", "eth0"]);

        Ok(Output {
            stdout: b"".to_vec(),
            stderr: b"RTNETLINK answers: File exists".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));
    let val = KI
        .add_ipv4("192.168.31.2".parse().unwrap(), "eth0")
        .expect("Failure to run ip test");
    assert!(!val);

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "add", "192.168.31.2/32", "dev", "eth0"]);

        Ok(Output {
            stdout: b"".to_vec(),
            stderr: b"Cannot find device \"eth0\"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));
    let val = KI.add_ipv4("192.168.31.2".parse().unwrap(), "eth0");
    assert!(val.is_err());

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "add", "192.168.31.2/32", "dev", "eth0"]);

        Ok(Output {
            stdout: b"".to_vec(),
            stderr: b"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));
    let val = KI
        .add_ipv4("192.168.31.2".parse().unwrap(), "eth0")
        .expect("Failure to run ip test");
    assert!(val);
}

#[test]
fn test_is_interface_up() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "show", "dev", "eth0"]);

        Ok(Output {
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 74:df:bf:30:37:f3 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::96:3add:69d9:906a/64 scope link
       valid_lft forever preferred_lft forever"
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
    }));

    let val = KI.is_iface_up("eth0");

    assert_eq!(Some(true), val);

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "show", "dev", "eth0"]);

        Ok(Output {
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state DOWN group default qlen 1000
    link/ether 74:df:bf:30:37:f3 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::96:3add:69d9:906a/64 scope link
       valid_lft forever preferred_lft forever"
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
    }));

    let val = KI.is_iface_up("eth0");

    assert_eq!(Some(false), val);

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "show", "dev", "eth0"]);

        Ok(Output {
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state group default qlen 1000
    link/ether 74:df:bf:30:37:f3 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::96:3add:69d9:906a/64 scope link
       valid_lft forever preferred_lft forever"
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
    }));

    let val = KI.is_iface_up("eth0");

    assert_eq!(Some(false), val);
}
