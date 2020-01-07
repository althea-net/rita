use super::KernelInterface;

use failure::Error;
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
            Ok(stdout) => match stdout.lines().next() {
                Some(line) => Some(line.contains("state UP")),
                _ => None,
            },
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
                        Err(format_err!("Error setting ip {}", line))
                    }
                }
                None => Ok(true),
            },
            Err(e) => Err(format_err!("Could not decode stderr from ip with {:?}", e)),
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
    assert_eq!(false, val);

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
    assert_eq!(true, val);
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
