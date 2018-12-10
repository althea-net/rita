use super::{KernelInterface, KernelInterfaceError};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex::Regex;

use failure::Error;

impl KernelInterface {
    /// This gets our link local ip for a given device
    pub fn get_link_local_device_ip(&self, dev: &str) -> Result<Ipv6Addr, Error> {
        let output = self.run_command("ip", &["addr", "show", "dev", dev, "scope", "link"])?;
        trace!("Got {:?} from `ip addr`", output);

        lazy_static! {
            static ref RE: Regex = Regex::new(r"inet6 (\S*?)(/[0-9]+)? scope link")
                .expect("Unable to compile regular expression");
        }

        let cap_str = String::from_utf8(output.stdout)?;
        let cap = RE.captures(&cap_str);
        if let Some(cap) = cap {
            trace!("got link local IP of {} from device {}", &cap[1], &dev);
            Ok(cap[1].parse::<Ipv6Addr>()?)
        } else {
            Err(KernelInterfaceError::RuntimeError(
                "No link local addresses found or no interface found".to_string(),
            )
            .into())
        }
    }

    /// This gets our global ip for a given device
    pub fn get_global_device_ip(&self, dev: &str) -> Result<Ipv6Addr, Error> {
        let output = self.run_command("ip", &["addr", "show", "dev", dev, "scope", "global"])?;
        trace!("Got {:?} from `ip addr`", output);

        lazy_static! {
            static ref RE: Regex = Regex::new(r"inet (\S*?)(/[0-9]+)? scope global")
                .expect("Unable to compile regular expression");
        }

        let cap_str = String::from_utf8(output.stdout)?;
        let cap = RE.captures(&cap_str);
        if let Some(cap) = cap {
            trace!("got global IP of {} from device {}", &cap[1], &dev);
            Ok(cap[1].parse::<Ipv6Addr>()?)
        } else {
            Err(KernelInterfaceError::RuntimeError(
                "No global found or no interface found".to_string(),
            )
            .into())
        }
    }

    pub fn get_global_device_ip_v4(&self, dev: &str) -> Result<Ipv4Addr, Error> {
        let output = self.run_command("ip", &["addr", "show", "dev", dev, "scope", "global"])?;
        trace!("Got {:?} from `ip addr`", output);

        lazy_static! {
            static ref RE: Regex = Regex::new(r"inet (\S*?)(/[0-9]+)? scope global")
                .expect("Unable to compile regular expression");
        }

        let cap_str = String::from_utf8(output.stdout)?;
        let cap = RE.captures(&cap_str);
        if let Some(cap) = cap {
            trace!("got global IP of {} from device {}", &cap[1], &dev);
            Ok(cap[1].parse::<Ipv4Addr>()?)
        } else {
            Err(KernelInterfaceError::RuntimeError(
                "No global found or no interface found".to_string(),
            )
            .into())
        }
    }

    /// Given a neighboring link local ip, return the device name
    pub fn get_device_name(&self, their_ip: IpAddr) -> Result<String, Error> {
        let neigh = self.get_neighbors()?;
        trace!("looking for {:?} in {:?} for device name", their_ip, neigh);
        for (ip, dev) in neigh {
            if ip == their_ip {
                return Ok(dev.to_string());
            }
        }

        Err(KernelInterfaceError::RuntimeError("Address not found in neighbors".to_string()).into())
    }

    /// This gets our link local ip that can be reached by another node with link local ip
    pub fn get_reply_ip(
        &self,
        their_ip: Ipv6Addr,
        external_interface: Option<String>,
    ) -> Result<Ipv6Addr, Error> {
        let neigh = self.get_neighbors()?;

        trace!("Looking for {:?} in {:?} for reply ip", their_ip, neigh);
        for (ip, dev) in neigh {
            if ip == their_ip {
                return Ok(self.get_link_local_device_ip(&dev)?);
            }
        }

        if let Some(external_interface) = external_interface {
            let global_ip = self.get_global_device_ip(&external_interface)?;
            trace!(
                "Didn't find {:?} in neighbors, sending global ip {:?}",
                their_ip,
                global_ip
            );
            Ok(global_ip)
        } else {
            trace!("Didn't find {:?} in neighbors, bailing out", their_ip);
            Err(
                KernelInterfaceError::RuntimeError("Address not found in neighbors".to_string())
                    .into(),
            )
        }
    }
    /// Returns all existing interfaces
    pub fn get_iface_index(&self, name: &str) -> Result<u32, Error> {
        let links = String::from_utf8(self.run_command("ip", &["link"])?.stdout)?;

        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"([0-9]+): (.*?)(:|@)").expect("Unable to compile regular expression");
        }

        for caps in RE.captures_iter(&links) {
            if name == &caps[2] {
                return Ok(caps[1].parse()?);
            }
        }
        Err(KernelInterfaceError::RuntimeError("Interface not found".to_string()).into())
    }
}

#[test]
fn test_get_device_name_linux() {
    use KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["neighbor"]);

        Ok(Output {
            stdout: b"10.0.2.2 dev eth0 lladdr 00:00:00:aa:00:03 STALE
10.0.0.2 dev eth0  FAILED
10.0.1.2 dev eth0 lladdr 00:00:00:aa:00:05 REACHABLE
2001::2 dev eth0 lladdr 00:00:00:aa:00:56 REACHABLE
fe80::7459:8eff:fe98:81 dev eth0 lladdr 76:59:8e:98:00:81 STALE
fe80::433:25ff:fe8c:e1ea dev eth2 lladdr 1a:32:06:78:05:0a STALE
2001::2 dev eth0  FAILED"
                .to_vec(),
            stderr: b"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));

    let dev = KI
        .get_device_name("fe80::433:25ff:fe8c:e1ea".parse().unwrap())
        .unwrap();

    assert_eq!(dev, "eth2")
}

#[test]
fn test_get_link_local_device_ip_linux() {
    use KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "show", "dev", "eth0", "scope", "link"]);

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

    let ip = KI.get_link_local_device_ip("eth0").unwrap();

    assert_eq!(ip, "fe80::96:3add:69d9:906a".parse::<IpAddr>().unwrap())
}

#[test]
fn test_get_link_local_reply_ip_linux() {
    use KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ip");
                assert_eq!(args, &["neighbor"]);

                Ok(Output {
                    stdout: b"
fe80::7459:8eff:fe98:81 dev eth0 lladdr 76:59:8e:98:00:81 STALE
fe80::433:25ff:fe8c:e1ea dev eth2 lladdr 1a:32:06:78:05:0a STALE"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            2 => {
                assert_eq!(program, "ip");
                assert_eq!(args, &["addr", "show", "dev", "eth0", "scope", "link"]);

                Ok(Output {
                        stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 74:df:bf:30:37:f3 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::96:3add:69d9:906a/64 scope link
       valid_lft forever preferred_lft forever"
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            _ => unimplemented!("called too many times"),
        }
    }));

    let dev = KI
        .get_reply_ip("fe80::7459:8eff:fe98:81".parse().unwrap(), None)
        .unwrap();

    assert_eq!(dev, "fe80::96:3add:69d9:906a".parse::<IpAddr>().unwrap())
}
