use super::{KernelInterface, KernelInterfaceError};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex::Regex;

use failure::Error;

use eui48::MacAddress;

fn mac_to_link_local(mac: MacAddress) -> Ipv6Addr {
    let mut new_ip = [0u8; 16];
    let mac_bytes = mac.as_bytes();
    let mask = 2u8;
    // see this spec https://en.wikipedia.org/wiki/IPv6_address#Modified_EUI-64
    new_ip[0] = 0xFE;
    new_ip[1] = 0x80;
    for val in 2..7 {
        new_ip[val] = 0;
    }
    new_ip[8] = mac_bytes[0] ^ mask;
    new_ip[9] = mac_bytes[1];
    new_ip[10] = mac_bytes[2];
    new_ip[11] = 0xFF;
    new_ip[12] = 0xFE;
    new_ip[13] = mac_bytes[3];
    new_ip[14] = mac_bytes[4];
    new_ip[15] = mac_bytes[5];
    Ipv6Addr::from(new_ip)
}

impl dyn KernelInterface {
    /// This gets our link local ip for a given device
    pub fn get_link_local_device_ip(&self, dev: &str) -> Result<Ipv6Addr, KernelInterfaceError> {
        let output = self.run_command("ip", &["addr", "show", "dev", dev, "scope", "link"])?;
        trace!("Got {:?} from `ip addr`", output);

        lazy_static! {
            static ref RE: Regex = Regex::new(r"inet6 (\S*?)(/[0-9]+)? scope link")
                .expect("Unable to compile regular expression");
        }

        let cap_str = String::from_utf8(output.stdout)?;
        let err = String::from_utf8(output.stderr)?;
        let cap = RE.captures(&cap_str);
        if let Some(cap) = cap {
            trace!("got link local IP of {} from device {}", &cap[1], &dev);
            Ok(cap[1].parse::<Ipv6Addr>()?)
        } else if err.contains("does not exist") {
            Err(KernelInterfaceError::NoInterfaceError(dev.to_string()))
        } else if cap.is_none() && output.status.success() {
            Err(KernelInterfaceError::AddressNotReadyError(
                "No address seems to be available yet".to_string(),
            ))
        } else {
            Err(KernelInterfaceError::RuntimeError(
                "Some other error occured".to_string(),
            ))
        }
    }

    /// Some devices are stubborn and won't set a linklocal ip unless somthing is plugged in
    /// so we generate one using eui64 and the mach address,
    pub fn get_or_set_link_local_device_ip(
        &self,
        dev: &str,
    ) -> Result<Ipv6Addr, KernelInterfaceError> {
        trace!("Getting or setting link local device ip for {}", dev);
        if let Ok(ip) = self.get_link_local_device_ip(dev) {
            return Ok(ip);
        }
        let mac = self.get_iface_mac(dev)?;
        let ip = mac_to_link_local(mac);
        self.run_command(
            "ip",
            &[
                "addr",
                "add",
                "dev",
                dev,
                "scope",
                "link",
                &format!("{}/64", ip),
            ],
        )?;
        trace!("Successfully set {} with link local ip {}", dev, ip);
        Ok(ip)
    }

    /// This gets the 64bit mac address for a given device
    pub fn get_iface_mac(&self, dev: &str) -> Result<MacAddress, KernelInterfaceError> {
        let output = self.run_command("ip", &["addr", "show", "dev", dev])?;
        trace!("Got {:?} from `ip addr`", output);

        lazy_static! {
            static ref RE: Regex = Regex::new(r"link/ether (\S*?)(/[0-9]+)? brd")
                .expect("Unable to compile regular expression");
        }

        let cap_str = String::from_utf8(output.stdout)?;
        let err = String::from_utf8(output.stderr)?;
        let cap = RE.captures(&cap_str);
        if let Some(cap) = cap {
            trace!("got mac address of {} from device {}", &cap[1], &dev);
            Ok(cap[1].parse::<MacAddress>()?)
        } else if err.contains("does not exist") {
            Err(KernelInterfaceError::NoInterfaceError(dev.to_string()))
        } else if cap.is_none() && output.status.success() {
            Err(KernelInterfaceError::AddressNotReadyError(
                "Interface has no MAC?".to_string(),
            ))
        } else {
            Err(KernelInterfaceError::RuntimeError(
                "Some other error occured".to_string(),
            ))
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
    use crate::KI;

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
    use crate::KI;

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
    use crate::KI;

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

#[test]
fn test_get_mac_in_linux() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ip");
                assert_eq!(args, &["addr", "show", "dev", "eth4"]);

                Ok(Output {
                        stdout: b"9: eth4: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether 18:03:73:ca:04:c3 brd ff:ff:ff:ff:ff:ff
    inet6 fde6::1/128 scope global tentative
       valid_lft forever preferred_lft forever"
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            _ => unimplemented!("called too many times"),
        }
    }));

    let dev = KI.get_iface_mac("eth4").unwrap();

    assert_eq!(dev, "18:03:73:ca:04:c3".parse::<MacAddress>().unwrap())
}

#[test]
fn test_link_local_ip_gen_in_linux() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ip");
                assert_eq!(args, &["addr", "show", "dev", "eth4", "scope", "link"]);

                Ok(Output {
                        stdout: b"eth4: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether 18:03:73:ca:04:c3 brd ff:ff:ff:ff:ff:ff"
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            2 => {
                assert_eq!(program, "ip");
                assert_eq!(args, &["addr", "show", "dev", "eth4", "scope", "link"]);

                Ok(Output {
                        stdout: b"2eth4: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether 18:03:73:ca:04:c3 brd ff:ff:ff:ff:ff:ff"
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            3 => {
                assert_eq!(program, "ip");
                assert_eq!(args, &["addr", "add", "dev", "eth4", "scope", "link", "fe80::1a03:73ff:feca:4c3/64"]);

                Ok(Output {
                        stdout: b""
                            .to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            _ => unimplemented!("called too many times"),
        }
    }));

    let dev = KI.get_or_set_link_local_device_ip("eth4").unwrap();

    assert_eq!(dev, "fe80::1a03:73ff:feca:4c3".parse::<Ipv6Addr>().unwrap())
}

#[test]
fn test_mac_to_link_local() {
    let ip = mac_to_link_local("18:03:73:ca:04:c3".parse().unwrap());
    assert_eq!(ip, "fe80::1a03:73ff:feca:4c3".parse::<Ipv6Addr>().unwrap())
}
