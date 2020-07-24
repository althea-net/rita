use super::KernelInterface;

use regex::Regex;

use failure::Error;
use std::net::IpAddr;
use std::str::from_utf8;

impl dyn KernelInterface {
    /// Returns all existing interfaces
    pub fn get_interfaces(&self) -> Result<Vec<String>, Error> {
        let links = String::from_utf8(self.run_command("ip", &["link"])?.stdout)?;

        let mut vec = Vec::new();

        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"[0-9]+: (.*?)(:|@)").expect("Unable to compile regular expression");
        }
        for caps in RE.captures_iter(&links) {
            vec.push(String::from(&caps[1]));
        }

        trace!("interfaces: {:?}", vec);
        Ok(vec)
    }

    /// Deletes an named interface
    pub fn del_interface(&self, name: &str) -> Result<(), Error> {
        self.run_command("ip", &["link", "del", "dev", name])?;
        Ok(())
    }

    pub fn iface_status(&self, iface: &str) -> Result<String, Error> {
        // cat so we can mock
        let output = self.run_command("cat", &[&format!("/sys/class/net/{}/operstate", iface)])?;

        let output = from_utf8(&output.stdout)?;

        Ok(output.trim_end().to_string())
    }

    pub fn get_wg_remote_ip(&self, name: &str) -> Result<IpAddr, Error> {
        let output = self.run_command("wg", &["show", name, "endpoints"])?;
        let stdout = String::from_utf8(output.stdout)?;

        lazy_static! {
            static ref RE: Regex = Regex::new(r"(?:([0-9a-f:]+)%)|(?:([0-9\.]+):)")
                .expect("Unable to compile regular expression");
        }
        let cap = RE.captures(&stdout);

        match cap {
            Some(cap) => {
                let ip_str = match cap.get(1) {
                    // ipv6
                    Some(cap) => cap.as_str(),
                    None => {
                        match cap.get(2) {
                            Some(cap) => {
                                // ipv4
                                cap.as_str()
                            }
                            None => {
                                bail!("Cannot parse `wg show {} endpoints` output, got {}, captured {:?}", name, stdout, cap);
                            }
                        }
                    }
                };

                Ok(ip_str.parse()?)
            }
            None => {
                bail!(
                    "Cannot parse `wg show {} endpoints` output, got {}, nothing captured",
                    name,
                    stdout
                );
            }
        }
    }

    /// Gets all the IPv4 addresses from an interface and returns the address and it's netmask
    /// as a tuple.
    pub fn get_ip_from_iface(&self, name: &str) -> Result<Vec<(IpAddr, u8)>, Error> {
        let output = self.run_command("ip", &["address", "show", "dev", name])?;
        let stdout = String::from_utf8(output.stdout)?;

        lazy_static! {
            static ref RE: Regex = Regex::new(r"((\d){1,3}\.){3}(\d){1,3}/(\d){1,3}")
                .expect("Unable to compile regular expression");
        }
        let mut ret = Vec::new();
        for line in stdout.lines() {
            let cap = RE.captures(&line);
            // we captured something on this line
            if let Some(cap) = cap {
                for ip_cap in cap.iter() {
                    if let Some(ip_cap) = ip_cap {
                        let mut split = ip_cap.as_str().split('/');
                        let ip_str = split.next();
                        let netmask = split.next();
                        if let (Some(ip_str), Some(netmask)) = (ip_str, netmask) {
                            if let (Ok(parsed_ip), Ok(parsed_netmask)) =
                                (ip_str.parse(), netmask.parse())
                            {
                                ret.push((parsed_ip, parsed_netmask));
                            }
                        }
                    }
                }
            }
        }

        Ok(ret)
    }
}

#[test]
fn test_get_interfaces_linux() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["link"]);

        Ok(Output {
                stdout: b"
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: dummy: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 22:8a:b6:9e:2d:1e brd ff:ff:ff:ff:ff:ff
3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/none
2843: veth-1-6@if2842: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc netem state UP mode DEFAULT group default qlen 1000
    link/ether 76:d1:f5:3d:32:53 brd ff:ff:ff:ff:ff:ff link-netnsid 1"
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
    }));

    let interfaces = KI.get_interfaces().unwrap();

    assert_eq!(interfaces[0].to_string(), "lo");
    assert_eq!(interfaces[1].to_string(), "dummy");
    assert_eq!(interfaces[2].to_string(), "wg0");
    assert_eq!(interfaces[3].to_string(), "veth-1-6");
}

#[test]
fn test_get_wg_remote_ip() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "wg");
        assert_eq!(args, &["show", "wg0", "endpoints"]);
        Ok(Output {
            stdout: b"fvLYbeMV+RYbzJEc4lNEPuK8ulva/5wcSJBz0W5t3hM=	71.8.186.226:60000\
"
            .to_vec(),
            stderr: b"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));

    assert_eq!(
        KI.get_wg_remote_ip("wg0").unwrap(),
        "71.8.186.226".parse::<IpAddr>().unwrap()
    );

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "wg");
        assert_eq!(args, &["show", "wg0", "endpoints"]);
        Ok(Output{
            stdout: b"v5yFYZVfl98N/LRVDK3hbyt5/dK/00VnEGHRBikHHXs=	[fe80::78e4:1cff:fe61:560d%veth-1-6]:60000\
".to_vec(),
            stderr: b"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));

    assert_eq!(
        KI.get_wg_remote_ip("wg0").unwrap(),
        "fe80::78e4:1cff:fe61:560d".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn test_get_ip_addresses_linux() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["address", "show", "dev", "eth8"]);

        Ok(Output {
                stdout: b"
    13: eth8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:e0:4c:67:a1:57 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.203/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet 192.168.1.154/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet 192.168.1.73/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet 192.168.1.137/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet 192.168.88.20/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet 192.168.88.197/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet 192.168.88.214/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet 192.168.1.206/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet 192.168.1.35/32 scope global eth8
       valid_lft forever preferred_lft forever
    inet6 fde6::1/128 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::2e0:4cff:fe67:a157/64 scope link
       valid_lft forever preferred_lft forever
                "
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
    }));

    let interfaces = KI.get_ip_from_iface("eth8").unwrap();
    let val = ("192.168.1.203".parse().unwrap(), 32);
    assert!(interfaces.contains(&val))
}
