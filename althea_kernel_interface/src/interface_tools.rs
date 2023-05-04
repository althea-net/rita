use crate::file_io::get_lines;
use crate::KernelInterface;
use crate::KernelInterfaceError as Error;
use regex::Regex;
use std::fs::read_dir;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::from_utf8;

impl dyn KernelInterface {
    /// Returns all existing interfaces
    pub fn get_interfaces(&self) -> Result<Vec<String>, Error> {
        let links = read_dir("/sys/class/net/")?;

        let mut vec = Vec::new();
        for dir in links {
            let dir = dir?;
            if dir.path().is_dir() {
                // this could fail if the interface contains any characters
                // not allowed in unicode. I don't think the kernel allows
                // this in the first place
                vec.push(dir.file_name().to_str().unwrap().to_string());
            }
        }

        trace!("interfaces: {:?}", vec);
        Ok(vec)
    }

    pub fn ifindex_to_interface_name(&self, ifindex: usize) -> Result<String, Error> {
        for interface in self.get_interfaces()? {
            let found_ifindex = self.get_ifindex(&interface)?;
            if ifindex == found_ifindex {
                return Ok(interface);
            }
        }
        Err(Error::NoInterfaceError(ifindex.to_string()))
    }

    /// Deletes an named interface
    pub fn del_interface(&self, name: &str) -> Result<(), Error> {
        self.run_command("ip", &["link", "del", "dev", name])?;
        Ok(())
    }

    pub fn iface_status(&self, iface: &str) -> Result<String, Error> {
        // cat so we can mock
        let output = self.run_command("cat", &[&format!("/sys/class/net/{iface}/operstate")])?;

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
                                return Err(Error::RuntimeError(format!(
                                "Cannot parse `wg show {name} endpoints` output, got {stdout}, captured {cap:?}"
                            )))
                            }
                        }
                    }
                };

                Ok(ip_str.parse()?)
            }
            None => Err(Error::RuntimeError(format!(
                "Cannot parse `wg show {name} endpoints` output, got {stdout}, nothing captured"
            ))),
        }
    }

    /// Gets all the IPv4 addresses from an interface and returns the address and it's netmask
    /// as a tuple.
    pub fn get_ip_from_iface(&self, name: &str) -> Result<Vec<(Ipv4Addr, u8)>, Error> {
        let output = self.run_command("ip", &["address", "show", "dev", name])?;
        let stdout = String::from_utf8(output.stdout)?;

        lazy_static! {
            static ref RE: Regex = Regex::new(r"((\d){1,3}\.){3}(\d){1,3}/(\d){1,3}")
                .expect("Unable to compile regular expression");
        }

        let mut ret = Vec::new();
        for line in stdout.lines() {
            let cap = RE.captures(line);
            // we captured something on this line
            if let Some(cap) = cap {
                // flatten drops the 'none' values in this array
                for ip_cap in cap.iter().flatten() {
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

        Ok(ret)
    }

    /// Gets all the IPv6 addresses from an interface and returns the address and it's netmask
    /// as a tuple.
    pub fn get_ipv6_from_iface(&self, name: &str) -> Result<Vec<(Ipv6Addr, u8)>, Error> {
        let output = self.run_command("ip", &["address", "show", "dev", name])?;
        let stdout = String::from_utf8(output.stdout)?;

        lazy_static! {
            static ref RE: Regex = Regex::new(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/(\d){1,3}").expect("Unable to compile regular expression");
        }

        let mut ret = Vec::new();
        for line in stdout.lines() {
            let cap = RE.captures(line);
            // we captured something on this line
            if let Some(cap) = cap {
                // flatten drops the 'none' values in this array
                for ip_cap in cap.iter().flatten() {
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

        Ok(ret)
    }

    /// calls iproute2 to set an interface up or down
    pub fn set_if_up_down(&self, if_name: &str, up_down: &str) -> Result<(), Error> {
        let output = self.run_command("ip", &["link", "set", "dev", if_name, up_down])?;
        if !output.stderr.is_empty() {
            Err(Error::RuntimeError(format!(
                "received error setting wg interface up: {}",
                String::from_utf8(output.stderr)?
            )))
        } else {
            Ok(())
        }
    }

    /// Gets the mtu from an interface
    pub fn get_mtu(&self, if_name: &str) -> Result<usize, Error> {
        let lines = get_lines(&format!("/sys/class/net/{if_name}/mtu"))?;
        if let Some(mtu) = lines.get(0) {
            Ok(mtu.parse()?)
        } else {
            Err(Error::NoInterfaceError(if_name.to_string()))
        }
    }

    /// Gets the ifindex from an interface
    pub fn get_ifindex(&self, if_name: &str) -> Result<usize, Error> {
        if cfg!(feature = "integration_test") {
            // ip netns exec n-1 cat /sys/class/net/veth-n-1-n-2/iflink
            let ns = self.get_namespace().unwrap();
            let location = format!("/sys/class/net/{if_name}/ifindex");
            let index = self
                .run_command("ip", &["netns", "exec", &ns, "cat", &location])
                .unwrap();

            let index = match String::from_utf8(index.stdout) {
                Ok(mut s) => {
                    //this outputs with an extra newline \n on the end which was messing up the next command
                    s.truncate(s.len() - 1);
                    s
                }
                Err(_) => panic!("Could not get index number!"),
            };
            info!("location: {:?}, index {:?}", location, index);

            Ok(index.parse().unwrap())
        } else {
            let lines = get_lines(&format!("/sys/class/net/{if_name}/ifindex"))?;
            if let Some(ifindex) = lines.get(0) {
                Ok(ifindex.parse()?)
            } else {
                Err(Error::NoInterfaceError(if_name.to_string()))
            }
        }
    }

    /// Gets the iflink value from an interface. Physical interfaces have an ifindex and iflink that are
    /// identical but if you have a virtual (say DSA) interface then this will be the physical interface name
    pub fn get_iflink(&self, if_name: &str) -> Result<usize, Error> {
        let lines = get_lines(&format!("/sys/class/net/{if_name}/iflink"))?;
        if let Some(iflink) = lines.get(0) {
            Ok(iflink.parse()?)
        } else {
            Err(Error::NoInterfaceError(if_name.to_string()))
        }
    }

    /// Sets the mtu of an interface, if this interface is a DSA interface the
    /// parent interface will be located and it's mtu increased as appropriate
    pub fn set_mtu(&self, if_name: &str, mtu: usize) -> Result<(), Error> {
        let ifindex = self.get_ifindex(if_name)?;
        let iflink = self.get_iflink(if_name)?;
        // dsa interface detected, this is an interface controlled by an internal switch
        // the parent interface (which has the ifindex value represented in iflink for the child interface)
        // needs to have whatever the mtu is, plus room for VLAN headers
        const DSA_VLAN_HEADER_SIZE: usize = 8;
        if ifindex != iflink {
            let parent_if_name = self.ifindex_to_interface_name(iflink)?;
            self.set_mtu(&parent_if_name, mtu + DSA_VLAN_HEADER_SIZE)?;
        }

        let output = self.run_command(
            "ip",
            &["link", "set", "dev", if_name, "mtu", &mtu.to_string()],
        )?;
        if !output.stderr.is_empty() {
            Err(Error::RuntimeError(format!(
                "received error setting interface mtu: {}",
                String::from_utf8(output.stderr)?
            )))
        } else {
            Ok(())
        }
    }

    /// Gets the network namespace name that holds the thread this function was called from.
    /// If the calling thread was not inside a network namespace/in the default namespace, this
    /// function returns a None
    pub fn get_namespace(&self) -> Option<String> {
        let output = match self.run_command("ip", &["netns", "identify"]) {
            Ok(output) => output,
            Err(_) => {
                warn!("Could not run ip netns- is ip netns installed?");
                return None;
            }
        };
        match String::from_utf8(output.stdout) {
            Ok(mut s) => {
                s.truncate(s.len() - 1);
                if !s.is_empty() {
                    return Some(s);
                }
                None
            }
            Err(_) => {
                warn!("Could not get ip netns name from stdout!");
                None
            }
        }
    }
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
