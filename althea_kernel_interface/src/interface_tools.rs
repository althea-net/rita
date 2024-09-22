use crate::file_io::get_lines;
use crate::netns::get_namespace;
use crate::run_command;
use crate::KernelInterfaceError as Error;
use althea_types::InterfaceUsageStats;
use regex::Regex;
use std::fs::read_dir;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::from_utf8;

/// Utility function for get_per_interface_usage that makes options ? compatible
fn get_helper(input: Option<&&str>) -> Result<String, Error> {
    match input {
        Some(v) => Ok(v.to_string()),
        None => Err(Error::ParseError(
            "Missing field in /proc/net/dev!".to_string(),
        )),
    }
}

/// Gets usage data from all interfaces from /proc/net/dev, note that for wireguard interfaces
/// updating the interface on the fly (like we do with wg_exit) will reset the usage
/// counter on the wireguard side, but not on in proc which this code pulls from
pub fn get_per_interface_usage() -> Result<Vec<InterfaceUsageStats>, Error> {
    let lines = get_lines("/proc/net/dev")?;
    // all lines represent an interface, except the first line which is a header
    let mut lines = lines.iter();
    // skip the first and second lines
    lines.next();
    lines.next();
    let mut ret = Vec::new();
    for line in lines {
        println!("line ins {}", line);
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        ret.push(InterfaceUsageStats {
            interface_name: get_helper(parts.first())?.trim_end_matches(':').to_string(),
            recieve_bytes: get_helper(parts.get(1))?.parse()?,
            recieve_packets: get_helper(parts.get(2))?.parse()?,
            recieve_errors: get_helper(parts.get(3))?.parse()?,
            recieve_dropped: get_helper(parts.get(4))?.parse()?,
            recieve_fifo_errors: get_helper(parts.get(5))?.parse()?,
            recieve_frame_errors: get_helper(parts.get(6))?.parse()?,
            recieve_multicast_erorrs: get_helper(parts.get(8))?.parse()?,
            transmit_bytes: get_helper(parts.get(9))?.parse()?,
            transmit_packets: get_helper(parts.get(10))?.parse()?,
            transmit_errors: get_helper(parts.get(11))?.parse()?,
            transmit_fifo_errors: get_helper(parts.get(12))?.parse()?,
            transmit_collission_erorrs: get_helper(parts.get(13))?.parse()?,
            tranmist_carrier_errors: get_helper(parts.get(14))?.parse()?,
        })
    }
    Ok(ret)
}

/// Returns all existing interfaces
pub fn get_interfaces() -> Result<Vec<String>, Error> {
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

pub fn ifindex_to_interface_name(ifindex: usize) -> Result<String, Error> {
    for interface in get_interfaces()? {
        let found_ifindex = get_ifindex(&interface)?;
        if ifindex == found_ifindex {
            return Ok(interface);
        }
    }
    Err(Error::NoInterfaceError(ifindex.to_string()))
}

/// Deletes an named interface
pub fn del_interface(name: &str) -> Result<(), Error> {
    run_command("ip", &["link", "del", "dev", name])?;
    Ok(())
}

pub fn iface_status(iface: &str) -> Result<String, Error> {
    // cat so we can mock
    let output = run_command("cat", &[&format!("/sys/class/net/{iface}/operstate")])?;

    let output = from_utf8(&output.stdout)?;

    Ok(output.trim_end().to_string())
}

/// Internal testing function for get_wg_remote_ip
fn get_wg_remote_ip_internal(stdout: String, name: String) -> Result<IpAddr, Error> {
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

pub fn get_wg_remote_ip(name: &str) -> Result<IpAddr, Error> {
    let output = run_command("wg", &["show", name, "endpoints"])?;
    let stdout = String::from_utf8(output.stdout)?;
    get_wg_remote_ip_internal(stdout, name.to_string())
}

/// Internal utility function for testing get_ip_from_iface
fn get_ip_from_iface_internal(stdout: String) -> Result<Vec<(Ipv4Addr, u8)>, Error> {
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
                    if let (Ok(parsed_ip), Ok(parsed_netmask)) = (ip_str.parse(), netmask.parse()) {
                        ret.push((parsed_ip, parsed_netmask));
                    }
                }
            }
        }
    }

    Ok(ret)
}

/// Gets all the IPv4 addresses from an interface and returns the address and it's netmask
/// as a tuple.
pub fn get_ip_from_iface(name: &str) -> Result<Vec<(Ipv4Addr, u8)>, Error> {
    let output = run_command("ip", &["address", "show", "dev", name])?;
    let stdout = String::from_utf8(output.stdout)?;
    get_ip_from_iface_internal(stdout)
}

/// Gets all the IPv6 addresses from an interface and returns the address and it's netmask
/// as a tuple.
pub fn get_ipv6_from_iface(name: &str) -> Result<Vec<(Ipv6Addr, u8)>, Error> {
    let output = run_command("ip", &["address", "show", "dev", name])?;
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
                    if let (Ok(parsed_ip), Ok(parsed_netmask)) = (ip_str.parse(), netmask.parse()) {
                        ret.push((parsed_ip, parsed_netmask));
                    }
                }
            }
        }
    }

    Ok(ret)
}

/// calls iproute2 to set an interface up or down
pub fn set_if_up_down(if_name: &str, up_down: &str) -> Result<(), Error> {
    let output = run_command("ip", &["link", "set", "dev", if_name, up_down])?;
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
pub fn get_mtu(if_name: &str) -> Result<usize, Error> {
    let lines = get_lines(&format!("/sys/class/net/{if_name}/mtu"))?;
    if let Some(mtu) = lines.first() {
        Ok(mtu.parse()?)
    } else {
        Err(Error::NoInterfaceError(if_name.to_string()))
    }
}

/// Gets the ifindex from an interface
pub fn get_ifindex(if_name: &str) -> Result<usize, Error> {
    if cfg!(feature = "integration_test") {
        // ip netns exec n-1 cat /sys/class/net/veth-n-1-n-2/iflink
        let ns = get_namespace().unwrap();
        let location = format!("/sys/class/net/{if_name}/ifindex");
        let index = run_command("ip", &["netns", "exec", &ns, "cat", &location])?;

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
        if let Some(ifindex) = lines.first() {
            Ok(ifindex.parse()?)
        } else {
            Err(Error::NoInterfaceError(if_name.to_string()))
        }
    }
}

/// Gets the iflink value from an interface. Physical interfaces have an ifindex and iflink that are
/// identical but if you have a virtual (say DSA) interface then this will be the physical interface name
pub fn get_iflink(if_name: &str) -> Result<usize, Error> {
    let lines = get_lines(&format!("/sys/class/net/{if_name}/iflink"))?;
    if let Some(iflink) = lines.first() {
        Ok(iflink.parse()?)
    } else {
        Err(Error::NoInterfaceError(if_name.to_string()))
    }
}

/// Sets the mtu of an interface, if this interface is a DSA interface the
/// parent interface will be located and it's mtu increased as appropriate
pub fn set_mtu(if_name: &str, mtu: usize) -> Result<(), Error> {
    let ifindex = get_ifindex(if_name)?;
    let iflink = get_iflink(if_name)?;
    // dsa interface detected, this is an interface controlled by an internal switch
    // the parent interface (which has the ifindex value represented in iflink for the child interface)
    // needs to have whatever the mtu is, plus room for VLAN headers
    const DSA_VLAN_HEADER_SIZE: usize = 8;
    if ifindex != iflink {
        let parent_if_name = ifindex_to_interface_name(iflink)?;
        set_mtu(&parent_if_name, mtu + DSA_VLAN_HEADER_SIZE)?;
    }

    let output = run_command(
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

#[test]
fn test_get_wg_remote_ip() {
    let stdout = "fvLYbeMV+RYbzJEc4lNEPuK8ulva/5wcSJBz0W5t3hM=	71.8.186.226:60000";

    assert_eq!(
        get_wg_remote_ip_internal(stdout.to_string(), "eth8".to_string()).unwrap(),
        "71.8.186.226".parse::<IpAddr>().unwrap()
    );

    let stdout =
        "v5yFYZVfl98N/LRVDK3hbyt5/dK/00VnEGHRBikHHXs=	[fe80::78e4:1cff:fe61:560d%veth-1-6]:60000";

    assert_eq!(
        get_wg_remote_ip_internal(stdout.to_string(), "eth8".to_string()).unwrap(),
        "fe80::78e4:1cff:fe61:560d".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn test_get_ip_addresses_linux() {
    let stdout ="
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
                ";

    let interfaces = get_ip_from_iface_internal(stdout.to_string()).unwrap();
    let val = ("192.168.1.203".parse().unwrap(), 32);
    assert!(interfaces.contains(&val))
}

#[test]
fn test_get_interface_usage() {
    let _ = get_per_interface_usage().unwrap();
}
