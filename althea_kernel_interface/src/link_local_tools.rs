use crate::{file_io::get_lines, KernelInterface, KernelInterfaceError};
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn parse_if_inet6_addr(line: String, is_local: bool) -> Result<Ipv6Addr, KernelInterfaceError> {
    if (is_local && line.starts_with("fe80")) || (!is_local && !line.starts_with("fe80")) {
        let mut line = line;
        // 32 hex characters in v6 addr
        line.truncate(32);

        let mut addr_str = "".to_string();
        for (i, c) in line.char_indices() {
            if i != 0 && i % 4 == 0 {
                addr_str.push(':');
            }
            addr_str.push(c);
        }

        let addr: Ipv6Addr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                error!("Unable to parse ipv6 link local with {:?}", e);
                return Err(KernelInterfaceError::ParseError(addr_str));
            }
        };

        return Ok(addr);
    }

    Err(KernelInterfaceError::RuntimeError(
        "Cannot find request ip on interface".to_string(),
    ))
}

impl dyn KernelInterface {
    /// This gets our link local ip for a given device
    pub fn get_link_local_device_ip(&self, dev: &str) -> Result<Ipv6Addr, KernelInterfaceError> {
        let path = "/proc/net/if_inet6";
        let lines = get_lines(path)?;
        for line in lines {
            if line.contains(dev) {
                match parse_if_inet6_addr(line, true) {
                    Ok(a) => return Ok(a),
                    Err(_) => continue,
                }
            }
        }
        Err(KernelInterfaceError::AddressNotReadyError(
            "No address seems to be available yet".to_string(),
        ))
    }

    /// This gets our global ip for a given device
    pub fn get_global_device_ip(&self, dev: &str) -> Result<Ipv6Addr, KernelInterfaceError> {
        let path = "/proc/net/if_inet6";
        let lines = get_lines(path)?;
        for line in lines {
            if line.contains(dev) {
                match parse_if_inet6_addr(line, false) {
                    Ok(a) => return Ok(a),
                    Err(_) => continue,
                }
            }
        }
        Err(KernelInterfaceError::AddressNotReadyError(
            "No address seems to be available yet".to_string(),
        ))
    }

    pub fn get_global_device_ip_v4(&self, dev: &str) -> Result<Ipv4Addr, KernelInterfaceError> {
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
            ))
        }
    }

    /// Given a neighboring link local ip, return the device name
    pub fn get_device_name(&self, their_ip: IpAddr) -> Result<String, KernelInterfaceError> {
        let neigh = self.get_neighbors()?;
        trace!("looking for {:?} in {:?} for device name", their_ip, neigh);
        for (ip, dev) in neigh {
            if ip == their_ip {
                return Ok(dev);
            }
        }

        Err(KernelInterfaceError::RuntimeError(
            "Address not found in neighbors".to_string(),
        ))
    }

    /// This gets our link local ip that can be reached by another node with link local ip
    pub fn get_reply_ip(
        &self,
        their_ip: Ipv6Addr,
        external_interface: Option<String>,
    ) -> Result<Ipv6Addr, KernelInterfaceError> {
        let neigh = self.get_neighbors()?;

        trace!("Looking for {:?} in {:?} for reply ip", their_ip, neigh);
        for (ip, dev) in neigh {
            if ip == their_ip {
                return self.get_link_local_device_ip(&dev);
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
            Err(KernelInterfaceError::RuntimeError(
                "Address not found in neighbors".to_string(),
            ))
        }
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
        assert_eq!(args, &["neigh"]);

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
fn test_if_inet6_parsing() {
    let addrs = "26003c01e002f1000000000000000000 06 3c 00 80   br-lan
fd53a881fcbb6747a0ae2e1d8473b242 10 80 00 80      wg1
fd53a881fcbb6747a0ae2e1d8473b242 0e 80 00 80      wg0
fe800000000000009683c4fffe0deeb5 09 40 20 80    wlan1
fe80000000000000a0ae2e1d8473b242 10 40 20 80      wg1
fe80000000000000a0ae2e1d8473b242 0f 40 20 80  wg_exit
fe80000000000000a0ae2e1d8473b242 0e 40 20 80      wg0
00000000000000000000000000000001 01 80 10 80       lo
fe800000000000009683c4fffe0deeb4 0a 40 20 80    wlan0
fe800000000000009683c4fffe0deeb4 06 40 20 80   br-lan
fe800000000000009683c4fffe0deeb4 02 40 20 80     eth0
fe800000000000009683c4fffe0deeb4 08 40 20 80   eth0.4"
        .to_string();

    let mut br_lan_local: Option<Ipv6Addr> = None;
    let mut br_lan_global: Option<Ipv6Addr> = None;

    let lines = addrs.split('\n').collect::<Vec<&str>>();
    for line in lines {
        if line.contains("br-lan") {
            match parse_if_inet6_addr(line.to_string(), false) {
                Ok(a) => br_lan_global = Some(a),
                Err(_) => continue,
            }
        }
    }

    let lines = addrs.split('\n').collect::<Vec<&str>>();
    for line in lines {
        if line.contains("br-lan") {
            match parse_if_inet6_addr(line.to_string(), true) {
                Ok(a) => br_lan_local = Some(a),
                Err(_) => continue,
            }
        }
    }

    assert_eq!(
        br_lan_global,
        Some("2600:3c01:e002:f100::".parse().unwrap())
    );
    assert_eq!(
        br_lan_local,
        Some("fe80::9683:c4ff:fe0d:eeb4".parse().unwrap())
    )
}
