use super::{KernelInterface, KernelManagerError};

use std::net::IpAddr;
use std::str::FromStr;
use std::fs::File;
use std::io::{Read, Write};

use regex::Regex;

use failure::Error;

impl KernelInterface {
    /// This gets our link local ip for a given device
    pub fn get_link_local_device_ip(&self, dev: &str) -> Result<IpAddr, Error> {
        let output = self.run_command("ip", &["addr", "show", "dev", dev, "scope", "link"])?;
        trace!("Got {:?} from `ip addr`", output);

        let re = Regex::new(r"inet6 (\S*?)/[0-9]{2} scope link").unwrap();
        let str = String::from_utf8(output.stdout)?;
        let cap = re.captures(&str);
        if let Some(cap) = cap {
            trace!("got link local IP of {} from device {}", &cap[1], &dev);
            return Ok(cap[1].parse()?);
        } else {
            return Err(KernelManagerError::RuntimeError(
                "No link local addresses found or no interface found".to_string(),
            ).into());
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

        Err(KernelManagerError::RuntimeError("Address not found in neighbors".to_string()).into())
    }

    /// This gets our link local ip that can be reached by another node with link local ip
    pub fn get_reply_ip(&self, their_ip: IpAddr, global_non_mesh_ip: Option<IpAddr>) -> Result<IpAddr, Error> {
        let neigh = self.get_neighbors()?;

        trace!("looking for {:?} in {:?} for reply ip", their_ip, neigh);
        for ( ip, dev) in neigh {
            if ip == their_ip {
                return Ok(self.get_link_local_device_ip(&dev)?);
            }
        }

        trace!("didn't find {:?} in neighbors, sending global ip {:?}", their_ip, global_non_mesh_ip);

        if let Some(global_non_mesh_ip) = global_non_mesh_ip {
            Ok(global_non_mesh_ip)
        } else {
            Err(KernelManagerError::RuntimeError("Address not found in neighbors".to_string()).into())
        }
    }

    /// Gets the interface index for a named interface
    pub fn get_iface_index(&self, name: &str) -> Result<u32, Error> {
        let mut f = File::open(format!("/sys/class/net/{}/ifindex", name))?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        contents.pop(); //remove trailing newline

        let index = contents.parse::<u32>()?;

        trace!("Got index: {}", index);

        Ok(index)
    }
}

#[test]
fn test_get_device_name_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(|program, args| {
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
        })),
    };

    let dev = ki.get_device_name("fe80::433:25ff:fe8c:e1ea".parse().unwrap())
        .unwrap();

    assert_eq!(dev, "eth2")
}

#[test]
fn test_get_link_local_device_ip_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(|program, args| {
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
        })),
    };

    let ip = ki.get_link_local_device_ip("eth0").unwrap();

    assert_eq!(ip, "fe80::96:3add:69d9:906a".parse::<IpAddr>().unwrap())
}

#[test]
fn test_get_link_local_reply_ip_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut counter = 0;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program, args| {
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
        })),
    };

    let dev = ki.get_reply_ip("fe80::7459:8eff:fe98:81".parse().unwrap())
        .unwrap();

    assert_eq!(dev, "fe80::96:3add:69d9:906a".parse::<IpAddr>().unwrap())
}
