#[macro_use]
extern crate derive_error;

#[macro_use]
extern crate log;

extern crate eui48;
extern crate regex;
extern crate itertools;

use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::str::FromStr;
use std::time::{Instant};

use std::str;

use eui48::MacAddress;

mod create_wg_key;
mod delete_tunnel;
mod get_wg_pubkey;
mod open_tunnel;
mod setup_wg_if;
mod counter;
mod get_interfaces;
mod link_local_tools;
mod get_neighbors;

pub use counter::FilterTarget;

#[derive(Debug, Error)]
pub enum Error {
    Io(std::io::Error),
    StringUTF8(std::string::FromUtf8Error),
    StrUTF8(std::str::Utf8Error),
    ParseInt(std::num::ParseIntError),
    AddrParse(std::net::AddrParseError),
    MacParse(eui48::ParseError),
    #[error(msg_embedded, no_from, non_std)]
    RuntimeError(String),
}

#[cfg(test)]
pub struct KernelInterface {
    run_command: Box<FnMut(&str, &[&str]) -> Result<Output, Error>>,
}

#[cfg(not(test))]
pub struct KernelInterface {}

impl KernelInterface {
    #[cfg(not(test))]
    fn run_command(&self, program: &str, args: &[&str]) -> Result<Output, Error> {
        let start = Instant::now();
        let output = Command::new(program).args(args).output()?;
        trace!("Command {} {:?} returned: {:?}", program, args, output);
        if !output.status.success() {
            trace!("An error was returned");
        }
        info!("command completed in {}s {}ms", start.elapsed().as_secs(), start.elapsed().subsec_nanos()/1000000);
        return Ok(output);
    }

    #[cfg(test)]
    fn run_command(&self, args: &str, program: &[&str]) -> Result<Output, Error> {
        (self.run_command)(args, program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::fs::remove_file;
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::process::{ExitStatus};

    #[test]
    fn test_get_neighbors_linux() {
        let mut ki = KernelInterface {
            run_command: Box::new(|program, args| {
                assert_eq!(program, "ip");
                assert_eq!(args, &["neighbor"]);

                Ok(Output {
                    stdout: b"10.0.2.2 dev eth0 lladdr 00:00:00:aa:00:03 STALE
10.0.0.2 dev eth0  FAILED
10.0.1.2 dev eth0 lladdr 00:00:00:aa:00:05 REACHABLE
2001::2 dev eth0 lladdr 00:00:00:aa:00:56 REACHABLE
fe80::7459:8eff:fe98:81 dev eth0 lladdr 76:59:8e:98:00:81 STALE
fe80::433:25ff:fe8c:e1ea dev eth0 lladdr 1a:32:06:78:05:0a STALE
2001::2 dev eth0  FAILED"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        let addresses = ki.get_neighbors().unwrap();

        assert_eq!(format!("{}", addresses[0].0), "00-00-00-aa-00-03");
        assert_eq!(format!("{}", addresses[0].1), "10.0.2.2");

        assert_eq!(format!("{}", addresses[1].0), "00-00-00-aa-00-05");
        assert_eq!(format!("{}", addresses[1].1), "10.0.1.2");

        assert_eq!(format!("{}", addresses[2].0), "00-00-00-aa-00-56");
        assert_eq!(format!("{}", addresses[2].1), "2001::2");
    }

    #[test]
    fn test_read_flow_counters_linux() {
        let mut ki = KernelInterface {
            run_command: Box::new(|program, args| {
                assert_eq!(program, "ebtables");
                assert_eq!(args, &["-L", "INPUT", "--Lc", "--Lmac2"]);

                Ok(Output {
                    stdout:
b"Bridge table: filter

Bridge chain: INPUT, entries: 3, policy: ACCEPT
-p IPv6 -s 00:00:00:aa:00:02 --ip6-dst 2001::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 1199 -- bcnt = 124696
-p IPv6 -s 00:00:00:aa:00:00 --ip6-dst 2001::3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 1187 -- bcnt = 123448
-p IPv6 -s 00:00:00:aa:00:00 --ip6-dst 2001::3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 0 -- bcnt = 0"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        let traffic = ki.read_flow_counters_linux(false).unwrap();

        assert_eq!(format!("{}", traffic[0].0), "00-00-00-aa-00-02");
        assert_eq!(format!("{}", traffic[0].1), "2001::1");
        assert_eq!(traffic[0].2, 124696);

        assert_eq!(format!("{}", traffic[1].0), "00-00-00-aa-00-00");
        assert_eq!(format!("{}", traffic[1].1), "2001::3");
        assert_eq!(traffic[1].2, 123448);
    }

    #[test]
    fn test_delete_counter_linux() {
        let mut counter = 0;
        let delete_rule = &[
            "-D",
            "INPUT",
            "-s",
            "00:00:00:aa:00:02",
            "-p",
            "IPV6",
            "--ip6-dst",
            "2001::3",
            "-j",
            "CONTINUE",
        ];
        let mut ki = KernelInterface {
            run_command: Box::new(move |program, args| {
                assert_eq!(program, "ebtables");

                counter = counter + 1;
                println!("COUNTER {}", counter);
                match counter {
                    1 => {
                        assert_eq!(args, delete_rule);
                        Ok(Output {
                            stdout: b"".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    2 => {
                        assert_eq!(args, delete_rule);
                        Ok(Output {
                            stdout: b"".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    3 => {
                        assert_eq!(args, delete_rule);
                        Ok(Output {
                            stdout: b"Sorry, rule does not exist.".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    _ => panic!("run_command called too many times"),

                }

            }),
        };
        ki.delete_flow_counter_linux(
            MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ).unwrap();

        let mut ki = KernelInterface {
            run_command: Box::new(move |_, _| {
                counter = counter + 1;
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        match ki.delete_flow_counter_linux(
            MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ) {
            Err(e) => assert_eq!(e.to_string(), "loop limit of 100 exceeded"),
            _ => panic!("no loop limit error")
        }

        let mut ki = KernelInterface {
            run_command: Box::new(move |_, _| {
                counter = counter + 1;
                Ok(Output {
                    stdout: b"shibby".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        match ki.delete_flow_counter(
            MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ) {
            Err(e) => assert_eq!(e.to_string(), "unexpected output from ebtables \"-D INPUT -s 00:00:00:aa:00:02 -p IPV6 --ip6-dst 2001::3 -j CONTINUE\": \"shibby\""),
            _ => panic!("no unexpeted input error")
        }
    }

    #[test]
    fn test_start_flow_counter_linux() {
        let mut counter = 0;
        let add_rule = &[
            "-A",
            "INPUT",
            "-s",
            "00:00:00:aa:00:02",
            "-p",
            "IPV6",
            "--ip6-dst",
            "2001::3",
            "-j",
            "CONTINUE",
        ];
        let mut ki = KernelInterface {
            run_command: Box::new(move |program, args| {
                assert_eq!(program, "ebtables");

                counter = counter + 1;
                println!("COUNTER {}", counter);
                match counter {
                    1 => { Ok(Output {
                            stdout:
                            b"Bridge table: filter

Bridge chain: INPUT, entries: 3, policy: ACCEPT
"
                                .to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0)})}
                    2 => {
                        assert_eq!(args, add_rule);
                        Ok(Output {
                            stdout: b"".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    _ => panic!("run_command called too many times"),

                }

            }),
        };

        ki.start_flow_counter_linux(
            MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ).unwrap();
    }

    #[test]
    fn test_open_tunnel_linux() {
        let interface = String::from("wg1");
        let endpoint_ip = Ipv6Addr::new(0x2001,0,0,0,0,0,0,1);
        let endpoint = SocketAddr::V6(SocketAddrV6::new(endpoint_ip,8088,0,0));
        let remote_pub_key = String::from("x8AcR9wI4t97aowYFlis077BDBk9SLdq6khMiixuTsQ=");
        let private_key_path = Path::new("private_key");

        let wg_args = &[
            "set",
            "wg1",
            "private-key",
            "private_key",
            "peer",
            "x8AcR9wI4t97aowYFlis077BDBk9SLdq6khMiixuTsQ=",
            "endpoint",
            "[2001::1]:8088",
            "allowed-ips",
            "::/0"];

        let mut ki = KernelInterface {
            run_command: Box::new(move |program,args| {
                assert_eq!(program, "wg");
                assert_eq!(args, wg_args);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0)
                })
            })
        };

        ki.open_tunnel(&interface, &endpoint, &remote_pub_key, &private_key_path).unwrap();
    }

    #[test]
    fn test_delete_tunnel_linux() {
        let ip_args = &["link", "del", "wg1"];

        let mut ki = KernelInterface {
            run_command: Box::new(move |program,args| {
                assert_eq!(program, "ip");
                assert_eq!(args,ip_args);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0)
                })
            })
        };
        ki.delete_tunnel_linux(&String::from("wg1")).unwrap();
    }

    #[test]
    fn test_setup_wg_if_linux() {
        let addr = IpAddr::V6(Ipv6Addr::new(0xfd01,0,0,0,0,0,0,1));
        let peer = IpAddr::V6(Ipv6Addr::new(0xfd01,0,0,0,0,0,0,2));
        let mut counter = 0;

        let link_args = &["link"];
        let link_add = &[
            "link",
            "add",
            "wg1",
            "type",
            "wireguard"];
        let mut ki = KernelInterface {
            run_command: Box::new(move |program,args|{
                assert_eq!(program,"ip");
                counter += 1;

                match counter {
                    1 => {
                        assert_eq!(args,link_args);
                        Ok(Output{
                            stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    2 => {
                        assert_eq!(args,link_add);
                        Ok(Output{
                            stdout: b"".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    _ => panic!("command called too many times")
                }
            })
        };

        ki.setup_wg_if_linux().unwrap();
    }

    #[test]
    fn test_create_wg_key_linux() {
        let wg_args = &["genkey"];
        let mut ki = KernelInterface {
            run_command: Box::new(move |program, args| {
                assert_eq!(program, "wg");
                assert_eq!(args,wg_args);
                Ok(Output {
                    stdout: b"cD6//mKSM4mhaF4mNY7N93vu5zKad79/MyIRD3L9L0s=".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0)
                })
            })
        };
        let test_path = Path::new("/tmp/wgtestkey");
        ki.create_wg_key_linux(test_path).unwrap();
        remove_file(test_path).unwrap();
    }
}
