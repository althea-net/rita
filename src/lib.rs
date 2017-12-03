#[macro_use]
extern crate derive_error;

use std::str;
extern crate hwaddr;
extern crate regex;

use std::collections::HashMap;
use std::net::IpAddr;
use hwaddr::HwAddr;
use std::str::FromStr;
use regex::Regex;
use std::process::{Command, Output, ExitStatus};
use std::os::unix::process::ExitStatusExt;

#[derive(Debug, Error)]
pub enum Error {
    Io(std::io::Error),
    UTF8(std::string::FromUtf8Error),
    ParseInt(std::num::ParseIntError),
    AddrParse(std::net::AddrParseError),
    #[error(msg_embedded, no_from, non_std)]
    RuntimeError(String),
}

pub struct KernelInterface {
    run_command: Box<FnMut(&str, &[&str]) -> Result<Output, Error>>,
}

impl KernelInterface {
    pub fn new() -> KernelInterface {
        KernelInterface {
            run_command: Box::new(|program, args| {
                let output = Command::new(program).args(args).output()?;
                if !output.status.success() {
                    return Err(Error::RuntimeError(String::from(format!(
                        "{:?} {:?} exited with error code {}, and message {}",
                        program,
                        args,
                        output.status.code().unwrap(),
                        String::from_utf8_lossy(&output.stderr)
                    ))));
                } else {
                    return Ok(output);
                }
            }),
        }
    }

    fn get_neighbors_linux(&mut self) -> Result<Vec<(HwAddr, IpAddr)>, Error> {
        let output = (self.run_command)("ip", &["neighbor"])?;
        let mut vec = Vec::new();
        let re = Regex::new(r"(\S*) .* (\S*) (REACHABLE|STALE|DELAY)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            vec.push((
                caps.get(2).unwrap().as_str().parse::<HwAddr>()?,
                IpAddr::from_str(&caps[1])?,
            ));
        }
        Ok(vec)
    }

    /// Returns a vector of neighbors reachable over layer 2, giving the hardware
    /// and IP address of each. Implemented with `ip neighbor` on Linux.
    pub fn get_neighbors(&mut self) -> Result<Vec<(HwAddr, IpAddr)>, Error> {
        if cfg!(target_os = "linux") {
            return self.get_neighbors_linux();
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    fn register_flow_linux(
        &mut self,
        source_neighbor: HwAddr,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_flow_linux(source_neighbor, destination)?;
        match (self.run_command)(
            "ebtables",
            &[
                "-A",
                "INPUT",
                "-s",
                &format!("{}", source_neighbor),
                "-p",
                "IPV6",
                "--ip6-dst",
                &format!("{}", destination),
                "-j",
                "ACCEPT",
            ]
                [..],
        ) {
            Ok(v) => {
                match v.status.success() {
                    true => Ok(()),
                    false => Err(Error::RuntimeError(
                        String::from(format!("{}", v.status.code().unwrap())),
                    )),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// This starts a counter of the bytes used by a particular "flow", a
    /// Neighbor/Destination pair. If the flow already exists, it resets the counter.
    /// Implemented with `ebtables` on linux.
    pub fn register_flow(
        &mut self,
        source_neighbor: HwAddr,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.register_flow_linux(source_neighbor, destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    fn delete_flow_linux(
        &mut self,
        source_neighbor: HwAddr,
        destination: IpAddr,
    ) -> Result<(), Error> {
        loop {
            let res = (self.run_command)(
                "ebtables",
                &[
                    "-D",
                    "INPUT",
                    "-s",
                    &format!("{}", source_neighbor),
                    "-p",
                    "IPV6",
                    "--ip6-dst",
                    &format!("{}", destination),
                    "-j",
                    "ACCEPT",
                ]
                    [..],
            )?;
            // keeps looping until it is sure to have deleted the rule
            if res.stdout == b"Sorry, rule does not exist.".to_vec() {
                return Ok(());
            }
        }
    }

    /// This deletes a counter of the bytes used by a particular "flow", a
    /// Neighbor/Destination pair.
    /// Implemented with `ebtables` on linux.
    pub fn delete_flow(
        &mut self,
        source_neighbor: HwAddr,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.delete_flow_linux(source_neighbor, destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    fn get_traffic_linux(&mut self) -> Result<Vec<(HwAddr, IpAddr, u64)>, Error> {
        let output = (self.run_command)("ebtables", &["-L", "INPUT", "--Lc"])?;
        let mut vec = Vec::new();
        let re = Regex::new(r"-s (.*) --ip6-dst (.*)/.* bcnt = (.*)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            vec.push((
                caps[1].parse::<HwAddr>()?,
                IpAddr::from_str(&caps[2])?,
                caps[3].parse::<u64>()?,
            ));
        }
        Ok(vec)
    }

    /// Returns a vector of traffic coming from a specific hardware address and going
    /// to a specific IP. Note that this will only track flows that have already been
    /// registered. Implemented with `ebtables` on Linux.
    pub fn get_traffic(&mut self) -> Result<Vec<(HwAddr, IpAddr, u64)>, Error> {
        if cfg!(target_os = "linux") {
            return self.get_traffic_linux();
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let addresses = ki.get_neighbors_linux().unwrap();

        assert_eq!(format!("{}", addresses[0].0), "0:0:0:AA:0:3");
        assert_eq!(format!("{}", addresses[0].1), "10.0.2.2");

        assert_eq!(format!("{}", addresses[1].0), "0:0:0:AA:0:5");
        assert_eq!(format!("{}", addresses[1].1), "10.0.1.2");

        assert_eq!(format!("{}", addresses[2].0), "0:0:0:AA:0:56");
        assert_eq!(format!("{}", addresses[2].1), "2001::2");
    }

    #[test]
    fn test_get_traffic_linux() {
        let mut ki = KernelInterface {
            run_command: Box::new(|program, args| {
                assert_eq!(program, "ebtables");
                assert_eq!(args, &["-L", "INPUT", "--Lc"]);

                Ok(Output {
                    stdout:
b"Bridge table: filter

Bridge chain: INPUT, entries: 3, policy: ACCEPT
-p IPv6 -s 0:0:0:aa:0:2 --ip6-dst 2001::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 1199 -- bcnt = 124696
-p IPv6 -s 0:0:0:aa:0:0 --ip6-dst 2001::3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 1187 -- bcnt = 123448
-p IPv6 -s 0:0:0:aa:0:0 --ip6-dst 2001::3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 0 -- bcnt = 0"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        let traffic = ki.get_traffic_linux().unwrap();

        assert_eq!(format!("{}", traffic[0].0), "0:0:0:AA:0:2");
        assert_eq!(format!("{}", traffic[0].1), "2001::1");
        assert_eq!(traffic[0].2, 124696);

        assert_eq!(format!("{}", traffic[1].0), "0:0:0:AA:0:0");
        assert_eq!(format!("{}", traffic[1].1), "2001::3");
        assert_eq!(traffic[1].2, 123448);
    }

    #[test]
    fn test_delete_flow_linux() {
        let mut counter = 0;
        let delete_rule = &[
            "-D",
            "INPUT",
            "-s",
            "0:0:0:AA:0:2",
            "-p",
            "IPV6",
            "--ip6-dst",
            "2001::3",
            "-j",
            "ACCEPT",
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
        ki.delete_flow_linux(
            "0:0:0:aa:0:2".parse::<HwAddr>().unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ).unwrap();
    }

    #[test]
    fn test_register_flow_linux() {
        let mut counter = 0;
        let delete_rule = &[
            "-D",
            "INPUT",
            "-s",
            "0:0:0:AA:0:2",
            "-p",
            "IPV6",
            "--ip6-dst",
            "2001::3",
            "-j",
            "ACCEPT",
        ];
        let add_rule = &[
            "-A",
            "INPUT",
            "-s",
            "0:0:0:AA:0:2",
            "-p",
            "IPV6",
            "--ip6-dst",
            "2001::3",
            "-j",
            "ACCEPT",
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
                            stdout: b"Sorry, rule does not exist.".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
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

        ki.register_flow_linux(
            "0:0:0:aa:0:2".parse::<HwAddr>().unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ).unwrap();
    }
}
