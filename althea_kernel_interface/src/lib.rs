#[macro_use]
extern crate derive_error;

#[macro_use]
extern crate log;

extern crate eui48;
extern crate regex;
extern crate itertools;

use std::fs;
use std::fs::{File, remove_file};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, SocketAddrV6, Ipv6Addr};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Output, ExitStatus, Stdio};
use std::str::FromStr;
use std::str;

use eui48::MacAddress;
use itertools::join;
use regex::Regex;

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
    fn run_command(&mut self, program: &str, args: &[&str]) -> Result<Output, Error> {
        let output = Command::new(program).args(args).output()?;
        trace!("Command {} {:?} returned: {:?}", program, args, output);
        if !output.status.success() {
            trace!("An error was returned");
        }
        return Ok(output);
    }

    #[cfg(test)]
    fn run_command(&mut self, args: &str, program: &[&str]) -> Result<Output, Error> {
        (self.run_command)(args, program)
    }

    fn get_neighbors_linux(&mut self) -> Result<Vec<(MacAddress, IpAddr, String)>, Error> {
        let output = self.run_command("ip", &["neighbor"])?;
        trace!("Got {:?} from `ip neighbor`", output);

        let mut vec = Vec::new();
        let re = Regex::new(r"(\S*).*dev (\S*).*lladdr (\S*).*(REACHABLE|STALE|DELAY)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            trace!("Regex captured {:?}", caps);

            vec.push((
                MacAddress::parse_str(&caps[3]).unwrap(), // Ugly and inconsiderate, ditch ASAP
                IpAddr::from_str(&caps[1])?,
                caps[2].to_string()
            ));
        }
        trace!("Got neighbors {:?}", vec);
        Ok(vec)
    }

    fn start_flow_counter_linux(
        &mut self,
        source_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_flow_counter_linux(source_neighbor, destination)?;
        self.run_command(
            "ebtables",
            &[
                "-A",
                "INPUT",
                "-s",
                &format!("{}", source_neighbor.to_hex_string()),
                "-p",
                "IPV6",
                "--ip6-dst",
                &format!("{}", destination),
                "-j",
                "CONTINUE",
            ],
        )?;
        Ok(())
    }

    fn start_destination_counter_linux(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_destination_counter_linux(destination)?;
        self.run_command(
            "ebtables",
            &[
                "-A",
                "INPUT",
                "-p",
                "IPV6",
                "--ip6-dst",
                &format!("{}", destination),
                "-j",
                "CONTINUE",
            ],
        )?;
        Ok(())
    }


    fn delete_ebtables_rule(
        &mut self,
        args: &[&str]
    ) -> Result<(), Error> {
        let loop_limit = 100;
        for _ in 0..loop_limit {
            let program = "ebtables";
            let res = self.run_command(program, args)?;

            let re = Regex::new(r"rule does not exist").unwrap();

            // keeps looping until it is sure to have deleted the rule
            if re.is_match(str::from_utf8(&res.stderr)?) || re.is_match(str::from_utf8(&res.stdout)?) {
                return Ok(());
            }
            if res.stdout == b"".to_vec() {
                continue;
            } else {
                return Err(Error::RuntimeError(
                    format!("unexpected output from {} {:?}: {:?}", program, join(args, " "), String::from_utf8_lossy(&res.stdout)),
                ))
            }
        }
        Err(Error::RuntimeError(
            format!("loop limit of {} exceeded", loop_limit)
        ))
    }

    fn delete_flow_counter_linux(
        &mut self,
        source_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_ebtables_rule(&[
            "-D",
            "INPUT",
            "-s",
            &format!("{}", source_neighbor.to_hex_string()),
            "-p",
            "IPV6",
            "--ip6-dst",
            &format!("{}", destination),
            "-j",
            "CONTINUE",
        ])
    }

    fn delete_destination_counter_linux(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_ebtables_rule(&[
            "-D",
            "INPUT",
            "-p",
            "IPV6",
            "--ip6-dst",
            &format!("{}", destination),
            "-j",
            "CONTINUE",
        ])
    }

    fn read_flow_counters_linux(&mut self) -> Result<Vec<(MacAddress, IpAddr, u64)>, Error> {
        let output = self.run_command("ebtables", &["-L", "INPUT", "--Lc", "--Lmac2"])?;
        let mut vec = Vec::new();
        let re = Regex::new(r"-s (.*) --ip6-dst (.*)/.* bcnt = (.*)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            vec.push((
                    MacAddress::parse_str(&caps[1]).unwrap_or_else(|e| {
                        panic!("{:?}, original string {:?}", e, caps);
                    }), // Ugly and inconsiderate, remove ASAP
                IpAddr::from_str(&caps[2])?,
                caps[3].parse::<u64>()?,
            ));
        }
        trace!("Read flow couters {:?}", &vec);
        Ok(vec)
    }

    /// Returns a vector of neighbors reachable over layer 2, giving the hardware
    /// and IP address of each. Implemented with `ip neighbor` on Linux.
    pub fn get_neighbors(&mut self) -> Result<Vec<(MacAddress, IpAddr, String)>, Error> {
        if cfg!(target_os = "linux") {
            return self.get_neighbors_linux();
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }


    /// This starts a counter of bytes forwarded to a certain destination.
    /// If the destination already exists, it resets the counter.
    /// Implemented with `ebtables` on linux.
    pub fn start_destination_counter(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.start_destination_counter_linux(destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    /// This deletes a counter of bytes forwarded to a certain destination.
    /// Implemented with `ebtables` on linux.
    pub fn delete_destination_counter(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.delete_destination_counter_linux(destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }


    /// This starts a counter of the bytes used by a particular "flow", a
    /// Neighbor/Destination pair. If the flow already exists, it resets the counter.
    /// Implemented with `ebtables` on linux.
    pub fn start_flow_counter(
        &mut self,
        source_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.start_flow_counter_linux(source_neighbor, destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    /// This deletes a counter of the bytes used by a particular "flow", a
    /// Neighbor/Destination pair.
    /// Implemented with `ebtables` on linux.
    pub fn delete_flow_counter(
        &mut self,
        source_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.delete_flow_counter_linux(source_neighbor, destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    /// Returns a vector of traffic coming from a specific hardware address and going
    /// to a specific IP. Note that this will only track flows that have already been
    /// registered. Implemented with `ebtables` on Linux.
    pub fn read_flow_counters(&mut self) -> Result<Vec<(MacAddress, IpAddr, u64)>, Error> {
        if cfg!(target_os = "linux") {
            return self.read_flow_counters_linux();
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    /// Gets the interface index for a named interface
    pub fn get_iface_index(&mut self, name: &str) -> Result<u32, Error> {
        let mut f = File::open(format!("/sys/class/net/{}/ifindex", name))?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        contents.pop(); //remove trailing newline

        let index = contents.parse::<u32>()?;

        trace!("Got index: {}", index);

        Ok(index)
    }

    pub fn open_tunnel(
        &mut self,
        interface: &String,
        endpoint: &SocketAddr,
        remote_pub_key: &String,
        private_key_path: &Path
    ) -> Result<(), Error> {
            if cfg!(target_os = "linux") {
                return self.open_tunnel_linux(interface, endpoint, remote_pub_key, private_key_path);
            }

            Err(Error::RuntimeError(String::from("not implemented for this platform")))
    }

    fn open_tunnel_linux(
        &mut self,
        interface: &String,
        endpoint: &SocketAddr,
        remote_pub_key: &String,
        private_key_path: &Path
    ) -> Result<(), Error> {
        let output = self.run_command("wg", &[
            "set",
            &interface,
            "private-key",
            &format!("{}", private_key_path.to_str().unwrap()),
            "peer",
            &format!("{}", remote_pub_key),
            "endpoint",
            &format!("{}", endpoint),
            "allowed-ips",
            "::/0"
        ])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error from wg command: {}", String::from_utf8(output.stderr)?)));
        }
        Ok(())
    }

    pub fn delete_tunnel(&mut self, interface: &String) -> Result<(),Error> {
            if cfg!(target_os = "linux") {
                return self.delete_tunnel_linux(interface);
            }

            Err(Error::RuntimeError(String::from("not implemented for this platform")))
    }

    fn delete_tunnel_linux(&mut self, interface: &String) -> Result<(),Error> {
        let output = self.run_command("ip", &["link", "del", &interface])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error deleting wireguard interface: {}", String::from_utf8(output.stderr)?)));
        }
        Ok(())
    }

    pub fn setup_wg_if(&mut self, addr: &IpAddr, peer: &IpAddr) -> Result<String,Error> {
            if cfg!(target_os = "linux") {
                return self.setup_wg_if_linux(addr, peer);
            }

            Err(Error::RuntimeError(String::from("not implemented for this platform")))
    }
    //checks the existing interfaces to find an interface name that isn't in use.
    //then calls iproute2 to set up a new interface.
    fn setup_wg_if_linux(&mut self, addr: &IpAddr, peer: &IpAddr) -> Result<String,Error> {
        //call "ip links" to get a list of currently set up links
        let links = String::from_utf8(self.run_command("ip", &["link"])?.stdout)?;
        let mut if_num = 0;
        //loop through the output of "ip links" until we find a wg suffix that isn't taken (e.g. "wg3")
        while links.contains(format!("wg{}", if_num).as_str()) {
            if_num += 1;
        }
        let interface = format!("wg{}", if_num);
        let output = self.run_command("ip", &["link", "add", &interface, "type", "wireguard"])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error adding wg link: {}", String::from_utf8(output.stderr)?)))
        }
        let output = self.run_command("ip", &["addr", "add", &format!("{}", addr), "dev", &interface, "peer", &format!("{}", peer)])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error adding wg address: {}", String::from_utf8(output.stderr)?)))
        }
        let output = self.run_command("ip", &["link", "set", &interface, "up"])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error setting wg interface up: {}", String::from_utf8(output.stderr)?)))
        }
        Ok(interface)
    }

    pub fn create_wg_key(&mut self, path: &Path) -> Result<(),Error> {
            if cfg!(target_os = "linux") {
                return self.create_wg_key_linux(path);
            }

            Err(Error::RuntimeError(String::from("not implemented for this platform")))

    }
    fn create_wg_key_linux(&mut self, path: &Path) -> Result<(),Error> {
        let mut output = self.run_command("wg", &["genkey"])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error in generating wg key: {}", String::from_utf8(output.stderr)?)));
        }
        output.stdout.truncate(44); //key should only be 44 bytes
        let mut priv_key_file = File::create(path)?;
        write!(priv_key_file, "{}", String::from_utf8(output.stdout)?)?;
        Ok(())
    }

    pub fn get_wg_pubkey(&mut self, path: &Path) -> Result<String, Error> {
            if cfg!(target_os = "linux") {
                return self.get_wg_pubkey_linux(path);
            }

            Err(Error::RuntimeError(String::from("not implemented for this platform")))
    }
    fn get_wg_pubkey_linux(&mut self, path: &Path) -> Result<String, Error> {
        let priv_key_file = File::open(path)?;
        let mut output = Command::new("wg").args(&["pubkey"]).stdin(Stdio::from(priv_key_file)).output()?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error in getting wg public key: {}", String::from_utf8(output.stderr)?)));
        }
        output.stdout.truncate(44); //key should only be 44 bytes
        Ok(String::from_utf8(output.stdout)?)
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

        let traffic = ki.read_flow_counters_linux().unwrap();

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

        match ki.delete_flow_counter_linux(
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

        ki.open_tunnel_linux(&interface,&endpoint,&remote_pub_key,&private_key_path).unwrap();
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
        let addr_add = &[
            "addr",
            "add",
            "fd01::1",
            "dev",
            "wg1",
            "peer",
            "fd01::2"];
        let link_set = &[
            "link",
            "set",
            "wg1",
            "up"
        ];
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
                    3 => {
                        assert_eq!(args,addr_add);
                        Ok(Output{
                            stdout: b"".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    4 => {
                        assert_eq!(args,link_set);
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

        ki.setup_wg_if_linux(&addr, &peer).unwrap();
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
