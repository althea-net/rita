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
}

pub struct KernelInterface<'a> {
    fake_outputs: Option<HashMap<(&'a str, &'a [&'a str]), Output>>,
}

impl<'a> KernelInterface<'a> {
    pub fn new() -> KernelInterface<'a> {
        KernelInterface {
            fake_outputs: None
        }
    }

    fn add_fake_outputs(&mut self, fake_outputs: HashMap<(&'a str, &'a [&'a str]), Output>) {
        self.fake_outputs = Some(fake_outputs);
    }

    fn run_command(self, program: &'a str, args: &'a [&str]) -> Result<Output, Error> {
        match self.fake_outputs {
            Some(outputs) => Ok(outputs[&(program, args)].clone()),
            None => Command::new(program).args(args).output().map_err(|e| Error::Io(e))
        }
    }

    fn get_neighbors_linux(self) -> Result<Vec<(HwAddr, IpAddr)>, Error> {
        let output = self.run_command("ip", &["neighbor"])?;
        let mut vec = Vec::new();
        let re = Regex::new(r"(\S*) .* (\S*) (REACHABLE|STALE|DELAY)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            vec.push((
                caps.get(2).unwrap().as_str().parse::<HwAddr>().unwrap(),
                IpAddr::from_str(&caps[1]).unwrap(),
            ));
        }
        Ok(vec)
    }
    
    #[cfg(target_os = "linux")]
    pub fn get_neighbors(self) -> Result<Vec<(HwAddr, IpAddr)>, Error> {
        self.get_neighbors_linux()
    }

    fn get_traffic_linux(self) -> Result<Vec<(HwAddr, IpAddr, u64)>, Error> {
        let output = self.run_command("ebtables", &["-L", "INPUT", "--Lc"])?;
        let mut vec = Vec::new();
        let re = Regex::new(r"-s (.*) --ip6-dst (.*)/.* bcnt = (.*)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            vec.push((
                caps[1].parse::<HwAddr>().unwrap(),
                IpAddr::from_str(&caps[2]).unwrap(),
                caps[3].parse::<u64>().unwrap(),
            ));
        }
        Ok(vec)
    }

    #[cfg(target_os = "linux")]
    pub fn get_traffic(self) -> Result<Vec<(HwAddr, IpAddr, u64)>, Error> {
        self.get_traffic_linux()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_neighbors_linux() {
        let mut outputs = HashMap::new();
        outputs.insert(
            ("ip", &["neighbor"][..]),
            Output {
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
            },
        );
  
        let mut ki = KernelInterface::new();
        ki.add_fake_outputs(outputs);

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
        let mut outputs = HashMap::new();
        outputs.insert(("ebtables", &["-L", "INPUT", "--Lc"][..]), Output {
                    stdout: b"Bridge table: filter

Bridge chain: INPUT, entries: 3, policy: ACCEPT
-p IPv6 -s 0:0:0:aa:0:2 --ip6-dst 2001::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 1199 -- bcnt = 124696
-p IPv6 -s 0:0:0:aa:0:0 --ip6-dst 2001::3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 1187 -- bcnt = 123448
-p IPv6 -s 0:0:0:aa:0:0 --ip6-dst 2001::3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 0 -- bcnt = 0".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0)
                });

        let mut ki = KernelInterface::new();
        ki.add_fake_outputs(outputs);

        let traffic = ki.get_traffic_linux().unwrap();

        assert_eq!(format!("{}", traffic[0].0), "0:0:0:AA:0:2");
        assert_eq!(format!("{}", traffic[0].1), "2001::1");
        assert_eq!(traffic[0].2, 124696);

        assert_eq!(format!("{}", traffic[1].0), "0:0:0:AA:0:0");
        assert_eq!(format!("{}", traffic[1].1), "2001::3");
        assert_eq!(traffic[1].2, 123448);
    }


}
