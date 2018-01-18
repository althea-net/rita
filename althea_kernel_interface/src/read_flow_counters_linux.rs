use super::{KernelInterface, Error};

use std::net::{IpAddr};
use std::str::FromStr;

use eui48::MacAddress;
use regex::Regex;

impl KernelInterface {
    pub fn read_flow_counters_linux(&mut self) -> Result<Vec<(MacAddress, IpAddr, u64)>, Error> {
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
}