use super::{KernelInterface, Error};

use std::net::{IpAddr};
use std::str::FromStr;

use regex::Regex;

impl KernelInterface {
    pub fn read_destination_counters_linux(&mut self) -> Result<Vec<(IpAddr, u64)>, Error> {
        let output = self.run_command("ebtables", &["-L", "OUTPUT", "--Lc", "--Lmac2"])?;
        let mut vec = Vec::new();
        let re = Regex::new(r"-p IPv6 --ip6-dst (.*)/.* bcnt = (.*)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            vec.push((
                IpAddr::from_str(&caps[1])?,
                caps[2].parse::<u64>()?,
            ));
        }
        trace!("Read destination couters {:?}", &vec);
        Ok(vec)
    }

}