use super::{KernelInterface, Error};

use std::net::{IpAddr};
use std::str::FromStr;

use eui48::MacAddress;
use regex::Regex;

impl KernelInterface {
    pub fn get_neighbors_linux(&mut self) -> Result<Vec<(MacAddress, IpAddr, String)>, Error> {
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
}