use super::{KernelInterface, Error};

use std::net::{IpAddr};

use regex::Regex;

impl KernelInterface {
    /// Returns all existing interfaces
    pub fn get_interfaces(&self) -> Result<Vec<String>,Error> {
        let links = String::from_utf8(self.run_command("ip", &["link"])?.stdout)?;

        let mut vec = Vec::new();
        let re = Regex::new(r"[0-9]+: (.*?)( :|@)").unwrap();
        for caps in re.captures_iter(&links) {
            vec.push(String::from(&caps[1]));
        }

        trace!("interfaces: {:?}", vec);
        Ok(vec)
    }
}