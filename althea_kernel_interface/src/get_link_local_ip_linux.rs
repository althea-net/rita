use super::{KernelInterface, Error};

use std::net::{IpAddr};
use std::str::FromStr;

use regex::Regex;

impl KernelInterface {
    /// This gets our link local ip for a given device
    pub fn get_link_local_device_ip_linux(&self, dev: &str) -> Result<IpAddr, Error> {
        let output = self.run_command("ip", &["addr", "show", "dev", dev, "scope", "link"])?;
        trace!("Got {:?} from `ip addr`", output);

        let re = Regex::new(r"inet6 (\S*?)/[0-9]{2} scope link").unwrap();
        let str = String::from_utf8(output.stdout)?;
        let cap = re.captures(&str);
        if let Some(cap) = cap {
            trace!("got link local IP of {} from device {}", &cap[1], &dev);
            return Ok(cap[1].parse()?);
        } else {
            return Err(Error::RuntimeError("No link local addresses found or no interface found".to_string()))
        }
    }

    /// Given a neighboring link local ip, return the device name
    pub fn get_device_name_linux(&self, their_ip: IpAddr) -> Result<String, Error> {
        let neigh = self.get_neighbors()?;
        for (mac, ip, dev) in neigh {
            if ip == their_ip {
                return Ok(dev.to_string())
            }
        }

        Err(Error::RuntimeError("Address not found in neighbors".to_string()))
    }

    /// This gets our link local ip that can be reached by another node with link local ip
    pub fn get_link_local_reply_ip_linux(&self, their_ip: IpAddr) -> Result<IpAddr, Error> {
        let neigh = self.get_neighbors()?;

        for (mac, ip, dev) in neigh {
            if ip == their_ip {
                return Ok(self.get_link_local_device_ip_linux(&dev)?)
            }
        }

        Err(Error::RuntimeError("Address not found in neighbors".to_string()))
    }
}