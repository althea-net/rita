use super::{KernelInterface, Error};

use std::net::{IpAddr};

impl KernelInterface {
    //checks the existing interfaces to find an interface name that isn't in use.
    //then calls iproute2 to set up a new interface.
    pub fn setup_wg_if_linux(&mut self, addr: &IpAddr, peer: &IpAddr) -> Result<String,Error> {
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
}