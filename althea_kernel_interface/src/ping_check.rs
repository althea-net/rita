use super::KernelInterface;
use failure::Error;
use std::net::{Ipv4Addr, Ipv6Addr};

impl dyn KernelInterface {
    //Pings a ipv6 address to determine if it's online
    pub fn ping_check_v6(&self, ip: &Ipv6Addr) -> Result<bool, Error> {
        let result = self.run_command("ping6", &["-w1", "-W1", "-c1", &ip.to_string()]);
        Ok(result?.status.success())
    }
    /// Pings a ipv4 address to determine if it's online
    pub fn ping_check_v4(&self, ip: &Ipv4Addr) -> Result<bool, Error> {
        let result = self.run_command("ping", &["-w1", "-W1", "-c1", &ip.to_string()]);
        Ok(result?.status.success())
    }
}
