use super::{KernelInterface, KernelManagerError};

use std::net::IpAddr;

use failure::Error;

impl KernelInterface {
    /// calls a ubus rpc
    pub fn ubus_call(&self, function: &str, argument: &str) -> Result<String, Error> {
        let output = String::from_utf8(
            self.run_command("ubus", &["call", function, argument])?
                .stdout,
        )?;
        Ok(output)
    }
}
