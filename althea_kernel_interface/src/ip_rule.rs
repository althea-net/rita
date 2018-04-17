use super::{KernelInterface, KernelInterfaceError};

use std::net::IpAddr;

use failure::Error;

impl KernelInterface {
    pub fn set_interface_route_via_exit(
        &self,
        interface: &str,
        exit_internal_ip: IpAddr,
    ) -> Result<(), Error> {
        self.run_command(
            "ip",
            &[
                "route",
                "add",
                "default",
                "via",
                &format!("{}", exit_internal_ip),
                "table",
                "99",
            ],
        );
        self.run_command("ip", &["rule", "add", "iif", interface, "table", "99"]);
        self.run_command("ip", &["route", "flush", "cache"])?;
        Ok(())
    }
}
