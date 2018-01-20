use super::{Error, KernelInterface};

use std::net::{IpAddr};

impl KernelInterface {
    pub fn start_destination_counter_linux(&mut self, destination: IpAddr) -> Result<(), Error> {
        self.delete_destination_counter_linux(destination)?;
        self.run_command(
            "ebtables",
            &[
                "-A",
                "OUTPUT",
                "-p",
                "IPV6",
                "--ip6-dst",
                &format!("{}", destination),
                "-j",
                "CONTINUE",
            ],
        )?;
        Ok(())
    }
}
