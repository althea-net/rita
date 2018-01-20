use super::{Error, KernelInterface};

use std::net::{IpAddr};
use eui48::MacAddress;

impl KernelInterface {
    pub fn start_flow_counter_linux(
        &mut self,
        source_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_flow_counter_linux(source_neighbor, destination)?;
        self.run_command(
            "ebtables",
            &[
                "-A",
                "INPUT",
                "-s",
                &format!("{}", source_neighbor.to_hex_string()),
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
