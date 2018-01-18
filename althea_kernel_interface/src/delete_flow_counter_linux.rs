use super::{KernelInterface, Error};

use std::net::{IpAddr};

use eui48::MacAddress;

impl KernelInterface {
    pub fn delete_flow_counter_linux(
        &mut self,
        source_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_ebtables_rule(&[
            "-D",
            "INPUT",
            "-s",
            &format!("{}", source_neighbor.to_hex_string()),
            "-p",
            "IPV6",
            "--ip6-dst",
            &format!("{}", destination),
            "-j",
            "CONTINUE",
        ])
    }
}