use super::{KernelInterface, Error};

use std::net::{IpAddr};

use eui48::MacAddress;

impl KernelInterface {
    pub fn delete_destination_counter_linux(
        &mut self,
        des_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_ebtables_rule(&[
            "-D",
            "OUTPUT",
            "-d",
            &format!("{}", des_neighbor.to_hex_string()),
            "-p",
            "IPV6",
            "--ip6-dst",
            &format!("{}", destination),
            "-j",
            "ACCEPT",
        ])
    }
}