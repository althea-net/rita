use super::{KernelInterface, Error};

use std::net::{IpAddr};

impl KernelInterface {
    pub fn delete_destination_counter_linux(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_ebtables_rule(&[
            "-D",
            "OUTPUT",
            "-p",
            "IPV6",
            "--ip6-dst",
            &format!("{}", destination),
            "-j",
            "CONTINUE",
        ])
    }

}