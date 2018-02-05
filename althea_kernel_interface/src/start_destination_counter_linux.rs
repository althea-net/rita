use super::{Error, KernelInterface};

use std::net::{IpAddr};

use eui48::MacAddress;

impl KernelInterface {
    pub fn start_destination_counter_linux(
        &mut self,
        des_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        let ctr = self.read_destination_counters(false)?;
        let mut exists = false;
        for (mac, ip, _) in ctr {
            if (mac == des_neighbor) && (ip == destination) {
                exists = true;
            }
        }
        trace!("rule exists: {:?}", exists);
        if !exists {
            self.run_command(
                "ebtables",
                &[
                    "-A",
                    "OUTPUT",
                    "-d",
                    &format!("{}", des_neighbor.to_hex_string()),
                    "-p",
                    "IPV6",
                    "--ip6-dst",
                    &format!("{}", destination),
                    "-j",
                    "ACCEPT",
                ],
            )?;
        }
        Ok(())
    }
}
