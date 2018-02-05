use super::{Error, KernelInterface};

use std::net::{IpAddr};
use eui48::MacAddress;

impl KernelInterface {
    pub fn start_flow_counter_linux(
        &mut self,
        source_neighbor: MacAddress,
        destination: IpAddr,
    ) -> Result<(), Error> {
        let ctr = self.read_flow_counters(false)?;
        let mut exists = false;
        for (mac, ip, _) in ctr {
            if (mac == source_neighbor) && (ip == destination) {
                exists = true;
            }
        }
        trace!("rule exists: {:?}", exists);
        if !exists {
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
        }
        Ok(())
    }
}
