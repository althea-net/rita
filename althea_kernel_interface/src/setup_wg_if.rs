use super::{KernelInterface, KernelInterfaceError};
use std::str::from_utf8;

use failure::Error;

impl KernelInterface {
    pub fn get_peers(&self, iface_name: &str) -> Result<Vec<String>, Error> {
        let output = self.run_command("wg", &["show", iface_name, "peers"])?;

        let output = from_utf8(&output.stdout)?;

        let mut peers = Vec::new();

        for l in output.lines() {
            peers.push(l.to_string());
        }

        Ok(peers)
    }

    /// checks the existing interfaces to find an interface name that isn't in use.
    /// then calls iproute2 to set up a new interface.
    pub fn setup_wg_if(&self) -> Result<String, Error> {
        //call "ip links" to get a list of currently set up links
        let links = String::from_utf8(self.run_command("ip", &["link"])?.stdout)?;
        let mut if_num = 0;
        //loop through the output of "ip links" until we find a wg suffix that isn't taken (e.g. "wg3")
        while links.contains(format!("wg{}", if_num).as_str()) {
            if_num += 1;
        }
        let interface = format!("wg{}", if_num);
        self.setup_wg_if_named(&interface)?;
        Ok(interface)
    }

    /// calls iproute2 to set up a new interface with a given name.
    pub fn setup_wg_if_named(&self, name: &str) -> Result<(), Error> {
        let output = self.run_command("ip", &["link", "add", &name, "type", "wireguard"])?;
        let stderr = String::from_utf8(output.stderr)?;
        if !stderr.is_empty() {
            if stderr.contains("exists") {
                return Ok(());
            } else {
                return Err(KernelInterfaceError::RuntimeError(format!(
                    "received error adding wg link: {}",
                    stderr
                )).into());
            }
        }
        Ok(())
    }
}

#[test]
fn test_setup_wg_if_linux() {
    use KI;

    KI.test_commands(
        "test_setup_wg_if_linux",
        &[
            (
                "ip link",
                "82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000",
            ),
            ("ip link add wg1 type wireguard", ""),
        ],
    );

    KI.setup_wg_if().unwrap();
}
