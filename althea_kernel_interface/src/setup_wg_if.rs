use super::{KernelInterface, KernelInterfaceError};

use std::net::IpAddr;

use failure::Error;

impl KernelInterface {
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
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error adding wg link: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(())
    }
}

#[test]
fn test_setup_wg_if_linux() {
    use KI;

    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    let link_args = &["link"];
    let link_add = &["link", "add", "wg1", "type", "wireguard"];
    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        counter += 1;

        match counter {
            1 => {
                assert_eq!(args, link_args);
                Ok(Output{
                        stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            2 => {
                assert_eq!(args, link_add);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("command called too many times"),
        }
    }));

    KI.setup_wg_if().unwrap();
}
