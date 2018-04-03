use super::{KernelInterface, KernelManagerError};

use std::net::IpAddr;

use regex::Regex;

use failure::Error;

impl KernelInterface {
    /// Returns all existing interfaces
    pub fn get_interfaces(&self) -> Result<Vec<String>, Error> {
        let links = String::from_utf8(self.run_command("ip", &["link"])?.stdout)?;

        let mut vec = Vec::new();
        let re = Regex::new(r"[0-9]+: (.*?)(:|@)").unwrap();
        for caps in re.captures_iter(&links) {
            vec.push(String::from(&caps[1]));
        }

        trace!("interfaces: {:?}", vec);
        Ok(vec)
    }

    /// Deletes an named interface
    pub fn del_interface(&self, name: &str) -> Result<(), Error> {
        self.run_command("ip", &["link", "del", "dev", name])?;
        Ok(())
    }
}

#[test]
fn test_get_interfaces_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(|program, args| {
            assert_eq!(program, "ip");
            assert_eq!(args, &["link"]);

            Ok(Output {
                stdout: b"
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: dummy: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 22:8a:b6:9e:2d:1e brd ff:ff:ff:ff:ff:ff
3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/none
2843: veth-1-6@if2842: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc netem state UP mode DEFAULT group default qlen 1000
    link/ether 76:d1:f5:3d:32:53 brd ff:ff:ff:ff:ff:ff link-netnsid 1"
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        })),
    };

    let interfaces = ki.get_interfaces().unwrap();

    assert_eq!(format!("{}", interfaces[0]), "lo");
    assert_eq!(format!("{}", interfaces[1]), "dummy");
    assert_eq!(format!("{}", interfaces[2]), "wg0");
    assert_eq!(format!("{}", interfaces[3]), "veth-1-6");
}
