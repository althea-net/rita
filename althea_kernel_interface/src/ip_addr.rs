use crate::hardware_info::maybe_get_single_line_string;
use crate::open_tunnel::is_link_local;
use crate::KernelInterface;
use crate::KernelInterfaceError as Error;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::net::Ipv4Addr;

impl dyn KernelInterface {
    /// Returns a bool based on device state, "UP" or "DOWN", "UNKNOWN" is
    /// interpreted as DOWN
    pub fn is_iface_up(&self, dev: &str) -> Option<bool> {
        let path = format!("/sys/class/net/{dev}");
        if let Some(is_up) = maybe_get_single_line_string(&format!("{path}/operstate")) {
            let is_up = is_up.contains("up");
            Some(is_up)
        } else {
            None
        }
    }

    /// Adds an ipv4 address to a given interface, true is returned when
    /// the ip is added, false if it is already there and Error if the interface
    /// does not exist or some other error has occured
    pub fn add_ipv4(&self, ip: Ipv4Addr, dev: &str) -> Result<bool, Error> {
        // upwrap here because it's ok if we panic when the system does not have 'ip' installed
        let output = self
            .run_command("ip", &["addr", "add", &format!("{ip}/32"), "dev", dev])
            .unwrap();
        // Get the first line, check if it has "file exists"
        match String::from_utf8(output.stderr) {
            Ok(stdout) => match stdout.lines().next() {
                Some(line) => {
                    if line.contains("File exists") {
                        Ok(false)
                    } else {
                        Err(Error::RuntimeError(format!("Error setting ip {line}")))
                    }
                }
                None => Ok(true),
            },
            Err(e) => Err(Error::RuntimeError(format!(
                "Could not decode stderr from ip with {e:?}"
            ))),
        }
    }

    /// After receiving an ipv6 addr from the exit, this function adds that ip
    /// to br-lan SLAAC takes this ip and assigns a /64 to hosts that connect
    /// to the router
    pub fn setup_ipv6_slaac(&self, router_ipv6_str: IpNetwork) {
        // Get all the v6 addrs on interface
        let v6_addrs = match self.get_ipv6_from_iface("br-lan") {
            Ok(a) => {
                trace!("Our ip list on brlan looks like {:?}", a);
                a
            }
            Err(e) => {
                error!("IPV6 ERROR: Unable to parse ips from interface br-lan, didnt not setup slaac: {:?}", e);
                return;
            }
        };

        for (addr, netmask) in v6_addrs {
            let net = IpNetwork::new(IpAddr::V6(addr), netmask)
                .expect("Why did we get an invalid addr from kernel?");
            // slaac addr is already set
            if net == router_ipv6_str {
                return;
            }

            // Remove all previously set ipv6 addrs
            if !is_link_local(IpAddr::V6(addr)) {
                if let Err(e) =
                    self.run_command("ip", &["addr", "del", &net.to_string(), "dev", "br-lan"])
                {
                    error!(
                        "IPV6 Error: Why are not able to delete the addr {:?} Error {:?}",
                        net, e
                    );
                }
            }
        }

        // Add the new ipv6 addr
        if let Err(e) = self.run_command(
            "ip",
            &["addr", "add", &router_ipv6_str.to_string(), "dev", "br-lan"],
        ) {
            error!(
                "IPV6 ERROR: WHy are we unalbe to add the new subnet {:?} Error: {:?}",
                router_ipv6_str, e
            );
        }
    }

    /// Adds an ipv4 address to a given interface, true is returned when
    /// the ip is added, false if it is already there and Error if the interface
    /// does not exist or some other error has occured
    pub fn add_ipv4_mask(&self, ip: Ipv4Addr, mask: u32, dev: &str) -> Result<bool, Error> {
        // upwrap here because it's ok if we panic when the system does not have 'ip' installed
        let output = self
            .run_command("ip", &["addr", "add", &format!("{ip}/{mask}"), "dev", dev])
            .unwrap();
        // Get the first line, check if it has "file exists"
        match String::from_utf8(output.stderr) {
            Ok(stdout) => match stdout.lines().next() {
                Some(line) => {
                    if line.contains("File exists") {
                        Ok(false)
                    } else {
                        Err(Error::RuntimeError(format!("Error setting ip {line}")))
                    }
                }
                None => Ok(true),
            },
            Err(e) => Err(Error::RuntimeError(format!(
                "Could not decode stderr from ip with {e:?}"
            ))),
        }
    }
}

#[test]
fn test_add_ipv4() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "add", "192.168.31.2/32", "dev", "eth0"]);

        Ok(Output {
            stdout: b"".to_vec(),
            stderr: b"RTNETLINK answers: File exists".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));
    let val = KI
        .add_ipv4("192.168.31.2".parse().unwrap(), "eth0")
        .expect("Failure to run ip test");
    assert!(!val);

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "add", "192.168.31.2/32", "dev", "eth0"]);

        Ok(Output {
            stdout: b"".to_vec(),
            stderr: b"Cannot find device \"eth0\"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));
    let val = KI.add_ipv4("192.168.31.2".parse().unwrap(), "eth0");
    assert!(val.is_err());

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        assert_eq!(args, &["addr", "add", "192.168.31.2/32", "dev", "eth0"]);

        Ok(Output {
            stdout: b"".to_vec(),
            stderr: b"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));
    let val = KI
        .add_ipv4("192.168.31.2".parse().unwrap(), "eth0")
        .expect("Failure to run ip test");
    assert!(val);
}
