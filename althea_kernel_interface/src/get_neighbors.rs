use super::{KernelInterface, KernelManagerError};

use std::net::IpAddr;
use std::str::FromStr;

use eui48::MacAddress;
use regex::Regex;

use failure::Error;

impl KernelInterface {
    /// Returns a vector of neighbors reachable over layer 2, giving IP address of each.
    /// Implemented with `ip neighbor` on Linux.
    pub fn get_neighbors(&self) -> Result<Vec<(IpAddr, String)>, Error> {
        let output = self.run_command("ip", &["neighbor"])?;
        trace!("Got {:?} from `ip neighbor`", output);

        let mut vec = Vec::new();
        let re = Regex::new(r"(\S*).*dev (\S*).*lladdr (\S*).*(REACHABLE|STALE|DELAY)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            trace!("Regex captured {:?}", caps);

            vec.push((
                IpAddr::from_str(&caps[1])?,
                caps[2].to_string(),
            ));
        }
        trace!("Got neighbors {:?}", vec);
        Ok(vec)
    }

    pub fn trigger_neighbor_disc(&self) -> Result<(), Error> {
        for interface in self.get_interfaces()? {
            self.run_command("ping6", &["-c1", "-I", &interface, "ff02::1"])?;
        }
        Ok(())
    }
}

#[test]
fn test_get_neighbors_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(|program, args| {
            assert_eq!(program, "ip");
            assert_eq!(args, &["neighbor"]);

            Ok(Output {
                stdout: b"10.0.2.2 dev eth0 lladdr 00:00:00:aa:00:03 STALE
10.0.0.2 dev eth0  FAILED
10.0.1.2 dev eth0 lladdr 00:00:00:aa:00:05 REACHABLE
2001::2 dev eth0 lladdr 00:00:00:aa:00:56 REACHABLE
fe80::7459:8eff:fe98:81 dev eth0 lladdr 76:59:8e:98:00:81 STALE
fe80::433:25ff:fe8c:e1ea dev eth0 lladdr 1a:32:06:78:05:0a STALE
2001::2 dev eth0  FAILED"
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        })),
    };

    let addresses = ki.get_neighbors().unwrap();

    assert_eq!(format!("{}", addresses[0].0), "00-00-00-aa-00-03");
    assert_eq!(format!("{}", addresses[0].1), "10.0.2.2");
    assert_eq!(format!("{}", addresses[0].2), "eth0");

    assert_eq!(format!("{}", addresses[1].0), "00-00-00-aa-00-05");
    assert_eq!(format!("{}", addresses[1].1), "10.0.1.2");
    assert_eq!(format!("{}", addresses[1].2), "eth0");

    assert_eq!(format!("{}", addresses[2].0), "00-00-00-aa-00-56");
    assert_eq!(format!("{}", addresses[2].1), "2001::2");
    assert_eq!(format!("{}", addresses[2].2), "eth0");
}
