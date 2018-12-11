use super::KernelInterface;

use std::net::IpAddr;

use failure::Error;

pub enum IpRoute {
    /// For creating default routes
    DefaultRoute,
    /// A route to a specific address
    ToAddr(IpAddr),
}

impl ToString for IpRoute {
    fn to_string(&self) -> String {
        match *self {
            IpRoute::DefaultRoute => "default".into(),
            IpRoute::ToAddr(addr) => addr.to_string(),
        }
    }
}

impl dyn KernelInterface {
    pub fn get_default_route(&self) -> Option<Vec<String>> {
        let output = self
            .run_command("ip", &["route", "list", "default"])
            .unwrap();

        let stdout = String::from_utf8(output.stdout).unwrap();

        // Get the first line that starts with "default", and
        // convert token separated by whitespace into a valid
        // result of type Vec<String>. Otherwise returns
        // None if it couldn't be found.
        Some(
            stdout
                .lines()
                .filter(|line| line.starts_with("default"))
                .nth(0)?
                .split_whitespace() // Extract first
                .map(|s| s.to_string())
                .collect(),
        )
    }

    fn set_route(&self, to: &IpRoute, route: &Vec<String>) -> Result<(), Error> {
        let to = to.to_string();
        let mut def_route = vec!["route", "add", &to];

        let tokens = route.iter().skip(1);
        def_route.reserve_exact(tokens.len());
        for token in tokens {
            def_route.push(&token);
        }
        self.run_command("ip", &def_route)?;
        Ok(())
    }

    pub fn update_settings_route(
        &self,
        settings_default_route: &mut Vec<String>,
    ) -> Result<(), Error> {
        let def_route = match self.get_default_route() {
            Some(route) => route,
            None => return Ok(()),
        };

        if !def_route.contains(&String::from("wg_exit")) {
            // update the default route if default route is not wg exit
            *settings_default_route = def_route.clone();
        }
        Ok(())
    }

    pub fn manual_peers_route(
        &self,
        endpoint_ip: &IpAddr,
        settings_default_route: &mut Vec<String>,
    ) -> Result<(), Error> {
        self.update_settings_route(settings_default_route)?;

        self.set_route(&IpRoute::ToAddr(*endpoint_ip), &settings_default_route)?;
        Ok(())
    }

    pub fn restore_default_route(
        &self,
        settings_default_route: &mut Vec<String>,
    ) -> Result<(), Error> {
        match self.get_default_route() {
            Some(route) => {
                if route.contains(&String::from("wg_exit")) {
                    self.set_route(&IpRoute::DefaultRoute, settings_default_route)?;
                } else {
                    *settings_default_route = route;
                }
            }
            None => {
                self.set_route(&IpRoute::DefaultRoute, settings_default_route)?;
            }
        };
        Ok(())
    }
}

#[test]
fn test_get_default_route_invalid() {
    use crate::KI;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    let mut counter = 0;

    // This will mock `run_command` to run a real output of `ip route`
    // with addition that there are additional spaces, more than one default
    // route etc.
    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ip");
                assert_eq!(args, vec!["route", "list", "default"]);
                Ok(Output {
                    stdout: b"1.2.3.4/16 dev interface scope link metric 1000".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));

    assert!(
        KI.get_default_route().is_none(),
        "Invalid `ip route` unexpectedly returned a valid route"
    );
}

#[test]
fn test_get_default_route() {
    use crate::KI;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    let mut counter = 0;

    // This will mock `run_command` to run a real output of `ip route`
    // with addition that there are additional spaces, more than one default
    // route etc.
    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ip");
                assert_eq!(args, vec!["route", "list", "default"]);
                Ok(Output {
                    stdout: b"
169.254.0.0/16 dev wifiinterface scope link metric 1000
172.16.82.0/24   dev vmnet1 proto kernel scope link src 172.16.82.1
default   via   192.168.8.1   dev wifiinterface proto dhcp   metric 600
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
192.168.8.0/24 dev wifiinterface proto kernel scope link src 192.168.8.175 metric 600
default via 192.168.9.1 dev wifiinterface proto dhcp metric 1200
192.168.36.0/24 dev vmnet8 proto kernel scope link src 192.168.36.1"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));

    let result = KI.get_default_route().expect("Unable to get default route");
    assert_eq!(
        result,
        vec![
            "default",
            "via",
            "192.168.8.1",
            "dev",
            "wifiinterface",
            "proto",
            "dhcp",
            "metric",
            "600",
        ]
    );
}

#[test]
fn test_set_route() {
    use crate::KI;
    use std::net::Ipv4Addr;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ip");
                assert_eq!(args, vec!["route", "add", "127.0.0.1", "token2", "token3"]);

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));

    KI.set_route(
        &IpRoute::ToAddr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        &vec!["token1".into(), "token2".into(), "token3".into()],
    )
    .expect("Unable to set route");
}

#[test]
fn test_set_default_route() {
    use crate::KI;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ip");
                assert_eq!(args, vec!["route", "add", "default"]);

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));

    KI.set_route(&IpRoute::DefaultRoute, &vec![])
        .expect("Unable to set default route");
}
