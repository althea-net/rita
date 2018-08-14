use super::KernelInterface;

use std::net::IpAddr;

use failure::Error;

impl KernelInterface {
    fn get_default_route(&self) -> Option<Vec<String>> {
        let output = self
            .run_command("ip", &["route", "list", "default"])
            .unwrap();

        let stdout = String::from_utf8(output.stdout).unwrap();

        let mut def_route = Vec::new();

        // find all lines
        for i in stdout.lines() {
            // starting with default
            if i.starts_with("default") {
                for j in i.split_whitespace() {
                    if j.len() != 0 {
                        def_route.push(String::from(j));
                    }
                }
                return Some(def_route);
            }
        }

        None
    }

    fn set_route(&self, to: &IpAddr, route: &Vec<String>) -> Result<(), Error> {
        let to = to.to_string();

        let mut def_route_ref: Vec<&str> = vec!["route", "add"];

        def_route_ref.push(to.as_str());

        for i in 1..route.len() {
            def_route_ref.push(route[i].as_str())
        }

        self.run_command("ip", &def_route_ref[..])?;
        Ok(())
    }

    fn set_default_route(&self, route: &Vec<String>) -> Result<(), Error> {
        let mut def_route_ref: Vec<&str> = vec!["route", "add", "default"];

        for i in 1..route.len() {
            def_route_ref.push(route[i].as_str())
        }

        self.run_command("ip", &def_route_ref[..])?;
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

        self.set_route(&endpoint_ip, settings_default_route)?;
        Ok(())
    }

    pub fn restore_default_route(
        &self,
        settings_default_route: &mut Vec<String>,
    ) -> Result<(), Error> {
        match self.get_default_route() {
            Some(route) => {
                if route.contains(&String::from("wg_exit")) {
                    self.set_default_route(settings_default_route)?;
                } else {
                    *settings_default_route = route;
                }
            }
            None => {
                self.set_default_route(settings_default_route)?;
            }
        };
        Ok(())
    }
}

#[test]
fn test_get_default_route() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    use KI;
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
            "600"
        ]
    );
}
