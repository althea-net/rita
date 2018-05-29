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

        let mut found = false;

        // find all lines
        for i in stdout.lines() {
            // starting with default
            if i.starts_with("default") {
                for j in i.split_whitespace() {
                    if j.len() != 0 {
                        def_route.push(String::from(j));
                    }
                }
                found = true;
                break;
            }
        }

        if found {
            Some(def_route)
        } else {
            None
        }
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
        let mut def_route_ref: Vec<&str> = vec!["route", "add"];

        def_route_ref.push("default");

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
        };
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
