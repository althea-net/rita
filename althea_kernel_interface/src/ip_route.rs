use crate::KernelInterface;
use crate::KernelInterfaceError as Error;
use althea_types::FromStr;
use std::fmt::Display;
use std::fmt::Write as _;
use std::net::IpAddr;

/// Stores a default route of the format
/// proto must be a value in /etc/iproute2/rt_protos but we always
/// want to set 'static' so that our routes don't get messed with
/// ip route default via <ip> dev <nic> proto <proto> <tokens>
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DefaultRoute {
    pub via: IpAddr,
    pub nic: String,
    pub proto: Option<String>,
    pub src: Option<IpAddr>,
    pub metric: Option<u16>,
}

impl DefaultRoute {
    pub fn is_althea_default_route(&self) -> bool {
        self.nic.to_lowercase().contains("wg_exit")
    }
}
/// A route to a specific address in the format
/// proto must be a value in /etc/iproute2/rt_protos but we always
/// want to set 'static' so that our routes don't get messed with
/// ip route <dst> via <ip> dev <nic> proto <proto> <tokens>
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToSubnet {
    pub dst: IpAddr,
    pub subnet: u16,
    pub via: Option<IpAddr>,
    pub nic: String,
    pub proto: Option<String>,
    pub src: Option<IpAddr>,
    pub metric: Option<u16>,
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IpRoute {
    DefaultRoute(DefaultRoute),
    ToSubnet(ToSubnet),
}

impl IpRoute {
    pub fn is_althea_default_route(&self) -> bool {
        if let IpRoute::DefaultRoute(DefaultRoute { nic, .. }) = self {
            nic.to_lowercase().contains("wg_exit")
        } else {
            false
        }
    }
}

/// this function gets a given 'tag' from a list of strings
/// for example ["a", "b", "c", "d"] if you called get_item(list, "a")
/// you would get back "b"
fn get_item(list: &[&str], item: &str) -> Option<String> {
    let mut iter = list.iter();
    while let Some(value) = iter.next() {
        if value.to_lowercase().contains(&item.to_lowercase()) {
            match iter.next() {
                Some(val) => return Some(val.to_string()),
                None => return None,
            }
        }
    }
    None
}

fn get_and_parse_item<T: FromStr>(list: &[&str], item: &str) -> Option<T>
where
    <T as FromStr>::Err: 'static,
    <T as althea_types::FromStr>::Err: std::fmt::Debug,
{
    match get_item(list, item) {
        Some(string_val) => match string_val.parse() {
            Ok(parsed_val) => Some(parsed_val),
            Err(e) => {
                warn!("Error parsing {} from {:?} with {:?}", item, list, e);
                None
            }
        },
        None => None,
    }
}

impl FromStr for IpRoute {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let tokens = s.split_whitespace();
        if tokens.clone().count() == 0 {
            Err(Error::EmptyRouteString)
        } else {
            let mut t = tokens.clone();
            let list: Vec<&str> = tokens.collect();
            if t.any(|a| a.to_lowercase().contains("default")) {
                let via = get_item(&list, "via");
                let nic = get_item(&list, "dev");
                let proto = get_item(&list, "proto");
                let src = get_and_parse_item(&list, "src");
                let metric = get_and_parse_item(&list, "metric");
                if let (Some(via), Some(nic)) = (via, nic) {
                    Ok(IpRoute::DefaultRoute(DefaultRoute {
                        via: via.parse()?,
                        nic,
                        proto,
                        metric,
                        src,
                    }))
                } else {
                    Err(Error::InvalidRouteString(format!(
                        "{s} does not contain via, nic",
                    )))
                }
            } else {
                let addr_and_subnet: Vec<&str> = list[0].split('/').collect();
                let dst = addr_and_subnet[0].parse()?;
                let subnet = if let Some(subnet) = addr_and_subnet.get(1) {
                    subnet.parse()?
                } else {
                    32
                };
                let via = get_and_parse_item(&list, "via");
                let nic = get_item(&list, "dev");
                let proto = get_item(&list, "proto");
                let scope = get_item(&list, "scope");
                let src = get_and_parse_item(&list, "src");
                let metric = get_and_parse_item(&list, "metric");
                if let Some(nic) = nic {
                    Ok(IpRoute::ToSubnet(ToSubnet {
                        dst,
                        subnet,
                        via,
                        nic,
                        proto,
                        src,
                        metric,
                        scope,
                    }))
                } else {
                    Err(Error::InvalidRouteString(format!(
                        "{s} does not contain nic",
                    )))
                }
            }
        }
    }
}

impl Display for IpRoute {
    /// Converts this route object into a string that is a ready-to-run command
    /// for applying this route, once appended 'ip route add'
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.clone() {
            IpRoute::DefaultRoute(DefaultRoute { via, nic, src, .. }) => {
                if let Some(src) = src {
                    write!(f, "default via {via} dev {nic} proto static src {src}")
                } else {
                    write!(f, "default via {via} dev {nic} proto static")
                }
            }

            IpRoute::ToSubnet(ToSubnet {
                dst,
                subnet,
                via,
                nic,
                src,
                ..
            }) => {
                let mut out = if subnet == 32 {
                    format!("{dst} ")
                } else {
                    format!("{dst}/{subnet} ")
                };
                if let Some(via) = via {
                    write!(out, " via {via} ").unwrap();
                }
                write!(out, " dev {nic} proto static ").unwrap();
                if let Some(src) = src {
                    write!(out, " src {src} ").unwrap();
                }
                write!(f, "{}", out)
            }
        }
    }
}

impl dyn KernelInterface {
    /// Gets the default route, returns Error if the command fails and None
    /// if no default route is set
    pub fn get_default_route(&self) -> Result<Option<DefaultRoute>, Error> {
        let output = self.run_command("ip", &["route", "list", "default"])?;

        let stdout = String::from_utf8(output.stdout).unwrap();
        // return the first valid default route that correctly parses into a route
        // there can be multiple default routes with different metrics but ip is kind
        // enough to always put the lowest metric (aka the 'best' one) to the top
        for line in stdout.lines() {
            match line.parse() {
                Ok(route) => {
                    if let IpRoute::DefaultRoute(r) = route {
                        return Ok(Some(r));
                    }
                }
                Err(e) => error!("Failed to parse route! {:?}", e),
            }
        }
        Ok(None)
    }

    pub fn set_route(&self, to: &IpRoute) -> Result<(), Error> {
        let to = to.to_string();
        let to: Vec<&str> = to.split_whitespace().collect();
        let mut def_route = vec!["route", "add"];
        def_route.extend(to);
        self.run_command("ip", &def_route)?;
        Ok(())
    }

    /// Updates the settings default route, returns true if an edit to the settings has been performed
    pub fn update_settings_route(
        &self,
        settings_default_route: &mut Option<DefaultRoute>,
    ) -> Result<bool, Error> {
        let def_route = match self.get_default_route()? {
            Some(route) => route,
            None => return Ok(false),
        };
        if !def_route.is_althea_default_route() {
            // update the default route if default route is not wg exit
            *settings_default_route = Some(def_route);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// sets the manual route for a peer using ip route, returns true if the settings
    /// have been updated
    pub fn manual_peers_route(
        &self,
        endpoint_ip: &IpAddr,
        settings_default_route: &mut Option<DefaultRoute>,
    ) -> Result<bool, Error> {
        let changed = self.update_settings_route(settings_default_route)?;
        match settings_default_route {
            Some(d) => {
                self.set_route(&IpRoute::ToSubnet(ToSubnet {
                    dst: *endpoint_ip,
                    subnet: 32,
                    via: Some(d.via),
                    nic: d.nic.to_string(),
                    proto: Some("static".to_string()),
                    metric: None,
                    src: None,
                    scope: None,
                }))?;
                Ok(changed)
            }
            // no default route, nothing to do
            None => Ok(changed),
        }
    }

    /// restore the default route, if we find a default route is already in place that is not
    /// our wg_exit route we grab that one, save it off, and make no changes.
    pub fn restore_default_route(
        &self,
        settings_default_route: &mut Option<DefaultRoute>,
    ) -> Result<(), Error> {
        let current_route = self.get_default_route()?;
        match current_route.clone() {
            Some(d) => {
                if d.is_althea_default_route() {
                    // if we didn't have a default route already it's restored by default
                    if let Some(route) = settings_default_route {
                        self.set_route(&IpRoute::DefaultRoute(route.clone()))?;
                    }
                } else {
                    *settings_default_route = Some(current_route.unwrap());
                }
            }
            None => {
                // if we didn't have a default route already it's restored by default
                if let Some(route) = settings_default_route {
                    self.set_route(&IpRoute::DefaultRoute(route.clone()))?;
                }
            }
        };
        Ok(())
    }
}

#[test]
//"default", "via", "64.146.145.5", "dev", "eth0", "proto", "static", "linkdown"
fn test_get_default_route_invalid() {
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
        KI.get_default_route().unwrap().is_none(),
        "Invalid `ip route` unexpectedly returned a valid route"
    );
}

#[test]
fn test_parse_routes() {
    let route_strings = vec![
        "169.254.0.0/16 dev wifiinterface scope link metric 1000",
        "172.16.82.0/24   dev vmnet1 proto kernel scope link src 172.16.82.1",
        "default   via   192.168.8.1   dev wifiinterface proto dhcp   metric 600",
        "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown",
        "192.168.8.0/24 dev wifiinterface proto kernel scope link src 192.168.8.175 metric 600",
        "default via 192.168.9.1 dev wifiinterface proto dhcp metric 1200",
        "192.168.36.0/24 dev vmnet8 proto kernel scope link src 192.168.36.1",
        "64.136.143.4/30 dev eth0 proto kernel  scope link src 64.246.135.6",
    ];
    for route in route_strings {
        let _route: IpRoute = route.parse().unwrap();
    }
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

    let result = KI
        .get_default_route()
        .expect("Unable to get default route")
        .unwrap();
    let correct = DefaultRoute {
        via: "192.168.8.1".parse().unwrap(),
        nic: "wifiinterface".to_string(),
        proto: Some("dhcp".to_string()),
        metric: Some(600),
        src: None,
    };
    assert_eq!(result, correct);
}

#[test]
fn test_set_route() {
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
                assert_eq!(
                    args,
                    vec![
                        "route",
                        "add",
                        "127.0.0.1",
                        "via",
                        "127.0.0.2",
                        "dev",
                        "eno3p",
                        "proto",
                        "static"
                    ]
                );

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            2 => {
                assert_eq!(program, "ip");
                assert_eq!(
                    args,
                    vec![
                        "route",
                        "add",
                        "127.0.0.1",
                        "via",
                        "127.0.0.2",
                        "dev",
                        "eno3p",
                        "proto",
                        "static"
                    ]
                );

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            3 => {
                assert_eq!(program, "ip");
                assert_eq!(
                    args,
                    vec![
                        "route",
                        "add",
                        "127.0.0.1/24",
                        "dev",
                        "eno3p",
                        "proto",
                        "static"
                    ]
                );

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            4 => {
                assert_eq!(program, "ip");
                assert_eq!(
                    args,
                    vec![
                        "route",
                        "add",
                        "127.0.0.1/24",
                        "via",
                        "127.0.0.2",
                        "dev",
                        "eno3p",
                        "proto",
                        "static",
                        "src",
                        "127.0.0.2"
                    ]
                );

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));

    // as it would be normally parsed
    let route = IpRoute::ToSubnet(ToSubnet {
        dst: "127.0.0.1".parse().unwrap(),
        subnet: 32,
        via: Some("127.0.0.2".parse().unwrap()),
        nic: "eno3p".to_string(),
        proto: Some("static".to_string()),
        src: None,
        metric: None,
        scope: None,
    });
    // without proto we insert proto static to prevent other
    // programs from messing with our routes so it should still be there
    KI.set_route(&route).expect("Unable to set route");
    let route = IpRoute::ToSubnet(ToSubnet {
        dst: "127.0.0.1".parse().unwrap(),
        subnet: 32,
        via: Some("127.0.0.2".parse().unwrap()),
        nic: "eno3p".to_string(),
        proto: None,
        src: None,
        metric: None,
        scope: None,
    });
    KI.set_route(&route).expect("Unable to set route");
    // without via, with subnet
    let route = IpRoute::ToSubnet(ToSubnet {
        dst: "127.0.0.1".parse().unwrap(),
        subnet: 24,
        via: None,
        nic: "eno3p".to_string(),
        proto: None,
        src: None,
        metric: None,
        scope: None,
    });
    KI.set_route(&route).expect("Unable to set route");
    // without via, with subnet with other options
    let route = IpRoute::ToSubnet(ToSubnet {
        dst: "127.0.0.1".parse().unwrap(),
        subnet: 24,
        via: Some("127.0.0.2".parse().unwrap()),
        nic: "eno3p".to_string(),
        // intentionally bogus
        proto: Some("link".to_string()),
        src: Some("127.0.0.2".parse().unwrap()),
        metric: Some(7777),
        // will be ignored
        scope: Some("link".to_string()),
    });
    KI.set_route(&route).expect("Unable to set route");
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
                assert_eq!(
                    args,
                    vec![
                        "route",
                        "add",
                        "default",
                        "via",
                        "192.168.8.1",
                        "dev",
                        "wifiinterface",
                        "proto",
                        "static"
                    ]
                );

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            2 => {
                assert_eq!(program, "ip");
                assert_eq!(
                    args,
                    vec![
                        "route",
                        "add",
                        "default",
                        "via",
                        "192.168.8.1",
                        "dev",
                        "wifiinterface",
                        "proto",
                        "static",
                        "src",
                        "127.0.0.2"
                    ]
                );

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));
    let correct = IpRoute::DefaultRoute(DefaultRoute {
        via: "192.168.8.1".parse().unwrap(),
        nic: "wifiinterface".to_string(),
        proto: Some("dhcp".to_string()),
        metric: Some(600),
        src: None,
    });

    KI.set_route(&correct).expect("Unable to set default route");

    let correct = IpRoute::DefaultRoute(DefaultRoute {
        via: "192.168.8.1".parse().unwrap(),
        nic: "wifiinterface".to_string(),
        proto: Some("bogus".to_string()),
        metric: Some(600),
        src: Some("127.0.0.2".parse().unwrap()),
    });

    KI.set_route(&correct).expect("Unable to set default route");
}
