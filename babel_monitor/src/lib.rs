#[macro_use]
extern crate failure;

#[macro_use]
extern crate log;

use std::collections::VecDeque;
use std::io::{BufRead, Read, Write};
use std::iter::Iterator;
use std::net::IpAddr;
use std::str;

use bufstream::BufStream;
use failure::Error;
use ipnetwork::IpNetwork;

#[derive(Debug, Fail)]
pub enum BabelMonitorError {
    #[fail(display = "variable '{}' not found in '{}'", _0, _1)]
    VariableNotFound(String, String),
    #[fail(display = "Invalid preamble: {}", _0)]
    InvalidPreamble(String),
    #[fail(display = "Could not find local fee in '{}'", _0)]
    LocalFeeNotFound(String),
    #[fail(display = "Command '{}' failed. {}", _0, _1)]
    CommandFailed(String, String),
    #[fail(display = "Erroneous Babel output:\n{}", _0)]
    ReadFailed(String),
    #[fail(display = "No terminator after Babel output:\n{}", _0)]
    NoTerminator(String),
    #[fail(display = "No Neighbor was found matching address:\n{}", _0)]
    NoNeighbor(String),
}

use crate::BabelMonitorError::*;

// If a function doesn't need internal state of the Babel object
// we don't want to place it as a member function.
fn find_babel_val(val: &str, line: &str) -> Result<String, Error> {
    let mut iter = line.split(" ");
    while let Some(entry) = iter.next() {
        if entry.to_string() == val {
            match iter.next() {
                Some(v) => return Ok(v.to_string()),
                None => continue,
            }
        }
    }
    warn!("find_babel_val warn! Can not find {} in {}", val, line);
    return Err(VariableNotFound(String::from(val), String::from(line)).into());
}

#[derive(Debug, Clone)]
pub struct Route {
    pub id: String,
    pub iface: String,
    pub xroute: bool,
    pub installed: bool,
    pub neigh_ip: IpAddr,
    pub prefix: IpNetwork,
    pub metric: u16,
    pub refmetric: u16,
    pub full_path_rtt: f32,
    pub price: u32,
    pub fee: u32,
}

#[derive(Debug, Clone)]
pub struct Neighbor {
    pub id: String,
    pub address: IpAddr,
    pub iface: String,
    pub reach: u16,
    pub txcost: u16,
    pub rxcost: u16,
    pub rtt: f32,
    pub rttcost: u16,
    pub cost: u16,
}

pub struct Babel<T: Read + Write> {
    stream: BufStream<T>,
}

impl<T: Read + Write> Babel<T> {
    pub fn new(stream: T) -> Babel<T> {
        Babel {
            stream: BufStream::new(stream),
        }
    }

    fn read_babel(&mut self) -> Result<String, Error> {
        let mut ret = String::new();
        for line in Read::by_ref(&mut self.stream).lines() {
            let line = &line?;
            ret.push_str(line);
            ret.push_str("\n");
            match line.as_str().trim() {
                "ok" => {
                    trace!(
                        "Babel returned ok; full output:\n{}\nEND OF BABEL OUTPUT",
                        ret
                    );
                    return Ok(ret);
                }
                "bad" | "no" => {
                    warn!(
                        "Babel returned bad/no; full output:\n{}\nEND OF BABEL OUTPUT",
                        ret
                    );
                    return Err(ReadFailed(ret).into());
                }
                _ => continue,
            }
        }
        warn!(
            "Terminator was never found; full output:\n{:?}\nEND OF BABEL OUTPUT",
            ret
        );
        return Err(NoTerminator(ret).into());
    }

    fn command(&mut self, cmd: &str) -> Result<String, Error> {
        self.stream.write_all(format!("{}\n", cmd).as_bytes())?;
        self.stream.flush()?;

        trace!("Sent '{}' to babel", cmd);
        match self.read_babel() {
            Ok(out) => Ok(out),
            Err(e) => Err(CommandFailed(String::from(cmd), e.to_string()).into()),
        }
    }

    // Consumes the automated Preamble and validates configuration api version
    pub fn start_connection(&mut self) -> Result<(), Error> {
        let preamble = self.read_babel()?;
        // Note you have changed the config interface, bump to 1.1 in babel
        if preamble.contains("ALTHEA 0.1") {
            trace!("Attached OK to Babel with preamble: {}", preamble);
            return Ok(());
        } else {
            return Err(InvalidPreamble(preamble).into());
        }
    }

    pub fn get_local_fee(&mut self) -> Result<u32, Error> {
        let babel_output = self.command("dump")?;
        let fee_entry = match babel_output.split("\n").nth(0) {
            Some(entry) => entry,
            // Even an empty string wouldn't yield None
            None => return Err(LocalFeeNotFound(String::from("<Babel output is None>")).into()),
        };

        if fee_entry.contains("local fee") {
            let fee = find_babel_val("fee", fee_entry)?.parse()?;
            trace!("Retrieved a local fee of {}", fee);
            return Ok(fee);
        }

        Err(LocalFeeNotFound(String::from(fee_entry)).into())
    }

    pub fn set_local_fee(&mut self, new_fee: u32) -> Result<(), Error> {
        let _babel_output = self.command(&format!("fee {}", new_fee))?;
        Ok(())
    }

    pub fn set_metric_factor(&mut self, new_factor: u32) -> Result<(), Error> {
        let _babel_output = self.command(&format!("metric-factor {}", new_factor))?;
        Ok(())
    }

    pub fn monitor(&mut self, iface: &str) -> Result<(), Error> {
        let _ = self.command(&format!(
            "interface {} max-rtt-penalty 500 enable-timestamps true",
            iface
        ))?;
        trace!("Babel started monitoring: {}", iface);
        Ok(())
    }

    pub fn redistribute_ip(&mut self, ip: &IpAddr, allow: bool) -> Result<(), Error> {
        let commmand = format!(
            "redistribute ip {}/128 {}",
            ip,
            if allow { "allow" } else { "deny" }
        );
        self.command(&commmand)?;
        let _ = self.read_babel()?;
        Ok(())
    }

    pub fn unmonitor(&mut self, iface: &str) -> Result<(), Error> {
        self.command(&format!("flush interface {}", iface))?;
        Ok(())
    }

    pub fn parse_neighs(&mut self) -> Result<VecDeque<Neighbor>, Error> {
        let mut vector: VecDeque<Neighbor> = VecDeque::with_capacity(5);
        let mut found_neigh = false;
        for entry in self.command("dump")?.split("\n") {
            if entry.contains("add neighbour") {
                found_neigh = true;
                let neigh = Neighbor {
                    id: match find_babel_val("neighbour", entry) {
                        Ok(val) => val,
                        Err(_) => continue,
                    },
                    address: match find_babel_val("address", entry) {
                        Ok(entry) => match entry.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing address for neigh {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    iface: match find_babel_val("if", entry) {
                        Ok(val) => val,
                        Err(_) => continue,
                    },
                    reach: match find_babel_val("reach", entry) {
                        Ok(val) => match u16::from_str_radix(&val, 16) {
                            Ok(val) => val,
                            Err(e) => {
                                warn!("Failed to convert reach {:?} {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    txcost: match find_babel_val("txcost", entry) {
                        Ok(entry) => match entry.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing txcost for neigh {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    rxcost: match find_babel_val("rxcost", entry) {
                        Ok(entry) => match entry.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing rxcost for neigh {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    rtt: match find_babel_val("rtt", entry) {
                        Ok(entry) => match entry.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing rtt for neigh {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        // it's possible that our neigh does not have rtt enabled, handle
                        Err(_) => 0.0,
                    },
                    rttcost: match find_babel_val("rttcost", entry) {
                        Ok(entry) => match entry.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing rtt for neigh {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        // it's possible that our neigh does not have rtt enabled, handle
                        Err(_) => 0,
                    },
                    cost: match find_babel_val("cost", entry) {
                        Ok(entry) => match entry.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing cost for neigh {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                };
                vector.push_back(neigh);
            }
        }
        if vector.len() == 0 && found_neigh {
            bail!("All Babel neigh parsing failed!")
        }
        Ok(vector)
    }

    pub fn parse_routes(&mut self) -> Result<VecDeque<Route>, Error> {
        let mut vector: VecDeque<Route> = VecDeque::with_capacity(20);
        let babel_out = self.command("dump")?;
        let mut found_route = false;
        trace!("Got from babel dump: {}", babel_out);

        for entry in babel_out.split("\n") {
            if entry.contains("add route") {
                trace!("Parsing 'add route' entry: {}", entry);
                found_route = true;
                let route = Route {
                    id: match find_babel_val("route", entry) {
                        Ok(value) => value,
                        Err(_) => continue,
                    },
                    iface: match find_babel_val("if", entry) {
                        Ok(value) => value,
                        Err(_) => continue,
                    },
                    xroute: false,
                    installed: match find_babel_val("installed", entry) {
                        Ok(value) => value.contains("yes"),
                        Err(_) => continue,
                    },
                    neigh_ip: match find_babel_val("via", entry) {
                        Ok(value) => match value.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing neigh_ip for route {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    prefix: match find_babel_val("prefix", entry) {
                        Ok(value) => match value.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing prefix for route {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    metric: match find_babel_val("metric", entry) {
                        Ok(value) => match value.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing metric for route {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    refmetric: match find_babel_val("refmetric", entry) {
                        Ok(value) => match value.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing refmetric {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    full_path_rtt: match find_babel_val("full-path-rtt", entry) {
                        Ok(value) => match value.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing full_path_rtt {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    price: match find_babel_val("price", entry) {
                        Ok(value) => match value.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing price {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                    fee: match find_babel_val("fee", entry) {
                        Ok(value) => match value.parse() {
                            Ok(parsed_data) => parsed_data,
                            Err(e) => {
                                warn!("Error parsing fee {:?} from {}", e, entry);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    },
                };

                vector.push_back(route);
            }
        }
        if vector.len() == 0 && found_route {
            bail!("All Babel route parsing failed!")
        }
        Ok(vector)
    }

    /// In this function we take a route snapshot then loop over the routes list twice
    /// to find the neighbor local address and then the route to the destination
    /// via that neighbor. This could be dramatically more efficient if we had the neighbors
    /// local ip lying around somewhere.
    pub fn get_route_via_neigh(
        &mut self,
        neigh_mesh_ip: IpAddr,
        dest_mesh_ip: IpAddr,
        routes: &VecDeque<Route>,
    ) -> Result<Route, Error> {
        // First find the neighbors route to itself to get the local address
        for neigh_route in routes.iter() {
            // This will fail on v4 babel routes etc
            if let IpNetwork::V6(ref ip) = neigh_route.prefix {
                if ip.ip() == neigh_mesh_ip {
                    let neigh_local_ip = neigh_route.neigh_ip;
                    // Now we take the neigh_local_ip and search for a route via that
                    for route in routes.iter() {
                        if let IpNetwork::V6(ref ip) = route.prefix {
                            if ip.ip() == dest_mesh_ip && route.neigh_ip == neigh_local_ip {
                                return Ok(route.clone());
                            }
                        }
                    }
                }
            }
        }
        Err(NoNeighbor(neigh_mesh_ip.to_string()).into())
    }

    /// Checks if Babel has an installed route to the given destination
    pub fn do_we_have_route(
        &mut self,
        mesh_ip: &IpAddr,
        routes: &VecDeque<Route>,
    ) -> Result<bool, Error> {
        for route in routes.iter() {
            if let IpNetwork::V6(ref ip) = route.prefix {
                if ip.ip() == *mesh_ip && route.installed {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Returns the installed route to a given destination
    pub fn get_installed_route(
        &mut self,
        mesh_ip: &IpAddr,
        routes: &VecDeque<Route>,
    ) -> Result<Route, Error> {
        let mut exit_route = None;
        for route in routes.iter() {
            // Only ip6
            if let IpNetwork::V6(ref ip) = route.prefix {
                // Only host addresses and installed routes
                if ip.prefix() == 128 && route.installed && IpAddr::V6(ip.ip()) == *mesh_ip {
                    exit_route = Some(route);
                    break;
                }
            }
        }
        if exit_route.is_none() {
            bail!("No installed route to that destination!");
        }
        Ok(exit_route.unwrap().clone())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mockstream::SharedMockStream;

    static TABLE: &'static str =
"local fee 1024\n\
add interface wlan0 up true ipv6 fe80::1a8b:ec1:8542:1bd8 ipv4 10.28.119.131\n\
add interface wg0 up true ipv6 fe80::2cee:2fff:7380:8354 ipv4 10.0.236.201\n\
add neighbour 14f19a8 address fe80::2cee:2fff:648:8796 if wg0 reach ffff rxcost 256 txcost 256 rtt \
26.723 rttcost 912 cost 1168\n\
add neighbour 14f0640 address fe80::e841:e384:491e:8eb9 if wlan0 reach 9ff7 rxcost 512 txcost 256 \
rtt 19.323 rttcost 508 cost 1020\n\
add neighbour 14f05f0 address fe80::e9d0:498f:6c61:be29 if wlan0 reach feff rxcost 258 txcost 341 \
rtt 18.674 rttcost 473 cost 817\n\
add neighbour 14f0488 address fe80::e914:2335:a76:bda3 if wlan0 reach feff rxcost 258 txcost 256 \
rtt 22.805 rttcost 698 cost 956\n\
add xroute 10.28.119.131/32-::/0 prefix 10.28.119.131/32 from ::/0 metric 0\n\
add route 14f0820 prefix 10.28.7.7/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:5b:fe:c7 \
metric 1596 price 3072 fee 3072 refmetric 638 full-path-rtt 22.805 via fe80::e914:2335:a76:bda3 if wlan0\n\
add route 14f07a0 prefix 10.28.7.7/32 from 0.0.0.0/0 installed no id ba:27:eb:ff:fe:5b:fe:c7 \
metric 1569 price 5032 fee 5032 refmetric 752 full-path-rtt 42.805 via fe80::e9d0:498f:6c61:be29 if wlan0\n\
add route 14f06d8 prefix 10.28.20.151/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:c1:2d:d5 \
metric 817 price 4008 fee 4008 refmetric 0 full-path-rtt 18.674 via fe80::e9d0:498f:6c61:be29 if wlan0 \n\
add route 14f0548 prefix 10.28.244.138/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:d1:3e:ba \
metric 958 price 2048 fee 2048 refmetric 0 full-path-rtt 56.805 via fe80::e914:2335:a76:bda3 if wlan0\n\
add route 241fee0 prefix fdc5:5bcb:24ac:b35a:4b7f:146a:a2a1:bdc4/128 from ::/0 installed no id \
e6:95:6e:ff:fe:44:c4:12 metric 328 price 426000 fee 354600 refmetric 217 full-path-rtt 39.874 via fe80::6459:f009:c4b4:9971 if wg36
ok\n";

    static PREAMBLE: &'static str =
        "ALTHEA 0.1\nversion babeld-1.8.0-24-g6335378\nhost raspberrypi\nmy-id \
         ba:27:eb:ff:fe:09:06:dd\nok\n";

    static XROUTE_LINE: &'static str =
        "add xroute 10.28.119.131/32-::/0 prefix 10.28.119.131/32 from ::/0 metric 0";

    static ROUTE_LINE: &'static str =
        "add route 14f06d8 prefix 10.28.20.151/32 from 0.0.0.0/0 installed yes id \
         ba:27:eb:ff:fe:c1:2d:d5 metric 1306 price 4008 refmetric 0 full-path-rtt 18.674 via \
         fe80::e9d0:498f:6c61:be29 if wlan0";

    static PROBLEM_ROUTE_LINE: &'static str = 
        "add route 241fee0 prefix fdc5:5bcb:24ac:b35a:4b7f:146a:a2a1:bdc4/128 \
         from ::/0 installed no id e6:95:6e:ff:fe:44:c4:12 metric 331 price 426000 fee 354600 refmetric 220 full-path-rtt \
         38.286 via fe80::6459:f009:c4b4:9971 if wg36";

    static NEIGH_LINE: &'static str =
        "add neighbour 14f05f0 address fe80::e9d0:498f:6c61:be29 if wlan0 reach ffff rxcost \
         256 txcost 256 rtt 29.264 rttcost 1050 cost 1306";

    static IFACE_LINE: &'static str =
        "add interface wlan0 up true ipv6 fe80::1a8b:ec1:8542:1bd8 ipv4 10.28.119.131";

    static PRICE_LINE: &'static str = "local price 1024";

    #[test]
    fn mock_connect() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(PREAMBLE.as_bytes());
        let mut b = Babel::new(s);
        b.start_connection().unwrap()
    }

    #[test]
    fn mock_dump() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(TABLE.as_bytes());

        let mut b = Babel::new(s);
        let dump = b.command("dump").unwrap();
        assert_eq!(&dump, TABLE);
    }

    #[test]
    fn line_parse() {
        assert_eq!(find_babel_val("metric", XROUTE_LINE).unwrap(), "0");
        assert_eq!(
            find_babel_val("prefix", XROUTE_LINE).unwrap(),
            "10.28.119.131/32"
        );
        assert_eq!(find_babel_val("route", ROUTE_LINE).unwrap(), "14f06d8");
        assert_eq!(find_babel_val("if", ROUTE_LINE).unwrap(), "wlan0");
        assert_eq!(
            find_babel_val("via", ROUTE_LINE).unwrap(),
            "fe80::e9d0:498f:6c61:be29"
        );
        assert_eq!(
            find_babel_val("route", PROBLEM_ROUTE_LINE).unwrap(),
            "241fee0"
        );
        assert_eq!(
            find_babel_val("fee", PROBLEM_ROUTE_LINE).unwrap(),
            "354600"
        );
        assert_eq!(
            find_babel_val("price", PROBLEM_ROUTE_LINE).unwrap(),
            "426000"
        );
        assert_eq!(find_babel_val("if", PROBLEM_ROUTE_LINE).unwrap(), "wg36");
        assert_eq!(
            find_babel_val("prefix", PROBLEM_ROUTE_LINE).unwrap(),
            "fdc5:5bcb:24ac:b35a:4b7f:146a:a2a1:bdc4/128"
        );
        assert_eq!(
            find_babel_val("full-path-rtt", PROBLEM_ROUTE_LINE).unwrap(),
            "38.286"
        );
        assert_eq!(find_babel_val("reach", NEIGH_LINE).unwrap(), "ffff");
        assert_eq!(find_babel_val("rxcost", NEIGH_LINE).unwrap(), "256");
        assert_eq!(find_babel_val("rtt", NEIGH_LINE).unwrap(), "29.264");
        assert_eq!(find_babel_val("interface", IFACE_LINE).unwrap(), "wlan0");
        assert_eq!(find_babel_val("ipv4", IFACE_LINE).unwrap(), "10.28.119.131");
        assert_eq!(find_babel_val("price", PRICE_LINE).unwrap(), "1024");
    }

    #[test]
    fn neigh_parse() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(TABLE.as_bytes());
        let mut b = Babel::new(s);
        let neighs = b.parse_neighs().unwrap();
        let neigh = neighs.get(0);
        assert!(neigh.is_some());
        let neigh = neigh.unwrap();
        assert_eq!(neighs.len(), 4);
        assert_eq!(neigh.id, "14f19a8");
    }

    #[test]
    fn route_parse() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(TABLE.as_bytes());
        let mut b = Babel::new(s);

        let routes = b.parse_routes().unwrap();
        assert_eq!(routes.len(), 5);

        let route = routes.get(0).unwrap();
        assert_eq!(route.price, 3072);
    }

    #[test]
    fn local_fee_parse() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(TABLE.as_bytes());

        let mut b = Babel::new(s);
        assert_eq!(b.get_local_fee().unwrap(), 1024);
    }

    #[test]
    fn multiple_babel_outputs_in_stream() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(PREAMBLE.as_bytes());
        s.push_bytes_to_read(TABLE.as_bytes());
        s.push_bytes_to_read(b"ok\n");

        let mut b = Babel::new(s);
        b.start_connection().unwrap();

        let routes = b.parse_routes().unwrap();
        assert_eq!(routes.len(), 5);

        let route = routes.get(0).unwrap();
        assert_eq!(route.price, 3072);
        assert_eq!(route.full_path_rtt, 22.805);

        b.command("interface wg0").unwrap();
    }

    #[test]
    fn only_ok_in_output() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(b"ok\n");

        let mut b = Babel::new(s);
        b.command("interface wg0").unwrap();
    }
}
