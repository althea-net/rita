#[macro_use]
extern crate failure;
extern crate ip_network;
#[macro_use]
extern crate log;
extern crate mockstream;

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::net::TcpStream;
use std::str;

use failure::Error;
use ip_network::IpNetwork;
use mockstream::SharedMockStream;

#[derive(Debug, Fail)]
pub enum BabelMonitorError {
    #[fail(display = "variable '{}' not found in '{}'", _0, _1)]
    VariableNotFound(String, String),
    #[fail(display = "Invalid preamble: {}", _0)]
    InvalidPreamble(String),
    #[fail(display = "Could not find local fee in '{}'", _0)]
    LocalFeeNotFound(String),
    #[fail(display = "Last Babel command failed with output:\n{}", _0)]
    CommandFailed(String),
}

use BabelMonitorError::*;

// If a function doesn't modify the state of the Babel object
// we don't want to place it as a member function.
fn find_babel_val(val: &str, line: &str) -> Result<String, Error> {
    let mut iter = line.split(" ");
    while let Some(entry) = iter.next() {
        if entry.to_string().contains(val) {
            match iter.next() {
                Some(v) => return Ok(v.to_string()),
                None => continue,
            }
        }
    }
    return Err(VariableNotFound(String::from(val), String::from(line)).into());
}

fn is_terminator(line: &String) -> bool {
    line == "ok" || line == "no" || line == "bad"
}

fn positive_termination(message: &String) -> bool {
    message.contains("\nok\n")
}

#[derive(Debug)]
pub struct Route {
    pub id: String,
    pub iface: String,
    pub xroute: bool,
    pub installed: bool,
    pub neigh_ip: IpAddr,
    pub prefix: IpNetwork,
    pub metric: u16,
    pub refmetric: u16,
    pub price: u32,
    pub fee: u32,
}

#[derive(Debug)]
pub struct Neighbor {
    pub id: String,
    pub iface: String,
    pub reach: u16,
    pub txcost: u16,
    pub rxcost: u16,
    pub rtt: f32,
    pub rttcost: u16,
    pub cost: u16,
}

impl Babel for TcpStream {}
impl Babel for SharedMockStream {}

pub trait Babel: Read + Write {
    /// Apart from just retrieving latest babeld output, this method also checks that the output
    /// was one connected to a successful operation.
    fn read_babel(&mut self) -> Result<String, Error> {
        let mut reader = BufReader::new(self);
        let mut ret = String::new();
        for line in reader.by_ref().lines() {
            let line = &line?;
            ret.push_str(line);
            ret.push_str("\n");
            if is_terminator(line) {
                break;
            }
        }
        trace!("babel returned {}", ret);
        if ret.ends_with("ok\n") {
            Ok(ret)
        } else {
            Err(CommandFailed(ret).into())
        }
    }

    fn write_babel(&mut self, command: &str) -> Result<(), Error> {
        self.write_all(command.as_bytes())?;
        trace!("sent {} to babel", command);
        Ok(())
    }
}

impl Babel {
    // Consumes the automated Preamble and validates configuration api version
    pub fn start_connection(&mut self) -> Result<(), Error> {
        trace!("About to get the preamble");
        let preamble = self.read_babel()?;
        trace!("Got the preamble: {}", preamble);
        // Note you have changed the config interface, bump to 1.1 in babel
        if preamble.contains("ALTHEA 0.1") && positive_termination(&preamble) {
            info!("Attached OK to Babel with preamble: {}", preamble);
            return Ok(());
        } else {
            return Err(InvalidPreamble(preamble).into());
        }
    }

    pub fn local_fee(&mut self) -> Result<u32, Error> {
        self.write_babel("dump\n")?;

        let babel_output = self.read_babel()?;
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

    pub fn monitor(&mut self, iface: &str) -> Result<(), Error> {
        let commmand = format!("interface {} \n", iface);
        self.write_babel(&commmand)?;
        let _ = self.read_babel()?;
        info!("Babel started monitoring: {}", iface);
        Ok(())
    }

    pub fn redistribute_ip(&mut self, ip: &IpAddr, allow: bool) -> Result<(), Error> {
        let commmand = format!(
            "redistribute ip {}/128 {}\n",
            ip,
            if allow { "allow" } else { "deny" }
        );
        self.write_babel(&commmand)?;
        let _ = self.read_babel()?;
        Ok(())
    }

    pub fn unmonitor(&mut self, iface: &str) -> Result<(), Error> {
        let commmand = format!("unmonitor {}\n", iface);
        self.write_babel(&commmand)?;
        let _ = self.read_babel()?;
        Ok(())
    }

    pub fn parse_neighs(&mut self) -> Result<VecDeque<Neighbor>, Error> {
        let mut vector: VecDeque<Neighbor> = VecDeque::with_capacity(5);
        self.write_babel("dump\n")?;
        for entry in self.read_babel()?.split("\n") {
            if entry.contains("add neighbour") {
                vector.push_back(Neighbor {
                    id: find_babel_val("neighbour", entry)?,
                    iface: find_babel_val("if", entry)?,
                    reach: u16::from_str_radix(&find_babel_val("reach", entry)?, 16)?,
                    txcost: find_babel_val("txcost", entry)?.parse()?,
                    rxcost: find_babel_val("rxcost", entry)?.parse()?,
                    rtt: find_babel_val("rtt", entry)?.parse()?,
                    rttcost: find_babel_val("rttcost", entry)?.parse()?,
                    cost: find_babel_val("cost", entry)?.parse()?,
                });
            }
        }
        Ok(vector)
    }

    pub fn parse_routes(&mut self) -> Result<VecDeque<Route>, Error> {
        let mut vector: VecDeque<Route> = VecDeque::with_capacity(20);
        self.write_babel("dump\n")?;
        let babel_out = self.read_babel()?;
        trace!("Got from babel dump: {}", babel_out);

        for entry in babel_out.split("\n") {
            if entry.contains("add route") {
                trace!("Parsing 'add route' entry: {}", entry);
                vector.push_back(Route {
                    id: find_babel_val("route", entry)?,
                    iface: find_babel_val("if", entry)?,
                    xroute: false,
                    installed: find_babel_val("installed", entry)?.contains("yes"),
                    neigh_ip: find_babel_val("via", entry)?.parse()?,
                    prefix: find_babel_val("prefix", entry)?.parse()?,
                    metric: find_babel_val("metric", entry)?.parse()?,
                    refmetric: find_babel_val("refmetric", entry)?.parse()?,
                    price: find_babel_val("price", entry)?.parse()?,
                    fee: find_babel_val("fee", entry)?.parse()?,
                });
            }
        }
        Ok(vector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static TABLE: &'static str =
"local fee 1024\n\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\
\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\
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
add route 14f0820 prefix 10.28.7.7/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:5b:fe:c7\
metric 1596 price 3072 fee 3072 refmetric 638 via fe80::e914:2335:a76:bda3 if wlan0\n\
add route 14f07a0 prefix 10.28.7.7/32 from 0.0.0.0/0 installed no id ba:27:eb:ff:fe:5b:fe:c7\
metric 1569 price 5032 fee 5032 refmetric 752 via fe80::e9d0:498f:6c61:be29 if wlan0\n\
add route 14f06d8 prefix 10.28.20.151/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:c1:2d:d5\
metric 817 price 4008 fee 4008 refmetric 0 via fe80::e9d0:498f:6c61:be29 if wlan0\n\
add route 14f0548 prefix 10.28.244.138/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:d1:3e:ba\
metric 958 price 2048 fee 2048 refmetric 0 via fe80::e914:2335:a76:bda3 if wlan0\n\
ok\n\u{0}\u{0}";

    static PREAMBLE: &'static str =
        "ALTHEA 0.1\nversion babeld-1.8.0-24-g6335378\nhost raspberrypi\nmy-id \
         ba:27:eb:ff:fe:09:06:dd\nok\n\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\
         \u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}";

    static XROUTE_LINE: &'static str =
        "add xroute 10.28.119.131/32-::/0 prefix 10.28.119.131/32 from ::/0 metric 0";

    static ROUTE_LINE: &'static str =
        "add route 14f06d8 prefix 10.28.20.151/32 from 0.0.0.0/0 installed yes id \
         ba:27:eb:ff:fe:c1:2d:d5 metric 1306 price 4008 refmetric 0 via \
         fe80::e9d0:498f:6c61:be29 if wlan0";

    static NEIGH_LINE: &'static str =
        "add neighbour 14f05f0 address fe80::e9d0:498f:6c61:be29 if wlan0 reach ffff rxcost \
         256 txcost 256 rtt 29.264 rttcost 1050 cost 1306";

    static IFACE_LINE: &'static str =
        "add interface wlan0 up true ipv6 fe80::1a8b:ec1:8542:1bd8 ipv4 10.28.119.131";

    static PRICE_LINE: &'static str = "local price 1024";

    /*fn real_babel_basic() {
      let mut b1 = Babel {stream: NetStream::Tcp(TcpStream::connect("::1:8080").unwrap())};
      assert_eq!(b1.start_connection(), true);
      assert_eq!(b1.write("dump\n"), true);
      println!("{:?}", b1.read());
      }*/

    #[test]
    fn mock_connect() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(PREAMBLE.as_bytes());
        let b: &mut Babel = &mut s;
        b.start_connection().unwrap()
    }

    #[test]
    fn mock_dump() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(TABLE.as_bytes());
        s.write(b"dump\n").unwrap();
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
        s.write(b"dump\n").unwrap();
        let b: &mut Babel = &mut s;
        let neighs = b.parse_neighs().unwrap();
        println!("{:?}", neighs);
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
        s.write(b"dump\n").unwrap();
        let b: &mut Babel = &mut s;

        let routes = b.parse_routes().unwrap();
        assert_eq!(routes.len(), 4);

        let route = routes.get(0).unwrap();
        assert_eq!(route.price, 3072);
    }

    #[test]
    fn local_fee_parse() {
        let mut s = SharedMockStream::new();
        s.push_bytes_to_read(TABLE.as_bytes());
        s.write(b"dump\n").unwrap();
        let b: &mut Babel = &mut s;

        assert_eq!(b.local_fee().unwrap(), 1024);
    }
}
