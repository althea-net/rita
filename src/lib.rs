
#[macro_use]
extern crate derive_error;

#[macro_use]
extern crate log;

extern crate ip_network;
extern crate mockstream;
use std::io::{BufReader, BufRead};

use std::{time};
use std::io::{Read, Write};
use std::str;
use mockstream::SharedMockStream;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::{TcpStream, SocketAddr};
use ip_network::IpNetwork;

#[derive(Debug, Error)]
pub enum Error {
    Io(std::io::Error),
    FromUTF8(std::string::FromUtf8Error),
    UTF8(std::str::Utf8Error),
    ParseInt(std::num::ParseIntError),
    ParseFloat(std::num::ParseFloatError),
    AddrParse(std::net::AddrParseError),
    IpNetworkParseError(ip_network::IpNetworkParseError),
    #[error(msg_embedded, no_from, non_std)] BabelError(String),
}

// If a function doesn't modify the state of the Babel object
// we don't want to place it as a member function.
fn find_babel_val(val: &str, line: &str) -> Result<String, Error> {
    let mut iter = line.split(" ");
    while let Some(entry) = iter.next() {
        if entry.to_string().contains(val) {
            match iter.next() {
                Some(v) => return Ok(v.to_string()),
                None => continue
            }
        }
    }
    return Err(Error::BabelError(format!("{} not found in babel output", val)));
}


fn contains_terminator(message: &String) -> bool {
    message.contains("\nok\n") ||
    message.contains("\nno\n") ||
    message.contains("\nbad\n")
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
}

#[derive(Debug)]
pub struct Neighbour {
    pub id: String,
    pub iface: String,
    pub reach: u16,
    pub txcost: u16,
    pub rxcost: u16,
    pub rtt: f32,
    pub rttcost: u16,
    pub cost: u16,
}

pub struct Babel<T: Read + Write> {
    stream: BufReader<T>,
}

impl Babel<TcpStream> {
    pub fn new(addr: &SocketAddr) -> Babel<TcpStream> {
        let mut babel = Babel { stream: BufReader::new(TcpStream::connect_timeout(addr, time::Duration::from_secs(5)).unwrap()) };
        babel.start_connection().unwrap();
        babel
    }
}

impl<T: Read + Write> Babel<T> {
    // Consumes the automated Preamble and validates configuration api version
    pub fn start_connection(&mut self) -> Result<(), Error> {
        let preamble = self.read()?;
        // Note you have changed the config interface, bump to 1.1 in babel
        if preamble.contains("ALTHEA 0.1") && positive_termination(&preamble) {
            return Ok(());
        } else {
            return Err(Error::BabelError(format!("Connection to Babel not started correctly. Invalid preamble: {}", preamble)));
        }
    }

    //TODO use BufRead instead of this
    // fn read(&mut self) -> Result<String, Error> {
    //     let mut data: [u8; 512] = [0; 512];
    //     self.stream.read(&mut data)?;
    //     let mut ret = str::from_utf8(&data)?.to_string();
    //     // Messages may be long or get interupped, we must consume
    //     // until we hit a terminator
    //     while !contains_terminator(&ret) {
    //         self.stream.read(&mut data)?;
    //         ret = ret + &str::from_utf8(&data)?.to_string();
    //     }
    //     Ok(ret)
    // }

    fn read(&mut self) -> Result<String, Error> {
        let mut ret = String::new();
        for line in self.stream.by_ref().lines() {
            let line = &line?;
            ret.push_str(line);
            ret.push_str("\n");
            if contains_terminator(line) {
                break;
            }
        }
        Ok(ret)
    }

    fn write(&mut self, command: &'static str) -> Result<(), Error> {
        self.stream.get_mut().write(command.as_bytes())?;
        Ok(())
    }

    pub fn local_price(&mut self) -> Result<u32, Error> {
        self.write("dump\n")?;
        for entry in self.read()?.split("\n") {
            if entry.contains("local price") {
                return Ok(find_babel_val("price", entry)?.parse::<u32>()?);
            }
        }
        Ok(0)
    }


    pub fn parse_neighs(&mut self) -> Result<VecDeque<Neighbour>, Error> {
        let mut vector: VecDeque<Neighbour> = VecDeque::with_capacity(5);
        self.write("dump\n")?;
        for entry in self.read()?.split("\n") {
            if entry.contains("add neighbour") {
                vector.push_back(Neighbour {
                    id: find_babel_val("neighbour", entry)?,
                    iface: find_babel_val("if", entry)?,
                    reach: u16::from_str_radix(&find_babel_val("reach", entry)?, 16)?,
                    txcost: find_babel_val("txcost", entry)?.parse::<u16>()?,
                    rxcost: find_babel_val("rxcost", entry)?.parse::<u16>()?,
                    rtt: find_babel_val("rtt", entry)?.parse::<f32>()?,
                    rttcost: find_babel_val("rttcost", entry)?.parse::<u16>()?,
                    cost: find_babel_val("cost", entry)?.parse::<u16>()?,
                });
            }
        }
        Ok(vector)
    }


    pub fn parse_routes(&mut self) -> Result<VecDeque<Route>, Error> {
        let mut vector: VecDeque<Route> = VecDeque::with_capacity(20);
        self.write("dump\n")?;
        let babel_out = self.read()?;
        trace!("Got from babel dump: {}", babel_out);

        for entry in babel_out.split("\n") {
            if entry.contains("add route") {
                trace!("Parsing 'add route' entry: {}", entry);
                vector.push_back(Route {
                    id: find_babel_val("route", entry)?,
                    iface: find_babel_val("if", entry)?,
                    xroute: false,
                    installed: find_babel_val("installed", entry)?.contains("yes"),
                    neigh_ip: find_babel_val("via", entry)?.parse::<IpAddr>()?,
                    prefix: find_babel_val("prefix", entry)?.parse::<IpNetwork>()?,
                    metric: find_babel_val("metric", entry)?.parse::<u16>()?,
                    refmetric: find_babel_val("refmetric", entry)?.parse::<u16>()?,
                    price: find_babel_val("price", entry)?.parse::<u32>()?,
                });
            }
        }
        Ok(vector)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    static TABLE: &'static str = "local price 1024\n\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\
                                  \u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}add interface wlan0 up true \
                                  ipv6 fe80::1a8b:ec1:8542:1bd8 ipv4 10.28.119.131\nadd interface wg0 up true ipv6 \
                                  fe80::2cee:2fff:7380:8354 ipv4 10.0.236.201\nadd neighbour 14f19a8 address fe80::2cee:2fff:648:8796 \
                                  if wg0 reach ffff rxcost 256 txcost 256 rtt 26.723 rttcost 912 cost 1168\nadd neighbour 14f0640 \
                                  address fe80::e841:e384:491e:8eb9 if wlan0 reach 9ff7 rxcost 512 txcost 256 rtt 19.323 rttcost 508 \
                                  cost 1020\nadd neighbour 14f05f0 address fe80::e9d0:498f:6c61:be29 if wlan0 reach feff rxcost 258 \
                                  txcost 341 rtt 18.674 rttcost 473 cost 817\nadd neighbour 14f0488 address fe80::e914:2335:a76:bda3 \
                                  if wlan0 reach feff rxcost 258 txcost 256 rtt 22.805 rttcost 698 cost 956\nadd xroute \
                                  10.28.119.131/32-::/0 prefix 10.28.119.131/32 from ::/0 metric 0\nadd route 14f0820 prefix \
                                  10.28.7.7/32 from 0.0.0.0/0 installed yes id ba:27:eb:ff:fe:5b:fe:c7 metric 1596 price 3072 refmetric \
                                  638 via fe80::e914:2335:a76:bda3 if wlan0\nadd route 14f07a0 prefix 10.28.7.7/32 from 0.0.0.0/0 \
                                  installed no id ba:27:eb:ff:fe:5b:fe:c7 metric 1569 price 5032 refmetric 752 via \
                                  fe80::e9d0:498f:6c61:be29 if wlan0\nadd route 14f06d8 prefix 10.28.20.151/32 from 0.0.0.0/0 installed \
                                  yes id ba:27:eb:ff:fe:c1:2d:d5 metric 817 price 4008 refmetric 0 via fe80::e9d0:498f:6c61:be29 if \
                                  wlan0\nadd route 14f0548 prefix 10.28.244.138/32 from 0.0.0.0/0 installed yes id \
                                  ba:27:eb:ff:fe:d1:3e:ba metric 958 price 2048 refmetric 0 via fe80::e914:2335:a76:bda3 if \
                                  wlan0\nok\n\u{0}\u{0}";

    static PREAMBLE: &'static str = "ALTHEA 0.1\nversion babeld-1.8.0-24-g6335378\nhost raspberrypi\nmy-id \
                                    ba:27:eb:ff:fe:09:06:dd\nok\n\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\
                                    \u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}";

    static XROUTE_LINE: &'static str = "add xroute 10.28.119.131/32-::/0 prefix 10.28.119.131/32 from ::/0 metric 0";

    static ROUTE_LINE: &'static str = "add route 14f06d8 prefix 10.28.20.151/32 from 0.0.0.0/0 installed yes id \
                                       ba:27:eb:ff:fe:c1:2d:d5 metric 1306 price 4008 refmetric 0 via \
                                       fe80::e9d0:498f:6c61:be29 if wlan0";

    static NEIGH_LINE: &'static str = "add neighbour 14f05f0 address fe80::e9d0:498f:6c61:be29 if wlan0 reach ffff rxcost \
                                       256 txcost 256 rtt 29.264 rttcost 1050 cost 1306";


    static IFACE_LINE: &'static str = "add interface wlan0 up true ipv6 fe80::1a8b:ec1:8542:1bd8 ipv4 10.28.119.131";

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
        let mut b1 = Babel { stream: BufReader::new(s.clone()) };
        s.push_bytes_to_read(PREAMBLE.as_bytes());
        b1.start_connection().unwrap()
    }

    #[test]
    fn mock_dump() {
        let mut s = SharedMockStream::new();
        let mut b1 = Babel { stream: BufReader::new(s.clone()) };
        s.push_bytes_to_read(TABLE.as_bytes());
        b1.write("dump\n").unwrap();
    }

    #[test]
    fn line_parse() {
        assert_eq!(find_babel_val("metric", XROUTE_LINE).unwrap(), "0");
        assert_eq!(find_babel_val("prefix", XROUTE_LINE).unwrap(), "10.28.119.131/32");
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
        let mut b1 = Babel { stream: BufReader::new(s.clone()) };
        s.push_bytes_to_read(TABLE.as_bytes());
        b1.write("dump\n").unwrap();
        let neighs = b1.parse_neighs().unwrap();
        let neigh = neighs.get(0);
        assert!(neigh.is_some());
        let neigh = neigh.unwrap();
        assert_eq!(neighs.len(), 4);
        assert_eq!(neigh.id, "14f19a8");
    }

    #[test]
    fn route_parse() {
        let mut s = SharedMockStream::new();
        let mut b1 = Babel { stream: BufReader::new(s.clone()) };
        s.push_bytes_to_read(TABLE.as_bytes());
        b1.write("dump\n").unwrap();

        let routes = b1.parse_routes().unwrap();
        // assert_eq!(routes.len(), 5);

        // let route = routes.get(0).unwrap();
        // assert_eq!(route.price, 0);
    }

    #[test]
    fn local_price_parse() {
        let mut s = SharedMockStream::new();
        let mut b1 = Babel { stream: BufReader::new(s.clone()) };
        s.push_bytes_to_read(TABLE.as_bytes());
        b1.write("dump\n").unwrap();
        assert_eq!(b1.local_price().unwrap(), 1024);
    }
}
