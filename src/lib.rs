use std::io;
use std::io::{Read,Write};
use std::net::TcpStream;
extern crate mockstream;
extern crate ascii;
use std::str;
use mockstream::SharedMockStream;

// From rust_mockstream MIT
enum NetStream {
	Mocked(SharedMockStream),
	Tcp(TcpStream)
}

impl io::Read for NetStream {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match *self {
			NetStream::Mocked(ref mut s) => s.read(buf),
			NetStream::Tcp(ref mut s) => s.read(buf),
		}
	}
}

impl io::Write for NetStream {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		match *self {
			NetStream::Mocked(ref mut s) => s.write(buf),
			NetStream::Tcp(ref mut s) => s.write(buf),
		}
	}

	fn flush(&mut self) -> io::Result<()> {
		match *self {
			NetStream::Mocked(ref mut s) => s.flush(),
			NetStream::Tcp(ref mut s) => s.flush(),
		}
	}
}
// end mockstream code

struct Babel {
    stream: NetStream
}

impl Babel {

    // Consumes the automated Preamble and validates configuration api version
    fn start_connection(&mut self) -> bool {
        let preamble = self.read();
        // Note you have changed the config interface, bump to 1.1 in babel
        if preamble.contains("BABEL 1.0") && self.positive_termination(&preamble) {
            true
        }
        else {
            false
        }
    }

    // Safely closes the babel connection and terminates
    // the monitor thread
    fn close_connection(&mut self) -> bool {
        true
    }

    //TODO write function to shrink these strings in memory
    fn read(&mut self) -> String {
        let mut data: [u8; 512] = [0;512];
        self.stream.read(&mut data);
        let mut ret = str::from_utf8(&data).unwrap().to_string();
        // Messages may be long or get interupped, we must consume
        // until we hit a terminator
        loop {
            self.stream.read(&mut data);
            let mut message = &str::from_utf8(&data).unwrap().to_string();
            println!("{:?}", message);
            ret = ret + message;
            if self.contains_terminator(message) {
                break;
            }
        }
        ret
    }

    fn contains_terminator(&self, message: &str) -> bool {
        if message.contains("\nok\n") {
            true
        }
        else if message.contains("\nno\n") {
            true
        }
        else if message.contains("\nbad\n") {
            true
        }
        else {
            false
        }
    }

    fn positive_termination(&self, message: &str) -> bool {
        if message.contains("\nok\n") {
            true
        }
        else {
            false
        }
    }

    fn write(&mut self, command: &'static str) -> bool {
        let written_bytes = self.stream.write(command.as_bytes());
        //lets see how common this failure is before writing
        //a full retry system
        assert_eq!(written_bytes.unwrap(), command.as_bytes().len());
        true
    }

    fn parse_babel_val(&self, val: &'static str, line: &'static str) -> String {
        let mut place = line.split(" ");
        let mut entry = place.next();
        while !entry.unwrap().to_string().contains(val) {
            entry = place.next();
        }
        place.next().unwrap().to_string()
    }

}

struct Route {
    xroute: bool,
    installed: bool,
    id: String,
    neigh_id: String,
    ip: String,
    metric: u16,
    price: u32,
    refmetric: u16

}

struct Neighbour {
    id: String,
    iface: String,
    reach: u16,
    txcost: u16,
    rxcost: u16,
    rtt: f32,
    rttcost: u16,
    cost: u16
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
    static PREAMBLE: &'static str = "BABEL 1.0\nversion babeld-1.8.0-24-g6335378\nhost raspberrypi\nmy-id \
                                    ba:27:eb:ff:fe:09:06:dd\nok\n\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\
                                    \u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}";

    /*fn real_babel_basic() {
        let mut b1 = Babel {stream: NetStream::Tcp(TcpStream::connect("::1:8080").unwrap())};
        assert_eq!(b1.start_connection(), true);
        assert_eq!(b1.write("dump\n"), true);
        println!("{:?}", b1.read());
    }*/

    #[test]
    fn mock_connect() {
        let mut s = SharedMockStream::new();
        let mut b1 = Babel {stream: NetStream::Mocked(s.clone())};
        s.push_bytes_to_read(PREAMBLE.as_bytes());
        assert_eq!(b1.start_connection(), true);
    }

    #[test]
    fn mock_dump() {
        let mut s = SharedMockStream::new();
        let mut b1 = Babel {stream: NetStream::Mocked(s.clone())};
        s.push_bytes_to_read(TABLE.as_bytes());
        assert_eq!(b1.write("dump\n"), true);
    }
}
