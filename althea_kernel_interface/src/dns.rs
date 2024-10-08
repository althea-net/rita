use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::net::IpAddr;

/// Gets a list of IP addresses of nameservers from /etc/resolv.conf, may be v6, v4 or both
/// generally ignores malformed lines but produces IO errors
pub fn get_resolv_servers() -> Result<Vec<IpAddr>, Error> {
    let mut f = File::open("/etc/resolv.conf")?;
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    let mut res = Vec::new();
    for line in contents.lines() {
        if line.starts_with("nameserver") {
            let mut nameserver = line.split_whitespace();
            nameserver.next();
            match nameserver.next() {
                Some(ip) => match ip.parse() {
                    Ok(addr) => res.push(addr),
                    Err(e) => {
                        warn!("Could not parse /etc/resolv.conf ip {:?} with {:?}", ip, e)
                    }
                },
                None => warn!("Invalid /etc/resolv.conf!"),
            }
        }
    }
    Ok(res)
}
