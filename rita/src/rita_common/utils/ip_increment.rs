use failure::Error;
<<<<<<< HEAD:rita/src/rita_common/utils/ip_increment.rs
use std::net::IpAddr;
use std::net::Ipv4Addr;

#[allow(dead_code)]
pub fn incrementv4(address: Ipv4Addr, netmask: u8) -> Result<Ipv4Addr, Error> {
    assert_eq!(netmask % 8, 0);
    // the number of bytes we can cover using this netmask
    let bytes_to_modify = ((32 - netmask) + 7) / 8;
    assert!(netmask <= 32);
    assert!(bytes_to_modify <= 4);
    assert!(bytes_to_modify > 0);

    let mut carry = false;
    let mut oct = address.octets();
    for i in (3 - (bytes_to_modify)..4).rev() {
        let index = i as usize;
        if i == (4 - bytes_to_modify) && oct[index] == 255 && carry {
            bail!("Ip space in the netmask has been exhausted!");
        }

        if oct[index] == 255 {
            oct[index] = 0;
            carry = true;
            continue;
        }

        if carry {
            oct[index] += 1;
            return Ok(oct.into());
        }

        oct[index] += 1;
        return Ok(oct.into());
    }
    bail!("No more ip address space!")
}

/// adds one to whole netmask ip addresses
#[allow(dead_code)]
pub fn increment(address: IpAddr, netmask: u8) -> Result<IpAddr, Error> {
=======
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// adds one to whole netmask ip addresses
pub fn incrementv4(address: Ipv4Addr, netmask: u8) -> Result<Ipv4Addr, Error> {
>>>>>>> 6aaf144d... Exit ipv6 vars and helper functions:rita/src/rita_exit/database/ip_increment.rs
    assert_eq!(netmask % 8, 0);
    // the number of bytes we can cover using this netmask
    let bytes_to_modify = ((32 - netmask) + 7) / 8;
    assert!(netmask <= 32);
    assert!(bytes_to_modify <= 4);
    assert!(bytes_to_modify > 0);

    let mut carry = false;
    let mut oct = address.octets();
    for i in (3 - (bytes_to_modify)..4).rev() {
        let index = i as usize;
        if i == (4 - bytes_to_modify) && oct[index] == 255 && carry {
            bail!("Ip space in the netmask has been exhausted!");
        }

        if oct[index] == 255 {
            oct[index] = 0;
            carry = true;
            continue;
        }

        if carry {
            oct[index] += 1;
            return Ok(oct.into());
        }

        oct[index] += 1;
        return Ok(oct.into());
    }
    bail!("No more ip address space!")
}

/// Given an ip and subnet, return an ip incremented to the next subnet of that same
/// size. So 192.168.1.1/24 would increment to 192.168.2.1/24 or 256 addresses, since
/// /24 is 8 bits and 2^8 = 256
pub fn increment_subnetv6(address: Ipv6Addr, netmask: u8) -> Ipv6Addr {
    assert!(netmask <= 128);
    let mut bits: u128 = address.into();
    // now we have a single bit vector to work with
    // mask off the bottom bits
    let mask: u128 = !(2u128.pow(netmask.into()) - 1);
    bits &= mask;
    bits >>= netmask;
    bits += 1;
    bits <<= netmask;
    let new_addr: Ipv6Addr = bits.into();
    new_addr
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn increment_basic_v4() {
        let addr1: Ipv4Addr = [0, 0, 0, 0].into();
        let addr2: Ipv4Addr = [0, 0, 0, 1].into();
        assert_eq!(incrementv4(addr1, 16).unwrap(), addr2);
    }

    #[test]
    fn increment_overflow_v4() {
        let addr1: Ipv4Addr = [0, 0, 0, 255].into();
        let addr2: Ipv4Addr = [0, 0, 1, 0].into();
        assert_eq!(incrementv4(addr1, 16).unwrap(), addr2);
    }
    #[test]
    fn increment_out_of_bounds_simple_v4() {
        let addr1: Ipv4Addr = [0, 0, 255, 255].into();
        assert!(incrementv4(addr1, 16).is_err());
    }

    #[test]
    fn increment_across_netmask_v4() {
        let mut ip: Ipv4Addr = "192.168.0.0".parse().unwrap();
        let stop_ip: Ipv4Addr = "192.168.255.255".parse().unwrap();
        while ip != stop_ip {
            let res = incrementv4(ip, 16);
            assert!(res.is_ok());
            ip = res.unwrap();
        }
    }
<<<<<<< HEAD:rita/src/rita_common/utils/ip_increment.rs

    #[test]
    fn increment_basic_v4_specific() {
        let addr1: Ipv4Addr = [0, 0, 0, 0].into();
        let addr2: Ipv4Addr = [0, 0, 0, 1].into();
        assert_eq!(incrementv4(addr1, 16).unwrap(), addr2);
    }

    #[test]
    fn increment_overflow_v4_specific() {
        let addr1: Ipv4Addr = [0, 0, 0, 255].into();
        let addr2: Ipv4Addr = [0, 0, 1, 0].into();
        assert_eq!(incrementv4(addr1, 16).unwrap(), addr2);
    }
    #[test]
    fn increment_out_of_bounds_simple_v4_speficic() {
        let addr1: Ipv4Addr = [0, 0, 255, 255].into();
        assert!(incrementv4(addr1, 16).is_err());
    }

    #[test]
    fn increment_across_netmask_v4_specific() {
        let mut ip: Ipv4Addr = "192.168.0.0".parse().unwrap();
        let stop_ip: Ipv4Addr = "192.168.255.255".parse().unwrap();
        while ip != stop_ip {
            let res = incrementv4(ip, 16);
            assert!(res.is_ok());
            ip = res.unwrap();
        }
    }

    #[test]
    fn increment_basic_v6() {
        let addr1: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into();
        let addr2: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].into();
        assert_eq!(increment(addr1, 112).unwrap(), addr2);
    }

    #[test]
    fn increment_overflow_v6() {
        let addr1: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255].into();
        let addr2: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0].into();
        assert_eq!(increment(addr1, 112).unwrap(), addr2);
    }
    #[test]
    fn increment_out_of_bounds_simple_v6() {
        let addr1: IpAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255].into();
        assert!(increment(addr1, 112).is_err());
    }
=======
>>>>>>> 6aaf144d... Exit ipv6 vars and helper functions:rita/src/rita_exit/database/ip_increment.rs
}
