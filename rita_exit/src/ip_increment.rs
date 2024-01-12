use rita_common::RitaCommonError;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

pub fn incrementv4(address: Ipv4Addr, netmask: u8) -> Result<Ipv4Addr, RitaCommonError> {
    let byte_vec = u32::from_be_bytes(address.octets());
    let mut mask = 0;
    for i in 0..netmask {
        mask = flip_bit_at_index_u32(mask, i);
    }
    let new_ip = byte_vec + 1;
    if new_ip & !mask == 0 {
        return Err(RitaCommonError::MiscStringError(
            "Address space exhausted!".to_string(),
        ));
    }

    let new_ip: Ipv4Addr = new_ip.to_be_bytes().into();
    Ok(new_ip)
}

pub fn incrementv6(address: Ipv6Addr, netmask: u8) -> Result<Ipv6Addr, RitaCommonError> {
    let byte_vec = u128::from_be_bytes(address.octets());
    let mut mask = 0;
    for i in 0..netmask {
        mask = flip_bit_at_index_u128(mask, i);
    }
    let new_ip = byte_vec + 1;
    if new_ip & !mask == 0 {
        return Err(RitaCommonError::MiscStringError(
            "Address space exhausted!".to_string(),
        ));
    }

    let new_ip: Ipv6Addr = new_ip.to_be_bytes().into();
    Ok(new_ip)
}

/// flips the bit at the given index assuming bigendian counting
fn flip_bit_at_index_u32(input: u32, bit: u8) -> u32 {
    let mask = 1;
    let shift = 31 - bit;
    let mask = mask << shift;
    input ^ mask
}

/// flips the bit at the given index assuming bigendian counting
fn flip_bit_at_index_u128(input: u128, bit: u8) -> u128 {
    let mask = 1;
    let shift = 127 - bit;
    let mask = mask << shift;
    input ^ mask
}

/// adds one to whole netmask ip addresses
#[allow(dead_code)]
pub fn increment(address: IpAddr, netmask: u8) -> Result<IpAddr, RitaCommonError> {
    assert_eq!(netmask % 8, 0);
    match address {
        IpAddr::V4(address) => match incrementv4(address, netmask) {
            Ok(addr) => Ok(addr.into()),
            Err(e) => Err(e),
        },
        IpAddr::V6(address) => match incrementv6(address, netmask) {
            Ok(addr) => Ok(addr.into()),
            Err(e) => Err(e),
        },
    }
}

/// Lifted directly from https://doc.rust-lang.org/src/std/net/ip.rs.html
/// this identifies fe80 linklocal addresses
#[allow(dead_code)]
pub fn is_unicast_link_local(input: &Ipv6Addr) -> bool {
    (input.segments()[0] & 0xffc0) == 0xfe80
}

/// Lifted directly from https://doc.rust-lang.org/src/std/net/ip.rs.html
/// this identifies fd local addresses in short mesh addresses
#[allow(dead_code)]
pub fn is_unique_local(input: &Ipv6Addr) -> bool {
    (input.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flip_start_u32() {
        let res = flip_bit_at_index_u32(0, 0);
        assert_eq!(res, u32::pow(2, 31))
    }

    #[test]
    fn flip_end_u32() {
        let res = flip_bit_at_index_u32(0, 31);
        assert_eq!(res, 1)
    }

    #[test]
    fn flip_middle_u32() {
        let res = flip_bit_at_index_u32(0, 15);
        assert_eq!(res, u32::pow(2, 16))
    }

    #[test]
    fn flip_start_u128() {
        let res = flip_bit_at_index_u128(0, 0);
        assert_eq!(res, u128::pow(2, 127))
    }

    #[test]
    fn flip_end_u128() {
        let res = flip_bit_at_index_u128(0, 127);
        assert_eq!(res, 1)
    }

    #[test]
    fn flip_middle_u128() {
        let res = flip_bit_at_index_u128(0, 111);
        assert_eq!(res, u128::pow(2, 16))
    }

    #[test]
    fn increment_basic_v4() {
        let addr1: IpAddr = [0, 0, 0, 0].into();
        let addr2: IpAddr = [0, 0, 0, 1].into();
        assert_eq!(increment(addr1, 16).unwrap(), addr2);
    }

    #[test]
    fn increment_overflow_v4() {
        let addr1: IpAddr = [0, 0, 0, 255].into();
        let addr2: IpAddr = [0, 0, 1, 0].into();
        assert_eq!(increment(addr1, 16).unwrap(), addr2);
    }
    #[test]
    fn increment_out_of_bounds_simple_v4() {
        let addr1: IpAddr = [0, 0, 0, 255].into();
        assert!(increment(addr1, 24).is_err());
    }

    #[test]
    fn increment_out_of_bounds_simple_v4_specific() {
        let addr1: Ipv4Addr = [0, 0, 0, 255].into();
        assert!(incrementv4(addr1, 24).is_err());
    }

    #[test]
    fn increment_across_netmask_v4() {
        let mut ip: IpAddr = "192.168.0.0".parse().unwrap();
        let stop_ip: IpAddr = "192.168.255.255".parse().unwrap();
        while ip != stop_ip {
            let res = increment(ip, 16);
            assert!(res.is_ok());
            ip = res.unwrap();
        }
    }

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
}
