use failure::Error;
use std::net::IpAddr;

/// adds one to whole netmask ip addresses
pub fn increment(address: IpAddr, netmask: u8) -> Result<IpAddr, Error> {
    assert_eq!(netmask % 8, 0);
    // same algorithm for either path, couldn't converge the codepaths
    // without having to play with slices for oct
    match address {
        IpAddr::V4(address) => {
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
        IpAddr::V6(address) => {
            // the number of bytes we can cover using this netmask
            let bytes_to_modify = ((128 - netmask) + 7) / 8;
            assert!(netmask <= 128);
            assert!(bytes_to_modify <= 16);
            assert!(bytes_to_modify > 0);

            let mut carry = false;
            let mut oct = address.octets();
            for i in ((16 - bytes_to_modify)..16).rev() {
                let index = i as usize;
                if i == (15 - bytes_to_modify) && oct[index] == 255 && carry {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let addr1: IpAddr = [0, 0, 255, 255].into();
        assert!(increment(addr1, 16).is_err());
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
