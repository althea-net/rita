use althea_types::{Identity, WgKey};
use ipnetwork::{IpNetwork, Ipv6Network};

use crate::RitaExitError;
use std::net::{IpAddr, Ipv6Addr};

// Default Subnet size assigned to each client
pub const DEFAULT_CLIENT_SUBNET_SIZE: u8 = 56;

/// Take an index i, a larger subnet and a smaller subnet length and generate the ith smaller subnet in the larger subnet
/// For instance, if our larger subnet is fd00::1330/120, smaller sub len is 124, and index is 1, our generated subnet would be fd00::1310/124
pub fn generate_iterative_client_subnet(
    exit_sub: IpNetwork,
    ind: u64,
    subprefix: u8,
) -> Result<IpNetwork, Box<RitaExitError>> {
    let net;

    // Covert the subnet's ip address into a u128 integer to allow for easy iterative
    // addition operations. To this u128, we add (interative_index * client_subnet_size)
    // and convert this result into an ipv6 addr. This is the starting ip in the client subnet
    //
    // For example, if we have exit subnet: fbad::1000/120, client subnet size is 124, index is 1
    // we do (fbad::1000).to_int() + (16 * 1) = fbad::1010/124 is the client subnet
    let net_as_int: u128 = if let IpAddr::V6(addr) = exit_sub.network() {
        net = Ipv6Network::new(addr, subprefix).unwrap();
        addr.into()
    } else {
        return Err(Box::new(RitaExitError::MiscStringError(
            "Exit subnet expected to be ipv6!!".to_string(),
        )));
    };

    if subprefix < exit_sub.prefix() {
        return Err(Box::new(RitaExitError::MiscStringError(
            "Client subnet larger than exit subnet".to_string(),
        )));
    }

    // This bitshifting is the total number of client subnets available. We are checking that our iterative index
    // is lower than this number. For example, exit subnet: fd00:1000/120, client subnet /124, number of subnets will be
    // 2^(124 - 120) => 2^4 => 16
    if ind < (1 << (subprefix - exit_sub.prefix())) {
        let ret = net_as_int + (ind as u128 * net.size());
        let v6addr = Ipv6Addr::from(ret);
        let ret = IpNetwork::from(match Ipv6Network::new(v6addr, subprefix) {
            Ok(a) => a,
            Err(e) => {
                return Err(Box::new(RitaExitError::MiscStringError(format!(
                    "Unable to parse a valid client subnet: {e:?}"
                ))))
            }
        });

        Ok(ret)
    } else {
        error!(
            "Our index is larger than available subnets, either error in logic or no more subnets"
        );
        Err(Box::new(RitaExitError::MiscStringError(
            "Index larger than available subnets".to_string(),
        )))
    }
}

pub fn get_all_regsitered_clients() -> Vec<Identity> {
    unimplemented!()
}

pub fn get_registered_client_using_wgkey(_key: WgKey) -> Option<Identity> {
    unimplemented!()
}

pub fn get_clients_exit_cluster_list(_key: WgKey) -> Vec<Identity> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test iterative subnet generation
    #[test]
    fn test_generate_iterative_subnet() {
        // Complex subnet example
        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 64);
        assert_eq!("2602:FBAD::/64".parse::<IpNetwork>().unwrap(), ret.unwrap());

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 1, 64);
        assert_eq!(
            "2602:FBAD:0:1::/64".parse::<IpNetwork>().unwrap(),
            ret.unwrap()
        );

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 50, 64);
        assert_eq!(
            "2602:FBAD:0:32::/64".parse::<IpNetwork>().unwrap(),
            ret.unwrap()
        );

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 2_u64.pow(24), 64);
        assert!(ret.is_err());

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 30);
        assert!(ret.is_err());

        // Simple subnet example
        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 124);
        assert_eq!("fd00::1300/124".parse::<IpNetwork>().unwrap(), ret.unwrap());

        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 2, 124);
        assert_eq!("fd00::1320/124".parse::<IpNetwork>().unwrap(), ret.unwrap());

        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 15, 124);
        assert_eq!("fd00::13f0/124".parse::<IpNetwork>().unwrap(), ret.unwrap());

        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 16, 124);
        assert!(ret.is_err());
    }
}
