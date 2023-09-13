use althea_kernel_interface::ExitClient;
use althea_types::{Identity, WgKey};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::RitaExitError;

use super::RITA_EXIT_STATE;

/// Wg exit port on client side
pub const CLIENT_WG_PORT: u16 = 59999;

/// Max number of time we try to generate a valid ip addr before returning an eror
pub const MAX_IP_RETRIES: u8 = 10;

// Default Subnet size assigned to each client
pub const DEFAULT_CLIENT_SUBNET_SIZE: u8 = 56;

#[derive(Clone, Debug, Default)]
pub struct IpAssignmentMap {
    pub ipv6_assignments: HashMap<IpAddr, WgKey>,
    pub internal_ip_assignments: HashMap<IpAddr, WgKey>,
}

// Lazy static setters/getters
pub fn get_ipv6_assignments() -> HashMap<IpAddr, WgKey> {
    RITA_EXIT_STATE
        .read()
        .unwrap()
        .ip_assignment_map
        .ipv6_assignments
        .clone()
}

pub fn get_internal_ip_assignments() -> HashMap<IpAddr, WgKey> {
    RITA_EXIT_STATE
        .read()
        .unwrap()
        .ip_assignment_map
        .internal_ip_assignments
        .clone()
}

pub fn add_new_ipv6_assignment(addr: IpAddr, key: WgKey) {
    RITA_EXIT_STATE
        .write()
        .unwrap()
        .ip_assignment_map
        .ipv6_assignments
        .insert(addr, key);
}

pub fn add_new_internal_ip_assignement(addr: IpAddr, key: WgKey) {
    RITA_EXIT_STATE
        .write()
        .unwrap()
        .ip_assignment_map
        .internal_ip_assignments
        .insert(addr, key);
}

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

/// Given a client identity, get the clients ipv6 addr using the wgkey as a generative seed
pub fn get_client_ipv6(
    their_record: Identity,
    exit_sub: Option<IpNetwork>,
    client_subnet_size: u8,
) -> Result<Option<IpNetwork>, Box<RitaExitError>> {
    if let Some(exit_sub) = exit_sub {
        let wg_hash = hash_wgkey(their_record.wg_public_key);

        // This bitshifting is the total number of client subnets available. We are checking that our iterative index
        // is lower than this number. For example, exit subnet: fd00:1000/120, client subnet /124, number of subnets will be
        // 2^(124 - 120) => 2^4 => 16
        let total_subnets = 1 << (client_subnet_size - exit_sub.prefix());
        let mut generative_index = wg_hash % total_subnets;

        // Loop to try to generate a valid address
        let mut retries = 0;
        loop {
            // Return an error if we retry too many times
            if retries > MAX_IP_RETRIES {
                return Err(Box::new(RitaExitError::MiscStringError(format!(
                    "Unable to get internet ipv6 using network {} and index {}",
                    exit_sub, generative_index
                ))));
            }

            let client_subnet =
                generate_iterative_client_subnet(exit_sub, generative_index, client_subnet_size)?;

            if validate_internet_ipv6(client_subnet, their_record.wg_public_key) {
                add_new_ipv6_assignment(client_subnet.ip(), their_record.wg_public_key);
                return Ok(Some(client_subnet));
            } else {
                retries += 1;
                generative_index = (generative_index + 1) % total_subnets;
                continue;
            }
        }
    } else {
        // This exit doesnt support ipv6
        Ok(None)
    }
}

/// Given a client identity, get the clients internal ip addr using the wgkey as a generative seed
pub fn get_client_internal_ip(
    their_record: Identity,
    netmask: u8,
    gateway_ip: Ipv4Addr,
) -> Result<IpAddr, Box<RitaExitError>> {
    let wg_hash = hash_wgkey(their_record.wg_public_key);
    // total number of available addresses
    let total_addresses: u64 = 2_u64.pow((32 - netmask).into());
    let mut generative_index = wg_hash % total_addresses;
    let network = match Ipv4Network::new(gateway_ip, netmask) {
        Ok(a) => a,
        Err(e) => {
            return Err(Box::new(RitaExitError::MiscStringError(format!(
                "Unable to setup and ipnetwork to generate internal ip {}",
                e
            ))))
        }
    };

    // Keep trying to generate an address till we get a valid one
    let mut retries = 0;
    loop {
        // Return an error if we retry too many times
        if retries > MAX_IP_RETRIES {
            return Err(Box::new(RitaExitError::MiscStringError(format!(
                "Unable to get internal ip using network {} and index {}",
                network, generative_index
            ))));
        }

        let internal_ip = network.nth(match generative_index.try_into() {
            Ok(a) => a,
            Err(e) => {
                warn!("Internal Ip failure: {}", e);
                retries += 1;
                generative_index = (generative_index + 1) % total_addresses;
                continue;
            }
        });

        let internal_ip = match internal_ip {
            Some(a) => a,
            None => {
                retries += 1;
                generative_index = (generative_index + 1) % total_addresses;
                continue;
            }
        };

        // Validate that this ip is valid and return it
        if validate_internal_ip(network, internal_ip, gateway_ip, their_record.wg_public_key) {
            add_new_internal_ip_assignement(IpAddr::V4(internal_ip), their_record.wg_public_key);
            return Ok(IpAddr::V4(internal_ip));
        } else {
            retries += 1;
            generative_index = (generative_index + 1) % total_addresses;
            continue;
        }
    }
}

/// Check that this ip can be assigned, make sure there isnt a collision with previously assigned ips
pub fn validate_internet_ipv6(client_subnet: IpNetwork, our_wgkey: WgKey) -> bool {
    let assigned_ips = get_ipv6_assignments();
    let assignment = assigned_ips.get(&client_subnet.ip());
    match assignment {
        Some(a) => {
            // There is an entry, verify if its our entry else false
            *a == our_wgkey
        }
        // There is no assigned ip here, ip is valid
        None => true,
    }
}

/// Check that this ip can be assigned, make sure it isnt our ip, network ip, broadcast ip, etc
pub fn validate_internal_ip(
    network: Ipv4Network,
    assigned_ip: Ipv4Addr,
    our_ip: Ipv4Addr,
    our_wgkey: WgKey,
) -> bool {
    let broadcast = network.broadcast();
    let network_ip = network.network();

    // Collision with our ip
    if assigned_ip == our_ip {
        return false;
    }
    // collision with the network ip
    if assigned_ip == network_ip {
        return false;
    }
    // collision with broadcast address
    if assigned_ip == broadcast {
        return false;
    }

    let assignments = get_internal_ip_assignments();
    let assignment = assignments.get(&IpAddr::V4(assigned_ip));
    match assignment {
        Some(a) => {
            // check if this existing ip is ours
            *a == our_wgkey
        }
        // No assignment, we can use this address
        None => true,
    }
}

pub fn to_exit_client(client: Identity) -> Result<ExitClient, Box<RitaExitError>> {
    let internet_ipv6 = get_client_ipv6(
        client,
        settings::get_rita_exit().exit_network.subnet,
        settings::get_rita_exit()
            .get_client_subnet_size()
            .unwrap_or(DEFAULT_CLIENT_SUBNET_SIZE),
    )?;
    let internal_ip = get_client_internal_ip(
        client,
        settings::get_rita_exit().exit_network.netmask,
        settings::get_rita_exit().exit_network.own_internal_ip,
    )?;

    Ok(ExitClient {
        mesh_ip: client.mesh_ip,
        internal_ip,
        port: CLIENT_WG_PORT,
        public_key: client.wg_public_key,
        internet_ipv6,
    })
}

pub fn hash_wgkey(key: WgKey) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.to_string().hash(&mut hasher);
    hasher.finish()
}

/// quick display function for a neat error
pub fn display_hashset(input: &HashSet<String>) -> String {
    let mut out = String::new();
    for item in input.iter() {
        write!(out, "{item}, ").unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use althea_types::Identity;
    use ipnetwork::IpNetwork;

    use crate::database::in_memory_database::{
        generate_iterative_client_subnet, get_client_internal_ip, get_internal_ip_assignments,
        get_ipv6_assignments,
    };

    use super::{get_client_ipv6, hash_wgkey};

    #[test]
    fn test_internet_ipv6_assignment() {
        let exit_sub = Some("2602:FBAD:10::/126".parse().unwrap());
        let dummy_client = Identity {
            mesh_ip: "fd00::1337".parse().unwrap(),
            eth_address: "0x4Af6D4125f3CBF07EBAD056E2eCa7b17c58AFEa4"
                .parse()
                .unwrap(),
            wg_public_key: "TgR85AcLBY/7cLHXZIICcwVDU+1Pj/cjFeduCUNvLVU="
                .parse()
                .unwrap(),
            nickname: None,
        };

        // Generate a client subnet
        let ip = get_client_ipv6(dummy_client, exit_sub, 128)
            .unwrap()
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(get_ipv6_assignments().len() == 1);
        assert_eq!(
            *get_ipv6_assignments().get(&ip.ip()).unwrap(),
            dummy_client.wg_public_key
        );

        // Try retrieving the same client
        let ip_2 = get_client_ipv6(dummy_client, exit_sub, 128)
            .unwrap()
            .unwrap();
        assert_eq!(ip, ip_2);

        // Make sure no new entries in assignemnt db
        assert!(get_ipv6_assignments().len() == 1);
        assert_eq!(
            *get_ipv6_assignments().get(&ip.ip()).unwrap(),
            dummy_client.wg_public_key
        );

        println!("Assigned Ip client 1: {:?}", ip);

        // Add a second client
        let dummy_client_2 = Identity {
            mesh_ip: "fd00::1447".parse().unwrap(),
            eth_address: "0x4Af6D4125f3CBF07EBAD056E2eCa7b17c58AFEa4"
                .parse()
                .unwrap(),
            wg_public_key: "CEnTMKvpWr+xTFl7niTYyqH56w5iPdMjiC938X542GA="
                .parse()
                .unwrap(),
            nickname: None,
        };

        // Generate a client subnet
        let ip = get_client_ipv6(dummy_client_2, exit_sub, 128)
            .unwrap()
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(get_ipv6_assignments().len() == 2);
        assert_eq!(
            *get_ipv6_assignments().get(&ip.ip()).unwrap(),
            dummy_client_2.wg_public_key
        );

        let ip_2 = get_client_ipv6(dummy_client_2, exit_sub, 128)
            .unwrap()
            .unwrap();
        assert_eq!(ip, ip_2);

        // Make sure no new entries in assignemnt db
        assert!(get_ipv6_assignments().len() == 2);
        assert_eq!(
            *get_ipv6_assignments().get(&ip.ip()).unwrap(),
            dummy_client_2.wg_public_key
        );

        println!("Assigned Ip client 2: {:?}", ip);

        // Generate a collision
        let dummy_client_3 = Identity {
            mesh_ip: "fd00::1557".parse().unwrap(),
            eth_address: "0x4Af6D4125f3CBF07EBAD056E2eCa7b17c58AFEa4"
                .parse()
                .unwrap(),
            wg_public_key: "+Iai9Qj5aIuTAq6h1srDL8yKElN65/PhNtkccSOJwls="
                .parse()
                .unwrap(),
            nickname: None,
        };

        // Generate a client subnet
        let ip = get_client_ipv6(dummy_client_3, exit_sub, 128)
            .unwrap()
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(get_ipv6_assignments().len() == 3);
        assert_eq!(
            *get_ipv6_assignments().get(&ip.ip()).unwrap(),
            dummy_client_3.wg_public_key
        );

        let _ = get_client_ipv6(dummy_client_2, exit_sub, 128)
            .unwrap()
            .unwrap();
        let ip_2 = get_client_ipv6(dummy_client_3, exit_sub, 128)
            .unwrap()
            .unwrap();
        assert_eq!(ip, ip_2);

        // Make sure no new entries in assignemnt db
        assert!(get_ipv6_assignments().len() == 3);
        assert_eq!(
            *get_ipv6_assignments().get(&ip.ip()).unwrap(),
            dummy_client_3.wg_public_key
        );

        println!("Assigned Ip client 3: {:?}", ip);
    }

    #[test]
    fn hash_playground() {
        let key_1_hash = hash_wgkey(
            "TgR85AcLBY/7cLHXZIICcwVDU+1Pj/cjFeduCUNvLVU="
                .parse()
                .unwrap(),
        ) % 4;
        println!("hash: {}", key_1_hash);
        let key_1_hash = hash_wgkey(
            "+Iai9Qj5aIuTAq6h1srDL8yKElN65/PhNtkccSOJwls="
                .parse()
                .unwrap(),
        ) % 4;
        println!("hash: {}", key_1_hash);
        let key_1_hash = hash_wgkey(
            "CEnTMKvpWr+xTFl7niTYyqH56w5iPdMjiC938X542GA="
                .parse()
                .unwrap(),
        ) % 4;
        println!("hash: {}", key_1_hash);
    }

    #[test]
    fn test_internal_ip_assignment() {
        let dummy_client = Identity {
            mesh_ip: "fd00::1337".parse().unwrap(),
            eth_address: "0x4Af6D4125f3CBF07EBAD056E2eCa7b17c58AFEa4"
                .parse()
                .unwrap(),
            wg_public_key: "TgR85AcLBY/7cLHXZIICcwVDU+1Pj/cjFeduCUNvLVU="
                .parse()
                .unwrap(),
            nickname: None,
        };
        let ip =
            get_client_internal_ip(dummy_client, 30, "172.168.0.100".parse().unwrap()).unwrap();

        // Verify assignement db is correctly populated
        assert!(get_internal_ip_assignments().len() == 1);
        assert_eq!(
            *get_internal_ip_assignments().get(&ip).unwrap(),
            dummy_client.wg_public_key
        );

        // requesting the same client shouldnt change any state
        let ip2 =
            get_client_internal_ip(dummy_client, 30, "172.168.0.100".parse().unwrap()).unwrap();

        assert_eq!(ip, ip2);

        assert!(get_internal_ip_assignments().len() == 1);
        assert_eq!(
            *get_internal_ip_assignments().get(&ip2).unwrap(),
            dummy_client.wg_public_key
        );

        println!("Internal ip client 1: {}", ip);

        // Second client who collides
        let dummy_client_2 = Identity {
            mesh_ip: "fd00::1557".parse().unwrap(),
            eth_address: "0x4Af6D4125f3CBF07EBAD056E2eCa7b17c58AFEa4"
                .parse()
                .unwrap(),
            wg_public_key: "+Iai9Qj5aIuTAq6h1srDL8yKElN65/PhNtkccSOJwls="
                .parse()
                .unwrap(),
            nickname: None,
        };

        let ip =
            get_client_internal_ip(dummy_client_2, 30, "172.168.0.100".parse().unwrap()).unwrap();

        // Verify assignement db is correctly populated
        assert!(get_internal_ip_assignments().len() == 2);
        assert_eq!(
            *get_internal_ip_assignments().get(&ip).unwrap(),
            dummy_client_2.wg_public_key
        );

        // requesting the same client shouldnt change any state
        let ip2 =
            get_client_internal_ip(dummy_client_2, 30, "172.168.0.100".parse().unwrap()).unwrap();

        assert_eq!(ip, ip2);

        assert!(get_internal_ip_assignments().len() == 2);
        assert_eq!(
            *get_internal_ip_assignments().get(&ip2).unwrap(),
            dummy_client_2.wg_public_key
        );

        println!("Internal ip client 2: {}", ip);
    }

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
