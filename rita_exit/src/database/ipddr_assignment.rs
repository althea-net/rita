use althea_kernel_interface::ExitClient;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState, Identity, WgKey};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use settings::get_rita_exit;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::database::get_exit_info;
use crate::RitaExitError;

/// Wg exit port on client side
pub const CLIENT_WG_PORT: u16 = 59999;

/// Max number of time we try to generate a valid ip addr before returning an eror
pub const MAX_IP_RETRIES: u8 = 10;

// Default Subnet size assigned to each client
pub const DEFAULT_CLIENT_SUBNET_SIZE: u8 = 56;

#[derive(Clone, Debug, Default)]
pub struct ClientListAnIpAssignmentMap {
    ipv6_assignments: HashMap<Ipv6Network, Identity>,
    internal_ip_assignments: HashMap<Ipv4Addr, Identity>,
    registered_clients: HashSet<Identity>,
}

impl ClientListAnIpAssignmentMap {
    pub fn new(clients: HashSet<Identity>) -> Self {
        ClientListAnIpAssignmentMap {
            ipv6_assignments: HashMap::new(),
            internal_ip_assignments: HashMap::new(),
            registered_clients: clients,
        }
    }

    pub fn get_ipv6_assignments(&self) -> HashMap<Ipv6Network, Identity> {
        self.ipv6_assignments.clone()
    }

    pub fn get_internal_ip_assignments(&self) -> HashMap<Ipv4Addr, Identity> {
        self.internal_ip_assignments.clone()
    }

    pub fn is_client_registered(&self, client: Identity) -> bool {
        self.registered_clients.contains(&client)
    }

    pub fn get_registered_clients(&self) -> HashSet<Identity> {
        self.registered_clients.clone()
    }

    pub fn set_registered_clients(&mut self, clients: HashSet<Identity>) {
        self.registered_clients = clients;
    }

    /// Returns true if the provided ipv4 address is valid for use between the client and the exit
    /// as the internal ip
    pub fn ip_is_valid_to_assign(
        &self,
        network: Ipv4Network,
        assigned_ip: Ipv4Addr,
        our_ip: Ipv4Addr,
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

        !self.internal_ip_assignments.contains_key(&assigned_ip)
    }

    /// Validates if an IPv6 subnet is valid to assign to a client
    pub fn is_ipv6_subnet_valid_to_assign(&self, client_subnet: Ipv6Network) -> bool {
        !self.ipv6_assignments.contains_key(&client_subnet)
    }

    /// Gets the status of a client, this may include assigning them an IP if there's no existing assignment
    pub fn get_client_status(
        &mut self,
        client: ExitClientIdentity,
    ) -> Result<ExitState, Box<RitaExitError>> {
        trace!("Checking if record exists for {:?}", client.global.mesh_ip);
        let exit = get_rita_exit();
        let exit_network = exit.exit_network.clone();
        let own_internal_ip = exit_network.internal_ipv4.internal_ip();
        let internal_netmask = exit_network.internal_ipv4.prefix();
        if self.is_client_registered(client.global) {
            trace!("record exists, updating");

            let current_ip: Ipv4Addr = self.get_or_add_client_internal_ip(
                client.global,
                internal_netmask,
                own_internal_ip,
            )?;
            let current_internet_ipv6 = self.get_or_add_client_ipv6(
                client.global,
                exit_network.get_ipv6_subnet_alt(),
                exit.get_client_subnet_size()
                    .unwrap_or(DEFAULT_CLIENT_SUBNET_SIZE),
            )?;

            let current_internet_ipv6: Option<IpNetwork> = current_internet_ipv6.map(|a| a.into());

            Ok(ExitState::Registered {
                our_details: ExitClientDetails {
                    client_internal_ip: IpAddr::V4(current_ip),
                    internet_ipv6_subnet: current_internet_ipv6,
                },
                general_details: get_exit_info(),
                message: "Registration OK".to_string(),
                identity: Box::new(exit.get_exit_identity()),
            })
        } else {
            Err(Box::new(RitaExitError::NoClientError))
        }
    }

    /// Given a client identity, get the clients internal ipv4 addr using the wgkey as a generative seed
    /// this is the ip used for the wg_exit tunnel for the client. Not the clients public ip visible to the internet
    /// which is determined by the NAT settings on the exit
    pub fn get_or_add_client_internal_ip(
        &mut self,
        their_record: Identity,
        netmask: u8,
        gateway_ip: Ipv4Addr,
    ) -> Result<Ipv4Addr, Box<RitaExitError>> {
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

        // check if we already have an ip for this client, TODO optimize this datastructure, it's optimized for generating
        // new ip, not for lookup, the generation process can be streamlined to avoid that.
        for (ip, id) in self.internal_ip_assignments.iter() {
            if *id == their_record {
                return Ok(*ip);
            }
        }

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
            if self.ip_is_valid_to_assign(network, internal_ip, gateway_ip) {
                self.internal_ip_assignments
                    .insert(internal_ip, their_record);
                return Ok(internal_ip);
            } else {
                retries += 1;
                generative_index = (generative_index + 1) % total_addresses;
                continue;
            }
        }
    }

    pub fn get_or_add_client_ipv6(
        &mut self,
        their_record: Identity,
        exit_sub: Option<IpNetwork>,
        client_subnet_size: u8,
    ) -> Result<Option<Ipv6Network>, Box<RitaExitError>> {
        // check if we already have an ip for this client, TODO optimize this datastructure, it's optimized for generating
        // new ip, not for lookup, the generation process can be streamlined to avoid that.
        for (ip, id) in self.ipv6_assignments.iter() {
            if *id == their_record {
                return Ok(Some(*ip));
            }
        }

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

                let client_subnet = generate_iterative_client_subnet(
                    exit_sub,
                    generative_index,
                    client_subnet_size,
                )?;

                if self.is_ipv6_subnet_valid_to_assign(client_subnet) {
                    self.ipv6_assignments.insert(client_subnet, their_record);
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

    /// Convert an identity into a rita exit client, this is used to setup the exit tunnel for a client
    /// if the client has not already been assigned an ip, it will be assigned one as the exit client
    /// is created
    pub fn id_to_exit_client(
        &mut self,
        client: Identity,
    ) -> Result<ExitClient, Box<RitaExitError>> {
        let internet_ipv6 = self.get_or_add_client_ipv6(
            client,
            settings::get_rita_exit().exit_network.get_ipv6_subnet_alt(),
            settings::get_rita_exit()
                .get_client_subnet_size()
                .unwrap_or(DEFAULT_CLIENT_SUBNET_SIZE),
        )?;
        let internal_ip = self.get_or_add_client_internal_ip(
            client,
            settings::get_rita_exit()
                .exit_network
                .internal_ipv4
                .prefix(),
            settings::get_rita_exit()
                .exit_network
                .internal_ipv4
                .internal_ip(),
        )?;
        let internet_ipv6 = internet_ipv6.map(|a| a.into());

        Ok(ExitClient {
            mesh_ip: client.mesh_ip,
            internal_ip: IpAddr::V4(internal_ip),
            port: CLIENT_WG_PORT,
            public_key: client.wg_public_key,
            internet_ipv6,
        })
    }
}

/// Take an index i, a larger subnet and a smaller subnet length and generate the ith smaller subnet in the larger subnet
/// For instance, if our larger subnet is fd00::1330/120, smaller sub len is 124, and index is 1, our generated subnet would be fd00::1310/124
pub fn generate_iterative_client_subnet(
    exit_sub: IpNetwork,
    ind: u64,
    subprefix: u8,
) -> Result<Ipv6Network, Box<RitaExitError>> {
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
        let ret = match Ipv6Network::new(v6addr, subprefix) {
            Ok(a) => a,
            Err(e) => {
                return Err(Box::new(RitaExitError::MiscStringError(format!(
                    "Unable to parse a valid client subnet: {e:?}"
                ))))
            }
        };

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

pub fn hash_wgkey(key: WgKey) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.to_string().hash(&mut hasher);
    hasher.finish()
}

/// quick display function for a neat error
pub fn display_hashset<T: ToString>(input: &HashSet<T>) -> String {
    let mut out = String::new();
    for item in input.iter() {
        write!(out, "{}, ", item.to_string()).unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hash_wgkey;
    use crate::{
        database::ipddr_assignment::generate_iterative_client_subnet, ClientListAnIpAssignmentMap,
    };
    use althea_types::Identity;
    use ipnetwork::{IpNetwork, Ipv6Network};
    use std::collections::HashSet;

    pub fn get_test_data() -> ClientListAnIpAssignmentMap {
        let clients = HashSet::new();
        ClientListAnIpAssignmentMap::new(clients)
    }

    #[test]
    fn test_internet_ipv6_assignment() {
        let mut data = get_test_data();
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
        let ip = data
            .get_or_add_client_ipv6(dummy_client, exit_sub, 128)
            .unwrap()
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_ipv6_assignments().len() == 1);
        assert_eq!(*data.get_ipv6_assignments().get(&ip).unwrap(), dummy_client);

        // Try retrieving the same client
        let ip_2 = data
            .get_or_add_client_ipv6(dummy_client, exit_sub, 128)
            .unwrap()
            .unwrap();
        assert_eq!(ip, ip_2);

        // Make sure no new entries in assignemnt db
        assert!(data.get_ipv6_assignments().len() == 1);
        assert_eq!(*data.get_ipv6_assignments().get(&ip).unwrap(), dummy_client);

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
        let ip = data
            .get_or_add_client_ipv6(dummy_client_2, exit_sub, 128)
            .unwrap()
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_ipv6_assignments().len() == 2);
        assert_eq!(
            *data.get_ipv6_assignments().get(&ip).unwrap(),
            dummy_client_2
        );

        let ip_2 = data
            .get_or_add_client_ipv6(dummy_client_2, exit_sub, 128)
            .unwrap()
            .unwrap();
        assert_eq!(ip, ip_2);

        // Make sure no new entries in assignemnt db
        assert!(data.get_ipv6_assignments().len() == 2);
        assert_eq!(
            *data.get_ipv6_assignments().get(&ip).unwrap(),
            dummy_client_2
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
        let ip = data
            .get_or_add_client_ipv6(dummy_client_3, exit_sub, 128)
            .unwrap()
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_ipv6_assignments().len() == 3);
        assert_eq!(
            *data.get_ipv6_assignments().get(&ip).unwrap(),
            dummy_client_3
        );

        let _ = data
            .get_or_add_client_ipv6(dummy_client_2, exit_sub, 128)
            .unwrap()
            .unwrap();
        let ip_2 = data
            .get_or_add_client_ipv6(dummy_client_3, exit_sub, 128)
            .unwrap()
            .unwrap();
        assert_eq!(ip, ip_2);

        // Make sure no new entries in assignemnt db
        assert!(data.get_ipv6_assignments().len() == 3);
        assert_eq!(
            *data.get_ipv6_assignments().get(&ip).unwrap(),
            dummy_client_3
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
        let mut data = get_test_data();
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
        let ip = data
            .get_or_add_client_internal_ip(dummy_client, 30, "172.168.0.100".parse().unwrap())
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_internal_ip_assignments().len() == 1);
        assert_eq!(
            *data.get_internal_ip_assignments().get(&ip).unwrap(),
            dummy_client
        );

        // requesting the same client shouldnt change any state
        let ip2 = data
            .get_or_add_client_internal_ip(dummy_client, 30, "172.168.0.100".parse().unwrap())
            .unwrap();

        assert_eq!(ip, ip2);

        assert!(data.get_internal_ip_assignments().len() == 1);
        assert_eq!(
            *data.get_internal_ip_assignments().get(&ip2).unwrap(),
            dummy_client
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

        let ip = data
            .get_or_add_client_internal_ip(dummy_client_2, 30, "172.168.0.100".parse().unwrap())
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_internal_ip_assignments().len() == 2);
        assert_eq!(
            *data.get_internal_ip_assignments().get(&ip).unwrap(),
            dummy_client_2
        );

        // requesting the same client shouldnt change any state
        let ip2 = data
            .get_or_add_client_internal_ip(dummy_client_2, 30, "172.168.0.100".parse().unwrap())
            .unwrap();

        assert_eq!(ip, ip2);

        assert!(data.get_internal_ip_assignments().len() == 2);
        assert_eq!(
            *data.get_internal_ip_assignments().get(&ip2).unwrap(),
            dummy_client_2
        );

        println!("Internal ip client 2: {}", ip);
    }

    /// Test iterative subnet generation
    #[test]
    fn test_generate_iterative_subnet() {
        // Complex subnet example
        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 64);
        assert_eq!(
            "2602:FBAD::/64".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 1, 64);
        assert_eq!(
            "2602:FBAD:0:1::/64".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let net: IpNetwork = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 50, 64);
        assert_eq!(
            "2602:FBAD:0:32::/64".parse::<Ipv6Network>().unwrap(),
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
        assert_eq!(
            "fd00::1300/124".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 2, 124);
        assert_eq!(
            "fd00::1320/124".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 15, 124);
        assert_eq!(
            "fd00::13f0/124".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );
        let net: IpNetwork = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 16, 124);
        assert!(ret.is_err());
    }
}
