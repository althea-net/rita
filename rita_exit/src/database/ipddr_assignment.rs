use super::dualmap::DualMap;
use crate::database::get_exit_info;
use crate::RitaExitError;
use althea_kernel_interface::ExitClient;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState, Identity, WgKey};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use settings::exit::{ExitIpv4RoutingSettings, ExitIpv6RoutingSettings};
use settings::get_rita_exit;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Wg exit port on client side
pub const CLIENT_WG_PORT: u16 = 59999;

/// Max number of time we try to generate a valid ip addr before returning an eror
pub const MAX_IP_RETRIES: u8 = 10;

/// The biggest responsibility of the exit is to map user traffic to the internet. This struct keeps track
/// of the key data around internal and external ipv4 and ipv6 assignments. Across the various modes that
/// exits support.
#[derive(Clone, Debug)]
pub struct ClientListAnIpAssignmentMap {
    /// Settings for ipv4 assignment, this includes the internal subnet as well as external nat settings
    ipv4_assignment_settings: ExitIpv4RoutingSettings,
    /// Settings for ipv6 assignment, fewer options than ipv4 as ipv6 traffic is never natted, can be none
    /// if the exit doesn't support ipv6
    ipv6_assignment_settings: Option<ExitIpv6RoutingSettings>,
    /// A map of ipv6 subnets assigned to clients, these are used both internally and externally since
    /// there's no address translation, meaning the traffic maintains the same ip from the client device
    /// all the way to the internet
    ipv6_assignments: DualMap<Ipv6Network, Identity>,
    /// A map of ipv4 addresses assigned to clients, these are used internally for the wg_exit tunnel
    /// and never external, the external ip is determined by the exit's nat settings
    internal_ip_assignments: DualMap<Ipv4Addr, Identity>,
    /// The external ip for a specific client or set of clients depending on the ipv4 nat mode. Under CGNAT
    /// each ip will have multiple fixed clients, under SNAT each ip will have one client
    external_ip_assignemnts: HashMap<Ipv4Addr, HashSet<Identity>>,
    /// A set of all clients that have been registered with the exit
    registered_clients: HashSet<Identity>,
}

impl ClientListAnIpAssignmentMap {
    pub fn new(
        clients: HashSet<Identity>,
        ipv6_settings: Option<ExitIpv6RoutingSettings>,
        ipv4_settings: ExitIpv4RoutingSettings,
    ) -> Self {
        ClientListAnIpAssignmentMap {
            ipv6_assignments: DualMap::new(),
            internal_ip_assignments: DualMap::new(),
            external_ip_assignemnts: HashMap::new(),
            registered_clients: clients,
            ipv4_assignment_settings: ipv4_settings,
            ipv6_assignment_settings: ipv6_settings,
        }
    }

    pub fn get_external_ip_assignments(&self) -> &HashMap<Ipv4Addr, HashSet<Identity>> {
        &self.external_ip_assignemnts
    }

    pub fn get_ipv4_settings(&self) -> &ExitIpv4RoutingSettings {
        &self.ipv4_assignment_settings
    }

    pub fn get_ipv6_settings(&self) -> Option<ExitIpv6RoutingSettings> {
        self.ipv6_assignment_settings.clone()
    }

    pub fn get_ipv6_assignments(&self) -> HashMap<Ipv6Network, Identity> {
        self.ipv6_assignments.clone().into_hashmap()
    }

    pub fn get_internal_ip_assignments(&self) -> HashMap<Ipv4Addr, Identity> {
        self.internal_ip_assignments.clone().into_hashmap()
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
            let current_internet_ipv6 = self.get_or_add_client_ipv6(client.global)?;

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

    /// Gets the clients external ipv4 ip depending on the nat mode of the exit
    pub fn get_or_add_client_external_ip(
        &mut self,
        their_record: Identity,
    ) -> Result<Option<Ipv4Addr>, Box<RitaExitError>> {
        match &self.ipv4_assignment_settings {
            ExitIpv4RoutingSettings::NAT => {
                // If we are in NAT mode, we don't assign external ips to clients
                // they will use the ip assigned to the exit
                Ok(None)
            }
            ExitIpv4RoutingSettings::CGNAT {
                subnet,
                static_assignments,
            } => {
                // check static assignmetns first
                for id in static_assignments {
                    if their_record == id.client_id {
                        // make sure we have assigned this clients external ip. in CGNAT mode static clients just get
                        // the same ip every time, they don't get that ip exclusively assigned to them, so adding to this
                        // list is mostly a way to load balance the clients across the available ips including any static assignments
                        // in that count.
                        match self.external_ip_assignemnts.get_mut(&id.client_external_ip) {
                            Some(clients) => {
                                clients.insert(their_record);
                            }
                            None => {
                                let mut new_clients = HashSet::new();
                                new_clients.insert(their_record);
                                self.external_ip_assignemnts
                                    .insert(id.client_external_ip, new_clients);
                            }
                        }

                        return Ok(Some(id.client_external_ip));
                    }
                }

                // check for already assigned ips
                for (ip, clients) in self.external_ip_assignemnts.iter() {
                    if clients.contains(&their_record) {
                        return Ok(Some(*ip));
                    }
                }

                // if we don't have a static assignment, we need to assign an ip, we should pick the ip with the fewest clients
                // note this code is designed for relatively small subnets, but since public ipv4 are so valuable it's improbable
                // anyone with a /8 is going to show up and use this.
                let mut possible_ips: Vec<Ipv4Addr> = subnet.into_iter().collect();
                // we don't want to assign the first ip in the subnet as it's the gateway
                possible_ips.remove(0);

                let mut target_ip = None;
                let mut last_num_assigned = usize::MAX;
                for ip in possible_ips {
                    match self.external_ip_assignemnts.get(&ip) {
                        Some(clients) => {
                            if clients.len() < last_num_assigned {
                                target_ip = Some(ip);
                                last_num_assigned = clients.len();
                            }
                        }
                        None => {
                            target_ip = Some(ip);
                            // may as well break here, it's impossible to do better than an ip unused
                            // by any other clients
                            break;
                        }
                    }
                }

                // finally we add the newly assigned ip to the list of clients
                let target_ip = target_ip.unwrap();
                match self.external_ip_assignemnts.get_mut(&target_ip) {
                    Some(clients) => {
                        clients.insert(their_record);
                    }
                    None => {
                        let mut new_clients = HashSet::new();
                        new_clients.insert(their_record);
                        self.external_ip_assignemnts.insert(target_ip, new_clients);
                    }
                }

                Ok(Some(target_ip))
            }
            ExitIpv4RoutingSettings::SNAT {
                subnet,
                static_assignments,
            } => {
                // unlike in CGNAT mode, in SNAT mode we assign clients an ip and they are exclusively assigned that ip
                // so we need to make sure the static ip assignments are handled first by building the full list
                for id in static_assignments {
                    // duplicate static assignments are a configuration error
                    let mut new_clients = HashSet::new();
                    new_clients.insert(id.client_id);
                    self.external_ip_assignemnts
                        .insert(id.client_external_ip, new_clients);
                }

                // check for already assigned ips
                for (ip, clients) in self.external_ip_assignemnts.iter() {
                    if clients.contains(&their_record) {
                        return Ok(Some(*ip));
                    }
                }

                // if we don't have a static assignment, we need to find an open ip and assign it
                let mut possible_ips: Vec<Ipv4Addr> = subnet.into_iter().collect();
                // we don't want to assign the first ip in the subnet as it's the gateway
                possible_ips.remove(0);

                let mut target_ip = None;
                for ip in possible_ips {
                    if !self.external_ip_assignemnts.contains_key(&ip) {
                        target_ip = Some(ip);
                        break;
                    }
                }

                match target_ip {
                    Some(ip) => {
                        // since this is SNAT we never have to deal with multiple clients on the same ip
                        let mut new_clients = HashSet::new();
                        new_clients.insert(their_record);
                        self.external_ip_assignemnts.insert(ip, new_clients);
                        Ok(Some(ip))
                    }
                    None => {
                        // we have exhausted all available ips, we can't assign this client an ip
                        Err(Box::new(RitaExitError::IpExhaustionError))
                    }
                }
            }
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

        if let Some(val) = self.internal_ip_assignments.get_by_value(&their_record) {
            return Ok(*val);
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
    ) -> Result<Option<Ipv6Network>, Box<RitaExitError>> {
        if let Some(val) = self.ipv6_assignments.get_by_value(&their_record) {
            return Ok(Some(*val));
        }

        if let Some(ipv6_settings) = self.get_ipv6_settings() {
            let exit_sub = ipv6_settings.subnet;
            let client_subnet_size = ipv6_settings.client_subnet_size;
            let wg_hash = hash_wgkey(their_record.wg_public_key);

            // if you hit this check your subnet size is too small to assign a single client, what gives?
            assert!(client_subnet_size >= exit_sub.prefix());
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
        let internet_ipv6 = self.get_or_add_client_ipv6(client)?;
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
    exit_sub: Ipv6Network,
    ind: u64,
    subprefix: u8,
) -> Result<Ipv6Network, Box<RitaExitError>> {
    // Covert the subnet's ip address into a u128 integer to allow for easy iterative
    // addition operations. To this u128, we add (interative_index * client_subnet_size)
    // and convert this result into an ipv6 addr. This is the starting ip in the client subnet
    //
    // For example, if we have exit subnet: fbad::1000/120, client subnet size is 124, index is 1
    // we do (fbad::1000).to_int() + (16 * 1) = fbad::1010/124 is the client subnet
    let net = Ipv6Network::new(exit_sub.network(), subprefix).unwrap();
    let net_as_int: u128 = net.network().into();

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
    use althea_types::identity::random_identity;
    use ipnetwork::{Ipv4Network, Ipv6Network};
    use settings::exit::{
        ClientIpv4StaticAssignment, ClientIpv6StaticAssignment, ExitIpv4RoutingSettings,
        ExitIpv6RoutingSettings,
    };
    use std::{
        collections::{HashMap, HashSet},
        vec,
    };

    pub fn get_ipv4_external_test_subnet() -> Ipv4Network {
        "10.0.0.0/24".parse().unwrap()
    }

    pub fn get_ipv6_external_test_subnet() -> Ipv6Network {
        "2602:FBAD:10::/32".parse().unwrap()
    }

    pub fn get_test_config_nat(
        static_assignments: Vec<ClientIpv6StaticAssignment>,
    ) -> ClientListAnIpAssignmentMap {
        let clients = HashSet::new();
        let ipv6_settings =
            ExitIpv6RoutingSettings::new(get_ipv6_external_test_subnet(), 64, static_assignments);
        let ipv4_settings = ExitIpv4RoutingSettings::NAT;
        ClientListAnIpAssignmentMap::new(clients, Some(ipv6_settings), ipv4_settings)
    }

    pub fn get_test_config_snat(
        static_assignments: Vec<ClientIpv4StaticAssignment>,
    ) -> ClientListAnIpAssignmentMap {
        let clients = HashSet::new();
        let ipv6_settings =
            ExitIpv6RoutingSettings::new(get_ipv6_external_test_subnet(), 64, vec![]);
        let ipv4_settings = ExitIpv4RoutingSettings::SNAT {
            subnet: get_ipv4_external_test_subnet(),
            static_assignments,
        };
        ClientListAnIpAssignmentMap::new(clients, Some(ipv6_settings), ipv4_settings)
    }

    pub fn get_test_config_cgnat(
        static_assignments: Vec<ClientIpv4StaticAssignment>,
    ) -> ClientListAnIpAssignmentMap {
        let clients = HashSet::new();
        let ipv6_settings =
            ExitIpv6RoutingSettings::new(get_ipv6_external_test_subnet(), 64, vec![]);
        let ipv4_settings = ExitIpv4RoutingSettings::CGNAT {
            subnet: get_ipv4_external_test_subnet(),
            static_assignments,
        };
        ClientListAnIpAssignmentMap::new(clients, Some(ipv6_settings), ipv4_settings)
    }

    #[test]
    fn test_cgnat_external_ip_assignment() {
        let static_assignments = vec![ClientIpv4StaticAssignment {
            client_id: random_identity(),
            client_external_ip: "10.0.0.2".parse().unwrap(),
        }];
        let mut data = get_test_config_cgnat(static_assignments.clone());

        // this way we ensure we always exhaust our test subnet, so that by the end of the test we can
        // check that we load balance clients across the available ips
        let num_clients = get_ipv4_external_test_subnet().size() * 4;
        let mut clients = vec![];

        // generate some clients
        for _ in 0..num_clients {
            clients.push(random_identity());
        }

        let mut assigned_ip_count = HashMap::new();

        // assign everyone an ip, make sure static assignments are respected
        for client in clients {
            let ip = data.get_or_add_client_external_ip(client).unwrap().unwrap();
            for assignment in static_assignments.iter() {
                if assignment.client_id == client {
                    assert_eq!(ip, assignment.client_external_ip);
                }
            }
            assigned_ip_count
                .entry(ip)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }
    }

    #[test]
    fn test_snat_external_ip_assignment() {
        let static_assignments = vec![ClientIpv4StaticAssignment {
            client_id: random_identity(),
            client_external_ip: "10.0.0.2".parse().unwrap(),
        }];
        let mut data = get_test_config_snat(static_assignments.clone());

        // this way we ensure we always exhaust our test subnet, so that by the end of the test we can
        // check that we can't assign any more ips
        let num_clients =
            get_ipv4_external_test_subnet().size() - static_assignments.len() as u32 - 1;
        let mut clients = vec![];

        // generate some clients
        for _ in 0..num_clients {
            clients.push(random_identity());
        }

        // assign everyone an ip, make sure static assignments are respected
        for client in clients {
            let ip = data.get_or_add_client_external_ip(client).unwrap().unwrap();
            for assignment in static_assignments.iter() {
                if assignment.client_id == client {
                    assert_eq!(ip, assignment.client_external_ip);
                }
            }
        }

        for assignment in data.get_external_ip_assignments() {
            assert_eq!(assignment.1.len(), 1);
        }

        // Ensure that assignments fail once the subnet is exhausted
        let extra_client = random_identity();
        let result = data.get_or_add_client_external_ip(extra_client);
        println!("{:?}", result);
        assert!(result.is_err());
    }

    #[test]
    fn test_internet_ipv6_assignment() {
        let static_assignments = vec![ClientIpv6StaticAssignment {
            client_id: random_identity(),
            client_subnet: "2602:fbad:fdcf:8cc8::/64".parse().unwrap(),
        }];
        let mut data = get_test_config_nat(static_assignments.clone());
        let dummy_client = random_identity();

        // static ip assignment check
        for static_assignment in static_assignments.iter() {
            let ip = data
                .get_or_add_client_ipv6(static_assignment.client_id)
                .unwrap()
                .unwrap();
            assert_eq!(ip, static_assignment.client_subnet);
        }

        // Generate a client subnet
        let ip = data.get_or_add_client_ipv6(dummy_client).unwrap().unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_ipv6_assignments().len() == 1);
        assert_eq!(*data.get_ipv6_assignments().get(&ip).unwrap(), dummy_client);

        // Try retrieving the same client
        let ip_2 = data.get_or_add_client_ipv6(dummy_client).unwrap().unwrap();
        assert_eq!(ip, ip_2);

        // Make sure no new entries in assignemnt db
        assert!(data.get_ipv6_assignments().len() == 1);
        assert_eq!(*data.get_ipv6_assignments().get(&ip).unwrap(), dummy_client);

        println!("Assigned Ip client 1: {:?}", ip);

        // Add a second client
        let dummy_client_2 = random_identity();

        // Generate a client subnet
        let ip = data
            .get_or_add_client_ipv6(dummy_client_2)
            .unwrap()
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_ipv6_assignments().len() == 2);
        assert_eq!(
            *data.get_ipv6_assignments().get(&ip).unwrap(),
            dummy_client_2
        );

        let ip_2 = data
            .get_or_add_client_ipv6(dummy_client_2)
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
        let mut dummy_client_3 = random_identity();
        dummy_client_3.eth_address = dummy_client_2.eth_address;

        // Generate a client subnet
        let ip = data
            .get_or_add_client_ipv6(dummy_client_3)
            .unwrap()
            .unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_ipv6_assignments().len() == 3);
        assert_eq!(
            *data.get_ipv6_assignments().get(&ip).unwrap(),
            dummy_client_3
        );

        let _ = data
            .get_or_add_client_ipv6(dummy_client_2)
            .unwrap()
            .unwrap();
        let ip_2 = data
            .get_or_add_client_ipv6(dummy_client_3)
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
        let mut data = get_test_config_nat(vec![]);
        let dummy_client = random_identity();
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
        let mut dummy_client_2 = random_identity();
        dummy_client_2.eth_address = dummy_client.eth_address;

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
        let net: Ipv6Network = "2602:FBAD::/40".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 64);
        assert_eq!(
            "2602:FBAD::/64".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let ret = generate_iterative_client_subnet(net, 1, 64);
        assert_eq!(
            "2602:FBAD:0:1::/64".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let ret = generate_iterative_client_subnet(net, 50, 64);
        assert_eq!(
            "2602:FBAD:0:32::/64".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let ret = generate_iterative_client_subnet(net, 2_u64.pow(24), 64);
        assert!(ret.is_err());

        let ret = generate_iterative_client_subnet(net, 0, 30);
        assert!(ret.is_err());

        // Simple subnet example
        let net: Ipv6Network = "fd00::1337/120".parse().unwrap();
        let ret = generate_iterative_client_subnet(net, 0, 124);
        assert_eq!(
            "fd00::1300/124".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let ret = generate_iterative_client_subnet(net, 2, 124);
        assert_eq!(
            "fd00::1320/124".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );

        let ret = generate_iterative_client_subnet(net, 15, 124);
        assert_eq!(
            "fd00::13f0/124".parse::<Ipv6Network>().unwrap(),
            ret.unwrap()
        );
        let ret = generate_iterative_client_subnet(net, 16, 124);
        assert!(ret.is_err());
    }
}
