use super::dualmap::DualMap;
use crate::database::get_exit_info;
use crate::rita_loop::RitaExitData;
use crate::RitaExitError;
use althea_kernel_interface::exit_server_tunnel::setup_client_snat;
use althea_kernel_interface::ExitClient;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState, Identity};
use ipnetwork::{IpNetwork, Ipv6Network};
use rita_common::CLIENT_WG_PORT;
use settings::exit::{ExitInternalIpv4Settings, ExitIpv4RoutingSettings, ExitIpv6RoutingSettings};
use settings::get_rita_exit;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

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
    /// Internal ip assignment settings, used between the exit and the client, never exposed to the internet
    internal_ipv4_assignment_settings: ExitInternalIpv4Settings,
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
    /// A map of clients that have been inactive for some time and their last checkin time. These will have their
    /// routes town down if they hit the downtime threshold in SNAT mode
    inactive_clients: HashMap<Identity, Instant>,
}

impl ClientListAnIpAssignmentMap {
    pub fn new(
        clients: HashSet<Identity>,
        ipv6_settings: Option<ExitIpv6RoutingSettings>,
        ipv4_settings: ExitIpv4RoutingSettings,
        internal_ipv4_settings: ExitInternalIpv4Settings,
    ) -> Self {
        ClientListAnIpAssignmentMap {
            ipv6_assignments: DualMap::new(),
            internal_ip_assignments: DualMap::new(),
            external_ip_assignemnts: HashMap::new(),
            registered_clients: clients,
            ipv4_assignment_settings: ipv4_settings,
            ipv6_assignment_settings: ipv6_settings,
            internal_ipv4_assignment_settings: internal_ipv4_settings,
            inactive_clients: HashMap::new(),
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

    pub fn get_ipv4_nat_mode(&self) -> &ExitIpv4RoutingSettings {
        &self.ipv4_assignment_settings
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

    /// Gets the status of a client, this may include assigning them an IP if there's no existing assignment
    pub fn get_client_status(
        &mut self,
        client: ExitClientIdentity,
    ) -> Result<ExitState, Box<RitaExitError>> {
        trace!("Checking if record exists for {:?}", client.global.mesh_ip);
        let exit = get_rita_exit();
        if self.is_client_registered(client.global) {
            trace!("record exists, updating");

            let current_ip: Ipv4Addr = self.get_or_add_client_internal_ip(client.global)?;
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
            ExitIpv4RoutingSettings::MASQUERADENAT => {
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
                possible_ips.pop(); // we don't want to assign the last ip in the subnet as it's the broadcast address

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
                gateway_ipv4,
                external_ipv4,
                broadcast_ipv4,
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
                possible_ips.remove(0); // we don't want to assign the first ip in the subnet as it's the subnet default .0

                let mut target_ip = None;
                for ip in possible_ips {
                    if ip == *gateway_ipv4 || ip == *broadcast_ipv4 || ip == *external_ipv4 {
                        continue;
                    }
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
    ) -> Result<Ipv4Addr, Box<RitaExitError>> {
        // check if we have already assigned an ip to this client
        if let Some(val) = self.internal_ip_assignments.get_by_value(&their_record) {
            return Ok(*val);
        }

        // the internal subnet might be very large, so we shouldn't collect this list.
        let mut possible_ips = self
            .internal_ipv4_assignment_settings
            .internal_subnet
            .into_iter();
        // drop the first element as it's the gateway ip, or our ip on the internal subnet
        possible_ips.next();
        // we assign the first available ip
        for ip in possible_ips {
            if !self.internal_ip_assignments.contains_key(&ip)
                && ip
                    != self
                        .internal_ipv4_assignment_settings
                        .internal_subnet
                        .broadcast()
            {
                self.internal_ip_assignments.insert(ip, their_record);
                return Ok(ip);
            }
        }

        // if we get here we have exhausted the internal subnet
        Err(Box::new(RitaExitError::IpExhaustionError))
    }

    pub fn get_or_add_client_ipv6(
        &mut self,
        their_record: Identity,
    ) -> Result<Option<Ipv6Network>, Box<RitaExitError>> {
        if let Some(ipv6_settings) = self.get_ipv6_settings() {
            // first we populate the static assignments
            for assignment in ipv6_settings.static_assignments.iter() {
                // validate should have chcked this
                assert!(assignment.client_subnet.is_subnet_of(ipv6_settings.subnet));
                self.ipv6_assignments
                    .insert(assignment.client_subnet, assignment.client_id);
            }
            // then we return the static assignment if it exists
            if let Some(val) = self.ipv6_assignments.get_by_value(&their_record) {
                return Ok(Some(*val));
            }

            // the starting ip, also the subnet assigned to the exit itself
            let start_ip = Ipv6Network::new(
                ipv6_settings.subnet.network(),
                ipv6_settings.client_subnet_size,
            )
            .unwrap();
            // drop the first subnet which is the exit's subnet
            let mut target_ip = ipv6_subnet_iter(start_ip, ipv6_settings.client_subnet_size);
            while ipv6_settings.subnet.is_supernet_of(target_ip) {
                if !self.ipv6_assignments.contains_key(&target_ip) {
                    self.ipv6_assignments.insert(target_ip, their_record);
                    return Ok(Some(target_ip));
                }
                target_ip = ipv6_subnet_iter(target_ip, ipv6_settings.client_subnet_size);
            }

            // if we get here we have exhausted the subnet
            Err(Box::new(RitaExitError::IpExhaustionError))
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
        let internal_ip = self.get_or_add_client_internal_ip(client)?;
        let internet_ipv6 = internet_ipv6.map(|a| a.into());

        Ok(ExitClient {
            mesh_ip: client.mesh_ip,
            internal_ip: IpAddr::V4(internal_ip),
            port: CLIENT_WG_PORT,
            public_key: client.wg_public_key,
            internet_ipv6,
        })
    }

    pub fn get_inactive_list(&self) -> HashMap<Identity, Instant> {
        self.inactive_clients.clone()
    }

    pub fn set_inactive_list(&mut self, list: HashMap<Identity, Instant>) {
        self.inactive_clients = list;
    }
}

/// quick display function for a neat error
pub fn display_hashset<T: ToString>(input: &HashSet<T>) -> String {
    let mut out = String::new();
    for item in input.iter() {
        write!(out, "{}, ", item.to_string()).unwrap();
    }
    out
}

/// For a given provided ipv6 address increment the subnet by the provided subnet size
/// effectively we mask the lower bits of the address to get the subnet, then increment
/// the subnet by the subnet size
pub fn ipv6_subnet_iter(input: Ipv6Network, subnet_size: u8) -> Ipv6Network {
    let increment: u128 = 1 << (128 - subnet_size);
    let mut val = input.network().to_bits();
    val += increment;
    Ipv6Network::new(Ipv6Addr::from(val), input.prefix()).unwrap()
}

// calls the iptables setup for each client in the list, and updates the exit info
// with the mapping of Identity to Ipv4 address
pub fn setup_clients_snat(clients_list: &HashSet<Identity>, rita_exit_info: &mut RitaExitData) {
    for client in clients_list {
        // if we can't unwrap here panic is fine- all ips have been exhausted
        let client_ext_ipv4 = rita_exit_info
            .get_or_add_client_external_ip(*client)
            .unwrap()
            .unwrap();
        let client_int_ipv4 = rita_exit_info
            .get_or_add_client_internal_ip(*client)
            .unwrap();
        match setup_client_snat(
            &settings::get_rita_exit().network.external_nic.unwrap(),
            client_ext_ipv4,
            client_int_ipv4,
        ) {
            Ok(_) => continue,
            Err(e) => {
                error!("Error setting up SNAT for client: {:?}", e);
                // continue on error, we don't want to stop the whole process in case just one client fails for whatever reason
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ipv6_subnet_iter, ClientListAnIpAssignmentMap};
    use althea_types::identity::random_identity;
    use ipnetwork::{Ipv4Network, Ipv6Network};
    use settings::exit::{
        ClientIpv4StaticAssignment, ClientIpv6StaticAssignment, ExitInternalIpv4Settings,
        ExitIpv4RoutingSettings, ExitIpv6RoutingSettings,
    };
    use std::{
        collections::{HashMap, HashSet},
        net::Ipv4Addr,
        vec,
    };

    pub fn get_ipv4_internal_test_subnet() -> Ipv4Network {
        "10.0.0.0/8".parse().unwrap()
    }

    // smaller test subnet for ipv4 exhaustion tests
    pub fn get_ipv4_small_internal_test_subnet() -> Ipv4Network {
        "10.0.0.0/24".parse().unwrap()
    }

    pub fn get_ipv4_external_test_subnet() -> Ipv4Network {
        "172.168.1.0/24".parse().unwrap()
    }

    pub fn get_ipv6_external_test_subnet() -> Ipv6Network {
        "2602:FBAD::/32".parse().unwrap()
    }

    pub fn get_ipv6_small_external_test_subnet() -> Ipv6Network {
        "2602:FBAD::/56".parse().unwrap()
    }

    pub fn get_test_config_nat(
        static_assignments: Vec<ClientIpv6StaticAssignment>,
    ) -> ClientListAnIpAssignmentMap {
        let ipv6_settings =
            ExitIpv6RoutingSettings::new(get_ipv6_external_test_subnet(), 64, static_assignments);
        ipv6_settings.validate().unwrap();
        let ipv4_settings = ExitIpv4RoutingSettings::MASQUERADENAT;
        ipv4_settings.validate().unwrap();
        let internal_ipv4_settings = ExitInternalIpv4Settings {
            internal_subnet: get_ipv4_internal_test_subnet(),
        };
        internal_ipv4_settings.validate().unwrap();
        ClientListAnIpAssignmentMap::new(
            HashSet::new(),
            Some(ipv6_settings),
            ipv4_settings,
            internal_ipv4_settings,
        )
    }

    pub fn get_test_config_snat(
        static_assignments: Vec<ClientIpv4StaticAssignment>,
    ) -> ClientListAnIpAssignmentMap {
        let ipv6_settings =
            ExitIpv6RoutingSettings::new(get_ipv6_external_test_subnet(), 64, vec![]);
        ipv6_settings.validate().unwrap();
        let ipv4_settings = ExitIpv4RoutingSettings::SNAT {
            subnet: get_ipv4_external_test_subnet(),
            static_assignments,
            gateway_ipv4: Ipv4Addr::new(172, 168, 1, 1),
            external_ipv4: Ipv4Addr::new(172, 168, 1, 2),
            broadcast_ipv4: Ipv4Addr::new(172, 168, 1, 255),
        };
        ipv4_settings.validate().unwrap();
        let internal_ipv4_settings = ExitInternalIpv4Settings {
            internal_subnet: get_ipv4_internal_test_subnet(),
        };
        internal_ipv4_settings.validate().unwrap();
        ClientListAnIpAssignmentMap::new(
            HashSet::new(),
            Some(ipv6_settings),
            ipv4_settings,
            internal_ipv4_settings,
        )
    }

    pub fn get_test_config_cgnat(
        static_assignments: Vec<ClientIpv4StaticAssignment>,
    ) -> ClientListAnIpAssignmentMap {
        let ipv6_settings =
            ExitIpv6RoutingSettings::new(get_ipv6_external_test_subnet(), 64, vec![]);
        ipv6_settings.validate().unwrap();
        let ipv4_settings = ExitIpv4RoutingSettings::CGNAT {
            subnet: get_ipv4_external_test_subnet(),
            static_assignments,
        };
        ipv4_settings.validate().unwrap();
        let internal_ipv4_settings = ExitInternalIpv4Settings {
            internal_subnet: get_ipv4_internal_test_subnet(),
        };
        internal_ipv4_settings.validate().unwrap();
        ClientListAnIpAssignmentMap::new(
            HashSet::new(),
            Some(ipv6_settings),
            ipv4_settings,
            internal_ipv4_settings,
        )
    }

    #[test]
    fn test_subnet_increment() {
        let subnet = "2602:fbad::/64".parse().unwrap();
        let next_subnet = ipv6_subnet_iter(subnet, 64);
        assert_eq!(next_subnet, "2602:fbad:0:1::/64".parse().unwrap());
    }

    #[test]
    fn test_subnet_of() {
        let supernet: Ipv6Network = "2602:fbad::/32".parse().unwrap();
        let subnet = "2602:fbad:0:1::/64".parse().unwrap();
        let not_subnet = "2602:fbaf:0:1::/64".parse().unwrap();
        assert!(supernet.is_supernet_of(subnet));
        assert!(!supernet.is_supernet_of(not_subnet));
    }

    #[test]
    fn test_cgnat_external_ip_assignment() {
        let static_assignments = vec![ClientIpv4StaticAssignment {
            client_id: random_identity(),
            client_external_ip: "172.168.1.12".parse().unwrap(),
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
            client_external_ip: "172.168.1.12".parse().unwrap(),
        }];
        let mut data = get_test_config_snat(static_assignments.clone());

        // this way we ensure we always exhaust our test subnet, so that by the end of the test we can
        // check that we can't assign any more ips
        let num_clients =
            get_ipv4_external_test_subnet().size() - static_assignments.len() as u32 - 4;
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
            client_subnet: "2602:fbad:0:2a4::/64".parse().unwrap(),
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
        assert!(data.get_ipv6_assignments().len() == 2);
        assert_eq!(*data.get_ipv6_assignments().get(&ip).unwrap(), dummy_client);

        // Try retrieving the same client
        let ip_2 = data.get_or_add_client_ipv6(dummy_client).unwrap().unwrap();
        assert_eq!(ip, ip_2);

        // Make sure no new entries in assignemnt db
        assert!(data.get_ipv6_assignments().len() == 2);
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
        assert!(data.get_ipv6_assignments().len() == 3);
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
        assert!(data.get_ipv6_assignments().len() == 3);
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
        assert!(data.get_ipv6_assignments().len() == 4);
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
        assert!(data.get_ipv6_assignments().len() == 4);
        assert_eq!(
            *data.get_ipv6_assignments().get(&ip).unwrap(),
            dummy_client_3
        );

        println!("Assigned Ip client 3: {:?}", ip);
    }

    #[test]
    fn test_external_ipv6_subnet_exhaustion() {
        let internal_ipv4_settings = ExitInternalIpv4Settings {
            internal_subnet: get_ipv4_internal_test_subnet(),
        };
        internal_ipv4_settings.validate().unwrap();
        let ipv6_settings =
            ExitIpv6RoutingSettings::new(get_ipv6_small_external_test_subnet(), 64, vec![]);
        ipv6_settings.validate().unwrap();
        let mut data = ClientListAnIpAssignmentMap::new(
            HashSet::new(),
            Some(ipv6_settings.clone()),
            ExitIpv4RoutingSettings::MASQUERADENAT,
            internal_ipv4_settings,
        );

        // this way we ensure we always exhaust our test subnet, so that by the end of the test we can
        // check that we can't assign any more ips
        let num_clients = 2_usize.pow(
            (ipv6_settings.client_subnet_size - get_ipv6_small_external_test_subnet().prefix())
                as u32,
        ) - 1;
        let mut clients = vec![];

        // generate some clients
        for _ in 0..num_clients {
            clients.push(random_identity());
        }

        println!("Finished generating clients");

        // assign everyone an ip, make sure static assignments are respected
        for client in clients {
            let _ = data.get_or_add_client_ipv6(client).unwrap();
        }

        // Ensure that assignments fail once the subnet is exhausted
        let extra_client = random_identity();
        let result = data.get_or_add_client_ipv6(extra_client);
        println!("{:?}", result);
        assert!(result.is_err());
    }

    #[test]
    fn test_internal_ip_assignment() {
        let mut data = get_test_config_nat(vec![]);
        let dummy_client = random_identity();
        let ip = data.get_or_add_client_internal_ip(dummy_client).unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_internal_ip_assignments().len() == 1);
        assert_eq!(
            *data.get_internal_ip_assignments().get(&ip).unwrap(),
            dummy_client
        );

        // requesting the same client shouldnt change any state
        let ip2 = data.get_or_add_client_internal_ip(dummy_client).unwrap();

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

        let ip = data.get_or_add_client_internal_ip(dummy_client_2).unwrap();

        // Verify assignement db is correctly populated
        assert!(data.get_internal_ip_assignments().len() == 2);
        assert_eq!(
            *data.get_internal_ip_assignments().get(&ip).unwrap(),
            dummy_client_2
        );

        // requesting the same client shouldnt change any state
        let ip2 = data.get_or_add_client_internal_ip(dummy_client_2).unwrap();

        assert_eq!(ip, ip2);

        assert!(data.get_internal_ip_assignments().len() == 2);
        assert_eq!(
            *data.get_internal_ip_assignments().get(&ip2).unwrap(),
            dummy_client_2
        );

        println!("Internal ip client 2: {}", ip);
    }

    #[test]
    fn test_internal_ip_assignment_subnet_exhaustion() {
        let internal_ipv4_settings = ExitInternalIpv4Settings {
            internal_subnet: get_ipv4_small_internal_test_subnet(),
        };
        internal_ipv4_settings.validate().unwrap();
        let mut data = ClientListAnIpAssignmentMap::new(
            HashSet::new(),
            None,
            ExitIpv4RoutingSettings::MASQUERADENAT,
            internal_ipv4_settings,
        );

        // this way we ensure we always exhaust our test subnet, so that by the end of the test we can
        // check that we can't assign any more ips
        let num_clients = get_ipv4_small_internal_test_subnet().size() - 2;
        let mut clients = vec![];

        // generate some clients
        for _ in 0..num_clients {
            clients.push(random_identity());
        }

        // assign everyone an ip, make sure static assignments are respected
        for client in clients {
            let _ = data.get_or_add_client_internal_ip(client).unwrap();
        }

        // Ensure that assignments fail once the subnet is exhausted
        let extra_client = random_identity();
        let result = data.get_or_add_client_internal_ip(extra_client);
        println!("{:?}", result);
        assert!(result.is_err());
    }
}
