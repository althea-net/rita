use crate::localization::LocalizationSettings;
use crate::logging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::operator::ExitOperatorSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_exit, SettingsError};
use althea_types::{regions::Regions, ExitIdentity, Identity};
use clarity::Address;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "rita_exit";

// IP serving exit lists from the root server back to clients
// this unique address is multihomed across every exit server so that
// clients can always call the nearest exit and get the signed list
pub const EXIT_LIST_IP: Ipv6Addr = Ipv6Addr::new(
    0xfd00, 0xca11, 0xc0de, 0xcafe, 0x0000, 0x0000, 0x0000, 0x0001,
);
/// This is the port which exit lists are served over
pub const EXIT_LIST_PORT: u16 = 5566;
/// Represents a static ipv4 assignment for a client
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ClientIpv4StaticAssignment {
    pub client_id: Identity,
    pub client_external_ip: Ipv4Addr,
}

/// Represents a static ipv6 assignment for a client
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ClientIpv6StaticAssignment {
    pub client_id: Identity,
    pub client_subnet: Ipv6Network,
}

/// This enum describes the different ways we can route ipv4 traffic out of the exit
/// and assign addresses to clients
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum ExitIpv4RoutingSettings {
    /// The default and simplest option, all clients are NAT'd out of the exit's own IP
    MASQUERADENAT,
    /// A provided subnet of ipv4 addresses is split between clients as evenly as possible
    /// the exits own ip is used only for management traffic and the exit's own traffic
    /// IP's from this range can be assigned to specific clients. In that case traffic for other
    /// customers will be distributed as evenly as possible over the remaining addresses
    CGNAT {
        subnet: Ipv4Network,
        static_assignments: Vec<ClientIpv4StaticAssignment>,
        gateway_ipv4: Ipv4Addr,
        external_ipv4: Ipv4Addr,
        broadcast_ipv4: Ipv4Addr,
    },
    /// A provided subnet of ipv4 addresses is assigned one by one to clients as they connect. With an optional
    /// list of static assignments for clients that will always be assigned the same IP. Use this option with caution
    /// if the subnet is too small and too many clients connect there will be no more addresses to assign. Once that happens
    /// the exit will stop accepting new connections until a client disconnects. Be mindful, in cases where a client can not
    /// find another exit to connect to they will be unable to access the internet.
    SNAT {
        subnet: Ipv4Network,
        /// upstream isp's ipv4 addr as seen by the exit
        gateway_ipv4: Ipv4Addr,
        /// exit's own external ipv4 addr as seen by the upstream isp
        external_ipv4: Ipv4Addr,
        /// broadcast ipv4 addr for the exit's external network
        broadcast_ipv4: Ipv4Addr,
        static_assignments: Vec<ClientIpv4StaticAssignment>,
    },
}

impl ExitIpv4RoutingSettings {
    pub fn validate(&self) -> Result<(), SettingsError> {
        match self {
            ExitIpv4RoutingSettings::MASQUERADENAT => Ok(()),
            ExitIpv4RoutingSettings::CGNAT {
                subnet,
                static_assignments,
                ..
            } => {
                for assignment in static_assignments {
                    if !subnet.contains(assignment.client_external_ip) {
                        return Err(SettingsError::InvalidIpv4Configuration(
                            "Static assignment outside of subnet".to_string(),
                        ));
                    }
                }
                if static_assignments.len() as u32 > subnet.size() {
                    return Err(SettingsError::InvalidIpv4Configuration(
                        "Not enough addresses in subnet for static assignments".to_string(),
                    ));
                }

                Ok(())
            }
            ExitIpv4RoutingSettings::SNAT {
                static_assignments,
                subnet,
                ..
            } => {
                let mut used_ips = HashSet::new();
                for assignment in static_assignments {
                    if used_ips.contains(&assignment.client_external_ip) {
                        return Err(SettingsError::InvalidIpv4Configuration(
                            "Duplicate static assignment".to_string(),
                        ));
                    }
                    if !subnet.contains(assignment.client_external_ip) {
                        return Err(SettingsError::InvalidIpv4Configuration(
                            "Static assignment outside of subnet".to_string(),
                        ));
                    }
                    used_ips.insert(assignment.client_external_ip);
                }
                if static_assignments.len() as u32 > subnet.size() {
                    return Err(SettingsError::InvalidIpv4Configuration(
                        "Not enough addresses in subnet for static assignments".to_string(),
                    ));
                }

                Ok(())
            }
        }
    }
}

/// This struct describes the settings for ipv6 routing out of the exit and assignment to clients
/// the only knob here is the subnet size, which is the size of the subnet assigned to each client
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitIpv6RoutingSettings {
    pub subnet: Ipv6Network,
    pub client_subnet_size: u8,
    pub static_assignments: Vec<ClientIpv6StaticAssignment>,
}
impl ExitIpv6RoutingSettings {
    pub fn new(
        subnet: Ipv6Network,
        client_subnet_size: u8,
        static_assignments: Vec<ClientIpv6StaticAssignment>,
    ) -> Self {
        ExitIpv6RoutingSettings {
            subnet,
            client_subnet_size,
            static_assignments,
        }
    }
}

impl ExitIpv6RoutingSettings {
    pub fn spit_ip_prefix(&self) -> (IpAddr, u8) {
        (self.subnet.ip().into(), self.subnet.prefix())
    }

    pub fn validate(&self) -> Result<(), SettingsError> {
        if self.client_subnet_size < self.subnet.prefix() {
            return Err(SettingsError::InvalidIpv6Configuration(
                "Client subnet size is larger than the exit subnet".to_string(),
            ));
        }
        for assignment in self.static_assignments.iter() {
            if !assignment.client_subnet.is_subnet_of(self.subnet) {
                return Err(SettingsError::InvalidIpv6Configuration(
                    "Static assignment outside of subnet".to_string(),
                ));
            }
            if assignment.client_subnet.prefix() != self.client_subnet_size {
                return Err(SettingsError::InvalidIpv6Configuration(
                    "Static assignment subnet size does not match exit subnet size".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// The settings for the exit's internal ipv4 network, this is the internal subnet that the exit uses to
/// NAT traffic. If this subnet is to small for the number of active users the exit will run out of addresses
/// to assign to clients and will stop accepting new connections. Note "active" in this context means users we
/// have seen since the last exit restart. By default the internal ip of the exit will be the first ip in this
/// subnet, and the exit will assign the rest of the addresses to clients
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitInternalIpv4Settings {
    pub internal_subnet: Ipv4Network,
}

impl ExitInternalIpv4Settings {
    pub fn internal_ip(&self) -> Ipv4Addr {
        self.internal_subnet.ip()
    }

    pub fn prefix(&self) -> u8 {
        self.internal_subnet.prefix()
    }

    pub fn validate(&self) -> Result<(), SettingsError> {
        if !self.internal_subnet.network().is_private() {
            return Err(SettingsError::InvalidIpv4Configuration(
                "Internal subnet is not private".to_string(),
            ));
        }
        Ok(())
    }
}

/// This is the network settings specific to rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitNetworkSettings {
    /// This is the port which the exit registration happens over, and should only be accessible
    /// over the mesh
    pub exit_hello_port: u16,
    /// This is the port which the exit tunnel listens on
    pub wg_tunnel_port: u16,
    /// Price in wei per byte which is charged to traffic both coming in and out over the internet
    pub exit_price: u64,
    /// Settings controlling the exits external ipv4 network and how traffic is routed there
    #[serde(default = "default_ipv4_routing")]
    pub ipv4_routing: ExitIpv4RoutingSettings,
    /// Settings controlling the internal subnet used for NAT And CGNAT
    #[serde(default = "default_internal_ipv4")]
    pub internal_ipv4: ExitInternalIpv4Settings,
    /// Settings controlled the exits external ipv6 network and how traffic is routed there
    /// None if no ipv6 is available
    pub ipv6_routing: Option<ExitIpv6RoutingSettings>,
    /// api credentials for Maxmind geoip
    pub geoip_api_user: Option<String>,
    pub geoip_api_key: Option<String>,
    /// Determines if enforcement is ensabled on the wg_exit interfaces, the htb classifier used here
    /// is slower than we would like, and therefore overloaded exits may wish to disable enforcment
    /// to maintain a good user experience while migrating users or waiting on a faster enforcement classifier
    #[serde(default = "enable_enforcement_default")]
    pub enable_enforcement: bool,
    /// Address of the Althea contract to store registered users data
    pub registered_users_contract_addr: Address,
    /// List of countries this exit will accept connections from, empty value means no restriction
    /// values will be ignored if geoip_api_user and geoip_api_key are not set
    #[serde(default = "default_allowed_countries")]
    pub allowed_countries: HashSet<Regions>,
}

impl ExitNetworkSettings {
    pub fn get_ipv6_subnet(&self) -> Option<Ipv6Network> {
        self.ipv6_routing.as_ref().map(|x| x.subnet)
    }

    pub fn get_ipv6_subnet_alt(&self) -> Option<IpNetwork> {
        self.ipv6_routing.as_ref().map(|x| x.subnet.into())
    }
}

fn default_allowed_countries() -> HashSet<Regions> {
    HashSet::new()
}

fn enable_enforcement_default() -> bool {
    true
}

fn default_ipv4_routing() -> ExitIpv4RoutingSettings {
    ExitIpv4RoutingSettings::MASQUERADENAT
}

fn default_internal_ipv4() -> ExitInternalIpv4Settings {
    ExitInternalIpv4Settings {
        internal_subnet: Ipv4Network::new(Ipv4Addr::new(172, 16, 255, 254), 12).unwrap(),
    }
}

impl ExitNetworkSettings {
    /// Generates a configuration that can be used in integration tests, does not use the
    /// default trait to prevent some future code from picking up on the 'default' implementation
    /// and actually using it. Since obviously hardcoded keys are not at all secure
    pub fn test_default() -> Self {
        ExitNetworkSettings {
            exit_hello_port: 4875,
            wg_tunnel_port: 59999,
            exit_price: 10,
            geoip_api_user: None,
            geoip_api_key: None,
            enable_enforcement: true,
            registered_users_contract_addr: "0x9BAbFde52Fe18A5CD00a542b87b4D124a4879582"
                .parse()
                .unwrap(),
            allowed_countries: HashSet::new(),
            ipv4_routing: ExitIpv4RoutingSettings::MASQUERADENAT,
            internal_ipv4: ExitInternalIpv4Settings {
                internal_subnet: Ipv4Network::new(Ipv4Addr::new(172, 16, 255, 254), 12).unwrap(),
            },
            ipv6_routing: None,
        }
    }

    pub fn validate(&self) -> bool {
        let ipv6_status = match self.ipv6_routing {
            Some(ref x) => x.validate().is_ok(),
            None => true,
        };
        ipv6_status && self.ipv4_routing.validate().is_ok() && self.internal_ipv4.validate().is_ok()
    }
}

fn default_remote_log() -> bool {
    false
}
pub fn default_root_url() -> String {
    "https://exitroot.althea.net:4050".to_string()
}

/// This is the main settings struct for rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct RitaExitSettingsStruct {
    /// the size of the worker thread pool, the connection pool is this plus one
    pub workers: u32,
    /// if we should log remotely or if we should send our logs to the logging server
    #[serde(default = "default_remote_log")]
    pub remote_log: bool,
    #[serde(default)]
    pub log: LoggingSettings,
    /// The description of this exit, what is sent to clients and displayed to the user
    pub description: String,
    pub payment: PaymentSettings,
    #[serde(default)]
    pub localization: LocalizationSettings,
    pub network: NetworkSettings,
    pub exit_network: ExitNetworkSettings,
    #[serde(default)]
    pub operator: ExitOperatorSettings,
    /// Countries which the clients to the exit are allowed from, blank for no geoip validation.
    /// (ISO country code)
    #[serde(skip_serializing_if = "HashSet::is_empty", default)]
    pub allowed_countries: HashSet<Regions>,
    /// url to the exit root of trust server to query exit lists, and make registration requests
    #[serde(default = "default_root_url")]
    pub exit_root_url: String,
}

impl RitaExitSettingsStruct {
    /// Returns true if the settings are valid
    pub fn validate(&self) -> bool {
        self.payment.validate() && self.exit_network.validate()
    }

    /// Generates a configuration that can be used in integration tests, does not use the
    /// default trait to prevent some future code from picking up on the 'default' implementation
    pub fn test_default() -> Self {
        RitaExitSettingsStruct {
            workers: 1,
            remote_log: false,
            description: "".to_string(),
            payment: PaymentSettings::default(),
            localization: LocalizationSettings::default(),
            network: NetworkSettings::default(),
            operator: ExitOperatorSettings::default(),
            exit_network: ExitNetworkSettings::test_default(),
            allowed_countries: HashSet::new(),
            log: LoggingSettings::default(),
            exit_root_url: "http://10.0.0.1:4050".to_string(),
        }
    }

    pub fn get_identity(&self) -> Option<Identity> {
        Some(Identity::new(
            self.network.mesh_ip?,
            self.payment.eth_address?,
            self.network.wg_public_key?,
            self.network.nickname,
        ))
    }

    pub fn get_exit_identity(&self) -> ExitIdentity {
        let id = self.get_identity().unwrap();
        let mut set = HashSet::new();
        set.insert(self.payment.system_chain);
        ExitIdentity {
            mesh_ip: id.mesh_ip,
            wg_key: id.wg_public_key,
            eth_addr: id.eth_address,
            registration_port: self.exit_network.exit_hello_port,
            wg_exit_listen_port: self.exit_network.wg_tunnel_port,
            allowed_regions: self.allowed_countries.clone(),
            payment_types: set,
        }
    }

    pub fn get_client_subnet_size(&self) -> Option<u8> {
        self.exit_network
            .ipv6_routing
            .as_ref()
            .map(|x| x.client_subnet_size)
    }

    pub fn get_all(&self) -> Result<serde_json::Value, SettingsError> {
        Ok(serde_json::to_value(self.clone())?)
    }

    pub fn merge(&mut self, changed_settings: serde_json::Value) -> Result<(), SettingsError> {
        let mut settings_value = serde_json::to_value(self.clone())?;

        json_merge(&mut settings_value, &changed_settings);

        match serde_json::from_value(settings_value) {
            Ok(new_settings) => {
                *self = new_settings;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn new(file_name: &str) -> Result<Self, SettingsError> {
        if !Path::new(file_name).exists() {
            return Err(SettingsError::FileNotFoundError(file_name.to_string()));
        }

        let config_toml = std::fs::read_to_string(file_name)?;
        let ret: Self = toml::from_str(&config_toml)?;
        Ok(ret)
    }

    pub fn new_watched(file_name: PathBuf) -> Result<Self, SettingsError> {
        if !Path::new(&file_name).exists() {
            return Err(SettingsError::FileNotFoundError(
                file_name.as_os_str().to_string_lossy().to_string(),
            ));
        }

        let config_toml = std::fs::read_to_string(file_name)?;
        let ret: Self = toml::from_str(&config_toml)?;

        set_rita_exit(ret.clone());

        Ok(ret)
    }
}
