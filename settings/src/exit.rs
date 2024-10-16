use crate::localization::LocalizationSettings;
use crate::logging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::operator::ExitOperatorSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_exit, SettingsError};
use althea_types::{regions::Regions, ExitIdentity, Identity};
use clarity::Address;
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "rita_exit";

// IP serving exit lists from the root server back to clients
pub const EXIT_LIST_IP: &str = "10.11.12.13";
/// This is the port which exit lists are served over
pub const EXIT_LIST_PORT: u16 = 5566;
/// This is the network settings specific to rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitNetworkSettings {
    /// This is the port which the exit registration happens over, and should only be accessible
    /// over the mesh
    pub exit_hello_port: u16,
    /// This is the port which the exit tunnel listens on
    pub wg_tunnel_port: u16,
    pub wg_v2_tunnel_port: u16,
    /// Price in wei per byte which is charged to traffic both coming in and out over the internet
    pub exit_price: u64,
    /// This is the exit's own ip/gateway ip in the exit wireguard tunnel
    pub own_internal_ip: Ipv4Addr,
    /// The netmask, in bits to mask out, for the exit tunnel
    pub netmask: u8,
    /// The subnet we use to assign to client routers for ipv6
    pub subnet: Option<IpNetwork>,
    /// The specified client subnet, else use /56
    pub client_subnet_size: Option<u8>,
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

fn default_allowed_countries() -> HashSet<Regions> {
    HashSet::new()
}

fn enable_enforcement_default() -> bool {
    true
}

impl ExitNetworkSettings {
    /// Generates a configuration that can be used in integration tests, does not use the
    /// default trait to prevent some future code from picking up on the 'default' implementation
    /// and actually using it. Since obviously hardcoded keys are not at all secure
    pub fn test_default() -> Self {
        ExitNetworkSettings {
            exit_hello_port: 4875,
            wg_tunnel_port: 59999,
            wg_v2_tunnel_port: 59998,
            exit_price: 10,
            own_internal_ip: "172.16.255.254".parse().unwrap(),
            netmask: 12,
            subnet: Some(IpNetwork::V6("ff01::0/128".parse().unwrap())),
            client_subnet_size: None,
            geoip_api_user: None,
            geoip_api_key: None,
            enable_enforcement: true,
            registered_users_contract_addr: "0x9BAbFde52Fe18A5CD00a542b87b4D124a4879582"
                .parse()
                .unwrap(),
            allowed_countries: HashSet::new(),
        }
    }
}

fn default_remote_log() -> bool {
    false
}
pub fn default_reg_url() -> String {
    "https://operator.althea.net:8080/register_router".to_string()
}

/// This is the main settings struct for rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct RitaExitSettingsStruct {
    /// url exit uses to request a clients registration
    #[serde(default = "default_reg_url")]
    pub client_registration_url: String,
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
    /// This is the Address/Pubkey of the exit root of trust server which clients use to verify signed exit lists
    pub allowed_exit_list_signatures: Vec<Address>,
    /// url to the exit root of trust server to query exit lists
    pub exit_root_url: String,
}

impl RitaExitSettingsStruct {
    /// Returns true if the settings are valid
    pub fn validate(&self) -> bool {
        self.payment.validate()
    }

    /// Generates a configuration that can be used in integration tests, does not use the
    /// default trait to prevent some future code from picking up on the 'default' implementation
    pub fn test_default() -> Self {
        RitaExitSettingsStruct {
            client_registration_url: "".to_string(),
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
            allowed_exit_list_signatures: Vec::new(),
            exit_root_url: "".to_string(),
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
            wg_exit_listen_port: self.exit_network.wg_v2_tunnel_port,
            allowed_regions: self.allowed_countries.clone(),
            payment_types: set,
        }
    }

    pub fn get_client_subnet_size(&self) -> Option<u8> {
        self.exit_network.client_subnet_size
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
