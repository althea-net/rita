use crate::localization::LocalizationSettings;
use crate::logging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::operator::OperatorSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_client, SettingsError};
use althea_types::exit_interop::ExitState;
use althea_types::Identity;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "rita";

pub const EXIT_CLIENT_LISTEN_PORT: u16 = 59999;

pub fn default_app_name() -> String {
    APP_NAME.to_string()
}

pub fn default_save_interval() -> u64 {
    172800
}

pub fn default_config_path() -> PathBuf {
    format!("/etc/{APP_NAME}.toml").into()
}

/// This struct represents a single exit server, it represents all the details needed
/// to connect to an exit and query this routers status and the exits info required for
/// setting up a working connection. We don't want to store more than this in our config
/// because it may go stale.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct ExitServer {
    /// This is the unique identity of the exit. Previously exit
    /// had a shared wg key and mesh ip, this struct needs to have unique
    /// meship, wgkey and ethaddress for each entry
    pub exit_id: Identity,

    /// The power we reach out to to hit the register endpoint
    /// also used for all other exit lifecycle management api calls
    #[serde(default = "default_registration_port")]
    pub registration_port: u16,
}

fn default_registration_port() -> u16 {
    4875
}

fn exit_db_smart_contract_on_xdai() -> String {
    "0x29a3800C28dc133f864C22533B649704c6CD7e15".to_string()
}

fn default_boostrapping_exits() -> HashSet<ExitServer> {
    HashSet::new()
}

fn default_registration_state() -> ExitState {
    ExitState::default()
}

/// This struct is used by rita to encapsulate all the state/information needed to connect/register
/// to a exit and to setup the exit tunnel
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitClientSettings {
    #[serde(default = "default_boostrapping_exits")]
    /// This map of exits is populated in the routers initial config. Once the router is up and running is it will query
    /// one or more of these exits to understand it's current status and to register with the exit database smart contract.
    /// Once regsitered and online this list may be populated with new exits through the chain of trust established by the
    /// bootstrapping process
    pub bootstrapping_exits: HashSet<ExitServer>,
    /// The registration state of this router with the exit database smart contract
    /// note this value may be affected by what contract is currently selected and what
    /// chain we are on. Since different chains may reference different registration smart contracts
    #[serde(default = "default_registration_state", flatten)]
    pub registration_state: ExitState,
    /// This is the address of the exit database contract on the xDai chain, this value is a config value in case
    /// a new version of the contract is ever deployed. Otherwise it won't change much. What this contract contains
    /// is the registration data for all routers, facilitating key exchange between new exits in the cluster and clients
    /// So the client registers with the smart contract and the exit takes it's registration data (wireguard key) and sets
    /// up a tunnel, vice versa for the client after bootstrapping by talking to an exit in it's config
    #[serde(default = "exit_db_smart_contract_on_xdai")]
    pub exit_db_smart_contract_on_xdai: String,
}

impl Default for ExitClientSettings {
    fn default() -> Self {
        ExitClientSettings {
            registration_state: default_registration_state(),
            bootstrapping_exits: default_boostrapping_exits(),
            exit_db_smart_contract_on_xdai: exit_db_smart_contract_on_xdai(),
        }
    }
}

impl RitaClientSettings {
    pub fn new(file_name: &str) -> Result<Self, SettingsError> {
        if !Path::new(file_name).exists() {
            error!(
                "Failed to find settings file at location {}, generating",
                file_name
            );
            return Ok(RitaClientSettings::default());
        }

        let config_toml = std::fs::read_to_string(file_name)?;
        let ret: Self = toml::from_str(&config_toml)?;
        Ok(ret)
    }

    pub fn new_watched(file_name: PathBuf) -> Result<Self, SettingsError> {
        if !file_name.exists() {
            return Err(SettingsError::FileNotFoundError(
                file_name.display().to_string(),
            ));
        }

        let config_toml = std::fs::read_to_string(file_name)?;
        let ret: Self = toml::from_str(&config_toml)?;

        set_rita_client(ret.clone());

        Ok(ret)
    }
}

/// This is the main struct for rita
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct RitaClientSettings {
    pub payment: PaymentSettings,
    #[serde(default)]
    pub log: LoggingSettings,
    #[serde(default)]
    pub operator: OperatorSettings,
    #[serde(default)]
    pub localization: LocalizationSettings,
    pub network: NetworkSettings,
    pub exit_client: ExitClientSettings,
    #[serde(default = "default_app_name")]
    pub app_name: String,
    /// The save interval defaults to 48 hours for exit settings represented in seconds
    #[serde(default = "default_save_interval")]
    pub save_interval: u64,
}

impl RitaClientSettings {
    /// This is a low level fn that mutates the current settings object, but does not save it.
    /// prefer the higher level settings::merge_config_json(new_settings), which calls this, to actually merge into memory
    pub fn merge(&mut self, changed_settings: serde_json::Value) -> Result<(), SettingsError> {
        let mut settings_value = serde_json::to_value(self.clone())?;

        info!("Merge is being called, maybe error here");

        json_merge(&mut settings_value, &changed_settings);

        match serde_json::from_value(settings_value) {
            Ok(new_settings) => {
                *self = new_settings;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_all(&self) -> Result<serde_json::Value, SettingsError> {
        Ok(serde_json::to_value(self.clone())?)
    }

    pub fn get_identity(&self) -> Option<Identity> {
        Some(Identity::new(
            self.network.mesh_ip?,
            self.payment.eth_address?,
            self.network.wg_public_key?,
            self.network.nickname,
        ))
    }
}
