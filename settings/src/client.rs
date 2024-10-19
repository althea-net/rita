use crate::logging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::operator::OperatorSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_client, SettingsError};
use althea_types::regions::Regions;
use althea_types::{ExitServerList, ExitState, Identity};
use clarity::Address;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "rita";

pub const DUMMY_ROOT_IP: &str = "1.1.1.1";

pub fn default_save_interval() -> u64 {
    172800
}

pub fn default_config_path() -> PathBuf {
    format!("/etc/{APP_NAME}.toml").into()
}

fn exit_db_smart_contract_on_xdai() -> String {
    "0x29a3800C28dc133f864C22533B649704c6CD7e15".to_string()
}

fn default_registration_state() -> ExitState {
    ExitState::default()
}

/// This struct is used by rita to encapsulate all the state/information needed to connect/register
/// to a exit and to setup the exit tunnel
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitClientSettings {
    /// This list of exits is populated once it can verify an exit list received from an exit. Once the router is up and
    /// running is it will query one or more of these exits to understand it's current status and to register with the
    /// exit database smart contract. Once registered and online this list may be populated with new exits through the
    /// exit manager loop which receives verifiable exit lists.
    pub verified_exit_list: Option<ExitServerList>,
    /// The registration state of this router with the exit database smart contract
    /// note this value may be affected by what contract is currently selected and what
    /// chain we are on. Since different chains may reference different registration smart contracts
    #[serde(default = "default_registration_state", flatten)]
    pub registration_state: ExitState,
    /// This is the address of the exit database contract on the xDai chain, this value is a config value in case
    /// a new version of the contract is ever deployed. Otherwise it won't change much. What this contract contains
    /// is the registration data for all routers, facilitating key exchange between new exits in the cluster and clients
    /// So the client registers with the smart contract and the exit takes it's registration data (wireguard key) and sets
    /// up a tunnel, vice versa for the client after finding an exit to register to
    #[serde(default = "exit_db_smart_contract_on_xdai")]
    pub exit_db_smart_contract_on_xdai: String,
    /// This controls which interfaces will be proxied over the exit tunnel
    pub lan_nics: HashSet<String>,
    /// This is the region we are in, this is used to determine if we are in a region that is allowed to connect to the exit
    /// For example if we have a None value, we will connect to other exits with no specified region, but not ones that specify a region lock.
    /// If we have some value we will connect to exits that have that region specified as well as exits with no region specified.
    pub our_region: Option<Regions>,
    /// This is the Address/Pubkey of the exit root of trust server which clients use to verify signed exit lists
    pub allowed_exit_list_signatures: Vec<Address>,
}

impl Default for ExitClientSettings {
    fn default() -> Self {
        ExitClientSettings {
            registration_state: default_registration_state(),
            exit_db_smart_contract_on_xdai: exit_db_smart_contract_on_xdai(),
            lan_nics: HashSet::new(),
            our_region: None,
            allowed_exit_list_signatures: Vec::new(),
            verified_exit_list: None,
        }
    }
}

impl RitaClientSettings {
    /// This is a test setup function that returns a default settings object
    /// and sets the default settings as the current settings object
    pub fn setup_test(our_id: Identity) -> Self {
        let mut settings = RitaClientSettings {
            payment: PaymentSettings::default(),
            log: LoggingSettings::default(),
            operator: OperatorSettings::default(),
            network: NetworkSettings::default(),
            exit_client: ExitClientSettings::default(),
        };
        settings.network.mesh_ip = Some(our_id.mesh_ip);
        settings.network.wg_public_key = Some(our_id.wg_public_key);
        settings.payment.eth_address = Some(our_id.eth_address);

        set_rita_client(settings.clone());
        settings
    }

    /// Loads a settings file from the disk and returns a new settings object
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

    /// Loads a new settings file from a pathbuf and sets it as the current settings
    /// object for this instance of Rita
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
    pub network: NetworkSettings,
    pub exit_client: ExitClientSettings,
}

impl RitaClientSettings {
    /// Returns true if the settings are valid
    pub fn validate(&self) -> bool {
        self.payment.validate()
    }

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
