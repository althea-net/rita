use crate::localization::LocalizationSettings;
use crate::logging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::operator::OperatorSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_client, SettingsError};
use althea_types::{ExitState, Identity};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "rita";

pub const DUMMY_ROOT_IP: &str = "1.1.1.1";

pub fn default_app_name() -> String {
    APP_NAME.to_string()
}

pub fn default_save_interval() -> u64 {
    172800
}

pub fn default_config_path() -> PathBuf {
    format!("/etc/{APP_NAME}.toml").into()
}

/// This struct represents a single exit server. It contains all the details
/// needed to contact and register to the exit.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitServer {
    /// This is the unique identity of the exit. Previously exit
    /// had a shared wg key and mesh ip, this struct needs to have unique
    /// meship, wgkey and ethaddress for each entry
    pub exit_id: Identity,

    /// The power we reach out to to hit the register endpoint
    /// also used for all other exit lifecycle management api calls
    #[serde(default = "default_registration_port")]
    pub registration_port: u16,

    /// The power we reach out to to hit the register endpoint
    /// also used for all other exit lifecycle management api calls
    #[serde(default = "default_wg_listen_port")]
    pub wg_exit_listen_port: u16,

    /// The registration state and other data about the exit
    #[serde(default, flatten)]
    pub info: ExitState,
}

fn default_registration_port() -> u16 {
    4875
}

fn default_wg_listen_port() -> u16 {
    59998
}

/// Simple struct that keeps track of details related to the exit we are currently connected to, as well as the next potential exit to switch to
#[derive(Default, Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SelectedExit {
    // Exit we currently forward to
    pub selected_id: Option<IpAddr>,

    // Advertised Metric of selected_id. This is different from that advertised by babel due to bias of metric being degraded by current traffic
    pub selected_id_metric: Option<u16>,

    // Since our advertised metric doesnt change through babel, we measure how much the average metric degrades over time and add this to sel_id_metric
    pub selected_id_degradation: Option<u16>,

    // This could be different from selected_id, we dont switch immediately to avoid route flapping
    // This is what we keep track of in lazy static metric vector
    pub tracking_exit: Option<IpAddr>,
}

/// This is the state machine for exit switching logic. Given there are three exits we track: current, best, and tracking, there are several situations we can be in
/// Given that there are several scenarios to be in, We use this enum to tracking our state during every tick
///
/// InitialExitSetup: We have just connected to the first exit and tracking vector is empty
///
/// ContinueCurrentReset: Best exit, current exit and tracking exit are all the same. We continue with the same exit. However our tracking vector is full,
/// so we reset it, with no change to exits
///
/// ContinueCurrent: Same as above, but vector is not full. We continue adding metrics to tracking vector.
///
/// SwitchExit: Current exit is different but tracking and best are same. Vec is full, we switch to best/tracking exit
///
/// ContinueTracking: Current exit is different but tracking == best. Vec is not full, so we dont switch yet, just continue updating the tracking vector
///
/// ResetTracking: tracking and best are diffrent. We reset timer/vector and start tracking new best
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum ExitSwitchingCode {
    InitialExitSetup,
    ContinueCurrentReset,
    ContinueCurrent,
    SwitchExit,
    ContinueTracking,
    ResetTracking,
}

fn default_balance_notification() -> bool {
    true
}

/// This struct is used by rita to encapsulate all the state/information needed to connect/register
/// to a exit and to setup the exit tunnel
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitClientSettings {
    /// This stores a mapping between an identifier (any string) to exits
    #[serde(rename = "new_exits", default)]
    pub exits: HashMap<IpAddr, ExitServer>,
    /// This is the port which the exit wireguard tunnel will listen on
    /// NOTE: must be under `wg_start_port` in `NetworkSettings`
    pub wg_listen_port: u16,
    /// This controls which interfaces will be proxied over the exit tunnel
    pub lan_nics: HashSet<String>,
    /// Specifies if the user would like to receive low balance messages from the exit
    #[serde(default = "default_balance_notification")]
    pub low_balance_notification: bool,
}

impl Default for ExitClientSettings {
    fn default() -> Self {
        ExitClientSettings {
            exits: HashMap::new(),
            wg_listen_port: 59999,
            lan_nics: HashSet::new(),
            low_balance_notification: true,
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
            localization: LocalizationSettings::default(),
            network: NetworkSettings::default(),
            exit_client: ExitClientSettings::default(),
            app_name: APP_NAME.to_string(),
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
    #[serde(default)]
    pub localization: LocalizationSettings,
    pub network: NetworkSettings,
    pub exit_client: ExitClientSettings,
    #[serde(default = "default_app_name")]
    pub app_name: String,
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
