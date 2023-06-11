use crate::localization::LocalizationSettings;
use crate::logging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::operator::OperatorSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_client, setup_accepted_denoms, SettingsError};
use althea_types::wg_key::WgKey;
use althea_types::{ContactStorage, ExitState, Identity};
use clarity::Address;
use ipnetwork::IpNetwork;
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

/// This struct represents an exit server cluster, meaning
/// an arbitrary number of actual machines may be represented here
/// all exits in a cluster share a wireguard and eth private key used for their
/// wg_exit connections and are found via searching the routing table for
/// ip's within the provided subnet.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitServer {
    /// Ip of exit we first connect to when connected to this cluster
    #[serde(default = "dummy_root_ip")]
    pub root_ip: IpAddr,

    /// Subnet for backwards compatilibity
    #[serde(default)]
    pub subnet: Option<IpNetwork>,

    /// eth address of this exit cluster
    pub eth_address: Address,

    /// wg public key used for wg_exit by this cluster
    /// each exit has a distinct wg key used for peer
    /// to peer tunnels and to identify it in logs
    pub wg_public_key: WgKey,

    /// The power we reach out to to hit the register endpoint
    /// also used for all other exit lifecycle management api calls
    #[serde(default)]
    pub registration_port: u16,

    /// the exit description, a short string blurb that is displayed
    /// directly to the user
    #[serde(default)]
    pub description: String,
    /// The registration state and other data about the exit
    #[serde(default, flatten)]
    pub info: ExitState,
}

fn dummy_root_ip() -> IpAddr {
    DUMMY_ROOT_IP.parse().unwrap()
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
    pub exits: HashMap<String, ExitServer>,
    /// This stores the current exit identifier
    pub current_exit: Option<String>,
    /// This is the port which the exit wireguard tunnel will listen on
    /// NOTE: must be under `wg_start_port` in `NetworkSettings`
    pub wg_listen_port: u16,
    /// ContactStorage is a TOML serialized representation of ContactType, use the .into()
    /// traits to get ContactType for actual operations. This struct represents a full range
    /// of possibilities for contact info.
    pub contact_info: Option<ContactStorage>,
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
            current_exit: None,
            wg_listen_port: 59999,
            contact_info: None,
            lan_nics: HashSet::new(),
            low_balance_notification: true,
        }
    }
}

impl ExitClientSettings {
    pub fn get_current_exit(&self) -> Option<&ExitServer> {
        if self.exits.contains_key(self.current_exit.as_ref()?) {
            Some(&self.exits[self.current_exit.as_ref()?])
        } else {
            None
        }
    }
}

impl RitaClientSettings {
    pub fn new(file_name: &str) -> Result<Self, SettingsError> {
        if !Path::new(file_name).exists() {
            return Err(SettingsError::FileNotFoundError(file_name.to_string()));
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

        let mut ret = Self::convert_subnet_to_root_ip(&ret);
        // Setup accepted denoms for payment validator, this is for routers during opkg updates,
        // this can be removed once all router are updated to the version that handles althea chain
        ret.payment.accepted_denoms = Some(setup_accepted_denoms());

        set_rita_client(ret.clone());

        Ok(ret)
    }

    pub fn convert_subnet_to_root_ip(&self) -> Self {
        let mut ret = self.clone();
        let exit_server = &self.exit_client.exits;
        for (hash, ser) in exit_server.iter() {
            match (ser.subnet.is_none(), ser.root_ip == dummy_root_ip()) {
                (true, true) => panic!("Please setup config with correct root_ip value"),
                (false, true) => {
                    let exit_ser = ret
                        .exit_client
                        .exits
                        .get_mut(hash)
                        .expect("Why did this fail");
                    exit_ser.root_ip = ser.subnet.unwrap().ip();
                    exit_ser.subnet = None;
                    continue;
                }
                _ => continue,
            }
        }
        ret
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
    #[serde(skip)]
    pub future: bool,
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

    pub fn get_future(&self) -> bool {
        self.future
    }

    pub fn set_future(&mut self, future: bool) {
        self.future = future
    }
}
