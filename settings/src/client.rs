use crate::localization::LocalizationSettings;
use crate::logging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::operator::OperatorSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_client, spawn_watch_thread_client, update_config, SUBNET};
use althea_types::wg_key::WgKey;
use althea_types::{ContactStorage, ExitState, Identity};
use clarity::Address;
use config::Config;
use failure::Error;
use ipnetwork::IpNetwork;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

/// This struct is used by rita to store exit specific information
/// There is one instance per exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitServer {
    // Subnet of exits in cluster
    pub subnet: IpNetwork,

    // Field added for serde config writing
    pub id: Option<Identity>,

    //field added for serde config writing
    pub subnet_len: u8,

    // Struct containing information of current exit and tracking exit, if connected to one
    pub selected_exit: SelectedExit,

    // eth address of Selected exit
    pub eth_address: Address,

    //wg public key of selected exit
    pub wg_public_key: WgKey,

    /// The port over which we will reach the exit apis on over the mesh
    #[serde(default)]
    pub registration_port: u16,
    #[serde(default)]
    pub description: String,
    /// The state and data about the exit
    #[serde(default, flatten)]
    pub info: ExitState,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct OldExitServer {
    pub id: Identity,
    /// The port over which we will reach the exit apis on over the mesh

    #[serde(default)]
    pub subnet_len: Option<u8>,

    pub registration_port: u16,
    #[serde(default)]
    pub description: String,
    /// The state and data about the exit
    #[serde(default, flatten)]
    pub info: ExitState,
}

/// Simple struct that keeps track of details related to the exit we are currently connected to, as well as the next potential exit to switch to
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
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

impl Default for SelectedExit {
    fn default() -> Self {
        SelectedExit {
            selected_id: None,
            selected_id_metric: None,
            selected_id_degradation: None,
            tracking_exit: None,
        }
    }
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
    #[serde(default)]
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

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct OldExitClientSettings {
    /// This stores a mapping between an identifier (any string) to exits
    #[serde(default)]
    pub exits: HashMap<String, OldExitServer>,
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

impl Default for OldExitClientSettings {
    fn default() -> Self {
        OldExitClientSettings {
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
        Some(&self.exits[self.current_exit.as_ref()?])
    }
}

impl RitaClientSettings {
    pub fn new(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        assert!(Path::new(file_name).exists());
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;

        Ok(settings)
    }

    pub fn new_watched(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;

        set_rita_client(settings.clone());

        spawn_watch_thread_client(settings.clone(), file_name);

        Ok(settings)
    }

    pub fn get_exit_id(&self) -> Option<IpAddr> {
        self.exit_client
            .get_current_exit()
            .as_ref()?
            .selected_exit
            .selected_id
    }
}

impl OldRitaClientSettings {
    pub fn new(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        assert!(Path::new(file_name).exists());
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;

        Ok(settings)
    }

    pub fn new_watched(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;

        let subnet = SUBNET;
        let new_settings = update_config(settings.clone(), subnet);
        let new_settings = new_settings?;

        set_rita_client(new_settings.clone());

        spawn_watch_thread_client(new_settings, file_name);

        Ok(settings)
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
}

/// This is the main struct for rita
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct OldRitaClientSettings {
    pub payment: PaymentSettings,
    #[serde(default)]
    pub log: LoggingSettings,
    #[serde(default)]
    pub operator: OperatorSettings,
    #[serde(default)]
    pub localization: LocalizationSettings,
    pub network: NetworkSettings,
    pub exit_client: OldExitClientSettings,
    #[serde(skip)]
    pub future: bool,
}

impl RitaClientSettings {
    pub fn merge(&mut self, changed_settings: serde_json::Value) -> Result<(), Error> {
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

    pub fn get_all(&self) -> Result<serde_json::Value, Error> {
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
