use crate::localization::LocalizationSettings;
use crate::logging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::operator::OperatorSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_client, spawn_watch_thread_client};
use althea_types::{ContactStorage, ExitState, Identity};
use config::Config;
use failure::Error;
use std::collections::{HashMap, HashSet};

/// This struct is used by rita to store exit specific information
/// There is one instance per exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitServer {
    pub id: Identity,
    /// The port over which we will reach the exit apis on over the mesh
    pub registration_port: u16,
    #[serde(default)]
    pub description: String,
    /// The state and data about the exit
    #[serde(default, flatten)]
    pub info: ExitState,
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
        Some(&self.exits[self.current_exit.as_ref()?])
    }
}

impl RitaClientSettings {
    pub fn new(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
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

    pub fn get_exit_id(&self) -> Option<Identity> {
        Some(self.exit_client.get_current_exit().as_ref()?.id)
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
