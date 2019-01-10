use config;

use toml;

use serde;
use serde_json;

use owning_ref::{RwLockReadGuardRef, RwLockWriteGuardRefMut};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use config::Config;

use althea_types::{ExitRegistrationDetails, ExitState, Identity};

use failure::Error;

use crate::dao::SubnetDAOSettings;
use crate::json_merge;
use crate::loging::LoggingSettings;
use crate::network::NetworkSettings;
use crate::payment::PaymentSettings;
use crate::spawn_watch_thread;
use crate::RitaCommonSettings;

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
    /// Details for exit registration
    pub reg_details: Option<ExitRegistrationDetails>,
    /// This controls which interfaces will be proxied over the exit tunnel
    pub lan_nics: HashSet<String>,
}

impl Default for ExitClientSettings {
    fn default() -> Self {
        ExitClientSettings {
            exits: HashMap::new(),
            current_exit: None,
            wg_listen_port: 59999,
            reg_details: Some(ExitRegistrationDetails {
                email: Some("1234@gmail.com".into()),
                email_code: Some("000000".into()),
            }),
            lan_nics: HashSet::new(),
        }
    }
}

impl ExitClientSettings {
    pub fn get_current_exit(&self) -> Option<&ExitServer> {
        Some(&self.exits[self.current_exit.as_ref()?])
    }
}

pub trait RitaClientSettings {
    fn get_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientSettings>;
    fn get_exit_client_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientSettings>;
    fn get_exits<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, HashMap<String, ExitServer>>;
    fn get_exits_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, HashMap<String, ExitServer>>;
    fn get_log<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, LoggingSettings>;
    fn get_log_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, LoggingSettings>;
}

impl RitaClientSettings for Arc<RwLock<RitaSettingsStruct>> {
    fn get_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_client)
    }
    fn get_exit_client_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.exit_client)
    }

    fn get_exits<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, HashMap<String, ExitServer>> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_client.exits)
    }

    fn get_exits_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, HashMap<String, ExitServer>> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.exit_client.exits)
    }

    fn get_log<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, LoggingSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.log)
    }

    fn get_log_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, LoggingSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.log)
    }
}

impl RitaSettingsStruct {
    pub fn new(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;

        Ok(settings)
    }

    pub fn new_watched(file_name: &str) -> Result<Arc<RwLock<Self>>, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.clone().try_into()?;

        let settings = Arc::new(RwLock::new(settings));

        trace!("starting with settings: {:?}", settings.read().unwrap());

        spawn_watch_thread(settings.clone(), file_name).unwrap();

        Ok(settings)
    }

    pub fn get_exit_id(&self) -> Option<Identity> {
        Some(self.exit_client.get_current_exit().as_ref()?.id.clone())
    }
}

/// This is the main struct for rita
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct RitaSettingsStruct {
    payment: PaymentSettings,
    #[serde(default)]
    dao: SubnetDAOSettings,
    #[serde(default)]
    log: LoggingSettings,
    network: NetworkSettings,
    exit_client: ExitClientSettings,
    #[serde(skip)]
    future: bool,
}

impl RitaCommonSettings<RitaSettingsStruct> for Arc<RwLock<RitaSettingsStruct>> {
    fn get_payment<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, PaymentSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.payment)
    }

    fn get_payment_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, PaymentSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.payment)
    }

    fn get_dao<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, SubnetDAOSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.dao)
    }

    fn get_dao_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, SubnetDAOSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.dao)
    }

    fn get_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, NetworkSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.network)
    }

    fn get_network_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, NetworkSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.network)
    }

    fn merge(&self, changed_settings: serde_json::Value) -> Result<(), Error> {
        let mut settings_value = serde_json::to_value(self.read().unwrap().clone())?;

        json_merge(&mut settings_value, &changed_settings);

        match serde_json::from_value(settings_value) {
            Ok(new_settings) => {
                *self.write().unwrap() = new_settings;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn get_all(&self) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(self.read().unwrap().clone())?)
    }

    fn get_identity(&self) -> Option<Identity> {
        Some(Identity::new(
            self.get_network().mesh_ip?.clone(),
            self.get_payment().clone().eth_address?,
            self.get_network().clone().wg_public_key?,
        ))
    }

    fn get_future(&self) -> bool {
        self.read().unwrap().future
    }

    fn set_future(&self, future: bool) {
        self.write().unwrap().future = future
    }
}
