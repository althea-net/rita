extern crate althea_types;
extern crate config;
extern crate eui48;
extern crate failure;
extern crate num256;
extern crate owning_ref;
extern crate toml;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

extern crate serde;
extern crate serde_json;

extern crate althea_kernel_interface;

use owning_ref::{RwLockReadGuardRef, RwLockWriteGuardRefMut};

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use config::Config;

use althea_types::{
    EthAddress, ExitClientDetails, ExitDetails, ExitRegistrationDetails, ExitState, Identity,
};

use num256::Int256;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use failure::Error;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct NetworkSettings {
    pub own_ip: IpAddr,
    pub bounty_ip: IpAddr,
    pub babel_port: u16,
    pub rita_hello_port: u16,
    pub rita_dashboard_port: u16,
    pub bounty_port: u16,
    pub wg_private_key: String,
    pub wg_private_key_path: String,
    pub wg_public_key: String,
    pub wg_start_port: u16,
    pub peer_interfaces: HashSet<String>,
    pub manual_peers: Vec<String>,
    pub conf_link_local: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_nic: Option<String>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        NetworkSettings {
            own_ip: "fd00::1".parse().unwrap(),
            bounty_ip: "fd00::3".parse().unwrap(),
            babel_port: 6872,
            rita_hello_port: 4876,
            rita_dashboard_port: 4877,
            bounty_port: 8888,
            wg_private_key: String::new(),
            wg_private_key_path: String::new(),
            wg_public_key: String::new(),
            wg_start_port: 60000,
            peer_interfaces: HashSet::new(),
            manual_peers: Vec::new(),
            external_nic: None,
            conf_link_local: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PaymentSettings {
    pub pay_threshold: Int256,
    pub close_threshold: Int256,
    pub close_fraction: Int256,
    pub buffer_period: u32,
    pub eth_address: EthAddress,
}

impl Default for PaymentSettings {
    fn default() -> Self {
        PaymentSettings {
            pay_threshold: 0.into(),
            close_threshold: (-10000).into(),
            close_fraction: 100.into(),
            buffer_period: 3,
            eth_address: EthAddress([1; 20]),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitServer {
    pub id: Identity,
    pub registration_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_details: Option<ExitClientDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub general_details: Option<ExitDetails>,
    #[serde(default)]
    pub state: ExitState,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitClientSettings {
    #[serde(default)]
    pub exits: HashMap<String, ExitServer>,
    pub current_exit: Option<String>,
    pub wg_listen_port: u16,
    pub reg_details: Option<ExitRegistrationDetails>,
}

impl Default for ExitClientSettings {
    fn default() -> Self {
        ExitClientSettings {
            exits: HashMap::new(),
            current_exit: None,
            wg_listen_port: 59999,
            reg_details: Some(ExitRegistrationDetails {
                zip_code: Some("1234".into()),
                email: Some("1234@gmail.com".into()),
                country: Some("Althea".into()),
            }),
        }
    }
}

impl ExitClientSettings {
    pub fn get_current_exit(&self) -> Option<&ExitServer> {
        Some(&self.exits[self.current_exit.as_ref()?])
    }
    pub fn get_current_exit_name(&self) -> Option<&ExitServer> {
        Some(&self.exits[self.current_exit.as_ref()?])
    }
    pub fn get_current_exit_details(&self) -> Option<&ExitClientDetails> {
        match self.get_current_exit() {
            Some(ref exit) => match exit.our_details {
                Some(ref details) => return Some(details),
                _ => (),
            },
            _ => (),
        }
        None
    }
    pub fn set_current_exit(&mut self) -> Option<&mut ExitServer> {
        self.exits.get_mut(self.current_exit.as_ref()?)
    }
    pub fn current_exit_exists(&self) -> bool {
        if self.current_exit == None {
            return false;
        }
        return self.exits.contains_key(self.current_exit.as_ref().unwrap());
    }
    pub fn current_exit_details_exists(&self) -> bool {
        if self.current_exit == None {
            return false;
        }
        if self.exits.contains_key(self.current_exit.as_ref().unwrap()) == false {
            return false;
        }
        return self.exits[self.current_exit.as_ref().unwrap()]
            .our_details
            .is_some();
    }
    pub fn reg_details_set(&self) -> bool {
        self.reg_details.is_some()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct StatsServerSettings {
    pub stats_address: String,
    pub stats_port: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct ExitTunnelSettings {
    pub lan_nics: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct RitaSettingsStruct {
    payment: PaymentSettings,
    network: NetworkSettings,
    exit_client: ExitClientSettings,
    exit_tunnel_settings: ExitTunnelSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats_server: Option<StatsServerSettings>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitNetworkSettings {
    pub exit_hello_port: u16,
    pub wg_tunnel_port: u16,
    pub exit_price: u64,
    pub own_internal_ip: IpAddr,
    pub exit_start_ip: IpAddr,
    pub netmask: u8,
}

impl Default for ExitNetworkSettings {
    fn default() -> Self {
        ExitNetworkSettings {
            exit_hello_port: 4875,
            wg_tunnel_port: 59999,
            exit_price: 10,
            own_internal_ip: "172.168.1.254".parse().unwrap(),
            exit_start_ip: "172.168.1.100".parse().unwrap(),
            netmask: 24,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct RitaExitSettingsStruct {
    db_file: String,
    description: String,
    payment: PaymentSettings,
    network: NetworkSettings,
    exit_network: ExitNetworkSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats_server: Option<StatsServerSettings>,
    #[serde(skip_serializing_if = "HashSet::is_empty", default)]
    allowed_countries: HashSet<String>,
}

pub trait RitaCommonSettings<T: Serialize + Deserialize<'static>> {
    fn get_payment<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, PaymentSettings>;
    fn set_payment<'ret, 'me: 'ret>(&'me self) -> RwLockWriteGuardRefMut<'ret, T, PaymentSettings>;

    fn get_network<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, NetworkSettings>;
    fn set_network<'ret, 'me: 'ret>(&'me self) -> RwLockWriteGuardRefMut<'ret, T, NetworkSettings>;

    fn get_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, T, StatsServerSettings>;
    fn init_stats_server_settings(&self, exit_client: StatsServerSettings);
    fn set_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, StatsServerSettings>;
    fn stats_server_settings_is_set(&self) -> bool;
    fn clear_stats_server_settings(&self);

    fn merge(&self, changed_settings: Value) -> Result<(), Error>;
    fn get_all(&self) -> Result<serde_json::Value, Error>;

    fn get_identity(&self) -> Identity;
}

fn json_merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (&mut Value::Object(ref mut a), &Value::Object(ref b)) => {
            for (k, v) in b {
                json_merge(a.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (a, b) => {
            *a = b.clone();
        }
    }
}

impl RitaCommonSettings<RitaSettingsStruct> for Arc<RwLock<RitaSettingsStruct>> {
    fn get_payment<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, PaymentSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.payment)
    }

    fn set_payment<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, PaymentSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.payment)
    }

    fn get_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, NetworkSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.network)
    }

    fn set_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, NetworkSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.network)
    }

    fn get_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, StatsServerSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| match g.stats_server {
            Some(ref stat_server) => stat_server,
            None => panic!("exit client not set but needed"),
        })
    }

    fn init_stats_server_settings(&self, stat_server: StatsServerSettings) {
        self.write().unwrap().stats_server = Some(stat_server)
    }

    fn set_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, StatsServerSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| match g.stats_server {
            Some(ref mut stat_server) => stat_server,
            None => panic!("exit client not set but needed"),
        })
    }

    fn stats_server_settings_is_set(&self) -> bool {
        self.read().unwrap().stats_server.is_some()
    }
    fn clear_stats_server_settings(&self) {
        self.write().unwrap().stats_server = None;
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

    fn get_identity(&self) -> Identity {
        Identity::new(
            self.get_network().own_ip.clone(),
            self.get_payment().eth_address.clone(),
            self.get_network().wg_public_key.clone(),
        )
    }
}

impl RitaCommonSettings<RitaExitSettingsStruct> for Arc<RwLock<RitaExitSettingsStruct>> {
    fn get_payment<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, PaymentSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.payment)
    }

    fn set_payment<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, PaymentSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.payment)
    }

    fn get_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, NetworkSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.network)
    }

    fn set_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, NetworkSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.network)
    }

    fn get_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, StatsServerSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| match g.stats_server {
            Some(ref stat_server) => stat_server,
            None => panic!("exit client not set but needed"),
        })
    }

    fn init_stats_server_settings(&self, stat_server: StatsServerSettings) {
        self.write().unwrap().stats_server = Some(stat_server)
    }

    fn set_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, StatsServerSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| match g.stats_server {
            Some(ref mut stat_server) => stat_server,
            None => panic!("exit client not set but needed"),
        })
    }

    fn stats_server_settings_is_set(&self) -> bool {
        self.read().unwrap().stats_server.is_some()
    }

    fn clear_stats_server_settings(&self) {
        self.write().unwrap().stats_server = None;
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

    fn get_identity(&self) -> Identity {
        Identity::new(
            self.get_network().own_ip.clone(),
            self.get_payment().eth_address.clone(),
            self.get_network().wg_public_key.clone(),
        )
    }
}

pub trait RitaClientSettings {
    fn get_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientSettings>;
    fn set_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientSettings>;
    fn get_exits<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, HashMap<String, ExitServer>>;
    fn set_exits<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, HashMap<String, ExitServer>>;
    fn get_exit_tunnel_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitTunnelSettings>;
}

impl RitaClientSettings for Arc<RwLock<RitaSettingsStruct>> {
    fn get_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_client)
    }
    fn set_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.exit_client)
    }

    fn get_exits<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, HashMap<String, ExitServer>> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_client.exits)
    }

    fn set_exits<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, HashMap<String, ExitServer>> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.exit_client.exits)
    }

    fn get_exit_tunnel_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitTunnelSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_tunnel_settings)
    }
}

pub trait RitaExitSettings {
    fn get_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, ExitNetworkSettings>;
    fn set_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, ExitNetworkSettings>;

    fn get_db_file(&self) -> String;
    fn get_description(&self) -> String;
    fn get_allowed_countries<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, HashSet<String>>;
}

impl RitaExitSettings for Arc<RwLock<RitaExitSettingsStruct>> {
    fn get_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, ExitNetworkSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_network)
    }

    fn set_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, ExitNetworkSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.exit_network)
    }

    fn get_db_file(&self) -> String {
        self.read().unwrap().db_file.clone()
    }
    fn get_description(&self) -> String {
        self.read().unwrap().description.clone()
    }
    fn get_allowed_countries<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, HashSet<String>> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.allowed_countries)
    }
}

pub trait FileWrite {
    fn write(&self, file_name: &str) -> Result<(), Error>;
}

fn spawn_watch_thread<'de, T: 'static>(
    settings: Arc<RwLock<T>>,
    file_path: &str,
) -> Result<(), Error>
where
    T: serde::Deserialize<'de> + Sync + Send + std::fmt::Debug + Clone + Eq + FileWrite,
{
    let file_path = file_path.to_string();

    thread::spawn(move || {
        let old_settings = settings.read().unwrap().clone();
        thread::sleep(Duration::from_millis(200));

        loop {
            let new_settings = settings.read().unwrap().clone();

            if old_settings != new_settings {
                info!("writing updated config: {:?}", new_settings);
                match settings.read().unwrap().write(&file_path) {
                    Err(e) => warn!("writing updated config failed {:?}", e),
                    _ => (),
                }
            }

            thread::sleep(Duration::from_secs(5));
        }
    });

    Ok(())
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

        spawn_watch_thread(settings.clone(), file_name).unwrap();

        Ok(settings)
    }

    pub fn get_exit_id(&self) -> Option<Identity> {
        Some(self.exit_client.get_current_exit().as_ref()?.id.clone())
    }
}

impl FileWrite for RitaSettingsStruct {
    fn write(&self, file_name: &str) -> Result<(), Error> {
        let ser = toml::Value::try_from(self.clone()).unwrap();
        let ser = toml::to_string(&ser).unwrap();
        let mut file = File::create(file_name)?;
        file.write_all(ser.as_bytes())?;
        file.flush().unwrap();
        Ok(())
    }
}

impl RitaExitSettingsStruct {
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

        spawn_watch_thread(settings.clone(), file_name).unwrap();

        Ok(settings)
    }
}

impl FileWrite for RitaExitSettingsStruct {
    fn write(&self, file_name: &str) -> Result<(), Error> {
        let ser = toml::Value::try_from(self.clone()).unwrap();
        let ser = toml::to_string(&ser).unwrap();
        let mut file = File::create(file_name)?;
        file.write_all(ser.as_bytes())?;
        file.flush().unwrap();
        Ok(())
    }
}
