//! The Settings crate handles settings for Rita, specifically it uses lazy_static to load and
//! deserialize the config file on system start. Once deserialized using Serde into internal data
//! structures it is then provided to Rita as a global static reference, this reference is locked
//! using a RwLock to allow multiple readers and writers throughout the code. If you hold a read
//! reference in a blocking function call or a read and write reference at the same time you will
//! cause a deadlock.
//!
//! This can be dependent on the behavior of the borrow checker since the lock
//! is released based on when the reference is dropped. Take care when using _mut to either
//! namespace or clone quickly to avoid deadlocks.

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
extern crate arrayvec;

use althea_kernel_interface::KI;
use althea_types::Identity;
use logging::LoggingSettings;
use network::NetworkSettings;
use payment::PaymentSettings;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

pub mod client;
pub mod exit;
pub mod localization;
pub mod logging;
pub mod network;
pub mod operator;
pub mod payment;

mod error;
pub use error::SettingsError;

use crate::client::RitaClientSettings;
use crate::exit::RitaExitSettingsStruct;
/// denom that debt keeper works in. We convert all currencies received to this amount
pub const DEBT_KEEPER_DENOM: &str = "wei";
pub const DEBT_KEEPER_DENOM_DECIMAL: u64 = 1_000_000_000_000_000_000;

pub const SUBNET: u8 = 128;
pub const US_WEST_SUBNET: u8 = 116;
pub const AFRICA_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x2e2f));
pub const APAC_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x4e2f));
pub const SA_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x6e2f));

lazy_static! {
    static ref FLAG_CONFIG: Arc<RwLock<HashMap<u32, PathBuf>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

lazy_static! {
    static ref SETTINGS: Arc<RwLock<HashMap<u32, Settings>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

#[derive()]
pub struct AdaptorSettings {
    pub adaptor: Box<dyn WrappedSettingsAdaptor + Send + Sync + 'static>,
}
impl Debug for AdaptorSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AdaptorSettings")
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Settings {
    Client(RitaClientSettings),
    Exit(RitaExitSettingsStruct),
    Adaptor(AdaptorSettings),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettingsType {
    None,
    Client,
    Exit,
    Adaptor,
}

// WrappedSettingsAdaptor allows settings to be handled by a higher layer that wraps RitaClientSettings and adds its own additional fields.
// The higher layer is responsible for the actual read/write of settings to disk.
// This adaptor must be thread safe (Send + Sync)
pub trait WrappedSettingsAdaptor {
    fn get_client(&self) -> Result<RitaClientSettings, SettingsError>;
    fn set_client(&self, client_settings: RitaClientSettings) -> Result<(), SettingsError>;
    fn write_config(&self) -> Result<(), SettingsError>;
    fn merge_client_json(&self, changed_settings: serde_json::Value) -> Result<(), SettingsError>;
    fn get_config_json(&self) -> Result<serde_json::Value, SettingsError>;
}

// This function can be called from a higher layer (wrapping binary) to set a reference to its adaptor
// Doing so will disable local reads/writes and instead call the adaptor's relevant fns
// Can only be called once if no other settings exist in the SETTINGS global
pub fn set_adaptor<T: 'static + WrappedSettingsAdaptor + Send + Sync>(adaptor: T) {
    let netns = KI.check_integration_test_netns();
    let mut settings_ref = SETTINGS.write().unwrap();
    match settings_ref.contains_key(&netns) {
        // make sure this only gets called once on start
        true => panic!("Attempted to set settings adapter to a non-empty SETTINGS global"),
        // if there are no settings, then save as Adaptor
        false => {
            settings_ref.insert(
                netns,
                Settings::Adaptor(AdaptorSettings {
                    adaptor: Box::new(adaptor),
                }),
            );
        }
    }
}

/// A generic version of the more specific Rita settings struts use for Rita common
pub struct RitaSettings {
    pub payment: PaymentSettings,
    pub network: NetworkSettings,
    pub log: LoggingSettings,
    /// This member kept private to prevent modification since it's not
    /// saved in set_rita_common()
    identity: Option<Identity>,
    app_name: String,
}

impl RitaSettings {
    pub fn get_identity(&self) -> Option<Identity> {
        self.identity
    }
    /// Returns true if the settings are valid
    pub fn validate(&self) -> bool {
        self.payment.validate()
    }

    /// returns the app name
    pub fn get_app_name(&self) -> String {
        self.app_name.clone()
    }
}

/// write the current SETTINGS from memory to file
pub fn write_config() -> Result<(), SettingsError> {
    let netns = KI.check_integration_test_netns();
    match SETTINGS.read().unwrap().get(&netns) {
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.write_config(),
        Some(Settings::Client(settings)) => {
            let filename = FLAG_CONFIG.read().unwrap();
            let filename = filename.get(&netns);
            if let Some(filename) = filename {
                settings.write(filename.clone())?
            }
            Ok(())
        }
        Some(Settings::Exit(settings)) => {
            let filename = FLAG_CONFIG.read().unwrap();
            let filename = filename.get(&netns);
            if let Some(filename) = filename {
                settings.write(filename.clone())?
            }
            Ok(())
        }
        None => panic!("expected settings but got none"),
    }
}

/// On an interupt (SIGTERM), saving settings before exiting
pub fn save_settings_on_shutdown() {
    if let Err(e) = write_config() {
        error!("Unable to save settings with error: {}", e);
        return;
    }

    info!("Shutdown: saving settings");
}

/// get a JSON value of all settings
pub fn get_config_json() -> Result<serde_json::Value, SettingsError> {
    let netns = KI.check_integration_test_netns();
    match SETTINGS.read().unwrap().get(&netns) {
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.get_config_json(),
        Some(Settings::Client(settings)) => settings.get_all(),
        Some(Settings::Exit(settings)) => settings.get_all(),
        None => panic!("expected settings but got none"),
    }
}

/// merge a json of a subset of settings into global settings
pub fn merge_config_json(changed_settings: serde_json::Value) -> Result<(), SettingsError> {
    let netns = KI.check_integration_test_netns();
    let mut settings_ref = SETTINGS.write().unwrap();
    let settings_ref = settings_ref.get_mut(&netns);
    match settings_ref {
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.merge_client_json(changed_settings),
        Some(Settings::Client(client_settings)) => client_settings.merge(changed_settings),
        Some(Settings::Exit(exit_settings)) => exit_settings.merge(changed_settings),
        None => panic!("attempted to merge config to a missing Settings"),
    }
}

/// Save generic settings into memory.
/// Does not currently save the identity paramater, as we don't
/// need to modify that in a generic context.
pub fn set_rita_common(input: RitaSettings) {
    let netns = KI.check_integration_test_netns();
    let mut settings_ref = SETTINGS.write().unwrap();
    match settings_ref.get_mut(&netns) {
        Some(Settings::Adaptor(adapt)) => {
            let mut client_settings = adapt
                .adaptor
                .get_client()
                .expect("Adaptor failed to get_client");
            client_settings.network = input.network;
            client_settings.payment = input.payment;
            adapt
                .adaptor
                .set_client(client_settings)
                .expect("Adaptor failed to set_client");
        }
        // if there's a client setting, update it
        Some(Settings::Client(client_settings)) => {
            client_settings.network = input.network;
            client_settings.payment = input.payment;
        }
        // if there's an exit settings, update it
        Some(Settings::Exit(exit_settings)) => {
            exit_settings.network = input.network;
            exit_settings.payment = input.payment;
        }
        // if there are no settings, panic
        None => panic!("attempted to save rita settings to an empty Settings var"),
    }
}

/// get the current settings and extract generic RitaSettings from it
pub fn get_rita_common() -> RitaSettings {
    let netns = KI.check_integration_test_netns();
    match SETTINGS.read().unwrap().get(&netns) {
        Some(Settings::Adaptor(adapt)) => {
            let settings = adapt.adaptor.get_client().unwrap();
            RitaSettings {
                network: settings.network.clone(),
                payment: settings.payment.clone(),
                log: settings.log.clone(),
                identity: settings.get_identity(),
                app_name: crate::client::APP_NAME.to_string(),
            }
        }
        Some(Settings::Client(settings)) => RitaSettings {
            network: settings.network.clone(),
            payment: settings.payment.clone(),
            log: settings.log.clone(),
            identity: settings.get_identity(),
            app_name: crate::client::APP_NAME.to_string(),
        },
        Some(Settings::Exit(settings)) => RitaSettings {
            network: settings.network.clone(),
            payment: settings.payment.clone(),
            log: settings.log.clone(),
            identity: settings.get_identity(),
            app_name: crate::exit::APP_NAME.to_string(),
        },
        None => panic!("expected settings but got none"),
    }
}

pub fn get_git_hash() -> String {
    env!("GIT_HASH").to_string()
}

pub fn set_flag_config(flag_config: PathBuf) {
    let netns = KI.check_integration_test_netns();
    FLAG_CONFIG.write().unwrap().insert(netns, flag_config);
}

pub fn get_flag_config() -> PathBuf {
    let netns = KI.check_integration_test_netns();
    FLAG_CONFIG.read().unwrap().get(&netns).unwrap().clone()
}

/// set client settings into local or adaptor memory
/// panics if called on exit settings
pub fn set_rita_client(client_setting: RitaClientSettings) {
    let netns = KI.check_integration_test_netns();
    let mut settings_ref = SETTINGS.write().unwrap();
    match settings_ref.get(&netns) {
        // if there's an adaptor already saved, then use it to set there
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.set_client(client_setting).unwrap(),
        // if there's a client setting, then save over it
        Some(Settings::Client(_)) => {
            settings_ref.insert(netns, Settings::Client(client_setting));
        }
        // error if there's an exit here
        Some(Settings::Exit(_)) => panic!("attempted to save client settings over exit settings"),
        // if there are no settings, then save as Client
        None => {
            settings_ref.insert(netns, Settings::Client(client_setting));
        }
    }
}

/// get client settings from local or adaptor memory
/// panics if called on exit settings
pub fn get_rita_client() -> RitaClientSettings {
    let netns = KI.check_integration_test_netns();
    match SETTINGS.read().unwrap().get(&netns) {
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.get_client().unwrap(),
        Some(Settings::Client(settings)) => settings.clone(),
        Some(Settings::Exit(_)) => panic!("expected client settings, but got exit setttings"),
        None => panic!("expected settings but got none"),
    }
}

/// Set exit settings into memory
pub fn set_rita_exit(exit_setting: RitaExitSettingsStruct) {
    let netns = KI.check_integration_test_netns();
    SETTINGS
        .write()
        .unwrap()
        .insert(netns, Settings::Exit(exit_setting));
}

/// Retrieve exit settings from memory
pub fn get_rita_exit() -> RitaExitSettingsStruct {
    let netns = KI.check_integration_test_netns();
    let temp = SETTINGS.read().unwrap();
    let temp = temp.get(&netns);
    if let Some(Settings::Exit(val)) = temp {
        val.clone()
    } else {
        panic!("Failed to get RitaExitSettings from storage");
    }
}

/// This code checks to see if the current device/setting is client or not
pub fn check_if_client() -> bool {
    let netns = KI.check_integration_test_netns();
    match SETTINGS.read().unwrap().get(&netns) {
        Some(Settings::Adaptor(_)) => false,
        Some(Settings::Client(_)) => true,
        Some(Settings::Exit(_)) => false,
        None => false,
    }
}


/// This code checks to see if the current device/setting is an exit or not
pub fn check_if_exit() -> bool {
    let netns = KI.check_integration_test_netns();
    match SETTINGS.read().unwrap().get(&netns) {
        Some(Settings::Adaptor(_)) => false,
        Some(Settings::Client(_)) => false,
        Some(Settings::Exit(_)) => true,
        None => false,
    }
}

/// This merges 2 json objects, overwriting conflicting values in `a`
pub fn json_merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (&mut Value::Object(ref mut a), Value::Object(b)) => {
            for (k, v) in b {
                json_merge(a.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (a, b) => {
            *a = b.clone();
        }
    }
}

/// FileWrite does the actual write of settings to disk.
/// Must be called from the context that holds the settings var in memory.
/// In the case of adaptor settings, must be called in the wrapping binary.  
pub trait FileWrite {
    fn write(&self, file_name: PathBuf) -> Result<(), SettingsError>;
}

impl<T> FileWrite for T
where
    T: Serialize,
{
    fn write(&self, file_name: PathBuf) -> Result<(), SettingsError> {
        let ser = toml::Value::try_from(self)?;
        let ser = toml::to_string(&ser)?;
        let mut file = File::create(file_name)?;
        file.write_all(ser.as_bytes())?;
        file.flush().unwrap();
        file.sync_all().unwrap();
        drop(file);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::RitaClientSettings;
    use crate::exit::RitaExitSettingsStruct;

    #[test]
    fn test_settings_test() {
        let ret = RitaClientSettings::new("test.toml").unwrap();
        println!("{ret:?}");
    }

    #[test]
    fn test_exit_settings_test() {
        RitaExitSettingsStruct::new("test_exit.toml").unwrap();
    }

    #[test]
    fn test_exit_settings_example() {
        RitaExitSettingsStruct::new("example_exit.toml").unwrap();
    }
}
