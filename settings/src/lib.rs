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
use network::NetworkSettings;
use payment::PaymentSettings;
use serde::Serialize;
use serde_json::Value;
use std::fmt::Debug;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
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

pub const SUBNET: u8 = 128;
pub const US_WEST_SUBNET: u8 = 116;
pub const AFRICA_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x2e2f));
pub const APAC_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x4e2f));
pub const SA_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x6e2f));

lazy_static! {
    static ref GIT_HASH: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
}

lazy_static! {
    static ref FLAG_CONFIG: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
}

lazy_static! {
    static ref SETTINGS: Arc<RwLock<Option<Settings>>> = Arc::new(RwLock::new(None));
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
    let settings_ref: &mut Option<Settings> = &mut SETTINGS.write().unwrap();
    match settings_ref {
        // make sure this only gets called once on start
        Some(_) => panic!("Attempted to set settings adapter to a non-empty SETTINGS global"),
        // if there are no settings, then save as Adaptor
        None => {
            *settings_ref = Some(Settings::Adaptor(AdaptorSettings {
                adaptor: Box::new(adaptor),
            }))
        }
    }
}

/// A generic version of the more specific Rita settings struts use for Rita common
pub struct RitaSettings {
    pub payment: PaymentSettings,
    pub network: NetworkSettings,
    /// This member kept private to prevent modification since it's not
    /// saved in set_rita_common()
    identity: Option<Identity>,
}

impl RitaSettings {
    pub fn get_identity(&self) -> Option<Identity> {
        self.identity
    }
}

/// write the current SETTINGS from memory to file
pub fn write_config() -> Result<(), SettingsError> {
    if cfg!(feature = "load_from_disk") {
        // settings already saved in any set step
        return Ok(());
    }
    match &*SETTINGS.read().unwrap() {
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.write_config(),
        Some(Settings::Client(settings)) => {
            let filename = FLAG_CONFIG.read().unwrap();
            settings.write(&filename)
        }
        Some(Settings::Exit(settings)) => {
            let filename = FLAG_CONFIG.read().unwrap();
            settings.write(&filename)
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
    match &*SETTINGS.read().unwrap() {
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.get_config_json(),
        Some(Settings::Client(settings)) => settings.get_all(),
        Some(Settings::Exit(settings)) => settings.get_all(),
        None => panic!("expected settings but got none"),
    }
}

/// merge a json of a subset of settings into global settings
pub fn merge_config_json(changed_settings: serde_json::Value) -> Result<(), SettingsError> {
    let settings_ref: &mut Option<Settings> = &mut SETTINGS.write().unwrap();
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
    if cfg!(feature = "load_from_disk") {
        let settings_file = get_settings_file_from_ns();
        // load settings data from the settings file
        let mut ritasettings = RitaClientSettings::new(&settings_file).unwrap();
        ritasettings.network = input.network;
        ritasettings.payment = input.payment;
        // save to file
        set_rita_client(ritasettings);
        return;
    }
    let settings_ref: &mut Option<Settings> = &mut SETTINGS.write().unwrap();
    match settings_ref {
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
    if cfg!(feature = "load_from_disk") {
        let settings_file = get_settings_file_from_ns();

        match (
            RitaClientSettings::new(&settings_file),
            RitaExitSettingsStruct::new(&settings_file),
        ) {
            (Ok(ritasettings), _) => {
                // load settings data from the settings file
                let commonsettings = RitaSettings {
                    payment: ritasettings.payment.clone(),
                    network: ritasettings.network.clone(),
                    identity: ritasettings.get_identity(),
                };
                return commonsettings;
            }
            (_, Ok(ritasettings)) => {
                // load settings data from the settings file
                let commonsettings = RitaSettings {
                    payment: ritasettings.payment.clone(),
                    network: ritasettings.network.clone(),
                    identity: ritasettings.get_identity(),
                };
                return commonsettings;
            }
            (_, _) => panic!(
                "Impossible settings case in integration tests? {}",
                settings_file
            ),
        }
    }
    match &*SETTINGS.read().unwrap() {
        Some(Settings::Adaptor(adapt)) => {
            let settings = adapt.adaptor.get_client().unwrap();
            RitaSettings {
                network: settings.network.clone(),
                payment: settings.payment.clone(),
                identity: settings.get_identity(),
            }
        }
        Some(Settings::Client(settings)) => RitaSettings {
            network: settings.network.clone(),
            payment: settings.payment.clone(),
            identity: settings.get_identity(),
        },
        Some(Settings::Exit(settings)) => RitaSettings {
            network: settings.network.clone(),
            payment: settings.payment.clone(),
            identity: settings.get_identity(),
        },
        None => panic!("expected settings but got none"),
    }
}

pub fn set_git_hash(git_hash: String) {
    *GIT_HASH.write().unwrap() = git_hash;
}

pub fn get_git_hash() -> String {
    let ret = &*GIT_HASH.read().unwrap();
    ret.clone()
}

pub fn set_flag_config(flag_config: String) {
    *FLAG_CONFIG.write().unwrap() = flag_config;
}

pub fn get_flag_config() -> String {
    let ret = &*FLAG_CONFIG.read().unwrap();
    ret.clone()
}

/// set client settings into local or adaptor memory
/// panics if called on exit settings
pub fn set_rita_client(mut client_setting: RitaClientSettings) {
    if cfg!(feature = "load_from_disk") {
        let settings_file = get_settings_file_from_ns();
        // save new data to the settings file
        client_setting.write(&settings_file).unwrap();
        return;
    }
    client_setting.log.enabled = true;
    let settings_ref = &mut *SETTINGS.write().unwrap();
    match settings_ref {
        // if there's an adaptor already saved, then use it to set there
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.set_client(client_setting).unwrap(),
        // if there's a client setting, then save over it
        Some(Settings::Client(_)) => *settings_ref = Some(Settings::Client(client_setting)),
        // error if there's an exit here
        Some(Settings::Exit(_)) => panic!("attempted to save client settings over exit settings"),
        // if there are no settings, then save as Client
        None => *settings_ref = Some(Settings::Client(client_setting)),
    }
}

/// get client settings from local or adaptor memory
/// panics if called on exit settings
pub fn get_rita_client() -> RitaClientSettings {
    if cfg!(feature = "load_from_disk") {
        let settings_file = get_settings_file_from_ns();
        // load settings data from the settings file
        let ritasettings = RitaClientSettings::new(&settings_file).unwrap();
        return ritasettings;
    }
    match &*SETTINGS.read().unwrap() {
        Some(Settings::Adaptor(adapt)) => adapt.adaptor.get_client().unwrap(),
        Some(Settings::Client(settings)) => settings.clone(),
        Some(Settings::Exit(_)) => panic!("expected client settings, but got exit setttings"),
        None => panic!("expected settings but got none"),
    }
}

/// Set exit settings into memory
pub fn set_rita_exit(exit_setting: RitaExitSettingsStruct) {
    *SETTINGS.write().unwrap() = Some(Settings::Exit(exit_setting));
}

/// Retrieve exit settings from memory
pub fn get_rita_exit() -> RitaExitSettingsStruct {
    let temp = &*SETTINGS.read().unwrap();
    if let Some(Settings::Exit(val)) = temp {
        val.clone()
    } else {
        panic!("Failed to get RitaExitSettings from storage");
    }
}

/// This code checks to see if the current device/setting is an exit or not
pub fn check_if_exit() -> bool {
    match &*SETTINGS.read().unwrap() {
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

/// Gets the current namespace that rita is executing in and returns the name of the
/// settings file associated with this instance of rita. ONLY FOR INTEGRATION TESTV2
fn get_settings_file_from_ns() -> String {
    let ns = KI.run_command("ip", &["netns", "identify"]).unwrap();
    let ns = match String::from_utf8(ns.stdout) {
        Ok(s) => s,
        Err(_) => panic!("Could not get netns name!"),
    };
    let settings_file = format!("/var/tmp/settings_{ns}");
    settings_file
}

/// FileWrite does the actual write of settings to disk.
/// Must be called from the context that holds the settings var in memory.
/// In the case of adaptor settings, must be called in the wrapping binary.  
pub trait FileWrite {
    fn write(&self, file_name: &str) -> Result<(), SettingsError>;
}

impl<T> FileWrite for T
where
    T: Serialize,
{
    fn write(&self, file_name: &str) -> Result<(), SettingsError> {
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
