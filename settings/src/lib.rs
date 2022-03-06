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

use crate::client::{ExitClientSettings, ExitServer, SelectedExit};
use althea_types::Identity;
use ipnetwork::IpNetwork;
use network::NetworkSettings;
use payment::PaymentSettings;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

pub mod client;
pub mod exit;
pub mod localization;
pub mod logging;
pub mod network;
pub mod operator;
pub mod payment;
// pub mod tower;

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
    let settings_ref: &mut Option<Settings> = &mut *SETTINGS.write().unwrap();
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
    let settings_ref: &mut Option<Settings> = &mut *SETTINGS.write().unwrap();
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
    let settings_ref: &mut Option<Settings> = &mut *SETTINGS.write().unwrap();
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
pub fn set_rita_client(client_setting: RitaClientSettings) {
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

/// This merges 2 json objects, overwriting conflicting values in `a`
pub fn json_merge(a: &mut Value, b: &Value) {
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

/// Spawns a thread that will grab a copy of the updated RitaSettings
/// struct and then write it to the disk, if it changes every so often
/// currently this period is 600 seconds or 10 minutes per write. The value
/// should be kept low on routers due to low write endurance of storage
fn spawn_watch_thread_client(settings: RitaClientSettings, file_path: &str) {
    let file_path = file_path.to_string();

    thread::spawn(move || {
        let mut old_settings = settings.clone();
        loop {
            thread::sleep(Duration::from_secs(600));

            let new_settings = get_rita_client();

            if old_settings != new_settings {
                if let Err(e) = new_settings.write(&file_path) {
                    warn!("writing updated config failed {:?}", e);
                }
                old_settings = new_settings.clone();
            }
        }
    });
}

/// Spawns a thread that will grab a copy of the updated RitaSettings
/// struct and then write it to the disk, if it changes every so often
/// currently this period is 600 seconds or 10 minutes per write. The value
/// should be kept low on routers due to low write endurance of storage
fn spawn_watch_thread_exit(settings: RitaExitSettingsStruct, file_path: &str) {
    let file_path = file_path.to_string();

    thread::spawn(move || {
        let mut old_settings = settings.clone();
        loop {
            thread::sleep(Duration::from_secs(600));

            let new_settings = get_rita_exit();

            if old_settings != new_settings {
                trace!("writing updated config: {:?}", new_settings);
                if let Err(e) = new_settings.write(&file_path) {
                    warn!("writing updated config failed {:?}", e);
                }
                old_settings = new_settings.clone();
            }
        }
    });
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

///Takes a file config and updates the config to use the new ExitServer struct
pub fn update_config(
    old_settings: RitaClientSettings,
    subnet: u8,
) -> Result<RitaClientSettings, SettingsError> {
    let mut new_settings = RitaClientSettings {
        payment: old_settings.payment,
        log: old_settings.log,
        operator: old_settings.operator,
        localization: old_settings.localization,
        network: old_settings.network,
        exit_client: old_settings.exit_client.clone(),
        future: old_settings.future,
        app_name: old_settings.app_name,
    };

    // we have already updated to reading the new settings
    if old_settings.exit_client.old_exits.is_empty() {
        return Ok(new_settings);
    }

    let mut new_exits: HashMap<String, ExitServer> = HashMap::new();
    for (k, v) in old_settings.exit_client.clone().old_exits {
        let s_len = if v.subnet_len.is_some() {
            v.subnet_len.unwrap()
        } else {
            subnet
        };
        let mut new_exit: ExitServer = ExitServer {
            subnet: IpNetwork::new(v.id.mesh_ip, s_len)?,
            id: Some(v.id),
            subnet_len: s_len,
            selected_exit: SelectedExit::default(),
            eth_address: v.id.eth_address,
            wg_public_key: v.id.wg_public_key,
            registration_port: v.registration_port,
            description: v.description,
            info: v.info,
        };

        // we set the selected exit (starting exit) to be the one provided in config. This is required for registration
        new_exit.selected_exit.selected_id = Some(v.id.mesh_ip);

        // Special case for us_west, making it subnet 116. For africa, apac and sa, migrate ip such that they dont collide with uswest subnet
        if v.id.mesh_ip == IpAddr::V6("fd00::1337:e2f".parse().unwrap()) {
            new_exit = migrate_exit_ip(
                new_exit.clone(),
                new_exit.id.unwrap().mesh_ip,
                US_WEST_SUBNET,
            );
        } else if v.id.mesh_ip == IpAddr::V6("fd00::1337:e7f".parse().unwrap()) {
            //africa
            new_exit = migrate_exit_ip(new_exit, AFRICA_IP, SUBNET);
        } else if v.id.mesh_ip == IpAddr::V6("fd00::1337:e4f".parse().unwrap()) {
            //apac
            new_exit = migrate_exit_ip(new_exit, APAC_IP, SUBNET);
        } else if v.id.mesh_ip == IpAddr::V6("fd00::1337:e8f".parse().unwrap()) {
            //South Africa
            new_exit = migrate_exit_ip(new_exit, SA_IP, SUBNET);
        }

        new_exits.insert(k, new_exit);
    }

    let exit_client = old_settings.exit_client;
    new_settings.exit_client = ExitClientSettings {
        old_exits: exit_client.clone().old_exits,
        exits: exit_client.clone().exits,
        current_exit: exit_client.clone().current_exit,
        wg_listen_port: exit_client.wg_listen_port,
        //contact_info: exit_client.clone().contact_info,
        lan_nics: exit_client.clone().lan_nics,
        low_balance_notification: exit_client.low_balance_notification,
    };
    new_settings.exit_client.exits = new_exits.clone();
    //remove old info after migrating over
    new_settings.exit_client.old_exits = HashMap::new();
    Ok(new_settings)
}

/// This function updates RitaClient struct with hardcoded values for exit. For US West the subnet is expanded to 116 and for those
/// exits colliding within this subnet, they're ip gets mapped to a dummy ip
fn migrate_exit_ip(exit: ExitServer, exit_ip: IpAddr, subnet: u8) -> ExitServer {
    let mut new_exit = exit;
    new_exit.subnet = IpNetwork::new(exit_ip, subnet).unwrap();
    new_exit.subnet_len = subnet;
    let mut id = new_exit.id.as_mut().unwrap();
    id.mesh_ip = exit_ip;
    new_exit.selected_exit.selected_id = Some(exit_ip);
    new_exit
}

#[cfg(test)]
mod tests {
    use crate::client::RitaClientSettings;
    use crate::exit::RitaExitSettingsStruct;

    #[test]
    fn test_settings_test() {
        RitaClientSettings::new("test.toml").unwrap();
    }

    #[test]
    fn test_settings_example() {
        let settings = RitaClientSettings::new("old_example.toml").unwrap();
        assert!(!settings.exit_client.exits.is_empty())
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
