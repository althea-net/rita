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
use failure::Error;
use ipnetwork::IpNetwork;
use network::NetworkSettings;
use payment::PaymentSettings;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
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

use crate::client::RitaClientSettings;
use crate::exit::RitaExitSettingsStruct;

pub const SUBNET: u8 = 128;
pub const US_WEST_SUBNET: u8 = 116;
pub const AFRICA_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x2e2f));
pub const APAC_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x4e2f));
pub const SA_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x6e2f));

lazy_static! {
    static ref EXIT_SETTING: Arc<RwLock<Option<RitaExitSettingsStruct>>> =
        Arc::new(RwLock::new(None));
}

lazy_static! {
    static ref CLIENT_SETTING: Arc<RwLock<Option<RitaClientSettings>>> =
        Arc::new(RwLock::new(None));
}

lazy_static! {
    static ref GIT_HASH: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
}

lazy_static! {
    static ref FLAG_CONFIG: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
}

lazy_static! {
    static ref SETTINGS_TYPE: Arc<RwLock<SettingsType>> = Arc::new(RwLock::new(SettingsType::None));
}

lazy_static! {
    static ref ADAPTOR: Arc<RwLock<Option<Box<dyn WrappedSettingsAdaptor + Send + Sync + 'static>>>> =
        Arc::new(RwLock::new(None));
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
    fn get_client(&self) -> Result<RitaClientSettings, Error>;
    fn set_client(&self, client_settings: RitaClientSettings) -> Result<(), Error>;
    fn write_config(&self) -> Result<(), Error>;
    fn merge_client_json(&self, changed_settings: serde_json::Value) -> Result<(), Error>;
    fn get_config_json(&self) -> Result<serde_json::Value, Error>;
    // fn read_client(&self) -> Result<RitaClientSettings, Error>;
    // fn test(&self, arg: i32);
}

// This function can be called from a higher layer to set a reference to its adaptor
// Doing so will disable local reads/writes and instead call the adaptor's relevant fns
pub fn set_adaptor<T: 'static + WrappedSettingsAdaptor + Send + Sync>(adaptor: T) {
    // set the type to adaptor which disables local processing
    set_settings_type(SettingsType::Adaptor);
    // set the ref
    *ADAPTOR.write().unwrap() = Some(Box::new(adaptor))
}

pub fn get_settings_type() -> SettingsType {
    let temp = &*SETTINGS_TYPE.read().unwrap();
    temp.clone()
}

pub fn set_settings_type(typ: SettingsType) {
    *SETTINGS_TYPE.write().unwrap() = typ
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

pub fn write_config() -> Result<(), Error> {
    if get_settings_type() == SettingsType::Adaptor {
        match &*ADAPTOR.read().unwrap() {
            Some(adaptor) => adaptor.write_config(),
            None => panic!("Settings are wrapped but found no adaptor!"),
        }
    } else {
        let client_settings = &mut *CLIENT_SETTING.write().unwrap();
        let exit_settings = &mut *EXIT_SETTING.write().unwrap();
        // let wrap_settings = WRAP_ADAPTOR
        let filename = FLAG_CONFIG.read().unwrap();
        match (client_settings, exit_settings) {
            (Some(client), None) => client.write(&filename),
            (None, Some(exit)) => exit.write(&filename),
            (Some(_), Some(_)) => {
                panic!("Both types of config are loaded, this is impossible in production!")
            }
            (None, None) => panic!("No config has been loaded, check init"),
        }
    }
}

pub fn get_config_json() -> Result<serde_json::Value, Error> {
    if get_settings_type() == SettingsType::Adaptor {
        match &*ADAPTOR.read().unwrap() {
            Some(adaptor) => adaptor
                .get_client()
                .expect("Adaptor failed to get_client")
                .get_all(),
            None => panic!("settings are wrapped but found no adaptor!"),
        }
    } else {
        let client_settings = &mut *CLIENT_SETTING.write().unwrap();
        let exit_settings = &mut *EXIT_SETTING.write().unwrap();
        match (client_settings, exit_settings) {
            (Some(client), None) => client.get_all(),
            (None, Some(exit)) => exit.get_all(),
            (Some(_), Some(_)) => {
                panic!("Both types of config are loaded, this is impossible in production!")
            }
            (None, None) => panic!("No config has been loaded, check init"),
        }
    }
}

pub fn merge_config_json(changed_settings: serde_json::Value) -> Result<(), Error> {
    if get_settings_type() == SettingsType::Adaptor {
        match &*ADAPTOR.read().unwrap() {
            Some(adaptor) => adaptor.merge_client_json(changed_settings),
            None => panic!("settings are wrapped but found no adaptor!"),
        }
    } else {
        let client_settings = &mut *CLIENT_SETTING.write().unwrap();
        let exit_settings = &mut *EXIT_SETTING.write().unwrap();
        match (client_settings, exit_settings) {
            (Some(client), None) => client.merge(changed_settings),
            (None, Some(exit)) => exit.merge(changed_settings),
            (Some(_), Some(_)) => {
                panic!("Both types of config are loaded, this is impossible in production!")
            }
            (None, None) => panic!("No config has been loaded, check init"),
        }
    }
}

/// Set the RitaClientSettings Struct or RitaExitSettingsStruct
/// depending on which one is called from the argument parameter
/// does not currently save the identity paramater, as we don't
/// need to modify that in a generic context.
pub fn set_rita_common(input: RitaSettings) {
    if get_settings_type() == SettingsType::Adaptor {
        match &*ADAPTOR.read().unwrap() {
            Some(adaptor) => {
                let mut client_settings =
                    adaptor.get_client().expect("Adaptor failed to get_client");
                client_settings.network = input.network;
                client_settings.payment = input.payment;
                adaptor
                    .set_client(client_settings)
                    .expect("Adaptor failed to set_client");
            }
            None => panic!("settings are wrapped but found no adaptor!"),
        }
    } else {
        let client_settings = &mut *CLIENT_SETTING.write().unwrap();
        let exit_settings = &mut *EXIT_SETTING.write().unwrap();
        match (client_settings, exit_settings) {
            (Some(client), None) => {
                client.network = input.network;
                client.payment = input.payment;
            }
            // do the other way around for rita exit, panic if both are Some()
            // if both are none also panic becuase rita_client or rita_exit must first
            // initialize
            (None, Some(exit)) => {
                exit.network = input.network;
                exit.payment = input.payment;
            }
            (Some(_), Some(_)) => {
                panic!("Both types of config are loaded, this is impossible in production!")
            }
            (None, None) => panic!("No config has been loaded, check init"),
        }
    }
}

/// Get the RitaClientSettingsStruct or RitaExitSettingsStruct
/// depending on which one is set
pub fn get_rita_common() -> RitaSettings {
    if get_settings_type() == SettingsType::Adaptor {
        match &*ADAPTOR.read().unwrap() {
            Some(adaptor) => {
                let client_settings = adaptor.get_client().expect("Adaptor failed to get_client");
                RitaSettings {
                    network: client_settings.network.clone(),
                    payment: client_settings.payment.clone(),
                    identity: client_settings.get_identity(),
                }
            }
            None => panic!("settings are wrapped but found no adaptor!"),
        }
    } else {
        let client_settings = &*CLIENT_SETTING.read().unwrap();
        let exit_settings = &*EXIT_SETTING.read().unwrap();
        match (client_settings, exit_settings) {
            (Some(client), None) => RitaSettings {
                network: client.network.clone(),
                payment: client.payment.clone(),
                identity: client.get_identity(),
            },
            (None, Some(exit)) => RitaSettings {
                network: exit.network.clone(),
                payment: exit.payment.clone(),
                identity: exit.get_identity(),
            },
            (Some(_), Some(_)) => panic!("Rita_common cannot be both exit and client"),
            (None, None) => panic!("Both types are none. One needs to be initalized!"),
        }
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

pub fn set_rita_client(client_setting: RitaClientSettings) {
    if get_settings_type() == SettingsType::Adaptor {
        match &*ADAPTOR.read().unwrap() {
            Some(adaptor) => adaptor
                .set_client(client_setting)
                .expect("Adaptor failed to set_client"),
            None => panic!("Settings are wrapped but found no adaptor!"),
        }
    } else {
        *CLIENT_SETTING.write().unwrap() = Some(client_setting);
    }
}

pub fn get_rita_client() -> RitaClientSettings {
    if get_settings_type() == SettingsType::Adaptor {
        match &*ADAPTOR.read().unwrap() {
            Some(adaptor) => adaptor.get_client().expect("Adaptor failed to get_client"),
            None => panic!("Settings are wrapped but found no adaptor!"),
        }
    } else {
        let temp = &*CLIENT_SETTING.read().unwrap();
        let ret = match temp {
            Some(val) => val,
            None => panic!("Attempted to get_rita_client() before initialization"),
        };
        ret.clone()
    }
}

pub fn set_rita_exit(exit_setting: RitaExitSettingsStruct) {
    *EXIT_SETTING.write().unwrap() = Some(exit_setting);
}

/// This function retrieves the rita exit binary settings.
pub fn get_rita_exit() -> RitaExitSettingsStruct {
    let temp = &*EXIT_SETTING.read().unwrap();
    let ret = match temp {
        Some(val) => val,
        None => panic!("Attempted to get_rita_exit() before initialization"),
    };
    ret.clone()
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

pub trait FileWrite {
    fn write(&self, file_name: &str) -> Result<(), Error>;
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

impl<T> FileWrite for T
where
    T: Serialize,
{
    fn write(&self, file_name: &str) -> Result<(), Error> {
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
) -> Result<RitaClientSettings, Error> {
    let mut new_settings = RitaClientSettings {
        payment: old_settings.payment,
        log: old_settings.log,
        operator: old_settings.operator,
        localization: old_settings.localization,
        network: old_settings.network,
        exit_client: old_settings.exit_client.clone(),
        future: old_settings.future,
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
        contact_info: exit_client.clone().contact_info,
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
