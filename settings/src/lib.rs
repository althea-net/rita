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
pub const US_WEST_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1000, 0x0e2f));
pub const US_WEST_SUBNET: u8 = 116;

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
    let client_settings = &mut *CLIENT_SETTING.write().unwrap();
    let exit_settings = &mut *EXIT_SETTING.write().unwrap();
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

pub fn get_config_json() -> Result<serde_json::Value, Error> {
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

pub fn merge_config_json(changed_settings: serde_json::Value) -> Result<(), Error> {
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

/// Set the RitaClientSettings Struct or RitaExitSettingsStruct
/// depending on which one is called from the argument parameter
/// does not currently save the identity paramater, as we don't
/// need to modify that in a generic context.
pub fn set_rita_common(input: RitaSettings) {
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

/// Get the RitaClientSettingsStruct or RitaExitSettingsStruct
/// depending on which one is set
pub fn get_rita_common() -> RitaSettings {
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
    *CLIENT_SETTING.write().unwrap() = Some(client_setting);
}

/// This function retrieves the rita client binary settings.
pub fn get_rita_client() -> RitaClientSettings {
    let temp = &*CLIENT_SETTING.read().unwrap();
    let ret = match temp {
        Some(val) => val,
        None => panic!("Attempted to get_rita_client() before initialization"),
    };
    ret.clone()
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
        exit_client: ExitClientSettings::default(),
        future: old_settings.future,
    };

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

        // Special case for us_west.
        if v.id.mesh_ip == IpAddr::V6("fd00::1337:e2f".parse().unwrap()) {
            new_exit = set_us_west(new_exit);
        }

        new_exits.insert(k, new_exit);
    }

    let exit_client = old_settings.exit_client;
    new_settings.exit_client = ExitClientSettings {
        old_exits: exit_client.clone().old_exits,
        exits: HashMap::new(),
        current_exit: exit_client.clone().current_exit,
        wg_listen_port: exit_client.wg_listen_port,
        contact_info: exit_client.clone().contact_info,
        lan_nics: exit_client.clone().lan_nics,
        low_balance_notification: exit_client.low_balance_notification,
    };
    new_settings.exit_client.exits = new_exits.clone();

    Ok(new_settings)
}

/// This function updates RitaClient struct with hardcoded values for us_west. To update this, we change the ip and add a subnet 116. When
/// router update to this version of rita, this automatically sets us west as a subnet to take advantage of the exit switching code
fn set_us_west(exit: ExitServer) -> ExitServer {
    let mut new_exit = exit;
    new_exit.subnet = IpNetwork::new(US_WEST_IP, US_WEST_SUBNET).unwrap();
    new_exit.id.unwrap().mesh_ip = US_WEST_IP;
    new_exit.subnet_len = US_WEST_SUBNET;
    new_exit.selected_exit.selected_id = Some(US_WEST_IP);
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
