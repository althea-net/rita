extern crate althea_types;
extern crate config;
extern crate eui48;
extern crate num256;
extern crate owning_ref;
extern crate toml;

extern crate failure;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

extern crate serde;
extern crate serde_json;

extern crate althea_kernel_interface;

use owning_ref::{RwLockReadGuardRef, RwLockWriteGuardRefMut};

use std::clone;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread;
use std::time::Duration;

use config::Config;

use althea_types::{EthAddress, ExitRegistrationDetails, Identity};

use num256::Int256;

use althea_kernel_interface::{KernelInterface, KI};

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
pub struct ExitClientSettings {
    pub exit_ip: IpAddr,
    pub exit_registration_port: u16,
    pub wg_listen_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ExitClientDetails>,
    pub reg_details: ExitRegistrationDetails,
}

impl Default for ExitClientSettings {
    fn default() -> Self {
        ExitClientSettings {
            exit_ip: "fd00::8".parse().unwrap(),
            exit_registration_port: 4875,
            wg_listen_port: 59999,
            details: None,
            reg_details: ExitRegistrationDetails {
                zip_code: Some("1234".into()),
                email: Some("1234@gmail.com".into()),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitClientDetails {
    pub own_internal_ip: IpAddr,
    pub server_internal_ip: IpAddr,
    pub netmask: u8,
    pub eth_address: EthAddress,
    pub wg_public_key: String,
    pub wg_exit_port: u16,
    pub exit_price: u64,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_client: Option<ExitClientSettings>,
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
    payment: PaymentSettings,
    network: NetworkSettings,
    exit_network: ExitNetworkSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats_server: Option<StatsServerSettings>,
}

pub trait RitaCommonSettings<T> {
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

    fn get_identity(&self) -> Identity;
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
    fn init_exit_client(&self, exit_client: ExitClientSettings);
    fn set_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientSettings>;
    fn exit_client_is_set(&self) -> bool;

    fn get_exit_client_details<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientDetails>;
    fn init_exit_client_details(&self, details: ExitClientDetails);
    fn set_exit_client_details<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientDetails>;
    fn exit_client_details_is_set(&self) -> bool;

    fn get_exit_tunnel_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitTunnelSettings>;
}

impl RitaClientSettings for Arc<RwLock<RitaSettingsStruct>> {
    fn get_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| match g.exit_client {
            Some(ref exit_client) => exit_client,
            None => panic!("exit client not set but needed"),
        })
    }

    fn init_exit_client(&self, exit_client: ExitClientSettings) {
        self.write().unwrap().exit_client = Some(exit_client)
    }

    fn set_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| match g.exit_client {
            Some(ref mut exit_client) => exit_client,
            None => panic!("exit client not set but needed"),
        })
    }

    fn exit_client_is_set(&self) -> bool {
        self.read().unwrap().exit_client.is_some()
    }

    fn get_exit_client_details<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientDetails> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| match g.exit_client {
            Some(ref exit_client) => match exit_client.details {
                Some(ref details) => details,
                None => panic!("exit client details not set but needed"),
            },
            None => panic!("exit client not set but needed"),
        })
    }

    fn init_exit_client_details(&self, details: ExitClientDetails) {
        self.set_exit_client().details = Some(details)
    }

    fn set_exit_client_details<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientDetails> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| match g.exit_client {
            Some(ref mut exit_client) => match exit_client.details {
                Some(ref mut details) => details,
                None => panic!("exit client details not set but needed"),
            },
            None => panic!("exit client not set but needed"),
        })
    }

    fn exit_client_details_is_set(&self) -> bool {
        self.get_exit_client().details.is_some()
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
}

pub trait FileWrite {
    fn write(&self, file_name: &str) -> Result<(), Error>;
}

fn spawn_watch_thread<'de, T: 'static>(
    settings: Arc<RwLock<T>>,
    mut config: Config,
    file_path: &str,
) -> Result<(), Error>
where
    T: serde::Deserialize<'de> + Sync + Send + std::fmt::Debug + Clone + Eq + FileWrite,
{
    let file_path = file_path.to_string();

    thread::spawn(move || {
        let old_settings = settings.read().unwrap().clone();

        loop {
            thread::sleep(Duration::from_secs(5));

            let new_settings = settings.read().unwrap().clone();

            if old_settings != new_settings {
                info!("writing updated config: {:?}", new_settings);
                settings.read().unwrap().write(&file_path);
            }
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

        spawn_watch_thread(settings.clone(), s, file_name).unwrap();

        Ok(settings)
    }

    pub fn get_exit_id(&self) -> Option<Identity> {
        let details = self.exit_client.clone()?.details?;

        Some(Identity::new(
            self.exit_client.clone()?.exit_ip,
            details.eth_address.clone(),
            details.wg_public_key.clone(),
        ))
    }
}

impl FileWrite for RitaSettingsStruct {
    fn write(&self, file_name: &str) -> Result<(), Error> {
        let ser = toml::to_string(&self).unwrap();
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

        spawn_watch_thread(settings.clone(), s, file_name).unwrap();

        Ok(settings)
    }
}

impl FileWrite for RitaExitSettingsStruct {
    fn write(&self, file_name: &str) -> Result<(), Error> {
        let ser = toml::to_string(&self).unwrap();
        let mut file = File::create(file_name)?;
        file.write_all(ser.as_bytes())?;
        file.flush().unwrap();
        Ok(())
    }
}
