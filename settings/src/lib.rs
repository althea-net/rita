extern crate althea_types;
extern crate config;
extern crate eui48;
extern crate num256;
extern crate toml;

#[macro_use]
extern crate failure;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

extern crate serde;
extern crate serde_json;

extern crate althea_kernel_interface;

extern crate inotify;
use inotify::{Inotify, WatchMask};

use std::net::IpAddr;
use std::path::Path;
use std::fs::File;
use std::io::Write;
use std::thread;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use config::Config;

use althea_types::{EthAddress, Identity};

use num256::Int256;

use althea_kernel_interface::KernelInterface;

use failure::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkSettings {
    pub own_ip: IpAddr,
    pub bounty_ip: IpAddr,
    pub babel_port: u16,
    pub rita_port: u16,
    pub bounty_port: u16,
    pub wg_private_key: String,
    pub wg_private_key_path: String,
    pub wg_public_key: String,
    pub wg_start_port: u16,
    pub babel_interfaces: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentSettings {
    pub pay_threshold: Int256,
    pub close_threshold: Int256,
    pub close_fraction: Int256,
    pub buffer_period: u32,
    pub eth_address: EthAddress,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExitClientSettings {
    pub exit_ip: IpAddr,
    pub exit_registration_port: u16,
    pub wg_listen_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ExitClientDetails>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExitClientDetails {
    pub internal_ip: IpAddr,
    pub eth_address: EthAddress,
    pub wg_public_key: String,
    pub wg_exit_port: u16,
    pub exit_price: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RitaSettings {
    pub payment: PaymentSettings,
    pub network: NetworkSettings,
    pub exit_client: ExitClientSettings,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExitNetworkSettings {
    pub wg_tunnel_port: u16,
    pub external_nic: String,
    pub exit_price: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RitaExitSettings {
    pub db_file: String,
    pub payment: PaymentSettings,
    pub network: NetworkSettings,
    pub exit_network: ExitNetworkSettings,
}

fn spawn_watch_thread<'de, T: 'static>(
    settings: Arc<RwLock<T>>,
    mut config: Config,
    file_path: &str,
) -> Result<(), Error>
where
    T: serde::Deserialize<'de> + Sync + Send + std::fmt::Debug,
{
    let file_path = file_path.to_string();

    thread::spawn(move || {
        let mut inotify = Inotify::init().expect("Failed to initialize inotify");

        inotify
            .add_watch(&file_path, WatchMask::MODIFY)
            .expect("Failed to add inotify watch");

        println!("Watching file for activity...");

        let mut buffer = [0u8; 4096];
        loop {
            let events = inotify
                .read_events_blocking(&mut buffer)
                .expect("Failed to read inotify events");

            for _ in events {
                info!("config file written; refreshing configuration ...");
                thread::sleep(Duration::from_secs(1));
                let config = config.refresh().unwrap();
                let new_settings: T = config.clone().try_into().unwrap();
                info!("new config: {:#?}", new_settings);
                *settings.write().unwrap() = new_settings;
            }
        }
    });

    Ok(())
}

impl RitaSettings {
    pub fn new(file_name: &str, default: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(default))?;
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;

        Ok(settings)
    }

    pub fn new_watched(file_name: &str, default: &str) -> Result<Arc<RwLock<Self>>, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(default))?;
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.clone().try_into()?;

        let settings = Arc::new(RwLock::new(settings));

        spawn_watch_thread(settings.clone(), s, file_name).unwrap();

        Ok(settings)
    }

    pub fn get_identity(&self) -> Identity {
        let ki = KernelInterface {};
        Identity::new(
            self.network.own_ip.clone(),
            self.payment.eth_address.clone(),
            ki.get_wg_pubkey(Path::new(&self.network.wg_private_key_path))
                .unwrap(),
        )
    }

    pub fn get_exit_id(&self) -> Option<Identity> {
        let details = self.exit_client.details.clone()?;

        Some(Identity::new(
            self.exit_client.exit_ip.clone(),
            details.eth_address.clone(),
            details.wg_public_key.clone(),
        ))
    }

    pub fn write(&self, file_name: &str) -> Result<(), Error> {
        let ser = toml::to_string(&self).unwrap();
        let mut file = File::create(file_name)?;
        file.write_all(ser.as_bytes())?;
        file.flush().unwrap();
        Ok(())
    }
}

impl RitaExitSettings {
    pub fn new(file_name: &str, default: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(default))?;
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;

        let mut file = File::create(&Path::new(&settings.network.wg_private_key_path))?;
        file.write_all(&settings.network.wg_private_key.as_bytes())?;

        Ok(settings)
    }

    pub fn new_watched(file_name: &str, default: &str) -> Result<Arc<RwLock<Self>>, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(default))?;
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.clone().try_into()?;

        let mut file = File::create(&Path::new(&settings.network.wg_private_key_path))?;
        file.write_all(&settings.network.wg_private_key.as_bytes())?;

        let settings = Arc::new(RwLock::new(settings));

        spawn_watch_thread(settings.clone(), s, file_name).unwrap();

        Ok(settings)
    }

    pub fn get_identity(&self) -> Identity {
        let ki = KernelInterface {};

        Identity::new(
            self.network.own_ip.clone(),
            self.payment.eth_address.clone(),
            ki.get_wg_pubkey(Path::new(&self.network.wg_private_key_path))
                .unwrap(),
        )
    }

    pub fn write(&self, file_name: &str) -> Result<(), Error> {
        let ser = toml::to_string(&self).unwrap();
        let mut file = File::create(file_name)?;
        file.write_all(ser.as_bytes())?;
        Ok(())
    }
}
