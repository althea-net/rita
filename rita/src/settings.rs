use std::net::IpAddr;

use serde::{Deserialize};

use config::{ConfigError, Config, File, Environment};

use althea_types::{EthAddress, MacAddress, Int256};

#[derive(Debug, Deserialize)]
pub struct NetworkSettings {
    pub own_ip: IpAddr,
    pub own_mac: MacAddress,
    pub bounty_ip: IpAddr,
    pub babel_port: u16,
    pub rita_port: u16,
    pub bounty_port: u16,
}

#[derive(Debug, Deserialize)]
pub struct PaymentSettings {
    pub pay_threshold: Int256,
    pub close_threshold: Int256,
    pub close_fraction: Int256,
    pub buffer_period: u32,
    pub eth_address: EthAddress,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub payment: PaymentSettings,
    pub network: NetworkSettings
}

impl Settings {
    pub fn new(file_name: &str) -> Result<Self, ConfigError> {
        let mut s = Config::new();
        s.merge(File::with_name(file_name))?;
        s.try_into()
    }
}