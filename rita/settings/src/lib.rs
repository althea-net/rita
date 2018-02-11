use std::net::IpAddr;

extern crate config;
use config::{ConfigError, Config, File, Environment};

extern crate althea_types;
use althea_types::{EthAddress, MacAddress, Int256};

extern crate docopt;
use docopt::Docopt;

#[macro_use]
extern crate serde_derive;
extern crate serde;
use serde::{Deserialize};

#[macro_use]
extern crate lazy_static;

const USAGE: &'static str = "
Usage: rita --config <settings>
Options:
    --config   Name of config file
";

lazy_static! {
    pub static ref SETTING: Settings = {
        let args = Docopt::new(USAGE)
        .and_then(|d| d.parse())
        .unwrap_or_else(|e| e.exit());

        let settings_file = args.get_str("<settings>");

        Settings::new(settings_file).unwrap()
    };
}

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