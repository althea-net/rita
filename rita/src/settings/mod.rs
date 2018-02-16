use std::net::IpAddr;
use std::path::Path;

use config::{ConfigError, Config, File, Environment};

use althea_types::{EthAddress, Identity};

use eui48::MacAddress;

use num256::Int256;

use docopt::Docopt;

use serde::{Serialize, Deserialize};

use althea_kernel_interface::KernelInterface;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub own_ip: IpAddr,
    pub own_mac: MacAddress,
    pub bounty_ip: IpAddr,
    pub babel_port: u16,
    pub rita_port: u16,
    pub bounty_port: u16,
    pub wg_private_key: String,
    pub wg_start_port: u16
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentSettings {
    pub pay_threshold: Int256,
    pub close_threshold: Int256,
    pub close_fraction: Int256,
    pub buffer_period: u32,
    pub eth_address: EthAddress,
}

#[derive(Debug, Serialize, Deserialize)]
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

    pub fn get_identity(&self) -> Identity {
        let mut ki = KernelInterface{};
        ki.create_wg_key(Path::new(&SETTING.network.wg_private_key));

        Identity{
            eth_address: self.payment.eth_address.clone(),
            mesh_ip: self.network.own_ip.clone(),
            wg_public_key: ki.get_wg_pubkey(Path::new(&self.network.wg_private_key)).unwrap(),
        }
    }
}