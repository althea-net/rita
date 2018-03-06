use std::net::IpAddr;

extern crate config;
use config::{Config, ConfigError, Environment, File};

extern crate serde;
#[macro_use]
extern crate serde_derive;
use serde::Deserialize;

extern crate docopt;
use docopt::Docopt;

#[macro_use]
extern crate lazy_static;

const USAGE: &'static str = "
Usage: post_office --config <settings>
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
pub struct ServerSettings {
    pub bind_ip: IpAddr,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub server: ServerSettings,
}

impl Settings {
    pub fn new(file_name: &str) -> Result<Self, ConfigError> {
        let mut s = Config::new();
        s.merge(File::with_name(file_name))?;
        s.try_into()
    }
}
