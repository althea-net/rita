use althea_types::WgKey;
use clarity::PrivateKey;
use lazy_static::lazy_static;
use log::error;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read};

use crate::DEVELOPMENT;

///Struct containing settings for Exit root server
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigStruct {
    pub clarity_private_key: PrivateKey,
    pub wg_private_key: WgKey,
}

impl ConfigStruct {
    pub fn load(path: String) -> Option<ConfigStruct> {
        let mut config_toml = String::new();

        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(_) => {
                error!("Could not find config file. Using default!");
                return None;
            }
        };

        file.read_to_string(&mut config_toml)
            .unwrap_or_else(|err| panic!("Error while reading config: [{}]", err));

        let res = toml::from_str(&config_toml).unwrap();
        Some(res)
    }
}

/// loads the exit root server config, broken out here so that
/// we can easily verify that the config is valid before starting
pub fn load_config() -> ConfigStruct {
    // change the config name based on our development status
    let file_name = if DEVELOPMENT || cfg!(test) {
        return ConfigStruct {
            clarity_private_key: PrivateKey::from_bytes([1u8; 32]).unwrap(),
            wg_private_key: WgKey::from([2; 32]),
        };
    } else {
        "/etc/exit_root_server.toml"
    };
    let config_structs = ConfigStruct::load(file_name.to_string());
    if let Some(conf) = config_structs {
        conf
    } else {
        panic!(
            "Can not find configuration file! for filename {:?}",
            file_name
        );
    }
}

lazy_static! {
    pub static ref CONFIG: ConfigStruct = load_config();
}
