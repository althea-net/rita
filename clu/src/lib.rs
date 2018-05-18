#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

use std::net::IpAddr;

extern crate settings;
use settings::{NetworkSettings, RitaCommonSettings};

extern crate ipgen;
extern crate rand;
use rand::{thread_rng, Rng};

use std::str;

use failure::Error;

extern crate reqwest;

use althea_kernel_interface::KI;

extern crate althea_kernel_interface;
use regex::Regex;
use std::path::Path;
use std::sync::{Arc, RwLock};

extern crate althea_types;
extern crate regex;

#[derive(Debug, Fail)]
pub enum CluError {
    #[fail(display = "Runtime Error: {:?}", _0)]
    RuntimeError(String),
}

fn linux_generate_wg_keys(config: &mut NetworkSettings) -> Result<(), Error> {
    let keys = KI.create_wg_keypair()?;
    let wg_public_key = &keys[0];
    let wg_private_key = &keys[1];

    //Mutates settings, intentional side effect
    config.wg_private_key = wg_private_key.to_string();
    config.wg_public_key = wg_public_key.to_string();

    Ok(())
}

fn linux_generate_mesh_ip(config: &mut NetworkSettings) -> Result<(), Error> {
    let seed: String = thread_rng().gen_ascii_chars().take(50).collect();
    let mesh_ip = ipgen::ip(&seed, "fd00::/8").unwrap();

    info!("generated new ip address {}", mesh_ip);

    // Mutates Settings intentional side effect
    config.own_ip = mesh_ip;
    Ok(())
}

fn validate_wg_key(key: &str) -> bool {
    key.len() == 44 && key.ends_with("=") && !key.contains(" ")
}

fn validate_mesh_ip(ip: &IpAddr) -> bool {
    ip.is_ipv6() && !ip.is_unspecified()
}

/// called before anything is started to delete existing wireguard per hop tunnels
pub fn cleanup() -> Result<(), Error> {
    let interfaces = KI.get_interfaces()?;

    let re = Regex::new(r"^wg[0-9]+$")?;

    for i in interfaces {
        if re.is_match(&i) {
            match KI.del_interface(&i) {
                Err(e) => trace!("Failed to delete wg# {:?}", e),
                _ => (),
            };
        }
    }

    match KI.del_interface("wg_exit") {
        Err(e) => trace!("Failed to delete wg_exit {:?}", e),
        _ => (),
    };

    Ok(())
}

fn linux_init(config: Arc<RwLock<settings::RitaSettingsStruct>>) -> Result<(), Error> {
    cleanup()?;
    KI.restore_default_route(&mut config.get_network_mut().default_route)?;

    let privkey = config.get_network().wg_private_key.clone();
    let pubkey = config.get_network().wg_public_key.clone();
    let mesh_ip = config.get_network().own_ip.clone();

    if !validate_wg_key(&privkey) || !validate_wg_key(&pubkey) {
        linux_generate_wg_keys(&mut config.get_network_mut()).expect("failed to generate wg keys");
    }
    if !validate_mesh_ip(&mesh_ip) {
        linux_generate_mesh_ip(&mut config.get_network_mut()).expect("failed to generate ip");
    }

    //Creates file on disk containing key
    KI.create_wg_key(
        &Path::new(&config.get_network().wg_private_key_path),
        &config.get_network().wg_private_key,
    )?;

    Ok(())
}

fn linux_exit_init(config: Arc<RwLock<settings::RitaExitSettingsStruct>>) -> Result<(), Error> {
    cleanup()?;

    let privkey = config.get_network().wg_private_key.clone();
    let pubkey = config.get_network().wg_public_key.clone();
    let mesh_ip = config.get_network().own_ip.clone();

    if !validate_wg_key(&privkey) || !validate_wg_key(&pubkey) {
        linux_generate_wg_keys(&mut config.get_network_mut())?;
    }
    if !validate_mesh_ip(&mesh_ip) {
        linux_generate_mesh_ip(&mut config.get_network_mut())?;
    }

    //Creates file on disk containing key
    KI.create_wg_key(
        &Path::new(&config.get_network().wg_private_key_path),
        &config.get_network().wg_private_key,
    )?;

    Ok(())
}

pub fn init(platform: &str, settings: Arc<RwLock<settings::RitaSettingsStruct>>) {
    match platform {
        "linux" => linux_init(settings).unwrap(),
        _ => unimplemented!(),
    }
}

pub fn exit_init(platform: &str, settings: Arc<RwLock<settings::RitaExitSettingsStruct>>) {
    match platform {
        "linux" => linux_exit_init(settings).unwrap(),
        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_wg_key() {
        let good_key = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=";
        let bad_key1 = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpXk=";
        let bad_key2 = "look at me, I'm the same length as a key but";
        let bad_key3 = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpXkk";
        let bad_key4 = "8BeCExnthLe5ou0EYe 5jNqJ/PduZ1x2o7lpXJOpXkk";
        assert_eq!(validate_wg_key(&good_key), true);
        assert_eq!(validate_wg_key(&bad_key1), false);
        assert_eq!(validate_wg_key(&bad_key2), false);
        assert_eq!(validate_wg_key(&bad_key3), false);
        assert_eq!(validate_wg_key(&bad_key4), false);
    }

    #[test]
    fn test_generate_wg_key() {
        let keys = KI.create_wg_keypair().unwrap();
        let wg_public_key = &keys[0];
        let wg_private_key = &keys[1];
        assert_eq!(validate_wg_key(&wg_public_key), true);
        assert_eq!(validate_wg_key(&wg_private_key), true);
    }

    #[test]
    fn test_validate_mesh_ip() {
        let good_ip = "fd44:94c:41e2::9e6".parse::<IpAddr>().unwrap();
        let bad_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        assert_eq!(validate_mesh_ip(&good_ip), true);
        assert_eq!(validate_mesh_ip(&bad_ip), false);
    }
}
