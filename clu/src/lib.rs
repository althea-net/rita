//! Clu is used to handle init tasks, mostly genreating eth and wireguard keys

#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;

use althea_kernel_interface::KI;
use clarity::PrivateKey;
use failure::Error;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use regex::Regex;
use settings::client::RitaClientSettings;
use settings::exit::RitaExitSettingsStruct;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::str;

#[derive(Debug, Fail)]
pub enum CluError {
    #[fail(display = "Runtime Error: {:?}", _0)]
    RuntimeError(String),
}

pub fn generate_mesh_ip() -> Result<IpAddr, Error> {
    let seed: String =
        String::from_utf8(thread_rng().sample_iter(&Alphanumeric).take(50).collect()).unwrap();
    let mesh_ip = match ipgen::ip(&seed, "fd00::/8".parse().unwrap()) {
        Ok(ip) => ip,
        Err(msg) => bail!(msg), // For some reason, ipgen devs decided to use Strings for all errors
    };

    info!("Generated a new mesh IP address: {}", mesh_ip);

    Ok(mesh_ip)
}

pub fn validate_mesh_ip(ip: &IpAddr) -> bool {
    ip.is_ipv6() && !ip.is_unspecified()
}

/// Called before anything is started to delete existing wireguard per hop tunnels
pub fn cleanup() -> Result<(), Error> {
    debug!("Cleaning up WireGuard tunnels");

    lazy_static! {
        static ref RE: Regex = Regex::new(r"^wg[0-9]+$").unwrap();
    }

    for i in KI.get_interfaces()? {
        if RE.is_match(&i) {
            if let Err(e) = KI.del_interface(&i) {
                trace!("Failed to delete wg# {:?}", e);
            }
        }
    }

    if let Err(e) = KI.del_interface("wg_exit") {
        trace!("Failed to delete wg_exit {:?}", e);
    }

    Ok(())
}

fn linux_init(settings: RitaClientSettings) -> Result<RitaClientSettings, Error> {
    cleanup()?;
    let mut settings = settings;
    let mut network_settings = settings.network;
    // this value will be none for most routers but a route for gateways.
    KI.restore_default_route(&mut network_settings.last_default_route)?;

    // handle things we need to generate at runtime
    let mesh_ip_option = network_settings.mesh_ip;
    let wg_pubkey_option = network_settings.wg_public_key;
    let wg_privkey_option = network_settings.wg_private_key;
    let device_option = network_settings.device.clone();

    match mesh_ip_option {
        Some(existing_mesh_ip) => {
            if !validate_mesh_ip(&existing_mesh_ip) {
                warn!(
                    "Existing mesh_ip field {} is invalid, generating a new mesh IP",
                    existing_mesh_ip
                );
                network_settings.mesh_ip =
                    Some(generate_mesh_ip().expect("failed to generate a new mesh IP"));
            } else {
                info!("Mesh IP is {}", existing_mesh_ip);
            }
        }
        None => {
            info!("There's no mesh IP configured, generating");
            network_settings.mesh_ip =
                Some(generate_mesh_ip().expect("failed to generate a new mesh IP"));
        }
    }

    match device_option {
        Some(existing_device) => {
            info!("Device name is {}", existing_device);
        }
        None => {
            let release_file_path = "/etc/althea-firmware-release";
            info!(
                "No device name was found, reading from {}",
                release_file_path
            );

            let mut contents = String::new();
            match File::open(release_file_path) {
                Ok(mut f) => {
                    f.read_to_string(&mut contents)?;
                }
                Err(e) => warn!("Couldn't open {}: {}", release_file_path, e),
            };

            for line in contents.lines() {
                if line.starts_with("device:") {
                    let device = line.split(' ').nth(1).ok_or_else(|| {
                        format_err!("Could not obtain device name from line {:?}", line)
                    })?;

                    network_settings.device = Some(device.to_string());

                    break;
                }
            }

            if network_settings.device.is_none() {
                warn!("Device name could not be read from {}", release_file_path);
            }
        }
    }

    // generates a keypair if we don't already have a valid one
    if wg_privkey_option.is_none() || wg_pubkey_option.is_none() {
        info!("Existing wireguard keypair is invalid, generating from scratch");
        let keypair = KI.create_wg_keypair().expect("failed to generate wg keys");
        network_settings.wg_public_key = Some(keypair.public);
        network_settings.wg_private_key = Some(keypair.private);
    }

    // Creates file on disk containing key
    KI.create_wg_key(
        Path::new(&network_settings.wg_private_key_path),
        &network_settings
            .wg_private_key
            .expect("How did we get here without generating a key above?"),
    )?;

    // Sometimes due to a bad port toggle the external nic can still be populated
    // as a peer_interface, this cleans that up.
    if let Some(external_nic) = network_settings.external_nic.clone() {
        let res = network_settings.peer_interfaces.remove(&external_nic);
        if res {
            warn!("Duplicate interface removed!");
        }
    }
    settings.network = network_settings;

    let mut payment_settings = settings.payment;
    let eth_private_key_option = payment_settings.eth_private_key;

    match eth_private_key_option {
        Some(existing_eth_private_key) => {
            info!(
                "Starting with Eth address {:?}",
                existing_eth_private_key.to_public_key()?
            );

            payment_settings.eth_address = Some(existing_eth_private_key.to_public_key()?);
        }
        None => {
            info!("Eth key details not configured, generating");
            let key_buf: [u8; 32] = rand::random();
            let new_private_key = PrivateKey::from_slice(&key_buf)?;
            payment_settings.eth_private_key = Some(new_private_key);

            payment_settings.eth_address = Some(new_private_key.to_public_key()?)
        }
    }

    settings.payment = payment_settings;

    trace!("Starting with settings (after clu) : {:?}", settings);
    assert!(settings.get_identity().is_some());
    Ok(settings)
}

fn linux_exit_init(settings: RitaExitSettingsStruct) -> Result<RitaExitSettingsStruct, Error> {
    cleanup()?;
    let mut settings = settings;

    let mut network_settings = settings.network;
    let exit_network_settings = settings.exit_network;
    let mesh_ip_option = network_settings.mesh_ip;
    let wg_pubkey_option = network_settings.wg_public_key;
    let wg_privkey_option = network_settings.wg_private_key;

    match mesh_ip_option {
        Some(existing_mesh_ip) => {
            if !validate_mesh_ip(&existing_mesh_ip) {
                warn!(
                    "Existing mesh_ip field {} is invalid, generating a new mesh IP",
                    existing_mesh_ip
                );
                network_settings.mesh_ip =
                    Some(generate_mesh_ip().expect("failed to generate a new mesh IP"));
            } else {
                info!("Mesh IP is {}", existing_mesh_ip);
            }
        }

        None => {
            info!("There's no mesh IP configured, generating");
            network_settings.mesh_ip =
                Some(generate_mesh_ip().expect("failed to generate a new mesh IP"));
        }
    }

    if wg_privkey_option.is_none() || wg_pubkey_option.is_none() {
        info!("Existing wireguard keypair is invalid, generating from scratch");
        let keypair = KI.create_wg_keypair().expect("failed to generate wg keys");
        network_settings.wg_public_key = Some(keypair.public);
        network_settings.wg_private_key = Some(keypair.private);
    }

    // Creates file on disk containing key
    KI.create_wg_key(
        Path::new(&network_settings.wg_private_key_path),
        &network_settings
            .wg_private_key
            .expect("How did we get here without generating a key above?"),
    )?;
    // same thing but with the exit key
    KI.create_wg_key(
        Path::new(&exit_network_settings.wg_private_key_path),
        &exit_network_settings.wg_private_key.clone(),
    )?;

    let mut payment_settings = settings.payment;
    let eth_private_key_option = payment_settings.eth_private_key;

    match eth_private_key_option {
        Some(existing_eth_private_key) => {
            info!(
                "Starting with Eth address {:?}",
                existing_eth_private_key.to_public_key()?
            );

            payment_settings.eth_address = Some(existing_eth_private_key.to_public_key()?);
        }
        None => {
            info!("Eth key details not configured, generating");
            let key_buf: [u8; 32] = rand::random();
            let new_private_key = PrivateKey::from_slice(&key_buf)?;
            payment_settings.eth_private_key = Some(new_private_key);

            payment_settings.eth_address = Some(new_private_key.to_public_key()?)
        }
    }
    settings.payment = payment_settings;
    settings.network = network_settings;
    settings.exit_network = exit_network_settings;
    trace!("Starting with settings (after clu) : {:?}", settings);
    assert!(settings.get_identity().is_some());
    Ok(settings)
}

pub fn init(platform: &str, settings: RitaClientSettings) -> RitaClientSettings {
    match platform {
        "linux" => linux_init(settings).unwrap(),
        _ => unimplemented!(),
    }
}

pub fn exit_init(platform: &str, settings: RitaExitSettingsStruct) -> RitaExitSettingsStruct {
    match platform {
        "linux" => linux_exit_init(settings).unwrap(),
        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod tests {
    use crate::generate_mesh_ip;
    use crate::validate_mesh_ip;
    use althea_types::WgKey;
    use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
    use std::collections::HashSet;
    use std::net::IpAddr;

    /// generate 1000 mesh ip's make sure we succeed and that all are unique
    #[test]
    fn test_generate_mesh_ip() {
        let mut history = HashSet::new();
        for _ in 0..1000 {
            let ip = generate_mesh_ip().unwrap();
            if history.get(&ip).is_some() {
                panic!("Got duplicate ip {}", ip)
            } else {
                history.insert(ip);
            }
        }
    }

    #[test]
    fn test_validate_mesh_ip() {
        let good_ip = "fd44:94c:41e2::9e6".parse::<IpAddr>().unwrap();
        let bad_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        assert!(validate_mesh_ip(&good_ip));
        assert!(!validate_mesh_ip(&bad_ip));
    }

    #[test]
    fn libsodium_wg_compat() {
        let wg_gen_secret: WgKey = "aMLGOa3Z4Rjmfq7lUVTnc01wA/oh0OImoMxiFMbLtG0="
            .parse()
            .unwrap();
        let wg_gen_pub: WgKey = "ODxLQWc+ZrHqmPuGx/NWH8IfgBWJGZDsHOls16EaJF0="
            .parse()
            .unwrap();
        let libsodium_secret: SecretKey = wg_gen_secret.into();
        let libsodium_pub = libsodium_secret.public_key();
        let libsodium_generated_public_key: WgKey = libsodium_pub.0.into();
        println!("{} vs {}", wg_gen_pub, libsodium_generated_public_key);
        assert_eq!(libsodium_generated_public_key, wg_gen_pub);
    }
}
