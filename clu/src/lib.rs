//! Clu is used to handle init tasks, mostly genreating eth and wireguard keys

#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

#[macro_use]
extern crate lazy_static;

use settings;
use settings::exit::RitaExitSettings;
use settings::RitaCommonSettings;

use ipgen;
use rand;

use clarity::PrivateKey;

use rand::{thread_rng, Rng};

use std::str;

use failure::Error;

use althea_kernel_interface::KI;

use rand::distributions::Alphanumeric;
use regex::Regex;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Arc, RwLock};

use babel_monitor::Babel;

#[derive(Debug, Fail)]
pub enum CluError {
    #[fail(display = "Runtime Error: {:?}", _0)]
    RuntimeError(String),
}

pub fn linux_generate_mesh_ip() -> Result<IpAddr, Error> {
    let seed: String = thread_rng().sample_iter(&Alphanumeric).take(50).collect();
    let mesh_ip = match ipgen::ip(&seed, "fd00::/8") {
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

fn linux_init(config: Arc<RwLock<settings::client::RitaSettingsStruct>>) -> Result<(), Error> {
    cleanup()?;
    KI.restore_default_route(&mut config.get_network_mut().default_route)?;

    // handle things we need to generate at runtime
    let mut network_settings = config.get_network_mut();
    let mesh_ip_option = network_settings.mesh_ip.clone();
    let wg_pubkey_option = network_settings.wg_public_key.clone();
    let wg_privkey_option = network_settings.wg_private_key.clone();
    let device_option = network_settings.device.clone();

    match mesh_ip_option {
        Some(existing_mesh_ip) => {
            if !validate_mesh_ip(&existing_mesh_ip) {
                warn!(
                    "Existing mesh_ip field {} is invalid, generating a new mesh IP",
                    existing_mesh_ip
                );
                network_settings.mesh_ip =
                    Some(linux_generate_mesh_ip().expect("failed to generate a new mesh IP"));
            } else {
                info!("Mesh IP is {}", existing_mesh_ip);
            }
        }
        None => {
            info!("There's no mesh IP configured, generating");
            network_settings.mesh_ip =
                Some(linux_generate_mesh_ip().expect("failed to generate a new mesh IP"));
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
                    let device = line.split(" ").nth(1).ok_or(format_err!(
                        "Could not obtain device name from line {:?}",
                        line
                    ))?;

                    network_settings.device = Some(device.to_string());

                    break;
                }
            }

            if network_settings.device.is_none() {
                warn!("Device name could not be read from {}", release_file_path);
            }
        }
    }

    if wg_privkey_option.is_none() || wg_pubkey_option.is_none() {
        info!("Existing wireguard keypair is invalid, generating from scratch");
        let keypair = KI.create_wg_keypair().expect("failed to generate wg keys");
        network_settings.wg_public_key = Some(keypair.public);
        network_settings.wg_private_key = Some(keypair.private);
    }

    //Creates file on disk containing key
    KI.create_wg_key(
        &Path::new(&network_settings.wg_private_key_path),
        &network_settings
            .wg_private_key
            .clone()
            .expect("How did we get here without generating a key above?"),
    )?;

    // Yield the mut lock
    drop(network_settings);

    let mut payment_settings = config.get_payment_mut();
    let eth_private_key_option = payment_settings.eth_private_key.clone();

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

    // Yield the mut lock
    drop(payment_settings);

    let local_fee = config.get_payment().local_fee;
    let metric_factor = config.get_network().metric_factor;
    if local_fee == 0 {
        warn!("THIS NODE IS GIVING BANDWIDTH AWAY FOR FREE. PLEASE SET local_fee TO A NON-ZERO VALUE TO DISABLE THIS WARNING.");
    }
    if metric_factor == 0 {
        warn!("THIS NODE DOESN'T PAY ATTENTION TO ROUTE QUALITY - IT'LL CHOOSE THE CHEAPEST ROUTE EVEN IF IT'S THE WORST LINK AROUND. PLEASE SET metric_factor TO A NON-ZERO VALUE TO DISABLE THIS WARNING.");
    }
    if metric_factor > 2000000 {
        warn!("THIS NODE DOESN'T PAY ATTENTION TO ROUTE PRICE - IT'LL CHOOSE THE BEST ROUTE EVEN IF IT COSTS WAY TOO MUCH. PLEASE SET metric_factor TO A LOWER VALUE TO DISABLE THIS WARNING.");
    }

    let stream = TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", config.get_network().babel_port).parse()?,
    )?;

    let mut babel = Babel::new(stream);

    babel.start_connection()?;

    match babel.set_local_fee(local_fee) {
        Ok(()) => info!("Local fee set to {}", local_fee),
        Err(e) => warn!("Could not set local fee! {:?}", e),
    }

    match babel.set_metric_factor(metric_factor) {
        Ok(()) => info!("Metric factor set to {}", metric_factor),
        Err(e) => warn!("Could not set metric factor! {:?}", e),
    }

    Ok(())
}

fn linux_exit_init(
    config: Arc<RwLock<settings::exit::RitaExitSettingsStruct>>,
) -> Result<(), Error> {
    cleanup()?;

    // we need to avoid a deadlock by copying things out explicitly
    let exit_network_settings_ref = config.get_exit_network();
    let exit_network_settings = exit_network_settings_ref.clone();
    drop(exit_network_settings_ref);

    let mut network_settings = config.get_network_mut();
    let mesh_ip_option = network_settings.mesh_ip.clone();
    let wg_pubkey_option = network_settings.wg_public_key.clone();
    let wg_privkey_option = network_settings.wg_private_key.clone();

    match mesh_ip_option {
        Some(existing_mesh_ip) => {
            if !validate_mesh_ip(&existing_mesh_ip) {
                warn!(
                    "Existing mesh_ip field {} is invalid, generating a new mesh IP",
                    existing_mesh_ip
                );
                network_settings.mesh_ip =
                    Some(linux_generate_mesh_ip().expect("failed to generate a new mesh IP"));
            } else {
                info!("Mesh IP is {}", existing_mesh_ip);
            }
        }

        None => {
            info!("There's no mesh IP configured, generating");
            network_settings.mesh_ip =
                Some(linux_generate_mesh_ip().expect("failed to generate a new mesh IP"));
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
        &Path::new(&network_settings.wg_private_key_path),
        &network_settings
            .wg_private_key
            .clone()
            .expect("How did we get here without generating a key above?"),
    )?;
    // same thing but with the exit key
    KI.create_wg_key(
        &Path::new(&exit_network_settings.wg_private_key_path),
        &exit_network_settings.wg_private_key.clone(),
    )?;

    drop(network_settings);

    let mut payment_settings = config.get_payment_mut();
    let eth_private_key_option = payment_settings.eth_private_key.clone();

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

    // Yield the mut lock
    drop(payment_settings);

    let local_fee = config.get_payment().local_fee;
    let metric_factor = config.get_network().metric_factor;

    let stream = TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", config.get_network().babel_port).parse()?,
    )?;

    let mut babel = Babel::new(stream);

    babel.start_connection()?;

    babel.set_local_fee(local_fee)?;
    if local_fee == 0 {
        warn!("THIS NODE IS GIVING BANDWIDTH AWAY FOR FREE. PLEASE SET local_fee TO A NON-ZERO VALUE TO DISABLE THIS WARNING.");
    }

    babel.set_metric_factor(metric_factor)?;
    if metric_factor == 0 {
        warn!("THIS NODE DOESN'T PAY ATTENTION TO ROUTE QUALITY - IT'LL CHOOSE THE CHEAPEST ROUTE EVEN IF IT'S THE WORST LINK AROUND. PLEASE SET metric_factor TO A NON-ZERO VALUE TO DISABLE THIS WARNING.");
    }

    Ok(())
}

pub fn init(platform: &str, settings: Arc<RwLock<settings::client::RitaSettingsStruct>>) {
    match platform {
        "linux" => linux_init(settings.clone()).unwrap(),
        _ => unimplemented!(),
    }
    trace!(
        "Starting with settings (after clu) : {:?}",
        settings.read().unwrap()
    );
}

pub fn exit_init(platform: &str, settings: Arc<RwLock<settings::exit::RitaExitSettingsStruct>>) {
    match platform {
        "linux" => linux_exit_init(settings.clone()).unwrap(),
        _ => unimplemented!(),
    }
    trace!(
        "Starting with settings (after clu) : {:?}",
        settings.read().unwrap()
    );
}

#[cfg(test)]
mod tests {
    use crate::validate_mesh_ip;
    use std::net::IpAddr;

    #[test]
    fn test_validate_mesh_ip() {
        let good_ip = "fd44:94c:41e2::9e6".parse::<IpAddr>().unwrap();
        let bad_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        assert_eq!(validate_mesh_ip(&good_ip), true);
        assert_eq!(validate_mesh_ip(&bad_ip), false);
    }
}
