#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

#[macro_use]
extern crate lazy_static;

extern crate settings;
use settings::{ExitVerifSettings, RitaCommonSettings, RitaExitSettings};

extern crate ipgen;
extern crate rand;
use rand::{thread_rng, Rng};

use std::str;

use failure::Error;

use althea_kernel_interface::KI;

extern crate althea_kernel_interface;
use rand::distributions::Alphanumeric;
use regex::Regex;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Arc, RwLock};

extern crate althea_types;
extern crate babel_monitor;
extern crate regex;

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

fn validate_wg_key(key: &str) -> bool {
    key.len() == 44 && key.ends_with("=") && !key.contains(" ")
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

fn linux_init(config: Arc<RwLock<settings::RitaSettingsStruct>>) -> Result<(), Error> {
    cleanup()?;
    KI.restore_default_route(&mut config.get_network_mut().default_route)?;

    let mut network_settings = config.get_network_mut();
    let privkey = network_settings.wg_private_key.clone();
    let pubkey = network_settings.wg_public_key.clone();
    let mesh_ip_option = network_settings.mesh_ip.clone();
    let own_ip_option = network_settings.own_ip.clone(); // TODO: REMOVE IN ALPHA 11
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

        // Fall back and migrate from own_ip if possible, TODO: REMOVE IN ALPHA 11
        None => match own_ip_option {
            Some(existing_own_ip) => {
                if validate_mesh_ip(&existing_own_ip) {
                    info!(
                        "Found existing compat own_ip field {}, migrating to mesh_ip",
                        existing_own_ip
                    );
                    network_settings.mesh_ip = Some(existing_own_ip);
                } else {
                    warn!(
                    "Existing compat own_ip value {} is invalid, generating a new mesh IP and migrating to mesh_ip",
                    existing_own_ip
                    );
                    network_settings.mesh_ip =
                        Some(linux_generate_mesh_ip().expect("failed to generate a new mesh IP"));
                }
            }
            None => {
                info!("There's no mesh IP configured, generating");
                network_settings.mesh_ip =
                    Some(linux_generate_mesh_ip().expect("failed to generate a new mesh IP"));
            }
        },
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

    // Setting the compat value to None prevents serde from putting it back in the config (thanks
    // to the skip_serializing_if annotation)
    network_settings.own_ip = None;

    if !validate_wg_key(&privkey) || !validate_wg_key(&pubkey) {
        info!("Existing wireguard keypair is invalid, generating from scratch");
        let keypair = KI.create_wg_keypair().expect("failed to generate wg keys");
        network_settings.wg_public_key = keypair.public;
        network_settings.wg_private_key = keypair.private;
    }

    //Creates file on disk containing key
    KI.create_wg_key(
        &Path::new(&network_settings.wg_private_key_path),
        &network_settings.wg_private_key,
    )?;

    // Yield the mut lock
    drop(network_settings);

    let local_fee = config.get_local_fee();
    let metric_factor = config.get_metric_factor();
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

fn linux_exit_init(config: Arc<RwLock<settings::RitaExitSettingsStruct>>) -> Result<(), Error> {
    cleanup()?;

    let mut network_settings = config.get_network_mut();
    let privkey = network_settings.wg_private_key.clone();
    let pubkey = network_settings.wg_public_key.clone();
    let mesh_ip_option = network_settings.mesh_ip.clone();
    let own_ip_option = network_settings.own_ip.clone(); // TODO: REMOVE IN ALPHA 11

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

        // Fall back and migrate from own_ip if possible, TODO: REMOVE IN ALPHA 11
        None => match own_ip_option {
            Some(existing_own_ip) => {
                if validate_mesh_ip(&existing_own_ip) {
                    info!(
                        "Found existing compat own_ip field {}, migrating to mesh_ip",
                        existing_own_ip
                    );
                    network_settings.mesh_ip = Some(existing_own_ip);
                } else {
                    warn!(
                    "Existing compat own_ip value {} is invalid, generating a new mesh IP and migrating to mesh_ip",
                    existing_own_ip
                    );
                    network_settings.mesh_ip =
                        Some(linux_generate_mesh_ip().expect("failed to generate a new mesh IP"));
                }
            }
            None => {
                info!("There's no mesh IP configured, generating");
                network_settings.mesh_ip =
                    Some(linux_generate_mesh_ip().expect("failed to generate a new mesh IP"));
            }
        },
    }

    if !validate_wg_key(&privkey) || !validate_wg_key(&pubkey) {
        info!("Existing wireguard keypair is invalid, generating from scratch");
        let keypair = KI.create_wg_keypair().expect("failed to generate wg keys");
        network_settings.wg_public_key = keypair.public;
        network_settings.wg_private_key = keypair.private;
    }

    //Creates file on disk containing key
    KI.create_wg_key(
        &Path::new(&network_settings.wg_private_key_path),
        &network_settings.wg_private_key,
    )?;

    drop(network_settings);

    // Migrate compat mailer settings. This is put in this particular spot so that the network
    // settings lock can be dropped beforehand.
    //
    // TODO: REMOVE IN ALPHA 13 FROM HERE TILL THE Ok(())
    let compat_mailer_settings = config.get_mailer().clone();
    let verif_settings = config.get_verif_settings().clone();

    match verif_settings.clone() {
        Some(_settings) => match compat_mailer_settings {
            Some(_) => {
                info!("Both verif_settings and compat settings exist, removing compat settings.");
                *config.get_mailer_mut() = None;
            }
            None => {}
        },
        None => match compat_mailer_settings {
            Some(compat_settings) => {
                info!("Only compat mailer settings are present, migrating to verif_settings");
                *config.get_verif_settings_mut() =
                    Some(ExitVerifSettings::Email(compat_settings.clone()));
                *config.get_mailer_mut() = None;
            }
            None => {}
        },
    }

    let local_fee = config.get_local_fee();
    let metric_factor = config.get_metric_factor();

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

pub fn init(platform: &str, settings: Arc<RwLock<settings::RitaSettingsStruct>>) {
    match platform {
        "linux" => linux_init(settings.clone()).unwrap(),
        _ => unimplemented!(),
    }
    trace!(
        "Starting with settings (after clu) : {:?}",
        settings.read().unwrap()
    );
}

pub fn exit_init(platform: &str, settings: Arc<RwLock<settings::RitaExitSettingsStruct>>) {
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
    #[ignore]
    fn test_generate_wg_key() {
        let keypair = KI.create_wg_keypair().unwrap();
        assert_eq!(validate_wg_key(&keypair.public), true);
        assert_eq!(validate_wg_key(&keypair.private), true);
    }

    #[test]
    fn test_validate_mesh_ip() {
        let good_ip = "fd44:94c:41e2::9e6".parse::<IpAddr>().unwrap();
        let bad_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        assert_eq!(validate_mesh_ip(&good_ip), true);
        assert_eq!(validate_mesh_ip(&bad_ip), false);
    }
}
