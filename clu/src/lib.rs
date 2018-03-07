#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

use std::net::IpAddr;

extern crate settings;

extern crate ipgen;
extern crate rand;
use rand::Rng;

use std::str;

use failure::Error;

extern crate reqwest;

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate althea_types;

extern crate simple_logger;

#[derive(Debug, Fail)]
pub enum CluError {
    #[fail(display = "Runtime Error: {:?}", _0)]
    RuntimeError(String),
}

fn openwrt_generate_and_set_wg_keys(SETTINGS: &mut settings::RitaSettings) -> Result<(), Error> {
    let mut ki = KernelInterface {};
    let keys = ki.create_wg_keypair()?;
    let wg_public_key = &keys[0];
    let wg_private_key = &keys[1];

    let ret = ki.set_uci_var("network.wgExit.private_key", &wg_private_key);
    ret.expect("Failed to set UCI var! {:?}");
    let ret = ki.uci_commit();
    ret.expect("Failed to commit UCI changes!");

    //Mutates settings, intentional side effect
    SETTINGS.network.wg_private_key = wg_private_key.to_string();
    SETTINGS.network.wg_public_key = wg_public_key.to_string();

    Ok(())
}

fn openwrt_generate_and_set_mesh_ip(SETTINGS: &mut settings::RitaSettings) -> Result<(), Error> {
    let mut ki = KernelInterface {};
    let seed = rand::thread_rng().gen::<[u8; 10]>();
    let mesh_ip = ipgen::ip(std::str::from_utf8(&seed)?, "fd::/120").unwrap();
    let ifaces = SETTINGS.network.babel_interfaces.split(" ");

    // Mutates Settings intentional side effect
    SETTINGS.network.own_ip = mesh_ip;

    for interface in ifaces {
        let identifier = "network.babel_".to_string() + interface;
        ki.set_uci_var(&identifier, &mesh_ip.to_string());
    }

    ki.uci_commit();
    Ok(())
}

fn validate_wg_key(key: &str) -> bool {
    if key.len() != 44 || !key.ends_with("=") {
        false
    } else {
        true
    }
}

fn validate_mesh_ip(ip: &IpAddr) -> bool {
    if !ip.is_ipv6() || ip.is_unspecified() {
        false
    } else {
        true
    }
}

fn openwrt_validate_exit_setup() -> Result<(), Error> {
    Ok(())
}

fn request_own_exit_ip(SETTINGS: &mut settings::RitaSettings) -> Result<(), Error> {
    let exit_server = SETTINGS.exit_client.exit_ip;
    let ident = althea_types::ExitIdentity {
        global: SETTINGS.get_identity(),
        wg_port: SETTINGS.exit_client.wg_listen_port.clone(),
    };

    let endpoint = "http://".to_string() + &exit_server.to_string() + ":"
        + &SETTINGS.exit_client.exit_registration_port.to_string() + "/setup";

    trace!("Sending exit setup request to {:?}", endpoint);
    let client = reqwest::Client::new();
    let response = client.post(&endpoint).json(&ident).send();

    trace!("Got exit setup response {:?}", response);

    Ok(())
}

// Replacement for the setup.ash file in althea firmware
fn openwrt_init(mut SETTINGS: settings::RitaSettings) -> Result<(), Error> {
    let privkey = SETTINGS.network.wg_private_key.clone();
    let pubkey = SETTINGS.network.wg_public_key.clone();
    let mesh_ip = SETTINGS.network.own_ip.clone();
    let our_exit_ip = SETTINGS.exit_client.exit_ip.clone();

    request_own_exit_ip(&mut SETTINGS);
    trace!("Exit ip request exited");
    if validate_wg_key(&privkey) || validate_wg_key(&pubkey) {
        openwrt_generate_and_set_wg_keys(&mut SETTINGS);
    }
    if validate_mesh_ip(&mesh_ip) {
        openwrt_generate_and_set_mesh_ip(&mut SETTINGS);
    }
    if !our_exit_ip.is_ipv4() && !our_exit_ip.is_unspecified() {
        request_own_exit_ip(&mut SETTINGS);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_wg_key() {
        let good_key = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=";
        let bad_key1 = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpXk=";
        let bad_key2 = "look at me, I'm the same length as a key but";
        assert_eq!(validate_wg_key(&good_key), true);
        assert_eq!(validate_wg_key(&bad_key1), false);
        assert_eq!(validate_wg_key(&bad_key2), false);
    }

    #[test]
    fn test_generate_wg_key() {
        let mut ki = KernelInterface {};
        let keys = ki.create_wg_keypair().unwrap();
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
