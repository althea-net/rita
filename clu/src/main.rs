#[macro_use] extern crate log;

#[macro_use]
extern crate derive_error;

use std::fs::{File};
use std::io::{Read, Write};
use std::path::Path;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use std::collections::HashMap;

extern crate settings;
use settings::Settings;

extern crate docopt;
use docopt::Docopt;

extern crate ipgen;
extern crate rand;
use rand::Rng;

use std::str;

extern crate reqwest;

extern crate althea_kernel_interface;
use althea_kernel_interface::KernelInterface;

extern crate simple_logger;

#[macro_use]
extern crate lazy_static;

#[derive(Debug, Error)]
pub enum Error {
    Io(std::io::Error),
    StringUTF8(std::string::FromUtf8Error),
    StrUTF8(std::str::Utf8Error),
    ParseInt(std::num::ParseIntError),
    AddrParse(std::net::AddrParseError),
    althea_kernel_interface(althea_kernel_interface::Error),
    request(reqwest::Error),
    #[error(msg_embedded, no_from, non_std)]
    RuntimeError(String),
}

fn openwrt_generate_and_set_wg_keys(SETTINGS :&mut settings::Settings) -> Result<(), Error> {
    let mut ki = KernelInterface{};
    let keys = ki.create_wg_keypair()?;
    let wg_public_key = &keys[0];
    let wg_private_key = &keys[1];

    let ret = ki.set_uci_var("network.wgExit.private_key", &wg_private_key);
    let ret = ki.uci_commit();

    //Mutates settings, intentional side effect
    SETTINGS.network.wg_private_key = wg_private_key.to_string();
    SETTINGS.network.wg_public_key = wg_public_key.to_string();

    Ok(())
}

fn openwrt_generate_and_set_mesh_ip(SETTINGS :&mut settings::Settings) -> Result<(), Error> {
    let mut ki = KernelInterface{};
    let seed = rand::thread_rng().gen::<[u8;10]>();
    let mesh_ip = ipgen::ip(std::str::from_utf8(&seed)?,"fd::/120").unwrap();
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

fn openwrt_validate_wg_key(key: &str) -> bool {
    let empty_string = "".to_string();
    if key == empty_string || key.len() != 45 {
        false
    }
    else {
        true
    }
}

fn openwrt_validate_mesh_ip() -> Result<(), Error> {
    Ok(())
}


fn openwrt_validate_exit_setup() -> Result<(), Error> {
    Ok(())
}

fn request_own_exit_ip(SETTINGS :&mut settings::Settings) -> Result<(), Error> {
    let exit_server = SETTINGS.network.exit_address;
    let mut map = HashMap::new();
    map.insert("wg_public_key", SETTINGS.network.wg_public_key.clone());
    map.insert("mesh_ip", SETTINGS.network.own_ip.to_string());
    map.insert("port", SETTINGS.network.wg_exit_port.to_string());

    let endpoint = "http://".to_string()+&exit_server.to_string()+":"
    +&SETTINGS.network.exit_registration_port.to_string()+"/setup";

    trace!("Sending exit setup request to {:?}", endpoint);
    let client = reqwest::Client::new();
    let response = client.post(&endpoint).json(&map).send();

    trace!("Got exit setup response {:?}", response);

    Ok(())
}

// Replacement for the setup.ash file in althea firmware
fn openwrt_init(mut SETTINGS :settings::Settings) -> Result<(), Error> {
    let privkey = SETTINGS.network.wg_private_key.clone();
    let pubkey = SETTINGS.network.wg_public_key.clone();
    let mesh_ip = SETTINGS.network.own_ip.clone();
    let exit_ip = SETTINGS.network.exit_address.clone();
    let our_exit_ip = SETTINGS.network.exit_address.clone();

    request_own_exit_ip(&mut SETTINGS);
    trace!("Exit ip request exited");
    if openwrt_validate_wg_key(&privkey) || openwrt_validate_wg_key(&pubkey) {
        openwrt_generate_and_set_wg_keys(&mut SETTINGS);
    }
    if !mesh_ip.is_ipv6() && !mesh_ip.is_unspecified() {
        openwrt_generate_and_set_mesh_ip(&mut SETTINGS);
    }
    if !our_exit_ip.is_ipv4() && !our_exit_ip.is_unspecified() {
        request_own_exit_ip(&mut SETTINGS);
    }
    Ok(())
}

//fn openwrt_generate_and_set_wg_keys
const USAGE: &'static str = "
Usage: clu --config <settings> --default <default>
Options:
    --config   Name of config file
    --default   Name of default config file
";

fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|d| d.parse())
        .unwrap_or_else(|e| e.exit());

    let settings_file = args.get_str("<settings>");
    let defaults_file = args.get_str("<default>");

    let mut SETTINGS = Settings::new(settings_file, defaults_file).unwrap();
    simple_logger::init().unwrap();
    trace!("Starting");
    println!("{:?}", openwrt_init(SETTINGS));
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
