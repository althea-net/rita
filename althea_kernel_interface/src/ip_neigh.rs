use crate::run_command;
use mac_address::MacAddress;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;

/// Runs the ip neigh command via the Kernel interface lazy static and returns an error if it doesn't work
pub fn grab_ip_neigh() -> Result<Vec<(IpAddr, MacAddress)>, std::io::Error> {
    info!("Sending ip neigh command to kernel");
    let res = run_command("ip", &["neigh"]);
    match res {
        Ok(output) => {
            // Extra checking since output struct is ambigious on how it works
            if !output.stdout.is_empty() {
                let string_to_parse = String::from_utf8_lossy(&output.stdout).to_string();
                Ok(parse_ip_neigh(string_to_parse))
            } else {
                Err(Error::new(
                    ErrorKind::Other,
                    "Empty ip neigh command. Failed".to_string(),
                ))
            }
        }
        Err(e) => Err(Error::new(
            ErrorKind::Other,
            format!("Unable to grab ip neigh from router. Failed with error {e:?}"),
        )),
    }
}

/// Parses the ip neighb command and returns a mapping of the following format:
/// (IP_ADDR, MAC_ADDRESS)
fn parse_ip_neigh(command: String) -> Vec<(IpAddr, MacAddress)> {
    let lines = command.lines();
    let mut arp_mapping = Vec::new();
    for line in lines {
        let entries = line.split_whitespace();
        let (mut valid_ip_address, mut valid_mac_address) = (None, None);
        let mut reachable: Option<bool> = None;
        for entry in entries {
            if entry.eq("STALE") {
                reachable = Some(false);
            } else if entry.eq("REACHABLE") {
                reachable = Some(true);
            }
            let ip_address = entry.parse::<IpAddr>();
            let mac_address = entry.parse::<MacAddress>();
            match (ip_address, mac_address) {
                (Ok(valid_ip), _) => valid_ip_address = Some(valid_ip),
                (_, Ok(valid_mac)) => valid_mac_address = Some(valid_mac),
                (_, _) => continue,
            }
        }
        if let (Some(ip_address), Some(mac_address)) = (valid_ip_address, valid_mac_address) {
            if let Some(value) = reachable {
                if value {
                    arp_mapping.push((ip_address, mac_address));
                }
            }
        }
    }
    arp_mapping
}
