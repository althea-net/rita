use crate::dashboard::extend_hardware_info;
use actix_web_async::{HttpRequest, HttpResponse};
use althea_kernel_interface::{
    hardware_info::get_hardware_info,
    interface_tools::{get_ip_from_iface, get_ipv6_from_iface},
    ip_neigh::grab_ip_neigh,
    run_command,
};
use althea_types::HardwareInfo;
use mac_address::MacAddress;
use serde::Serializer;
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    net::IpAddr,
};

/// Devices can have multiple ip addresses but mac addresses on a wlan should be unique to each device
fn consolidate_wlan_arp_table(
    arp_table: Vec<(IpAddr, MacAddress)>,
) -> HashMap<MacAddress, HashSet<IpAddr>> {
    let mut new_arp_table = HashMap::new();
    for (ip_addr, mac_addr) in arp_table {
        new_arp_table
            .entry(mac_addr)
            .or_insert_with(HashSet::new)
            .insert(ip_addr);
    }
    new_arp_table
}

/// Used to prune all devices not part of the lan by using the netmask to delete invalid ips
fn prune_non_lan_entries(mut arp_table: Vec<(IpAddr, MacAddress)>) -> Vec<(IpAddr, MacAddress)> {
    let ip4 = get_ip_from_iface("br-lan");
    let ip6 = get_ipv6_from_iface("br-lan");

    // The long set of calls essentially grabs each ipaddress out of the arp table and checks if there is a singular
    // address match within each of the interfaces for ipv4 or ipv6. Otherwise, it prunes the ipaddress out of the arp
    // table.
    match (ip4, ip6) {
        (Ok(valid4), Ok(valid6)) => {
            arp_table.retain(|(ipaddr, _macaddr)| {
                match valid4
                    .clone()
                    .into_iter()
                    .find(|(ip4, bitmask)| !check_ip_in_subnet(*ipaddr, IpAddr::V4(*ip4), *bitmask))
                {
                    Some((_val1, _val2)) => true,
                    None => false,
                }
            });

            arp_table.retain(|(ipaddr, _macaddr)| {
                match valid6
                    .clone()
                    .into_iter()
                    .find(|(ip6, bitmask)| !check_ip_in_subnet(*ipaddr, IpAddr::V6(*ip6), *bitmask))
                {
                    Some((_val1, _val2)) => true,
                    None => false,
                }
            });
        }
        (Ok(valid4), Err(_)) => {
            arp_table.retain(|(ipaddr, _macaddr)| {
                match valid4
                    .clone()
                    .into_iter()
                    .find(|(ip4, bitmask)| !check_ip_in_subnet(*ipaddr, IpAddr::V4(*ip4), *bitmask))
                {
                    Some((_val1, _val2)) => true,
                    None => false,
                }
            });
        }
        (Err(_), Ok(valid6)) => {
            arp_table.retain(|(ipaddr, _macaddr)| {
                match valid6
                    .clone()
                    .into_iter()
                    .find(|(ip6, bitmask)| !check_ip_in_subnet(*ipaddr, IpAddr::V6(*ip6), *bitmask))
                {
                    Some((_val1, _val2)) => true,
                    None => false,
                }
            });
        }
        (Err(_), Err(_)) => (),
    }

    arp_table
}

/// The endpoint struct sent back to the devices on the frontend
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LanDevice {
    pub wired: bool,
    pub ip_addr: HashSet<IpAddr>,
    #[serde(serialize_with = "mac_serialize")]
    pub mac_addr: MacAddress,
    pub name: String,
    pub signal_strength: Option<String>,
    pub upload_bytes_used: Option<u64>,
    pub download_bytes_used: Option<u64>,
}

pub fn mac_serialize<S>(mac_addr: &MacAddress, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_str(&mac_addr.to_string())
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LanDevices {
    pub all_lan_devices: Vec<LanDevice>,
}

/// Generates the lan devices
pub fn generate_lan_device(
    lan_arp_table: HashMap<MacAddress, HashSet<IpAddr>>,
    hardware_to_check: HardwareInfo,
) -> LanDevices {
    let mut lan_devices = Vec::new();

    for (mac_addr, ip_addr) in lan_arp_table {
        let mut no_matches = true;
        for wifi_device in &hardware_to_check.wifi_devices {
            for station in &wifi_device.station_data {
                if let Ok(mac_address) = station.clone().station.parse::<MacAddress>() {
                    if mac_address.eq(&mac_addr) {
                        lan_devices.push(LanDevice {
                            signal_strength: Some(station.signal_dbm.clone()),
                            upload_bytes_used: Some(station.rx_bytes),
                            download_bytes_used: Some(station.tx_bytes),
                            name: resolve_name(ip_addr.clone(), mac_addr),
                            ip_addr: ip_addr.clone(),
                            mac_addr,
                            wired: false,
                        });
                        no_matches = false;
                        break;
                    }
                }
            }
        }
        if no_matches {
            lan_devices.push(LanDevice {
                signal_strength: None,
                upload_bytes_used: None,
                download_bytes_used: None,
                name: resolve_name(ip_addr.clone(), mac_addr),
                ip_addr,
                mac_addr,
                wired: true,
            });
        }
    }

    LanDevices {
        all_lan_devices: lan_devices,
    }
}

/// This function grabs all ip addresses associated to the device and attempts to
/// resolve its name by checking the dhcp lease and see if the name is in their
/// if it isn't it simply returns its mac addresses to use
fn resolve_name(ip_addresses: HashSet<IpAddr>, mac_addr: MacAddress) -> String {
    info!("Sending cat command to kernel");
    let res = run_command("cat", &["/tmp/dhcp.leases"]);
    match res {
        Ok(output) => {
            if !output.stdout.is_empty() {
                let parsed_output = String::from_utf8_lossy(&output.stdout).to_string();
                let lines = parsed_output.lines();
                for line in lines {
                    let mut found_match = false;
                    let entries = line.split_whitespace();
                    for (index, entry) in entries.into_iter().enumerate() {
                        if index == 2 {
                            match entry.parse::<IpAddr>() {
                                Ok(val) => {
                                    if ip_addresses.contains(&val) {
                                        found_match = true;
                                    } else {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        if index == 3 && found_match {
                            if entry.to_string().len() <= 3 {
                                return mac_addr.to_string();
                            } else {
                                return entry.to_string();
                            }
                        }
                    }
                }
                mac_addr.to_string()
            } else {
                mac_addr.to_string()
            }
        }
        Err(_e) => mac_addr.to_string(),
    }
}

/// This is an endpoint to grab all the lan devices mapping to ip address and
/// returns the json request populated with the related hardware information
pub async fn get_devices_lan_endpoint(_req: HttpRequest) -> HttpResponse {
    let command_response = grab_ip_neigh();
    match command_response {
        Ok(output) => {
            let arp_table = output;
            info!("Arp table length: {:?}", arp_table);

            let lan_arp_table = prune_non_lan_entries(arp_table);
            let consolidated_lan_arp_table = consolidate_wlan_arp_table(lan_arp_table);

            let rita_client = settings::get_rita_client();
            let hardware_to_check = match get_hardware_info(rita_client.network.device) {
                Ok(info) => extend_hardware_info(info),
                Err(e) => {
                    return HttpResponse::InternalServerError().json(format!(
                        "Unable to grab rita client hardware information. Failed with error {e:?}"
                    ));
                }
            };

            HttpResponse::Ok().json(generate_lan_device(
                consolidated_lan_arp_table,
                hardware_to_check,
            ))
        }
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
    }
}

/// Checks to see if a target ip addresses falls within the lan subnet by using an address w/ bitmask
/// This is done by bitmasking each address and comparing to see if they are the same
/// OUTPUTS:
/// Returns false if the ip addresses do not match the same format ipv4 with ipv6 or ipv6 with ipv4
/// Returns true if the addresses do not fall within each other subnets
fn check_ip_in_subnet(address1: IpAddr, address2: IpAddr, subnet_mask: u8) -> bool {
    match (address1, address2) {
        // The fancy long set of function calls essentially just modifies the ip addresses
        // by applying a bitmask to each octet of the ip address whether it's a 4 format or 6.
        (IpAddr::V4(ip1), IpAddr::V4(ip2)) => {
            let mut octets1: [u8; 4] = ip1.octets();
            octets1 = octets1
                .iter()
                .enumerate()
                .map(|(index, x)| {
                    apply_subnet_mask_to_ip_octet(*x, subnet_mask - ((index as u8) * 8))
                })
                .collect::<Vec<u8>>()
                .as_slice()
                .try_into()
                .unwrap();
            let mut octets2: [u8; 4] = ip2.octets();
            octets2 = octets2
                .iter()
                .enumerate()
                .map(|(index, x)| {
                    apply_subnet_mask_to_ip_octet(*x, subnet_mask - ((index as u8) * 8))
                })
                .collect::<Vec<u8>>()
                .as_slice()
                .try_into()
                .unwrap();
            octets1.eq(&octets2)
        }
        (IpAddr::V4(_), IpAddr::V6(_)) => false,
        (IpAddr::V6(_), IpAddr::V4(_)) => false,
        (IpAddr::V6(ip1), IpAddr::V6(ip2)) => {
            let mut octets1: [u8; 16] = ip1.octets();
            octets1 = octets1
                .iter()
                .enumerate()
                .map(|(index, x)| {
                    apply_subnet_mask_to_ip_octet(*x, subnet_mask - ((index as u8) * 8))
                })
                .collect::<Vec<u8>>()
                .as_slice()
                .try_into()
                .unwrap();
            let mut octets2: [u8; 16] = ip2.octets();
            octets2 = octets2
                .iter()
                .enumerate()
                .map(|(index, x)| {
                    apply_subnet_mask_to_ip_octet(*x, subnet_mask - ((index as u8) * 8))
                })
                .collect::<Vec<u8>>()
                .as_slice()
                .try_into()
                .unwrap();
            octets1.eq(&octets2)
        }
    }
}

/// Applies the bitmask octet to the related octet
fn apply_subnet_mask_to_ip_octet(octet: u8, subnet_mask: u8) -> u8 {
    if subnet_mask == 0 {
        return octet;
    }

    // Bitwise and on the bitmask with the relevant digits which cannot exceed 8
    let bitmask_octet = 2 << if subnet_mask > 8 { 8 } else { subnet_mask };
    octet & bitmask_octet
}
