//! A generalized interface for modifying networking interface assignments using UCI
use actix_web_async::http::StatusCode;
use actix_web_async::web::Path;
use actix_web_async::{web::Json, HttpRequest, HttpResponse};
use althea_kernel_interface::is_openwrt::is_openwrt_2410_plus;
use rita_common::{RitaCommonError, KI};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::Ipv4Addr;

use crate::RitaClientError;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InterfacesToSet {
    pub interfaces: Vec<String>,
    pub modes: Vec<InterfaceMode>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Copy)]
pub enum InterfaceMode {
    /// 'Mesh' mode essentially defines a port where Rita is attached and performing
    /// it's own hello/ImHere protocol as defined in PeerListener. These ports are just
    /// setup as static in the OpenWRT config and so long as SLACC IPv6 linklocal auto
    /// negotiation is on Rita takes it from there. Some key caveats is that a port
    /// may not be 'mesh' (eg: defined in Rita's peer_interfaces var) and also configured
    /// as a WAN port.
    Mesh,
    /// LAN port is essentially defined as any port attached to the br-lan bridge. The br-lan
    /// bridge then provides DHCP. Finally Rita comes in and places a default route though the
    /// exit server so that users can actually reach the internet.
    Lan,
    /// WAN port, specifically means that this device is listening for DHCP (instead of providing DHCP
    /// like on LAN). This route will be accepted and installed. Keep in mind if a WAN port is set this
    /// device will count itself as a 'gateway' regardless of if there is actual activity on the port.
    /// Example effects of a device being defined as a 'gateway' include making DHCP requests for manual_peers
    /// in tunnel_manager and taking the gateway price in operator_update
    Wan,
    /// Same as WAN but configures a static IP for this device.
    StaticWan {
        netmask: Ipv4Addr,
        ipaddr: Ipv4Addr,
        gateway: Ipv4Addr,
    },
    /// Similar to WAN, but not a gateway, so no static DNS routes and only IP peers (10.45.0.1)
    LTE,
    /// Ambiguous wireless modes like monitor, or promiscuous show up here, but other things that might also
    /// be unknown are various forms of malformed configs. Take for example a StaticWAN missing a config param
    Unknown,
}

impl Display for InterfaceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceMode::Mesh => write!(f, "mesh"),
            InterfaceMode::Lan => write!(f, "LAN"),
            InterfaceMode::Wan => write!(f, "WAN"),
            InterfaceMode::StaticWan { .. } => write!(f, "StaticWAN"),
            InterfaceMode::Unknown => write!(f, "Unknown"),
            InterfaceMode::LTE => write!(f, "LTE"),
        }
    }
}

/// Gets a list of interfaces and their modes by parsing UCI
pub fn get_interfaces() -> Result<HashMap<String, InterfaceMode>, RitaClientError> {
    let mut retval = HashMap::new();

    // Wired
    for (setting_name, value) in KI.uci_show(Some("network"))? {
        // Only non-loopback non-bridge interface names should get past
        if setting_name.contains("ifname") && !value.contains("backhaul") && value != "lo" {
            // it's a list and we need to handle that
            if value.contains(' ') {
                for list_member in value.split(' ') {
                    // legacy filter for phone light clients a removed feature
                    // this may be removable some day when all router configs have turned over
                    if list_member.contains("pbs-wlan") {
                        continue;
                    }
                    retval.insert(
                        list_member.replace(' ', "").to_string(),
                        ethernet2mode(&value, &setting_name)?,
                    );
                }
            } else {
                // legacy filter for phone light clients a removed feature
                // this may be removable some day when all router configs have turned over
                if value.contains("pbs-wlan") {
                    continue;
                }
                retval.insert(value.clone(), ethernet2mode(&value, &setting_name)?);
            }
        }
        // openwrt 24.10 or later the schema changed and devices have sub ports, so if we find one use it's key
        // to query the ports section for more, this runs once per device section
        else if value == "device" {
            // this ports field may or may not exist if no ports are currently attached to the lan bridge
            let ports = KI
                .uci_show(Some(&format!("{}.ports", setting_name)))
                .unwrap_or_default();
            let lan = KI.uci_show(Some(&format!("{}.name", setting_name)))?;
            // ports can be empty (len 0) if no ports are attached to the lan bridge
            if ports.len() <= 1 && lan.len() != 1 {
                // not sure what openwrt version we're on so react gracefully to the unexpected
                continue;
            }
            // confirm we have a lan object and not some other object
            if let Some((_, value)) = lan.into_iter().next() {
                if value != "br-lan" {
                    continue;
                }
                let port_list = match ports.into_iter().next() {
                    Some((_, list)) => list,
                    None => "".to_string(),
                };
                // we have already identified what sort of ports these are so we can skip the mode check
                for list_member in port_list.split(' ') {
                    retval.insert(
                        list_member.replace(' ', "").replace("'", "").to_string(),
                        InterfaceMode::Lan,
                    );
                }
            }
        }
    }

    Ok(retval)
}

/// Find out a wired interface's mode (mesh, LAN, WAN) from the setting name
pub fn ethernet2mode(ifname: &str, setting_name: &str) -> Result<InterfaceMode, RitaClientError> {
    trace!(
        "ethernet2mode: ifname {:?}, setting_name {:?}",
        ifname,
        setting_name
    );

    // Match parent section name
    Ok(match &setting_name.replace(".ifname", "") {
        s if s.contains("rita_") => InterfaceMode::Mesh,
        s if s.contains("lan") => InterfaceMode::Lan,
        s if s.contains("lte") => InterfaceMode::LTE,
        s if s.contains("backhaul") => {
            let prefix = "network.backhaul";
            let backhaul = KI.uci_show(Some(prefix))?;
            trace!("{:?}", backhaul);
            let proto = if let Some(val) = backhaul.get(&format!("{prefix}.proto")) {
                val
            } else {
                return Err(RitaClientError::InterfaceModeError(
                    "WAN network with no proto?".to_string(),
                ));
            };

            if proto.contains("dhcp") {
                return Ok(InterfaceMode::Wan);
            } else if proto.contains("static") {
                let opt_tuple = (
                    backhaul.get(&format!("{prefix}.netmask")),
                    backhaul.get(&format!("{prefix}.ipaddr")),
                    backhaul.get(&format!("{prefix}.gateway")),
                );
                if let (Some(netmask), Some(ipaddr), Some(gateway)) = opt_tuple {
                    return Ok(InterfaceMode::StaticWan {
                        netmask: netmask.parse()?,
                        ipaddr: ipaddr.parse()?,
                        gateway: gateway.parse()?,
                    });
                } else {
                    return Err(RitaClientError::InterfaceModeError(
                        "Failed to parse static wan!".to_string(),
                    ));
                }
            }
            return Err(RitaClientError::InterfaceModeError(
                "Failed to parse backhaul entry!".to_string(),
            ));
        }
        other => {
            warn!(
                "Unknown wired port mode for interface {:?}, section name {:?}",
                ifname, other
            );
            InterfaceMode::Unknown
        }
    })
}

/// Set mode for an individual interface
fn set_interface_mode(iface_name: String, mode: InterfaceMode) -> Result<(), RitaClientError> {
    let target_mode = mode;
    info!("In set interface mode for iface {iface_name:?} to mode {target_mode:?}");
    let interfaces = get_interfaces()?;
    info!("Current interfaces: {:?}", interfaces);
    let current_mode = get_current_interface_mode(&interfaces, &iface_name);
    if !interfaces.contains_key(&iface_name) {
        return Err(RitaClientError::InterfaceModeError(
            "Attempted to configure non-existant or unavailable interface!".to_string(),
        ));
    } else if target_mode == InterfaceMode::Wan {
        // we can only have one WAN interface, check for others
        // StaticWAN entries are not identified seperately but if they ever are
        // you'll have to handle them here
        for entry in interfaces {
            let mode = entry.1;
            if (matches!(
                mode,
                InterfaceMode::Wan | InterfaceMode::StaticWan { .. } | InterfaceMode::LTE
            ) && entry.0 != iface_name)
            {
                info!("Found another WAN or LTE interface: {:?}", entry);
                return Err(RitaClientError::InterfaceModeError(
                    "There can only be one WAN or LTE interface!".to_string(),
                ));
            }
        }
    }
    ethernet_transform_mode(&iface_name, current_mode, target_mode)
}

/// Handles the validation of new port settings from multi port toggle
fn multiset_interfaces(
    iface_name: Vec<String>,
    mode: Vec<InterfaceMode>,
) -> Result<(), RitaClientError> {
    if iface_name.len() != mode.len() {
        return Err(RitaClientError::MiscStringError(
            "Extra mode or iface found!".to_string(),
        ));
    }
    // do not allow multiple WANs- this is checked for before we run through the setter so we do
    // not waste time on obviously incorrect configs
    let mut wan_count = 0;
    for m in &mode {
        if matches!(m, InterfaceMode::Wan) || matches!(m, InterfaceMode::StaticWan { .. }) {
            wan_count += 1;
        }
    }
    if wan_count > 1 {
        return Err(RitaClientError::MiscStringError(
            "Only one WAN interface allowed!".to_string(),
        ));
    }

    for (iface, mode) in iface_name.into_iter().zip(mode.into_iter()) {
        let setter = set_interface_mode(iface.clone(), mode);
        if let Err(e) = setter {
            return Err(RitaClientError::InterfaceModeError(format!(
                "Failed to set {iface:?} to mode {mode:?}: {e:?}"
            )));
        }
    }

    trace!("Successfully transformed ethernet mode, rebooting");
    // reboot has been moved here to avoid doing it after every interface, in theory we could do this without rebooting
    // and some attention has been paid to maintaining that possibility
    KI.run_command("reboot", &[])?;
    Ok(())
}

/// Transform a wired interface from mode A to mode B
pub fn ethernet_transform_mode(
    ifname: &str,
    a: InterfaceMode,
    b: InterfaceMode,
) -> Result<(), RitaClientError> {
    info!("Ethernet mode transform: ifname {ifname:?}, a {a:?}, b {b:?}",);
    if a == b {
        // noop that was easy!
        return Ok(());
    } else if a == InterfaceMode::Unknown || b == InterfaceMode::Unknown {
        return Err(RitaClientError::InterfaceModeError(
            "We can't change Unknown interfaces!".to_string(),
        ));
    }
    let rita_client = settings::get_rita_client();
    let mut network = rita_client.network;

    // if we have edited UCI and it fails we set this var to handle cleanup later
    let mut return_codes = Vec::new();
    // in case of failure we revert to here
    let old_network_settings = { network.clone() };
    let filtered_ifname = format!("network.rita_{}", ifname.replace('.', ""));

    match a {
        // Wan is very simple, just delete it
        InterfaceMode::Wan | InterfaceMode::StaticWan { .. } => {
            network.external_nic = None;

            let ret = KI.del_uci_var("network.backhaul");
            return_codes.push(ret);
        }
        // LTE is the same
        InterfaceMode::LTE => {
            network.external_nic = None;

            let ret = KI.del_uci_var("network.lte");
            return_codes.push(ret);
        }
        // LAN is a bridge and the lan bridge must always remain because things
        // like WiFi interfaces are attached to it. So we just remove the interface
        // from the list
        InterfaceMode::Lan => {
            if is_openwrt_2410_plus() {
                info!("Detected OpenWRT 24.10+, using device ports for LAN interface management");
                // Remove from ports list in device section
                match get_lan_device_section() {
                    Ok(device_section) => match get_lan_ports_list(&device_section) {
                        Ok(port_list) => {
                            let new_list = list_remove(&port_list, ifname);
                            let ret = set_lan_ports_list(&device_section, &new_list).map_err(|e| {
                                althea_kernel_interface::KernelInterfaceError::RuntimeError(
                                    format!("{e:?}"),
                                )
                            });
                            return_codes.push(ret);
                        }
                        Err(e) => {
                            warn!("Failed to get LAN ports list: {e:?}");
                            return_codes.push(Err(
                                althea_kernel_interface::KernelInterfaceError::RuntimeError(
                                    format!("{e:?}"),
                                ),
                            ));
                        }
                    },
                    Err(e) => {
                        warn!("Failed to get LAN device section: {e:?}");
                        return_codes.push(Err(
                            althea_kernel_interface::KernelInterfaceError::RuntimeError(format!(
                                "{e:?}"
                            )),
                        ));
                    }
                }
            } else {
                info!("Using legacy LAN interface management");
                let list = KI.get_uci_var("network.lan.ifname")?;
                let new_list = list_remove(&list, ifname);
                let ret = KI.set_uci_var("network.lan.ifname", &new_list);
                return_codes.push(ret);
            }
        }
        // remove the section from the network and rita config, peer listener watches this setting
        // and will yank these interfaces from active listening
        InterfaceMode::Mesh => {
            network.peer_interfaces.remove(ifname);

            let ret = KI.del_uci_var(&filtered_ifname);
            return_codes.push(ret);
        }
        InterfaceMode::Unknown => unimplemented!(),
    }

    match b {
        // here we add back all the properties of backhaul we removed
        InterfaceMode::Wan => {
            network.external_nic = Some(ifname.to_string());

            let ret = KI.set_uci_var("network.backhaul", "interface");
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.ifname", ifname);
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.proto", "dhcp");
            return_codes.push(ret);
        }
        InterfaceMode::StaticWan {
            netmask,
            ipaddr,
            gateway,
        } => {
            network.external_nic = Some(ifname.to_string());

            let ret = KI.set_uci_var("network.backhaul", "interface");
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.ifname", ifname);
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.proto", "static");
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.netmask", &format!("{netmask}"));
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.ipaddr", &format!("{ipaddr}"));
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.gateway", &format!("{gateway}"));
            return_codes.push(ret);
        }
        InterfaceMode::LTE => {
            network.external_nic = Some(ifname.to_string());

            let ret = KI.set_uci_var("network.lte", "interface");
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.lte.ifname", ifname);
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.lte.proto", "dhcp");
            return_codes.push(ret);
        }
        // since we left lan mostly unmodified we just pop in the ifname
        InterfaceMode::Lan => {
            if is_openwrt_2410_plus() {
                info!("Setting lan interface on OpenWRT 24.10+");
                // Add to ports list in device section (OpenWRT 24.10+)
                match get_lan_device_section() {
                    Ok(device_section) => match get_lan_ports_list(&device_section) {
                        Ok(port_list) => {
                            let new_list = list_add(&port_list, ifname);
                            let ret = set_lan_ports_list(&device_section, &new_list).map_err(|e| {
                                althea_kernel_interface::KernelInterfaceError::RuntimeError(
                                    format!("{e:?}"),
                                )
                            });
                            return_codes.push(ret);
                        }
                        Err(e) => {
                            warn!("Failed to get LAN ports list: {e:?}");
                            return_codes.push(Err(
                                althea_kernel_interface::KernelInterfaceError::RuntimeError(
                                    format!("{e:?}"),
                                ),
                            ));
                        }
                    },
                    Err(e) => {
                        warn!("Failed to get LAN device section: {e:?}");
                        return_codes.push(Err(
                            althea_kernel_interface::KernelInterfaceError::RuntimeError(format!(
                                "{e:?}"
                            )),
                        ));
                    }
                }
            } else {
                info!("Setting lan interface on OpenWRT before 24.10");
                let ret = KI.get_uci_var("network.lan.ifname");
                match ret {
                    Ok(list) => {
                        info!("The existing LAN interfaces list is {list:?}");
                        let new_list = list_add(&list, ifname);
                        trace!("Setting the new list {new_list:?}");
                        let ret = KI.set_uci_var("network.lan.ifname", &new_list);
                        return_codes.push(ret);
                    }
                    Err(e) => {
                        if e.to_string().contains("Entry not found") {
                            trace!("No LAN interfaces found, setting one now");
                            let ret = KI.set_uci_var("network.lan.ifname", ifname);
                            return_codes.push(ret);
                        } else {
                            warn!("Trying to read lan ifname returned {e:?}");
                            return_codes.push(Err(e));
                        }
                    }
                }
            }
        }
        InterfaceMode::Mesh => {
            network.peer_interfaces.insert(ifname.to_string());

            let ret = KI.set_uci_var(&filtered_ifname, "interface");
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("{filtered_ifname}.ifname"), ifname);
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("{filtered_ifname}.proto"), "static");
            return_codes.push(ret);
        }
        InterfaceMode::Unknown => unimplemented!(),
    }

    // check all of our return codes in order to handle any possible issue
    let mut error_occured = Vec::new();
    for ret in return_codes {
        if let Err(e) = ret {
            error_occured.push(e);
        }
    }
    let mut rita_client = settings::get_rita_client();
    if !error_occured.is_empty() {
        let res = KI.uci_revert("network");
        rita_client.network = old_network_settings;
        settings::set_rita_client(rita_client);
        //bail!("Error running UCI commands! Revert attempted: {:?}", res);
        if let Err(re) = res {
            return Err(RitaClientError::InterfaceToggleError {
                main_error: error_occured,
                revert_status: Some(re),
            });
        } else {
            return Err(RitaClientError::InterfaceToggleError {
                main_error: error_occured,
                revert_status: None,
            });
        }
    }

    KI.uci_commit("network")?;
    KI.openwrt_reset_network()?;

    rita_client.network = network;
    settings::set_rita_client(rita_client);

    // try and save the config and fail if we can't
    if let Err(_e) = settings::write_config() {
        return Err(RitaCommonError::SettingsError(_e).into());
    }

    trace!("Transforming ethernet");
    // We edited disk contents, force global sync
    KI.fs_sync()?;

    Ok(())
}

/// Unlike physical ethernet interfaces you can run multiple SSID's on a single WIFI card
/// so we don't provide options to 'change' wireless modes to match the users expectations
/// instead we provide a toggle interface.
/// For example 'toggle user wlan off' or 'toggle phone sale network on' or 'toggle router
/// to router wireless meshing'.
fn wlan_toggle_get(uci_spec: &str) -> Result<bool, RitaClientError> {
    if !KI.is_openwrt() {
        return Err(RitaClientError::MiscStringError(
            "Not an OpenWRT device!".to_string(),
        ));
    }
    let bad_wireless = "Wireless config not correct";
    let current_state = KI.uci_show(Some(uci_spec))?;
    let current_state = match current_state.get(uci_spec) {
        Some(val) => val,
        None => return Err(RitaClientError::MiscStringError(bad_wireless.to_string())),
    };
    let current_state = if current_state.contains('0') {
        true
    } else if current_state.contains('1') {
        false
    } else {
        return Err(RitaClientError::MiscStringError(bad_wireless.to_string()));
    };

    trace!(
        "wlan get status: uci_spec {}, enabled: {}",
        uci_spec,
        current_state
    );

    Ok(current_state)
}

pub async fn wlan_mesh_get(_: HttpRequest) -> HttpResponse {
    let res = wlan_toggle_get("wireless.mesh.disabled");
    match res {
        Ok(b) => HttpResponse::Ok().json(b),
        Err(e) => {
            error!("get mesh failed with {:?}", e);
            HttpResponse::InternalServerError().into()
        }
    }
}

pub async fn wlan_lightclient_get(_: HttpRequest) -> HttpResponse {
    let res = wlan_toggle_get("wireless.lightclient.disabled");
    match res {
        Ok(b) => HttpResponse::Ok().json(b),
        Err(e) => {
            error!("get lightclient failed with {:?}", e);
            HttpResponse::InternalServerError().into()
        }
    }
}

fn wlan_toggle_set(uci_spec: &str, enabled: bool) -> Result<(), RitaClientError> {
    if !KI.is_openwrt() {
        return Err(RitaClientError::MiscStringError(
            "Not an OpenWRT device!".to_string(),
        ));
    }
    let bad_wireless = "Wireless config not correct";
    trace!("wlan toggle: uci_spec {}, enabled: {}", uci_spec, enabled,);

    let current_state = KI.uci_show(Some(uci_spec))?;
    let current_state = match current_state.get(uci_spec) {
        Some(val) => val,
        None => return Err(RitaClientError::MiscStringError(bad_wireless.to_string())),
    };
    let current_state = if current_state.contains('0') {
        true
    } else if current_state.contains('1') {
        false
    } else {
        return Err(RitaClientError::MiscStringError(bad_wireless.to_string()));
    };

    if enabled == current_state {
        return Ok(());
    }

    // remember it's a 'disabled' toggle so we want to set it to zero to be 'enabled'
    let res = if enabled {
        KI.set_uci_var(uci_spec, "0")
    } else {
        KI.set_uci_var(uci_spec, "1")
    };

    if let Err(e) = res {
        let res_b = KI.uci_revert("wireless");
        if let Err(re) = res_b {
            return Err(RitaClientError::InterfaceToggleError {
                main_error: vec![e],
                revert_status: Some(re),
            });
        } else {
            return Err(RitaClientError::InterfaceToggleError {
                main_error: vec![e],
                revert_status: None,
            });
        }
    }

    KI.uci_commit("wireless")?;
    KI.openwrt_reset_wireless()?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;

    KI.run_command("reboot", &[])?;

    Ok(())
}

pub async fn wlan_mesh_set(enabled: Path<bool>) -> HttpResponse {
    let enabled = enabled.into_inner();
    let res = wlan_toggle_set("wireless.mesh.disabled", enabled);
    match res {
        Ok(_) => HttpResponse::Ok().into(),
        Err(e) => {
            error!("set mesh failed with {:?}", e);
            HttpResponse::InternalServerError().into()
        }
    }
}

pub async fn wlan_lightclient_set(enabled: Path<bool>) -> HttpResponse {
    let enabled = enabled.into_inner();
    let res = wlan_toggle_set("wireless.lightclient.disabled", enabled);
    match res {
        Ok(_) => HttpResponse::Ok().into(),
        Err(e) => {
            error!("set lightclient failed with {:?}", e);
            HttpResponse::InternalServerError().into()
        }
    }
}

/// A helper function for adding entries to a list
pub fn list_add(list: &str, entry: &str) -> String {
    if !list.is_empty() {
        format!("{list} {entry}")
    } else {
        entry.to_string()
    }
}

/// A helper function for removing entries from a list
pub fn list_remove(list: &str, entry: &str) -> String {
    if !list.is_empty() {
        let split = list.split(' ');
        let mut new_list = String::new();
        let mut first = true;
        for item in split {
            let filtered_item = item.trim();
            // Remove surrounding single quotes for comparison
            let stripped = filtered_item.trim_matches('\'');
            if stripped != entry {
                trace!("{filtered_item} is not {entry} it's on the list!");
                let tmp_list = new_list.to_string();
                if first {
                    new_list = tmp_list + filtered_item;
                    first = false;
                } else {
                    new_list = tmp_list + &format!(" {filtered_item}");
                }
            }
        }
        new_list
    } else {
        "".to_string()
    }
}

/// Gets the UCI section name for the LAN bridge device in OpenWRT 24.10+
/// This searches for the device section that has name='br-lan'
fn get_lan_device_section() -> Result<String, RitaClientError> {
    for (setting_name, value) in KI.uci_show(Some("network"))? {
        if setting_name.ends_with(".name") && value == "br-lan" {
            // setting_name is like "network.@device[0].name", we want "network.@device[0]"
            let section = setting_name.trim_end_matches(".name");
            return Ok(section.to_string());
        }
    }
    Err(RitaClientError::MiscStringError(
        "Could not find LAN bridge device section".to_string(),
    ))
}

/// Gets the current ports list from a device section
fn get_lan_ports_list(device_section: &str) -> Result<String, RitaClientError> {
    let ports_key = format!("{device_section}.ports");
    match KI.get_uci_var(&ports_key) {
        Ok(ports) => Ok(ports),
        Err(e) => {
            if e.to_string().contains("Entry not found") {
                Ok(String::new())
            } else {
                Err(RitaClientError::MiscStringError(format!(
                    "Failed to get ports: {e:?}"
                )))
            }
        }
    }
}

/// Sets the ports list for a device section
fn set_lan_ports_list(device_section: &str, new_list: &str) -> Result<(), RitaClientError> {
    let ports_key = format!("{device_section}.ports");
    KI.set_uci_var(&ports_key, new_list)
        .map_err(|e| RitaClientError::MiscStringError(format!("Failed to set ports: {e:?}")))
}

pub fn get_current_interface_mode(
    interfaces: &HashMap<String, InterfaceMode>,
    target_iface: &str,
) -> InterfaceMode {
    for entry in interfaces {
        let iface = entry.0;
        let mode = entry.1;
        if iface.contains(target_iface) {
            return *mode;
        }
    }
    InterfaceMode::Unknown
}

pub async fn get_interfaces_endpoint(_req: HttpRequest) -> HttpResponse {
    debug!("get /interfaces hit");

    match get_interfaces() {
        Ok(val) => HttpResponse::Ok().json(val),
        Err(e) => {
            error!("get_interfaces failed with {:?}", e);
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e:?}"))
        }
    }
}

pub async fn set_interfaces_endpoint(interfaces: Json<InterfacesToSet>) -> HttpResponse {
    let interface = interfaces.into_inner();
    debug!("set /interfaces hit");

    match multiset_interfaces(interface.interfaces, interface.modes) {
        Ok(_) => HttpResponse::Ok().into(),
        Err(e) => {
            error!("Set interfaces failed with {:?}", e);
            HttpResponse::InternalServerError().into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_remove() {
        let a = "eth0.3 eth1 eth2 eth3 eth4";

        let b = list_remove(a, "eth1");
        assert_eq!(b, "eth0.3 eth2 eth3 eth4");

        let b = list_remove(&b, "eth0.3");
        assert_eq!(b, "eth2 eth3 eth4");

        let b = list_remove(&b, "eth4");
        assert_eq!(b, "eth2 eth3");

        let b = list_remove(&b, "eth2");
        assert_eq!(b, "eth3");

        let b = list_remove(&b, "eth3");
        assert_eq!(b, "");
    }

    #[test]
    fn test_list_remove_device_ports() {
        // Test with single-quoted entries (OpenWRT 24.10+ style)
        let a = "'eth0' 'eth1' 'eth2'";
        let b = list_remove(a, "eth1");
        assert_eq!(b, "'eth0' 'eth2'");

        let b = list_remove(&b, "eth0");
        assert_eq!(b, "'eth2'");

        let b = list_remove(&b, "eth2");
        assert_eq!(b, "");
    }

    #[test]
    fn test_list_add() {
        let a = "";

        let b = list_add(a, "eth1");
        assert_eq!(b, "eth1");

        let b = list_add(&b, "eth0.3");
        assert_eq!(b, "eth1 eth0.3");

        let b = list_add(&b, "eth4");
        assert_eq!(b, "eth1 eth0.3 eth4");
    }
}
