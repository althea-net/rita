//! A generalized interface for modifying networking interface assignments using UCI
use crate::RitaCommonError;
use actix_web::http::StatusCode;
use actix_web::{web::Json, HttpRequest, HttpResponse};
use althea_kernel_interface::fs_sync::fs_sync;
use althea_kernel_interface::manipulate_uci::{
    del_uci_var, get_uci_var, openwrt_reset_network, set_uci_var, uci_commit, uci_revert, uci_show,
};
use althea_kernel_interface::run_command;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::Ipv4Addr;

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
pub fn get_interfaces() -> Result<HashMap<String, InterfaceMode>, RitaCommonError> {
    let mut retval = HashMap::new();

    // Wired
    for (setting_name, value) in uci_show(Some("network"))? {
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
    }

    Ok(retval)
}

/// Find out a wired interface's mode (mesh, LAN, WAN) from the setting name
pub fn ethernet2mode(ifname: &str, setting_name: &str) -> Result<InterfaceMode, RitaCommonError> {
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
            let backhaul = uci_show(Some(prefix))?;
            trace!("{:?}", backhaul);
            let proto = if let Some(val) = backhaul.get(&format!("{prefix}.proto")) {
                val
            } else {
                return Err(RitaCommonError::InterfaceModeError(
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
                    return Err(RitaCommonError::InterfaceModeError(
                        "Failed to parse static wan!".to_string(),
                    ));
                }
            }
            return Err(RitaCommonError::InterfaceModeError(
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
fn set_interface_mode(iface_name: String, mode: InterfaceMode) -> Result<(), RitaCommonError> {
    let target_mode = mode;
    let interfaces = get_interfaces()?;
    let current_mode = get_current_interface_mode(&interfaces, &iface_name);
    if !interfaces.contains_key(&iface_name) {
        return Err(RitaCommonError::InterfaceModeError(
            "Attempted to configure non-existant or unavailable interface!".to_string(),
        ));
    } else if matches!(
        target_mode,
        InterfaceMode::Wan | InterfaceMode::StaticWan { .. } | InterfaceMode::LTE
    ) {
        // we can only have one WAN interface, check for others
        // StaticWAN entries are not identified seperately but if they ever are
        // you'll have to handle them here
        for entry in interfaces {
            let mode = entry.1;
            if matches!(
                mode,
                InterfaceMode::Wan | InterfaceMode::StaticWan { .. } | InterfaceMode::LTE
            ) {
                return Err(RitaCommonError::InterfaceModeError(
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
) -> Result<(), RitaCommonError> {
    trace!("InterfaceToSet received");
    if iface_name.len() != mode.len() {
        return Err(RitaCommonError::MiscStringError(
            "Extra mode or iface found!".to_string(),
        ));
    }
    // do not allow multiple WANs- this is checked for before we run through the setter so we do
    // not waste time on obviously incorrect configs
    let mut wan_count = 0;
    for m in mode.iter() {
        if matches!(m, InterfaceMode::Wan)
            || matches!(m, InterfaceMode::StaticWan { .. })
            || matches!(m, InterfaceMode::LTE)
        {
            wan_count += 1;
        }
    }
    if wan_count > 1 {
        return Err(RitaCommonError::MiscStringError(
            "Only one WAN or LTE interface allowed!".to_string(),
        ));
    }

    for (iface, mode) in iface_name.into_iter().zip(mode.into_iter()) {
        let setter = set_interface_mode(iface.clone(), mode);
        if setter.is_err() {
            return Err(RitaCommonError::InterfaceModeError(iface));
        }
    }

    trace!("Successfully transformed ethernet mode, rebooting");
    // reboot has been moved here to avoid doing it after every interface, in theory we could do this without rebooting
    // and some attention has been paid to maintaining that possibility
    run_command("reboot", &[])?;
    Ok(())
}

/// Transform a wired interface from mode A to mode B
pub fn ethernet_transform_mode(
    ifname: &str,
    a: InterfaceMode,
    b: InterfaceMode,
) -> Result<(), RitaCommonError> {
    trace!(
        "Ethernet mode transform: ifname {:?}, a {:?}, b {:?}",
        ifname,
        a,
        b,
    );
    if a == b {
        // noop that was easy!
        return Ok(());
    } else if a == InterfaceMode::Unknown || b == InterfaceMode::Unknown {
        return Err(RitaCommonError::InterfaceModeError(
            "We can't change Unknown interfaces!".to_string(),
        ));
    }
    let mut rita_common = settings::get_rita_common();
    let mut network = rita_common.network;

    // if we have edited UCI and it fails we set this var to handle cleanup later
    let mut return_codes = Vec::new();
    // in case of failure we revert to here
    let old_network_settings = { network.clone() };
    let filtered_ifname = format!("network.rita_{}", ifname.replace('.', ""));

    match a {
        // Wan is very simple, just delete it
        InterfaceMode::Wan | InterfaceMode::StaticWan { .. } => {
            network.external_nic = None;

            let ret = del_uci_var("network.backhaul");
            return_codes.push(ret);
        }
        // LTE is the same
        InterfaceMode::LTE => {
            network.external_nic = None;

            let ret = del_uci_var("network.lte");
            return_codes.push(ret);
        }
        // LAN is a bridge and the lan bridge must always remain because things
        // like WiFi interfaces are attached to it. So we just remove the interface
        // from the list
        InterfaceMode::Lan => {
            let list = get_uci_var("network.lan.ifname")?;
            let new_list = list_remove(&list, ifname);
            let ret = set_uci_var("network.lan.ifname", &new_list);
            return_codes.push(ret);
        }
        // remove the section from the network and rita config, peer listener watches this setting
        // and will yank these interfaces from active listening
        InterfaceMode::Mesh => {
            network.peer_interfaces.remove(ifname);

            let ret = del_uci_var(&filtered_ifname);
            return_codes.push(ret);
        }
        InterfaceMode::Unknown => unimplemented!(),
    }

    match b {
        // here we add back all the properties of backhaul we removed
        InterfaceMode::Wan => {
            network.external_nic = Some(ifname.to_string());

            let ret = set_uci_var("network.backhaul", "interface");
            return_codes.push(ret);
            let ret = set_uci_var("network.backhaul.ifname", ifname);
            return_codes.push(ret);
            let ret = set_uci_var("network.backhaul.proto", "dhcp");
            return_codes.push(ret);
        }
        InterfaceMode::StaticWan {
            netmask,
            ipaddr,
            gateway,
        } => {
            network.external_nic = Some(ifname.to_string());

            let ret = set_uci_var("network.backhaul", "interface");
            return_codes.push(ret);
            let ret = set_uci_var("network.backhaul.ifname", ifname);
            return_codes.push(ret);
            let ret = set_uci_var("network.backhaul.proto", "static");
            return_codes.push(ret);
            let ret = set_uci_var("network.backhaul.netmask", &format!("{netmask}"));
            return_codes.push(ret);
            let ret = set_uci_var("network.backhaul.ipaddr", &format!("{ipaddr}"));
            return_codes.push(ret);
            let ret = set_uci_var("network.backhaul.gateway", &format!("{gateway}"));
            return_codes.push(ret);
        }
        InterfaceMode::LTE => {
            network.external_nic = Some(ifname.to_string());

            let ret = set_uci_var("network.lte", "interface");
            return_codes.push(ret);
            let ret = set_uci_var("network.lte.ifname", ifname);
            return_codes.push(ret);
            let ret = set_uci_var("network.lte.proto", "dhcp");
            return_codes.push(ret);
        }
        // since we left lan mostly unmodified we just pop in the ifname
        InterfaceMode::Lan => {
            trace!("Converting interface to lan with ifname {:?}", ifname);
            let ret = get_uci_var("network.lan.ifname");
            match ret {
                Ok(list) => {
                    info!("The existing LAN interfaces list is {:?}", list);
                    let new_list = list_add(&list, ifname);
                    trace!("Setting the new list {:?}", new_list);
                    let ret = set_uci_var("network.lan.ifname", &new_list);
                    return_codes.push(ret);
                }
                Err(e) => {
                    if e.to_string().contains("Entry not found") {
                        trace!("No LAN interfaces found, setting one now");
                        let ret = set_uci_var("network.lan.ifname", ifname);
                        return_codes.push(ret);
                    } else {
                        warn!("Trying to read lan ifname returned {:?}", e);
                        return_codes.push(Err(e));
                    }
                }
            }
        }
        InterfaceMode::Mesh => {
            network.peer_interfaces.insert(ifname.to_string());

            let ret = set_uci_var(&filtered_ifname, "interface");
            return_codes.push(ret);
            let ret = set_uci_var(&format!("{filtered_ifname}.ifname"), ifname);
            return_codes.push(ret);
            let ret = set_uci_var(&format!("{filtered_ifname}.proto"), "static");
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
    if !error_occured.is_empty() {
        let res = uci_revert("network");
        rita_common.network = old_network_settings;
        settings::set_rita_common(rita_common);
        //bail!("Error running UCI commands! Revert attempted: {:?}", res);
        if let Err(re) = res {
            return Err(RitaCommonError::InterfaceToggleError {
                main_error: error_occured,
                revert_status: Some(re),
            });
        } else {
            return Err(RitaCommonError::InterfaceToggleError {
                main_error: error_occured,
                revert_status: None,
            });
        }
    }

    uci_commit("network")?;
    openwrt_reset_network()?;

    rita_common.network = network;
    settings::set_rita_common(rita_common);

    // try and save the config and fail if we can't
    if let Err(_e) = settings::write_config() {
        return Err(RitaCommonError::SettingsError(_e));
    }

    trace!("Transforming ethernet");
    // We edited disk contents, force global sync
    fs_sync()?;

    Ok(())
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
        let mut new_list = "".to_string();
        let mut first = true;
        for item in split {
            let filtered_item = item.trim();
            if !item.contains(entry) {
                trace!("{} is not {} it's on the list!", filtered_item, entry);
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

/// Toggles interfaces on openwrt devices using the provided list of interfaces
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

/// An alterative to the set interfaces endpoint which performs exit specific validation
/// for example exits should never have LTE ports and must always have at least one WAN port
pub async fn set_interfaces_exit_endpoint(interfaces: Json<InterfacesToSet>) -> HttpResponse {
    let interface = interfaces.into_inner();
    debug!("set exit /interfaces hit");
    for interface in interface.modes.iter() {
        if matches!(interface, InterfaceMode::LTE) {
            return HttpResponse::BadRequest().json("LTE interfaces are not allowed on exits");
        }
    }

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
