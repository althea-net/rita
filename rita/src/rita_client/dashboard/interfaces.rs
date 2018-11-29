/*
A generalized interface for modifying networking interface assignments using UCI
*/

use super::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InterfaceToSet {
    pub interface: String,
    pub mode: InterfaceMode,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum InterfaceMode {
    Mesh,
    LAN,
    WAN,
    Meshpoint, //combo of lan and mesh
    Unknown,   // Ambiguous wireless modes like monitor or promiscuous
}

impl ToString for InterfaceMode {
    fn to_string(&self) -> String {
        match self {
            InterfaceMode::Mesh => "mesh".to_owned(),
            InterfaceMode::Meshpoint => "Meshpoint".to_owned(),
            InterfaceMode::LAN => "LAN".to_owned(),
            InterfaceMode::WAN => "WAN".to_owned(),
            InterfaceMode::Unknown => "unknown".to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct GetInterfaces;

impl Message for GetInterfaces {
    type Result = Result<HashMap<String, InterfaceMode>, Error>;
}

impl Handler<GetInterfaces> for Dashboard {
    type Result = Result<HashMap<String, InterfaceMode>, Error>;
    fn handle(&mut self, _msg: GetInterfaces, _ctx: &mut Self::Context) -> Self::Result {
        get_interfaces()
    }
}

/// Gets a list of interfaces and their modes by parsing UCI
pub fn get_interfaces() -> Result<HashMap<String, InterfaceMode>, Error> {
    let mut retval = HashMap::new();

    // Wired
    for (setting_name, value) in KI.uci_show(Some("network"))? {
        // Only non-loopback non-bridge interface names should get past
        if setting_name.contains("ifname") && !value.contains("backhaul") && value != "lo" {
            // it's a list and we need to handle that
            if value.contains(",") {
                for list_member in value.split(",") {
                    retval.insert(
                        list_member.replace(" ", "").to_string(),
                        ethernet2mode(&value, &setting_name)?,
                    );
                }
            } else {
                retval.insert(value.clone(), ethernet2mode(&value, &setting_name)?);
            }
        }
    }

    // Wireless
    match KI.uci_show(Some("wireless")) {
        Ok(value) => {
            for (setting_name, value) in value {
                if setting_name.contains("ifname") {
                    retval.insert(value.clone(), wlan2mode(&value, &setting_name)?);
                }
            }
        }
        _ => trace!("Device does not have WiFi!"),
    }

    Ok(retval)
}

/// Find out a wired interface's mode (mesh, LAN, WAN) from the setting name
pub fn ethernet2mode(ifname: &str, setting_name: &str) -> Result<InterfaceMode, Error> {
    trace!(
        "ethernet2mode: ifname {:?}, setting_name {:?}",
        ifname,
        setting_name
    );

    // Match parent section name
    Ok(match &setting_name.replace(".ifname", "") {
        s if s.contains("rita_") => InterfaceMode::Mesh,
        s if s.contains("lan") => InterfaceMode::LAN,
        s if s.contains("backhaul") => InterfaceMode::WAN,
        other => {
            warn!(
                "Unknown wired port mode for interface {:?}, section name {:?}",
                ifname, other
            );
            InterfaceMode::Unknown
        }
    })
}

/// Find out a wireless interface's mode (mesh, LAN, WAN) from the 802.11 mode of operation
pub fn wlan2mode(ifname: &str, setting_name: &str) -> Result<InterfaceMode, Error> {
    trace!(
        "wlan2mode: ifname {:?}, setting_name {:?}",
        ifname,
        setting_name
    );

    let uci = KI.uci_show(Some("wireless"))?;

    let radio_name = setting_name
        .replace("wireless.", "")
        .replace(".ifname", "")
        .replace("default_", "")
        .replace("mesh_", "");

    let meshpoint_enabled = uci.get(&format!("wireless.mesh_{}.disabled", radio_name));

    // Find the mode entry
    let mode_entry_name = format!("wireless.default_{}.mode", radio_name);

    let mode_name = match uci.get(&mode_entry_name) {
        Some(mode_name) => mode_name,
        None => {
            error!("Mode setting entry {:?} not found", mode_entry_name);
            bail!("Mode setting entry {:?} not found", mode_entry_name);
        }
    };

    // Match mode
    Ok(match (mode_name.as_str(), meshpoint_enabled) {
        ("adhoc", _) => InterfaceMode::Mesh,
        ("ap", None) => InterfaceMode::LAN,
        ("sta", None) => InterfaceMode::WAN,
        ("ap", Some(v)) => match v.as_str() {
            "1" => InterfaceMode::LAN,
            "0" => InterfaceMode::Meshpoint,
            _ => {
                warn!(
                    "Ambiguous Meshpoint status on interface {:?}, radio {:?}",
                    ifname, radio_name
                );
                InterfaceMode::Unknown
            }
        },
        ("sta", Some(v)) => match v.as_str() {
            "1" => InterfaceMode::LAN,
            "0" => InterfaceMode::Meshpoint,
            _ => {
                warn!(
                    "Ambiguous Meshpoint status on interface {:?}, radio {:?}",
                    ifname, radio_name
                );
                InterfaceMode::Unknown
            }
        },
        other => {
            warn!(
                "Ambiguous WiFi mode {:?} on interface {:?}, radio {:?}",
                other, ifname, radio_name
            );
            InterfaceMode::Unknown
        }
    })
}

impl Message for InterfaceToSet {
    type Result = Result<(), Error>;
}

impl Handler<InterfaceToSet> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: InterfaceToSet, _ctx: &mut Self::Context) -> Self::Result {
        let iface_name = msg.interface;
        let target_mode = msg.mode;
        let interfaces = get_interfaces()?;
        let current_mode = get_current_interface_mode(&interfaces, &iface_name);
        if !interfaces.contains_key(&iface_name) {
            bail!("Attempted to configure non-existant or unavailable itnerface!");
        } else if target_mode == InterfaceMode::WAN {
            // we can only have one WAN interface, check for others
            for entry in interfaces {
                let mode = entry.1;
                if mode == InterfaceMode::WAN {
                    bail!("There can only be one WAN interface!");
                }
            }
        } else if target_mode == InterfaceMode::LAN && !iface_name.contains("wlan") {
            // we can only have one LAN ethernet interface, check for others
            for entry in interfaces {
                let mode = entry.1;
                if mode == InterfaceMode::LAN {
                    bail!("There can only be one LAN ethernet interface!");
                }
            }
        }

        // in theory you can have all sorts of wonky interface names, but we know
        // that we hardcode wlan0 and wlan0 as wlan iface names so we check for that
        if iface_name.contains("wlan") {
            wlan_transform_mode(&iface_name, current_mode, target_mode)
        } else {
            ethernet_transform_mode(&iface_name, current_mode, target_mode)
        }
    }
}

/// Transform a wired inteface from mode A to mode B
pub fn ethernet_transform_mode(
    ifname: &str,
    a: InterfaceMode,
    b: InterfaceMode,
) -> Result<(), Error> {
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
        bail!("We can't change Unknown interfaces!");
    }

    // if we have edited UCI and it fails we set this var to handle cleanup later
    let mut return_codes = Vec::new();
    let mut mesh_add = false;
    let filtered_ifname = format!("network.rita_{}", ifname.replace(".", ""));

    match a {
        // Wan is very simple, just delete it
        InterfaceMode::WAN => {
            let ret = KI.del_uci_var("network.backhaul");
            SETTING.get_network_mut().external_nic = None;
            return_codes.push(ret);
        }
        // lan is a little more complicated, wifi interfaces
        // may depend on it so we only remove the ifname entry
        InterfaceMode::LAN => {
            let list = KI.get_uci_var("network.lan.ifname")?;
            let new_list = comma_list_remove(&list, ifname);
            let ret = KI.set_uci_var("network.lan.ifname", &new_list);
            return_codes.push(ret);
        }
        // for mesh we need to send an unlisten so that Rita stops
        // listening then we can remove the section
        InterfaceMode::Mesh => {
            PeerListener::from_registry().do_send(UnListen(ifname.clone().to_string()));
            let ret = KI.del_uci_var(&filtered_ifname);
            return_codes.push(ret);
        }
        InterfaceMode::Meshpoint => unimplemented!(),
        InterfaceMode::Unknown => unimplemented!(),
    }

    match b {
        // here we add back all the properties of backhaul we removed
        InterfaceMode::WAN => {
            SETTING.get_network_mut().external_nic = Some(ifname.to_string());
            let ret = KI.set_uci_var("network.backhaul", "interface");
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.ifname", ifname);
            return_codes.push(ret);
            let ret = KI.set_uci_var("network.backhaul.proto", "dhcp");
            return_codes.push(ret);
        }
        // since we left lan mostly unomidifed we just pop in the ifname
        InterfaceMode::LAN => {
            trace!("Converting interface to lan with ifname {:?}", ifname);
            let ret = KI.get_uci_var("network.lan.ifname");
            match ret {
                Ok(list) => {
                    trace!("The existing LAN interfaces list is {:?}", list);
                    let new_list = comma_list_add(&list, &ifname);
                    trace!("Setting the new list {:?}", new_list);
                    let ret = KI.set_uci_var("network.lan.ifname", &new_list);
                    return_codes.push(ret);
                }
                Err(e) => {
                    if e.to_string().contains("Entry not found") {
                        trace!("No LAN interfaces found, setting one now");
                        let ret = KI.set_uci_var("network.lan.ifname", &ifname);
                        return_codes.push(ret);
                    } else {
                        warn!("Trying to read lan ifname returned {:?}", e);
                        return_codes.push(Err(e));
                    }
                }
            }
        }
        // next we do some magic to listen on the interface after a minute
        InterfaceMode::Mesh => {
            let ret = KI.set_uci_var(&filtered_ifname, "interface");
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("{}.ifname", filtered_ifname), ifname);
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("{}.proto", filtered_ifname), "static");
            return_codes.push(ret);
            mesh_add = true;
        }
        InterfaceMode::Meshpoint => unimplemented!(),
        InterfaceMode::Unknown => unimplemented!(),
    }

    // check all of our return codes in order to handle any possible issue
    let mut error_occured = false;
    for ret in return_codes {
        if ret.is_err() {
            error_occured = true;
        }
    }
    if error_occured {
        let res = KI.uci_revert("network");
        bail!("Error running UCI commands! Revert attempted: {:?}", res);
    } else if mesh_add {
        let when = Instant::now() + Duration::from_millis(60000);
        let locally_owned_ifname = ifname.clone().to_string();

        let fut = Delay::new(when)
            .map_err(|e| warn!("timer failed; err={:?}", e))
            .and_then(move |_| {
                trace!("Adding mesh interface {:?}", locally_owned_ifname);
                PeerListener::from_registry().do_send(Listen(locally_owned_ifname));
                Ok(())
            });

        Arbiter::spawn(fut);
    }

    KI.uci_commit(&"network")?;
    KI.openwrt_reset_network()?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;

    Ok(())
}

/// Transform a wireless interface from mode A to mode B
pub fn wlan_transform_mode(ifname: &str, a: InterfaceMode, b: InterfaceMode) -> Result<(), Error> {
    trace!(
        "wlan mode transform: ifname {:?}, a {:?}, b {:?}",
        ifname,
        a,
        b,
    );
    if a == b {
        // noop that was easy!
        return Ok(());
    } else if a == InterfaceMode::Unknown || b == InterfaceMode::Unknown {
        bail!("We can't change Unknown interfaces!");
    } else if a == InterfaceMode::WAN || b == InterfaceMode::WAN {
        // possible in theory but not implemented
        bail!("WAN not supported for wlan interfaces!");
    }

    // if we have edited UCI and it fails we set this var to handle cleanup later
    let mut return_codes = Vec::new();
    let mut mesh_add = false;

    // we assume wlan0 => radio0 this is held true by our config
    // modifications but is not generally true for OpenWRT
    let radio = match ifname.chars().last() {
        Some(character) => format!("radio{}", character),
        None => bail!("Invalid interface name {:?}", ifname),
    };
    let network_section = format!("default_{}", radio);
    let mesh_wlan = match ifname {
        "wlan0" => "wlan2",
        "wlan1" => "wlan3",
        // we hardcode meshpoint radios to wlan2 and 3 but this assumes no device
        // will ever have more than two internal radios
        _ => bail!("wlan name not considered in design!"),
    };

    match a {
        InterfaceMode::WAN => unimplemented!(),
        // nothing to do here we overwrite everything we need later
        InterfaceMode::LAN => {}
        // for mesh we need to send an unlisten and delete the static interface we made
        InterfaceMode::Meshpoint => {
            let ret = KI.set_uci_var(&format!("wireless.mesh_{}.disabled", radio), "1");
            return_codes.push(ret);
            PeerListener::from_registry().do_send(UnListen(mesh_wlan.to_string()));
        }
        InterfaceMode::Mesh => unimplemented!(),
        InterfaceMode::Unknown => unimplemented!(),
    }

    match b {
        InterfaceMode::WAN => unimplemented!(),
        // since we left lan mostly unomidifed we just pop in the ifname
        InterfaceMode::LAN => {
            let ret = KI.set_uci_var(&format!("wireless.{}.network", network_section), "lan");
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("wireless.{}.mode", network_section), "ap");
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("wireless.{}.ssid", network_section), "AltheaHome");
            return_codes.push(ret);
            let ret = KI.set_uci_var(
                &format!("wireless.{}.encryption", network_section),
                "psk2+tkip+aes",
            );
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("wireless.{}.key", network_section), "ChangeMe");
            return_codes.push(ret);
        }
        // in this section we modfiy the wlan config to mesh and then add a static logical iface
        // that is used for things like ip assignment etc
        InterfaceMode::Meshpoint => {
            let val = KI.get_uci_var(&format!("wireless.mesh_{}.disabled", radio));
            match val {
                Ok(status) => match status.as_str() {
                    "0" => {
                        warn!("You can't meshpoint both wireless interfaces!");
                        return_codes.push(Err(format_err!(
                            "You can't meshpoint both wireless interfaces!"
                        )));
                    }
                    "1" => {
                        let ret = KI.set_uci_var(&format!("wireless.mesh_{}.disabled", radio), "0");
                        return_codes.push(ret);
                        mesh_add = true;
                    }
                    _ => {
                        error!("Deivce is not meshpoint enabled?");
                        return_codes.push(Err(format_err!("Device may not be meshpoint enabled!")));
                    }
                },
                Err(e) => return_codes.push(Err(e)),
            }
        }
        InterfaceMode::Mesh => unimplemented!(),
        InterfaceMode::Unknown => unimplemented!(),
    }

    // check all of our return codes in order to handle any possible issue
    let mut error_occured = false;
    for ret in return_codes {
        if ret.is_err() {
            error_occured = true;
        }
    }
    if error_occured {
        let res_a = KI.uci_revert("network");
        let res_b = KI.uci_revert("wireless");
        bail!(
            "Error running UCI commands! Revert attempted: {:?} {:?}",
            res_a,
            res_b
        );
    } else if mesh_add {
        let when = Instant::now() + Duration::from_millis(60000);
        let locally_owned_ifname = mesh_wlan.clone().to_string();

        let fut = Delay::new(when)
            .map_err(|e| warn!("timer failed; err={:?}", e))
            .and_then(move |_| {
                trace!("Adding mesh interface {:?}", locally_owned_ifname);
                PeerListener::from_registry().do_send(Listen(locally_owned_ifname));
                Ok(())
            });

        Arbiter::spawn(fut);
    }

    KI.uci_commit(&"wireless")?;
    KI.uci_commit(&"network")?;
    KI.openwrt_reset_network()?;
    KI.openwrt_reset_wireless()?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;

    Ok(())
}

/// A helper function for adding entires to a comma deliminated list
pub fn comma_list_add(list: &str, entry: &str) -> String {
    if list.len() > 0 {
        format!("{}, {}", list, entry)
    } else {
        entry.to_string()
    }
}

/// A helper function for removing entires to a comma deliminated list
pub fn comma_list_remove(list: &str, entry: &str) -> String {
    if list.len() > 0 {
        let split = list.split(",");
        let mut new_list = "".to_string();
        let mut first = true;
        for item in split {
            let filtered_item = item.trim();
            if !item.contains(entry) {
                trace!("{} is not {} it's on the list!", filtered_item, entry);
                let tmp_list = new_list.to_string();
                if first {
                    new_list = tmp_list + &format!("{}", filtered_item);
                    first = false;
                } else {
                    new_list = tmp_list + &format!(", {}", filtered_item);
                }
            }
        }
        new_list.to_string()
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
            return mode.clone();
        }
    }
    InterfaceMode::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comma_list_remove() {
        let a = "eth0.3, eth1, eth2, eth3, eth4";

        let b = comma_list_remove(a, "eth1");
        assert_eq!(b, "eth0.3, eth2, eth3, eth4");

        let b = comma_list_remove(&b, "eth0.3");
        assert_eq!(b, "eth2, eth3, eth4");

        let b = comma_list_remove(&b, "eth4");
        assert_eq!(b, "eth2, eth3");

        let b = comma_list_remove(&b, "eth2");
        assert_eq!(b, "eth3");

        let b = comma_list_remove(&b, "eth3");
        assert_eq!(b, "");
    }

    #[test]
    fn test_comma_list_add() {
        let a = "";

        let b = comma_list_add(a, "eth1");
        assert_eq!(b, "eth1");

        let b = comma_list_add(&b, "eth0.3");
        assert_eq!(b, "eth1, eth0.3");

        let b = comma_list_add(&b, "eth4");
        assert_eq!(b, "eth1, eth0.3, eth4");
    }
}

pub fn get_interfaces_endpoint(
    _req: HttpRequest,
) -> Box<Future<Item = Json<HashMap<String, InterfaceMode>>, Error = Error>> {
    debug!("get /interfaces hit");
    Dashboard::from_registry()
        .send(GetInterfaces)
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_interfaces_endpoint(
    interface: Json<InterfaceToSet>,
) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("set /interfaces hit");
    let to_set = interface.into_inner();
    Dashboard::from_registry()
        .send(to_set)
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
