//! This file contains all the network endpoints used for the client dashbaord. This management dashboard
//! is for users to use to configure and manage their router and should be firewalled from the outside
//! world.
//!
//! For more documentation on specific functions see the router-dashboard file in the docs folder

use actix::prelude::*;
use actix_web::Path;
use failure::Error;
use futures::Future;
use serde_json;
use serde_json::Value;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::string::ToString;
use std::time::{Duration, Instant};
use std::{thread, time};
use tokio::timer::Delay;

use althea_types::ExitState;
use babel_monitor::Babel;
use num256::Int256;
use rita_common::dashboard::Dashboard;
use rita_common::debt_keeper::{DebtKeeper, Dump};
use rita_common::peer_listener::PeerListener;
use rita_common::peer_listener::{Listen, UnListen};
use settings::ExitServer;
use settings::RitaClientSettings;
use settings::RitaCommonSettings;
use KI;
use SETTING;

pub mod network_endpoints;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WifiInterface {
    #[serde(default)]
    pub section_name: String,
    pub network: String,
    #[serde(default)]
    pub mesh: bool,
    pub mode: String,
    pub ssid: String,
    pub encryption: String,
    pub key: String,
    #[serde(default, skip_deserializing)]
    pub device: WifiDevice,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiDevice {
    #[serde(default)]
    pub section_name: String,
    #[serde(rename = "type")]
    pub i_type: String,
    pub channel: String,
    pub path: String,
    pub htmode: String,
    pub hwmode: String,
    pub disabled: String,
    #[serde(default)]
    pub radio_type: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiSSID {
    pub radio: String,
    pub ssid: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiPass {
    pub radio: String,
    pub pass: String,
}

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
    Unknown, // Ambiguous wireless modes like monitor or promiscuous
}

impl ToString for InterfaceMode {
    fn to_string(&self) -> String {
        match self {
            InterfaceMode::Mesh => "mesh".to_owned(),
            InterfaceMode::LAN => "LAN".to_owned(),
            InterfaceMode::WAN => "WAN".to_owned(),
            InterfaceMode::Unknown => "unknown".to_owned(),
        }
    }
}

struct GetWifiConfig;

impl Message for GetWifiConfig {
    type Result = Result<Vec<WifiInterface>, Error>;
}

impl Handler<GetWifiConfig> for Dashboard {
    type Result = Result<Vec<WifiInterface>, Error>;

    fn handle(&mut self, _msg: GetWifiConfig, _ctx: &mut Self::Context) -> Self::Result {
        let mut interfaces = Vec::new();
        let mut devices = HashMap::new();

        let config = KI.ubus_call("uci", "get", "{ \"config\": \"wireless\"}")?;

        let val: Value = serde_json::from_str(&config)?;

        let items = match val["values"].as_object() {
            Some(i) => i,
            None => {
                error!("No \"values\" key in parsed wifi config!");
                return Err(format_err!("No \"values\" key parsed wifi config")).into();
            }
        };

        for (k, v) in items {
            if v[".type"] == "wifi-device" {
                let mut device: WifiDevice = serde_json::from_value(v.clone())?;
                device.section_name = k.clone();

                let channel: String = serde_json::from_value(v["channel"].clone())?;
                let channel: u8 = channel.parse()?;
                if channel > 20 {
                    device.radio_type = "5ghz".to_string();
                } else {
                    device.radio_type = "2ghz".to_string();
                }

                devices.insert(device.section_name.to_string(), device);
            }
        }
        for (k, v) in items {
            if v[".type"] == "wifi-iface" {
                let mut interface: WifiInterface = serde_json::from_value(v.clone())?;
                interface.mesh = interface.mode.contains("adhoc");
                interface.section_name = k.clone();

                let device_name: String = serde_json::from_value(v["device"].clone())?;
                interface.device = devices[&device_name].clone();
                interfaces.push(interface);
            }
        }

        Ok(interfaces)
    }
}

struct SetWifiConfig(Vec<WifiInterface>);

impl Message for SetWifiConfig {
    type Result = Result<(), Error>;
}

impl Handler<SetWifiConfig> for Dashboard {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: SetWifiConfig, _ctx: &mut Self::Context) -> Self::Result {
        for i in msg.0 {
            //TODO parse ifname from the WifiDevice instead of this hack,
            // probably easy to add when we add the ability to change the default wireless channel
            let iface_number = i.section_name.clone().chars().last();

            if i.mesh && iface_number.is_some() {
                let iface_name = format!("wlan{}", iface_number.unwrap());

                KI.set_uci_var(&format!("wireless.{}.ssid", i.section_name), "AltheaMesh")?;
                KI.set_uci_var(&format!("wireless.{}.encryption", i.section_name), "none")?;
                KI.set_uci_var(&format!("wireless.{}.mode", i.section_name), "adhoc")?;
                KI.set_uci_var(&format!("wireless.{}.network", i.section_name), &iface_name)?;
                KI.set_uci_var(&format!("network.rita_{}", iface_name.clone()), "interface")?;
                KI.set_uci_var(
                    &format!("network.{}.ifname", iface_name.clone()),
                    &iface_name,
                )?;
                KI.set_uci_var(&format!("network.{}.proto", iface_name.clone()), "static")?;

                // These must run before listen/unlisten to avoid race conditions
                KI.uci_commit()?;
                KI.openwrt_reset_wireless()?;
                // when we run wifi reset it takes seconds for a new fe80 address to show up
                thread::sleep(time::Duration::from_millis(30000));

                PeerListener::from_registry().do_send(Listen(iface_name.clone()));
            } else if iface_number.is_some() {
                let iface_name = format!("wlan{}", iface_number.unwrap());
                KI.set_uci_var(&format!("wireless.{}.ssid", i.section_name), &i.ssid)?;
                KI.set_uci_var(&format!("wireless.{}.key", i.section_name), &i.key)?;
                KI.set_uci_var(&format!("wireless.{}.mode", i.section_name), "ap")?;
                KI.set_uci_var(
                    &format!("wireless.{}.encryption", i.section_name),
                    "psk2+tkip+aes",
                )?;
                KI.set_uci_var(&format!("wireless.{}.network", i.section_name), "lan")?;

                // Order is reversed here
                PeerListener::from_registry().do_send(UnListen(iface_name));

                KI.uci_commit()?;
                KI.openwrt_reset_wireless()?;
            }
        }

        KI.uci_commit()?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;

        Ok(())
    }
}

#[derive(Serialize)]
pub struct NodeInfo {
    pub nickname: String,
    pub route_metric_to_exit: u16,
    pub total_payments: Int256,
    pub debt: i64,
    pub link_cost: u16,
    pub price_to_exit: u32,
}

pub struct GetNodeInfo;

impl Message for GetNodeInfo {
    type Result = Result<Vec<NodeInfo>, Error>;
}

impl Handler<GetNodeInfo> for Dashboard {
    type Result = ResponseFuture<Vec<NodeInfo>, Error>;

    fn handle(&mut self, _msg: GetNodeInfo, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            DebtKeeper::from_registry()
                .send(Dump {})
                .from_err()
                .and_then(|res| {
                    let stream = TcpStream::connect::<SocketAddr>(
                        format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
                    )?;
                    let mut babel = Babel::new(stream);
                    babel.start_connection()?;
                    let route_table_sample = babel.parse_routes()?;

                    let res = res?;

                    let mut output = Vec::new();

                    let exit_client = SETTING.get_exit_client();
                    let current_exit = exit_client.get_current_exit();

                    for (identity, debt_info) in res.iter() {
                        if current_exit.is_some() {
                            let exit_ip = current_exit.unwrap().id.mesh_ip;
                            let maybe_route = babel.get_route_via_neigh(
                                identity.mesh_ip,
                                exit_ip,
                                &route_table_sample,
                            );

                            // We have a peer that is an exit, so we can't find a route
                            // from them to our selected exit. Other errors can also get
                            // caught here
                            if maybe_route.is_err() {
                                output.push(NodeInfo {
                                    nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                    route_metric_to_exit: u16::max_value(),
                                    total_payments: debt_info.total_payment_received.into(),
                                    debt: debt_info.debt.clone().into(),
                                    link_cost: u16::max_value(),
                                    price_to_exit: u32::max_value(),
                                });
                                continue;
                            }
                            let route = maybe_route?;

                            output.push(NodeInfo {
                                nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                route_metric_to_exit: route.metric,
                                total_payments: debt_info.total_payment_received.into(),
                                debt: debt_info.debt.clone().into(),
                                link_cost: route.refmetric,
                                price_to_exit: route.price,
                            })
                        } else {
                            output.push(NodeInfo {
                                nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                route_metric_to_exit: u16::max_value(),
                                total_payments: debt_info.total_payment_received.into(),
                                debt: debt_info.debt.clone().into(),
                                link_cost: u16::max_value(),
                                price_to_exit: u32::max_value(),
                            })
                        }
                    }

                    Ok(output)
                }),
        )
    }
}

#[derive(Serialize)]
pub struct ExitInfo {
    nickname: String,
    exit_settings: ExitServer,
    is_selected: bool,
    have_route: bool,
    is_reachable: bool,
    is_tunnel_working: bool,
}

pub struct GetExitInfo;

impl Message for GetExitInfo {
    type Result = Result<Vec<ExitInfo>, Error>;
}

/// Checks if the provided exit is selected
fn is_selected(exit: &ExitServer, current_exit: Option<&ExitServer>) -> Result<bool, Error> {
    match current_exit {
        None => Ok(false),
        Some(i) => Ok(i == exit),
    }
}

/// Determines if the provide exit is currently selected, if it's setup, and then if it can be reached over
/// the exit tunnel via a ping
fn is_tunnel_working(exit: &ExitServer, current_exit: Option<&ExitServer>) -> Result<bool, Error> {
    if current_exit.is_some() && is_selected(exit, current_exit)? {
        if current_exit.unwrap().info.general_details().is_some() {
            let internal_ip = current_exit
                .unwrap()
                .clone()
                .info
                .general_details()
                .unwrap()
                .server_internal_ip;
            KI.ping_check_v4(&internal_ip)
        } else {
            return Ok(false);
        }
    } else {
        return Ok(false);
    }
}

impl Handler<GetExitInfo> for Dashboard {
    type Result = Result<Vec<ExitInfo>, Error>;

    fn handle(&mut self, _msg: GetExitInfo, _ctx: &mut Self::Context) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;
        let mut babel = Babel::new(stream);
        babel.start_connection()?;
        let route_table_sample = babel.parse_routes()?;

        let mut output = Vec::new();

        let exit_client = SETTING.get_exit_client();
        let current_exit = exit_client.get_current_exit();

        for exit in exit_client.exits.clone().into_iter() {
            let selected = is_selected(&exit.1, current_exit)?;
            let have_route = babel.do_we_have_route(&exit.1.id.mesh_ip, &route_table_sample)?;

            // failed pings block for one second, so we should be sure it's at least reasonable
            // to expect the pings to work before issuing them.
            let reachable = match have_route {
                true => KI.ping_check_v6(&exit.1.id.mesh_ip)?,
                false => false,
            };
            let tunnel_working = match (have_route, selected) {
                (true, true) => is_tunnel_working(&exit.1, current_exit)?,
                _ => false,
            };

            output.push(ExitInfo {
                nickname: exit.0,
                exit_settings: exit.1.clone(),
                is_selected: selected,
                have_route: have_route,
                is_reachable: reachable,
                is_tunnel_working: tunnel_working,
            })
        }

        Ok(output)
    }
}

#[derive(Debug)]
pub struct SetWiFiSSID(WifiSSID);

impl Message for SetWiFiSSID {
    type Result = Result<(), Error>;
}

impl Handler<SetWiFiSSID> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: SetWiFiSSID, _ctx: &mut Self::Context) -> Self::Result {
        // think radio0, radio1
        let iface_name = msg.0.radio;
        let ssid = msg.0.ssid;
        let section_name = format!("default_{}", iface_name);
        KI.set_uci_var(&format!("wireless.{}.ssid", section_name), &ssid)?;

        KI.uci_commit()?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SetWiFiPass(WifiPass);

impl Message for SetWiFiPass {
    type Result = Result<(), Error>;
}

impl Handler<SetWiFiPass> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: SetWiFiPass, _ctx: &mut Self::Context) -> Self::Result {
        // think radio0, radio1
        let iface_name = msg.0.radio;
        let pass = msg.0.pass;
        let section_name = format!("default_{}", iface_name);
        KI.set_uci_var(&format!("wireless.{}.key", section_name), &pass)?;

        KI.uci_commit()?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
        Ok(())
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
            retval.insert(value.clone(), ethernet2mode(&value, &setting_name)?);
        }
    }

    // Wireless
    for (setting_name, value) in KI.uci_show(Some("wireless"))? {
        if setting_name.contains("ifname") {
            retval.insert(value.clone(), wlan2mode(&value, &setting_name)?);
        }
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
        other => bail!(
            "Unknown wired port mode for interface {:?}, section name {:?}",
            ifname,
            other
        ),
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

    let radio_name = setting_name.replace("wireless.", "").replace(".ifname", "");

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
    Ok(match mode_name.as_str() {
        "adhoc" => InterfaceMode::Mesh,
        "ap" => InterfaceMode::LAN,
        "sta" => InterfaceMode::WAN,
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
        }

        // in theory you can have all sorts of wonky interface names, but we know
        // that we hardcode wlan0 and wlan0 as wlan iface names so we check for that
        if iface_name.contains("wlan") {
            wifi_transform_mode(&iface_name, current_mode, target_mode)
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
        InterfaceMode::Unknown => unimplemented!(),
    }

    match b {
        // here we add back all the properties of backhaul we removed
        InterfaceMode::WAN => {
            let ret = KI.add_uci_var("network.backhaul", "interface");
            return_codes.push(ret);
            let ret = KI.add_uci_var("network.backhaul.ifname", ifname);
            return_codes.push(ret);
            let ret = KI.add_uci_var("network.backhaul.proto", "dhcp");
            return_codes.push(ret);
        }
        // since we left lan mostly unomidifed we just pop in the ifname
        InterfaceMode::LAN => {
            let ret = KI.get_uci_var("network.lan.ifname");
            match ret {
                Ok(list) => {
                    let new_list = comma_list_add(&list, &ifname);
                    let ret = KI.set_uci_var("network.lan.ifname", &new_list);
                    return_codes.push(ret);
                }
                Err(e) => {
                    warn!("Trying to read lan ifname returned {:?}", e);
                    return_codes.push(Err(e));
                }
            }
        }
        // next we do some magic to listen on the interface after a minute
        InterfaceMode::Mesh => {
            let ret = KI.add_uci_var(&filtered_ifname, "interface");
            return_codes.push(ret);
            let ret = KI.add_uci_var(&format!("{}.ifname", filtered_ifname), ifname);
            return_codes.push(ret);
            let ret = KI.add_uci_var(&format!("{}.proto", filtered_ifname), "static");
            return_codes.push(ret);
            mesh_add = true;
        }
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
        let _ = KI.uci_revert("network");
        bail!("Error running UCI commands! See logs for details");
    } else if mesh_add {
        let when = Instant::now() + Duration::from_millis(60000);
        let locally_owned_ifname = ifname.clone().to_string();

        let fut = Delay::new(when)
            .map_err(|e| warn!("timer failed; err={:?}", e))
            .and_then(move |_| {
                PeerListener::from_registry().do_send(Listen(locally_owned_ifname));
                Ok(())
            });

        Arbiter::spawn(fut);
    }

    KI.uci_commit()?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;

    Ok(())
}

/// Transform a wireless interface from mode A to mode B
pub fn wifi_transform_mode(ifname: &str, a: InterfaceMode, b: InterfaceMode) -> Result<(), Error> {
    trace!(
        "Wifi mode transform: ifname {:?}, a {:?}, b {:?}",
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
        bail!("WAN not supported for wifi interfaces!");
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

    match a {
        InterfaceMode::WAN => unimplemented!(),
        // nothing to do here we overwrite everything we need later
        InterfaceMode::LAN => {}
        // for mesh we need to send an unlisten and delete the static interface we made
        InterfaceMode::Mesh => {
            let ret = KI.del_uci_var(&format!("network.rita_{}", ifname));
            return_codes.push(ret);
            PeerListener::from_registry().do_send(UnListen(ifname.clone().to_string()));
        }
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
        InterfaceMode::Mesh => {
            let ret = KI.set_uci_var(
                &format!("wireless.{}.network", network_section),
                &format!("rita_{}", ifname),
            );
            return_codes.push(ret);
            // TODO detect if the driver perfers adhoc or meshpoint
            let ret = KI.set_uci_var(&format!("wireless.{}.mode", network_section), "adhoc");
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("wireless.{}.ssid", network_section), "AltheaMesh");
            return_codes.push(ret);
            let ret = KI.set_uci_var(&format!("wireless.{}.encryption", network_section), "none");
            return_codes.push(ret);

            let ret = KI.add_uci_var(&format!("network.rita_{}", ifname), "interface");
            return_codes.push(ret);
            let ret = KI.add_uci_var(&format!("network.rita_{}.ifname", ifname), ifname);
            return_codes.push(ret);
            let ret = KI.add_uci_var(&format!("network.rita_{}.proto", ifname), "static");
            return_codes.push(ret);
            mesh_add = true;
        }
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
        let _ = KI.uci_revert("network");
        let _ = KI.uci_revert("wireless");
        bail!("Error running UCI commands! See logs for details");
    } else if mesh_add {
        let when = Instant::now() + Duration::from_millis(60000);
        let locally_owned_ifname = ifname.clone().to_string();

        let fut = Delay::new(when)
            .map_err(|e| warn!("timer failed; err={:?}", e))
            .and_then(move |_| {
                PeerListener::from_registry().do_send(Listen(locally_owned_ifname));
                Ok(())
            });

        Arbiter::spawn(fut);
    }

    KI.uci_commit()?;
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
            if !item.contains(entry) {
                let tmp_list = new_list.to_string();
                if first {
                    new_list = tmp_list + &format!("{}", entry);
                    first = false;
                } else {
                    new_list = tmp_list + &format!(", {}", entry);
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
