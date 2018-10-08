/*
These endpoints are used to modify mundane wireless settings
*/

use actix::prelude::*;
use failure::Error;
use serde_json;
use serde_json::Value;
use std::collections::HashMap;

use rita_common::dashboard::Dashboard;
use KI;

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
    pub key: Option<String>,
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

impl Message for WifiSSID {
    type Result = Result<(), Error>;
}

impl Handler<WifiSSID> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: WifiSSID, _ctx: &mut Self::Context) -> Self::Result {
        // think radio0, radio1
        let iface_name = msg.radio;
        let ssid = msg.ssid;
        let section_name = format!("default_{}", iface_name);
        KI.set_uci_var(&format!("wireless.{}.ssid", section_name), &ssid)?;

        KI.uci_commit(&"wireless")?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
        Ok(())
    }
}

impl Message for WifiPass {
    type Result = Result<(), Error>;
}

impl Handler<WifiPass> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: WifiPass, _ctx: &mut Self::Context) -> Self::Result {
        // think radio0, radio1
        let iface_name = msg.radio;
        let pass = msg.pass;
        let section_name = format!("default_{}", iface_name);
        KI.set_uci_var(&format!("wireless.{}.key", section_name), &pass)?;

        KI.uci_commit(&"wireless")?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
        Ok(())
    }
}

pub struct GetWifiConfig;

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
            if v[".type"] == "wifi-iface" && v["mode"] != "mesh" {
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
