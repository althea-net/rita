
use actix::prelude::*;

use failure::Error;
use futures;
use futures::Future;
use serde_json;
use serde_json::Value;

use rita_common::tunnel_manager::{GetListen, Listen, TunnelManager, UnListen};
use rita_common::dashboard::Dashboard;
use KI;

pub mod network_endpoints;

#[derive(Serialize, Deserialize)]
pub struct WifiInterface {
    #[serde(default)]
    pub section_name: String,
    pub device: String,
    pub network: String,
    #[serde(default)]
    pub mesh: bool,
    pub ssid: String,
    pub encryption: String,
    pub key: String,
}

struct GetWifiConfig;

impl Message for GetWifiConfig {
    type Result = Result<Vec<WifiInterface>, Error>;
}

impl Handler<GetWifiConfig> for Dashboard {
    type Result = ResponseFuture<Vec<WifiInterface>, Error>;

    fn handle(&mut self, _msg: GetWifiConfig, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            TunnelManager::from_registry()
                .send(GetListen {})
                .from_err()
                .and_then(|res| {
                    let res = res.unwrap();
                    let mut interfaces = Vec::new();

                    let config = match KI.ubus_call("uci", "get", "{ \"config\": \"wireless\"}") {
                        Ok(cfg) => cfg,
                        Err(e) => return futures::future::err(e),
                    };

                    let val: Value = match serde_json::from_str(&config) {
                        Ok(v) => v,
                        Err(e) => return futures::future::err(e.into()),
                    };

                    let items = match val["values"].as_object() {
                        Some(i) => i,
                        None => {
                            error!("No \"values\" key in parsed wifi config!");
                            return Err(format_err!("No \"values\" key parsed wifi config")).into();
                        }
                    };

                    for (k, v) in items {
                        if v[".type"] == "wifi-iface" {
                            let mut interface: WifiInterface =
                                match serde_json::from_value(v.clone()) {
                                    Ok(i) => i,
                                    Err(e) => return futures::future::err(e.into()),
                                };
                            interface.mesh = res.contains(&interface.device);
                            interface.section_name = k.clone();
                            interfaces.push(interface);
                        }
                    }

                    futures::future::ok(interfaces)
                }),
        )
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
            if i.mesh {
                TunnelManager::from_registry().do_send(Listen(i.device.clone()))
            } else {
                TunnelManager::from_registry().do_send(UnListen(i.device.clone()))
            }

            KI.set_uci_var(&format!("wireless.{}.ssid", i.section_name), &i.ssid)?;
            KI.set_uci_var(
                &format!("wireless.{}.encryption", i.section_name),
                &i.encryption,
            )?;
            KI.set_uci_var(&format!("wireless.{}.key", i.section_name), &i.key)?;
        }

        KI.uci_commit()?;
        KI.openwrt_reset_wireless()?;

        Ok(())
    }
}