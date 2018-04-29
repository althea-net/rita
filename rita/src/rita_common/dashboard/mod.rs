use actix::prelude::*;
use KI;

use failure::Error;

use serde_json;
use serde_json::Value;

use rita_common::debt_keeper::{DebtKeeper, Dump};
use rita_common::tunnel_manager::{GetListen, Listen, TunnelManager, UnListen};

use futures;
use futures::Future;

use settings::{RitaCommonSettings, StatsServerSettings};

use SETTING;

pub mod network_endpoints;

struct Dashboard;

impl Actor for Dashboard {
    type Context = Context<Self>;
}

impl Supervised for Dashboard {}
impl SystemService for Dashboard {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Dashboard started");
    }
}

impl Default for Dashboard {
    fn default() -> Dashboard {
        Dashboard {}
    }
}

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
                .and_then(|res| {
                    let res = res.unwrap();
                    let mut interfaces = Vec::new();

                    let config = KI.ubus_call("uci", "get", "{ \"config\": \"wireless\"}")
                        .unwrap();

                    let val: Value = serde_json::from_str(&config).unwrap();

                    for (k, v) in val["values"].as_object().unwrap().iter() {
                        if v[".type"] == "wifi-iface" {
                            let mut interface: WifiInterface =
                                serde_json::from_value(v.clone()).unwrap();
                            interface.mesh = res.contains(&interface.device);
                            interface.section_name = k.clone();
                            interfaces.push(interface);
                        }
                    }

                    futures::future::ok(interfaces)
                })
                .from_err(),
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

#[derive(Serialize)]
pub struct NodeInfo {
    pub nickname: String,
    pub route_metric_to_exit: u64,
    pub total_payments: i64,
    pub debt: i64,
}

struct GetNodeInfo;

impl Message for GetNodeInfo {
    type Result = Result<Vec<NodeInfo>, Error>;
}

impl Handler<GetNodeInfo> for Dashboard {
    type Result = ResponseFuture<Vec<NodeInfo>, Error>;

    fn handle(&mut self, _msg: GetNodeInfo, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            DebtKeeper::from_registry()
                .send(Dump {})
                .and_then(|res| {
                    let res = res.unwrap();

                    let mut output = Vec::new();

                    for (k, v) in res.iter() {
                        output.push(NodeInfo {
                            nickname: serde_json::to_string(&k.mesh_ip).unwrap(),
                            route_metric_to_exit: 0,
                            total_payments: v.total_payment_recieved.clone().into(),
                            debt: v.debt.clone().into(),
                        })
                    }

                    futures::future::ok(output)
                })
                .from_err(),
        )
    }
}

struct GetStatsServerInfo;

impl Message for GetStatsServerInfo {
    type Result = Result<Option<StatsServerSettings>, Error>;
}

impl Handler<GetStatsServerInfo> for Dashboard {
    type Result = Result<Option<StatsServerSettings>, Error>;

    fn handle(&mut self, _msg: GetStatsServerInfo, _ctx: &mut Self::Context) -> Self::Result {
        if SETTING.stats_server_settings_is_set() {
            Ok(Some(SETTING.get_stats_server_settings().clone()))
        } else {
            Ok(None)
        }
    }
}

struct SetStatsServerInfo(Option<StatsServerSettings>);

impl Message for SetStatsServerInfo {
    type Result = Result<(), Error>;
}

impl Handler<SetStatsServerInfo> for Dashboard {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: SetStatsServerInfo, _ctx: &mut Self::Context) -> Self::Result {
        match msg.0 {
            Some(setting) => *SETTING.set_stats_server_settings() = setting,
            None => SETTING.clear_stats_server_settings(),
        }

        Ok(())
    }
}
