use actix::prelude::*;

use failure::Error;
use futures::Future;
use serde_json;
use serde_json::Value;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};

use babel_monitor::Babel;
use num256::Int256;
use rita_common::dashboard::Dashboard;
use rita_common::debt_keeper::{DebtKeeper, Dump};
use rita_common::tunnel_manager::{GetListen, Listen, TunnelManager, UnListen};
use settings::ExitServer;
use settings::RitaClientSettings;
use settings::RitaCommonSettings;
use KI;
use SETTING;

pub mod network_endpoints;

#[derive(Serialize, Deserialize, Clone)]
pub struct WifiInterface {
    #[serde(default)]
    pub section_name: String,
    pub network: String,
    #[serde(default)]
    pub mesh: bool,
    pub ssid: String,
    pub encryption: String,
    pub key: String,
    #[serde(default, skip_deserializing)]
    pub device: WifiDevice,
}

#[derive(Serialize, Deserialize, Default, Clone)]
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

                            let channel: String =
                                serde_json::from_value(v["channel"].clone()).unwrap();
                            let channel: u8 = channel.parse().unwrap();
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
                            interface.mesh = res.contains(&interface.device.section_name);
                            interface.section_name = k.clone();

                            let device_name: String =
                                serde_json::from_value(v["device"].clone()).unwrap();
                            interface.device = devices[&device_name].clone();
                            interfaces.push(interface);
                        }
                    }

                    Ok(interfaces)
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
                TunnelManager::from_registry().do_send(Listen(i.device.section_name.clone()))
            } else {
                TunnelManager::from_registry().do_send(UnListen(i.device.section_name.clone()))
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
                                    route_metric_to_exit: 0,
                                    total_payments: debt_info.total_payment_recieved.into(),
                                    debt: debt_info.debt.clone().into(),
                                    link_cost: 0,
                                    price_to_exit: 0,
                                });
                                continue;
                            }
                            let route = maybe_route?;

                            output.push(NodeInfo {
                                nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                route_metric_to_exit: route.metric,
                                total_payments: debt_info.total_payment_recieved.into(),
                                debt: debt_info.debt.clone().into(),
                                link_cost: route.refmetric,
                                price_to_exit: route.price,
                            })
                        } else {
                            output.push(NodeInfo {
                                nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                route_metric_to_exit: 0,
                                total_payments: debt_info.total_payment_recieved.into(),
                                debt: debt_info.debt.clone().into(),
                                link_cost: 0,
                                price_to_exit: 0,
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
        if current_exit.unwrap().general_details.is_some() {
            let internal_ip = current_exit
                .unwrap()
                .clone()
                .general_details
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
            output.push(ExitInfo {
                nickname: exit.0,
                exit_settings: exit.1.clone(),
                is_selected: is_selected(&exit.1, current_exit)?,
                have_route: babel.do_we_have_route(&exit.1.id.mesh_ip, &route_table_sample)?,
                is_reachable: KI.ping_check_v6(&exit.1.id.mesh_ip)?,
                is_tunnel_working: is_tunnel_working(&exit.1, current_exit)?,
            })
        }

        Ok(output)
    }
}
