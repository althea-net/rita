use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use std::boxed::Box;

use serde_json;

use super::{Dashboard, GetStatsServerInfo, GetWifiConfig, NodeInfo, SetStatsServerInfo,
            SetWifiConfig};

use bytes::Bytes;
use rita_common::dashboard::GetNodeInfo;
use rita_common::dashboard::WifiInterface;
use settings::StatsServerSettings;

pub fn get_wifi_config(
    req: HttpRequest,
) -> Box<Future<Item = Json<Vec<WifiInterface>>, Error = Error>> {
    Dashboard::from_registry()
        .send(GetWifiConfig {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_wifi_config(
    new_settings: Json<Vec<WifiInterface>>,
) -> Box<Future<Item = Json<()>, Error = Error>> {
    Dashboard::from_registry()
        .send(SetWifiConfig(new_settings.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_node_info(req: HttpRequest) -> Box<Future<Item = Json<Vec<NodeInfo>>, Error = Error>> {
    Dashboard::from_registry()
        .send(GetNodeInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_stats_server_info(
    req: HttpRequest,
) -> Box<Future<Item = Json<Option<StatsServerSettings>>, Error = Error>> {
    Dashboard::from_registry()
        .send(GetStatsServerInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_stats_server_info(
    new_settings: Json<Option<StatsServerSettings>>,
) -> Box<Future<Item = Json<()>, Error = Error>> {
    Dashboard::from_registry()
        .send(SetStatsServerInfo(new_settings.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
