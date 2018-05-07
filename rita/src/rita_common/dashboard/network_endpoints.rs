use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use std::boxed::Box;

use serde_json;

use SETTING;

use super::{Dashboard, GetOwnInfo, GetWifiConfig, NodeInfo, OwnInfo, SetWifiConfig};

use rita_common::dashboard::{GetNodeInfo, WifiInterface};
use settings::{RitaCommonSettings, StatsServerSettings};

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

pub fn get_own_info(req: HttpRequest) -> Box<Future<Item = Json<OwnInfo>, Error = Error>> {
    Dashboard::from_registry()
        .send(GetOwnInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_settings(req: HttpRequest) -> Result<Json<serde_json::Value>, Error> {
    Ok(Json(SETTING.get_all()?))
}

pub fn set_settings(new_settings: Json<serde_json::Value>) -> Result<String, Error> {
    SETTING.merge(new_settings.into_inner())?;
    Ok("New settings applied".to_string())
}
