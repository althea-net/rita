use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use failure::Error;

use std::boxed::Box;

use super::{
    Dashboard, ExitInfo, GetExitInfo, GetNodeInfo, GetWifiConfig, NodeInfo, SetWifiConfig,
};
use rita_client::dashboard::WifiInterface;

pub fn get_wifi_config(
    _req: HttpRequest,
) -> Box<Future<Item = Json<Vec<WifiInterface>>, Error = Error>> {
    debug!("Get wificonfig hit!");
    Dashboard::from_registry()
        .send(GetWifiConfig {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_wifi_config(
    new_settings: Json<WifiInterface>,
) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("Set wificonfig endpoint hit!");
    //This will be dead code if the JS is modified to submit both interfaces
    //in one vector
    let mut new_settings_vec = Vec::new();
    new_settings_vec.push(new_settings.into_inner());

    Dashboard::from_registry()
        .send(SetWifiConfig(new_settings_vec))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_node_info(_req: HttpRequest) -> Box<Future<Item = Json<Vec<NodeInfo>>, Error = Error>> {
    debug!("Neighbors endpoint hit!");
    Dashboard::from_registry()
        .send(GetNodeInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_exit_info(_req: HttpRequest) -> Box<Future<Item = Json<Vec<ExitInfo>>, Error = Error>> {
    debug!("Exit endpoint hit!");
    Dashboard::from_registry()
        .send(GetExitInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
