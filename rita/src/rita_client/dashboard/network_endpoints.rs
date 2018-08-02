use actix::registry::SystemService;
use actix_web::{AsyncResponder, HttpRequest, Json};
use failure::Error;
use futures::Future;

use rita_client::dashboard::WifiInterface;

use super::*;

use std::boxed::Box;

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

pub fn reset_exit(name: Path<String>) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("/exits/{}/reset hit", name);

    Dashboard::from_registry()
        .send(ResetExit(name.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn select_exit(name: Path<String>) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("/exits/{}/select hit", name);

    Dashboard::from_registry()
        .send(SelectExit(name.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_wifi_ssid(wifi_ssid: Json<WifiSSID>) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("/wifi_settings/ssid hit with {:?}", wifi_ssid);

    Dashboard::from_registry()
        .send(SetWiFiSSID(wifi_ssid.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_wifi_pass(wifi_pass: Json<WifiPass>) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("/wifi_settings/pass hit with {:?}", wifi_pass);

    Dashboard::from_registry()
        .send(SetWiFiPass(wifi_pass.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_wifi_mesh(wifi_mesh: Json<WifiMesh>) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("/wifi_settings/mesh hit with {:?}", wifi_mesh);

    Dashboard::from_registry()
        .send(SetWiFiMesh(wifi_mesh.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
