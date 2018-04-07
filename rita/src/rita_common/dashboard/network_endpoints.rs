use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use std::boxed::Box;

use serde_json;

use super::{Dashboard, GetWifiConfig, NodeInfo, SetWifiConfig};

use bytes::Bytes;
use rita_common::dashboard::WifiInterface;
use rita_common::dashboard::GetNodeInfo;

pub fn get_wifi_config(
    req: HttpRequest,
) -> Box<Future<Item = Json<Vec<WifiInterface>>, Error = Error>> {
    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            Dashboard::from_registry()
                .send(GetWifiConfig {})
                .then(move |reply| Ok(Json(reply.unwrap().unwrap())))
        })
        .responder()
}

pub fn set_wifi_config(req: HttpRequest) -> Box<Future<Item = Json<()>, Error = Error>> {
    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            let new_settings: Vec<WifiInterface> = serde_json::from_slice(&bytes[..]).unwrap();

            Dashboard::from_registry()
                .send(SetWifiConfig(new_settings))
                .then(move |reply| Ok(Json(reply.unwrap().unwrap())))
        })
        .responder()
}

pub fn get_node_info(req: HttpRequest) -> Box<Future<Item = Json<Vec<NodeInfo>>, Error = Error>> {
    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            Dashboard::from_registry()
                .send(GetNodeInfo {})
                .then(move |reply| Ok(Json(reply.unwrap().unwrap())))
        })
        .responder()
}
