use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use std::boxed::Box;

use serde_json;

use settings::RitaCommonSettings;
use SETTING;

use super::{Dashboard, GetOwnInfo, NodeInfo, OwnInfo};

use rita_common::dashboard::GetNodeInfo;

pub fn get_node_info(_req: HttpRequest) -> Box<Future<Item = Json<Vec<NodeInfo>>, Error = Error>> {
    Dashboard::from_registry()
        .send(GetNodeInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_own_info(_req: HttpRequest) -> Box<Future<Item = Json<OwnInfo>, Error = Error>> {
    Dashboard::from_registry()
        .send(GetOwnInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_settings(_req: HttpRequest) -> Result<Json<serde_json::Value>, Error> {
    Ok(Json(SETTING.get_all()?))
}

pub fn set_settings(new_settings: Json<serde_json::Value>) -> Result<String, Error> {
    SETTING.merge(new_settings.into_inner())?;
    Ok("New settings applied".to_string())
}
