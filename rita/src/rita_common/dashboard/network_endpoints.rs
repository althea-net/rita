use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use std::boxed::Box;

use failure::Error;

use serde_json;

use settings::RitaCommonSettings;
use SETTING;

use super::{Dashboard, GetOwnInfo, OwnInfo};

use rita_common::network_endpoints::JsonStatusResponse;

pub fn get_own_info(_req: HttpRequest) -> Box<Future<Item = Json<OwnInfo>, Error = Error>> {
    debug!("Get own info endpoint hit!");
    Dashboard::from_registry()
        .send(GetOwnInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_settings(_req: HttpRequest) -> Result<Json<serde_json::Value>, Error> {
    debug!("Get settings endpoint hit!");
    Ok(Json(SETTING.get_all()?))
}

pub fn set_settings(
    new_settings: Json<serde_json::Value>,
) -> Result<Json<JsonStatusResponse>, Error> {
    debug!("Set settings endpoint hit!");
    SETTING.merge(new_settings.into_inner())?;

    JsonStatusResponse::new(Ok("New settings applied".to_string()))
}
