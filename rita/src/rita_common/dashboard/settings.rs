use crate::rita_common::network_endpoints::JsonStatusResponse;
use crate::SETTING;
use ::actix_web::{HttpRequest, Json, Result};
use ::settings::RitaCommonSettings;
use failure::Error;
use serde_json;

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
