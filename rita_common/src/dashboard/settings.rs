use crate::network_endpoints::JsonStatusResponse;
use actix_web::{HttpRequest, Json, Result};
use failure::Error;

pub fn get_settings(_req: HttpRequest) -> Result<Json<serde_json::Value>, Error> {
    debug!("Get settings endpoint hit!");
    Ok(Json(settings::get_config_json()?))
}

pub fn set_settings(
    new_settings: Json<serde_json::Value>,
) -> Result<Json<JsonStatusResponse>, Error> {
    debug!("Set settings endpoint hit!");
    settings::merge_config_json(new_settings.into_inner())?;

    JsonStatusResponse::new(Ok("New settings applied".to_string()))
}
