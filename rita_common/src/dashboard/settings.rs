use crate::{network_endpoints::JsonStatusResponse, RitaCommonError};
use actix_web::{HttpRequest, Json, Result};

pub fn get_settings(_req: HttpRequest) -> Result<Json<serde_json::Value>, RitaCommonError> {
    debug!("Get settings endpoint hit!");
    Ok(Json(settings::get_config_json()?))
}

pub fn set_settings(
    new_settings: Json<serde_json::Value>,
) -> Result<Json<JsonStatusResponse>, RitaCommonError> {
    debug!("Set settings endpoint hit!");
    settings::merge_config_json(new_settings.into_inner())?;

    JsonStatusResponse::new(Ok("New settings applied".to_string()))
}
