use crate::RitaCommonError;
use actix_web::{HttpRequest, HttpResponse, Json, Result};

pub fn get_settings(_req: HttpRequest) -> Result<Json<serde_json::Value>, RitaCommonError> {
    debug!("Get settings endpoint hit!");
    Ok(Json(settings::get_config_json()?))
}

pub fn set_settings(
    new_settings: Json<serde_json::Value>,
) -> Result<HttpResponse, RitaCommonError> {
    debug!("Set settings endpoint hit!");
    settings::merge_config_json(new_settings.into_inner())?;

    Ok(HttpResponse::Ok().finish())
}
