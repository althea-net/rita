use crate::SETTING;
use actix_web::{HttpRequest, HttpResponse, Result};
use failure::Error;
use settings::RitaCommonSettings;

pub fn get_localization(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/localization GET hit");
    let localization = SETTING.get_localization().clone();
    Ok(HttpResponse::Ok().json(localization))
}
