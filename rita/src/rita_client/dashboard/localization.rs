use crate::SETTING;
use actix_web::{HttpRequest, HttpResponse, Result};
use failure::Error;
use settings::RitaCommonSettings;
use std::collections::HashMap;

pub fn get_localization(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/localization GET hit");
    let mut ret = HashMap::new();
    let localization = SETTING.get_localization();
    ret.insert("wyre_enabled", localization.wyre_enabled);

    Ok(HttpResponse::Ok().json(ret))
}
