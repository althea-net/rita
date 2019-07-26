use crate::SETTING;
use actix_web::{HttpRequest, HttpResponse, Result};
use failure::Error;
use settings::RitaCommonSettings;

pub fn get_wg_public_key(_req: HttpRequest) -> Result<HttpResponse, Error> {
    let wg_public_key = SETTING.get_network().wg_public_key;

    if wg_public_key.is_none() {
        bail!("wg_public_key not set!")
    } else {
        Ok(HttpResponse::Ok().json(wg_public_key.unwrap().to_string()))
    }
}
