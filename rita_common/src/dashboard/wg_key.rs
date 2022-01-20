use actix_web::{HttpRequest, HttpResponse, Result};

use crate::RitaCommonError;

pub fn get_wg_public_key(_req: HttpRequest) -> Result<HttpResponse, RitaCommonError> {
    let wg_public_key = settings::get_rita_common().network.wg_public_key;

    if let Some(wg_public_key) = wg_public_key {
        Ok(HttpResponse::Ok().json(wg_public_key.to_string()))
    } else {
        Err(RitaCommonError::MiscStringError(
            "wg_public_key not set!".to_string(),
        ))
    }
}
