use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};

use crate::RitaCommonError;

pub async fn get_wg_public_key(_req: HttpRequest) -> HttpResponse {
    let wg_public_key = settings::get_rita_common().network.wg_public_key;

    if let Some(wg_public_key) = wg_public_key {
        HttpResponse::Ok().json(wg_public_key.to_string())
    } else {
        HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!(
            "{:?}",
            RitaCommonError::MiscStringError("wg_public_key not set!".to_string())
        ))
    }
}
