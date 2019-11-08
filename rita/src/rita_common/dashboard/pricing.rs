use crate::ARGS;
use crate::SETTING;
use ::actix_web::Path;
use ::actix_web::{HttpRequest, HttpResponse, Json, Result};
use ::settings::FileWrite;
use ::settings::RitaCommonSettings;
use failure::Error;

pub fn auto_pricing_status(_req: HttpRequest) -> Result<Json<bool>, Error> {
    debug!("Get Auto pricing enabled hit!");
    Ok(Json(SETTING.get_dao().use_oracle_price))
}

pub fn set_auto_pricing(path: Path<bool>) -> Result<HttpResponse, Error> {
    let value = path.into_inner();
    debug!("Set Auto pricing enabled hit!");
    SETTING.get_dao_mut().use_oracle_price = value;

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(HttpResponse::Ok().json(()))
}
