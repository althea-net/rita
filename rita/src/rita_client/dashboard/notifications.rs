use crate::ARGS;
use crate::SETTING;
use ::actix_web::Path;
use ::actix_web::{HttpRequest, HttpResponse};
use failure::Error;
use settings::client::RitaClientSettings;
use settings::FileWrite;

pub fn get_low_balance_notification(_req: HttpRequest) -> Result<HttpResponse, Error> {
    let setting = SETTING.get_exit_client().low_balance_notification;

    Ok(HttpResponse::Ok().json(setting.to_string()))
}

pub fn set_low_balance_notification(path: Path<bool>) -> Result<HttpResponse, Error> {
    let value = path.into_inner();
    debug!("Set low balance notification hit!");
    SETTING.get_exit_client_mut().low_balance_notification = value;

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        error!("error saving config {:?}", e);
        return Err(e);
    }
    Ok(HttpResponse::Ok().json(()))
}
