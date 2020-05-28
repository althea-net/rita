use crate::ARGS;
use crate::SETTING;
use ::actix_web::Path;
use ::actix_web::{HttpRequest, HttpResponse};
use settings::client::RitaClientSettings;
use settings::FileWrite;

pub fn get_low_balance_notification(_req: HttpRequest) -> HttpResponse {
    let setting = SETTING.get_exit_client().low_balance_notification;

    HttpResponse::Ok().json(setting.to_string())
}

pub fn set_low_balance_notification(path: Path<bool>) -> HttpResponse {
    let value = path.into_inner();
    debug!("Set low balance notification hit!");
    SETTING.get_exit_client_mut().low_balance_notification = value;

    // try and save the config and fail if we can't
    if let Err(_e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(())
}
