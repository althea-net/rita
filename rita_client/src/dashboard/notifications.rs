use ::actix_web::Path;
use ::actix_web::{HttpRequest, HttpResponse};
use settings::FileWrite;

pub fn get_low_balance_notification(_req: HttpRequest) -> HttpResponse {
    let setting = settings::get_rita_client()
        .exit_client
        .low_balance_notification;

    HttpResponse::Ok().json(setting.to_string())
}

pub fn set_low_balance_notification(path: Path<bool>) -> HttpResponse {
    let value = path.into_inner();
    debug!("Set low balance notification hit!");

    let mut exit_client = settings::get_rita_client().exit_client;
    exit_client.low_balance_notification = value;
    let mut rita_client = settings::get_rita_client();
    rita_client.exit_client = exit_client;
    settings::set_rita_client(rita_client);

    // try and save the config and fail if we can't
    if let Err(_e) = settings::get_rita_client().write(&settings::get_flag_config()) {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().json(())
}
