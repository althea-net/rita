use ::actix_web::Path;
use ::actix_web::{HttpRequest, HttpResponse};

pub fn get_low_balance_notification(_req: HttpRequest) -> HttpResponse {
    let setting = settings::get_rita_client()
        .exit_client
        .low_balance_notification;

    HttpResponse::Ok().json(setting.to_string())
}

pub fn set_low_balance_notification(path: Path<bool>) -> HttpResponse {
    let value = path.into_inner();
    debug!("Set low balance notification hit!");

    let mut rita_client = settings::get_rita_client();
    // let mut exit_client = rita_client.exit_client;
    rita_client.exit_client.low_balance_notification = value;
    // rita_client.exit_client = exit_client;
    settings::set_rita_client(rita_client);

    if let Err(_e) = settings::write_config() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().json(())
}
