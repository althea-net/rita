use actix_web_async::{http::StatusCode, web::Path, HttpRequest, HttpResponse};
use rita_common::RitaCommonError;
use std::collections::HashMap;

pub fn get_backup_created(_req: HttpRequest) -> HttpResponse {
    debug!("/backup_created GET hit");
    let mut ret = HashMap::new();
    ret.insert(
        "backup_created",
        settings::get_rita_client()
            .network
            .backup_created
            .to_string(),
    );

    HttpResponse::Ok().json(ret)
}

pub fn set_backup_created(path: Path<bool>) -> HttpResponse {
    debug!("Setting backup created");
    let value = path.into_inner();

    let mut rita_client = settings::get_rita_client();
    rita_client.network.backup_created = value;
    settings::set_rita_client(rita_client);

    if let Err(e) = settings::write_config() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("{:?}", RitaCommonError::SettingsError(e)));
    }

    HttpResponse::Ok().json(())
}
