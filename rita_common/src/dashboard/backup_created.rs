use actix_web_async::{http::StatusCode, web::Path, HttpRequest, HttpResponse};
use crate::RitaCommonError;
use std::collections::HashMap;

pub async fn get_backup_created(_req: HttpRequest) -> HttpResponse {
    debug!("/backup_created GET hit");
    let mut ret = HashMap::new();
    ret.insert(
        "backup_created",
        settings::get_rita_common()
            .network
            .backup_created
            .to_string(),
    );

    HttpResponse::Ok().json(ret)
}

pub async fn set_backup_created(path: Path<bool>) -> HttpResponse {
    debug!("Setting backup created");
    let value = path.into_inner();

    let mut settings = settings::get_rita_common();
    settings.network.backup_created = value;
    settings::set_rita_common(settings);

    if let Err(e) = settings::write_config() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("{:?}", RitaCommonError::SettingsError(e)));
    }

    HttpResponse::Ok().json(())
}
