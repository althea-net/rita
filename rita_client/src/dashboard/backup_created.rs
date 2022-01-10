use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Result};
use std::collections::HashMap;

use crate::RitaClientError;

pub fn get_backup_created(_req: HttpRequest) -> Result<HttpResponse, RitaClientError> {
    debug!("/backup_created GET hit");
    let mut ret = HashMap::new();
    ret.insert(
        "backup_created",
        settings::get_rita_client()
            .network
            .backup_created
            .to_string(),
    );

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_backup_created(path: Path<bool>) -> Result<HttpResponse, RitaClientError> {
    debug!("Setting backup created");
    let value = path.into_inner();

    let mut rita_client = settings::get_rita_client();
    rita_client.network.backup_created = value;
    settings::set_rita_client(rita_client);

    if let Err(e) = settings::write_config() {
        return Err(RitaClientError::SettingsError(e));
    }

    Ok(HttpResponse::Ok().json(()))
}
