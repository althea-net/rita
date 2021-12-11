use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Result};
use failure::Error;
use std::collections::HashMap;

pub fn get_backup_created(_req: HttpRequest) -> Result<HttpResponse, Error> {
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

pub fn set_backup_created(path: Path<bool>) -> Result<HttpResponse, Error> {
    debug!("Setting backup created");
    let value = path.into_inner();

    let mut rita_client = settings::get_rita_client();
    rita_client.network.backup_created = value;
    settings::set_rita_client(rita_client);

    if let Err(e) = settings::write_config() {
        return Err(e);
    }

    Ok(HttpResponse::Ok().json(()))
}
