use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Result};
use failure::Error;
use settings::FileWrite;
use std::collections::HashMap;

pub fn get_backup_created(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/backup_created GET hit");
    let mut ret = HashMap::new();
    ret.insert(
        "backup_created",
        settings::get_rita_client()
            .get_network()
            .backup_created
            .to_string(),
    );

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_backup_created(path: Path<bool>) -> Result<HttpResponse, Error> {
    debug!("Setting backup created");
    let value = path.into_inner();

    let mut network = settings::get_rita_client().network;
    network.backup_created = value;

    // try and save the config and fail if we can't
    let rita_client = settings::get_rita_client();
    if let Err(e) = rita_client.write(&settings::get_flag_config()) {
        return Err(e);
    } else {
        settings::set_rita_client(rita_client);
    }
    let mut rita_client = settings::get_rita_client();
    rita_client.network = network;
    settings::set_rita_client(rita_client);
    Ok(HttpResponse::Ok().json(()))
}
