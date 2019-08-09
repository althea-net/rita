use crate::ARGS;
use crate::SETTING;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Result};
use failure::Error;
use settings::FileWrite;
use settings::RitaCommonSettings;
use std::collections::HashMap;

pub fn get_backup_created(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/backup_created GET hit");
    let mut ret = HashMap::new();
    ret.insert(
        "backup_created",
        SETTING.get_network().backup_created.to_string(),
    );

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_backup_created(path: Path<bool>) -> Result<HttpResponse, Error> {
    debug!("Setting backup created");
    let value = path.into_inner();
    SETTING.get_network_mut().backup_created = value;

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(HttpResponse::Ok().json(()))
}
