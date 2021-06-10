use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Path};
use failure::Error;
use log::LevelFilter;
use rita_common::KI;
use settings::FileWrite;

pub fn get_remote_logging(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(settings::get_rita_client().log.enabled))
}

pub fn remote_logging(path: Path<bool>) -> Result<HttpResponse, Error> {
    let enabled = path.into_inner();
    debug!("/remote_logging/enable/{} hit", enabled);

    // try and save the config and fail if we can't
    let mut rita_client = settings::get_rita_client();

    let mut log = settings::get_rita_client().log;
    log.enabled = enabled;
    rita_client.log = log;
    settings::set_rita_client(rita_client);

    if let Err(e) = settings::get_rita_client().write(&settings::get_flag_config()) {
        return Err(e);
    }
    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Err(e.into());
    }

    Ok(HttpResponse::Ok().json(()))
}

pub fn get_remote_logging_level(_req: HttpRequest) -> Result<HttpResponse, Error> {
    let rita_client = settings::get_rita_client();
    let level = &rita_client.log.level;
    Ok(HttpResponse::Ok().json(level))
}

pub fn remote_logging_level(path: Path<String>) -> Result<HttpResponse, Error> {
    let level = path.into_inner();
    debug!("/remote_logging/level/{}", level);

    let log_level: LevelFilter = match level.parse() {
        Ok(level) => level,
        Err(e) => {
            return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(format!("Could not parse loglevel {:?}", e)));
        }
    };

    let mut log = settings::get_rita_client().log;
    log.level = log_level.to_string();
    let mut rita_client = settings::get_rita_client();
    rita_client.log = log;
    settings::set_rita_client(rita_client);

    // try and save the config and fail if we can't
    let rita_client = settings::get_rita_client();
    if let Err(_e) = rita_client.write(&settings::get_flag_config()) {
        return Err(_e);
    }

    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Err(e.into());
    }

    Ok(HttpResponse::Ok().json(()))
}
