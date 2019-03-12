use crate::ARGS;
use crate::KI;
use crate::SETTING;
use ::actix_web::http::StatusCode;
use ::actix_web::{HttpResponse, Path};
use failure::Error;
use log::LevelFilter;
use settings::client::RitaClientSettings;
use settings::FileWrite;

pub fn remote_logging(path: Path<bool>) -> Result<HttpResponse, Error> {
    let enabled = path.into_inner();
    debug!("/loging/enable/{} hit", enabled);

    SETTING.get_log_mut().enabled = enabled;

    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Err(e);
    }

    Ok(HttpResponse::Ok().json(()))
}

pub fn remote_logging_level(path: Path<String>) -> Result<HttpResponse, Error> {
    let level = path.into_inner();
    debug!("/loging/level/{}", level);

    let log_level: LevelFilter = match level.parse() {
        Ok(level) => level,
        Err(e) => {
            return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(format!("Could not parse loglevel {:?}", e)));
        }
    };

    SETTING.get_log_mut().level = log_level.to_string();

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }

    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Err(e);
    }

    Ok(HttpResponse::Ok().json(()))
}
