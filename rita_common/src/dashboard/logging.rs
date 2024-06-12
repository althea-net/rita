use crate::KI;
use actix_web_async::http::StatusCode;
use actix_web_async::{web::Path, HttpRequest, HttpResponse};
use log::LevelFilter;

pub async fn get_remote_logging(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(settings::get_rita_common().log.enabled)
}

pub async fn remote_logging(path: Path<bool>) -> HttpResponse {
    let enabled = path.into_inner();
    debug!("/remote_logging/enable/{} hit", enabled);

    // try and save the config and fail if we can't
    let mut settings = settings::get_rita_common();

    settings.log.enabled = enabled;

    let service_path: String = format!("/etc/init.d/{}", settings.get_app_name());

    settings::set_rita_common(settings);

    if let Err(e) = settings::write_config() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("Failed to write config {e:?}"));
    }

    if KI.is_openwrt() {
        if let Err(e) = KI.run_command(service_path.as_str(), &["restart"]) {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .json(format!("Failed to restart service {e:?}"));
        }
    }

    HttpResponse::Ok().json(())
}

pub async fn get_remote_logging_level(_req: HttpRequest) -> HttpResponse {
    let rita_client = settings::get_rita_client();
    let level = &rita_client.log.level;
    HttpResponse::Ok().json(level)
}

pub async fn remote_logging_level(path: Path<String>) -> HttpResponse {
    let level = path.into_inner();
    debug!("/remote_logging/level/{}", level);

    let log_level: LevelFilter = match level.parse() {
        Ok(level) => level,
        Err(e) => {
            return HttpResponse::build(StatusCode::BAD_REQUEST)
                .json(format!("Could not parse loglevel {e:?}"));
        }
    };

    let mut settings = settings::get_rita_common();

    settings.log.level = log_level.to_string();

    let service_path: String = format!("/etc/init.d/{}", settings.get_app_name());

    settings::set_rita_common(settings);

    if let Err(e) = settings::write_config() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("Failed to write config {e:?}"));
    }

    if let Err(e) = KI.run_command(service_path.as_str(), &["restart"]) {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("Failed to restart service {e:?}"));
    }

    HttpResponse::Ok().json(())
}
