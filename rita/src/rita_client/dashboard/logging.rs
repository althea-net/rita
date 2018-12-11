use super::*;

pub fn remote_logging(path: Path<bool>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let enabled = path.into_inner();
    debug!("/loging/enable/{} hit", enabled);

    SETTING.get_log_mut().enabled = enabled;

    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Box::new(future::err(e));
    }

    return Box::new(future::ok(HttpResponse::Ok().json(())));
}

pub fn remote_logging_level(
    path: Path<String>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let level = path.into_inner();
    debug!("/loging/level/{}", level);

    let log_level: LevelFilter = match level.parse() {
        Ok(level) => level,
        Err(e) => {
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::BAD_REQUEST)
                    .into_builder()
                    .json(format!("Could not parse loglevel {:?}", e)),
            ))
        }
    };

    SETTING.get_log_mut().level = log_level.to_string();

    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Box::new(future::err(e));
    }

    return Box::new(future::ok(HttpResponse::Ok().json(())));
}
