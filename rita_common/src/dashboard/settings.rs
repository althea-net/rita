use actix_web::{http::StatusCode, web::Json, HttpRequest, HttpResponse};

pub async fn get_settings(_req: HttpRequest) -> HttpResponse {
    debug!("Get settings endpoint hit!");
    match settings::get_config_json() {
        Ok(a) => HttpResponse::Ok().json(a),
        Err(e) => HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("Unable to get config: {e}")),
    }
}

pub async fn set_settings(new_settings: Json<serde_json::Value>) -> HttpResponse {
    debug!("Set settings endpoint hit!");
    if let Err(e) = settings::merge_config_json(new_settings.into_inner()) {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("Unable to set settings: {e}"));
    }

    HttpResponse::Ok().finish()
}
