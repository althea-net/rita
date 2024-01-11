use actix_web_async::http::StatusCode;
use actix_web_async::web::Path;
use actix_web_async::{HttpRequest, HttpResponse};
use babel_monitor::open_babel_stream;
use babel_monitor::set_local_fee as babel_set_local_fee;
use babel_monitor::set_metric_factor as babel_set_metric_factor;
use std::collections::HashMap;
use std::time::Duration;

pub async fn get_local_fee(_req: HttpRequest) -> HttpResponse {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("local_fee", settings::get_rita_common().payment.local_fee);

    HttpResponse::Ok().json(ret)
}

pub async fn get_metric_factor(_req: HttpRequest) -> HttpResponse {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert(
        "metric_factor",
        settings::get_rita_common().network.metric_factor,
    );

    HttpResponse::Ok().json(ret)
}

pub async fn set_local_fee(path: Path<u32>) -> HttpResponse {
    let new_fee = path.into_inner();
    debug!("/local_fee/{} POST hit", new_fee);
    let babel_port = settings::get_rita_common().network.babel_port;
    let max_fee = settings::get_rita_common().payment.max_fee;
    // prevent the user from setting a higher price than they would pay
    // themselves
    let new_fee = if new_fee > max_fee { max_fee } else { new_fee };

    match open_babel_stream(babel_port, Duration::from_secs(5)) {
        Ok(mut stream) => {
            match babel_set_local_fee(&mut stream, new_fee) {
                Ok(_) => {
                    let mut common = settings::get_rita_common();
                    common.network.babeld_settings.local_fee = new_fee;
                    settings::set_rita_common(common);
                    // try and save the config and fail if we can't
                    if let Err(e) = settings::write_config() {
                        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                            .json(format!("{e:?}"));
                    }
                    HttpResponse::Ok().json(())
                }
                Err(e) => {
                    error!("Failed to set babel fee with {:?}", e);
                    HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                        .json("Failed to set babel fee")
                }
            }
        }
        Err(e) => {
            error!("Failed to open babel stream {:?}", e);
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .json("Failed to open babel stream to set fee")
        }
    }
}

/// Sets the metric factor for this node, lower values mean a higher price preference while higher
/// values mean a higher weight on route quality.
pub async fn set_metric_factor(path: Path<u32>) -> HttpResponse {
    let new_factor = path.into_inner();
    debug!("/metric_factor/{} POST hit", new_factor);
    let babel_port = settings::get_rita_common().network.babel_port;

    match open_babel_stream(babel_port, Duration::from_secs(5)) {
        Ok(mut stream) => {
            match babel_set_metric_factor(&mut stream, new_factor) {
                Ok(_) => {
                    let mut common = settings::get_rita_common();
                    common.network.babeld_settings.metric_factor = new_factor;
                    settings::set_rita_common(common);

                    // try and save the config and fail if we can't
                    if let Err(e) = settings::write_config() {
                        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                            .json(format!("{e}"));
                    }

                    HttpResponse::Ok().json(())
                }
                Err(e) => {
                    error!("Failed to set babel metric factor with {:?}", e);
                    HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                        .json("Failed to set babel metric factor")
                }
            }
        }
        Err(e) => {
            error!("Failed to open babel stream {:?}", e);
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                .json("Failed to open babel stream to set metric factor")
        }
    }
}
