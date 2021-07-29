use actix_web::http::StatusCode;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Result};
use babel_monitor_legacy::open_babel_stream_legacy;
use babel_monitor_legacy::set_local_fee_legacy as babel_set_local_fee_legacy;
use babel_monitor_legacy::set_metric_factor_legacy as babel_set_metric_factor_legacy;
use babel_monitor_legacy::start_connection_legacy;
use failure::Error;
use futures01::future::Future;
use std::collections::HashMap;

pub fn get_local_fee(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("local_fee", settings::get_rita_common().payment.local_fee);

    Ok(HttpResponse::Ok().json(ret))
}

pub fn get_metric_factor(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert(
        "metric_factor",
        settings::get_rita_common().network.metric_factor,
    );

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_local_fee(path: Path<u32>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let new_fee = path.into_inner();
    debug!("/local_fee/{} POST hit", new_fee);
    let babel_port = settings::get_rita_common().network.babel_port;
    let max_fee = settings::get_rita_common().payment.max_fee;
    // prevent the user from setting a higher price than they would pay
    // themselves
    let new_fee = if new_fee > max_fee { max_fee } else { new_fee };

    Box::new(open_babel_stream_legacy(babel_port).then(move |stream| {
        // if we can't get to babel here we panic
        let stream = stream.expect("Can't reach Babel!");
        start_connection_legacy(stream).and_then(move |stream| {
            babel_set_local_fee_legacy(stream, new_fee).then(move |res| {
                if let Err(e) = res {
                    error!("Failed to set babel fee with {:?}", e);
                    Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                        .into_builder()
                        .json("Failed to set babel fee"))
                } else {
                    let mut common = settings::get_rita_common();
                    common.payment.local_fee = new_fee;
                    settings::set_rita_common(common);

                    // try and save the config and fail if we can't
                    if let Err(e) = settings::write_config() {
                        return Err(e);
                    }
                    Ok(HttpResponse::Ok().json(()))
                }
            })
        })
    }))
}

/// Sets the metric factor for this node, lower values mean a higher price preference while higher
/// values mean a higher weight on route quality.
pub fn set_metric_factor(path: Path<u32>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let new_factor = path.into_inner();
    debug!("/metric_factor/{} POST hit", new_factor);
    let babel_port = settings::get_rita_common().network.babel_port;

    Box::new(open_babel_stream_legacy(babel_port).then(move |stream| {
        // if we can't get to babel here we panic
        let stream = stream.expect("Can't reach Babel!");
        start_connection_legacy(stream).and_then(move |stream| {
            babel_set_metric_factor_legacy(stream, new_factor).then(move |res| {
                if let Err(e) = res {
                    error!("Failed to set babel metric factor with {:?}", e);
                    Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                        .into_builder()
                        .json("Failed to set babel metric factor"))
                } else {
                    let mut common = settings::get_rita_common();
                    common.network.metric_factor = new_factor;
                    settings::set_rita_common(common);

                    // try and save the config and fail if we can't
                    if let Err(e) = settings::write_config() {
                        return Err(e);
                    }

                    Ok(HttpResponse::Ok().json(()))
                }
            })
        })
    }))
}
