use crate::ARGS;
use crate::SETTING;
use ::actix_web::http::StatusCode;
use ::actix_web::Path;
use ::actix_web::{HttpRequest, HttpResponse, Result};
use ::settings::FileWrite;
use ::settings::RitaCommonSettings;
use babel_monitor::open_babel_stream;
use babel_monitor::set_local_fee as babel_set_local_fee;
use babel_monitor::set_metric_factor as babel_set_metric_factor;
use babel_monitor::start_connection;
use failure::Error;
use futures01::future::Future;
use std::collections::HashMap;

pub fn get_local_fee(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("local_fee", SETTING.get_payment().local_fee);

    Ok(HttpResponse::Ok().json(ret))
}

pub fn get_metric_factor(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("metric_factor", SETTING.get_network().metric_factor);

    Ok(HttpResponse::Ok().json(ret))
}

pub fn set_local_fee(path: Path<u32>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let new_fee = path.into_inner();
    debug!("/local_fee/{} POST hit", new_fee);
    let babel_port = SETTING.get_network().babel_port;
    let max_fee = SETTING.get_payment().max_fee;
    // prevent the user from setting a higher price than they would pay
    // themselves
    let new_fee = if new_fee > max_fee { max_fee } else { new_fee };

    Box::new(open_babel_stream(babel_port).then(move |stream| {
        // if we can't get to babel here we panic
        let stream = stream.expect("Can't reach Babel!");
        start_connection(stream).and_then(move |stream| {
            babel_set_local_fee(stream, new_fee).then(move |res| {
                if let Err(e) = res {
                    error!("Failed to set babel fee with {:?}", e);
                    Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                        .into_builder()
                        .json("Failed to set babel fee"))
                } else {
                    SETTING.get_payment_mut().local_fee = new_fee;

                    // try and save the config and fail if we can't
                    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
                        return Err(e);
                    }

                    Ok(HttpResponse::Ok().json(()))
                }
            })
        })
    }))
}

pub fn set_metric_factor(path: Path<u32>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let new_factor = path.into_inner();
    debug!("/metric_factor/{} POST hit", new_factor);
    let babel_port = SETTING.get_network().babel_port;

    Box::new(open_babel_stream(babel_port).then(move |stream| {
        // if we can't get to babel here we panic
        let stream = stream.expect("Can't reach Babel!");
        start_connection(stream).and_then(move |stream| {
            babel_set_metric_factor(stream, new_factor).then(move |res| {
                if let Err(e) = res {
                    error!("Failed to set babel metric factor with {:?}", e);
                    Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                        .into_builder()
                        .json("Failed to set babel metric factor"))
                } else {
                    SETTING.get_network_mut().metric_factor = new_factor;

                    // try and save the config and fail if we can't
                    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
                        return Err(e);
                    }

                    Ok(HttpResponse::Ok().json(()))
                }
            })
        })
    }))
}
