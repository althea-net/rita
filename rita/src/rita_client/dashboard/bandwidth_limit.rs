//! Beta 16 introduces a feature where users can select their own self imposed router bandwidth limit
//! these dashboard endpoints facilitate users setting that value.

use crate::ARGS;
use crate::KI;
use crate::SETTING;
use actix_web::HttpResponse;
use actix_web::{HttpRequest, Path};
use failure::Error;
use settings::FileWrite;
use settings::RitaCommonSettings;

pub fn get_bandwidth_limit(_req: HttpRequest) -> HttpResponse {
    let val = SETTING.get_network().user_bandwidth_limit;
    HttpResponse::Ok().json(val)
}

pub fn set_bandwidth_limit(path: Path<String>) -> Result<HttpResponse, Error> {
    let value = path.into_inner();
    debug!("Set bandwidth limit!");
    let mut net = SETTING.get_network_mut();
    if value.is_empty() || value == "disable" {
        net.user_bandwidth_limit = None;
    } else if let Ok(parsed) = value.parse() {
        net.user_bandwidth_limit = Some(parsed);
    } else {
        return Ok(HttpResponse::BadRequest().finish());
    }
    let _res = KI.set_codel_shaping("wg_exit", net.user_bandwidth_limit, true);
    let _res = KI.set_codel_shaping("br-lan", net.user_bandwidth_limit, false);
    drop(net);

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(HttpResponse::Ok().json(()))
}
