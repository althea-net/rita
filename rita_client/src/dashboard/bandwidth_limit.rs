//! Beta 16 introduces a feature where users can select their own self imposed router bandwidth limit
//! these dashboard endpoints facilitate users setting that value.

use actix_web::HttpResponse;
use actix_web::{HttpRequest, Path};
use failure::Error;
use rita_common::KI;
use settings::FileWrite;

pub fn get_bandwidth_limit(_req: HttpRequest) -> HttpResponse {
    let val = settings::get_rita_client()
        .get_network()
        .user_bandwidth_limit;
    HttpResponse::Ok().json(val)
}

pub fn set_bandwidth_limit(path: Path<String>) -> Result<HttpResponse, Error> {
    let value = path.into_inner();
    debug!("Set bandwidth limit!");
    let mut rita_client = settings::get_rita_client();
    let mut network = rita_client.network;
    if value.is_empty() || value == "disable" {
        network.user_bandwidth_limit = None;
    } else if let Ok(parsed) = value.parse() {
        network.user_bandwidth_limit = Some(parsed);
    } else {
        return Ok(HttpResponse::BadRequest().finish());
    }
    let _res = KI.set_codel_shaping("wg_exit", network.user_bandwidth_limit, true);
    let _res = KI.set_codel_shaping("br-lan", network.user_bandwidth_limit, false);
    rita_client.network = network;
    settings::set_rita_client(rita_client);

    // try and save the config and fail if we can't
    let rita_client = settings::get_rita_client();
    if let Err(e) = rita_client.write(&settings::get_flag_config()) {
        return Err(e);
    } else {
        settings::set_rita_client(rita_client);
    }
    Ok(HttpResponse::Ok().json(()))
}
