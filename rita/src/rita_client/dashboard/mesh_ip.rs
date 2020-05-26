use crate::SETTING;
use ::actix_web::{HttpRequest, HttpResponse};
use failure::Error;
use settings::RitaCommonSettings;
use std::collections::HashMap;

pub fn get_mesh_ip(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/mesh_ip GET hit");

    let mut ret = HashMap::new();

    match SETTING.get_network().mesh_ip {
        Some(ip) => {
            ret.insert("mesh_ip".to_owned(), format!("{}", ip));
        }
        None => {
            let error_msg = "No mesh IP configured yet";
            warn!("{}", error_msg);
            ret.insert("error".to_owned(), error_msg.to_owned());
        }
    }

    Ok(HttpResponse::Ok().json(ret))
}
