use actix_web_async::{HttpRequest, HttpResponse};
use std::collections::HashMap;

pub async fn get_mesh_ip(_req: HttpRequest) -> HttpResponse {
    debug!("/mesh_ip GET hit");

    let mut ret = HashMap::new();

    match settings::get_rita_common().network.mesh_ip {
        Some(ip) => {
            ret.insert("mesh_ip".to_owned(), format!("{ip}"));
        }
        None => {
            let error_msg = "No mesh IP configured yet";
            warn!("{}", error_msg);
            ret.insert("error".to_owned(), error_msg.to_owned());
        }
    }

    HttpResponse::Ok().json(ret)
}
