use crate::ARGS;
use crate::KI;
use crate::SETTING;
use ::actix_web::{HttpRequest, HttpResponse, Json};
use failure::Error;
use settings::FileWrite;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::net::Ipv6Addr;

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

pub fn set_mesh_ip(mesh_ip_data: Json<HashMap<String, String>>) -> Result<HttpResponse, Error> {
    debug!("/mesh_ip POST hit");

    let mut ret = HashMap::new();

    match mesh_ip_data.into_inner().get("mesh_ip") {
        Some(ip_str) => match ip_str.parse::<Ipv6Addr>() {
            Ok(parsed) => {
                if !parsed.is_unspecified() {
                    SETTING.get_network_mut().mesh_ip = Some(parsed);
                } else {
                    let error_msg = format!(
                    "set_mesh_ip: Attempted to set a non-IPv6 or unsepcified address {} as mesh_ip",
                    parsed
                );
                    info!("{}", error_msg);
                    ret.insert("error".to_owned(), error_msg);
                }
            }
            Err(e) => {
                let error_msg = format!(
                    "set_mesh_ip: Failed to parse the address string {:?}",
                    ip_str
                );
                info!("{}", error_msg);
                ret.insert("error".to_owned(), error_msg);
                ret.insert("rust_error".to_owned(), e.to_string());
            }
        },
        None => {
            let error_msg = "set_mesh_ip: \"mesh_ip\" not found in supplied JSON";
            info!("{}", error_msg);
            ret.insert("error".to_owned(), error_msg.to_string());
        }
    }

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    // it's now safe to restart the process, return an error if that fails somehow
    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Err(e);
    }

    // Note: This will never be reached
    Ok(HttpResponse::Ok().json(ret))
}
