use actix::prelude::*;
use actix_web::http::StatusCode;
use actix_web::Path;
use actix_web::{AsyncResponder, HttpRequest, HttpResponse, Json};
use failure::Error;
use futures::future;
use futures::Future;
use log::LevelFilter;
use reqwest;

use althea_types::ExitState;
use rita_client::dashboard::exitinfo::{ExitInfo, GetExitInfo};
use rita_client::dashboard::interfaces::{GetInterfaces, InterfaceMode, InterfaceToSet};
use rita_client::dashboard::nodeinfo::{GetNodeInfo, NodeInfo};
use rita_client::dashboard::wifi::{GetWifiConfig, WifiInterface, WifiPass, WifiSSID};
use rita_client::exit_manager::exit_setup_request;
use rita_common::dashboard::Dashboard;
use settings::{ExitServer, RitaClientSettings, RitaCommonSettings};
use KI;
use SETTING;

use std::boxed::Box;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// A string of characters which we don't let users use because of corrupted UCI configs
static FORBIDDEN_CHARS: &'static str = "'/\"\\";

static MINIMUM_PASS_CHARS: usize = 8;

/// A helper error type for displaying UCI config value validation problems human-readably.
#[derive(Debug, Fail)]
pub enum ValidationError {
    #[fail(display = "Illegal character {} at position {}", c, pos)]
    IllegalCharacter { pos: usize, c: char },
    #[fail(display = "Empty value")]
    Empty,
    #[fail(display = "Value too short ({} required)", _0)]
    TooShort(usize),
}

pub fn get_node_info(_req: HttpRequest) -> Box<Future<Item = Json<Vec<NodeInfo>>, Error = Error>> {
    debug!("Neighbors endpoint hit!");
    Dashboard::from_registry()
        .send(GetNodeInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_exit_info(_req: HttpRequest) -> Box<Future<Item = Json<Vec<ExitInfo>>, Error = Error>> {
    debug!("Exit endpoint hit!");
    Dashboard::from_registry()
        .send(GetExitInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn reset_exit(path: Path<String>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/reset hit", exit_name);

    let mut exits = SETTING.get_exits_mut();
    let mut ret = HashMap::new();

    if let Some(exit) = exits.get_mut(&exit_name) {
        info!("Changing exit {:?} state to New", exit_name);
        exit.info = ExitState::New;
        return Box::new(future::ok(HttpResponse::Ok().json(ret)));
    } else {
        error!("Requested a reset on unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested reset on unknown exit {:?}", exit_name),
        );
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }
}

pub fn select_exit(path: Path<String>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/select hit", exit_name);

    let mut exit_client = SETTING.get_exit_client_mut();
    let mut ret = HashMap::new();

    if exit_client.exits.contains_key(&exit_name) {
        info!("Selecting exit {:?}", exit_name);
        exit_client.current_exit = Some(exit_name);
        Box::new(future::ok(HttpResponse::Ok().json(ret)))
    } else {
        error!("Requested selection of an unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested selection of an unknown exit {:?}", exit_name),
        );
        Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ))
    }
}

pub fn register_to_exit(path: Path<String>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/register hit", exit_name);

    debug!("Attempting to register on exit {:?}", exit_name);

    Box::new(exit_setup_request(exit_name, None).then(|res| {
        let mut ret = HashMap::new();
        match res {
            Ok(_) => future::ok(HttpResponse::Ok().json(ret)),
            Err(e) => {
                error!("exit_setup_request() failed with: {:?}", e);
                ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
                ret.insert("rust_error".to_owned(), format!("{:?}", e));
                future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                )
            }
        }
    }))
}

pub fn verify_on_exit_with_code(
    path: Path<(String, String)>,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let (exit_name, code) = path.into_inner();
    debug!("/exits/{}/verify/{} hit", exit_name, code);

    Box::new(exit_setup_request(exit_name, Some(code)).then(|res| {
        let mut ret = HashMap::new();
        match res {
            Ok(_) => future::ok(HttpResponse::Ok().json(ret)),
            Err(e) => {
                error!("exit_setup_request() failed with: {:?}", e);
                ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
                ret.insert("rust_error".to_owned(), format!("{:?}", e));
                future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                )
            }
        }
    }))
}

pub fn set_wifi_ssid(wifi_ssid: Json<WifiSSID>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    debug!("/wifi_settings/ssid hit with {:?}", wifi_ssid);

    let wifi_ssid = wifi_ssid.into_inner();
    let mut ret: HashMap<String, String> = HashMap::new();

    if let Err(e) = validate_config_value(&wifi_ssid.ssid) {
        info!("Setting of invalid SSID was requested: {}", e);
        ret.insert("error".to_owned(), format!("{}", e));
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }

    Box::new(
        Dashboard::from_registry()
            .send(wifi_ssid)
            .from_err()
            .and_then(move |_reply| future::ok(HttpResponse::Ok().json(ret))),
    )
}

pub fn set_wifi_pass(wifi_pass: Json<WifiPass>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    debug!("/wifi_settings/pass hit with {:?}", wifi_pass);

    let wifi_pass = wifi_pass.into_inner();
    let mut ret: HashMap<String, String> = HashMap::new();

    let wifi_pass_len = wifi_pass.pass.len();
    if wifi_pass_len < MINIMUM_PASS_CHARS {
        ret.insert(
            "error".to_owned(),
            format!("{}", ValidationError::TooShort(MINIMUM_PASS_CHARS)),
        );
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }

    if let Err(e) = validate_config_value(&wifi_pass.pass) {
        info!("Setting of invalid SSID was requested: {}", e);
        ret.insert("error".to_owned(), format!("{}", e));
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }

    Box::new(
        Dashboard::from_registry()
            .send(wifi_pass)
            .from_err()
            .and_then(move |_reply| future::ok(HttpResponse::Ok().json(ret))),
    )
}

pub fn get_interfaces(
    _req: HttpRequest,
) -> Box<Future<Item = Json<HashMap<String, InterfaceMode>>, Error = Error>> {
    debug!("get /interfaces hit");
    Dashboard::from_registry()
        .send(GetInterfaces)
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_interfaces(
    interface: Json<InterfaceToSet>,
) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("set /interfaces hit");
    let to_set = interface.into_inner();
    Dashboard::from_registry()
        .send(to_set)
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_mesh_ip(_req: HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
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

    Box::new(future::ok(HttpResponse::Ok().json(ret)))
}

pub fn set_mesh_ip(
    mesh_ip_data: Json<HashMap<String, String>>,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    debug!("/mesh_ip POST hit");

    let mut ret = HashMap::new();

    match mesh_ip_data.into_inner().get("mesh_ip") {
        Some(ip_str) => match ip_str.parse::<IpAddr>() {
            Ok(parsed) => {
                if parsed.is_ipv6() && !parsed.is_unspecified() {
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
            let error_msg = "set_mesh_ip: \"mesh_ip\" not found in supplied JSON".to_string();
            info!("{}", error_msg);
            ret.insert("error".to_owned(), error_msg);
        }
    }

    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Box::new(future::err(e));
    }

    // Note: This will never be reached
    Box::new(future::ok(HttpResponse::Ok().json(ret)))
}

/// This function checks that a supplied string is non-empty and doesn't contain any of the
/// `FORBIDDEN_CHARS`. If everything's alright the string itself is moved and returned for
/// convenience.
fn validate_config_value(s: &str) -> Result<(), ValidationError> {
    if s.is_empty() {
        return Err(ValidationError::Empty);
    }

    if let Some(pos) = s.find(|c| FORBIDDEN_CHARS.contains(c)) {
        trace!(
            "validate_config_value: Invalid character detected on position {}",
            pos
        );
        Err(ValidationError::IllegalCharacter {
            pos: pos + 1,                   // 1-indexed for human-readable display
            c: s.chars().nth(pos).unwrap(), // pos obtained from find(), must be correct
        })
    } else {
        Ok(())
    }
}

pub fn get_wifi_config(
    _req: HttpRequest,
) -> Box<Future<Item = Json<Vec<WifiInterface>>, Error = Error>> {
    debug!("Get wificonfig hit!");
    Dashboard::from_registry()
        .send(GetWifiConfig {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn remote_logging(path: Path<bool>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let enabled = path.into_inner();
    debug!("/loging/enable/{} hit", enabled);

    SETTING.get_log_mut().enabled = enabled;

    if let Err(e) = KI.run_command("/etc/init.d/rita", &["restart"]) {
        return Box::new(future::err(e));
    }

    Box::new(future::ok(HttpResponse::Ok().json(())))
}

pub fn remote_logging_level(path: Path<String>) -> Box<Future<Item = HttpResponse, Error = Error>> {
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

    Box::new(future::ok(HttpResponse::Ok().json(())))
}

pub fn add_exits(
    new_exits: Json<HashMap<String, ExitServer>>,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    debug!("/exits POST hit with {:?}", new_exits);
    let exits = &mut SETTING.get_exit_client_mut().exits;
    exits.extend(new_exits.into_inner());

    Box::new(future::ok(HttpResponse::Ok().json(exits.clone())))
}

pub fn exits_sync(
    list_url_json: Json<HashMap<String, String>>,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    debug!("/exits/sync hit with {:?}", list_url_json);

    let list_url = match list_url_json.get("url") {
        Some(url) if url.starts_with("https://") => url,
        Some(_unsafe_url) => {
            let mut ret = HashMap::new();
            ret.insert(
                "error".to_owned(),
                "Attempted to use a non-HTTPS url".to_owned(),
            );
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::BAD_REQUEST)
                    .into_builder()
                    .json(ret),
            ));
        }
        None => {
            let mut ret = HashMap::new();

            ret.insert(
                "error".to_owned(),
                "Could not find a \"url\" key in supplied JSON".to_owned(),
            );
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::BAD_REQUEST)
                    .into_builder()
                    .json(ret),
            ));
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let new_exits: HashMap<String, ExitServer> = match client.get(list_url).send() {
        Ok(mut response) => match response.json() {
            Ok(deserialized) => deserialized,
            Err(e) => {
                let mut ret = HashMap::<String, String>::new();

                error!(
                    "Could not deserialize exit list at {:?} because of error: {:?}",
                    list_url, e
                );
                ret.insert(
                    "error".to_owned(),
                    format!("Could not deserialize exit list at URL {:?}", list_url),
                );

                return Box::new(future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                ));
            }
        },
        Err(e) => {
            let mut ret = HashMap::new();

            error!(
                "Could not make GET request vor URL {:?}, Rust error: {:?}",
                list_url, e
            );
            ret.insert(
                "error".to_owned(),
                format!("Could not make GET request for URL {:?}", list_url),
            );
            ret.insert("rust_error".to_owned(), format!("{:?}", e));
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(ret),
            ));
        }
    };

    info!("exit_sync list: {:#?}", new_exits);

    let exits = &mut SETTING.get_exit_client_mut().exits;
    exits.extend(new_exits);

    Box::new(future::ok(HttpResponse::Ok().json(exits.clone())))
}
