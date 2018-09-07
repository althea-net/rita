use actix::registry::SystemService;
use actix_web::http::StatusCode;
use actix_web::{AsyncResponder, HttpRequest, HttpResponse, Json};
use failure::Error;
use futures::future;
use futures::Future;

use rita_client::dashboard::WifiInterface;
use rita_client::exit_manager::exit_setup_request;

use super::*;

use std::boxed::Box;
use std::collections::HashMap;

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

pub fn set_wifi_config(
    new_settings: Json<WifiInterface>,
) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("Set wificonfig endpoint hit!");
    //This will be dead code if the JS is modified to submit both interfaces
    //in one vector
    let mut new_settings_vec = Vec::new();
    new_settings_vec.push(new_settings.into_inner());

    Dashboard::from_registry()
        .send(SetWifiConfig(new_settings_vec))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
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
        return Box::new(future::ok(HttpResponse::Ok().json(ret)));
    } else {
        error!("Requested selection of an unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested selection of an unknown exit {:?}", exit_name),
        );
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
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
            .send(SetWiFiSSID(wifi_ssid))
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
            .send(SetWiFiPass(wifi_pass))
            .from_err()
            .and_then(move |_reply| future::ok(HttpResponse::Ok().json(ret))),
    )
}

pub fn set_wifi_mesh(wifi_mesh: Json<WifiMesh>) -> Box<Future<Item = Json<()>, Error = Error>> {
    debug!("/wifi_settings/mesh hit with {:?}", wifi_mesh);

    Dashboard::from_registry()
        .send(SetWiFiMesh(wifi_mesh.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

/// This function checks that a supplied string is non-empty and doesn't contain any of the
/// `FORBIDDEN_CHARS`. If everything's alright the string itself is moved and returned for
/// convenience.
fn validate_config_value(s: &str) -> Result<(), ValidationError> {
    if s.len() == 0 {
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
