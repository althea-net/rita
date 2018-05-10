use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use std::boxed::Box;

use super::{Dashboard, GetWifiConfig, SetWifiConfig};
use rita_client::dashboard::WifiInterface;

pub fn get_wifi_config(
    _req: HttpRequest,
) -> Box<Future<Item = Json<Vec<WifiInterface>>, Error = Error>> {
    Dashboard::from_registry()
        .send(GetWifiConfig {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn set_wifi_config(
    new_settings: Json<Vec<WifiInterface>>,
) -> Box<Future<Item = Json<()>, Error = Error>> {
    Dashboard::from_registry()
        .send(SetWifiConfig(new_settings.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
