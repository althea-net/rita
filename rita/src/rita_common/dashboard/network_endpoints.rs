use actix::registry::SystemService;
use actix_web::http::StatusCode;
use actix_web::*;
use althea_types::EthAddress;
use failure::Error;
use futures::{future, Future};
use serde_json;

use std::{
    boxed::Box,
    collections::HashMap,
    net::{SocketAddr, TcpStream},
};

use super::{Dashboard, GetOwnInfo, OwnInfo};
use babel_monitor::Babel;
use rita_common::debt_keeper::GetDebtsList;
use rita_common::debt_keeper::{DebtKeeper, GetDebtsResult};
use rita_common::network_endpoints::JsonStatusResponse;
use settings::RitaCommonSettings;
use SETTING;

pub fn get_own_info(_req: HttpRequest) -> Box<Future<Item = Json<OwnInfo>, Error = Error>> {
    debug!("Get own info endpoint hit!");
    Dashboard::from_registry()
        .send(GetOwnInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_settings(_req: HttpRequest) -> Result<Json<serde_json::Value>, Error> {
    debug!("Get settings endpoint hit!");
    Ok(Json(SETTING.get_all()?))
}

pub fn set_settings(
    new_settings: Json<serde_json::Value>,
) -> Result<Json<JsonStatusResponse>, Error> {
    debug!("Set settings endpoint hit!");
    SETTING.merge(new_settings.into_inner())?;

    JsonStatusResponse::new(Ok("New settings applied".to_string()))
}

#[cfg(not(feature = "development"))]
pub fn wipe(_req: HttpRequest) -> Result<HttpResponse, Error> {
    // This is returned on production builds.
    Ok(HttpResponse::NotFound().finish())
}

#[cfg(feature = "development")]
pub fn wipe(_req: HttpRequest) -> Result<HttpResponse, Error> {
    // Clean up existing WG interfaces
    match cleanup() {
        Ok(_) => trace!("wipe: WireGuard interfaces cleanup success!"),
        Err(e) => {
            warn!(
                "wipe: Unable to complete WireGuard interfaces cleanup: {:?}",
                e
            );
            return Err(e);
        }
    }

    // Restore default route
    match KI.restore_default_route(&mut SETTING.get_network_mut().default_route) {
        Ok(_) => trace!("wipe: Restore default route success!"),
        Err(e) => {
            warn!("wipe: Unable to restore default route: {:?}", e);
            return Err(e);
        }
    }

    // Create new WireGuard keys
    match linux_generate_wg_keys(&mut SETTING.get_network_mut()) {
        Ok(_) => trace!("wipe: Generated new WireGuard keys"),
        Err(e) => {
            warn!("wipe: Unable to generate new WireGuard keys: {:?}", e);
            return Err(e);
        }
    }
    // Generate new mesh IP
    match linux_generate_mesh_ip(&mut SETTING.get_network_mut()) {
        Ok(_) => trace!("wipe: Generated new mesh IP"),
        Err(e) => {
            warn!("wipe: Unable to generate new mesh IP: {:?}", e);
            return Err(e);
        }
    }

    // Creates file on disk containing key
    match KI.create_wg_key(
        &Path::new(&SETTING.get_network().wg_private_key_path),
        &SETTING.get_network().wg_private_key,
    ) {
        Ok(_) => trace!("wipe: Saved new WireGuard keys to disk"),
        Err(e) => {
            warn!("wipe: Unable to save new WireGuard keys: {:?}", e);
            return Err(e);
        }
    }

    Ok(HttpResponse::NoContent().finish())
}

pub fn get_debts(
    _req: HttpRequest,
) -> Box<Future<Item = Json<Vec<GetDebtsResult>>, Error = Error>> {
    trace!("get_debts: Hit");
    DebtKeeper::from_registry()
        .send(GetDebtsList {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_dao_list(_req: HttpRequest) -> Result<Json<Vec<EthAddress>>, Error> {
    trace!("get dao list: Hit");
    Ok(Json(SETTING.get_dao().dao_addresses.clone()))
}

pub fn add_to_dao_list(path: Path<(EthAddress)>) -> Result<Json<()>, Error> {
    trace!("Add to dao list: Hit");
    let provided_address = path.into_inner();
    for address in SETTING.get_dao().dao_addresses.iter() {
        if *address == provided_address {
            return Ok(Json(()));
        }
    }
    SETTING.get_dao_mut().dao_addresses.push(provided_address);
    Ok(Json(()))
}

pub fn remove_from_dao_list(path: Path<(EthAddress)>) -> Result<Json<()>, Error> {
    trace!("Remove from dao list: Hit");
    let provided_address = path.into_inner();
    let mut iter = 0;
    let mut found = false;
    for address in SETTING.get_dao().dao_addresses.iter() {
        if *address == provided_address {
            found = true;
            break;
        }
        iter = iter + 1;
    }
    if found {
        SETTING.get_dao_mut().dao_addresses.remove(iter);
    }
    Ok(Json(()))
}

pub fn get_local_fee(_req: HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("local_fee", SETTING.get_local_fee());

    Box::new(future::ok(HttpResponse::Ok().json(ret)))
}

pub fn get_metric_factor(_req: HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
    debug!("/local_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("metric_factor", SETTING.get_metric_factor());

    Box::new(future::ok(HttpResponse::Ok().json(ret)))
}

pub fn set_local_fee(path: Path<u32>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let new_fee = path.into_inner();
    debug!("/local_fee/{} POST hit", new_fee);
    let mut ret = HashMap::<String, String>::new();

    let stream = match TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", SETTING.get_network().babel_port)
            .parse()
            .unwrap(),
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to set local fee! {:?}", e);
            ret.insert(
                "error".to_owned(),
                "Could not create a socket for connecting to Babel".to_owned(),
            );
            ret.insert("rust_error".to_owned(), format!("{:?}", e));

            return Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(ret),
            ));
        }
    };

    let mut babel = Babel::new(stream);

    if let Err(e) = babel.start_connection() {
        error!("Failed to set local fee! {:?}", e);
        ret.insert("error".to_owned(), "Could not connect to Babel".to_owned());
        ret.insert("rust_error".to_owned(), format!("{:?}", e));

        return Box::new(future::ok(
            HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                .into_builder()
                .json(ret),
        ));
    }

    if let Err(e) = babel.set_local_fee(new_fee) {
        error!("Failed to set local fee! {:?}", e);
        ret.insert(
            "error".to_owned(),
            "Failed to ask Babel to set the proposed fee".to_owned(),
        );
        ret.insert("rust_error".to_owned(), format!("{:?}", e));

        return Box::new(future::ok(
            HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                .into_builder()
                .json(ret),
        ));
    };

    // Set the value in settings only after Babel successfuly accepts the passed value
    SETTING.set_local_fee(new_fee);

    if new_fee == 0 {
        warn!("THIS NODE IS GIVING BANDWIDTH AWAY FOR FREE. PLEASE SET local_fee TO A NON-ZERO VALUE TO DISABLE THIS WARNING.");
        ret.insert("warning".to_owned(), "THIS NODE IS GIVING BANDWIDTH AWAY FOR FREE. PLEASE SET local_fee TO A NON-ZERO VALUE TO DISABLE THIS WARNING.".to_owned());
    }

    Box::new(future::ok(HttpResponse::Ok().json(ret)))
}

pub fn set_metric_factor(path: Path<u32>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let new_factor = path.into_inner();
    debug!("/metric_factor/{} POST hit", new_factor);
    let mut ret = HashMap::<String, String>::new();

    let stream = match TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", SETTING.get_network().babel_port)
            .parse()
            .unwrap(),
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to set metric factor! {:?}", e);
            ret.insert(
                "error".to_owned(),
                "Could not create a socket for connecting to Babel".to_owned(),
            );
            ret.insert("rust_error".to_owned(), format!("{:?}", e));

            return Box::new(future::ok(
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .into_builder()
                    .json(ret),
            ));
        }
    };

    let mut babel = Babel::new(stream);

    if let Err(e) = babel.start_connection() {
        error!("Failed to set metric factor! {:?}", e);
        ret.insert("error".to_owned(), "Could not connect to Babel".to_owned());
        ret.insert("rust_error".to_owned(), format!("{:?}", e));

        return Box::new(future::ok(
            HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                .into_builder()
                .json(ret),
        ));
    }

    if let Err(e) = babel.set_metric_factor(new_factor) {
        error!("Failed to set metric factor! {:?}", e);
        ret.insert(
            "error".to_owned(),
            "Failed to ask Babel to set the proposed factor".to_owned(),
        );
        ret.insert("rust_error".to_owned(), format!("{:?}", e));

        return Box::new(future::ok(
            HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                .into_builder()
                .json(ret),
        ));
    };

    // Set the value in settings only after Babel successfuly accepts the passed value
    SETTING.set_metric_factor(new_factor);

    if new_factor == 0 {
        warn!("THIS NODE DOESN'T PAY ATTENTION TO ROUTE QUALITY - IT'LL CHOOSE THE CHEAPEST ROUTE EVEN IF IT'S THE WORST LINK AROUND. PLEASE SET metric_factor TO A NON-ZERO VALUE TO DISABLE THIS WARNING.");
        ret.insert("warning".to_owned(), "THIS NODE DOESN'T PAY ATTENTION TO ROUTE QUALITY - IT'LL CHOOSE THE CHEAPEST ROUTE EVEN IF IT'S THE WORST LINK AROUND. PLEASE SET metric_factor TO A NON-ZERO VALUE TO DISABLE THIS WARNING.".to_owned());
    }

    Box::new(future::ok(HttpResponse::Ok().json(ret)))
}
