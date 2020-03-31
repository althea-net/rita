use crate::ARGS;
use crate::SETTING;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Json, Result};
use clarity::Address;
use failure::Error;
use num256::Uint256;
use settings::client::RitaClientSettings;
use settings::FileWrite;
use std::collections::HashMap;

/// TODO remove after beta 12, provided for backwards compat
pub fn get_dao_list(_req: HttpRequest) -> Result<Json<Vec<Address>>, Error> {
    trace!("get dao list: Hit");
    match SETTING.get_operator().operator_address {
        Some(address) => Ok(Json(vec![address])),
        None => Ok(Json(Vec::new())),
    }
}

/// TODO remove after beta 12, provided for backwards compat
pub fn add_to_dao_list(path: Path<Address>) -> Result<Json<()>, Error> {
    trace!("Add to dao list: Hit");
    let provided_address = path.into_inner();
    SETTING.get_operator_mut().operator_address = Some(provided_address);
    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(Json(()))
}

/// TODO remove after beta 12, provided for backwards compat
pub fn remove_from_dao_list(_path: Path<Address>) -> Result<Json<()>, Error> {
    SETTING.get_operator_mut().operator_address = None;
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(Json(()))
}

/// TODO remove after beta 12, provided for backwards compat
pub fn get_dao_fee(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/dao_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("dao_fee", SETTING.get_operator().operator_fee.clone());

    Ok(HttpResponse::Ok().json(ret))
}

/// TODO remove after beta 12, provided for backwards compat
pub fn set_dao_fee(path: Path<Uint256>) -> Result<Json<()>, Error> {
    let new_fee = path.into_inner();
    debug!("/dao_fee/{} POST hit", new_fee);
    SETTING.get_operator_mut().operator_fee = new_fee;

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(Json(()))
}

pub fn get_operator(_req: HttpRequest) -> Json<Option<Address>> {
    trace!("get operator address: Hit");
    match SETTING.get_operator().operator_address {
        Some(address) => Json(Some(address)),
        None => Json(None),
    }
}

pub fn change_operator(path: Path<Address>) -> Result<Json<()>, Error> {
    trace!("add operator address: Hit");
    let provided_address = path.into_inner();
    SETTING.get_operator_mut().operator_address = Some(provided_address);
    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(Json(()))
}

pub fn remove_operator(_path: Path<Address>) -> Result<Json<()>, Error> {
    SETTING.get_operator_mut().operator_address = None;
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(Json(()))
}

pub fn get_operator_fee(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("get operator GET hit");
    Ok(HttpResponse::Ok().json(SETTING.get_operator().operator_fee.clone()))
}
