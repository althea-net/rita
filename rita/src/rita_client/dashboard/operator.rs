use crate::rita_client::operator_fee_manager::get_operator_fee_debt;
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
pub fn add_to_dao_list(path: Path<Address>) -> HttpResponse {
    trace!("Add to dao list: Hit");
    let provided_address = path.into_inner();
    SETTING.get_operator_mut().operator_address = Some(provided_address);
    if let Err(_e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().finish()
}

/// TODO remove after beta 12, provided for backwards compat
pub fn remove_from_dao_list(_path: Path<Address>) -> HttpResponse {
    SETTING.get_operator_mut().operator_address = None;
    if let Err(_e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().finish()
}

/// TODO remove after beta 12, provided for backwards compat
pub fn get_dao_fee(_req: HttpRequest) -> HttpResponse {
    debug!("/dao_fee GET hit");
    let mut ret = HashMap::new();
    ret.insert("dao_fee", SETTING.get_operator().operator_fee.clone());

    HttpResponse::Ok().json(ret)
}

/// TODO remove after beta 12, provided for backwards compat
pub fn set_dao_fee(path: Path<Uint256>) -> HttpResponse {
    let new_fee = path.into_inner();
    debug!("/dao_fee/{} POST hit", new_fee);
    SETTING.get_operator_mut().operator_fee = new_fee;

    if let Err(_e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().finish()
}

pub fn get_operator(_req: HttpRequest) -> Json<Option<Address>> {
    trace!("get operator address: Hit");
    match SETTING.get_operator().operator_address {
        Some(address) => Json(Some(address)),
        None => Json(None),
    }
}

pub fn change_operator(path: Path<Address>) -> HttpResponse {
    trace!("add operator address: Hit");
    let provided_address = path.into_inner();
    SETTING.get_operator_mut().operator_address = Some(provided_address);
    if let Err(_e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().finish()
}

pub fn remove_operator(_path: Path<Address>) -> HttpResponse {
    SETTING.get_operator_mut().operator_address = None;
    if let Err(_e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().finish()
}

pub fn get_operator_fee(_req: HttpRequest) -> HttpResponse {
    debug!("get operator GET hit");
    HttpResponse::Ok().json(SETTING.get_operator().operator_fee.clone())
}

pub fn get_operator_debt(_req: HttpRequest) -> HttpResponse {
    debug!("get operator debt hit");
    HttpResponse::Ok().json(get_operator_fee_debt())
}
