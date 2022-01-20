use crate::operator_fee_manager::get_operator_fee_debt;
use crate::RitaClientError;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Json, Result};
use clarity::Address;
use num256::Uint256;
use std::collections::HashMap;

/// TODO remove after beta 12, provided for backwards compat
pub fn get_dao_list(_req: HttpRequest) -> Result<Json<Vec<Address>>, RitaClientError> {
    trace!("get dao list: Hit");
    let rita_client = settings::get_rita_client();
    match rita_client.operator.operator_address {
        Some(address) => Ok(Json(vec![address])),
        None => Ok(Json(Vec::new())),
    }
}

/// TODO remove after beta 12, provided for backwards compat
pub fn add_to_dao_list(path: Path<Address>) -> HttpResponse {
    trace!("Add to dao list: Hit");
    let provided_address = path.into_inner();
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;
    operator.operator_address = Some(provided_address);

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);

    HttpResponse::Ok().finish()
}

/// TODO remove after beta 12, provided for backwards compat
pub fn remove_from_dao_list(_path: Path<Address>) -> HttpResponse {
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;

    operator.operator_address = None;

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);

    HttpResponse::Ok().finish()
}

/// TODO remove after beta 12, provided for backwards compat
pub fn get_dao_fee(_req: HttpRequest) -> HttpResponse {
    debug!("/dao_fee GET hit");
    let mut ret = HashMap::new();
    let rita_client = settings::get_rita_client();
    ret.insert("dao_fee", rita_client.operator.operator_fee);

    HttpResponse::Ok().json(ret)
}

/// TODO remove after beta 12, provided for backwards compat
pub fn set_dao_fee(path: Path<Uint256>) -> HttpResponse {
    let new_fee = path.into_inner();
    debug!("/dao_fee/{} POST hit", new_fee);
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;
    operator.operator_fee = new_fee;

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);

    HttpResponse::Ok().finish()
}

pub fn get_operator(_req: HttpRequest) -> Json<Option<Address>> {
    trace!("get operator address: Hit");
    let rita_client = settings::get_rita_client();
    match rita_client.operator.operator_address {
        Some(address) => Json(Some(address)),
        None => Json(None),
    }
}

pub fn change_operator(path: Path<Address>) -> HttpResponse {
    trace!("add operator address: Hit");
    let provided_address = path.into_inner();
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;

    operator.operator_address = Some(provided_address);

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);

    HttpResponse::Ok().finish()
}

pub fn remove_operator(_path: Path<Address>) -> HttpResponse {
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;
    operator.operator_address = None;

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);
    HttpResponse::Ok().finish()
}

pub fn get_operator_fee(_req: HttpRequest) -> HttpResponse {
    debug!("get operator GET hit");
    HttpResponse::Ok().json(settings::get_rita_client().operator.operator_fee)
}

pub fn get_operator_debt(_req: HttpRequest) -> HttpResponse {
    debug!("get operator debt hit");
    HttpResponse::Ok().json(get_operator_fee_debt())
}
