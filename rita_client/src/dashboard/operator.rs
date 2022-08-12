use crate::operator_fee_manager::get_operator_fee_debt;
use actix_web_async::web::Path;
use actix_web_async::{HttpRequest, HttpResponse};
use clarity::Address;
use num256::Uint256;
use settings::write_config;
use std::collections::HashMap;

/// TODO remove after beta 12, provided for backwards compat
pub async fn get_dao_list(_req: HttpRequest) -> HttpResponse {
    trace!("get dao list: Hit");
    let rita_client = settings::get_rita_client();
    match rita_client.operator.operator_address {
        Some(address) => HttpResponse::Ok().json(vec![address]),
        None => {
            let emp_vec: Vec<Address> = Vec::new();
            HttpResponse::Ok().json(emp_vec)
        }
    }
}

/// TODO remove after beta 12, provided for backwards compat
pub async fn add_to_dao_list(path: Path<Address>) -> HttpResponse {
    trace!("Add to dao list: Hit");
    let provided_address = path.into_inner();
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;
    operator.operator_address = Some(provided_address);

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);
    let res = write_config();
    if let Err(e) = res {
        error!("Failed to save operator address! {:?}", e);
    }

    HttpResponse::Ok().finish()
}

/// TODO remove after beta 12, provided for backwards compat
pub async fn remove_from_dao_list(_path: Path<Address>) -> HttpResponse {
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;

    operator.operator_address = None;

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);
    let res = write_config();
    if let Err(e) = res {
        error!("Failed to save operator remove! {:?}", e);
    }

    HttpResponse::Ok().finish()
}

/// TODO remove after beta 12, provided for backwards compat
pub async fn get_dao_fee(_req: HttpRequest) -> HttpResponse {
    debug!("/dao_fee GET hit");
    let mut ret = HashMap::new();
    let rita_client = settings::get_rita_client();
    ret.insert("dao_fee", rita_client.operator.operator_fee);

    HttpResponse::Ok().json(ret)
}

/// TODO remove after beta 12, provided for backwards compat
pub async fn set_dao_fee(path: Path<Uint256>) -> HttpResponse {
    let new_fee = path.into_inner();
    debug!("/dao_fee/{} POST hit", new_fee);
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;
    operator.operator_fee = new_fee;

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);
    let res = write_config();
    if let Err(e) = res {
        error!("Failed to save operator fee! {:?}", e);
    }

    HttpResponse::Ok().finish()
}

pub async fn get_operator(_req: HttpRequest) -> HttpResponse {
    trace!("get operator address: Hit");
    let rita_client = settings::get_rita_client();
    match rita_client.operator.operator_address {
        Some(address) => HttpResponse::Ok().json(Some(address)),
        None => {
            let emp_op: Option<Address> = None;
            HttpResponse::Ok().json(emp_op)
        }
    }
}

pub async fn change_operator(path: Path<Address>) -> HttpResponse {
    trace!("add operator address: Hit");
    let provided_address = path.into_inner();
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;

    operator.operator_address = Some(provided_address);

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);

    HttpResponse::Ok().finish()
}

pub async fn remove_operator(_path: Path<Address>) -> HttpResponse {
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;
    operator.operator_address = None;

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);
    HttpResponse::Ok().finish()
}

pub async fn get_operator_fee(_req: HttpRequest) -> HttpResponse {
    debug!("get operator GET hit");
    HttpResponse::Ok().json(settings::get_rita_client().operator.operator_fee)
}

pub async fn get_operator_debt(_req: HttpRequest) -> HttpResponse {
    debug!("get operator debt hit");
    HttpResponse::Ok().json(get_operator_fee_debt())
}
