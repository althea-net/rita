use crate::operator_fee_manager::get_operator_fee_debt;
use actix_web_async::web::Path;
use actix_web_async::{HttpRequest, HttpResponse};
use clarity::{Address, Uint256};

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

    // save immediately
    if let Err(_e) = settings::write_config() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().finish()
}

pub async fn remove_operator(_path: Path<Address>) -> HttpResponse {
    let mut rita_client = settings::get_rita_client();
    let mut operator = rita_client.operator;
    operator.operator_address = None;

    rita_client.operator = operator;
    settings::set_rita_client(rita_client);

    // save immediately
    if let Err(_e) = settings::write_config() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().finish()
}

pub async fn get_operator_fee(_req: HttpRequest) -> HttpResponse {
    debug!("get_operator_fee GET hit");
    HttpResponse::Ok().json(settings::get_rita_client().operator.operator_fee)
}

pub async fn set_operator_fee(fee: Path<Uint256>) -> HttpResponse {
    let op_fee = fee.into_inner();
    debug!("set_operator_fee POST hit {:?}", op_fee);

    let mut rita_client = settings::get_rita_client();
    rita_client.operator.operator_fee = op_fee;

    rita_client.operator.use_operator_price = op_fee == 0_u8.into();

    settings::set_rita_client(rita_client);

    // save immediately
    if let Err(_e) = settings::write_config() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().json(settings::get_rita_client().operator.operator_fee)
}

pub async fn get_operator_debt(_req: HttpRequest) -> HttpResponse {
    debug!("get operator debt hit");
    HttpResponse::Ok().json(get_operator_fee_debt())
}
