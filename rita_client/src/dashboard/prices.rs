use actix_web::http::StatusCode;
use actix_web::web::Path;
use actix_web::{HttpRequest, HttpResponse};
use num256::Uint256;

use crate::traffic_watcher::get_exit_dest_price;

pub async fn auto_pricing_status(_req: HttpRequest) -> HttpResponse {
    debug!("Get Auto pricing enabled hit!");
    HttpResponse::Ok().json(settings::get_rita_client().operator.use_operator_price)
}

pub async fn set_auto_pricing(path: Path<bool>) -> HttpResponse {
    let value = path.into_inner();
    debug!("Set Auto pricing enabled hit!");
    let mut rita_client = settings::get_rita_client();
    let mut op = rita_client.operator;
    if !op.force_use_operator_price {
        op.use_operator_price = value;
    }
    rita_client.operator = op;
    settings::set_rita_client(rita_client);

    // try and save the config and fail if we can't
    if let Err(e) = settings::write_config() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
            .json(format!("Error writing config: {e}"));
    }

    HttpResponse::Ok().json(())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Prices {
    exit_dest_price: u128,
    operator_fee: Uint256,
    simulated_tx_fee: u8,
}

pub async fn get_prices(_req: HttpRequest) -> HttpResponse {
    debug!("/prices GET hit");

    let payment = settings::get_rita_client().payment;
    let exit_dest_price = get_exit_dest_price();
    let simulated_tx_fee = payment.simulated_transaction_fee;
    let operator_fee = settings::get_rita_client().operator.operator_fee;
    let p = Prices {
        exit_dest_price,
        operator_fee,
        simulated_tx_fee,
    };
    HttpResponse::Ok().json(p)
}
