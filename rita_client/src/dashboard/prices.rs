use crate::traffic_watcher::GetExitDestPrice;
use crate::traffic_watcher::TrafficWatcherActor;

use actix::SystemService;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Json, Result};
use failure::Error;
use futures01::Future;
use num256::Uint256;
use settings::FileWrite;
pub fn auto_pricing_status(_req: HttpRequest) -> Result<Json<bool>, Error> {
    debug!("Get Auto pricing enabled hit!");
    Ok(Json(
        settings::get_rita_client().operator.use_operator_price,
    ))
}

pub fn set_auto_pricing(path: Path<bool>) -> Result<HttpResponse, Error> {
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
    let rita_client = settings::get_rita_client();
    if let Err(_e) = rita_client.write(&settings::get_flag_config()) {
        return Err(_e);
    } else {
        settings::set_rita_client(rita_client);
    }
    Ok(HttpResponse::Ok().json(()))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Prices {
    exit_dest_price: u128,
    dao_fee: Uint256,
    simulated_tx_fee: u8,
}

pub fn get_prices(_req: HttpRequest) -> Box<dyn Future<Item = Json<Prices>, Error = Error>> {
    debug!("/prices GET hit");

    let payment = settings::get_rita_client().payment;
    let f = TrafficWatcherActor::from_registry().send(GetExitDestPrice);
    let b = f.from_err().and_then(move |exit_dest_price| {
        let exit_dest_price = exit_dest_price.unwrap();
        let simulated_tx_fee = payment.simulated_transaction_fee;
        let operator_fee = settings::get_rita_client().operator.operator_fee;
        let p = Prices {
            exit_dest_price,
            dao_fee: operator_fee,
            simulated_tx_fee,
        };
        Ok(Json(p))
    });

    Box::new(b)
}
