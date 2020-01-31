use crate::rita_client::traffic_watcher::GetExitDestPrice;
use crate::rita_client::traffic_watcher::TrafficWatcher;
use crate::ARGS;
use crate::SETTING;
use actix::SystemService;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Json, Result};
use failure::Error;
use futures01::Future;
use num256::Uint256;
use settings::FileWrite;
use settings::RitaCommonSettings;

pub fn auto_pricing_status(_req: HttpRequest) -> Result<Json<bool>, Error> {
    debug!("Get Auto pricing enabled hit!");
    Ok(Json(SETTING.get_dao().use_oracle_price))
}

pub fn set_auto_pricing(path: Path<bool>) -> Result<HttpResponse, Error> {
    let value = path.into_inner();
    debug!("Set Auto pricing enabled hit!");
    SETTING.get_dao_mut().use_oracle_price = value;

    // try and save the config and fail if we can't
    if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
        return Err(e);
    }
    Ok(HttpResponse::Ok().json(()))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Prices {
    exit_dest_fee: u128,
    dao_fee: Uint256,
    simulated_tx_fee: u8,
}

pub fn get_prices(_req: HttpRequest) -> Box<dyn Future<Item = Json<Prices>, Error = Error>> {
    debug!("/prices GET hit");
    let f = TrafficWatcher::from_registry().send(GetExitDestPrice);
    let b = f.from_err().and_then(|exit_dest_fee| {
        let exit_dest_fee = exit_dest_fee.unwrap();
        let simulated_tx_fee = SETTING.get_payment().simulated_transaction_fee;
        let dao_fee = SETTING.get_dao().dao_fee.clone();
        let p = Prices {
            exit_dest_fee,
            dao_fee,
            simulated_tx_fee,
        };
        Ok(Json(p))
    });
    Box::new(b)
}
