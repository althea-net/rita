use crate::rita_common::oracle::low_balance;
use crate::SETTING;
use ::settings::RitaCommonSettings;
use actix_web::{HttpRequest, Json};
use clarity::Address;
use failure::Error;
use num256::{Int256, Uint256};

pub static READABLE_VERSION: &str = "Beta 7 RC1";

#[derive(Serialize)]
pub struct OwnInfo {
    pub address: Address,
    pub balance: Uint256,
    pub local_fee: u32,
    pub metric_factor: u32,
    pub pay_threshold: Int256,
    pub close_threshold: Int256,
    pub low_balance: bool,
    pub device: Option<String>,
    pub rita_version: String,
    pub version: String,
}

pub fn get_own_info(_req: HttpRequest) -> Result<Json<OwnInfo>, Error> {
    debug!("Get own info endpoint hit!");
    let payment_settings = SETTING.get_payment();
    let eth_address = payment_settings.eth_address.unwrap();
    let balance = payment_settings.balance.clone();
    let pay_threshold = payment_settings.pay_threshold.clone();
    let close_threshold = payment_settings.close_threshold.clone();

    let network_settings = SETTING.get_network();
    let local_fee = SETTING.get_payment().local_fee;
    let metric_factor = SETTING.get_network().metric_factor;
    let device = network_settings.device.clone();

    let reply = OwnInfo {
        address: eth_address,
        balance,
        local_fee,
        metric_factor,
        pay_threshold,
        close_threshold,
        low_balance: low_balance(),
        device,
        rita_version: env!("CARGO_PKG_VERSION").to_string(),
        version: READABLE_VERSION.to_string(),
    };
    Ok(Json(reply))
}
