use crate::blockchain_oracle::low_balance;
use crate::rita_loop::is_gateway;
use actix_web::{HttpRequest, Json};
use clarity::Address;
use failure::Error;
use num256::{Int256, Uint256};

pub static READABLE_VERSION: &str = "Beta 18 RC0";

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
    pub is_gateway: bool,
    pub client_can_use_free_tier: bool,
}

pub fn get_own_info(_req: HttpRequest) -> Result<Json<OwnInfo>, Error> {
    debug!("Get own info endpoint hit!");
    let payment_settings = settings::get_rita_common().get_payment();
    let eth_address = payment_settings.eth_address.unwrap();
    let balance = payment_settings.balance.clone();
    let pay_threshold = payment_settings.pay_threshold.clone();
    let close_threshold = payment_settings.close_threshold.clone();
    let local_fee = payment_settings.local_fee;
    let client_can_use_free_tier = payment_settings.client_can_use_free_tier;

    let network_settings = settings::get_rita_common().get_network();
    let metric_factor = network_settings.metric_factor;
    let device = network_settings.device;
    let is_gateway = is_gateway();

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
        is_gateway,
        client_can_use_free_tier,
    };
    Ok(Json(reply))
}
