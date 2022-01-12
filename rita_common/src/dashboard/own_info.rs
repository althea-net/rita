use crate::rita_loop::is_gateway;
use crate::{blockchain_oracle::low_balance, RitaCommonError};
use actix_web::{HttpRequest, Json};
use clarity::Address;
use num256::{Int256, Uint256};

pub static READABLE_VERSION: &str = "Beta 18 RC11";

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

pub fn get_own_info(_req: HttpRequest) -> Json<OwnInfo> {
    debug!("Get own info endpoint hit!");
    let payment_settings = settings::get_rita_common().payment;
    let eth_address = payment_settings.eth_address.unwrap();
    let balance = payment_settings.balance.clone();
    let pay_threshold = get_oracle_pay_thresh();
    let close_threshold = get_oracle_close_thresh();
    let local_fee = payment_settings.local_fee;
    let client_can_use_free_tier = payment_settings.client_can_use_free_tier;

    let network_settings = settings::get_rita_common().network;
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
    Json(reply)
}
