use crate::blockchain_oracle::{
    calculate_close_thresh, get_oracle_balance, get_pay_thresh, low_balance,
};
use crate::rita_loop::is_gateway;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use clarity::Address;
use num256::{Int256, Uint256};

pub static READABLE_VERSION: &str = "Beta 21 RC5";

#[derive(Serialize)]
pub struct OwnInfo {
    pub address: Address,
    pub balance: Option<Uint256>,
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

pub async fn get_own_info(_req: HttpRequest) -> HttpResponse {
    debug!("Get own info endpoint hit!");
    let payment_settings = settings::get_rita_common().payment;
    let network_settings = settings::get_rita_common().network;
    let eth_address = payment_settings.eth_address.unwrap();
    let balance = get_oracle_balance();
    let pay_threshold = get_pay_thresh();
    let close_threshold = calculate_close_thresh();
    let client_can_use_free_tier = payment_settings.client_can_use_free_tier;
    let local_fee = network_settings.babeld_settings.local_fee;
    let metric_factor = network_settings.babeld_settings.metric_factor;

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
    HttpResponse::Ok().json(reply)
}
